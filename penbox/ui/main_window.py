"""Fenêtre principale PenBox — assemble Cibles / Catalogue / Console / Résultats."""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDockWidget,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableView,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from penbox.catalog import REPO_ROOT, load_catalog, target_type_matches
from penbox.store import Store
from penbox.ui.catalog_panel import CatalogPanel
from penbox.ui.console_panel import ConsolePanel
from penbox.ui.detail_pane import DetailPane
from penbox.ui.export import export_csv, export_html
from penbox.ui.history_panel import HistoryPanel
from penbox.ui.host_keys_dialog import HostKeysDialog
from penbox.ui.jobs import JobManager
from penbox.ui.param_form import ParamFormDialog
from penbox.ui.remote_run_dialog import RemoteConnectDialog
from penbox.ui.resource_widget import ResourceWidget
from penbox.ui.results_model import FindingsFilterProxy, FindingsModel
from penbox.ui.run_diff_dialog import RunDiffDialog
from penbox.ui.run_output_dialog import RunOutputDialog
from penbox.ui.ssh_settings import get_ssh_mode, set_ssh_mode
from penbox.ui.targets_panel import TargetsPanel
from penbox.ui.vault_dialogs import ProfileManagerDialog
from penbox.ui.vault_session import ensure_unlocked, get_vault

DISCLAIMER_TEXT = (
    "<b>Avertissement légal</b><br><br>"
    "Ces scripts sont destinés exclusivement à des audits de sécurité "
    "<b>autorisés</b>. Toute utilisation non autorisée sur des systèmes tiers "
    "est illégale. L'auteur décline toute responsabilité en cas d'utilisation "
    "abusive.<br><br>"
    "En continuant, vous confirmez disposer d'une autorisation explicite pour "
    "toute cible que vous analyserez avec PenBox."
)

# Findings dont le nom est une valeur chaînable (subdomain_enum -> domaine, network_mapper -> IP).
CHAIN_TARGET_TYPE = {"subdomain_enum": "domain", "network_mapper": "ip"}

# Mode "chaînage automatique" (voir _auto_chain) : quel(s) outil(s) relancer sans
# confirmation sur les nouvelles cibles découvertes. Aucune de ces valeurs ne
# doit être une clé de CHAIN_TARGET_TYPE, sous peine de créer un pipeline
# auto-déclenché en boucle infinie.
AUTO_CHAIN_NEXT_TOOLS = {
    "subdomain_enum": ["port_scanner", "ssl_checker"],
    "network_mapper": ["port_scanner"],
}

RISK_LEVELS = ["critical", "high", "medium", "low", "info"]


class DisclaimerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("PenBox — Avertissement légal")
        self.setMinimumWidth(480)
        layout = QVBoxLayout(self)
        text = QTextBrowser()
        text.setHtml(DISCLAIMER_TEXT)
        layout.addWidget(text)
        self.confirm_check = QCheckBox("J'ai compris et je dispose des autorisations nécessaires")
        layout.addWidget(self.confirm_check)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setEnabled(False)
        self.confirm_check.toggled.connect(buttons.button(QDialogButtonBox.Ok).setEnabled)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class ChainDialog(QDialog):
    def __init__(self, tool_id: str, candidates: list[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Envoyer vers Cibles")
        self.setMinimumWidth(420)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(
            f"{tool_id} a trouvé {len(candidates)} valeur(s) pouvant être ajoutées "
            f"comme nouvelles cibles. Sélectionnez celles à importer :"
        ))
        self.list_widget = QListWidget()
        for value in candidates:
            item = QListWidgetItem(value)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked)
            self.list_widget.addItem(item)
        layout.addWidget(self.list_widget)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def selected_values(self) -> list[str]:
        return [
            self.list_widget.item(i).text()
            for i in range(self.list_widget.count())
            if self.list_widget.item(i).checkState() == Qt.Checked
        ]


class MainWindow(QMainWindow):
    def __init__(self, db_path: Path | None = None):
        super().__init__()
        self.setWindowTitle("PenBox — Cybersec Script Suite")
        self.resize(1440, 900)
        icon_path = REPO_ROOT / "penbox.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        self.store = Store(db_path or (REPO_ROOT / "penbox.db"))
        self.tools = load_catalog()
        self.jobs = JobManager(self.store, max_concurrent=3)

        self.targets_panel = TargetsPanel(self.store)
        self.catalog_panel = CatalogPanel(self.tools, self.store)
        self.history_panel = HistoryPanel(self.store)
        self.console_panel = ConsolePanel()
        self.detail_pane = DetailPane()

        self.results_model = FindingsModel(self.store)
        self.proxy = FindingsFilterProxy()
        self.proxy.setSourceModel(self.results_model)

        self.results_table = QTableView()
        self.results_table.setModel(self.proxy)
        self.results_table.setSortingEnabled(True)
        self.results_table.setSelectionBehavior(QTableView.SelectRows)
        self.results_table.setSelectionMode(QTableView.SingleSelection)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.selectionModel().currentRowChanged.connect(self._on_result_selected)
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self._show_results_context_menu)

        self._build_ui()
        self._build_menu()
        self._wire_signals()
        self._on_project_changed(self.targets_panel.current_project_id())

    # ─── Menu ────────────────────────────────────────────────────────────────

    def _build_menu(self) -> None:
        settings_menu = self.menuBar().addMenu("&Paramètres")

        self.strict_ssh_action = QAction("Mode strict SSH (refuser les hôtes inconnus)", self)
        self.strict_ssh_action.setCheckable(True)
        self.strict_ssh_action.setChecked(get_ssh_mode() == "strict")
        self.strict_ssh_action.setStatusTip(
            "Tolérant : la première connexion à un hôte enregistre sa clé (TOFU). "
            "Strict : refuse tout hôte dont la clé n'est pas déjà approuvée."
        )
        self.strict_ssh_action.toggled.connect(
            lambda checked: set_ssh_mode("strict" if checked else "tolerant")
        )
        settings_menu.addAction(self.strict_ssh_action)

        host_keys_action = QAction("Clés hôtes SSH...", self)
        host_keys_action.triggered.connect(lambda: HostKeysDialog(self).exec())
        settings_menu.addAction(host_keys_action)

        profiles_action = QAction("Profils de connexion SSH...", self)
        profiles_action.triggered.connect(self._open_profile_manager)
        settings_menu.addAction(profiles_action)

        settings_menu.addSeparator()
        self.auto_chain_action = QAction("Chaînage automatique (sans confirmation)", self)
        self.auto_chain_action.setCheckable(True)
        self.auto_chain_action.setChecked(QSettings("PenBox", "PenBox").value("auto_chain", False, type=bool))
        self.auto_chain_action.setStatusTip(
            f"Si activé : {', '.join(sorted(AUTO_CHAIN_NEXT_TOOLS))} enchaînent automatiquement "
            "vers de nouveaux scans sur les cibles découvertes, sans popup de confirmation."
        )
        self.auto_chain_action.toggled.connect(
            lambda checked: QSettings("PenBox", "PenBox").setValue("auto_chain", checked)
        )
        settings_menu.addAction(self.auto_chain_action)

        help_menu = self.menuBar().addMenu("&Aide")
        notice_action = QAction("Notice d'utilisation...", self)
        notice_action.triggered.connect(self._open_notice)
        help_menu.addAction(notice_action)

    def _open_profile_manager(self) -> None:
        if not ensure_unlocked(self):
            return
        ProfileManagerDialog(get_vault(), self).exec()

    def _open_notice(self) -> None:
        pdf_path = REPO_ROOT / "PenBox_Notice_Utilisation.pdf"
        md_path = REPO_ROOT / "penbox_notice.md"
        path = pdf_path if pdf_path.exists() else md_path
        if not path.exists():
            QMessageBox.warning(self, "Notice", "Aucune notice trouvée dans le dépôt.")
            return
        try:
            os.startfile(str(path))
        except OSError as e:
            QMessageBox.warning(self, "Notice", f"Impossible d'ouvrir la notice : {e}")

    # ─── Construction de l'UI ────────────────────────────────────────────────

    def _build_ui(self) -> None:
        left_dock = QDockWidget("Cibles", self)
        left_dock.setWidget(self.targets_panel)
        left_dock.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetFloatable)
        self.addDockWidget(Qt.LeftDockWidgetArea, left_dock)

        history_dock = QDockWidget("Historique", self)
        history_dock.setWidget(self.history_panel)
        history_dock.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetFloatable)
        self.addDockWidget(Qt.LeftDockWidgetArea, history_dock)
        self.tabifyDockWidget(left_dock, history_dock)
        left_dock.raise_()

        bottom_dock = QDockWidget("Console", self)
        bottom_dock.setWidget(self.console_panel)
        self.addDockWidget(Qt.BottomDockWidgetArea, bottom_dock)

        # ── Barre de filtres ────────────────────────────────────────────────
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Filtrer les résultats...")
        self.search_edit.textChanged.connect(self.proxy.set_text_filter)

        self.risk_checks: dict[str, QCheckBox] = {}
        risk_row = QHBoxLayout()
        risk_row.addWidget(self.search_edit, stretch=1)
        for risk in RISK_LEVELS:
            cb = QCheckBox(risk.capitalize())
            cb.setChecked(True)
            cb.toggled.connect(self._update_risk_filter)
            self.risk_checks[risk] = cb
            risk_row.addWidget(cb)

        self.tool_combo = QComboBox()
        self.tool_combo.addItem("Tous les outils", None)
        for tool_id in sorted(self.tools):
            self.tool_combo.addItem(tool_id, tool_id)
        self.tool_combo.currentIndexChanged.connect(
            lambda: self.proxy.set_tool_filter(self.tool_combo.currentData())
        )
        risk_row.addWidget(self.tool_combo)

        self.hide_fp_check = QCheckBox("Masquer les faux-positifs")
        self.hide_fp_check.setChecked(True)
        self.hide_fp_check.toggled.connect(self.proxy.set_hide_false_positives)
        risk_row.addWidget(self.hide_fp_check)

        self.export_html_btn = QPushButton("Export HTML")
        self.export_html_btn.clicked.connect(self._export_html)
        self.export_csv_btn = QPushButton("Export CSV")
        self.export_csv_btn.clicked.connect(self._export_csv)
        risk_row.addWidget(self.export_html_btn)
        risk_row.addWidget(self.export_csv_btn)

        filters_widget = QWidget()
        filters_widget.setLayout(risk_row)

        results_splitter = QSplitter(Qt.Vertical)
        results_splitter.addWidget(self.results_table)
        results_splitter.addWidget(self.detail_pane)
        results_splitter.setStretchFactor(0, 3)
        results_splitter.setStretchFactor(1, 2)

        results_area = QWidget()
        results_layout = QVBoxLayout(results_area)
        results_layout.setContentsMargins(0, 0, 0, 0)
        results_layout.addWidget(filters_widget)
        results_layout.addWidget(results_splitter, stretch=1)

        central_splitter = QSplitter(Qt.Horizontal)
        central_splitter.addWidget(self.catalog_panel)
        central_splitter.addWidget(results_area)
        central_splitter.setStretchFactor(0, 1)
        central_splitter.setStretchFactor(1, 2)
        self.setCentralWidget(central_splitter)

        self.statusBar().addPermanentWidget(ResourceWidget(self.jobs, self))
        self.statusBar().showMessage("Prêt")

    def _wire_signals(self) -> None:
        self.catalog_panel.run_requested.connect(self._on_run_requested)
        self.catalog_panel.run_remote_requested.connect(self._on_run_remote_requested)

        self.jobs.job_started.connect(self.console_panel.add_job_tab)
        self.jobs.job_output.connect(self.console_panel.append_output)
        self.jobs.job_finished.connect(self._on_job_finished)
        self.jobs.queue_changed.connect(self.console_panel.set_progress)
        self.console_panel.kill_requested.connect(self.jobs.kill)

        self.targets_panel.project_changed.connect(self._on_project_changed)

        self.history_panel.view_output_requested.connect(self._on_view_run_output)
        self.history_panel.filter_results_requested.connect(self.proxy.set_run_filter)
        self.history_panel.clear_filter_requested.connect(lambda: self.proxy.set_run_filter(None))
        self.history_panel.compare_runs_requested.connect(self._open_run_diff)

    def _update_risk_filter(self) -> None:
        allowed = {risk for risk, cb in self.risk_checks.items() if cb.isChecked()}
        self.proxy.set_risk_filter(allowed if allowed != set(RISK_LEVELS) else None)

    # ─── Lancement de jobs ───────────────────────────────────────────────────

    def _on_run_remote_requested(self, tool_ids: list[str]) -> None:
        dialog = RemoteConnectDialog(self)
        if dialog.exec() != QDialog.Accepted:
            return
        self._on_run_requested(tool_ids, ssh_params=dialog.ssh_params())

    def _on_run_requested(self, tool_ids: list[str], ssh_params: dict | None = None) -> None:
        checked_targets = self.targets_panel.checked_targets()
        enqueued = 0
        skipped: list[str] = []

        for tool_id in tool_ids:
            spec = self.tools[tool_id]
            if spec.input_mode == "target":
                matching = [t for t in checked_targets if target_type_matches(t["type"], spec.target_type)]
                if not matching:
                    skipped.append(f"{tool_id} (aucune cible cochée de type {spec.target_type})")
                    continue
                port = None
                if spec.port_flag:
                    port, ok = QInputDialog.getInt(
                        self, f"Port — {tool_id}", "Port :",
                        value=spec.default_port or 1, minValue=1, maxValue=65535,
                    )
                    if not ok:
                        port = spec.default_port
                for t in matching:
                    self.jobs.enqueue(spec, value=t["value"], target_id=t["id"], port=port, ssh_params=ssh_params)
                    enqueued += 1
            else:
                dialog = ParamFormDialog(spec, checked_targets, self)
                if dialog.exec() != QDialog.Accepted:
                    continue
                value = dialog.get_value()
                self.jobs.enqueue(spec, value=value, target_id=None, timeout_s=dialog.get_timeout(),
                                   ssh_params=ssh_params)
                enqueued += 1

        if skipped:
            QMessageBox.warning(self, "Scripts ignorés", "Non lancés :\n" + "\n".join(skipped))
        if enqueued:
            self.console_panel.set_progress(self.jobs.done_count(), self.jobs.total_count())
            self.statusBar().showMessage(f"{enqueued} job(s) en file")

    def _on_job_finished(self, run_id: int, status: str, findings_count: int) -> None:
        self.console_panel.mark_finished(run_id, status)
        self.results_model.refresh(self.targets_panel.current_project_id())
        self.history_panel.reload()

        run = self.store.get_run(run_id)
        if run is None:
            return
        tool_id = run["tool_id"]
        chain_type = CHAIN_TARGET_TYPE.get(tool_id)
        if chain_type and status == "ok" and findings_count > 0:
            if self.auto_chain_action.isChecked():
                self._auto_chain(run_id, tool_id, chain_type)
            else:
                self._offer_chaining(run_id, tool_id, chain_type)

    def _auto_chain(self, run_id: int, tool_id: str, chain_type: str) -> None:
        """Ajoute automatiquement les cibles chaînables ET relance les outils
        listés dans AUTO_CHAIN_NEXT_TOOLS sur ces nouvelles cibles, sans
        confirmation — voir le réglage Paramètres > Chaînage automatique."""
        rows = self.store.get_findings_for_run(run_id)
        candidates = sorted({r["name"] for r in rows if r["name"]})
        if not candidates:
            return
        project_id = self.targets_panel.current_project_id()
        added = self.targets_panel.add_chained_targets([(v, chain_type) for v in candidates], run_id)
        if not added:
            return

        new_targets = [t for t in self.store.list_targets(project_id) if t["source_run_id"] == run_id]
        enqueued = 0
        for next_tool_id in AUTO_CHAIN_NEXT_TOOLS.get(tool_id, []):
            spec = self.tools.get(next_tool_id)
            if spec is None or spec.input_mode != "target":
                continue
            for t in new_targets:
                if target_type_matches(t["type"], spec.target_type):
                    self.jobs.enqueue(spec, value=t["value"], target_id=t["id"], port=spec.default_port)
                    enqueued += 1

        message = f"{added} cible(s) ajoutée(s) automatiquement depuis {tool_id}"
        if enqueued:
            message += f" — {enqueued} job(s) enchaîné(s) lancé(s) automatiquement"
            self.console_panel.set_progress(self.jobs.done_count(), self.jobs.total_count())
        self.statusBar().showMessage(message)

    def _offer_chaining(self, run_id: int, tool_id: str, chain_type: str) -> None:
        rows = self.store.get_findings_for_run(run_id)
        candidates = sorted({r["name"] for r in rows if r["name"]})
        if not candidates:
            return
        dialog = ChainDialog(tool_id, candidates, self)
        if dialog.exec() != QDialog.Accepted:
            return
        selected = dialog.selected_values()
        added = self.targets_panel.add_chained_targets([(v, chain_type) for v in selected], run_id)
        if added:
            self.statusBar().showMessage(f"{added} cible(s) ajoutée(s) depuis {tool_id}")

    # ─── Résultats / projet ──────────────────────────────────────────────────

    def _on_project_changed(self, project_id) -> None:
        self.results_model.refresh(project_id)
        self.detail_pane.set_finding(None)
        self.history_panel.set_project(project_id)

    def _on_view_run_output(self, run_id: int) -> None:
        RunOutputDialog(self.store, run_id, self).exec()

    def _open_run_diff(self) -> None:
        project_id = self.targets_panel.current_project_id()
        if project_id is None:
            return
        RunDiffDialog(self.store, project_id, self).exec()

    def _show_results_context_menu(self, pos) -> None:
        index = self.results_table.indexAt(pos)
        if not index.isValid():
            return
        source_index = self.proxy.mapToSource(index)
        row = self.results_model.row_at(source_index.row())
        if row is None:
            return

        menu = QMenu(self)
        is_fp = bool(row["false_positive"])
        fp_action = menu.addAction("Retirer le marquage faux-positif" if is_fp else "Marquer comme faux-positif")

        risk_menu = menu.addMenu("Changer le niveau de risque")
        risk_actions = {}
        current_risk = str(row["risk"]).lower()
        for level in RISK_LEVELS:
            action = risk_menu.addAction(level.capitalize())
            action.setEnabled(level != current_risk)
            risk_actions[action] = level

        chosen = menu.exec(self.results_table.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if chosen is fp_action:
            self.store.update_finding(row["id"], false_positive=not is_fp)
        elif chosen in risk_actions:
            self.store.update_finding(row["id"], risk=risk_actions[chosen])
        self.results_model.refresh(self.targets_panel.current_project_id())

    def _on_result_selected(self, current, _previous) -> None:
        if not current.isValid():
            self.detail_pane.set_finding(None)
            return
        source_index = self.proxy.mapToSource(current)
        row = self.results_model.row_at(source_index.row())
        self.detail_pane.set_finding(row)

    # ─── Export ──────────────────────────────────────────────────────────────

    def _export_html(self) -> None:
        project_id = self.targets_panel.current_project_id()
        if project_id is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exporter en HTML", filter="HTML (*.html)")
        if not path:
            return
        export_html(self.store.list_findings(project_id), self.targets_panel.project_combo.currentText(), path)
        QMessageBox.information(self, "Export", f"Rapport HTML exporté :\n{path}")

    def _export_csv(self) -> None:
        project_id = self.targets_panel.current_project_id()
        if project_id is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exporter en CSV", filter="CSV (*.csv)")
        if not path:
            return
        export_csv(self.store.list_findings(project_id), path)
        QMessageBox.information(self, "Export", f"CSV exporté :\n{path}")

    # ─── Cycle de vie ────────────────────────────────────────────────────────

    def show_disclaimer_if_needed(self) -> bool:
        """Retourne False si l'utilisateur refuse (l'appelant doit alors fermer l'appli)."""
        settings = QSettings("PenBox", "PenBox")
        if settings.value("disclaimer_accepted", False, type=bool):
            return True
        dialog = DisclaimerDialog(self)
        if dialog.exec() != QDialog.Accepted:
            return False
        settings.setValue("disclaimer_accepted", True)
        return True

    def closeEvent(self, event) -> None:
        self.store.close()
        super().closeEvent(event)
