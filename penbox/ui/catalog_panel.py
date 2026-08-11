"""Panneau central : arbre cochable du catalogue de scripts, groupé par catégorie."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from penbox.catalog import ToolSpec
from penbox.store import Store

CATEGORY_LABELS = {
    "recon": "Reconnaissance",
    "network": "Analyse réseau",
    "vulnassess": "Évaluation de vulnérabilités",
    "logs": "Analyse de logs",
    "crypto": "Cryptographie",
    "remediation": "Remédiation",
    "exploit": "Exploitation",
    "privesc": "Post-exploitation",
    "web": "Sécurité Web",
    "osint": "OSINT",
    "forensic": "Forensic / IR",
}

TOOL_ID_ROLE = Qt.UserRole + 1


class CatalogPanel(QWidget):
    run_requested = Signal(list)         # list[str] tool_ids
    run_remote_requested = Signal(list)  # list[str] tool_ids

    def __init__(self, tools: dict[str, ToolSpec], store: Store, parent=None):
        super().__init__(parent)
        self.tools = tools
        self.store = store

        self.playbook_combo = QComboBox()
        self.playbook_combo.addItem("— Playbook —", None)
        self._reload_playbooks()
        self.load_playbook_btn = QPushButton("Charger")
        self.load_playbook_btn.clicked.connect(self._load_playbook)
        self.save_playbook_btn = QPushButton("Enregistrer la sélection...")
        self.save_playbook_btn.clicked.connect(self._save_playbook)
        self.delete_playbook_btn = QPushButton("Supprimer")
        self.delete_playbook_btn.clicked.connect(self._delete_playbook)
        playbook_row = QHBoxLayout()
        playbook_row.addWidget(self.playbook_combo, stretch=1)
        playbook_row.addWidget(self.load_playbook_btn)
        playbook_row.addWidget(self.delete_playbook_btn)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Rechercher un script...")
        self.search.textChanged.connect(self._apply_filter)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.itemChanged.connect(self._on_item_changed)
        self.tree.currentItemChanged.connect(self._on_selection_changed)
        self._populate()

        self.desc_label = QLabel("Sélectionnez un script pour voir sa description.")
        self.desc_label.setWordWrap(True)
        self.desc_label.setStyleSheet("color: #9aa4b2; padding: 4px;")

        self.run_btn = QPushButton("▶ Lancer la sélection")
        self.run_btn.clicked.connect(self._emit_run_requested)

        self.run_remote_btn = QPushButton("🌐 Exécuter à distance (SSH)...")
        self.run_remote_btn.clicked.connect(self._emit_run_remote_requested)

        layout = QVBoxLayout(self)
        layout.addLayout(playbook_row)
        layout.addWidget(self.search)
        layout.addWidget(self.tree, stretch=1)
        layout.addWidget(self.desc_label)
        layout.addWidget(self.run_btn)
        layout.addWidget(self.save_playbook_btn)
        layout.addWidget(self.run_remote_btn)

    def _populate(self) -> None:
        by_category: dict[str, list[ToolSpec]] = {}
        for spec in self.tools.values():
            by_category.setdefault(spec.category, []).append(spec)

        for category in sorted(by_category, key=lambda c: CATEGORY_LABELS.get(c, c)):
            cat_item = QTreeWidgetItem([CATEGORY_LABELS.get(category, category)])
            cat_item.setFlags(cat_item.flags() | Qt.ItemIsAutoTristate)
            self.tree.addTopLevelItem(cat_item)
            for spec in sorted(by_category[category], key=lambda s: s.id):
                child = QTreeWidgetItem([spec.id])
                child.setFlags(child.flags() | Qt.ItemIsUserCheckable)
                child.setCheckState(0, Qt.Unchecked)
                child.setData(0, TOOL_ID_ROLE, spec.id)
                cat_item.addChild(child)
            cat_item.setExpanded(False)

    def _on_item_changed(self, item: QTreeWidgetItem, column: int) -> None:
        pass  # tristate parent géré nativement par Qt.ItemIsAutoTristate

    def _on_selection_changed(self, current: QTreeWidgetItem, _previous) -> None:
        if current is None:
            return
        tool_id = current.data(0, TOOL_ID_ROLE)
        if not tool_id:
            self.desc_label.setText("")
            return
        spec = self.tools[tool_id]
        self.desc_label.setText(
            f"<b>{spec.id}</b> — {spec.desc}<br>"
            f"<span style='color:#9aa4b2;'>mode: {spec.input_mode}"
            f"{' · cible: ' + spec.target_type if spec.target_type else ''}"
            f" · timeout par défaut: {spec.default_timeout_s}s</span>"
        )

    def _apply_filter(self, text: str) -> None:
        text = text.strip().lower()
        for i in range(self.tree.topLevelItemCount()):
            cat_item = self.tree.topLevelItem(i)
            any_visible = False
            for j in range(cat_item.childCount()):
                child = cat_item.child(j)
                tool_id = child.data(0, TOOL_ID_ROLE)
                spec = self.tools.get(tool_id)
                matches = not text or text in tool_id.lower() or (spec and text in spec.desc.lower())
                child.setHidden(not matches)
                any_visible = any_visible or matches
            cat_item.setHidden(not any_visible)

    def checked_tool_ids(self) -> list[str]:
        ids = []
        for i in range(self.tree.topLevelItemCount()):
            cat_item = self.tree.topLevelItem(i)
            for j in range(cat_item.childCount()):
                child = cat_item.child(j)
                if child.checkState(0) == Qt.Checked:
                    ids.append(child.data(0, TOOL_ID_ROLE))
        return ids

    def set_checked_tool_ids(self, tool_ids: list[str]) -> None:
        wanted = set(tool_ids)
        for i in range(self.tree.topLevelItemCount()):
            cat_item = self.tree.topLevelItem(i)
            for j in range(cat_item.childCount()):
                child = cat_item.child(j)
                child.setCheckState(0, Qt.Checked if child.data(0, TOOL_ID_ROLE) in wanted else Qt.Unchecked)

    # ─── Playbooks ───────────────────────────────────────────────────────────

    def _reload_playbooks(self) -> None:
        current = self.playbook_combo.currentData()
        self.playbook_combo.blockSignals(True)
        self.playbook_combo.clear()
        self.playbook_combo.addItem("— Playbook —", None)
        for row in self.store.list_playbooks():
            self.playbook_combo.addItem(row["name"], row["name"])
        idx = self.playbook_combo.findData(current)
        self.playbook_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.playbook_combo.blockSignals(False)

    def _load_playbook(self) -> None:
        name = self.playbook_combo.currentData()
        if not name:
            return
        tool_ids = self.store.get_playbook(name)
        if tool_ids is None:
            return
        missing = [t for t in tool_ids if t not in self.tools]
        self.set_checked_tool_ids(tool_ids)
        if missing:
            QMessageBox.information(
                self, "Playbook",
                f"« {name} » chargé. {len(missing)} script(s) du playbook n'existent plus "
                f"dans le catalogue et ont été ignorés : {', '.join(missing)}",
            )

    def _save_playbook(self) -> None:
        ids = self.checked_tool_ids()
        if not ids:
            QMessageBox.information(self, "Playbook", "Cochez d'abord au moins un script à sauvegarder.")
            return
        existing_names = [row["name"] for row in self.store.list_playbooks()]
        name, ok = QInputDialog.getText(self, "Enregistrer le playbook", "Nom du playbook :")
        name = name.strip()
        if not ok or not name:
            return
        if name in existing_names and QMessageBox.question(
            self, "Playbook existant", f"« {name} » existe déjà — le remplacer ?"
        ) != QMessageBox.Yes:
            return
        self.store.save_playbook(name, ids)
        self._reload_playbooks()
        idx = self.playbook_combo.findData(name)
        if idx >= 0:
            self.playbook_combo.setCurrentIndex(idx)

    def _delete_playbook(self) -> None:
        name = self.playbook_combo.currentData()
        if not name:
            return
        if QMessageBox.question(self, "Confirmer", f"Supprimer le playbook « {name} » ?") != QMessageBox.Yes:
            return
        self.store.delete_playbook(name)
        self._reload_playbooks()

    def _emit_run_requested(self) -> None:
        ids = self.checked_tool_ids()
        if ids:
            self.run_requested.emit(ids)

    def _emit_run_remote_requested(self) -> None:
        ids = self.checked_tool_ids()
        if ids:
            self.run_remote_requested.emit(ids)
