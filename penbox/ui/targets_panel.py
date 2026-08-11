"""Panneau gauche : projets et cibles, avec validation stricte avant ajout."""

from __future__ import annotations

import sqlite3

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QFileDialog,
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

from penbox.store import Store
from penbox.ui.fetch_dialog import FetchDialog
from penbox.validators import validate_target

TARGET_TYPES = ["host", "ip", "domain", "url", "cidr", "file", "dir", "username"]
TARGET_ID_ROLE = Qt.UserRole + 1


class TargetsPanel(QWidget):
    project_changed = Signal(object)  # project_id (int) ou None
    targets_changed = Signal()

    def __init__(self, store: Store, parent=None):
        super().__init__(parent)
        self.store = store

        self.project_combo = QComboBox()
        self.project_combo.currentIndexChanged.connect(self._on_project_selected)
        self.new_project_btn = QPushButton("Nouveau projet")
        self.new_project_btn.clicked.connect(self._create_project)
        self.delete_project_btn = QPushButton("Supprimer le projet")
        self.delete_project_btn.clicked.connect(self._delete_project)

        project_row = QHBoxLayout()
        project_row.addWidget(self.project_combo, stretch=1)
        project_row.addWidget(self.new_project_btn)
        project_row.addWidget(self.delete_project_btn)

        self.value_edit = QLineEdit()
        self.value_edit.setPlaceholderText("Valeur de la cible...")
        self.value_edit.returnPressed.connect(self._add_target)
        self.type_combo = QComboBox()
        self.type_combo.addItems(TARGET_TYPES)
        self.type_combo.currentTextChanged.connect(self._update_browse_visibility)
        self.browse_btn = QPushButton("...")
        self.browse_btn.setMaximumWidth(30)
        self.browse_btn.clicked.connect(self._browse)
        self.add_btn = QPushButton("+ Ajouter")
        self.add_btn.clicked.connect(self._add_target)

        add_row = QHBoxLayout()
        add_row.addWidget(self.value_edit, stretch=1)
        add_row.addWidget(self.type_combo)
        add_row.addWidget(self.browse_btn)
        add_row.addWidget(self.add_btn)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: #e65100;")
        self.error_label.setWordWrap(True)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Type", "Valeur", "Origine"])
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)

        self.delete_btn = QPushButton("Supprimer la sélection")
        self.delete_btn.clicked.connect(self._delete_selected)

        self.fetch_btn = QPushButton("Récupérer via SFTP...")
        self.fetch_btn.clicked.connect(self._open_fetch_dialog)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Projet"))
        layout.addLayout(project_row)
        layout.addWidget(QLabel("Cibles"))
        layout.addLayout(add_row)
        layout.addWidget(self.error_label)
        layout.addWidget(self.tree, stretch=1)
        layout.addWidget(self.delete_btn)
        layout.addWidget(self.fetch_btn)

        self._update_browse_visibility(self.type_combo.currentText())
        self.reload_projects()
        self._update_delete_project_enabled()

    # ─── Projets ─────────────────────────────────────────────────────────────

    def reload_projects(self) -> None:
        self.project_combo.blockSignals(True)
        self.project_combo.clear()
        projects = self.store.list_projects()
        for p in projects:
            self.project_combo.addItem(p["name"], p["id"])
        self.project_combo.blockSignals(False)
        if projects:
            self.project_combo.setCurrentIndex(0)
            self._on_project_selected(0)
        else:
            self.project_changed.emit(None)
        self._update_delete_project_enabled()

    def _create_project(self) -> None:
        name, ok = QInputDialog.getText(self, "Nouveau projet", "Nom du projet :")
        if not ok or not name.strip():
            return
        try:
            self.store.create_project(name.strip())
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Projet existant", "Un projet porte déjà ce nom.")
            return
        self.reload_projects()

    def _delete_project(self) -> None:
        project_id = self.current_project_id()
        if project_id is None:
            return
        name = self.project_combo.currentText()
        if QMessageBox.question(
            self, "Supprimer le projet",
            f"Supprimer définitivement le projet « {name} » ?\n\n"
            "Toutes ses cibles, ses runs et ses findings seront supprimés "
            "avec lui. Cette action est irréversible.",
        ) != QMessageBox.Yes:
            return
        self.store.delete_project(project_id)
        self.reload_projects()

    def _update_delete_project_enabled(self) -> None:
        self.delete_project_btn.setEnabled(self.current_project_id() is not None)

    def _on_project_selected(self, index: int) -> None:
        self.reload_targets()
        self.project_changed.emit(self.current_project_id())
        self._update_delete_project_enabled()

    def current_project_id(self) -> int | None:
        return self.project_combo.currentData()

    # ─── Cibles ──────────────────────────────────────────────────────────────

    def _update_browse_visibility(self, target_type: str) -> None:
        self.browse_btn.setVisible(target_type in ("file", "dir"))

    def _browse(self) -> None:
        if self.type_combo.currentText() == "dir":
            path = QFileDialog.getExistingDirectory(self, "Choisir un répertoire")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Choisir un fichier")
        if path:
            self.value_edit.setText(path)

    def _add_target(self) -> None:
        project_id = self.current_project_id()
        if project_id is None:
            self.error_label.setText("Créez d'abord un projet.")
            return
        value = self.value_edit.text().strip()
        target_type = self.type_combo.currentText()
        ok, msg = validate_target(value, target_type)
        if not ok:
            self.error_label.setText(msg)
            return
        self.error_label.setText("")
        self.store.add_target(project_id, value, target_type)
        self.value_edit.clear()
        self.reload_targets()
        self.targets_changed.emit()

    def add_chained_targets(self, values: list[tuple[str, str]], source_run_id: int) -> int:
        """Ajoute des cibles issues d'un chaînage. Retourne le nombre effectivement ajouté
        (les valeurs qui échouent la validation sont ignorées)."""
        project_id = self.current_project_id()
        if project_id is None:
            return 0
        added = 0
        for value, target_type in values:
            ok, _ = validate_target(value, target_type)
            if ok:
                self.store.add_target(project_id, value, target_type, source_run_id=source_run_id)
                added += 1
        if added:
            self.reload_targets()
            self.targets_changed.emit()
        return added

    def reload_targets(self) -> None:
        self.tree.clear()
        project_id = self.current_project_id()
        if project_id is None:
            return
        for t in self.store.list_targets(project_id):
            origin = "chaînée" if t["source_run_id"] else "manuelle"
            item = QTreeWidgetItem([t["type"], t["value"], origin])
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(0, Qt.Unchecked)
            item.setData(0, TARGET_ID_ROLE, t["id"])
            self.tree.addTopLevelItem(item)
        for col in range(3):
            self.tree.resizeColumnToContents(col)

    def _delete_selected(self) -> None:
        items = self.tree.selectedItems()
        if not items:
            return
        for item in items:
            target_id = item.data(0, TARGET_ID_ROLE)
            self.store.delete_target(target_id)
        self.reload_targets()
        self.targets_changed.emit()

    def _open_fetch_dialog(self) -> None:
        project_id = self.current_project_id()
        if project_id is None:
            self.error_label.setText("Créez d'abord un projet.")
            return
        dialog = FetchDialog(self)
        if dialog.exec() != QDialog.Accepted or dialog.result is None:
            return
        value = str(dialog.result.local_path)
        target_type = dialog.local_target_type()
        ok, msg = validate_target(value, target_type)
        if not ok:
            QMessageBox.warning(self, "Cible invalide", msg)
            return
        self.store.add_target(project_id, value, target_type, notes="récupéré via SFTP")
        self.reload_targets()
        self.targets_changed.emit()

    def checked_targets(self) -> list[sqlite3.Row]:
        project_id = self.current_project_id()
        if project_id is None:
            return []
        checked_ids = set()
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            if item.checkState(0) == Qt.Checked:
                checked_ids.add(item.data(0, TARGET_ID_ROLE))
        return [t for t in self.store.list_targets(project_id) if t["id"] in checked_ids]
