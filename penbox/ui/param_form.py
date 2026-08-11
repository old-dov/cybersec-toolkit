"""Formulaire de paramètres pour les scripts en mode dégradé
(input_mode: none / file_input / payload / multi_target) — pas de panneau Cibles."""

from __future__ import annotations

import sqlite3

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
)
from PySide6.QtCore import Qt

from penbox.catalog import ToolSpec, target_type_matches


class ParamFormDialog(QDialog):
    def __init__(self, spec: ToolSpec, targets: list[sqlite3.Row], parent=None):
        super().__init__(parent)
        self.spec = spec
        self.setWindowTitle(f"Paramètres — {spec.id}")
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"<b>{spec.id}</b> — {spec.desc}"))

        self._file_edit: QLineEdit | None = None
        self._payload_edit: QLineEdit | None = None
        self._target_list: QListWidget | None = None
        self._manual_edit: QLineEdit | None = None

        if spec.input_mode == "none":
            layout.addWidget(QLabel("Ce script ne nécessite aucune cible : il sera exécuté tel quel."))

        elif spec.input_mode == "file_input":
            layout.addWidget(QLabel(f"Fichier ({spec.target_flag}) :"))
            row = QHBoxLayout()
            self._file_edit = QLineEdit()
            browse = QPushButton("Parcourir...")
            browse.clicked.connect(self._browse_file)
            row.addWidget(self._file_edit, stretch=1)
            row.addWidget(browse)
            layout.addLayout(row)

        elif spec.input_mode == "payload":
            layout.addWidget(QLabel(f"Valeur ({spec.target_flag}) :"))
            self._payload_edit = QLineEdit()
            layout.addWidget(self._payload_edit)

        elif spec.input_mode == "multi_target":
            matching = [t for t in targets if target_type_matches(t["type"], spec.target_type)]
            layout.addWidget(QLabel(f"Cibles existantes (type {spec.target_type}) :"))
            self._target_list = QListWidget()
            for t in matching:
                item = QListWidgetItem(t["value"])
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Unchecked)
                self._target_list.addItem(item)
            layout.addWidget(self._target_list)
            layout.addWidget(QLabel("Ou saisir manuellement (séparé par des virgules) :"))
            self._manual_edit = QLineEdit()
            layout.addWidget(self._manual_edit)

        timeout_row = QHBoxLayout()
        timeout_row.addWidget(QLabel("Timeout (s) :"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 3600)
        self.timeout_spin.setValue(spec.default_timeout_s)
        timeout_row.addWidget(self.timeout_spin)
        timeout_row.addStretch(1)
        layout.addLayout(timeout_row)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choisir un fichier", filter="JSON (*.json);;Tous les fichiers (*)")
        if path:
            self._file_edit.setText(path)

    def get_value(self):
        if self.spec.input_mode == "none":
            return None
        if self.spec.input_mode == "file_input":
            return self._file_edit.text().strip() or None
        if self.spec.input_mode == "payload":
            return self._payload_edit.text().strip() or None
        if self.spec.input_mode == "multi_target":
            values = []
            for i in range(self._target_list.count()):
                item = self._target_list.item(i)
                if item.checkState() == Qt.Checked:
                    values.append(item.text())
            manual = self._manual_edit.text().strip()
            if manual:
                values.extend(v.strip() for v in manual.split(",") if v.strip())
            return values or None
        return None

    def get_timeout(self) -> int:
        return self.timeout_spin.value()
