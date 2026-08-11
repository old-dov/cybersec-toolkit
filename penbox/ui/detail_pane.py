"""Panneau de détail d'un finding : champs + rendu générique clé:valeur du raw_json."""

from __future__ import annotations

import json
import sqlite3

from PySide6.QtWidgets import (
    QFormLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from penbox.ui.results_model import RISK_COLORS


def _populate_tree(parent: QTreeWidgetItem | QTreeWidget, value) -> None:
    """Rendu récursif générique d'une structure JSON dans un QTreeWidget."""
    if isinstance(value, dict):
        for k, v in value.items():
            item = QTreeWidgetItem([str(k), "" if isinstance(v, (dict, list)) else str(v)])
            (parent.addChild(item) if isinstance(parent, QTreeWidgetItem) else parent.addTopLevelItem(item))
            if isinstance(v, (dict, list)):
                _populate_tree(item, v)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            item = QTreeWidgetItem([f"[{i}]", "" if isinstance(v, (dict, list)) else str(v)])
            (parent.addChild(item) if isinstance(parent, QTreeWidgetItem) else parent.addTopLevelItem(item))
            if isinstance(v, (dict, list)):
                _populate_tree(item, v)
    else:
        item = QTreeWidgetItem(["", str(value)])
        (parent.addChild(item) if isinstance(parent, QTreeWidgetItem) else parent.addTopLevelItem(item))


class DetailPane(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.name_label = QLabel("—")
        self.name_label.setStyleSheet("font-weight: bold; font-size: 13px;")
        self.risk_label = QLabel("—")
        self.category_label = QLabel("—")
        self.detail_label = QLabel("—")
        self.detail_label.setWordWrap(True)
        self.note_label = QLabel("—")
        self.note_label.setWordWrap(True)

        form = QFormLayout()
        form.addRow("Finding", self.name_label)
        form.addRow("Risque", self.risk_label)
        form.addRow("Catégorie", self.category_label)
        form.addRow("Détail", self.detail_label)
        form.addRow("Note", self.note_label)

        self.toggle_btn = QPushButton("Voir le JSON brut")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.toggled.connect(self._toggle_raw_view)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Clé", "Valeur"])
        self.tree.setColumnWidth(0, 220)

        self.raw_text = QPlainTextEdit()
        self.raw_text.setReadOnly(True)
        self.raw_text.setFont(self._mono_font())

        self.stack = QStackedWidget()
        self.stack.addWidget(self.tree)
        self.stack.addWidget(self.raw_text)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.toggle_btn)
        layout.addWidget(self.stack, stretch=1)

        self.set_finding(None)

    @staticmethod
    def _mono_font():
        from PySide6.QtGui import QFont
        f = QFont("Consolas")
        f.setStyleHint(QFont.Monospace)
        return f

    def _toggle_raw_view(self, checked: bool) -> None:
        self.stack.setCurrentIndex(1 if checked else 0)
        self.toggle_btn.setText("Voir l'arbre" if checked else "Voir le JSON brut")

    def set_finding(self, row: sqlite3.Row | None) -> None:
        self.tree.clear()
        if row is None:
            self.name_label.setText("—")
            self.risk_label.setText("—")
            self.category_label.setText("—")
            self.detail_label.setText("—")
            self.note_label.setText("—")
            self.raw_text.setPlainText("")
            return

        self.name_label.setText(str(row["name"]))
        risk = str(row["risk"] or "info")
        color = RISK_COLORS.get(risk.lower())
        self.risk_label.setText(risk.upper())
        if color:
            self.risk_label.setStyleSheet(f"color: {color.name()}; font-weight: bold;")
        self.category_label.setText(str(row["category"] or ""))
        self.detail_label.setText(str(row["detail"] or ""))
        self.note_label.setText(str(row["note"] or ""))

        raw_json = row["raw_json"]
        if raw_json:
            try:
                parsed = json.loads(raw_json)
                _populate_tree(self.tree, parsed)
                self.tree.expandToDepth(1)
                self.raw_text.setPlainText(json.dumps(parsed, indent=2, ensure_ascii=False))
            except json.JSONDecodeError:
                self.raw_text.setPlainText(str(raw_json))
        else:
            self.raw_text.setPlainText("")
