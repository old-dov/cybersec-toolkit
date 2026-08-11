"""Gestion des clés hôtes SSH mémorisées (.penbox_known_hosts, voir
ssh_common.py) — consulter les empreintes approuvées et en révoquer une en
cas de changement légitime (ex. cible réinstallée)."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from penbox.ssh_common import forget_known_host, list_known_hosts


class HostKeysDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Clés hôtes SSH")
        self.setMinimumSize(560, 320)

        info = QLabel(
            "Empreintes des clés hôtes approuvées (fichier .penbox_known_hosts). "
            "Toute connexion où la clé a changé est refusée automatiquement — "
            "ne supprimez une entrée que si le changement est légitime."
        )
        info.setWordWrap(True)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Hôte", "Type de clé", "Empreinte"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)

        self.forget_btn = QPushButton("Supprimer la clé sélectionnée")
        self.forget_btn.clicked.connect(self._forget_selected)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)

        btn_row = QHBoxLayout()
        btn_row.addWidget(self.forget_btn)
        btn_row.addStretch(1)

        layout = QVBoxLayout(self)
        layout.addWidget(info)
        layout.addWidget(self.table)
        layout.addLayout(btn_row)
        layout.addWidget(buttons)

        self._reload()

    def _reload(self) -> None:
        entries = list_known_hosts()
        self.table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            self.table.setItem(row, 0, QTableWidgetItem(entry["host"]))
            self.table.setItem(row, 1, QTableWidgetItem(entry["keytype"]))
            self.table.setItem(row, 2, QTableWidgetItem(entry["fingerprint"]))

    def _forget_selected(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        host = self.table.item(rows[0].row(), 0).text()
        if QMessageBox.question(
            self, "Confirmer",
            f"Supprimer la clé hôte enregistrée pour {host} ?\n"
            "La prochaine connexion à cet hôte sera traitée comme un premier contact.",
        ) != QMessageBox.Yes:
            return
        forget_known_host(host)
        self._reload()
