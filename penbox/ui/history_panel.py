"""Onglet Historique — liste les runs passés d'un projet (persistés en SQLite,
donc disponibles même après un redémarrage de PenBox), pour consulter la
sortie d'un ancien run ou filtrer le panneau Résultats sur un run précis."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from penbox.store import Store

STATUS_LABEL = {
    "ok": "✅ ok", "error": "🔴 erreur", "timeout": "🔴 timeout",
    "killed": "🔴 tué", "running": "🔵 en cours",
}


class HistoryPanel(QWidget):
    view_output_requested = Signal(int)    # run_id
    filter_results_requested = Signal(int)  # run_id
    clear_filter_requested = Signal()
    compare_runs_requested = Signal()

    def __init__(self, store: Store, parent=None):
        super().__init__(parent)
        self.store = store
        self._project_id: int | None = None

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Run", "Outil", "Cible", "Statut", "Démarré", "Findings"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.doubleClicked.connect(self._view_output)

        self.view_btn = QPushButton("Voir la sortie...")
        self.view_btn.clicked.connect(self._view_output)
        self.filter_btn = QPushButton("Filtrer les résultats sur ce run")
        self.filter_btn.clicked.connect(self._filter_results)
        self.clear_btn = QPushButton("Afficher tous les résultats")
        self.clear_btn.clicked.connect(self.clear_filter_requested.emit)
        self.compare_btn = QPushButton("Comparer deux scans...")
        self.compare_btn.clicked.connect(self.compare_runs_requested.emit)
        self.refresh_btn = QPushButton("↻ Actualiser")
        self.refresh_btn.clicked.connect(self.reload)

        btn_row = QHBoxLayout()
        btn_row.addWidget(self.view_btn)
        btn_row.addWidget(self.filter_btn)
        btn_row.addWidget(self.clear_btn)
        btn_row.addWidget(self.compare_btn)
        btn_row.addStretch(1)
        btn_row.addWidget(self.refresh_btn)

        layout = QVBoxLayout(self)
        layout.addWidget(self.table)
        layout.addLayout(btn_row)

    def set_project(self, project_id: int | None) -> None:
        self._project_id = project_id
        self.reload()

    def reload(self) -> None:
        if self._project_id is None:
            self.table.setRowCount(0)
            return
        runs = self.store.list_runs(self._project_id)
        self.table.setRowCount(len(runs))
        for row, run in enumerate(runs):
            run_item = QTableWidgetItem(f"#{run['id']}")
            run_item.setData(Qt.UserRole, run["id"])
            self.table.setItem(row, 0, run_item)
            self.table.setItem(row, 1, QTableWidgetItem(run["tool_id"]))
            self.table.setItem(row, 2, QTableWidgetItem(run["target_value"] or ""))
            self.table.setItem(row, 3, QTableWidgetItem(STATUS_LABEL.get(run["status"], run["status"])))
            self.table.setItem(row, 4, QTableWidgetItem(run["started_at"] or ""))
            self.table.setItem(row, 5, QTableWidgetItem(str(run["findings_count"])))

    def _selected_run_id(self) -> int | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        return self.table.item(rows[0].row(), 0).data(Qt.UserRole)

    def _view_output(self) -> None:
        run_id = self._selected_run_id()
        if run_id is not None:
            self.view_output_requested.emit(run_id)

    def _filter_results(self) -> None:
        run_id = self._selected_run_id()
        if run_id is not None:
            self.filter_results_requested.emit(run_id)
