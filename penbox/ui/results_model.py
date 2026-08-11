"""Modèle de table pour les findings — QAbstractTableModel + proxy de tri/filtre."""

from __future__ import annotations

import sqlite3

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor, QFont

from penbox.store import Store

COLUMNS = ["target_value", "tool_id", "category", "risk", "name", "detail", "run_started_at"]
HEADERS = ["Cible", "Outil", "Catégorie", "Risque", "Nom", "Détail", "Horodatage"]

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
RISK_COLORS = {
    "critical": QColor("#b71c1c"),
    "high": QColor("#e65100"),
    "medium": QColor("#f9a825"),
    "low": QColor("#2e7d32"),
    "info": QColor("#455a64"),
}
RISK_COL = COLUMNS.index("risk")


class FindingsModel(QAbstractTableModel):
    def __init__(self, store: Store, parent=None):
        super().__init__(parent)
        self.store = store
        self._rows: list[sqlite3.Row] = []
        self._project_id: int | None = None

    def refresh(self, project_id: int | None) -> None:
        self.beginResetModel()
        self._project_id = project_id
        self._rows = self.store.list_findings(project_id) if project_id is not None else []
        self.endResetModel()

    def row_at(self, row: int) -> sqlite3.Row | None:
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    # ─── QAbstractTableModel ────────────────────────────────────────────────

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return HEADERS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        col = COLUMNS[index.column()]

        is_fp = bool(row["false_positive"]) if "false_positive" in row.keys() else False

        if role == Qt.DisplayRole:
            value = row[col] if col in row.keys() else ""
            text = "" if value is None else str(value)
            return f"{text} [faux-positif]" if is_fp and col == "name" else text
        if role == Qt.ForegroundRole:
            if is_fp:
                return QColor("#6b7280")  # grisé, quelle que soit la colonne
            if col == "risk":
                return RISK_COLORS.get(str(row["risk"]).lower(), QColor("#455a64"))
        if role == Qt.FontRole and is_fp:
            font = QFont()
            font.setStrikeOut(True)
            return font
        if role == Qt.UserRole and col == "risk":
            return RISK_ORDER.get(str(row["risk"]).lower(), 99)
        return None


class FindingsFilterProxy(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._text = ""
        self._allowed_risks: set[str] | None = None  # None = tout autorisé
        self._tool_id: str | None = None
        self._run_id: int | None = None
        self._hide_false_positives = True
        self.setSortRole(Qt.DisplayRole)

    def set_hide_false_positives(self, hide: bool) -> None:
        self._hide_false_positives = hide
        self.invalidateFilter()

    def set_text_filter(self, text: str) -> None:
        self._text = text.strip().lower()
        self.invalidateFilter()

    def set_risk_filter(self, risks: set[str] | None) -> None:
        self._allowed_risks = risks
        self.invalidateFilter()

    def set_tool_filter(self, tool_id: str | None) -> None:
        self._tool_id = tool_id
        self.invalidateFilter()

    def set_run_filter(self, run_id: int | None) -> None:
        """Restreint l'affichage à un seul run — voir l'onglet Historique."""
        self._run_id = run_id
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model: FindingsModel = self.sourceModel()
        row = model.row_at(source_row)
        if row is None:
            return False

        if self._run_id is not None and row["run_id"] != self._run_id:
            return False
        if self._hide_false_positives and bool(row["false_positive"]):
            return False
        if self._allowed_risks is not None and str(row["risk"]).lower() not in self._allowed_risks:
            return False
        if self._tool_id and row["tool_id"] != self._tool_id:
            return False
        if self._text:
            haystack = " ".join(str(row[c] or "") for c in ("target_value", "tool_id", "name", "detail", "category")).lower()
            if self._text not in haystack:
                return False
        return True

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        if left.column() == RISK_COL:
            lv = self.sourceModel().data(left, Qt.UserRole)
            rv = self.sourceModel().data(right, Qt.UserRole)
            return lv < rv
        return super().lessThan(left, right)
