"""Dock bas : console à onglets par job, stdout/stderr distincts, Kill,
progression globale, recherche/filtrage (texte ou regex) avec surlignage."""

from __future__ import annotations

import re

from PySide6.QtCore import Signal
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

STATUS_ICON = {
    "running": "\U0001F535",   # bleu
    "ok": "✅",            # coche verte
    "error": "\U0001F534",     # rouge
    "timeout": "\U0001F534",
    "killed": "\U0001F534",
}

STREAM_COLORS = {"stdout": QColor("#c8d0dc"), "stderr": QColor("#e65100")}


_MATCH_BG = QColor("#ffeb3b")
_MATCH_FG = QColor("#000000")
_CURRENT_MATCH_BG = QColor("#ff9800")


class _JobTab(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        f = QFont("Consolas")
        f.setStyleHint(QFont.Monospace)
        self.setFont(f)
        self._matches: list[tuple[int, int]] = []
        self._current_match = -1

    def append_colored(self, text: str, color: QColor) -> None:
        fmt = QTextCharFormat()
        fmt.setForeground(color)
        cursor = self.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.setCharFormat(fmt)
        cursor.insertText(text)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    @property
    def match_count(self) -> int:
        return len(self._matches)

    @property
    def current_match(self) -> int:
        return self._current_match

    def highlight(self, pattern: str, use_regex: bool) -> int:
        """Recalcule les correspondances et les surligne. Retourne le nombre
        de correspondances, ou -1 si le pattern regex est invalide."""
        self._matches = []
        self._current_match = -1
        if not pattern:
            self.setExtraSelections([])
            return 0
        try:
            regex = re.compile(pattern if use_regex else re.escape(pattern), re.IGNORECASE)
        except re.error:
            self.setExtraSelections([])
            return -1

        text = self.toPlainText()
        selections = []
        for m in regex.finditer(text):
            if m.start() == m.end():
                continue  # pattern qui matche une chaîne vide (ex. "a*") : rien à surligner, évite une boucle
            self._matches.append((m.start(), m.end()))
            cursor = self.textCursor()
            cursor.setPosition(m.start())
            cursor.setPosition(m.end(), QTextCursor.MoveMode.KeepAnchor)
            fmt = QTextCharFormat()
            fmt.setBackground(_MATCH_BG)
            fmt.setForeground(_MATCH_FG)
            sel = QTextEdit.ExtraSelection()
            sel.cursor = cursor
            sel.format = fmt
            selections.append(sel)
        self.setExtraSelections(selections)
        if self._matches:
            self.goto_match(0)
        return len(self._matches)

    def goto_match(self, index: int) -> None:
        if not self._matches:
            return
        index %= len(self._matches)
        self._current_match = index
        start, end = self._matches[index]
        cursor = self.textCursor()
        cursor.setPosition(start)
        cursor.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    def next_match(self) -> None:
        if self._matches:
            self.goto_match(self._current_match + 1)

    def prev_match(self) -> None:
        if self._matches:
            self.goto_match(self._current_match - 1)


class ConsolePanel(QWidget):
    kill_requested = Signal(int)  # run_id

    def __init__(self, parent=None):
        super().__init__(parent)
        self._tabs: dict[int, _JobTab] = {}
        self._tool_ids: dict[int, str] = {}

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_label = QLabel("Jobs : 0/0")
        self.kill_btn = QPushButton("\U0001F534 Kill")
        self.kill_btn.clicked.connect(self._kill_current)

        top_row = QHBoxLayout()
        top_row.addWidget(self.progress_label)
        top_row.addWidget(self.progress_bar, stretch=1)
        top_row.addWidget(self.kill_btn)

        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self._close_tab)
        self.tab_widget.currentChanged.connect(self._apply_search)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Rechercher dans cet onglet...")
        self.search_edit.textChanged.connect(self._apply_search)
        self.search_edit.returnPressed.connect(self._search_next)
        self.regex_checkbox = QCheckBox("Regex")
        self.regex_checkbox.toggled.connect(self._apply_search)
        self.search_prev_btn = QPushButton("◀")
        self.search_prev_btn.setFixedWidth(28)
        self.search_prev_btn.clicked.connect(self._search_prev)
        self.search_next_btn = QPushButton("▶")
        self.search_next_btn.setFixedWidth(28)
        self.search_next_btn.clicked.connect(self._search_next)
        self.search_match_label = QLabel("")
        self.search_match_label.setMinimumWidth(70)

        search_row = QHBoxLayout()
        search_row.addWidget(self.search_edit, stretch=1)
        search_row.addWidget(self.regex_checkbox)
        search_row.addWidget(self.search_prev_btn)
        search_row.addWidget(self.search_next_btn)
        search_row.addWidget(self.search_match_label)

        layout = QVBoxLayout(self)
        layout.addLayout(top_row)
        layout.addWidget(self.tab_widget)
        layout.addLayout(search_row)

    def add_job_tab(self, run_id: int, tool_id: str) -> None:
        tab = _JobTab()
        self._tabs[run_id] = tab
        self._tool_ids[run_id] = tool_id
        index = self.tab_widget.addTab(tab, f"{STATUS_ICON['running']} {tool_id} #{run_id}")
        self.tab_widget.setCurrentIndex(index)

    def append_output(self, run_id: int, stream: str, text: str) -> None:
        tab = self._tabs.get(run_id)
        if tab is None:
            return
        tab.append_colored(text, STREAM_COLORS.get(stream, QColor("#c8d0dc")))
        # Un job en cours reçoit du texte en continu ; on ne recalcule le
        # surlignage que pour l'onglet affiché, pour ne pas payer ce coût sur
        # des jobs en arrière-plan que l'utilisateur ne regarde pas.
        if self.search_edit.text() and tab is self.tab_widget.currentWidget():
            self._apply_search()

    # ─── Recherche / filtrage ────────────────────────────────────────────────

    def _current_tab(self) -> _JobTab | None:
        widget = self.tab_widget.currentWidget()
        return widget if isinstance(widget, _JobTab) else None

    def _apply_search(self) -> None:
        tab = self._current_tab()
        pattern = self.search_edit.text()
        if tab is None:
            self.search_match_label.setText("")
            return
        count = tab.highlight(pattern, self.regex_checkbox.isChecked())
        if not pattern:
            self.search_match_label.setText("")
        elif count < 0:
            self.search_match_label.setText("regex invalide")
            self.search_match_label.setStyleSheet("color: #e65100;")
        elif count == 0:
            self.search_match_label.setText("0 résultat")
            self.search_match_label.setStyleSheet("")
        else:
            self.search_match_label.setText(f"{tab.current_match + 1}/{count}")
            self.search_match_label.setStyleSheet("")

    def _search_next(self) -> None:
        tab = self._current_tab()
        if tab is None:
            return
        tab.next_match()
        if tab.match_count:
            self.search_match_label.setText(f"{tab.current_match + 1}/{tab.match_count}")

    def _search_prev(self) -> None:
        tab = self._current_tab()
        if tab is None:
            return
        tab.prev_match()
        if tab.match_count:
            self.search_match_label.setText(f"{tab.current_match + 1}/{tab.match_count}")

    def mark_finished(self, run_id: int, status: str) -> None:
        tab = self._tabs.get(run_id)
        if tab is None:
            return
        index = self.tab_widget.indexOf(tab)
        if index >= 0:
            icon = STATUS_ICON.get(status, STATUS_ICON["error"])
            self.tab_widget.setTabText(index, f"{icon} {self._tool_ids.get(run_id, '?')} #{run_id} [{status}]")

    def set_progress(self, done: int, total: int) -> None:
        self.progress_label.setText(f"Jobs : {done}/{total}")
        self.progress_bar.setMaximum(max(total, 1))
        self.progress_bar.setValue(done)

    def reset_progress(self, total: int) -> None:
        self.progress_label.setText(f"Jobs : 0/{total}")
        self.progress_bar.setMaximum(max(total, 1))
        self.progress_bar.setValue(0)

    def _current_run_id(self) -> int | None:
        current = self.tab_widget.currentWidget()
        for run_id, tab in self._tabs.items():
            if tab is current:
                return run_id
        return None

    def _kill_current(self) -> None:
        run_id = self._current_run_id()
        if run_id is not None:
            self.kill_requested.emit(run_id)

    def _close_tab(self, index: int) -> None:
        widget = self.tab_widget.widget(index)
        run_id = next((rid for rid, tab in self._tabs.items() if tab is widget), None)
        if run_id is not None:
            self._tabs.pop(run_id, None)
            self._tool_ids.pop(run_id, None)
        self.tab_widget.removeTab(index)
