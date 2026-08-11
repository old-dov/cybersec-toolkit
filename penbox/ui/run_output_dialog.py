"""Affiche la sortie stdout/stderr persistée d'un run passé (voir Store.get_run) —
seul moyen de la consulter une fois l'onglet Console d'origine fermé ou après
un redémarrage de l'app, la Console elle-même étant purement en mémoire."""

from __future__ import annotations

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QPlainTextEdit, QTabWidget, QVBoxLayout

from penbox.store import Store


class RunOutputDialog(QDialog):
    def __init__(self, store: Store, run_id: int, parent=None):
        super().__init__(parent)
        run = store.get_run(run_id)
        self.setWindowTitle(f"Sortie du run #{run_id}" + (f" — {run['tool_id']}" if run else ""))
        self.setMinimumSize(640, 420)

        layout = QVBoxLayout(self)

        if run is None:
            layout.addWidget(QLabel("Ce run n'existe plus."))
        else:
            info = QLabel(
                f"<b>{run['tool_id']}</b> — statut : {run['status']} · "
                f"démarré : {run['started_at']} · terminé : {run['finished_at'] or '—'}"
            )
            info.setWordWrap(True)
            layout.addWidget(info)

            tabs = QTabWidget()
            for label, content in (("stdout", run["stdout"] or ""), ("stderr", run["stderr"] or "")):
                edit = QPlainTextEdit(content)
                edit.setReadOnly(True)
                f = QFont("Consolas")
                f.setStyleHint(QFont.Monospace)
                edit.setFont(f)
                tabs.addTab(edit, label)
            layout.addWidget(tabs)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
