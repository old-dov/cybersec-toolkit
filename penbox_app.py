#!/usr/bin/env python3
"""PenBox — GUI desktop PySide6 pour la suite de scripts cybersécurité du repo.

Usage:
    .venv-penbox\\Scripts\\python.exe penbox_app.py
"""

import sys
from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from penbox.ui.main_window import MainWindow

ICON_PATH = Path(__file__).resolve().parent / "penbox.ico"


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("PenBox")
    app.setOrganizationName("PenBox")
    if ICON_PATH.exists():
        app.setWindowIcon(QIcon(str(ICON_PATH)))

    window = MainWindow()
    if not window.show_disclaimer_if_needed():
        return 0

    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
