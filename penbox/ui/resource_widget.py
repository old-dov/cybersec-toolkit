"""Petit indicateur CPU/RAM/jobs actifs dans la barre de statut — aide à
calibrer la parallélisation (JobManager.max_concurrent) plutôt que de la
régler à l'aveugle."""

from __future__ import annotations

import psutil
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QHBoxLayout, QLabel, QWidget

from penbox.ui.jobs import JobManager

_REFRESH_MS = 2000


class ResourceWidget(QWidget):
    def __init__(self, jobs: JobManager, parent=None):
        super().__init__(parent)
        self.jobs = jobs

        self.cpu_label = QLabel("CPU : —")
        self.ram_label = QLabel("RAM : —")
        self.jobs_label = QLabel("Jobs actifs : 0")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 0, 4, 0)
        layout.addWidget(self.cpu_label)
        layout.addWidget(self.ram_label)
        layout.addWidget(self.jobs_label)

        # Premier appel à cpu_percent() non significatif (mesure instantanée) ;
        # on l'amorce ici pour que le premier _refresh() donne déjà une vraie
        # moyenne sur l'intervalle écoulé plutôt que 0.0.
        psutil.cpu_percent(interval=None)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(_REFRESH_MS)
        self._refresh()

    def _refresh(self) -> None:
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        self.cpu_label.setText(f"CPU : {cpu:.0f}%")
        self.ram_label.setText(f"RAM : {ram:.0f}%")
        self.jobs_label.setText(f"Jobs actifs : {self.jobs.running_count()}")
