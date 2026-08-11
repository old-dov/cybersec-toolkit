"""Réglage global du mode de vérification de clé hôte SSH (voir ssh_common.py),
partagé entre le fetch SFTP et l'exécution distante."""

from __future__ import annotations

from PySide6.QtCore import QSettings

_ORG, _APP = "PenBox", "PenBox"


def get_ssh_mode() -> str:
    return QSettings(_ORG, _APP).value("ssh_mode", "tolerant", type=str)


def set_ssh_mode(mode: str) -> None:
    QSettings(_ORG, _APP).setValue("ssh_mode", mode)
