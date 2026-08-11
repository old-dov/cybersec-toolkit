"""Instance de coffre-fort (penbox.vault.Vault) partagée par toute l'UI, pour
ne demander le mot de passe maître qu'une fois par lancement de PenBox."""

from __future__ import annotations

from PySide6.QtWidgets import QWidget

from penbox.vault import Vault

_vault = Vault()


def get_vault() -> Vault:
    return _vault


def ensure_unlocked(parent: QWidget | None) -> bool:
    """S'assure que le coffre partagé est déverrouillé, en sollicitant l'UI si
    besoin (création au premier usage, saisie du mot de passe sinon). Retourne
    False si l'utilisateur annule."""
    if _vault.unlocked:
        return True

    from penbox.ui.vault_dialogs import MasterPasswordDialog  # import tardif : évite un cycle avec vault_dialogs

    mode = "unlock" if Vault.exists() else "create"
    dialog = MasterPasswordDialog(mode, _vault, parent)
    return dialog.exec() == MasterPasswordDialog.Accepted
