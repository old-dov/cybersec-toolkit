"""Dialogue de connexion SSH pour l'exécution distante (voir remote_exec.py).
Mêmes champs d'authentification que FetchDialog, plus l'interpréteur Python
distant — pas de transfert ici, juste les paramètres de connexion."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from penbox.ui.vault_dialogs import ProfileEditDialog
from penbox.ui.vault_session import ensure_unlocked, get_vault
from penbox.vault import Profile


class RemoteConnectDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Exécuter à distance via SSH")
        self.setMinimumWidth(420)

        self.load_profile_btn = QPushButton("Charger un profil...")
        self.load_profile_btn.clicked.connect(self._load_profile)
        self.save_profile_btn = QPushButton("Enregistrer comme profil...")
        self.save_profile_btn.clicked.connect(self._save_profile)
        profile_row = QHBoxLayout()
        profile_row.addWidget(self.load_profile_btn)
        profile_row.addWidget(self.save_profile_btn)
        profile_row.addStretch(1)

        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("192.168.1.38")
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(22)
        self.user_edit = QLineEdit()

        self.auth_combo = QComboBox()
        self.auth_combo.addItems(["Mot de passe", "Clé privée"])
        self.auth_combo.currentIndexChanged.connect(self._update_auth_stack)

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)

        self.key_edit = QLineEdit()
        self.key_browse = QPushButton("Parcourir...")
        self.key_browse.clicked.connect(self._browse_key)
        key_page = QWidget()
        key_page_layout = QHBoxLayout(key_page)
        key_page_layout.setContentsMargins(0, 0, 0, 0)
        key_page_layout.addWidget(self.key_edit, stretch=1)
        key_page_layout.addWidget(self.key_browse)

        self.auth_stack = QStackedWidget()
        self.auth_stack.addWidget(self.password_edit)
        self.auth_stack.addWidget(key_page)

        self.python_edit = QLineEdit()
        self.python_edit.setPlaceholderText("python3")

        form = QFormLayout()
        form.addRow("Hôte :", self.host_edit)
        form.addRow("Port :", self.port_spin)
        form.addRow("Utilisateur :", self.user_edit)
        form.addRow("Authentification :", self.auth_combo)
        form.addRow(self.auth_stack)
        form.addRow("Interpréteur Python distant :", self.python_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Se connecter et lancer")
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(profile_row)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _update_auth_stack(self, index: int) -> None:
        self.auth_stack.setCurrentIndex(index)

    def _browse_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choisir une clé privée")
        if path:
            self.key_edit.setText(path)

    def _load_profile(self) -> None:
        if not ensure_unlocked(self):
            return
        vault = get_vault()
        profiles = vault.list_profiles()
        if not profiles:
            QMessageBox.information(self, "Profils", "Aucun profil enregistré pour l'instant.")
            return
        name, ok = QInputDialog.getItem(
            self, "Charger un profil", "Profil :", [p.name for p in profiles], editable=False
        )
        if not ok:
            return
        p = vault.get_profile(name)
        self.host_edit.setText(p.host)
        self.port_spin.setValue(p.port)
        self.user_edit.setText(p.username)
        self.auth_combo.setCurrentIndex(0 if p.auth_mode == "password" else 1)
        self.password_edit.setText(p.password)
        self.key_edit.setText(p.key_path)
        self.python_edit.setText(p.python_exe)

    def _save_profile(self) -> None:
        host = self.host_edit.text().strip()
        username = self.user_edit.text().strip()
        if not host or not username:
            QMessageBox.warning(self, "Profil", "Renseignez au moins l'hôte et l'utilisateur avant d'enregistrer.")
            return
        if not ensure_unlocked(self):
            return
        by_password = self.auth_combo.currentIndex() == 0
        prefill = Profile(
            name="", host=host, port=self.port_spin.value(), username=username,
            auth_mode="password" if by_password else "key",
            password=self.password_edit.text() if by_password else "",
            key_path=self.key_edit.text().strip() if not by_password else "",
            python_exe=self.python_edit.text().strip() or "python3",
        )
        dialog = ProfileEditDialog(existing=prefill, parent=self)
        if dialog.exec() != QDialog.Accepted:
            return
        vault = get_vault()
        profile = dialog.profile()
        if vault.get_profile(profile.name) is not None and QMessageBox.question(
            self, "Profil existant", f"Un profil « {profile.name} » existe déjà — le remplacer ?"
        ) != QMessageBox.Yes:
            return
        vault.save_profile(profile)

    def _on_accept(self) -> None:
        if not self.host_edit.text().strip() or not self.user_edit.text().strip():
            return
        self.accept()

    def ssh_params(self) -> dict:
        auth_by_password = self.auth_combo.currentIndex() == 0
        return {
            "host": self.host_edit.text().strip(),
            "port": self.port_spin.value(),
            "username": self.user_edit.text().strip(),
            "password": self.password_edit.text() if auth_by_password else None,
            "key_path": self.key_edit.text().strip() if not auth_by_password else None,
            "python_exe": self.python_edit.text().strip() or "python3",
        }
