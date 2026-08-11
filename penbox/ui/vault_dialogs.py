"""Dialogues du coffre-fort d'identifiants : déverrouillage/création (mot de
passe maître) et gestion des profils de connexion SSH sauvegardés."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from penbox.vault import Profile, Vault, VaultError


class MasterPasswordDialog(QDialog):
    """mode="create" : premier usage, définit le mot de passe maître d'un
    nouveau coffre. mode="unlock" : déverrouille un coffre existant (le mot
    de passe erroné réaffiche l'erreur sans fermer, pour permettre un
    nouvel essai)."""

    def __init__(self, mode: str, vault: Vault, parent=None):
        super().__init__(parent)
        self.mode = mode
        self.vault = vault
        self.setWindowTitle("Créer le coffre-fort" if mode == "create" else "Déverrouiller le coffre-fort")
        self.setMinimumWidth(380)

        intro = QLabel(
            "Choisissez un mot de passe maître pour chiffrer vos profils de "
            "connexion. Il n'est jamais stocké — s'il est perdu, les profils "
            "enregistrés seront irrécupérables."
            if mode == "create" else
            "Saisissez le mot de passe maître pour accéder aux profils enregistrés."
        )
        intro.setWordWrap(True)

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.Password)

        form = QFormLayout()
        form.addRow("Mot de passe maître :", self.password_edit)
        if mode == "create":
            form.addRow("Confirmer :", self.confirm_edit)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: #c0392b;")
        self.error_label.setWordWrap(True)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(form)
        layout.addWidget(self.error_label)
        layout.addWidget(buttons)

    def _on_accept(self) -> None:
        pwd = self.password_edit.text()
        if not pwd:
            self.error_label.setText("Le mot de passe ne peut pas être vide.")
            return
        if self.mode == "create":
            if pwd != self.confirm_edit.text():
                self.error_label.setText("Les deux mots de passe ne correspondent pas.")
                return
            self.vault.create(pwd)
            self.accept()
        else:
            try:
                self.vault.unlock(pwd)
            except VaultError as e:
                self.error_label.setText(str(e))
                self.password_edit.clear()
                self.password_edit.setFocus()
                return
            self.accept()


class ProfileEditDialog(QDialog):
    """Formulaire d'ajout/modification d'un profil — mêmes champs
    d'authentification que FetchDialog/RemoteConnectDialog."""

    def __init__(self, existing: Profile | None = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Modifier le profil" if existing else "Nouveau profil")
        self.setMinimumWidth(420)
        self._editing_name = existing.name if existing else None

        self.name_edit = QLineEdit(existing.name if existing else "")
        self.host_edit = QLineEdit(existing.host if existing else "")
        self.host_edit.setPlaceholderText("192.168.1.38")
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(existing.port if existing else 22)
        self.user_edit = QLineEdit(existing.username if existing else "")

        self.auth_combo = QComboBox()
        self.auth_combo.addItems(["Mot de passe", "Clé privée"])
        self.auth_combo.currentIndexChanged.connect(self._update_auth_stack)

        self.password_edit = QLineEdit(existing.password if existing else "")
        self.password_edit.setEchoMode(QLineEdit.Password)

        self.key_edit = QLineEdit(existing.key_path if existing else "")
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
        if existing and existing.auth_mode == "key":
            self.auth_combo.setCurrentIndex(1)

        self.python_edit = QLineEdit(existing.python_exe if existing else "python3")

        form = QFormLayout()
        form.addRow("Nom du profil :", self.name_edit)
        form.addRow("Hôte :", self.host_edit)
        form.addRow("Port :", self.port_spin)
        form.addRow("Utilisateur :", self.user_edit)
        form.addRow("Authentification :", self.auth_combo)
        form.addRow(self.auth_stack)
        form.addRow("Interpréteur Python distant :", self.python_edit)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: #c0392b;")

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.error_label)
        layout.addWidget(buttons)

    def _update_auth_stack(self, index: int) -> None:
        self.auth_stack.setCurrentIndex(index)

    def _browse_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choisir une clé privée")
        if path:
            self.key_edit.setText(path)

    def _on_accept(self) -> None:
        if not self.name_edit.text().strip() or not self.host_edit.text().strip() \
                or not self.user_edit.text().strip():
            self.error_label.setText("Nom, hôte et utilisateur sont obligatoires.")
            return
        self.accept()

    def profile(self) -> Profile:
        by_password = self.auth_combo.currentIndex() == 0
        return Profile(
            name=self.name_edit.text().strip(),
            host=self.host_edit.text().strip(),
            port=self.port_spin.value(),
            username=self.user_edit.text().strip(),
            auth_mode="password" if by_password else "key",
            password=self.password_edit.text() if by_password else "",
            key_path=self.key_edit.text().strip() if not by_password else "",
            python_exe=self.python_edit.text().strip() or "python3",
        )


class ProfileManagerDialog(QDialog):
    def __init__(self, vault: Vault, parent=None):
        super().__init__(parent)
        self.vault = vault
        self.setWindowTitle("Profils de connexion SSH")
        self.setMinimumSize(520, 320)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Nom", "Hôte", "Utilisateur", "Auth"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)

        self.add_btn = QPushButton("Ajouter...")
        self.add_btn.clicked.connect(self._add)
        self.edit_btn = QPushButton("Modifier...")
        self.edit_btn.clicked.connect(self._edit)
        self.delete_btn = QPushButton("Supprimer")
        self.delete_btn.clicked.connect(self._delete)

        btn_row = QHBoxLayout()
        btn_row.addWidget(self.add_btn)
        btn_row.addWidget(self.edit_btn)
        btn_row.addWidget(self.delete_btn)
        btn_row.addStretch(1)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)

        layout = QVBoxLayout(self)
        layout.addWidget(self.table)
        layout.addLayout(btn_row)
        layout.addWidget(buttons)

        self._reload()

    def _reload(self) -> None:
        profiles = self.vault.list_profiles()
        self.table.setRowCount(len(profiles))
        for row, p in enumerate(profiles):
            self.table.setItem(row, 0, QTableWidgetItem(p.name))
            self.table.setItem(row, 1, QTableWidgetItem(f"{p.host}:{p.port}"))
            self.table.setItem(row, 2, QTableWidgetItem(p.username))
            self.table.setItem(row, 3, QTableWidgetItem("Clé" if p.auth_mode == "key" else "Mot de passe"))

    def _selected_name(self) -> str | None:
        rows = self.table.selectionModel().selectedRows()
        return self.table.item(rows[0].row(), 0).text() if rows else None

    def _add(self) -> None:
        dialog = ProfileEditDialog(parent=self)
        if dialog.exec() != QDialog.Accepted:
            return
        profile = dialog.profile()
        if self.vault.get_profile(profile.name) is not None:
            QMessageBox.warning(self, "Profil existant", f"Un profil nommé « {profile.name} » existe déjà.")
            return
        self.vault.save_profile(profile)
        self._reload()

    def _edit(self) -> None:
        name = self._selected_name()
        if name is None:
            return
        existing = self.vault.get_profile(name)
        dialog = ProfileEditDialog(existing=existing, parent=self)
        if dialog.exec() != QDialog.Accepted:
            return
        updated = dialog.profile()
        if updated.name != name:
            self.vault.delete_profile(name)
        self.vault.save_profile(updated)
        self._reload()

    def _delete(self) -> None:
        name = self._selected_name()
        if name is None:
            return
        if QMessageBox.question(self, "Confirmer", f"Supprimer le profil « {name} » ?") != QMessageBox.Yes:
            return
        self.vault.delete_profile(name)
        self._reload()
