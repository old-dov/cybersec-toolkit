"""Dialogue de rapatriement SFTP — récupère un fichier/dossier distant vers
.penbox_fetched/, sans geler l'UI (le transfert tourne dans un QThread)."""

from __future__ import annotations

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from penbox.fetcher import FetchError, FetchResult, fetch, sanitize_name
from penbox.ui.ssh_settings import get_ssh_mode
from penbox.ui.vault_dialogs import ProfileEditDialog
from penbox.ui.vault_session import ensure_unlocked, get_vault
from penbox.vault import Profile


class _FetchWorker(QObject):
    finished = Signal(object)  # FetchResult
    failed = Signal(str)
    progress = Signal(int, int, str)  # count, total, filename

    def __init__(self, host, port, username, remote_path, dest_name, password, key_path, mode):
        super().__init__()
        self._args = (host, port, username, remote_path, dest_name, password, key_path, mode)
        self._cancel_requested = False

    def cancel(self) -> None:
        self._cancel_requested = True

    def run(self) -> None:
        host, port, username, remote_path, dest_name, password, key_path, mode = self._args
        try:
            result = fetch(
                host, port, username, remote_path, dest_name,
                password=password, key_path=key_path, mode=mode,
                progress_cb=lambda count, total, filename: self.progress.emit(count, total, filename),
                is_cancelled=lambda: self._cancel_requested,
            )
            self.finished.emit(result)
        except FetchError as e:
            self.failed.emit(str(e))
        except Exception as e:  # garde-fou : jamais d'exception non gérée dans le thread
            self.failed.emit(f"Erreur inattendue : {e}")


class FetchDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Récupérer via SFTP")
        self.setMinimumWidth(440)

        self.result: FetchResult | None = None
        self._thread: QThread | None = None
        self._worker: _FetchWorker | None = None
        self._close_pending = False

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

        self.remote_path_edit = QLineEdit()
        self.remote_path_edit.setPlaceholderText("/home/user/dossier ou /etc/fichier.conf")
        self.remote_path_edit.textChanged.connect(self._suggest_local_name)

        self.local_name_edit = QLineEdit()

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)

        form = QFormLayout()
        form.addRow("Hôte :", self.host_edit)
        form.addRow("Port :", self.port_spin)
        form.addRow("Utilisateur :", self.user_edit)
        form.addRow("Authentification :", self.auth_combo)
        form.addRow(self.auth_stack)
        form.addRow("Chemin distant :", self.remote_path_edit)
        form.addRow("Nom local :", self.local_name_edit)

        self.fetch_btn = QPushButton("Récupérer")
        self.fetch_btn.clicked.connect(self._start_fetch)
        self.add_target_btn = QPushButton("Ajouter comme cible")
        self.add_target_btn.setEnabled(False)
        self.add_target_btn.clicked.connect(self.accept)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Close)
        self.buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(profile_row)
        layout.addLayout(form)
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.fetch_btn)
        layout.addWidget(self.add_target_btn)
        layout.addWidget(self.buttons)

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

    def _suggest_local_name(self, text: str) -> None:
        if text.strip():
            self.local_name_edit.setText(sanitize_name(text))

    def _set_busy(self, busy: bool) -> None:
        for w in (self.host_edit, self.port_spin, self.user_edit, self.auth_combo,
                   self.password_edit, self.key_edit, self.key_browse,
                   self.remote_path_edit, self.local_name_edit, self.fetch_btn):
            w.setEnabled(not busy)

    def _start_fetch(self) -> None:
        host = self.host_edit.text().strip()
        username = self.user_edit.text().strip()
        remote_path = self.remote_path_edit.text().strip()
        dest_name = self.local_name_edit.text().strip() or sanitize_name(remote_path or "fetched")

        if not host or not username or not remote_path:
            self.status_label.setText("Hôte, utilisateur et chemin distant sont obligatoires.")
            return

        password = self.password_edit.text() if self.auth_combo.currentIndex() == 0 else None
        key_path = self.key_edit.text().strip() if self.auth_combo.currentIndex() == 1 else None

        self.status_label.setText("Connexion en cours...")
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self._set_busy(True)
        self.add_target_btn.setEnabled(False)
        self.buttons.button(QDialogButtonBox.Close).setText("Annuler")

        self._thread = QThread(self)
        self._worker = _FetchWorker(host, self.port_spin.value(), username, remote_path,
                                     dest_name, password, key_path, get_ssh_mode())
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.start()

    def _on_progress(self, count: int, total: int, filename: str) -> None:
        if total > 0:
            self.progress_bar.setValue(int(count * 100 / total))
            self.status_label.setText(f"Récupération en cours... {count}/{total} fichiers ({filename})")
        else:
            self.status_label.setText(f"Récupération en cours... {count} fichier(s) ({filename})")

    def _on_finished(self, result: FetchResult) -> None:
        self.result = result
        kind = "dossier" if result.is_dir else "fichier"
        self.progress_bar.setValue(100)
        if result.cancelled:
            message = f"Annulé : {result.file_count} fichier(s) récupéré(s) avant interruption vers {result.local_path}"
        else:
            message = f"Terminé : {result.file_count} fichier(s) récupéré(s) ({kind}) vers {result.local_path}"
        if result.skipped:
            shown = result.skipped[:8]
            message += f"\n{len(result.skipped)} fichier(s) ignoré(s) (permissions/lien cassé/socket) :\n"
            message += "\n".join(shown)
            if len(result.skipped) > len(shown):
                message += f"\n... et {len(result.skipped) - len(shown)} autre(s)"
        if result.new_host_key:
            nhk = result.new_host_key
            message += (
                f"\n\n🔑 Nouvelle clé hôte approuvée pour {nhk['host']} : "
                f"{nhk['keytype']} {nhk['fingerprint']}\n"
                "Si vous ne reconnaissez pas cette empreinte, supprimez-la via "
                "Paramètres > Clés hôtes SSH."
            )
        self.status_label.setText(message)
        self._set_busy(False)
        self.buttons.button(QDialogButtonBox.Close).setText("Close")
        self.add_target_btn.setEnabled(not result.cancelled)
        self._finish_pending_close()

    def _on_failed(self, message: str) -> None:
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Échec : {message}")
        self._set_busy(False)
        self.buttons.button(QDialogButtonBox.Close).setText("Close")
        self._finish_pending_close()

    def _finish_pending_close(self) -> None:
        if self._close_pending:
            self._close_pending = False
            super().reject()

    def reject(self) -> None:
        # Un transfert (surtout un gros dossier) tourne dans un QThread ; le
        # détruire pendant qu'il tourne encore plante l'appli (Qt exige que le
        # thread soit arrêté avant que l'objet qui le possède soit détruit). On
        # demande une annulation coopérative et on ne ferme vraiment qu'une fois
        # le thread revenu proprement (voir _finish_pending_close).
        if self._thread is not None and self._thread.isRunning():
            if self._worker is not None:
                self._worker.cancel()
            self._close_pending = True
            self.status_label.setText("Annulation en cours...")
            self.buttons.button(QDialogButtonBox.Close).setEnabled(False)
            return
        super().reject()

    def local_target_type(self) -> str:
        return "dir" if (self.result and self.result.is_dir) else "file"
