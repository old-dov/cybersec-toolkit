"""Coffre-fort de profils de connexion SSH (host/port/user/auth) — chiffré au
repos avec Fernet, clé dérivée d'un mot de passe maître via PBKDF2HMAC (jamais
stocké). Évite de ressaisir les mêmes identifiants à chaque fetch SFTP ou
exécution distante, sans les garder en clair sur disque."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict, dataclass

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from penbox.catalog import REPO_ROOT

VAULT_PATH = REPO_ROOT / ".penbox_vault.enc"

# Recommandation OWASP (2023) pour PBKDF2-HMAC-SHA256.
_KDF_ITERATIONS = 480_000
_SALT_LEN = 16


class VaultError(Exception):
    pass


class VaultLockedError(VaultError):
    pass


@dataclass
class Profile:
    name: str
    host: str
    port: int = 22
    username: str = ""
    auth_mode: str = "password"  # "password" | "key"
    password: str = ""
    key_path: str = ""
    python_exe: str = "python3"


def _derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_KDF_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


class Vault:
    """Coffre déchiffré en mémoire pour la durée de la session — jamais
    persisté en clair. Une seule instance est partagée par l'UI (voir
    penbox.ui.vault_session) pour ne demander le mot de passe maître qu'une
    fois par lancement de l'application."""

    def __init__(self):
        self._profiles: dict[str, Profile] = {}
        self._key: bytes | None = None
        self._salt: bytes | None = None

    @staticmethod
    def exists() -> bool:
        return VAULT_PATH.exists()

    @property
    def unlocked(self) -> bool:
        return self._key is not None

    def create(self, master_password: str) -> None:
        """Crée un nouveau coffre vide protégé par ce mot de passe maître
        (écrase un éventuel coffre existant — l'appelant doit confirmer)."""
        self._salt = os.urandom(_SALT_LEN)
        self._key = _derive_key(master_password, self._salt)
        self._profiles = {}
        self._save()

    def unlock(self, master_password: str) -> None:
        if not VAULT_PATH.exists():
            raise VaultError("Aucun coffre existant — créez-en un d'abord.")
        raw = VAULT_PATH.read_bytes()
        salt, token = raw[:_SALT_LEN], raw[_SALT_LEN:]
        key = _derive_key(master_password, salt)
        try:
            plaintext = Fernet(key).decrypt(token)
        except InvalidToken as e:
            raise VaultError("Mot de passe maître incorrect.") from e
        data = json.loads(plaintext.decode("utf-8"))
        self._salt = salt
        self._key = key
        self._profiles = {p["name"]: Profile(**p) for p in data}

    def lock(self) -> None:
        self._key = None
        self._salt = None
        self._profiles = {}

    def _save(self) -> None:
        if self._key is None or self._salt is None:
            raise VaultLockedError("Coffre verrouillé.")
        payload = json.dumps([asdict(p) for p in self._profiles.values()]).encode("utf-8")
        token = Fernet(self._key).encrypt(payload)
        VAULT_PATH.write_bytes(self._salt + token)

    def list_profiles(self) -> list[Profile]:
        if self._key is None:
            raise VaultLockedError("Coffre verrouillé.")
        return sorted(self._profiles.values(), key=lambda p: p.name)

    def get_profile(self, name: str) -> Profile | None:
        if self._key is None:
            raise VaultLockedError("Coffre verrouillé.")
        return self._profiles.get(name)

    def save_profile(self, profile: Profile) -> None:
        self._profiles[profile.name] = profile
        self._save()

    def delete_profile(self, name: str) -> None:
        self._profiles.pop(name, None)
        self._save()

    def change_master_password(self, new_password: str) -> None:
        if self._key is None:
            raise VaultLockedError("Coffre verrouillé.")
        self._salt = os.urandom(_SALT_LEN)
        self._key = _derive_key(new_password, self._salt)
        self._save()
