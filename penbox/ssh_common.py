"""Connexion SSH partagée entre le fetch SFTP (fetcher.py) et l'exécution
distante (remote_exec.py) — un seul endroit pour la politique de clé d'hôte
et le timeout de connexion.

Vérification de clé hôte façon known_hosts (TOFU) : auparavant AutoAddPolicy
acceptait n'importe quelle clé hôte sans jamais la mémoriser (un nouveau
SSHClient étant recréé à chaque connexion), donc aucune protection contre un
changement de clé (MITM, ou machine remplacée) d'une connexion à l'autre.
Désormais la clé est enregistrée dans .penbox_known_hosts au premier contact
(mode "tolerant") et toute connexion ultérieure où la clé a changé est
refusée — dans les deux modes, strict ou tolérant."""

from __future__ import annotations

import base64
import hashlib

import paramiko

from penbox.catalog import REPO_ROOT

KNOWN_HOSTS_PATH = REPO_ROOT / ".penbox_known_hosts"


class SSHError(Exception):
    pass


class HostKeyRejectedError(SSHError):
    """Clé hôte inconnue (mode strict) ou différente de celle déjà enregistrée
    (mode strict ou tolérant — indice possible de MITM)."""


def fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def list_known_hosts() -> list[dict]:
    hk = paramiko.HostKeys()
    if KNOWN_HOSTS_PATH.exists():
        hk.load(str(KNOWN_HOSTS_PATH))
    entries = []
    for host, keys_by_type in hk.items():
        for keytype, key in keys_by_type.items():
            entries.append({"host": host, "keytype": keytype, "fingerprint": fingerprint(key)})
    return entries


def forget_known_host(host: str) -> None:
    """Supprime toutes les clés enregistrées pour cet hôte — pour le cas
    légitime d'un changement de clé (réinstallation de la machine cible)."""
    hk = paramiko.HostKeys()
    if not KNOWN_HOSTS_PATH.exists():
        return
    hk.load(str(KNOWN_HOSTS_PATH))
    if host in hk:
        del hk[host]
        hk.save(str(KNOWN_HOSTS_PATH))


class _TrustPolicy(paramiko.MissingHostKeyPolicy):
    """Appliquée seulement quand la clé hôte est totalement inconnue (absente
    de .penbox_known_hosts). Un changement de clé pour un hôte déjà connu ne
    passe jamais par ici : paramiko lève directement BadHostKeyException,
    géré dans connect() ci-dessous, quel que soit le mode."""

    def __init__(self, mode: str):
        self.mode = mode
        self.new_key: dict | None = None

    def missing_host_key(self, client, hostname, key) -> None:
        fp = fingerprint(key)
        if self.mode == "strict":
            raise HostKeyRejectedError(
                f"Clé hôte inconnue pour {hostname} (mode strict) — "
                f"empreinte {key.get_name()} {fp}. Approuvez-la d'abord via "
                "Paramètres > Clés hôtes SSH, ou repassez en mode tolérant."
            )
        client.get_host_keys().add(hostname, key.get_name(), key)
        client.get_host_keys().save(str(KNOWN_HOSTS_PATH))
        self.new_key = {"host": hostname, "keytype": key.get_name(), "fingerprint": fp}


def connect(host: str, port: int, username: str,
            password: str | None, key_path: str | None,
            mode: str = "tolerant") -> tuple[paramiko.SSHClient, dict | None]:
    """Se connecte en SSH avec vérification de la clé hôte.

    Retourne (client, new_host_key) — new_host_key est un dict
    {host, keytype, fingerprint} si c'est la toute première connexion
    approuvée pour cet hôte (mode tolérant), sinon None."""
    client = paramiko.SSHClient()
    if not KNOWN_HOSTS_PATH.exists():
        KNOWN_HOSTS_PATH.touch()
    client.load_host_keys(str(KNOWN_HOSTS_PATH))
    policy = _TrustPolicy(mode)
    client.set_missing_host_key_policy(policy)
    try:
        if key_path:
            client.connect(host, port=port, username=username, key_filename=key_path, timeout=15)
        else:
            client.connect(host, port=port, username=username, password=password, timeout=15)
    except paramiko.BadHostKeyException as e:
        raise HostKeyRejectedError(
            f"⚠️ La clé hôte de {host} a changé depuis la dernière connexion "
            f"approuvée (attendu {fingerprint(e.expected_key)}, reçu "
            f"{fingerprint(e.key)}) — connexion refusée (interception "
            "possible, ou machine cible réinstallée). Si ce changement est "
            "légitime, supprimez l'entrée via Paramètres > Clés hôtes SSH."
        ) from e
    except HostKeyRejectedError:
        raise
    except Exception as e:
        raise SSHError(f"Connexion SSH échouée : {e}") from e
    return client, policy.new_key
