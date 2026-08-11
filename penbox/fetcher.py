"""Rapatriement de fichiers/dossiers distants via SFTP.

Sert à alimenter localement les scripts qui n'opèrent que sur le système de
fichiers local (env_secrets_scanner, log_parser, metadata_extractor,
timeline_builder...) avec des artefacts issus d'une cible distante — le cas
d'usage le plus réaliste en pentest étant un accès SSH déjà obtenu sur la
cible, pas un partage réseau qu'elle offrirait spontanément.
"""

from __future__ import annotations

import re
import stat as statmod
from dataclasses import dataclass, field
from pathlib import Path

import paramiko

from penbox.catalog import REPO_ROOT
from penbox.ssh_common import SSHError
from penbox.ssh_common import connect as _ssh_connect

FETCH_ROOT = REPO_ROOT / ".penbox_fetched"

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


class FetchError(Exception):
    pass


@dataclass
class FetchResult:
    local_path: Path
    is_dir: bool
    file_count: int
    # "chemin distant: raison" pour chaque fichier qui n'a pas pu être récupéré
    # (permission refusée, lien symbolique cassé, socket/FIFO...) — le transfert
    # continue au lieu d'abandonner tout le dossier pour un seul fichier en cause.
    skipped: list[str] = field(default_factory=list)
    cancelled: bool = False
    # Renseigné si c'est la toute première connexion approuvée pour cet hôte
    # (mode tolérant) — voir ssh_common.connect().
    new_host_key: dict | None = None


def sanitize_name(name: str) -> str:
    """Nom de dossier local sûr dérivé d'un chemin distant (pas de traversée de
    chemin, pas de séparateurs)."""
    base = name.strip().rstrip("/").rsplit("/", 1)[-1] or "fetched"
    cleaned = _SAFE_NAME_RE.sub("_", base)
    return cleaned or "fetched"


def _connect(host: str, port: int, username: str, password: str | None,
             key_path: str | None, mode: str) -> tuple[paramiko.SSHClient, dict | None]:
    try:
        return _ssh_connect(host, port, username, password, key_path, mode=mode)
    except SSHError as e:
        raise FetchError(str(e)) from e


def _count_files(sftp: paramiko.SFTPClient, remote_dir: str, is_cancelled) -> int:
    """Passe préalable légère (métadonnées seules, pas de transfert) pour
    connaître le total à afficher dans la barre de progression. Un sous-dossier
    non listable (permissions) ne doit pas faire échouer tout le comptage —
    il contribuera juste 0 au total, comme s'il était vide."""
    if is_cancelled():
        return 0
    try:
        entries = sftp.listdir_attr(remote_dir)
    except OSError:
        return 0
    total = 0
    for entry in entries:
        if is_cancelled():
            break
        if statmod.S_ISDIR(entry.st_mode):
            total += _count_files(sftp, f"{remote_dir.rstrip('/')}/{entry.filename}", is_cancelled)
        else:
            total += 1
    return total


def _fetch_dir(sftp: paramiko.SFTPClient, remote_dir: str, local_dir: Path,
                progress_cb, total: int, skipped: list[str], is_cancelled, count: int = 0) -> int:
    local_dir.mkdir(parents=True, exist_ok=True)
    try:
        entries = sftp.listdir_attr(remote_dir)
    except OSError as e:
        # Sous-dossier non listable (permissions, point de montage...) : on le
        # journalise et on continue avec le reste de l'arborescence déjà en cours,
        # plutôt que de perdre tout ce qui a été récupéré jusqu'ici.
        skipped.append(f"{remote_dir}/*: {e}")
        return count
    for entry in entries:
        if is_cancelled():
            break
        remote_item = f"{remote_dir.rstrip('/')}/{entry.filename}"
        local_item = local_dir / entry.filename
        if statmod.S_ISDIR(entry.st_mode):
            count = _fetch_dir(sftp, remote_item, local_item, progress_cb, total, skipped, is_cancelled, count)
        else:
            try:
                sftp.get(remote_item, str(local_item))
                count += 1
                progress_cb(count + len(skipped), total, entry.filename)
            except OSError as e:
                # Permission refusée, lien symbolique cassé, socket/FIFO (ex.
                # ~/.gnupg/S.gpg-agent) — un fichier illisible ne doit pas faire
                # perdre tout ce qui a déjà été récupéré dans le dossier.
                skipped.append(f"{remote_item}: {e}")
                progress_cb(count + len(skipped), total, f"{entry.filename} (ignoré)")
    return count


def fetch(host: str, port: int, username: str, remote_path: str, dest_name: str,
          password: str | None = None, key_path: str | None = None,
          progress_cb=None, is_cancelled=None, mode: str = "tolerant") -> FetchResult:
    """Rapatrie un fichier ou un dossier distant (récursif) vers
    .penbox_fetched/<dest_name>/. Lève FetchError en cas d'échec.

    progress_cb(count, total, filename), appelé après chaque fichier transféré
    d'un dossier (le SFTP séquentiel fichier-par-fichier peut être lent sur un
    gros dossier ; sans ça, l'UI n'a aucun retour pendant tout le transfert).

    is_cancelled() est vérifié entre chaque fichier — permet d'interrompre
    proprement un gros transfert (la connexion SSH est toujours fermée
    normalement ensuite) plutôt que de devoir tuer le thread qui l'exécute."""
    progress_cb = progress_cb or (lambda count, total, filename: None)
    is_cancelled = is_cancelled or (lambda: False)
    client, new_host_key = _connect(host, port, username, password, key_path, mode)
    try:
        try:
            sftp = client.open_sftp()
        except Exception as e:
            raise FetchError(f"Ouverture SFTP échouée : {e}") from e

        try:
            local_dest = FETCH_ROOT / dest_name
            try:
                st = sftp.stat(remote_path)
            except FileNotFoundError as e:
                raise FetchError(f"Chemin distant introuvable : {remote_path}") from e
            except PermissionError as e:
                raise FetchError(f"Permission refusée sur : {remote_path}") from e
            except OSError as e:
                # Certains serveurs SFTP renvoient un statut générique plutôt que
                # "fichier introuvable"/"permission refusée" spécifiquement.
                raise FetchError(f"Impossible d'accéder à {remote_path} : {e}") from e

            try:
                if statmod.S_ISDIR(st.st_mode):
                    total = _count_files(sftp, remote_path, is_cancelled)
                    skipped: list[str] = []
                    count = _fetch_dir(sftp, remote_path, local_dest, progress_cb, total, skipped, is_cancelled)
                    if is_cancelled():
                        return FetchResult(local_path=local_dest, is_dir=True, file_count=count,
                                            skipped=skipped, cancelled=True, new_host_key=new_host_key)
                    if count == 0 and skipped:
                        # Rien récupéré du tout : très probablement le dossier de
                        # départ lui-même qui n'est pas listable par l'utilisateur
                        # SSH connecté (ex: /home/jean listé avec un autre compte
                        # que jean). Un message clair plutôt qu'un "0 fichier" muet.
                        raise FetchError(
                            f"Aucun fichier récupéré — {skipped[0]}"
                            + (f" (+{len(skipped) - 1} autre(s) souci)" if len(skipped) > 1 else "")
                        )
                    return FetchResult(local_path=local_dest, is_dir=True, file_count=count,
                                        skipped=skipped, new_host_key=new_host_key)
                else:
                    local_dest.parent.mkdir(parents=True, exist_ok=True)
                    sftp.get(remote_path, str(local_dest))
                    return FetchResult(local_path=local_dest, is_dir=False, file_count=1,
                                        new_host_key=new_host_key)
            except OSError as e:
                raise FetchError(f"Échec du rapatriement de {remote_path} : {e}") from e
        finally:
            sftp.close()
    finally:
        client.close()
