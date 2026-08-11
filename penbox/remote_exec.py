"""Exécution à distance des scripts du catalogue via SSH (paramiko).

Complète le fetch SFTP (fetcher.py) : là où fetcher.py rapatrie des fichiers
pour qu'un script local les analyse, remote_exec.py fait l'inverse — il
uploade un script du catalogue sur la cible SSH et l'y exécute directement.
Utile pour les scripts d'audit prévus pour tourner *sur* la machine cible
(privesc_checker, system_hardener, artifact_collector, patch_manager) plutôt
que pour scanner une copie locale.

La plupart des scripts d'audit local (privesc_checker, system_hardener,
artifact_collector, patch_manager, memory_dump) sont stdlib-only : un simple
upload du fichier suffit, pas besoin de venv ni de dépendances côté cible.

Attention : ce n'est PAS vrai de tout le catalogue — les outils recon/OSINT/web
qui dépendent d'un paquet tiers (whois_lookup → python-whois, subdomain_enum/
dns_analyzer → dnspython, http_headers_analyzer/sqli_detector/xss_scanner/
dir_bruteforcer/email_harvester/username_checker → requests, file_encryptor →
cryptography, metadata_cleaner/metadata_extractor → Pillow) échoueront à
l'exécution distante avec une erreur d'import, sauf si le paquet est déjà
installé sur le python3 de la cible. Ces outils-là n'ont de toute façon pas
vocation à être uploadés sur une cible — ils interrogent des services externes
(registre WHOIS, DNS, HTTP) et n'inspectent rien de local à la machine cible :
lancez-les en local contre la cible plutôt qu'à distance sur elle.
"""

from __future__ import annotations

import shlex
import stat as statmod
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import paramiko

from penbox.catalog import ToolSpec
from penbox.runner import RUN_ROOT, build_argv
from penbox.ssh_common import SSHError
from penbox.ssh_common import connect as _ssh_connect

REMOTE_RUN_ROOT = "/tmp/.penbox_remote"

# Préfixe d'une ligne injectée devant la commande réelle (voir run()) pour
# récupérer le PID distant sans dépendre d'un outil non-stdlib côté cible :
# `exec` remplace le shell par le process cible en conservant son PID, donc
# le $$ affiché juste avant est bien celui du script qui va tourner.
_PID_MARKER = "__PENBOX_PID__:"


class RemoteExecError(Exception):
    pass


@dataclass
class RemoteExecResult:
    exit_code: int | None
    stdout: str
    stderr: str
    json_local_path: Path | None
    killed: bool = False
    # Renseigné si c'est la toute première connexion approuvée pour cet hôte
    # (mode tolérant) — voir ssh_common.connect().
    new_host_key: dict | None = None


class RemoteRun:
    """Une exécution SSH annulable : connexion, upload du script, exec_command,
    streaming stdout/stderr via output_cb, rapatriement du JSON de sortie.

    Pensée pour tourner dans un QThread côté UI (voir ui/jobs.py), mais
    utilisable seule (usage synchrone, ex. tests) via .run()."""

    def __init__(self, spec: ToolSpec, run_id: int, host: str, port: int, username: str,
                 password: str | None = None, key_path: str | None = None, value=None,
                 python_exe: str = "python3", port_override: int | None = None,
                 output_cb=None, mode: str = "tolerant"):
        self.spec = spec
        self.run_id = run_id
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_path = key_path
        self.value = value
        self.python_exe = python_exe
        self.port_override = port_override
        self.output_cb = output_cb or (lambda stream, text: None)
        self.mode = mode
        self._channel: paramiko.Channel | None = None
        self._client: paramiko.SSHClient | None = None
        self._remote_pid: int | None = None
        self._killed = False

    def kill(self) -> None:
        """Ferme le canal SSH ET envoie un kill -9 explicite au PID distant
        capturé au lancement (voir _PID_MARKER dans run()).

        Fermer le canal seul ne suffit pas toujours : selon le serveur SSH et
        ce que fait le script (appel réseau bloquant, process qui ignore
        SIGHUP...), le process distant peut survivre à la fermeture du canal
        et continuer à tourner orphelin sur la cible — même défaut que
        proc.kill() côté local (cf. runner._hard_kill), donc même remède."""
        self._killed = True
        if self._channel is not None:
            try:
                self._channel.close()
            except Exception:
                pass
        if self._remote_pid is not None and self._client is not None:
            try:
                kill_chan = self._client.get_transport().open_session()
                try:
                    kill_chan.exec_command(f"kill -9 {self._remote_pid} 2>/dev/null")
                finally:
                    kill_chan.close()
            except Exception:
                pass  # transport déjà fermé, ou cible injoignable — rien de plus à tenter

    def run(self) -> RemoteExecResult:
        try:
            client, new_host_key = _ssh_connect(self.host, self.port, self.username,
                                                 self.password, self.key_path, mode=self.mode)
        except SSHError as e:
            raise RemoteExecError(str(e)) from e
        self._client = client

        try:
            try:
                sftp = client.open_sftp()
            except Exception as e:
                raise RemoteExecError(f"Ouverture SFTP échouée : {e}") from e

            try:
                remote_dir = f"{REMOTE_RUN_ROOT}/{self.run_id}-{uuid.uuid4().hex[:8]}"
                self._mkdir_p(sftp, remote_dir)

                remote_script = f"{remote_dir}/{Path(self.spec.path).name}"
                try:
                    sftp.put(str(self.spec.script_path()), remote_script)
                except OSError as e:
                    raise RemoteExecError(f"Upload du script échoué : {e}") from e

                remote_json = f"{remote_dir}/output.json" if self.spec.json_mode != "none" else None
                argv = build_argv(
                    self.spec, self.python_exe, self.value, remote_json,
                    port=self.port_override, script_path=remote_script,
                )
                command = " ".join(shlex.quote(tok) for tok in argv)
                # `exec` remplace le shell par la commande cible en conservant le
                # PID ($$ affiché juste avant) : permet à kill() de retrouver et
                # tuer le bon process côté cible même si fermer le canal ne
                # suffit pas (voir kill() ci-dessus).
                wrapped_command = f"echo {_PID_MARKER}$$; exec {command}"

                stdout_chunks: list[str] = []
                stderr_chunks: list[str] = []
                pid_pending = True
                pid_buf = ""
                try:
                    transport = client.get_transport()
                    channel = transport.open_session()
                    self._channel = channel
                    channel.exec_command(wrapped_command)

                    while True:
                        if self._killed:
                            break
                        got_data = False
                        if channel.recv_ready():
                            chunk = channel.recv(4096).decode("utf-8", errors="replace")
                            if chunk:
                                if pid_pending:
                                    pid_buf += chunk
                                    if "\n" not in pid_buf:
                                        got_data = True
                                        continue
                                    marker_line, _, rest = pid_buf.partition("\n")
                                    if marker_line.startswith(_PID_MARKER):
                                        try:
                                            self._remote_pid = int(marker_line[len(_PID_MARKER):].strip())
                                        except ValueError:
                                            pass
                                    pid_pending = False
                                    chunk = rest
                                if chunk:
                                    stdout_chunks.append(chunk)
                                    self.output_cb("stdout", chunk)
                                got_data = True
                        if channel.recv_stderr_ready():
                            chunk = channel.recv_stderr(4096).decode("utf-8", errors="replace")
                            if chunk:
                                stderr_chunks.append(chunk)
                                self.output_cb("stderr", chunk)
                                got_data = True
                        if not got_data:
                            if channel.exit_status_ready():
                                break
                            time.sleep(0.1)

                    exit_code = None if self._killed else channel.recv_exit_status()
                except Exception as e:
                    raise RemoteExecError(f"Exécution distante échouée : {e}") from e

                json_local_path = None
                if remote_json is not None and not self._killed:
                    try:
                        sftp.stat(remote_json)
                        run_dir = RUN_ROOT / str(self.run_id)
                        run_dir.mkdir(parents=True, exist_ok=True)
                        json_local_path = run_dir / "output.json"
                        sftp.get(remote_json, str(json_local_path))
                    except OSError:
                        json_local_path = None

                try:
                    self._rm_rf(sftp, remote_dir)
                except OSError:
                    pass

                return RemoteExecResult(
                    exit_code=exit_code, stdout="".join(stdout_chunks),
                    stderr="".join(stderr_chunks), json_local_path=json_local_path,
                    killed=self._killed, new_host_key=new_host_key,
                )
            finally:
                sftp.close()
        finally:
            client.close()

    @staticmethod
    def _mkdir_p(sftp: paramiko.SFTPClient, remote_dir: str) -> None:
        cur = ""
        for part in remote_dir.strip("/").split("/"):
            cur += "/" + part
            try:
                sftp.mkdir(cur)
            except OSError:
                pass  # existe déjà

    @staticmethod
    def _rm_rf(sftp: paramiko.SFTPClient, remote_dir: str) -> None:
        for entry in sftp.listdir_attr(remote_dir):
            path = f"{remote_dir}/{entry.filename}"
            if statmod.S_ISDIR(entry.st_mode):
                RemoteRun._rm_rf(sftp, path)
            else:
                sftp.remove(path)
        sftp.rmdir(remote_dir)
