"""Exécution des scripts du catalogue en sous-processus, avec timeout et Kill manuel.

Basé sur subprocess.Popen (pas QProcess) pour rester testable en headless (Étape C) ;
la couche UI (Étape D) peut piloter ce même Popen depuis un QThread sans réécriture.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from penbox.catalog import REPO_ROOT, ToolSpec
from penbox.normalizers import normalize
from penbox.store import Store

RUN_ROOT = Path(__file__).resolve().parent.parent / ".penbox_runs"


def _hard_kill(pid: int) -> None:
    """Dernier recours si proc.kill() n'a pas suffi : sur ce type de machine, un
    process Windows bloqué dans un appel réseau peut survivre à TerminateProcess
    pendant un temps anormalement long (observé en pratique avec whois_lookup.py
    bloqué sur une requête WHOIS). taskkill /F /T est un deuxième essai, pas une
    garantie absolue."""
    if sys.platform != "win32":
        return
    try:
        subprocess.Popen(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except OSError:
        pass


def build_argv(spec: ToolSpec, python_exe: str, value, json_out_path,
                port: int | None = None, script_path: str | None = None) -> list[str]:
    """script_path surcharge le chemin local par défaut (spec.script_path()) — utilisé
    par l'exécution distante pour pointer vers le script uploadé sur la cible SSH."""
    argv = [python_exe, script_path or str(spec.script_path())]
    argv.extend(spec.extra_args)

    if spec.input_mode == "target":
        argv += [spec.target_flag, str(value)]
    elif spec.input_mode == "multi_target":
        if not isinstance(value, (list, tuple)):
            raise ValueError(f"{spec.id}: input_mode=multi_target attend une liste de valeurs")
        argv += [spec.target_flag, *[str(v) for v in value]]
    elif spec.input_mode == "file_input":
        argv += [spec.target_flag, str(value)]
    elif spec.input_mode == "payload":
        argv += [spec.target_flag, str(value)]
    elif spec.input_mode == "none":
        pass
    else:
        raise ValueError(f"{spec.id}: input_mode inconnu '{spec.input_mode}'")

    if port is not None and spec.port_flag:
        argv += [spec.port_flag, str(port)]

    if json_out_path is not None:
        if spec.json_mode == "flag":
            argv.append("--json")
        argv += [spec.output_flag, str(json_out_path)]

    return argv


@dataclass
class RunHandle:
    run_id: int
    spec: ToolSpec
    proc: subprocess.Popen
    json_out_path: Path | None
    started_at: float
    killed: bool = False


@dataclass
class RunResult:
    run_id: int
    status: str  # "ok" | "error" | "timeout" | "killed"
    timed_out: bool
    exit_code: int | None
    stdout: str
    stderr: str
    findings_count: int


def start_run(store: Store, spec: ToolSpec, value=None, target_id: int | None = None,
              python_exe: str | None = None, port: int | None = None) -> RunHandle:
    """Lance le script en sous-processus (non bloquant) et enregistre le run en base."""
    python_exe = python_exe or sys.executable
    RUN_ROOT.mkdir(parents=True, exist_ok=True)

    params = {"value": value, "port": port} if value is not None else None
    run_id = store.create_run(spec.id, target_id=target_id, params=params)

    run_dir = RUN_ROOT / str(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    json_out_path = (run_dir / "output.json") if spec.json_mode != "none" else None

    argv = build_argv(spec, python_exe, value, json_out_path, port=port)

    # Les scripts impriment parfois des caractères hors du charset de la console
    # Windows (cp1252) ; PYTHONIOENCODING évite les crashs UnicodeEncodeError côté
    # enfant, indépendamment de l'encodage utilisé ici pour lire stdout/stderr.
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}

    proc = subprocess.Popen(
        argv,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )
    return RunHandle(run_id=run_id, spec=spec, proc=proc, json_out_path=json_out_path, started_at=time.time())


def kill(handle: RunHandle) -> None:
    if handle.proc.poll() is None:
        handle.killed = True
        handle.proc.kill()


def wait_and_finish(store: Store, handle: RunHandle, timeout: float | None = None) -> RunResult:
    """Attend la fin du process (ou le timeout), parse le JSON produit, écrit les findings."""
    timeout = timeout if timeout is not None else handle.spec.default_timeout_s
    timed_out = False

    try:
        stdout, stderr = handle.proc.communicate(timeout=timeout)
        exit_code = handle.proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        handle.proc.kill()
        try:
            # kill() ne garantit pas une terminaison instantanée (ex: antivirus
            # retardant TerminateProcess sur un binaire fraîchement créé) ;
            # on borne l'attente au lieu de bloquer indéfiniment.
            stdout, stderr = handle.proc.communicate(timeout=10)
            exit_code = handle.proc.returncode
        except subprocess.TimeoutExpired:
            _hard_kill(handle.proc.pid)
            try:
                stdout, stderr = handle.proc.communicate(timeout=10)
                exit_code = handle.proc.returncode
            except subprocess.TimeoutExpired:
                stdout, stderr = "", ""
                exit_code = None

    findings_count = 0
    json_parsed_ok = False
    if not timed_out and handle.json_out_path and handle.json_out_path.exists():
        try:
            raw = json.loads(handle.json_out_path.read_text(encoding="utf-8"))
            findings = normalize(handle.spec.id, raw)
            store.add_findings(handle.run_id, findings)
            findings_count = len(findings)
            json_parsed_ok = True
        except (json.JSONDecodeError, OSError):
            pass

    if timed_out:
        status = "timeout"
    elif handle.killed:
        status = "killed"
    elif exit_code == 0:
        status = "ok"
    elif handle.spec.nonzero_exit_ok and json_parsed_ok:
        status = "ok"
    else:
        status = "error"

    store.finish_run(
        handle.run_id,
        status=status,
        output_json_path=str(handle.json_out_path) if handle.json_out_path else None,
        timed_out=timed_out,
        exit_code=exit_code,
        stdout=stdout[-20000:] if stdout else "",
        stderr=stderr[-20000:] if stderr else "",
    )
    return RunResult(
        run_id=handle.run_id, status=status, timed_out=timed_out,
        exit_code=exit_code, stdout=stdout or "", stderr=stderr or "",
        findings_count=findings_count,
    )


def run_tool_sync(store: Store, spec: ToolSpec, value=None, target_id: int | None = None,
                   timeout: float | None = None, python_exe: str | None = None,
                   port: int | None = None) -> RunResult:
    """Lance et attend un run en un seul appel — pratique pour les tests headless."""
    handle = start_run(store, spec, value=value, target_id=target_id, python_exe=python_exe, port=port)
    return wait_and_finish(store, handle, timeout=timeout)
