"""File d'exécution des jobs basée sur QProcess — concurrence bornée, timeout par job,
stdout/stderr streamés séparément, Kill manuel. Réutilise build_argv/normalize/Store
de penbox.runner pour ne pas dupliquer la logique d'argv et de normalisation."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from PySide6.QtCore import QObject, QProcess, QProcessEnvironment, QThread, QTimer, Signal

from penbox.catalog import REPO_ROOT, ToolSpec
from penbox.normalizers import normalize
from penbox.remote_exec import RemoteExecError, RemoteExecResult, RemoteRun
from penbox.runner import RUN_ROOT, _hard_kill, build_argv
from penbox.store import Store
from penbox.ui.ssh_settings import get_ssh_mode

# Un process tué peut mettre du temps à réellement se terminer sur cette
# machine (observé avec un script bloqué sur un appel réseau, cf. runner.py).
# On escalade en taskkill forcé, puis on abandonne le suivi du process au-delà
# pour ne jamais bloquer durablement un slot de concurrence.
_KILL_ESCALATE_MS = 5_000
_KILL_GIVE_UP_MS = 20_000


@dataclass
class _JobInfo:
    run_id: int
    spec: ToolSpec
    proc: QProcess | None
    json_out_path: Path | None
    timer: QTimer | None = None
    killed: bool = False
    timed_out: bool = False
    stdout_buf: list[str] = field(default_factory=list)
    stderr_buf: list[str] = field(default_factory=list)
    # Run distant via SSH (voir remote_exec.py) au lieu d'un QProcess local.
    is_remote: bool = False
    thread: QThread | None = None
    worker: "_RemoteJobWorker | None" = None


class _RemoteJobWorker(QObject):
    """Fait tourner un RemoteRun (SSH) dans un QThread — les signaux traversent
    vers le thread GUI en connexion automatiquement mise en file (queued)."""

    output = Signal(str, str)          # stream ("stdout"/"stderr"), text
    finished = Signal(object)          # RemoteExecResult
    failed = Signal(str)

    def __init__(self, remote_run: RemoteRun):
        super().__init__()
        self.remote_run = remote_run

    def run(self) -> None:
        self.remote_run.output_cb = lambda stream, text: self.output.emit(stream, text)
        try:
            result = self.remote_run.run()
            self.finished.emit(result)
        except RemoteExecError as e:
            self.failed.emit(str(e))
        except Exception as e:  # garde-fou : jamais d'exception non gérée dans le thread
            self.failed.emit(f"Erreur inattendue : {e}")


class JobManager(QObject):
    job_started = Signal(int, str)          # run_id, tool_id
    job_output = Signal(int, str, str)       # run_id, stream ("stdout"/"stderr"), text
    job_finished = Signal(int, str, int)     # run_id, status, findings_count
    queue_changed = Signal(int, int)         # done, total

    def __init__(self, store: Store, max_concurrent: int = 3, parent=None):
        super().__init__(parent)
        self.store = store
        self.max_concurrent = max_concurrent
        self._pending: list[dict] = []
        self._running: dict[int, _JobInfo] = {}
        self._total = 0
        self._done = 0

    def reset_progress(self) -> None:
        self._total = 0
        self._done = 0

    def pending_count(self) -> int:
        return len(self._pending)

    def running_count(self) -> int:
        return len(self._running)

    def total_count(self) -> int:
        return self._total

    def done_count(self) -> int:
        return self._done

    def enqueue(self, spec: ToolSpec, value=None, target_id: int | None = None,
                timeout_s: float | None = None, port: int | None = None,
                ssh_params: dict | None = None) -> None:
        self._pending.append({
            "spec": spec, "value": value, "target_id": target_id,
            "timeout_s": timeout_s or spec.default_timeout_s, "port": port,
            "ssh_params": ssh_params,
        })
        self._total += 1
        self._try_start_next()

    def kill(self, run_id: int) -> None:
        info = self._running.get(run_id)
        if info is None:
            return
        info.killed = True
        if info.timer:
            info.timer.stop()
        if info.is_remote:
            info.worker.kill()
        elif info.proc.state() != QProcess.NotRunning:
            pid = info.proc.processId()
            info.proc.kill()
            self._schedule_kill_watchdog(run_id, pid)

    # ─── Interne ─────────────────────────────────────────────────────────────

    def _try_start_next(self) -> None:
        while self._pending and len(self._running) < self.max_concurrent:
            job = self._pending.pop(0)
            ssh_params = job.pop("ssh_params", None)
            if ssh_params is not None:
                self._start_remote_job(ssh_params=ssh_params, **job)
            else:
                self._start_job(**job)

    def _start_job(self, spec: ToolSpec, value, target_id, timeout_s: float,
                    port: int | None = None) -> None:
        params = {"value": value, "port": port} if value is not None else None
        run_id = self.store.create_run(spec.id, target_id=target_id, params=params)

        run_dir = RUN_ROOT / str(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        json_out_path = (run_dir / "output.json") if spec.json_mode != "none" else None

        argv = build_argv(spec, sys.executable, value, json_out_path, port=port)

        proc = QProcess(self)
        proc.setProcessChannelMode(QProcess.SeparateChannels)
        env = QProcessEnvironment.systemEnvironment()
        env.insert("PYTHONIOENCODING", "utf-8")
        proc.setProcessEnvironment(env)
        proc.setWorkingDirectory(str(REPO_ROOT))
        proc.setProgram(argv[0])
        proc.setArguments(argv[1:])

        info = _JobInfo(run_id=run_id, spec=spec, proc=proc, json_out_path=json_out_path)
        self._running[run_id] = info

        proc.readyReadStandardOutput.connect(lambda rid=run_id: self._on_ready_read(rid, "stdout"))
        proc.readyReadStandardError.connect(lambda rid=run_id: self._on_ready_read(rid, "stderr"))
        proc.finished.connect(lambda code, status, rid=run_id: self._on_finished(rid, code))
        proc.errorOccurred.connect(lambda err, rid=run_id: self._on_error(rid, err))

        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(lambda rid=run_id: self._on_timeout(rid))
        timer.start(max(1, int(timeout_s * 1000)))
        info.timer = timer

        self.job_started.emit(run_id, spec.id)
        proc.start()

    def _on_ready_read(self, run_id: int, stream: str) -> None:
        info = self._running.get(run_id)
        if info is None:
            return
        raw = info.proc.readAllStandardOutput() if stream == "stdout" else info.proc.readAllStandardError()
        text = bytes(raw).decode("utf-8", errors="replace")
        if not text:
            return
        (info.stdout_buf if stream == "stdout" else info.stderr_buf).append(text)
        self.job_output.emit(run_id, stream, text)

    def _on_timeout(self, run_id: int) -> None:
        info = self._running.get(run_id)
        if info is None:
            return
        info.timed_out = True
        if info.is_remote:
            info.worker.kill()
        elif info.proc.state() != QProcess.NotRunning:
            pid = info.proc.processId()
            info.proc.kill()
            self._schedule_kill_watchdog(run_id, pid)

    def _on_error(self, run_id: int, error) -> None:
        info = self._running.get(run_id)
        if info is None:
            return
        if error == QProcess.FailedToStart:
            self._on_finished(run_id, -1)

    def _schedule_kill_watchdog(self, run_id: int, pid: int) -> None:
        """proc.kill() ne garantit pas une terminaison rapide sur cette plateforme
        (observé avec un script bloqué sur un appel réseau). On escalade en
        taskkill forcé, puis on abandonne le suivi pour ne jamais bloquer
        durablement un slot de concurrence."""
        escalate = QTimer(self)
        escalate.setSingleShot(True)
        escalate.timeout.connect(lambda: self._escalate_kill(run_id, pid))
        escalate.start(_KILL_ESCALATE_MS)

        give_up = QTimer(self)
        give_up.setSingleShot(True)
        give_up.timeout.connect(lambda: self._give_up_on(run_id))
        give_up.start(_KILL_GIVE_UP_MS)

    def _escalate_kill(self, run_id: int, pid: int) -> None:
        info = self._running.get(run_id)
        if info is None or info.proc.state() == QProcess.NotRunning:
            return  # déjà terminé normalement, le signal finished a fait le ménage
        _hard_kill(pid)

    def _give_up_on(self, run_id: int) -> None:
        info = self._running.get(run_id)
        if info is None:
            return  # déjà terminé normalement
        self.job_output.emit(
            run_id, "stderr",
            "\n[PenBox] Le process ne répond pas au Kill — abandon du suivi "
            "(un arrêt manuel via le Gestionnaire des tâches peut être nécessaire).\n",
        )
        self._on_finished(run_id, -1)

    def _on_finished(self, run_id: int, exit_code: int) -> None:
        info = self._running.pop(run_id, None)
        if info is None:
            return
        if info.timer:
            info.timer.stop()

        findings_count = 0
        json_parsed_ok = False
        if not info.timed_out and info.json_out_path and info.json_out_path.exists():
            try:
                raw = json.loads(info.json_out_path.read_text(encoding="utf-8"))
                findings = normalize(info.spec.id, raw)
                self.store.add_findings(run_id, findings)
                findings_count = len(findings)
                json_parsed_ok = True
            except (json.JSONDecodeError, OSError):
                pass

        if info.timed_out:
            status = "timeout"
        elif info.killed:
            status = "killed"
        elif exit_code == 0:
            status = "ok"
        elif info.spec.nonzero_exit_ok and json_parsed_ok:
            status = "ok"
        else:
            status = "error"

        stdout = "".join(info.stdout_buf)
        stderr = "".join(info.stderr_buf)
        self.store.finish_run(
            run_id, status=status,
            output_json_path=str(info.json_out_path) if info.json_out_path else None,
            timed_out=info.timed_out, exit_code=exit_code,
            stdout=stdout[-20000:], stderr=stderr[-20000:],
        )

        self._done += 1
        self.job_finished.emit(run_id, status, findings_count)
        self.queue_changed.emit(self._done, self._total)
        self._try_start_next()

    # ─── Exécution distante (SSH) ───────────────────────────────────────────
    # Même bookkeeping/statut/normalisation que _start_job/_on_finished
    # ci-dessus, mais le transport est un QThread + RemoteRun (paramiko) au
    # lieu d'un QProcess local. Voir remote_exec.py.

    def _start_remote_job(self, spec: ToolSpec, value, target_id, timeout_s: float,
                           ssh_params: dict, port: int | None = None) -> None:
        params = {"value": value, "port": port} if value is not None else None
        run_id = self.store.create_run(spec.id, target_id=target_id, params=params)

        remote_run = RemoteRun(
            spec=spec, run_id=run_id,
            host=ssh_params["host"], port=ssh_params["port"], username=ssh_params["username"],
            password=ssh_params.get("password"), key_path=ssh_params.get("key_path"),
            value=value, python_exe=ssh_params.get("python_exe") or "python3", port_override=port,
            mode=get_ssh_mode(),
        )

        thread = QThread(self)
        worker = _RemoteJobWorker(remote_run)
        worker.moveToThread(thread)

        info = _JobInfo(run_id=run_id, spec=spec, proc=None, json_out_path=None,
                         is_remote=True, thread=thread, worker=worker)
        self._running[run_id] = info

        worker.output.connect(lambda stream, text, rid=run_id: self._on_remote_output(rid, stream, text))
        worker.finished.connect(lambda result, rid=run_id: self._on_remote_finished(rid, result))
        worker.failed.connect(lambda msg, rid=run_id: self._on_remote_failed(rid, msg))
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.started.connect(worker.run)

        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(lambda rid=run_id: self._on_timeout(rid))
        timer.start(max(1, int(timeout_s * 1000)))
        info.timer = timer

        self.job_started.emit(run_id, spec.id)
        thread.start()

    def _on_remote_output(self, run_id: int, stream: str, text: str) -> None:
        info = self._running.get(run_id)
        if info is None:
            return
        (info.stdout_buf if stream == "stdout" else info.stderr_buf).append(text)
        self.job_output.emit(run_id, stream, text)

    def _on_remote_finished(self, run_id: int, result: RemoteExecResult) -> None:
        info = self._running.pop(run_id, None)
        if info is None:
            return
        if info.timer:
            info.timer.stop()

        if result.new_host_key:
            nhk = result.new_host_key
            self.job_output.emit(
                run_id, "stdout",
                f"\n🔑 Nouvelle clé hôte SSH approuvée pour {nhk['host']} : "
                f"{nhk['keytype']} {nhk['fingerprint']}\n"
                "Si vous ne reconnaissez pas cette empreinte, supprimez-la via "
                "Paramètres > Clés hôtes SSH.\n"
            )

        findings_count = 0
        json_parsed_ok = False
        if not info.timed_out and result.json_local_path and result.json_local_path.exists():
            try:
                raw = json.loads(result.json_local_path.read_text(encoding="utf-8"))
                findings = normalize(info.spec.id, raw)
                self.store.add_findings(run_id, findings)
                findings_count = len(findings)
                json_parsed_ok = True
            except (json.JSONDecodeError, OSError):
                pass

        exit_code = result.exit_code
        if info.timed_out:
            status = "timeout"
        elif info.killed:
            status = "killed"
        elif exit_code == 0:
            status = "ok"
        elif info.spec.nonzero_exit_ok and json_parsed_ok:
            status = "ok"
        else:
            status = "error"

        stdout = "".join(info.stdout_buf)
        stderr = "".join(info.stderr_buf)
        self.store.finish_run(
            run_id, status=status,
            output_json_path=str(result.json_local_path) if result.json_local_path else None,
            timed_out=info.timed_out, exit_code=exit_code,
            stdout=stdout[-20000:], stderr=stderr[-20000:],
        )

        self._done += 1
        self.job_finished.emit(run_id, status, findings_count)
        self.queue_changed.emit(self._done, self._total)
        self._try_start_next()

    def _on_remote_failed(self, run_id: int, message: str) -> None:
        info = self._running.pop(run_id, None)
        if info is None:
            return
        if info.timer:
            info.timer.stop()
        self.job_output.emit(run_id, "stderr", f"\n[PenBox] {message}\n")
        self.store.finish_run(
            run_id, status="error", output_json_path=None,
            timed_out=False, exit_code=None,
            stdout="".join(info.stdout_buf)[-20000:], stderr=message[-20000:],
        )
        self._done += 1
        self.job_finished.emit(run_id, "error", 0)
        self.queue_changed.emit(self._done, self._total)
        self._try_start_next()
