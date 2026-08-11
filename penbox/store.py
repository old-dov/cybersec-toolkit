"""SQLite persistence layer for PenBox — projects, targets, runs, findings."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    value          TEXT NOT NULL,
    type           TEXT NOT NULL,
    notes          TEXT DEFAULT '',
    source_run_id  INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id         INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    tool_id           TEXT NOT NULL,
    status            TEXT NOT NULL,
    started_at        TEXT NOT NULL,
    finished_at       TEXT,
    output_json_path  TEXT,
    timed_out         INTEGER NOT NULL DEFAULT 0,
    params_json       TEXT,
    exit_code         INTEGER,
    stdout            TEXT,
    stderr            TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    category        TEXT NOT NULL DEFAULT '',
    risk            TEXT NOT NULL DEFAULT 'info',
    detail          TEXT DEFAULT '',
    note            TEXT DEFAULT '',
    raw_json        TEXT,
    false_positive  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS playbooks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    tool_ids   TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_targets_project ON targets(project_id);
CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    name: str
    category: str = ""
    risk: str = "info"
    detail: str = ""
    note: str = ""
    raw: dict | None = None


class Store:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._migrate()

    def _migrate(self) -> None:
        """CREATE TABLE IF NOT EXISTS n'ajoute pas de colonne à une table déjà
        existante — nécessaire pour les bases penbox.db créées avant l'ajout
        d'un champ (ex. false_positive)."""
        cols = {row["name"] for row in self.conn.execute("PRAGMA table_info(findings)")}
        if "false_positive" not in cols:
            self.conn.execute("ALTER TABLE findings ADD COLUMN false_positive INTEGER NOT NULL DEFAULT 0")
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ─── Projects ────────────────────────────────────────────────────────────

    def create_project(self, name: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO projects (name, created_at) VALUES (?, ?)", (name, _now())
        )
        self.conn.commit()
        return cur.lastrowid

    def get_or_create_project(self, name: str) -> int:
        row = self.conn.execute("SELECT id FROM projects WHERE name = ?", (name,)).fetchone()
        if row:
            return row["id"]
        return self.create_project(name)

    def list_projects(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM projects ORDER BY created_at").fetchall()

    def delete_project(self, project_id: int) -> None:
        """Supprime le projet et, par cascade (ON DELETE CASCADE dans SCHEMA),
        ses cibles, runs et findings. Les playbooks ne sont pas concernés :
        ils sont partagés entre projets, pas rattachés à l'un d'eux."""
        self.conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        self.conn.commit()

    # ─── Targets ─────────────────────────────────────────────────────────────

    def add_target(
        self,
        project_id: int,
        value: str,
        type_: str,
        notes: str = "",
        source_run_id: int | None = None,
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO targets (project_id, value, type, notes, source_run_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (project_id, value, type_, notes, source_run_id, _now()),
        )
        self.conn.commit()
        return cur.lastrowid

    def list_targets(self, project_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM targets WHERE project_id = ? ORDER BY created_at", (project_id,)
        ).fetchall()

    def delete_target(self, target_id: int) -> None:
        self.conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        self.conn.commit()

    # ─── Runs ────────────────────────────────────────────────────────────────

    def create_run(
        self,
        tool_id: str,
        target_id: int | None = None,
        params: dict | None = None,
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO runs (target_id, tool_id, status, started_at, params_json) "
            "VALUES (?, ?, 'running', ?, ?)",
            (target_id, tool_id, _now(), json.dumps(params) if params else None),
        )
        self.conn.commit()
        return cur.lastrowid

    def finish_run(
        self,
        run_id: int,
        status: str,
        output_json_path: str | None = None,
        timed_out: bool = False,
        exit_code: int | None = None,
        stdout: str | None = None,
        stderr: str | None = None,
    ) -> None:
        self.conn.execute(
            "UPDATE runs SET status = ?, finished_at = ?, output_json_path = ?, "
            "timed_out = ?, exit_code = ?, stdout = ?, stderr = ? WHERE id = ?",
            (status, _now(), output_json_path, int(timed_out), exit_code, stdout, stderr, run_id),
        )
        self.conn.commit()

    def get_run(self, run_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()

    def list_runs(self, project_id: int) -> list[sqlite3.Row]:
        """Historique des runs d'un projet, du plus récent au plus ancien,
        avec la cible et le nombre de findings de chaque run.

        Trié par id (pas started_at) : deux runs démarrés dans la même
        rafale (voir jobs.py._try_start_next) peuvent partager le même
        horodatage à la microseconde près sur cette machine, alors que id
        reflète toujours l'ordre chronologique réel."""
        return self.conn.execute(
            """
            SELECT runs.*, targets.value AS target_value, targets.type AS target_type,
                   (SELECT COUNT(*) FROM findings WHERE findings.run_id = runs.id) AS findings_count
            FROM runs
            JOIN targets ON targets.id = runs.target_id
            WHERE targets.project_id = ?
            ORDER BY runs.id DESC
            """,
            (project_id,),
        ).fetchall()

    # ─── Findings ────────────────────────────────────────────────────────────

    def add_findings(self, run_id: int, findings: list[Finding]) -> None:
        rows = [
            (
                run_id,
                f.name,
                f.category,
                f.risk,
                f.detail,
                f.note,
                json.dumps(f.raw, ensure_ascii=False) if f.raw is not None else None,
            )
            for f in findings
        ]
        self.conn.executemany(
            "INSERT INTO findings (run_id, name, category, risk, detail, note, raw_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        self.conn.commit()

    def update_finding(self, finding_id: int, *, risk: str | None = None,
                        false_positive: bool | None = None, note: str | None = None) -> None:
        fields: list[str] = []
        params: list = []
        if risk is not None:
            fields.append("risk = ?")
            params.append(risk)
        if false_positive is not None:
            fields.append("false_positive = ?")
            params.append(int(false_positive))
        if note is not None:
            fields.append("note = ?")
            params.append(note)
        if not fields:
            return
        params.append(finding_id)
        self.conn.execute(f"UPDATE findings SET {', '.join(fields)} WHERE id = ?", params)
        self.conn.commit()

    def get_findings_for_run(self, run_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM findings WHERE run_id = ? ORDER BY id", (run_id,)
        ).fetchall()

    # ─── Playbooks ───────────────────────────────────────────────────────────
    # Sélections de scripts du Catalogue sauvegardées sous un nom, pour
    # relancer d'un clic un scénario récurrent (ex. "Recon Externe Rapide").

    def save_playbook(self, name: str, tool_ids: list[str]) -> None:
        self.conn.execute(
            "INSERT INTO playbooks (name, tool_ids, created_at) VALUES (?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET tool_ids = excluded.tool_ids",
            (name, json.dumps(tool_ids), _now()),
        )
        self.conn.commit()

    def list_playbooks(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM playbooks ORDER BY name").fetchall()

    def get_playbook(self, name: str) -> list[str] | None:
        row = self.conn.execute("SELECT tool_ids FROM playbooks WHERE name = ?", (name,)).fetchone()
        return json.loads(row["tool_ids"]) if row else None

    def delete_playbook(self, name: str) -> None:
        self.conn.execute("DELETE FROM playbooks WHERE name = ?", (name,))
        self.conn.commit()

    def list_findings(self, project_id: int | None = None) -> list[sqlite3.Row]:
        query = """
            SELECT findings.*, runs.tool_id, runs.started_at AS run_started_at,
                   targets.value AS target_value, targets.type AS target_type,
                   targets.project_id AS project_id
            FROM findings
            JOIN runs ON runs.id = findings.run_id
            LEFT JOIN targets ON targets.id = runs.target_id
        """
        params: tuple = ()
        if project_id is not None:
            query += " WHERE targets.project_id = ?"
            params = (project_id,)
        query += " ORDER BY findings.id"
        return self.conn.execute(query, params).fetchall()
