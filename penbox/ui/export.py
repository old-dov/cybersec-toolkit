"""Export des findings en HTML (palette reprise de 06_Reporting/report_generator.py) et CSV."""

from __future__ import annotations

import csv
import sqlite3
from datetime import datetime
from pathlib import Path

from jinja2 import BaseLoader, Environment

HTML_TEMPLATE = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<title>PenBox — Rapport {{ project_name }}</title>
<style>
  :root { --crit:#b71c1c; --high:#e65100; --med:#f9a825; --low:#2e7d32; --info:#455a64; }
  body { background:#12161c; color:#e6e6e6; font-family: -apple-system, Segoe UI, sans-serif; margin:0; padding:32px; }
  h1 { font-size:20px; } h2 { font-size:16px; border-bottom:1px solid #2a2f3a; padding-bottom:6px; margin-top:32px; }
  table { border-collapse:collapse; width:100%; margin-top:12px; }
  th, td { text-align:left; padding:6px 10px; border-bottom:1px solid #232833; font-size:13px; }
  th { color:#9aa4b2; text-transform:uppercase; font-size:11px; }
  .badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:600; color:#fff; }
  .critical { background:var(--crit); } .high { background:var(--high); }
  .medium { background:var(--med); color:#1a1a1a; } .low { background:var(--low); } .info { background:var(--info); }
  .meta { color:#9aa4b2; font-size:12px; }
</style></head>
<body>
  <h1>PenBox — Rapport de findings</h1>
  <p class="meta">Projet : {{ project_name }} — Généré le {{ date }} — {{ findings|length }} finding(s)</p>
  {% for target, items in grouped %}
  <h2>{{ target }}</h2>
  <table>
    <tr><th>Outil</th><th>Risque</th><th>Nom</th><th>Détail</th><th>Note</th></tr>
    {% for f in items %}
    <tr>
      <td>{{ f.tool_id }}</td>
      <td><span class="badge {{ f.risk|lower }}">{{ f.risk|upper }}</span></td>
      <td>{{ f.name }}</td>
      <td>{{ f.detail }}</td>
      <td>{{ f.note }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endfor %}
</body></html>
"""


def export_html(findings: list[sqlite3.Row], project_name: str, path: str | Path) -> None:
    grouped: dict[str, list[dict]] = {}
    for f in findings:
        target = f["target_value"] or "(sans cible)"
        grouped.setdefault(target, []).append(dict(f))

    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(HTML_TEMPLATE)
    html = template.render(
        project_name=project_name,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        findings=findings,
        grouped=sorted(grouped.items()),
    )
    Path(path).write_text(html, encoding="utf-8")


def export_csv(findings: list[sqlite3.Row], path: str | Path) -> None:
    fieldnames = ["target_value", "tool_id", "category", "risk", "name", "detail", "note", "run_started_at"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in findings:
            writer.writerow({k: row[k] for k in fieldnames})
