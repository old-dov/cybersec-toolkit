#!/usr/bin/env python3
"""
=============================================================================
 timeline_builder.py — Construction de timeline forensique
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : aucune (stdlib uniquement)

 DESCRIPTION
 -----------
 Construit une timeline chronologique des fichiers d'un répertoire basée
 sur les timestamps du système de fichiers :

   mtime  (modification)   → quand le contenu a été modifié
   ctime  (changement)     → quand les métadonnées ont changé (Linux/Win)
   atime  (accès)          → dernier accès en lecture
   btime  (création)       → macOS uniquement (st_birthtime)

 Utile pour identifier :
   - Fichiers créés/modifiés pendant une période suspecte
   - Artefacts déposés par un attaquant
   - Ordre des événements lors d'un incident

 USAGE
 -----
   python timeline_builder.py [options]

 EXEMPLES
 --------
   python timeline_builder.py --path /var/www
   python timeline_builder.py --path /home --start "2026-01-01" --end "2026-05-07"
   python timeline_builder.py --path . --suspicious-only
   python timeline_builder.py --path /tmp --format csv -o timeline.csv
   python timeline_builder.py --path . --extensions .php,.py,.sh -o events.json

 OPTIONS
 -------
   --path          Répertoire à analyser (défaut: .)
   --start         Date de début (YYYY-MM-DD)
   --end           Date de fin (YYYY-MM-DD)
   --extensions    Extensions ciblées (ex: .php,.py,.sh)
   --min-size      Taille minimale en octets
   --suspicious-only Afficher uniquement les fichiers suspects
   --format        Format de sortie : csv ou json (défaut: json)
   -o, --output    Fichier de sortie
   --no-atime      Ignorer les timestamps d'accès (bruyants)

 AVERTISSEMENT LÉGAL
 -------------------
 Cet outil est réservé à l'investigation forensique légale.
=============================================================================
"""

import argparse
import csv
import io
import json
import os
import platform
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

def green(t):  return f"{Fore.GREEN}{t}{Style.RESET_ALL}" if COLOR else t
def yellow(t): return f"{Fore.YELLOW}{t}{Style.RESET_ALL}" if COLOR else t
def red(t):    return f"{Fore.RED}{t}{Style.RESET_ALL}" if COLOR else t
def cyan(t):   return f"{Fore.CYAN}{t}{Style.RESET_ALL}" if COLOR else t
def bold(t):   return f"{Style.BRIGHT}{t}{Style.RESET_ALL}" if COLOR else t
def dim(t):    return f"{Style.DIM}{t}{Style.RESET_ALL}" if COLOR else t

# ─── Heuristiques de suspicion ────────────────────────────────────────────────

SUSPICIOUS_EXTENSIONS = {
    ".php", ".php3", ".php5", ".phtml",  # webshells
    ".asp", ".aspx", ".ashx",
    ".jsp", ".jspx",
    ".sh", ".bash", ".ksh",             # scripts shell
    ".py", ".pl", ".rb",
    ".exe", ".dll", ".so",              # binaires
    ".bat", ".cmd", ".ps1", ".vbs",
    ".cgi",
}

SUSPICIOUS_NAMES = {
    "cmd.php", "shell.php", "c99.php", "r57.php", "webshell.php",
    ".htaccess", ".htpasswd",
    "passwd", "shadow", "sudoers",
    "id_rsa", "id_dsa", "authorized_keys",
    ".bash_history", ".zsh_history",
    "mimikatz", "meterpreter",
}

SUSPICIOUS_PATHS = {
    "/tmp", "/dev/shm", "/var/tmp",
    "C:\\Windows\\Temp", "C:\\Temp",
}


def is_suspicious(path: Path, st: os.stat_result) -> list:
    """Retourne une liste de raisons de suspicion."""
    reasons = []
    ext = path.suffix.lower()
    name = path.name.lower()

    if ext in SUSPICIOUS_EXTENSIONS:
        reasons.append(f"extension suspecte: {ext}")
    if name in SUSPICIOUS_NAMES:
        reasons.append(f"nom suspect: {name}")

    # Fichier exécutable positionné dans /tmp
    if platform.system() != "Windows":
        mode = stat.S_IMODE(st.st_mode)
        if (mode & stat.S_IXUSR) and any(
            str(path).startswith(p) for p in SUSPICIOUS_PATHS
        ):
            reasons.append("fichier exécutable dans /tmp ou /var/tmp")
        # SUID / SGID
        if mode & stat.S_ISUID:
            reasons.append("bit SUID positionné")
        if mode & stat.S_ISGID:
            reasons.append("bit SGID positionné")

    # Fichier monde-inscriptible
    if platform.system() != "Windows":
        if st.st_mode & stat.S_IWOTH:
            reasons.append("inscriptible par tous (world-writable)")

    return reasons

# ─── Collection des événements ────────────────────────────────────────────────

def collect_events(
    root: Path,
    start_dt: datetime | None,
    end_dt:   datetime | None,
    ext_filter: set | None,
    min_size: int,
    include_atime: bool,
) -> list:
    events = []
    is_mac = platform.system() == "Darwin"

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if ext_filter and path.suffix.lower() not in ext_filter:
            continue
        try:
            st = path.stat()
        except (PermissionError, OSError):
            continue
        if st.st_size < min_size:
            continue

        timestamps = {
            "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
            "ctime": datetime.fromtimestamp(st.st_ctime, tz=timezone.utc),
        }
        if include_atime:
            timestamps["atime"] = datetime.fromtimestamp(st.st_atime, tz=timezone.utc)
        if is_mac and hasattr(st, "st_birthtime"):
            timestamps["btime"] = datetime.fromtimestamp(st.st_birthtime, tz=timezone.utc)

        suspicious = is_suspicious(path, st)

        for ts_type, ts in timestamps.items():
            if start_dt and ts < start_dt:
                continue
            if end_dt and ts > end_dt:
                continue
            events.append({
                "timestamp":  ts.isoformat(),
                "ts_type":    ts_type,
                "path":       str(path),
                "name":       path.name,
                "size":       st.st_size,
                "suspicious": bool(suspicious),
                "reasons":    suspicious,
            })

    events.sort(key=lambda e: e["timestamp"])
    return events

# ─── Affichage ────────────────────────────────────────────────────────────────

TS_LABELS = {
    "mtime": "MOD",
    "ctime": "CHG",
    "atime": "ACC",
    "btime": "CRE",
}


def print_event(e: dict):
    ts    = e["timestamp"][:19].replace("T", " ")
    label = TS_LABELS.get(e["ts_type"], e["ts_type"])
    size  = f"{e['size']:>10,}"
    name  = e["name"]
    col = red if e["suspicious"] else dim
    flag = red(" [SUSPECT]") if e["suspicious"] else ""
    print(f"  {ts}  {yellow(label)}  {size}  {col(name)}{flag}")
    for r in e.get("reasons", []):
        print(f"    {red('→')} {r}")

# ─── Export ───────────────────────────────────────────────────────────────────

def export_csv(events: list, outfile: str):
    fields = ["timestamp", "ts_type", "path", "name", "size", "suspicious", "reasons"]
    with open(outfile, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for e in events:
            row = dict(e)
            row["reasons"] = "; ".join(e.get("reasons", []))
            w.writerow(row)


def export_json(events: list, root: str, outfile: str):
    out = {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "root":      root,
        "total":     len(events),
        "suspicious_count": sum(1 for e in events if e["suspicious"]),
        "events":    events,
    }
    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

# ─── Main ─────────────────────────────────────────────────────────────────────

def parse_date(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)


def main():
    parser = argparse.ArgumentParser(
        description="Construction de timeline forensique basée sur les timestamps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--path",        default=".",
                        help="Répertoire à analyser")
    parser.add_argument("--start",       help='Date de début (YYYY-MM-DD)')
    parser.add_argument("--end",         help='Date de fin (YYYY-MM-DD)')
    parser.add_argument("--extensions",  default="",
                        help="Extensions ciblées séparées par virgule (ex: .php,.sh)")
    parser.add_argument("--min-size",    type=int, default=0)
    parser.add_argument("--suspicious-only", action="store_true",
                        help="N'afficher que les fichiers suspects")
    parser.add_argument("--format",      choices=["json", "csv"], default="json")
    parser.add_argument("--no-atime",    action="store_true")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()

    root     = Path(args.path).resolve()
    start_dt = parse_date(args.start) if args.start else None
    end_dt   = parse_date(args.end)   if args.end   else None
    ext_filter = (
        {f".{e.strip().lstrip('.')}" for e in args.extensions.split(",") if e.strip()}
        if args.extensions else None
    )

    print(cyan("=" * 65))
    print(cyan("  Timeline Builder — Forensic File Timeline"))
    print(cyan(f"  Répertoire : {root}"))
    if start_dt: print(cyan(f"  Du         : {args.start}"))
    if end_dt:   print(cyan(f"  Au         : {args.end}"))
    print(cyan("=" * 65 + "\n"))

    print(dim("  Collecte des événements en cours..."))
    events = collect_events(
        root, start_dt, end_dt, ext_filter, args.min_size, not args.no_atime
    )

    if args.suspicious_only:
        events = [e for e in events if e["suspicious"]]

    suspects = sum(1 for e in events if e["suspicious"])
    print(f"  {len(events)} événements  |  {red(str(suspects)) if suspects else '0'} suspect(s)\n")

    # Affichage (limité à 100 lignes pour la console)
    display = events[:100]
    for e in display:
        print_event(e)
    if len(events) > 100:
        print(dim(f"\n  ... {len(events)-100} événements supplémentaires dans le fichier de sortie"))

    if args.output:
        if args.format == "csv":
            export_csv(events, args.output)
        else:
            export_json(events, str(root), args.output)
        print(green(f"\n[+] Timeline exportée : {args.output}"))
    elif not display:
        print(yellow("  Aucun événement dans la plage temporelle spécifiée."))


if __name__ == "__main__":
    main()
