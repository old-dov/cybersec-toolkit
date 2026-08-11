#!/usr/bin/env python3
"""
=============================================================================
 artifact_collector.py — Collecte d'artefacts forensiques système
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : aucune (stdlib uniquement)

 DESCRIPTION
 -----------
 Collecte des artefacts forensiques du système local de façon non intrusive.
 Aucune modification n'est apportée au système analysé.

 CATÉGORIES D'ARTEFACTS
 -----------------------
   logs       → Fichiers journaux système (/var/log, Event Logs Windows)
   cron       → Tâches planifiées (crontab, launchd, Task Scheduler)
   history    → Historiques de shells (bash, zsh, PowerShell)
   network    → Connexions actives, table de routage, DNS cache
   processes  → Processus en cours, arborescence
   users      → Comptes locaux, dernières connexions, sudo
   browser    → Chemins des historiques navigateurs (non-copiés)
   all        → Toutes les catégories

 USAGE
 -----
   python artifact_collector.py [options]

 EXEMPLES
 --------
   python artifact_collector.py                              # tout collecter
   python artifact_collector.py --categories logs,network
   python artifact_collector.py -o artifacts/ --compress
   python artifact_collector.py --categories all -o /tmp/ir/

 OPTIONS
 -------
   --categories  Catégories séparées par virgules (défaut: all)
   -o, --output  Dossier de sortie (défaut: artifacts_YYYYMMDD_HHMMSS/)
   --compress    Compresser le dossier de sortie en .zip
   --max-log-size Taille max par fichier log en Mo (défaut: 50)

 AVERTISSEMENT LÉGAL
 -------------------
 Cet outil collecte uniquement des données en lecture seule pour
 l'investigation légale. Ne l'utilisez que sur vos propres systèmes
 ou avec une autorisation écrite.
=============================================================================
"""

import argparse
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime
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

OS = platform.system()
HOME = Path.home()

# ─── Helpers ──────────────────────────────────────────────────────────────────

def run_cmd(args: list) -> str:
    """Exécute une commande et retourne sa sortie texte."""
    try:
        return subprocess.check_output(
            args, text=True, stderr=subprocess.DEVNULL, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW if OS == "Windows" else 0,
        )
    except Exception:
        return ""


def safe_read(path, max_bytes: int = 52_428_800) -> str:
    """Lit un fichier texte en limitant la taille."""
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        return f"[Lecture impossible : {e}]"


def write_artifact(out_dir: Path, name: str, content: str):
    """Écrit un artefact dans le dossier de sortie."""
    p = out_dir / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8", errors="replace")
    print(f"  {green('✓')} {name} ({len(content):,} caractères)")


def section(title: str):
    print(f"\n{cyan(bold(f'  ── {title} ──'))}")

# ─── Logs ────────────────────────────────────────────────────────────────────

def collect_logs(out_dir: Path, max_size_mb: int):
    section("Logs système")
    logs_dir = out_dir / "logs"

    if OS in ("Linux", "Darwin"):
        linux_logs = [
            "/var/log/auth.log", "/var/log/secure",
            "/var/log/syslog", "/var/log/messages",
            "/var/log/kern.log", "/var/log/dmesg",
            "/var/log/apache2/access.log", "/var/log/apache2/error.log",
            "/var/log/nginx/access.log", "/var/log/nginx/error.log",
            "/var/log/faillog", "/var/log/lastlog",
        ]
        for lp in linux_logs:
            p = Path(lp)
            if p.exists():
                write_artifact(logs_dir, p.name, safe_read(p, max_size_mb * 1_048_576))
        # macOS unified log (résumé)
        if OS == "Darwin":
            out = run_cmd(["log", "show", "--last", "1h", "--style", "compact"])
            if out:
                write_artifact(logs_dir, "macos_unified_1h.log", out)
    else:
        # Windows — chemins des journaux (ne pas copier les .evtx binaires)
        win_log_paths = [
            r"C:\Windows\System32\winevt\Logs\Security.evtx",
            r"C:\Windows\System32\winevt\Logs\System.evtx",
            r"C:\Windows\System32\winevt\Logs\Application.evtx",
        ]
        entries = []
        for lp in win_log_paths:
            p = Path(lp)
            entries.append({
                "path":   lp,
                "exists": p.exists(),
                "size":   p.stat().st_size if p.exists() else 0,
                "note":   "Utilisez l'Observateur d'événements ou Get-WinEvent pour lire ces fichiers",
            })
        write_artifact(logs_dir, "windows_eventlog_paths.json",
                       json.dumps(entries, indent=2))
        # Exporter via wevtutil (dernières 500 entrées)
        for log_name in ("Security", "System", "Application"):
            out = run_cmd(["wevtutil", "qe", log_name, "/c:500", "/f:text"])
            if out:
                write_artifact(logs_dir, f"windows_{log_name.lower()}_last500.txt", out)

# ─── Cron / Tâches planifiées ────────────────────────────────────────────────

def collect_cron(out_dir: Path):
    section("Tâches planifiées")
    cron_dir = out_dir / "cron"

    if OS == "Linux":
        for f in ["/etc/crontab", "/etc/cron.d", "/var/spool/cron"]:
            p = Path(f)
            if p.is_file():
                write_artifact(cron_dir, p.name, safe_read(p))
            elif p.is_dir():
                for cf in p.iterdir():
                    if cf.is_file():
                        write_artifact(cron_dir, f"{p.name}_{cf.name}", safe_read(cf))
        out = run_cmd(["crontab", "-l"])
        if out:
            write_artifact(cron_dir, "current_user_crontab.txt", out)

    elif OS == "Darwin":
        for agent_dir in [
            "/Library/LaunchAgents", "/Library/LaunchDaemons",
            str(HOME / "Library/LaunchAgents"),
        ]:
            p = Path(agent_dir)
            if p.is_dir():
                plists = "\n".join(str(f) for f in p.glob("*.plist"))
                if plists:
                    write_artifact(cron_dir, f"{p.name}_plists.txt", plists)

    else:
        out = run_cmd(["schtasks", "/query", "/fo", "LIST", "/v"])
        if out:
            write_artifact(cron_dir, "scheduled_tasks.txt", out)

# ─── Historiques shell ───────────────────────────────────────────────────────

def collect_history(out_dir: Path):
    section("Historiques shell")
    hist_dir = out_dir / "history"
    candidates = [
        HOME / ".bash_history",
        HOME / ".zsh_history",
        HOME / ".sh_history",
        HOME / ".python_history",
        HOME / ".mysql_history",
        HOME / ".psql_history",
    ]
    if OS == "Windows":
        # PowerShell history
        ps_hist = Path(os.environ.get("APPDATA", "")) / \
            "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"
        candidates.append(ps_hist)

    for p in candidates:
        if p.exists() and p.is_file():
            write_artifact(hist_dir, p.name, safe_read(p))

# ─── Réseau ──────────────────────────────────────────────────────────────────

def collect_network(out_dir: Path):
    section("Informations réseau")
    net_dir = out_dir / "network"

    if OS in ("Linux", "Darwin"):
        cmds = {
            "netstat_connections.txt": ["netstat", "-tnp"],
            "netstat_all.txt":         ["netstat", "-anp"],
            "ss_output.txt":           ["ss", "-tulnp"],
            "arp_table.txt":           ["arp", "-n"],
            "route_table.txt":         ["route", "-n"],
            "ifconfig.txt":            ["ifconfig"],
            "resolv_conf.txt":         ["/bin/cat", "/etc/resolv.conf"],
            "hosts_file.txt":          ["/bin/cat", "/etc/hosts"],
        }
    else:
        cmds = {
            "netstat.txt":      ["netstat", "-ano"],
            "arp_table.txt":    ["arp", "-a"],
            "route_table.txt":  ["route", "print"],
            "ipconfig.txt":     ["ipconfig", "/all"],
            "dns_cache.txt":    ["ipconfig", "/displaydns"],
            "hosts_file.txt":   ["type", r"C:\Windows\System32\drivers\etc\hosts"],
        }
    for fname, cmd in cmds.items():
        out = run_cmd(cmd)
        if out:
            write_artifact(net_dir, fname, out)

# ─── Processus ───────────────────────────────────────────────────────────────

def collect_processes(out_dir: Path):
    section("Processus en cours")
    proc_dir = out_dir / "processes"

    if OS in ("Linux", "Darwin"):
        cmds = {
            "ps_full.txt":  ["ps", "auxwwf"],
            "lsof_net.txt": ["lsof", "-i"],
        }
    else:
        cmds = {
            "tasklist.txt":      ["tasklist", "/v"],
            "wmic_process.txt":  ["wmic", "process", "list", "full"],
        }
    for fname, cmd in cmds.items():
        out = run_cmd(cmd)
        if out:
            write_artifact(proc_dir, fname, out)

# ─── Utilisateurs ────────────────────────────────────────────────────────────

def collect_users(out_dir: Path):
    section("Comptes et connexions utilisateurs")
    usr_dir = out_dir / "users"

    if OS == "Linux":
        for fp in ["/etc/passwd", "/etc/group", "/etc/sudoers"]:
            p = Path(fp)
            if p.exists():
                write_artifact(usr_dir, p.name, safe_read(p))
        for cmd, fname in [
            (["last"], "last_logins.txt"),
            (["lastb"], "failed_logins.txt"),
            (["who"], "current_sessions.txt"),
            (["id"], "current_user.txt"),
            (["sudo", "-l"], "sudo_perms.txt"),
        ]:
            out = run_cmd(cmd)
            if out:
                write_artifact(usr_dir, fname, out)

    elif OS == "Darwin":
        for cmd, fname in [
            (["dscl", ".", "-list", "/Users"], "local_users.txt"),
            (["last"], "last_logins.txt"),
            (["who"], "current_sessions.txt"),
            (["id"], "current_user.txt"),
        ]:
            out = run_cmd(cmd)
            if out:
                write_artifact(usr_dir, fname, out)

    else:
        for cmd, fname in [
            (["net", "user"], "net_users.txt"),
            (["net", "localgroup", "administrators"], "local_admins.txt"),
            (["whoami", "/all"], "whoami_all.txt"),
            (["query", "user"], "active_sessions.txt"),
        ]:
            out = run_cmd(cmd)
            if out:
                write_artifact(usr_dir, fname, out)

# ─── Navigateurs ─────────────────────────────────────────────────────────────

def collect_browser(out_dir: Path):
    section("Artefacts navigateurs (chemins)")
    brow_dir = out_dir / "browser"
    paths = []

    if OS == "Linux":
        candidates = {
            "Chrome History":  HOME / ".config/google-chrome/Default/History",
            "Firefox Profiles": HOME / ".mozilla/firefox",
            "Chromium History": HOME / ".config/chromium/Default/History",
        }
    elif OS == "Darwin":
        candidates = {
            "Chrome History":  HOME / "Library/Application Support/Google/Chrome/Default/History",
            "Safari History":  HOME / "Library/Safari/History.db",
            "Firefox Profiles": HOME / "Library/Application Support/Firefox/Profiles",
        }
    else:
        appdata = Path(os.environ.get("LOCALAPPDATA", ""))
        roaming = Path(os.environ.get("APPDATA", ""))
        candidates = {
            "Chrome History": appdata / "Google/Chrome/User Data/Default/History",
            "Edge History":   appdata / "Microsoft/Edge/User Data/Default/History",
            "Firefox Profiles": roaming / "Mozilla/Firefox/Profiles",
        }

    for label, p in candidates.items():
        p = Path(p)
        paths.append({
            "browser": label,
            "path":    str(p),
            "exists":  p.exists(),
            "note":    "Fichier SQLite — utilisez un visualiseur d'historique navigateur",
        })

    write_artifact(brow_dir, "browser_artifact_paths.json",
                   json.dumps(paths, indent=2, ensure_ascii=False))

# ─── Métadonnées IR ───────────────────────────────────────────────────────────

def write_ir_metadata(out_dir: Path):
    meta = {
        "collection_time": datetime.now().isoformat(),
        "hostname":        platform.node(),
        "os":              f"{OS} {platform.release()}",
        "os_version":      platform.version(),
        "architecture":    platform.machine(),
        "python":          platform.python_version(),
        "user":            os.environ.get("USER") or os.environ.get("USERNAME", "unknown"),
        "note":            "Collecte forensique non intrusive — lecture seule",
    }
    write_artifact(out_dir, "ir_metadata.json",
                   json.dumps(meta, indent=2, ensure_ascii=False))

# ─── Main ────────────────────────────────────────────────────────────────────

COLLECTORS = {
    "logs":      collect_logs,
    "cron":      collect_cron,
    "history":   collect_history,
    "network":   collect_network,
    "processes": collect_processes,
    "users":     collect_users,
    "browser":   collect_browser,
}


def main():
    parser = argparse.ArgumentParser(
        description="Collecte d'artefacts forensiques système (lecture seule)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--categories", default="all",
                        help="Catégories séparées par virgules : "
                             "logs,cron,history,network,processes,users,browser,all")
    parser.add_argument("-o", "--output",
                        default=f"artifacts_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        help="Dossier de sortie")
    parser.add_argument("--compress",  action="store_true",
                        help="Compresser en .zip après collecte")
    parser.add_argument("--max-log-size", type=int, default=50,
                        help="Taille max par log en Mo (défaut: 50)")
    args = parser.parse_args()

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(cyan("=" * 65))
    print(cyan("  Artifact Collector — Forensic IR"))
    print(cyan(f"  OS         : {OS} {platform.release()}"))
    print(cyan(f"  Sortie     : {out_dir.resolve()}"))
    print(cyan("=" * 65))

    # Sélection des catégories
    cats_raw = args.categories.strip().lower()
    if cats_raw == "all":
        selected = list(COLLECTORS.keys())
    else:
        selected = [c.strip() for c in cats_raw.split(",") if c.strip() in COLLECTORS]
        unknown = [c.strip() for c in cats_raw.split(",") if c.strip() not in COLLECTORS]
        if unknown:
            print(yellow(f"\n  [AVERT] Catégories inconnues : {', '.join(unknown)}"))

    # Métadonnées
    write_ir_metadata(out_dir)

    # Collecte
    for cat in selected:
        fn = COLLECTORS[cat]
        if cat == "logs":
            fn(out_dir, args.max_log_size)
        else:
            fn(out_dir)

    # Compression optionnelle
    if args.compress:
        zip_path = str(out_dir) + ".zip"
        print(f"\n{dim('  Compression en cours...')}")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for fp in out_dir.rglob("*"):
                if fp.is_file():
                    zf.write(fp, fp.relative_to(out_dir.parent))
        print(green(f"  Archive : {zip_path}"))

    print(f"\n{cyan('─'*65)}")
    print(green(f"  Collecte terminée → {out_dir.resolve()}"))
    print(cyan("─" * 65))


if __name__ == "__main__":
    main()
