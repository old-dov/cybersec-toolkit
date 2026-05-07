#!/usr/bin/env python3
"""
=============================================================================
 failed_login_detector.py — Détection de tentatives de force brute
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : stdlib uniquement

 DESCRIPTION
 -----------
 Analyse les fichiers de logs d'authentification pour détecter des
 tentatives de connexion échouées pouvant indiquer une attaque par
 force brute ou credential stuffing.

 Détecte les patterns dans :
   - /var/log/auth.log       (Debian/Ubuntu)
   - /var/log/secure         (RHEL/CentOS/Fedora)
   - /var/log/btmp           (binaire — via "lastb" si dispo)
   - Logs SSH standard
   - Fichiers texte personnalisés

 USAGE
 -----
   python failed_login_detector.py -f <fichier_log> [options]

 EXEMPLES
 --------
   python failed_login_detector.py -f /var/log/auth.log
   python failed_login_detector.py -f /var/log/secure --threshold 3
   python failed_login_detector.py -f auth.log --window 300 -o rapport.txt
   python failed_login_detector.py -f auth.log --whitelist "192.168.1.0/24,10.0.0.1"

 OPTIONS
 -------
   -f, --file          Fichier de log (obligatoire)
   --threshold         Seuil d'alertes par IP (défaut: 5 tentatives)
   --window            Fenêtre temporelle en secondes (défaut: 300 = 5 min)
   --whitelist         IPs/CIDRs en liste blanche (séparés par virgules)
   --show-users        Afficher les noms d'utilisateurs tentés
   --top               Top N IPs à afficher (défaut: 20)
   -o, --output        Fichier de sortie
   --json              Exporter en JSON

 FORMATS DE LOGS RECONNUS
 ------------------------
   Dec 10 12:34:56 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2
   Dec 10 12:34:56 host sshd[1234]: Invalid user admin from 1.2.3.4 port 22
   Dec 10 12:34:56 host sshd[1234]: authentication failure; ... rhost=1.2.3.4 user=root
=============================================================================
"""

import argparse
import ipaddress
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# ─── Couleurs ────────────────────────────────────────────────────────────────

def green(t):  return f"{Fore.GREEN}{t}{Style.RESET_ALL}" if COLOR else t
def yellow(t): return f"{Fore.YELLOW}{t}{Style.RESET_ALL}" if COLOR else t
def red(t):    return f"{Fore.RED}{t}{Style.RESET_ALL}" if COLOR else t
def cyan(t):   return f"{Fore.CYAN}{t}{Style.RESET_ALL}" if COLOR else t
def bold(t):   return f"{Style.BRIGHT}{t}{Style.RESET_ALL}" if COLOR else t

# ─── Patterns de détection ───────────────────────────────────────────────────

# SSH échec de mot de passe
SSH_FAILED_PW = re.compile(
    r'Failed password for (?:invalid user )?(\S+) from ([\d.]+) port \d+'
)
# Utilisateur invalide
SSH_INVALID_USER = re.compile(
    r'Invalid user (\S+) from ([\d.]+)'
)
# PAM auth failure
PAM_FAILURE = re.compile(
    r'authentication failure.*?rhost=([\d.]+)(?:.*?user=(\S+))?'
)
# Connexion maximale atteinte
MAX_AUTH = re.compile(
    r'error: maximum authentication attempts exceeded.*?from ([\d.]+)'
)
# Tentatives de déconnexion (possible brute)
DISCONNECT = re.compile(
    r'Disconnecting.*?Too many authentication failures.*?from ([\d.]+)'
)

# ─── Fonctions ───────────────────────────────────────────────────────────────

def parse_syslog_date(month: str, day: str, time_str: str, year: int = None) -> datetime | None:
    """Parse une date au format syslog (sans année)."""
    if year is None:
        year = datetime.now().year
    try:
        return datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def ip_in_whitelist(ip: str, whitelist: list) -> bool:
    """Vérifie si une IP est dans la liste blanche."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for entry in whitelist:
            entry = entry.strip()
            try:
                if "/" in entry:
                    if ip_obj in ipaddress.ip_network(entry, strict=False):
                        return True
                else:
                    if ip_obj == ipaddress.ip_address(entry):
                        return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False


def parse_log(filepath: str, whitelist: list) -> dict:
    """
    Analyse le fichier de log ligne par ligne.
    Retourne un dict : {ip: {"count": int, "users": set, "timestamps": list}}
    """
    data = defaultdict(lambda: {"count": 0, "users": set(), "timestamps": []})
    total_lines = 0

    # Regex de date syslog au début de ligne
    DATE_RE = re.compile(r'^(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})')

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                total_lines += 1
                ts = None
                dm = DATE_RE.match(line)
                if dm:
                    ts = parse_syslog_date(dm.group(1), dm.group(2), dm.group(3))

                # Tenter les différents patterns
                ip, user = None, None

                m = SSH_FAILED_PW.search(line)
                if m:
                    user, ip = m.group(1), m.group(2)

                if not ip:
                    m = SSH_INVALID_USER.search(line)
                    if m:
                        user, ip = m.group(1), m.group(2)

                if not ip:
                    m = PAM_FAILURE.search(line)
                    if m:
                        ip = m.group(1)
                        user = m.group(2) if m.lastindex >= 2 else None

                if not ip:
                    m = MAX_AUTH.search(line)
                    if m:
                        ip = m.group(1)

                if not ip:
                    m = DISCONNECT.search(line)
                    if m:
                        ip = m.group(1)

                if ip:
                    if ip_in_whitelist(ip, whitelist):
                        continue
                    data[ip]["count"] += 1
                    if user:
                        data[ip]["users"].add(user)
                    if ts:
                        data[ip]["timestamps"].append(ts)

    except FileNotFoundError:
        print(red(f"[ERREUR] Fichier introuvable : {filepath}"))
        sys.exit(1)
    except PermissionError:
        print(red(f"[ERREUR] Permission refusée : {filepath}"))
        sys.exit(1)

    return dict(data), total_lines


def detect_brute_force(data: dict, threshold: int, window: int) -> list:
    """
    Identifie les IPs dépassant le seuil dans la fenêtre temporelle.
    Retourne une liste d'alertes triée par nombre de tentatives.
    """
    alerts = []
    for ip, info in data.items():
        total = info["count"]
        # Vérification par fenêtre temporelle si on a des timestamps
        timestamps = sorted(info["timestamps"])
        burst = 0
        if timestamps:
            for i, ts in enumerate(timestamps):
                window_end = ts + timedelta(seconds=window)
                count_in_window = sum(1 for t in timestamps[i:] if t <= window_end)
                burst = max(burst, count_in_window)

        is_alert = total >= threshold or (burst >= threshold and burst > 0)
        if is_alert:
            alerts.append({
                "ip": ip,
                "total": total,
                "burst": burst,
                "users": sorted(info["users"]),
                "first_seen": timestamps[0].strftime("%Y-%m-%d %H:%M:%S") if timestamps else "N/A",
                "last_seen":  timestamps[-1].strftime("%Y-%m-%d %H:%M:%S") if timestamps else "N/A",
            })

    return sorted(alerts, key=lambda x: x["total"], reverse=True)

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Détection de tentatives de force brute dans les logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-f", "--file",       required=True, help="Fichier de log")
    parser.add_argument("--threshold",        type=int, default=5,
                        help="Seuil de tentatives par IP (défaut: 5)")
    parser.add_argument("--window",           type=int, default=300,
                        help="Fenêtre temporelle en secondes (défaut: 300)")
    parser.add_argument("--whitelist",        default="",
                        help="IPs/CIDRs en liste blanche (séparés par virgule)")
    parser.add_argument("--show-users",       action="store_true",
                        help="Afficher les utilisateurs tentés")
    parser.add_argument("--top",              type=int, default=20)
    parser.add_argument("-o", "--output",     help="Fichier de sortie")
    parser.add_argument("--json",             action="store_true")
    args = parser.parse_args()

    whitelist = [ip.strip() for ip in args.whitelist.split(",") if ip.strip()]

    print(cyan("=" * 65))
    print(cyan(f"  Brute Force Detector — {args.file}"))
    print(cyan(f"  Seuil    : {args.threshold} tentatives"))
    print(cyan(f"  Fenêtre  : {args.window}s ({args.window//60} min)"))
    print(cyan(f"  Whitelist: {', '.join(whitelist) if whitelist else 'aucune'}"))
    print(cyan(f"  Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(cyan("=" * 65))

    data, total_lines = parse_log(args.file, whitelist)
    alerts = detect_brute_force(data, args.threshold, args.window)

    print(f"\n  Lignes analysées  : {total_lines}")
    print(f"  IPs avec échecs   : {len(data)}")
    print(f"  Alertes générées  : {red(str(len(alerts)))}\n")

    if not alerts:
        print(green("  [✓] Aucune activité de force brute détectée."))
    else:
        print(f"  {bold(cyan('[ Alertes — IPs suspectes ]'))}\n")
        for i, alert in enumerate(alerts[:args.top], 1):
            severity = red("[CRITIQUE]") if alert["total"] >= args.threshold * 5 else yellow("[ALERTE]")
            print(f"  {severity} #{i}  {bold(alert['ip'])}")
            print(f"    Tentatives totales : {red(str(alert['total']))}")
            if alert["burst"]:
                print(f"    Burst (fenêtre)    : {alert['burst']} en {args.window}s")
            print(f"    Première vue       : {alert['first_seen']}")
            print(f"    Dernière vue       : {alert['last_seen']}")
            if args.show_users and alert["users"]:
                users_str = ", ".join(alert["users"][:10])
                if len(alert["users"]) > 10:
                    users_str += f" ... (+{len(alert['users'])-10})"
                print(f"    Utilisateurs       : {users_str}")
            print()

    print(cyan("=" * 65))

    # Sauvegarde
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(f"Brute Force Detector — {args.file}\n")
            f.write(f"Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Seuil    : {args.threshold}\n")
            f.write(f"Alertes  : {len(alerts)}\n\n")
            for alert in alerts:
                f.write(f"IP: {alert['ip']}\n")
                f.write(f"  Tentatives : {alert['total']}\n")
                f.write(f"  Première   : {alert['first_seen']}\n")
                f.write(f"  Dernière   : {alert['last_seen']}\n")
                if alert["users"]:
                    f.write(f"  Utilisateurs: {', '.join(alert['users'])}\n")
                f.write("\n")
        print(green(f"\n[+] Rapport sauvegardé : {args.output}"))

    if args.json:
        json_path = (args.output.rsplit(".", 1)[0] + ".json") if args.output else "brute_force.json"
        with open(json_path, "w", encoding="utf-8") as f:
            export = {
                "file": args.file,
                "date": datetime.now().isoformat(),
                "threshold": args.threshold,
                "window_seconds": args.window,
                "total_lines": total_lines,
                "alert_count": len(alerts),
                "alerts": alerts,
            }
            json.dump(export, f, indent=2, ensure_ascii=False)
        print(green(f"[+] JSON sauvegardé : {json_path}"))


if __name__ == "__main__":
    main()
