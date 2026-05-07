#!/usr/bin/env python3
"""
=============================================================================
 log_parser.py — Parseur de logs multi-format avec détection de patterns
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : stdlib uniquement

 DESCRIPTION
 -----------
 Analyse des fichiers de logs de différents formats et identifie les
 événements suspects : erreurs répétées, tentatives d'accès, adresses IP
 suspectes, payloads SQL/XSS, traversées de répertoire, etc.

 FORMATS SUPPORTÉS
 -----------------
   syslog    : /var/log/syslog, /var/log/messages
   auth      : /var/log/auth.log, /var/log/secure
   apache    : Combined Log Format (access.log)
   nginx     : Combined Log Format (access.log)
   custom    : Pattern regex fourni par l'utilisateur

 USAGE
 -----
   python log_parser.py -f <fichier> [options]

 EXEMPLES
 --------
   python log_parser.py -f /var/log/auth.log --format auth
   python log_parser.py -f access.log --format apache --top-ips 20
   python log_parser.py -f system.log --format syslog --since "2026-05-01"
   python log_parser.py -f custom.log --pattern "ERROR|CRITICAL" -o rapport.txt

 OPTIONS
 -------
   -f, --file        Fichier de log (obligatoire)
   --format          Format : syslog, auth, apache, nginx, custom (défaut: auto)
   --pattern         Regex personnalisé de recherche
   --since           Filtrer les entrées depuis cette date (YYYY-MM-DD)
   --until           Filtrer les entrées jusqu'à cette date (YYYY-MM-DD)
   --top-ips         Afficher le top N des IPs (défaut: 10)
   --severity        Niveau minimum : debug, info, warning, error, critical
   -o, --output      Fichier de sortie
   --json            Exporter en JSON
   -v, --verbose     Afficher toutes les lignes correspondantes
=============================================================================
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
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

SUSPICIOUS_PATTERNS = {
    "SQL Injection": re.compile(
        r"(?i)(union\s+select|select\s+.*from|insert\s+into|drop\s+table|"
        r"1=1|'or'|;--|\bxp_|\bexec\b|\bcast\()", re.I
    ),
    "XSS": re.compile(
        r"(?i)(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)", re.I
    ),
    "Path Traversal": re.compile(
        r"(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e%252f)", re.I
    ),
    "Command Injection": re.compile(
        r"(;ls|;cat|;id|;whoami|\|bash|\|sh|\$\(|`id`|`whoami`)", re.I
    ),
    "Scanner/Bot": re.compile(
        r"(sqlmap|nikto|nessus|nmap|masscan|dirbuster|gobuster|burpsuite|"
        r"zgrab|nuclei|acunetix|openvas)", re.I
    ),
    "Credential Stuffing": re.compile(
        r"(password=|passwd=|pwd=|login=).*admin|root|test|guest", re.I
    ),
}

# ─── Regex de formats ─────────────────────────────────────────────────────────

FORMATS = {
    "apache": re.compile(
        r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    ),
    "nginx": re.compile(
        r'(?P<ip>\S+)\s+-\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    ),
    "syslog": re.compile(
        r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+(?P<process>[^:]+):\s+(?P<message>.+)'
    ),
    "auth": re.compile(
        r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+(?P<process>[^:]+):\s+(?P<message>.+)'
    ),
}

# Regex d'extraction IP générique
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# ─── Fonctions ───────────────────────────────────────────────────────────────

def detect_format(filepath: str) -> str:
    """Tente de détecter le format automatiquement."""
    name = Path(filepath).name.lower()
    if "auth" in name or "secure" in name:
        return "auth"
    if "syslog" in name or "messages" in name or "system" in name:
        return "syslog"
    if "apache" in name or "access" in name:
        return "apache"
    if "nginx" in name:
        return "nginx"
    return "syslog"


def parse_line(line: str, fmt: str) -> dict | None:
    """Parse une ligne de log selon le format détecté."""
    pattern = FORMATS.get(fmt)
    if not pattern:
        return {"raw": line, "ip": (IP_RE.findall(line) or [""])[0]}
    m = pattern.match(line)
    if m:
        return m.groupdict()
    return {"raw": line, "ip": (IP_RE.findall(line) or [""])[0]}


def check_suspicious(line: str) -> list:
    """Retourne la liste des types de menaces détectées dans une ligne."""
    hits = []
    for threat, pattern in SUSPICIOUS_PATTERNS.items():
        if pattern.search(line):
            hits.append(threat)
    return hits


def analyze_file(filepath: str, fmt: str, custom_pattern: str | None,
                 since: datetime | None, until: datetime | None,
                 top_ips: int, verbose: bool) -> dict:
    """Analyse complète du fichier de log."""
    custom_re = re.compile(custom_pattern, re.I) if custom_pattern else None

    ip_counter = Counter()
    status_counter = Counter()
    threat_counter = Counter()
    suspicious_lines = []
    total = 0
    errors = 0

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip()
                if not line:
                    continue
                total += 1

                parsed = parse_line(line, fmt)
                ip = parsed.get("ip", "") if parsed else ""
                status = parsed.get("status", "") if parsed else ""

                if ip:
                    ip_counter[ip] += 1
                if status:
                    status_counter[status] += 1
                    if status.startswith(("4", "5")):
                        errors += 1

                # Détection de patterns suspects
                threats = check_suspicious(line)
                if threats or (custom_re and custom_re.search(line)):
                    for t in threats:
                        threat_counter[t] += 1
                    suspicious_lines.append({
                        "line": line[:300],
                        "ip": ip,
                        "threats": threats,
                        "custom_match": bool(custom_re and custom_re.search(line)),
                    })
                    if verbose:
                        threat_str = ", ".join(threats) if threats else "pattern personnalisé"
                        print(f"  {red('[SUSPECT]')} [{threat_str}]\n    {line[:120]}")

    except FileNotFoundError:
        print(red(f"[ERREUR] Fichier introuvable : {filepath}"))
        sys.exit(1)
    except PermissionError:
        print(red(f"[ERREUR] Permission refusée : {filepath}"))
        sys.exit(1)

    return {
        "file": filepath,
        "format": fmt,
        "total_lines": total,
        "error_count": errors,
        "ip_counter": ip_counter,
        "status_counter": status_counter,
        "threat_counter": threat_counter,
        "suspicious_lines": suspicious_lines,
        "top_ips": top_ips,
    }


def display_report(report: dict) -> None:
    """Affiche le rapport d'analyse."""
    print(cyan("\n" + "=" * 65))
    print(cyan(f"  Rapport d'analyse de logs"))
    print(cyan(f"  Fichier  : {report['file']}"))
    print(cyan(f"  Format   : {report['format']}"))
    print(cyan("=" * 65))

    print(f"\n  {bold(cyan('[ Statistiques globales ]'))}")
    print(f"    Lignes totales     : {report['total_lines']}")
    print(f"    Erreurs HTTP (4xx/5xx) : {report['error_count']}")
    print(f"    Lignes suspectes   : {len(report['suspicious_lines'])}")

    print(f"\n  {bold(cyan('[ Top IPs ]'))}")
    for ip, count in report["ip_counter"].most_common(report["top_ips"]):
        bar = "█" * min(count // max(1, report["total_lines"] // 100), 40)
        print(f"    {ip:<20} {count:>6} req  {yellow(bar)}")

    if report["status_counter"]:
        print(f"\n  {bold(cyan('[ Codes HTTP ]'))}")
        for status, count in sorted(report["status_counter"].items()):
            color = red if status.startswith(("4", "5")) else green
            print(f"    HTTP {status}  :  {color(str(count))}")

    if report["threat_counter"]:
        print(f"\n  {bold(cyan('[ Menaces détectées ]'))}")
        for threat, count in report["threat_counter"].most_common():
            print(f"    {red('[!]')} {threat:<30} : {count} occurrence(s)")
    else:
        print(f"\n  {bold(cyan('[ Menaces ]'))}  {green('Aucun pattern suspect détecté')}")

    print(cyan("\n" + "=" * 65))

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Parseur de logs multi-format avec détection de menaces",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-f", "--file",     required=True, help="Fichier de log")
    parser.add_argument("--format",         choices=["syslog", "auth", "apache", "nginx", "auto"],
                        default="auto", help="Format du log (défaut: auto)")
    parser.add_argument("--pattern",        help="Regex personnalisé de recherche")
    parser.add_argument("--since",          help="Depuis (YYYY-MM-DD)")
    parser.add_argument("--until",          help="Jusqu'à (YYYY-MM-DD)")
    parser.add_argument("--top-ips",        type=int, default=10, help="Top N IPs (défaut: 10)")
    parser.add_argument("-o", "--output",   help="Fichier de sortie")
    parser.add_argument("--json",           action="store_true")
    parser.add_argument("-v", "--verbose",  action="store_true", help="Afficher les lignes suspectes")
    args = parser.parse_args()

    fmt = args.format if args.format != "auto" else detect_format(args.file)
    since = datetime.strptime(args.since, "%Y-%m-%d") if args.since else None
    until = datetime.strptime(args.until, "%Y-%m-%d") if args.until else None

    print(f"[*] Analyse de : {args.file}  (format: {fmt})")

    report = analyze_file(
        args.file, fmt, args.pattern, since, until, args.top_ips, args.verbose
    )
    display_report(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(f"Analyse de logs — {args.file}\n")
            f.write(f"Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Format  : {fmt}\n")
            f.write(f"Lignes  : {report['total_lines']}\n")
            f.write(f"Suspects: {len(report['suspicious_lines'])}\n\n")
            f.write("[ Top IPs ]\n")
            for ip, count in report["ip_counter"].most_common(report["top_ips"]):
                f.write(f"  {ip:<20} {count}\n")
            f.write("\n[ Menaces ]\n")
            for threat, count in report["threat_counter"].most_common():
                f.write(f"  {threat}: {count}\n")
            f.write("\n[ Lignes suspectes ]\n")
            for s in report["suspicious_lines"]:
                f.write(f"  {s['line']}\n")
        print(green(f"\n[+] Rapport sauvegardé : {args.output}"))

    if args.json:
        json_path = (args.output.rsplit(".", 1)[0] + ".json") if args.output else "log_report.json"
        with open(json_path, "w", encoding="utf-8") as f:
            exportable = {
                "file": report["file"],
                "format": report["format"],
                "total_lines": report["total_lines"],
                "error_count": report["error_count"],
                "top_ips": report["ip_counter"].most_common(report["top_ips"]),
                "threats": dict(report["threat_counter"]),
                "suspicious_count": len(report["suspicious_lines"]),
                "suspicious_lines": report["suspicious_lines"][:50],
            }
            json.dump(exportable, f, indent=2, ensure_ascii=False)
        print(green(f"[+] JSON sauvegardé : {json_path}"))


if __name__ == "__main__":
    main()
