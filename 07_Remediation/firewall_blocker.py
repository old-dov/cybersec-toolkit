#!/usr/bin/env python3
"""
=============================================================================
 firewall_blocker.py — Blocage d'IPs malveillantes (multi-OS)
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : stdlib uniquement
 Droits   : Administrateur / root requis pour --apply

 DESCRIPTION
 -----------
 Remédie aux attaques détectées par failed_login_detector.py et
 log_parser.py en bloquant automatiquement les adresses IP malveillantes
 via le pare-feu natif de chaque système.

 Adapte automatiquement les commandes au système détecté :
   Linux   → iptables ou nftables
   macOS   → pf (Packet Filter)
   Windows → Windows Firewall (netsh advfirewall)

 PIPELINE
 --------
   1. python ../04_Log_Analysis/failed_login_detector.py \
             -f /var/log/auth.log --json -o brute_force.json
   2. python firewall_blocker.py --json brute_force.json --action block

 USAGE
 -----
   python firewall_blocker.py [options]

 EXEMPLES
 --------
   # Prévisualiser les règles (sans les appliquer)
   python firewall_blocker.py --json brute_force.json --dry-run

   # Bloquer via iptables (Linux)
   sudo python firewall_blocker.py --json brute_force.json --engine iptables --apply

   # Bloquer via nftables (Linux moderne)
   sudo python firewall_blocker.py --json brute_force.json --engine nftables --apply

   # Bloquer via pf (macOS)
   sudo python firewall_blocker.py --json brute_force.json --engine pf --apply

   # Bloquer via Windows Firewall
   python firewall_blocker.py --json brute_force.json --engine windows --apply

   # Bloquer des IPs manuelles
   python firewall_blocker.py --ips "1.2.3.4,5.6.7.8" --engine iptables --dry-run

   # Débloquer des IPs
   python firewall_blocker.py --json brute_force.json --action unblock --engine iptables --apply

   # Exporter les règles en script shell
   python firewall_blocker.py --json brute_force.json --engine iptables -o block.sh

 OPTIONS
 -------
   --json       JSON de brute_force ou log_parser (IPs à bloquer)
   --ips        IPs manuelles séparées par virgules
   --engine     Moteur de pare-feu : auto, iptables, nftables, pf, windows
   --action     block (défaut) ou unblock
   --threshold  Seuil minimum de tentatives pour bloquer (défaut: 5)
   --whitelist  IPs/CIDRs à ne jamais bloquer (ex: "192.168.1.0/24")
   --dry-run    Afficher les commandes sans les exécuter
   --apply      Appliquer les règles (requiert admin/root)
   -o, --output Exporter en script shell/bat

 AVERTISSEMENT
 -------------
 Le blocage d'IPs mal ciblé peut couper des accès légitimes.
 Utilisez toujours --dry-run avant --apply.
 Maintenez une liste blanche pour vos propres IPs.
=============================================================================
"""

import argparse
import ipaddress
import json
import os
import platform
import subprocess
import sys
from datetime import datetime

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

# ─── Détection OS ────────────────────────────────────────────────────────────

OS = platform.system().lower()  # "windows", "linux", "darwin"


def detect_engine() -> str:
    """Détecte automatiquement le meilleur moteur pare-feu disponible."""
    if OS == "windows":
        return "windows"
    if OS == "darwin":
        return "pf"
    # Linux : préférer nftables si disponible
    for cmd in ("nft", "iptables"):
        try:
            subprocess.run([cmd, "--version"], capture_output=True, check=False,
                            creationflags=subprocess.CREATE_NO_WINDOW if OS == "windows" else 0)
            return "nftables" if cmd == "nft" else "iptables"
        except FileNotFoundError:
            continue
    return "iptables"  # fallback

# ─── Générateurs de commandes ────────────────────────────────────────────────

def cmds_iptables(ip: str, action: str) -> list[str]:
    flag = "-A" if action == "block" else "-D"
    return [
        f"iptables {flag} INPUT -s {ip} -j DROP",
        f"iptables {flag} OUTPUT -d {ip} -j DROP",
        f"iptables-save > /etc/iptables/rules.v4",
    ]


def cmds_nftables(ip: str, action: str, table: str = "filter") -> list[str]:
    if action == "block":
        return [
            f'nft add element inet {table} blacklist {{ {ip} }}',
        ]
    else:
        return [
            f'nft delete element inet {table} blacklist {{ {ip} }}',
        ]


def cmds_pf(ip: str, action: str) -> list[str]:
    """macOS pf — utilise un fichier de table."""
    if action == "block":
        return [
            f'echo "{ip}" >> /etc/pf.blocklist',
            'pfctl -t blocklist -T add ' + ip,
        ]
    else:
        return [
            f'sed -i "" "/{ip}/d" /etc/pf.blocklist',
            'pfctl -t blocklist -T delete ' + ip,
        ]


def cmds_windows(ip: str, action: str) -> list[str]:
    rule_name = f"CybSec-Block-{ip.replace('.', '_')}"
    if action == "block":
        return [
            f'netsh advfirewall firewall add rule name="{rule_name}" '
            f'dir=in action=block remoteip={ip}',
            f'netsh advfirewall firewall add rule name="{rule_name}-OUT" '
            f'dir=out action=block remoteip={ip}',
        ]
    else:
        return [
            f'netsh advfirewall firewall delete rule name="{rule_name}"',
            f'netsh advfirewall firewall delete rule name="{rule_name}-OUT"',
        ]


# Initialiseurs nftables (table + set à créer une fois)
NFTABLES_INIT = """\
# Initialisation nftables — à exécuter une fois
nft add table inet filter
nft add set inet filter blacklist { type ipv4_addr\\; }
nft add rule inet filter input ip saddr @blacklist drop
nft add rule inet filter output ip daddr @blacklist drop
"""

PF_INIT = """\
# Initialisation pf (macOS) — ajouter au /etc/pf.conf
# table <blocklist> persist file "/etc/pf.blocklist"
# block quick from <blocklist>
# block quick to <blocklist>
# Puis : pfctl -f /etc/pf.conf && pfctl -e
"""

ENGINES = {
    "iptables": cmds_iptables,
    "nftables": cmds_nftables,
    "pf":       cmds_pf,
    "windows":  cmds_windows,
}

# ─── Chargement des IPs ──────────────────────────────────────────────────────

def load_ips_from_json(path: str, threshold: int) -> list[dict]:
    """Charge les IPs depuis un JSON failed_login_detector ou log_parser."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(red(f"[ERREUR] {path} : {e}"))
        sys.exit(1)

    ips = []
    # Format failed_login_detector
    if "alerts" in data:
        for alert in data["alerts"]:
            if alert.get("total", 0) >= threshold:
                ips.append({"ip": alert["ip"], "count": alert["total"],
                             "reason": "brute force"})
    # Format log_parser
    elif "top_ips" in data:
        for ip, count in data["top_ips"]:
            if count >= threshold:
                ips.append({"ip": ip, "count": count, "reason": "log suspect"})
    # Format liste simple
    elif isinstance(data, list):
        for entry in data:
            if isinstance(entry, str):
                ips.append({"ip": entry, "count": 0, "reason": "liste manuelle"})
            elif isinstance(entry, dict) and "ip" in entry:
                ips.append(entry)
    return ips


def validate_ip(ip: str) -> bool:
    """Valide une adresse IPv4 ou CIDR."""
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except ValueError:
        return False


def is_whitelisted(ip: str, whitelist: list) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip.split("/")[0])
        for entry in whitelist:
            try:
                if "/" in entry:
                    if ip_obj in ipaddress.ip_network(entry, strict=False):
                        return True
                elif ip_obj == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False

# ─── Exécution ───────────────────────────────────────────────────────────────

def run_command(cmd: str, dry_run: bool) -> bool:
    """Exécute une commande shell ou l'affiche si dry_run."""
    if dry_run:
        print(f"  {yellow('[DRY-RUN]')} {cmd}")
        return True
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if OS == "windows" else 0,
        )
        if result.returncode == 0:
            print(green(f"  [✓] {cmd}"))
            return True
        else:
            print(red(f"  [✗] {cmd}"))
            print(red(f"      Erreur : {result.stderr.strip()}"))
            return False
    except Exception as e:
        print(red(f"  [✗] {cmd} — {e}"))
        return False

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Blocage d'IPs malveillantes via le pare-feu natif",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--json",       dest="json_file",
                        help="JSON de failed_login_detector ou log_parser")
    parser.add_argument("--ips",        help="IPs manuelles séparées par virgules")
    parser.add_argument("--engine",     default="auto",
                        choices=["auto", "iptables", "nftables", "pf", "windows"])
    parser.add_argument("--action",     default="block", choices=["block", "unblock"])
    parser.add_argument("--threshold",  type=int, default=5,
                        help="Seuil de tentatives pour bloquer (défaut: 5)")
    parser.add_argument("--whitelist",  default="",
                        help="IPs/CIDRs à ne jamais bloquer (virgules)")
    parser.add_argument("--dry-run",    action="store_true",
                        help="Afficher sans exécuter")
    parser.add_argument("--apply",      action="store_true",
                        help="Appliquer les règles (requiert admin)")
    parser.add_argument("-o", "--output", help="Script de sortie (.sh ou .bat)")
    args = parser.parse_args()

    if not args.json_file and not args.ips:
        print(red("[ERREUR] Fournissez --json ou --ips"))
        sys.exit(1)

    if args.apply and not args.dry_run:
        if OS != "windows" and os.geteuid() != 0:
            print(red("[ERREUR] root requis. Relancez avec : sudo python firewall_blocker.py ..."))
            sys.exit(1)

    engine = args.engine if args.engine != "auto" else detect_engine()
    whitelist = [ip.strip() for ip in args.whitelist.split(",") if ip.strip()]
    cmd_fn = ENGINES.get(engine)

    if not cmd_fn:
        print(red(f"[ERREUR] Moteur inconnu : {engine}"))
        sys.exit(1)

    print(cyan("=" * 65))
    print(cyan(f"  Firewall Blocker"))
    print(cyan(f"  Action  : {args.action.upper()}"))
    print(cyan(f"  Moteur  : {engine}"))
    print(cyan(f"  Mode    : {'DRY-RUN (simulation)' if args.dry_run or not args.apply else 'RÉEL — application'}"))
    print(cyan(f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(cyan("=" * 65 + "\n"))

    # Collecte des IPs
    all_ips = []
    if args.json_file:
        all_ips.extend(load_ips_from_json(args.json_file, args.threshold))
    if args.ips:
        for ip in args.ips.split(","):
            ip = ip.strip()
            if ip:
                all_ips.append({"ip": ip, "count": 0, "reason": "manuel"})

    # Validation et filtrage
    valid_ips = []
    skipped = []
    for entry in all_ips:
        ip = entry["ip"]
        if not validate_ip(ip):
            print(yellow(f"  [IGNORÉ] IP invalide : {ip}"))
            skipped.append(ip)
            continue
        if is_whitelisted(ip, whitelist):
            print(yellow(f"  [IGNORÉ] IP en liste blanche : {ip}"))
            skipped.append(ip)
            continue
        valid_ips.append(entry)

    if not valid_ips:
        print(yellow("  Aucune IP à traiter."))
        return

    print(f"  IPs à traiter : {len(valid_ips)}  |  Ignorées : {len(skipped)}\n")

    # Note d'initialisation
    if engine == "nftables" and args.action == "block":
        print(yellow("  [INFO] Assurez-vous d'avoir initialisé nftables :"))
        print(yellow("  " + "\n  ".join(NFTABLES_INIT.strip().split("\n"))))
        print()
    if engine == "pf" and args.action == "block":
        print(yellow("  [INFO] Configuration pf requise :"))
        print(yellow("  " + "\n  ".join(PF_INIT.strip().split("\n"))))
        print()

    # Génération et exécution des commandes
    all_cmds = []
    for entry in valid_ips:
        ip = entry["ip"]
        count = entry.get("count", 0)
        reason = entry.get("reason", "")
        count_str = f"({count} tentatives)" if count else ""
        print(f"  {bold(ip)}  {yellow(count_str)}  [{reason}]")
        cmds = cmd_fn(ip, args.action)
        for cmd in cmds:
            if args.dry_run or not args.apply:
                run_command(cmd, dry_run=True)
            else:
                run_command(cmd, dry_run=False)
            all_cmds.append(cmd)
        print()

    # Export en script
    if args.output:
        is_windows = engine == "windows"
        shebang = "@echo off\n" if is_windows else "#!/bin/bash\n# Firewall block script\nset -e\n"
        comment = "REM" if is_windows else "#"
        with open(args.output, "w", encoding="utf-8", newline="\r\n" if is_windows else "\n") as f:
            f.write(shebang)
            f.write(f"{comment} Généré par firewall_blocker.py — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
            f.write(f"{comment} Moteur : {engine} | Action : {args.action}\n\n")
            if engine == "nftables":
                f.write(NFTABLES_INIT + "\n")
            if engine == "pf":
                f.write(PF_INIT + "\n")
            for cmd in all_cmds:
                f.write(cmd + "\n")
        if not is_windows:
            os.chmod(args.output, 0o750)
        print(green(f"[+] Script sauvegardé : {args.output}"))

    print(cyan("=" * 65))
    if args.dry_run or not args.apply:
        print(yellow(f"  [DRY-RUN] {len(valid_ips)} IP(s) seraient traitées."))
        print(yellow(f"  Relancez avec --apply pour appliquer réellement."))
    else:
        print(green(f"  [✓] {len(valid_ips)} IP(s) traitées avec succès."))
    print(cyan("=" * 65))


if __name__ == "__main__":
    main()
