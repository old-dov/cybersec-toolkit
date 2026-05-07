#!/usr/bin/env python3
"""
=============================================================================
 system_hardener.py — Audit et durcissement système (multi-OS)
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : stdlib uniquement
 Droits   : Certains audits et tous les --apply requièrent admin/root

 DESCRIPTION
 -----------
 Réalise un audit de sécurité système complet et peut appliquer
 automatiquement les correctifs de durcissement (hardening).

 Vérifie et corrige selon l'OS détecté :

   Linux   → SSH config, sysctl, UFW/iptables, fail2ban, comptes, SUID
   macOS   → SSH config, pf, SIP, Gatekeeper, FileVault, comptes
   Windows → SMB, RDP, PowerShell logging, Windows Defender, comptes locaux

 MODES
 -----
   --audit     Vérification sans modification (mode par défaut)
   --apply     Application des correctifs (requiert admin/root)
   --dry-run   Affiche les commandes --apply sans les exécuter

 USAGE
 -----
   python system_hardener.py [options]

 EXEMPLES
 --------
   # Audit complet (lecture seule)
   python system_hardener.py --audit

   # Voir ce qui serait appliqué
   python system_hardener.py --apply --dry-run

   # Appliquer sur Linux (root requis)
   sudo python system_hardener.py --apply

   # Seulement l'audit SSH
   python system_hardener.py --audit --category ssh

   # Exporter le rapport d'audit en JSON
   python system_hardener.py --audit --json -o audit.json

 OPTIONS
 -------
   --audit       Mode audit (défaut, lecture seule)
   --apply       Appliquer les correctifs de durcissement
   --dry-run     Simuler --apply sans exécuter
   --category    Filtrer : ssh, sysctl, firewall, accounts, services, all
   --json        Exporter les résultats en JSON
   -o, --output  Fichier de sortie
   -v, --verbose Afficher les détails

 CODES DE RETOUR
 ---------------
   0 → Tout est OK
   1 → Des problèmes ont été détectés (voir rapport)
   2 → Erreur d'exécution

 AVERTISSEMENT LÉGAL
 -------------------
 Ce script est fourni à des fins éducatives et d'audit légal uniquement.
 Utilisez-le uniquement sur des systèmes que vous êtes autorisé à auditer.
=============================================================================
"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
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

OS = platform.system().lower()  # "linux", "darwin", "windows"

# ─── Structures de résultat ──────────────────────────────────────────────────

def make_check(name: str, category: str, status: str,
               detail: str = "", fix: str = "", severity: str = "medium") -> dict:
    """status : ok | warn | fail | skip"""
    return {
        "name":     name,
        "category": category,
        "status":   status,
        "detail":   detail,
        "fix":      fix,
        "severity": severity,
    }

def run_cmd(cmd: str | list, timeout: int = 10) -> tuple[int, str, str]:
    """Exécute une commande, retourne (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", "not found"
    except Exception as e:
        return -3, "", str(e)

def read_file_safe(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""

# ─── Checks Linux ────────────────────────────────────────────────────────────

def check_linux_ssh() -> list[dict]:
    checks = []
    cfg = read_file_safe("/etc/ssh/sshd_config")
    if not cfg:
        checks.append(make_check("SSH config lisible", "ssh", "skip",
                                 "Impossible de lire /etc/ssh/sshd_config"))
        return checks

    tests = [
        ("PermitRootLogin",        r"^\s*PermitRootLogin\s+no",        "PermitRootLogin no",
         "PermitRootLogin no", "critical"),
        ("PasswordAuthentication", r"^\s*PasswordAuthentication\s+no", "PasswordAuthentication no",
         "PasswordAuthentication no", "high"),
        ("MaxAuthTries",           r"^\s*MaxAuthTries\s+[1-4]\b",      "MaxAuthTries ≤ 4",
         "MaxAuthTries 3", "medium"),
        ("X11Forwarding off",      r"^\s*X11Forwarding\s+no",          "X11Forwarding no",
         "X11Forwarding no", "low"),
        ("Protocol 2",             r"^\s*Protocol\s+2",                "Protocol 2",
         "Protocol 2", "high"),
        ("LoginGraceTime",         r"^\s*LoginGraceTime\s+([1-5]?\d[sm]|[1-5]\d\b)", "LoginGraceTime < 60s",
         "LoginGraceTime 30", "medium"),
    ]
    for name, pattern, desc, fix_line, severity in tests:
        found = bool(re.search(pattern, cfg, re.MULTILINE | re.IGNORECASE))
        status = "ok" if found else "fail"
        checks.append(make_check(
            f"SSH: {desc}", "ssh", status,
            detail=f"Pattern attendu : {pattern}" if not found else "",
            fix=f"Ajouter/modifier dans /etc/ssh/sshd_config : {fix_line}" if not found else "",
            severity=severity,
        ))
    return checks


def check_linux_sysctl() -> list[dict]:
    params = {
        "net.ipv4.ip_forward":                ("0", "Désactiver IP forwarding", "medium"),
        "net.ipv4.conf.all.accept_redirects":  ("0", "Refuser ICMP redirects", "medium"),
        "net.ipv4.conf.all.send_redirects":    ("0", "Ne pas envoyer ICMP redirects", "medium"),
        "net.ipv4.conf.all.accept_source_route": ("0", "Refuser source routing", "medium"),
        "net.ipv4.tcp_syncookies":             ("1", "Activer TCP SYN cookies", "high"),
        "net.ipv4.conf.all.log_martians":      ("1", "Logger les paquets martiens", "low"),
        "kernel.randomize_va_space":           ("2", "ASLR complet", "high"),
        "kernel.dmesg_restrict":               ("1", "Restreindre dmesg", "medium"),
        "fs.suid_dumpable":                    ("0", "Désactiver core dumps SUID", "medium"),
    }
    checks = []
    for param, (expected, desc, severity) in params.items():
        rc, stdout, _ = run_cmd(["sysctl", "-n", param])
        if rc == -2:
            checks.append(make_check(f"sysctl: {param}", "sysctl", "skip",
                                     "sysctl non disponible"))
            break
        val = stdout.strip()
        status = "ok" if val == expected else "fail"
        checks.append(make_check(
            f"sysctl: {desc}", "sysctl", status,
            detail=f"{param} = {val!r} (attendu: {expected!r})" if val != expected else f"{param} = {val}",
            fix=f"sysctl -w {param}={expected}" if val != expected else "",
            severity=severity,
        ))
    return checks


def check_linux_firewall() -> list[dict]:
    checks = []
    # UFW
    rc, stdout, _ = run_cmd("ufw status")
    if rc == 0:
        active = "active" in stdout.lower()
        checks.append(make_check(
            "UFW actif", "firewall", "ok" if active else "fail",
            detail=stdout.split("\n")[0] if stdout else "",
            fix="ufw enable" if not active else "",
            severity="high",
        ))
    else:
        # iptables fallback
        rc2, stdout2, _ = run_cmd("iptables -L INPUT -n --line-numbers")
        has_rules = rc2 == 0 and len(stdout2.splitlines()) > 2
        checks.append(make_check(
            "iptables: règles INPUT présentes", "firewall",
            "ok" if has_rules else "warn",
            detail="Aucune règle iptables détectée" if not has_rules else "",
            fix="Configurez iptables ou installez ufw" if not has_rules else "",
            severity="high",
        ))
    # fail2ban
    rc3, _, _ = run_cmd("systemctl is-active fail2ban")
    f2b = rc3 == 0
    checks.append(make_check(
        "fail2ban actif", "firewall", "ok" if f2b else "warn",
        fix="apt install fail2ban && systemctl enable --now fail2ban" if not f2b else "",
        severity="medium",
    ))
    return checks


def check_linux_accounts() -> list[dict]:
    checks = []
    # Comptes avec UID=0 autres que root
    rc, stdout, _ = run_cmd("awk -F: '($3==0 && $1!=\"root\"){print $1}' /etc/passwd")
    extra_roots = [l.strip() for l in stdout.splitlines() if l.strip()] if rc == 0 else []
    checks.append(make_check(
        "Comptes UID=0 supplémentaires", "accounts",
        "fail" if extra_roots else "ok",
        detail=f"Comptes trouvés : {', '.join(extra_roots)}" if extra_roots else "",
        fix="Supprimez ou modifiez ces comptes : " + ", ".join(extra_roots) if extra_roots else "",
        severity="critical",
    ))
    # Comptes sans mot de passe
    rc2, stdout2, _ = run_cmd("awk -F: '($2==\"\" || $2==\"!!\"){print $1}' /etc/shadow")
    empty_pw = [l.strip() for l in stdout2.splitlines() if l.strip()] if rc2 == 0 else []
    checks.append(make_check(
        "Comptes sans mot de passe", "accounts",
        "fail" if empty_pw else "ok",
        detail=f"Comptes : {', '.join(empty_pw)}" if empty_pw else "",
        fix="passwd <utilisateur> pour chaque compte" if empty_pw else "",
        severity="critical",
    ))
    return checks

# ─── Checks macOS ─────────────────────────────────────────────────────────────

def check_macos_sip() -> list[dict]:
    rc, stdout, _ = run_cmd("csrutil status")
    enabled = "enabled" in stdout.lower()
    return [make_check(
        "SIP (System Integrity Protection)", "services",
        "ok" if enabled else "warn",
        detail=stdout,
        fix="Réactivez SIP depuis le mode Recovery (csrutil enable)" if not enabled else "",
        severity="high",
    )]


def check_macos_gatekeeper() -> list[dict]:
    rc, stdout, _ = run_cmd("spctl --status")
    enabled = "enabled" in stdout.lower() or "assessments enabled" in stdout.lower()
    return [make_check(
        "Gatekeeper", "services", "ok" if enabled else "warn",
        detail=stdout,
        fix="spctl --master-enable" if not enabled else "",
        severity="medium",
    )]


def check_macos_filevault() -> list[dict]:
    rc, stdout, _ = run_cmd("fdesetup status")
    enabled = "on" in stdout.lower()
    return [make_check(
        "FileVault (chiffrement disque)", "services",
        "ok" if enabled else "warn",
        detail=stdout,
        fix="Activer via : Préférences Système → Sécurité → FileVault" if not enabled else "",
        severity="high",
    )]


def check_macos_firewall() -> list[dict]:
    rc, stdout, _ = run_cmd(
        "defaults read /Library/Preferences/com.apple.alf globalstate"
    )
    state = stdout.strip()
    enabled = state in ("1", "2")
    return [make_check(
        "Pare-feu macOS", "firewall",
        "ok" if enabled else "fail",
        detail=f"globalstate = {state}",
        fix="Activer : Préférences Système → Sécurité → Pare-feu (ou: /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on)" if not enabled else "",
        severity="high",
    )]


def check_macos_ssh() -> list[dict]:
    return check_linux_ssh()  # même format SSH

# ─── Checks Windows ──────────────────────────────────────────────────────────

def check_windows_smb() -> list[dict]:
    rc, stdout, _ = run_cmd(
        'powershell -Command "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol | ConvertTo-Json"'
    )
    checks = []
    smb1 = True  # assume worst case
    if rc == 0:
        try:
            data = json.loads(stdout)
            smb1 = data.get("EnableSMB1Protocol", True)
        except json.JSONDecodeError:
            smb1 = "true" in stdout.lower()
    checks.append(make_check(
        "SMBv1 désactivé", "services",
        "ok" if not smb1 else "fail",
        detail="SMBv1 est activé (vecteur WannaCry/NotPetya)" if smb1 else "SMBv1 désactivé",
        fix="Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force" if smb1 else "",
        severity="critical",
    ))
    return checks


def check_windows_defender() -> list[dict]:
    rc, stdout, _ = run_cmd(
        'powershell -Command "Get-MpComputerStatus | Select-Object AMRunningMode,RealTimeProtectionEnabled | ConvertTo-Json"'
    )
    checks = []
    if rc != 0 or not stdout:
        checks.append(make_check("Windows Defender", "services", "skip",
                                 "Impossible de vérifier (Get-MpComputerStatus)"))
        return checks
    try:
        data = json.loads(stdout)
        rtp = data.get("RealTimeProtectionEnabled", False)
    except json.JSONDecodeError:
        rtp = False
    checks.append(make_check(
        "Defender : protection temps réel", "services",
        "ok" if rtp else "fail",
        fix="Set-MpPreference -DisableRealtimeMonitoring $false" if not rtp else "",
        severity="high",
    ))
    return checks


def check_windows_rdp() -> list[dict]:
    rc, stdout, _ = run_cmd(
        'reg query "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections'
    )
    rdp_enabled = "0x0" in stdout  # 0 = RDP activé
    return [make_check(
        "RDP désactivé (ou NLA requis)", "services",
        "warn" if rdp_enabled else "ok",
        detail="RDP activé — assurez-vous que NLA est requis" if rdp_enabled else "RDP désactivé",
        fix="reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f" if rdp_enabled else "",
        severity="high",
    )]


def check_windows_ps_logging() -> list[dict]:
    rc, stdout, _ = run_cmd(
        'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v EnableScriptBlockLogging'
    )
    enabled = "0x1" in stdout
    return [make_check(
        "PowerShell Script Block Logging", "services",
        "ok" if enabled else "warn",
        detail="Script Block Logging non activé" if not enabled else "Script Block Logging actif",
        fix=(
            'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" '
            '/v EnableScriptBlockLogging /t REG_DWORD /d 1 /f'
        ) if not enabled else "",
        severity="medium",
    )]


def check_windows_accounts() -> list[dict]:
    rc, stdout, _ = run_cmd(
        'powershell -Command "Get-LocalUser | Where-Object {$_.Enabled -eq $true} | Select-Object Name,PasswordRequired | ConvertTo-Json"'
    )
    checks = []
    if rc != 0 or not stdout:
        checks.append(make_check("Comptes locaux", "accounts", "skip",
                                 "Impossible d'énumérer les comptes locaux"))
        return checks
    try:
        users = json.loads(stdout)
        if isinstance(users, dict):
            users = [users]
        no_pw = [u["Name"] for u in users if not u.get("PasswordRequired", True)]
    except (json.JSONDecodeError, KeyError):
        no_pw = []
    checks.append(make_check(
        "Comptes locaux sans mot de passe requis", "accounts",
        "fail" if no_pw else "ok",
        detail=f"Comptes : {', '.join(no_pw)}" if no_pw else "",
        fix="net user <utilisateur> * pour définir un mot de passe" if no_pw else "",
        severity="high",
    ))
    return checks

# ─── Dispatch par OS ─────────────────────────────────────────────────────────

def run_all_checks(category: str, verbose: bool) -> list[dict]:
    checks = []
    cat = category.lower()

    if OS == "linux":
        if cat in ("all", "ssh"):      checks += check_linux_ssh()
        if cat in ("all", "sysctl"):   checks += check_linux_sysctl()
        if cat in ("all", "firewall"): checks += check_linux_firewall()
        if cat in ("all", "accounts"): checks += check_linux_accounts()
    elif OS == "darwin":
        if cat in ("all", "ssh"):      checks += check_macos_ssh()
        if cat in ("all", "firewall"): checks += check_macos_firewall()
        if cat in ("all", "services"):
            checks += check_macos_sip()
            checks += check_macos_gatekeeper()
            checks += check_macos_filevault()
    elif OS == "windows":
        if cat in ("all", "services"):
            checks += check_windows_smb()
            checks += check_windows_defender()
            checks += check_windows_rdp()
            checks += check_windows_ps_logging()
        if cat in ("all", "accounts"): checks += check_windows_accounts()
    else:
        print(yellow(f"[AVERT] OS non reconnu : {OS}"))

    return checks

# ─── Affichage ───────────────────────────────────────────────────────────────

STATUS_ICONS = {"ok": "✓", "fail": "✗", "warn": "!", "skip": "?"}
STATUS_COLORS = {
    "ok":   green,
    "fail": red,
    "warn": yellow,
    "skip": dim,
}

def print_check(c: dict, verbose: bool):
    icon = STATUS_ICONS.get(c["status"], "?")
    col  = STATUS_COLORS.get(c["status"], lambda x: x)
    sev  = f"[{c['severity'].upper()}]" if c["status"] in ("fail", "warn") else ""
    print(f"  {col(f'[{icon}]')}  {c['name']}  {yellow(sev)}")
    if verbose and c["detail"]:
        print(f"       {dim(c['detail'])}")
    if c["status"] in ("fail", "warn") and c["fix"]:
        print(f"       {cyan('→ Correctif :')} {c['fix']}")

# ─── Application des correctifs ──────────────────────────────────────────────

def apply_fix(check: dict, dry_run: bool) -> bool:
    if not check.get("fix"):
        return True
    cmd = check["fix"]
    if dry_run:
        print(f"  {yellow('[DRY-RUN]')} {cmd}")
        return True
    rc, stdout, stderr = run_cmd(cmd)
    if rc == 0:
        print(green(f"  [✓] Appliqué : {cmd}"))
        return True
    else:
        print(red(f"  [✗] Échec : {cmd}"))
        if stderr:
            print(red(f"      {stderr}"))
        return False

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Audit et durcissement système (Linux / macOS / Windows)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--audit",   action="store_true", help="Audit seul (défaut)")
    mode.add_argument("--apply",   action="store_true", help="Appliquer les correctifs")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Simuler --apply sans exécuter")
    parser.add_argument("--category",  default="all",
                        choices=["all", "ssh", "sysctl", "firewall", "accounts", "services"])
    parser.add_argument("--json",      action="store_true", help="Sortie JSON")
    parser.add_argument("-o", "--output", help="Fichier de sortie")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    # Par défaut : audit
    if not args.apply:
        args.audit = True

    # Vérification des droits si --apply sur Linux/macOS
    if args.apply and not args.dry_run and OS != "windows":
        if os.geteuid() != 0:
            print(red("[ERREUR] root requis pour --apply. Relancez avec sudo."))
            sys.exit(2)

    print(cyan("=" * 65))
    print(cyan(f"  System Hardener — {OS.upper()}"))
    print(cyan(f"  Mode     : {'APPLY' + (' (dry-run)' if args.dry_run else '') if args.apply else 'AUDIT'}"))
    print(cyan(f"  Catég.   : {args.category}"))
    print(cyan(f"  Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(cyan("=" * 65 + "\n"))

    checks = run_all_checks(args.category, args.verbose)

    if not checks:
        print(yellow("  Aucun check disponible pour cet OS/catégorie."))
        sys.exit(0)

    # Affichage
    cat_shown = set()
    for c in checks:
        if c["category"] not in cat_shown:
            print(bold(f"\n[ {c['category'].upper()} ]"))
            cat_shown.add(c["category"])
        print_check(c, args.verbose)

    # Statistiques
    total  = len(checks)
    ok     = sum(1 for c in checks if c["status"] == "ok")
    fails  = sum(1 for c in checks if c["status"] == "fail")
    warns  = sum(1 for c in checks if c["status"] == "warn")
    skips  = sum(1 for c in checks if c["status"] == "skip")

    print(f"\n{cyan('─' * 65)}")
    print(f"  Total : {total}  |  {green(f'OK: {ok}')}  |  "
          f"{red(f'Échec: {fails}')}  |  {yellow(f'Avert: {warns}')}  |  {dim(f'Skip: {skips}')}")
    print(cyan("─" * 65))

    # Application des correctifs
    if args.apply:
        to_fix = [c for c in checks if c["status"] in ("fail", "warn") and c.get("fix")]
        if to_fix:
            print(bold(f"\n[ APPLICATION DES CORRECTIFS ({len(to_fix)}) ]\n"))
            for c in to_fix:
                print(f"  → {c['name']}")
                apply_fix(c, dry_run=args.dry_run)
        else:
            print(green("\n  [✓] Aucun correctif à appliquer."))

    # Export JSON
    if args.json or args.output:
        report = {
            "timestamp": datetime.now().isoformat(),
            "os":        OS,
            "mode":      "apply" if args.apply else "audit",
            "category":  args.category,
            "summary": {"total": total, "ok": ok, "fail": fails, "warn": warns, "skip": skips},
            "checks": checks,
        }
        json_str = json.dumps(report, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_str)
            print(green(f"\n[+] Rapport sauvegardé : {args.output}"))
        else:
            print("\n" + json_str)

    sys.exit(0 if fails == 0 else 1)


if __name__ == "__main__":
    main()
