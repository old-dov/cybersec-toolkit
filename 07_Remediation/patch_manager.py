#!/usr/bin/env python3
"""
=============================================================================
 patch_manager.py — Gestionnaire de correctifs de sécurité
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : aucune (stdlib uniquement)

 DESCRIPTION
 -----------
 Génère et applique les commandes de mise à jour pour corriger les CVEs
 identifiées par exploit_suggester.py. Supporte les gestionnaires de
 paquets les plus courants sur chaque OS.

 GESTIONNAIRES SUPPORTÉS
 -----------------------
   Linux   → apt, apt-get, yum, dnf, pacman, zypper, apk
   macOS   → brew, pip3, npm
   Windows → winget, choco, pip, scoop

 USAGE
 -----
   python patch_manager.py [options]

 EXEMPLES
 --------
   python patch_manager.py --audit                  # Lister les mises à jour disponibles
   python patch_manager.py --json cves.json         # Depuis les résultats d'exploit_suggester
   python patch_manager.py --packages openssl nginx # Paquets spécifiques
   python patch_manager.py --audit --apply          # Audit puis appliquer
   python patch_manager.py --audit --dry-run        # Afficher sans exécuter
   python patch_manager.py --full-upgrade           # Mise à jour système complète

 OPTIONS
 -------
   --audit         Lister les mises à jour disponibles
   --json FILE     Fichier JSON d'exploit_suggester (filtre les paquets affectés)
   --packages      Paquets spécifiques à mettre à jour
   --full-upgrade  Mettre à jour tous les paquets du système
   --apply         Exécuter les commandes de mise à jour
   --dry-run       Afficher les commandes sans les exécuter
   --manager       Forcer un gestionnaire spécifique
   -o, --output    Rapport JSON de sortie

 AVERTISSEMENT LÉGAL
 -------------------
 Testez toujours les mises à jour dans un environnement de staging avant
 de les appliquer en production. Cet outil ne garantit pas la stabilité
 des services après mise à jour.
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

OS_NAME = platform.system()

# ─── Détection du gestionnaire de paquets ────────────────────────────────────

MANAGERS = {
    # Linux
    "apt":    {"check": ["apt", "list", "--upgradable"],
               "update": ["sudo", "apt-get", "update"],
               "upgrade_pkg": ["sudo", "apt-get", "install", "--only-upgrade"],
               "full_upgrade": ["sudo", "apt-get", "upgrade", "-y"]},
    "apt-get":{"check": ["apt-get", "--simulate", "upgrade"],
               "update": ["sudo", "apt-get", "update"],
               "upgrade_pkg": ["sudo", "apt-get", "install", "--only-upgrade"],
               "full_upgrade": ["sudo", "apt-get", "upgrade", "-y"]},
    "dnf":    {"check": ["dnf", "check-update"],
               "update": ["dnf", "makecache"],
               "upgrade_pkg": ["sudo", "dnf", "upgrade", "-y"],
               "full_upgrade": ["sudo", "dnf", "upgrade", "-y"]},
    "yum":    {"check": ["yum", "check-update"],
               "update": ["yum", "makecache"],
               "upgrade_pkg": ["sudo", "yum", "update", "-y"],
               "full_upgrade": ["sudo", "yum", "update", "-y"]},
    "pacman": {"check": ["pacman", "-Sup", "--print"],
               "update": ["sudo", "pacman", "-Sy"],
               "upgrade_pkg": ["sudo", "pacman", "-S", "--noconfirm"],
               "full_upgrade": ["sudo", "pacman", "-Syu", "--noconfirm"]},
    "zypper": {"check": ["zypper", "list-updates"],
               "update": ["sudo", "zypper", "refresh"],
               "upgrade_pkg": ["sudo", "zypper", "update", "-y"],
               "full_upgrade": ["sudo", "zypper", "update", "-y"]},
    "apk":    {"check": ["apk", "version"],
               "update": ["sudo", "apk", "update"],
               "upgrade_pkg": ["sudo", "apk", "add", "--upgrade"],
               "full_upgrade": ["sudo", "apk", "upgrade"]},
    # macOS
    "brew":   {"check": ["brew", "outdated"],
               "update": ["brew", "update"],
               "upgrade_pkg": ["brew", "upgrade"],
               "full_upgrade": ["brew", "upgrade"]},
    # Windows
    "winget": {"check": ["winget", "upgrade", "--include-unknown"],
               "update": [],
               "upgrade_pkg": ["winget", "upgrade", "--id"],
               "full_upgrade": ["winget", "upgrade", "--all", "--silent"]},
    "choco":  {"check": ["choco", "outdated"],
               "update": [],
               "upgrade_pkg": ["choco", "upgrade", "-y"],
               "full_upgrade": ["choco", "upgrade", "all", "-y"]},
    "scoop":  {"check": ["scoop", "status"],
               "update": ["scoop", "update"],
               "upgrade_pkg": ["scoop", "update"],
               "full_upgrade": ["scoop", "update", "*"]},
}

# Paquets Python / Node
PY_MANAGERS = {
    "pip":  {"check": ["pip", "list", "--outdated"],
             "upgrade_pkg": ["pip", "install", "--upgrade"]},
    "pip3": {"check": ["pip3", "list", "--outdated"],
             "upgrade_pkg": ["pip3", "install", "--upgrade"]},
    "npm":  {"check": ["npm", "outdated", "-g"],
             "upgrade_pkg": ["npm", "install", "-g"]},
}


def detect_manager() -> str | None:
    priority = {
        "Linux":   ["apt", "dnf", "yum", "pacman", "zypper", "apk"],
        "Darwin":  ["brew"],
        "Windows": ["winget", "choco", "scoop"],
    }.get(OS_NAME, [])

    for mgr in priority:
        try:
            subprocess.check_output(
                [mgr, "--version"], stderr=subprocess.DEVNULL
            )
            return mgr
        except Exception:
            pass
    return None


def run_cmd(cmd: list, dry_run: bool) -> tuple[int, str]:
    if dry_run:
        return 0, f"[DRY-RUN] {' '.join(cmd)}"
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        return out.returncode, out.stdout + out.stderr
    except Exception as e:
        return 1, str(e)

# ─── Extraction des paquets depuis exploit_suggester.json ────────────────────

def extract_packages_from_cve_json(path: str) -> list:
    """Extrait les noms de services/paquets depuis le JSON d'exploit_suggester."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        services = set()
        for item in data.get("results", []):
            svc = item.get("service", "")
            # Normaliser en nom de paquet (lowercase, remplacer espaces)
            svc = re.sub(r"\s+", "-", svc.lower().strip())
            if svc:
                services.add(svc)
        return list(services)
    except Exception as e:
        print(yellow(f"  [AVERT] Impossible de lire {path} : {e}"))
        return []

# ─── Actions ─────────────────────────────────────────────────────────────────

def do_audit(manager: str, dry_run: bool) -> list:
    """Liste les mises à jour disponibles."""
    cfg = MANAGERS[manager]
    results = []

    # Mise à jour des métadonnées
    if cfg.get("update"):
        print(dim(f"  Mise à jour du cache ({manager})..."))
        code, out = run_cmd(cfg["update"], dry_run)

    # Lister les mises à jour
    print(f"  Vérification des mises à jour via {bold(manager)}...")
    check_cmd = cfg["check"]
    code, out = run_cmd(check_cmd, dry_run)
    if out.strip():
        for line in out.splitlines()[:50]:
            if line.strip():
                results.append(line.strip())
                print(f"    {yellow('↑')} {line.strip()}")
    else:
        print(green("    Aucune mise à jour disponible."))
    return results


def do_upgrade(manager: str, packages: list, full: bool, dry_run: bool, apply: bool) -> list:
    """Génère et exécute les commandes de mise à jour."""
    cfg = MANAGERS[manager]
    actions = []

    if full:
        cmd = cfg["full_upgrade"]
        actions.append({"action": "full_upgrade", "cmd": " ".join(cmd)})
        print(f"  {bold('Mise à jour complète')} : {' '.join(cmd)}")
        if apply:
            code, out = run_cmd(cmd, dry_run)
            actions[-1]["rc"] = code
            actions[-1]["output"] = out[:2000]
            if code == 0:
                print(green("    ✓ Succès"))
            else:
                print(red(f"    ✗ Erreur (code {code})"))
    else:
        for pkg in packages:
            cmd = cfg["upgrade_pkg"] + [pkg]
            actions.append({"action": "upgrade", "package": pkg, "cmd": " ".join(cmd)})
            print(f"  {bold('Mise à jour')} {cyan(pkg)} : {' '.join(cmd)}")
            if apply:
                code, out = run_cmd(cmd, dry_run)
                actions[-1]["rc"] = code
                actions[-1]["output"] = out[:2000]
                if code == 0:
                    print(green("    ✓ Succès"))
                else:
                    print(red(f"    ✗ Erreur (code {code})"))

    return actions

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Gestionnaire de correctifs de sécurité (CVE → patch)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--audit",         action="store_true",
                        help="Lister les mises à jour disponibles")
    parser.add_argument("--json",          metavar="FILE",
                        help="JSON exploit_suggester.py pour filtrer les paquets")
    parser.add_argument("--packages",      nargs="+", metavar="PKG",
                        help="Paquets spécifiques à mettre à jour")
    parser.add_argument("--full-upgrade",  action="store_true",
                        help="Mettre à jour tous les paquets")
    parser.add_argument("--apply",         action="store_true",
                        help="Exécuter les commandes (défaut: afficher seulement)")
    parser.add_argument("--dry-run",       action="store_true",
                        help="Afficher sans exécuter")
    parser.add_argument("--manager",       choices=list(MANAGERS.keys()),
                        help="Forcer un gestionnaire de paquets")
    parser.add_argument("-o", "--output",  help="Rapport JSON")
    args = parser.parse_args()

    print(cyan("=" * 65))
    print(cyan("  Patch Manager — Gestionnaire de correctifs"))
    print(cyan(f"  OS : {OS_NAME} {platform.release()}"))
    print(cyan("=" * 65 + "\n"))

    manager = args.manager or detect_manager()
    if not manager:
        print(red("  [ERREUR] Aucun gestionnaire de paquets détecté."))
        sys.exit(1)
    print(f"  Gestionnaire détecté : {bold(manager)}\n")

    packages = list(args.packages or [])
    if args.json:
        from_json = extract_packages_from_cve_json(args.json)
        packages = list(set(packages + from_json))
        print(f"  Paquets issus de {args.json} : {', '.join(from_json) or 'aucun'}\n")

    report = {
        "timestamp": datetime.now().isoformat(),
        "os":        f"{OS_NAME} {platform.release()}",
        "manager":   manager,
        "actions":   [],
    }

    if args.audit:
        print(bold(cyan("[AUDIT] Mises à jour disponibles :")))
        updates = do_audit(manager, args.dry_run)
        report["available_updates"] = updates

    if packages or args.full_upgrade:
        if not args.apply and not args.dry_run:
            print(yellow("\n  [INFO] Utilisez --apply pour exécuter, ou --dry-run pour prévisualiser."))
        print(bold(cyan("\n[PATCH] Commandes de mise à jour :")))
        actions = do_upgrade(manager, packages, args.full_upgrade, args.dry_run, args.apply)
        report["actions"].extend(actions)
    elif not args.audit:
        parser.print_help()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(green(f"\n[+] Rapport : {args.output}"))


if __name__ == "__main__":
    main()
