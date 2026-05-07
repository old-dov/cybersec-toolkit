#!/usr/bin/env python3
"""
=============================================================================
 cybersec_launcher.py — Lanceur interactif de scripts cybersécurité
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : colorama (optionnel)

 DESCRIPTION
 -----------
 Menu interactif qui organise les scripts par paires MENACE / REMÈDE.
 Pour chaque catégorie de menace, vous voyez immédiatement les outils
 d'analyse ET les outils de remédiation correspondants.

 USAGE
 -----
   python cybersec_launcher.py
   python cybersec_launcher.py --list      # Afficher le catalogue complet
   python cybersec_launcher.py --run port_scanner --args "--target 10.0.0.1"
=============================================================================
"""

import argparse
import os
import platform
import subprocess
import sys
from pathlib import Path

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    C = True
except ImportError:
    C = False

# ─── Helpers couleur ─────────────────────────────────────────────────────────

def _c(code, t):  return f"{code}{t}{Style.RESET_ALL}" if C else t
def red(t):       return _c(Fore.RED, t)
def green(t):     return _c(Fore.GREEN, t)
def yellow(t):    return _c(Fore.YELLOW, t)
def cyan(t):      return _c(Fore.CYAN, t)
def magenta(t):   return _c(Fore.MAGENTA, t)
def blue(t):      return _c(Fore.BLUE, t)
def white(t):     return _c(Fore.WHITE, t)
def bold(t):      return _c(Style.BRIGHT, t)
def dim(t):       return _c(Style.DIM, t)
def bg_dark(t):   return _c(Back.BLACK, t)

def clear():
    os.system("cls" if platform.system() == "Windows" else "clear")

# ─── Catalogue MENACE / REMÈDE ────────────────────────────────────────────────
# Chaque catégorie contient des scripts "menace" (détection/analyse/attaque)
# et des scripts "remède" (correction/durcissement/réponse).

BASE = Path(__file__).parent

CATALOG = [
    {
        "id":   "recon",
        "name": "Reconnaissance",
        "color": cyan,
        "icon": "[>]",
        "desc": "Cartographie des cibles, découverte de services et d'actifs exposés.",
        "threats": [
            {
                "script": "01_Reconnaissance/port_scanner.py",
                "name":   "port_scanner",
                "desc":   "Scan des ports TCP/UDP ouverts",
                "example": "--target 192.168.1.1 --ports 1-1024",
            },
            {
                "script": "01_Reconnaissance/subdomain_enum.py",
                "name":   "subdomain_enum",
                "desc":   "Énumération de sous-domaines",
                "example": "--domain example.com",
            },
            {
                "script": "01_Reconnaissance/whois_lookup.py",
                "name":   "whois_lookup",
                "desc":   "Informations WHOIS / ASN",
                "example": "--target example.com",
            },
        ],
        "remedies": [
            {
                "script": "07_Remediation/firewall_blocker.py",
                "name":   "firewall_blocker",
                "desc":   "Bloquer les IPs identifiées lors du scan",
                "example": "--ips 1.2.3.4 5.6.7.8 --apply",
            },
            {
                "script": "07_Remediation/system_hardener.py",
                "name":   "system_hardener",
                "desc":   "Durcir les services exposés détectés",
                "example": "--audit --category services",
            },
        ],
    },
    {
        "id":   "network",
        "name": "Analyse réseau",
        "color": cyan,
        "icon": "[~]",
        "desc": "Analyse du trafic, DNS, bannières et cartographie réseau.",
        "threats": [
            {
                "script": "02_Network_Analysis/network_mapper.py",
                "name":   "network_mapper",
                "desc":   "Cartographie du réseau local (ARP/ICMP)",
                "example": "--network 192.168.1.0/24",
            },
            {
                "script": "02_Network_Analysis/dns_analyzer.py",
                "name":   "dns_analyzer",
                "desc":   "Analyse DNS complète (MX, SPF, DKIM…)",
                "example": "--domain example.com",
            },
            {
                "script": "02_Network_Analysis/banner_grabber.py",
                "name":   "banner_grabber",
                "desc":   "Récupération des bannières de services",
                "example": "--target 192.168.1.1 --ports 22,80,443",
            },
        ],
        "remedies": [
            {
                "script": "07_Remediation/firewall_blocker.py",
                "name":   "firewall_blocker",
                "desc":   "Bloquer les connexions suspectes identifiées",
                "example": "--ips 1.2.3.4 --apply",
            },
            {
                "script": "07_Remediation/system_hardener.py",
                "name":   "system_hardener",
                "desc":   "Masquer les bannières et durcir la pile réseau",
                "example": "--audit --category sysctl",
            },
        ],
    },
    {
        "id":   "vulnassess",
        "name": "Évaluation des vulnérabilités",
        "color": yellow,
        "icon": "[!]",
        "desc": "Analyse SSL/TLS, en-têtes HTTP, redirections ouvertes.",
        "threats": [
            {
                "script": "03_Vulnerability_Assessment/ssl_checker.py",
                "name":   "ssl_checker",
                "desc":   "Audit SSL/TLS (protocoles, certificats, chiffres)",
                "example": "--host example.com",
            },
            {
                "script": "03_Vulnerability_Assessment/http_headers_analyzer.py",
                "name":   "http_headers_analyzer",
                "desc":   "Analyse des en-têtes de sécurité HTTP",
                "example": "--url https://example.com",
            },
            {
                "script": "03_Vulnerability_Assessment/open_redirect_checker.py",
                "name":   "open_redirect_checker",
                "desc":   "Détection des redirections ouvertes",
                "example": "--url https://example.com/redirect?url=INJECT",
            },
        ],
        "remedies": [
            {
                "script": "07_Remediation/ssl_hardening_config.py",
                "name":   "ssl_hardening_config",
                "desc":   "Générer une config TLS durcée (nginx/apache/haproxy)",
                "example": "--domain example.com --profile modern --server nginx",
            },
            {
                "script": "07_Remediation/harden_http_headers.py",
                "name":   "harden_http_headers",
                "desc":   "Générer les en-têtes de sécurité HTTP manquants",
                "example": "--server nginx --json scan.json",
            },
        ],
    },
    {
        "id":   "logs",
        "name": "Analyse de logs",
        "color": yellow,
        "icon": "[L]",
        "desc": "Détection d'anomalies, tentatives de connexion, activité suspecte.",
        "threats": [
            {
                "script": "04_Log_Analysis/log_parser.py",
                "name":   "log_parser",
                "desc":   "Analyse de fichiers de logs (Apache, auth, syslog)",
                "example": "--file /var/log/auth.log",
            },
            {
                "script": "04_Log_Analysis/failed_login_detector.py",
                "name":   "failed_login_detector",
                "desc":   "Détection d'attaques brute-force par log",
                "example": "--file /var/log/auth.log --threshold 10",
            },
        ],
        "remedies": [
            {
                "script": "07_Remediation/firewall_blocker.py",
                "name":   "firewall_blocker",
                "desc":   "Bloquer les IPs de brute-force détectées",
                "example": "--json brute_report.json --apply",
            },
            {
                "script": "07_Remediation/system_hardener.py",
                "name":   "system_hardener",
                "desc":   "Durcir SSH et la politique de comptes",
                "example": "--apply --category ssh",
            },
        ],
    },
    {
        "id":   "crypto",
        "name": "Cryptographie",
        "color": blue,
        "icon": "[#]",
        "desc": "Chiffrement de fichiers, génération et vérification de hachages.",
        "threats": [
            {
                "script": "05_Cryptography/file_encryptor.py",
                "name":   "file_encryptor",
                "desc":   "Chiffrer/déchiffrer des fichiers (AES-256-GCM)",
                "example": "--file secret.txt --encrypt",
            },
            {
                "script": "05_Cryptography/hash_generator.py",
                "name":   "hash_generator",
                "desc":   "Générer et vérifier des hachages (MD5/SHA/BLAKE2)",
                "example": "--file document.pdf --algo sha256",
            },
        ],
        "remedies": [],
    },
    {
        "id":   "exploit",
        "name": "Exploitation",
        "color": red,
        "icon": "[X]",
        "desc": "Identification de CVEs exploitables, encodage de payloads pour tests WAF.",
        "threats": [
            {
                "script": "08_Exploitation/exploit_suggester.py",
                "name":   "exploit_suggester",
                "desc":   "Suggérer des CVEs pour les services détectés (NVD API)",
                "example": "--json banners.json --cvss-min 7.0",
            },
            {
                "script": "08_Exploitation/payload_encoder.py",
                "name":   "payload_encoder",
                "desc":   "Encodage multi-format de payloads (base64, hex, unicode…)",
                "example": '--payload "<script>alert(1)</script>" --encoder base64,url',
            },
        ],
        "remedies": [
            {
                "script": "07_Remediation/patch_manager.py",
                "name":   "patch_manager",
                "desc":   "Mettre à jour les paquets vulnérables identifiés",
                "example": "--json cves.json --apply",
            },
            {
                "script": "07_Remediation/system_hardener.py",
                "name":   "system_hardener",
                "desc":   "Durcissement système post-identification CVE",
                "example": "--apply --category all",
            },
        ],
    },
    {
        "id":   "privesc",
        "name": "Post-exploitation / Privesc",
        "color": red,
        "icon": "[^]",
        "desc": "Vecteurs d'élévation de privilèges, secrets exposés dans l'environnement.",
        "threats": [
            {
                "script": "09_Post_Exploitation/privesc_checker.py",
                "name":   "privesc_checker",
                "desc":   "Audit local des vecteurs de privesc (SUID, sudo, cron…)",
                "example": "",
            },
            {
                "script": "09_Post_Exploitation/env_secrets_scanner.py",
                "name":   "env_secrets_scanner",
                "desc":   "Scanner les secrets exposés (clés API, mots de passe)",
                "example": "--dir /var/www --recursive",
            },
        ],
        "remedies": [
            {
                "script": "07_Remediation/system_hardener.py",
                "name":   "system_hardener",
                "desc":   "Corriger les vecteurs de privesc détectés",
                "example": "--apply --category accounts",
            },
            {
                "script": "07_Remediation/patch_manager.py",
                "name":   "patch_manager",
                "desc":   "Mettre à jour les binaires SUID/vulnérables",
                "example": "--packages sudo openssh-server --apply",
            },
        ],
    },
    {
        "id":   "web",
        "name": "Sécurité Web",
        "color": magenta,
        "icon": "[W]",
        "desc": "Injection SQL, XSS, découverte de répertoires cachés.",
        "threats": [
            {
                "script": "10_Web_Security/sqli_detector.py",
                "name":   "sqli_detector",
                "desc":   "Détection d'injections SQL (error/boolean/time-based)",
                "example": "--url 'https://site.com/page?id=INJECT'",
            },
            {
                "script": "10_Web_Security/xss_scanner.py",
                "name":   "xss_scanner",
                "desc":   "Scanner XSS réfléchi (paramètres + formulaires)",
                "example": "--url https://site.com/search --forms",
            },
            {
                "script": "10_Web_Security/dir_bruteforcer.py",
                "name":   "dir_bruteforcer",
                "desc":   "Découverte de répertoires et fichiers cachés",
                "example": "--url https://site.com --extensions .php,.bak",
            },
        ],
        "remedies": [
            {
                "script": "07_Remediation/web_vuln_patcher.py",
                "name":   "web_vuln_patcher",
                "desc":   "Générer des règles WAF depuis les résultats de scan",
                "example": "--sqli sqli.json --xss xss.json --server nginx -o waf.conf",
            },
            {
                "script": "07_Remediation/harden_http_headers.py",
                "name":   "harden_http_headers",
                "desc":   "Ajouter les en-têtes CSP/HSTS/X-Frame-Options",
                "example": "--server nginx --csp strict",
            },
        ],
    },
    {
        "id":   "osint",
        "name": "OSINT",
        "color": magenta,
        "icon": "[O]",
        "desc": "Renseignement en sources ouvertes : emails, pseudonymes, métadonnées.",
        "threats": [
            {
                "script": "11_OSINT/email_harvester.py",
                "name":   "email_harvester",
                "desc":   "Collecter les adresses email publiques d'un site",
                "example": "--url https://example.com --depth 3",
            },
            {
                "script": "11_OSINT/username_checker.py",
                "name":   "username_checker",
                "desc":   "Vérifier un pseudonyme sur ~35 plateformes",
                "example": "--username johndoe",
            },
            {
                "script": "11_OSINT/metadata_extractor.py",
                "name":   "metadata_extractor",
                "desc":   "Extraire les métadonnées (EXIF GPS, auteur PDF/Office)",
                "example": "--dir ./documents --recursive",
            },
        ],
        "remedies": [
            {
                "script": "07_Remediation/metadata_cleaner.py",
                "name":   "metadata_cleaner",
                "desc":   "Supprimer les métadonnées sensibles avant publication",
                "example": "--dir ./documents --recursive",
            },
        ],
    },
    {
        "id":   "forensic",
        "name": "Forensic / IR",
        "color": green,
        "icon": "[F]",
        "desc": "Investigation numérique, collecte d'artefacts, timeline, IOC.",
        "threats": [
            {
                "script": "12_Forensic_IR/ioc_scanner.py",
                "name":   "ioc_scanner",
                "desc":   "Scanner des IOC (hachages, IPs, domaines malveillants)",
                "example": "--ioc-file iocs.json --scan-path /var/www --check-network",
            },
            {
                "script": "12_Forensic_IR/timeline_builder.py",
                "name":   "timeline_builder",
                "desc":   "Construire une timeline forensique des fichiers modifiés",
                "example": '--path /var/www --start "2026-01-01" --suspicious-only',
            },
            {
                "script": "12_Forensic_IR/artifact_collector.py",
                "name":   "artifact_collector",
                "desc":   "Collecter les artefacts système (logs, cron, réseau…)",
                "example": "--categories all -o artifacts/",
            },
        ],
        "remedies": [
            {
                "script": "07_Remediation/firewall_blocker.py",
                "name":   "firewall_blocker",
                "desc":   "Bloquer les IPs malveillantes identifiées par les IOC",
                "example": "--ips 1.2.3.4 5.6.7.8 --apply",
            },
            {
                "script": "06_Reporting/report_generator.py",
                "name":   "report_generator",
                "desc":   "Générer le rapport d'incident final",
                "example": "--title 'Incident 2026-05-07' --json findings.json",
            },
        ],
    },
]

# ─── Résolution d'un script ───────────────────────────────────────────────────

def resolve(script_path: str) -> Path:
    return BASE / script_path


def script_exists(script_path: str) -> bool:
    return resolve(script_path).exists()

# ─── Affichage ────────────────────────────────────────────────────────────────

WIDTH = 72

def divider(ch="─", color=dim):
    print(color(ch * WIDTH))


def header():
    clear()
    divider("═", cyan)
    title = "  CyberSec Toolkit — Lanceur interactif"
    sub   = f"  OS: {platform.system()} {platform.release()}  |  Python {sys.version.split()[0]}"
    print(bold(cyan(title)))
    print(dim(sub))
    divider("═", cyan)


def print_category_line(idx: int, cat: dict, short: bool = False):
    color = cat["color"]
    icon  = cat["icon"]
    name  = cat["name"]
    desc  = cat["desc"] if not short else ""
    threat_count = len(cat["threats"])
    remedy_count = len(cat["remedies"])
    badge = dim(f"({threat_count}T / {remedy_count}R)")
    print(f"  {bold(str(idx)):>4}  {color(icon)}  {bold(name):30}  {badge}")
    if desc and not short:
        print(f"         {dim(desc[:WIDTH-10])}")


def print_script_entry(idx: int | str, entry: dict, label_color, label: str):
    exists = script_exists(entry["script"])
    status = green("✓") if exists else yellow("?")
    print(f"    {dim(str(idx)):>4}  {status}  {label_color(label):12}  "
          f"{bold(entry['name']):<30}  {dim(entry['desc'][:32])}")


def show_category(cat: dict):
    header()
    color = cat["color"]
    print(f"\n  {color(cat['icon'])}  {bold(cat['name'])}")
    print(f"  {dim(cat['desc'])}\n")

    # Menaces
    divider()
    print(f"  {bold(red('MENACES'))} — Outils d'analyse / détection / attaque\n")
    for i, t in enumerate(cat["threats"], 1):
        exists = script_exists(t["script"])
        status = green("✓") if exists else yellow("(non trouvé)")
        print(f"  {bold(str(i)):>4}  {red('▶')}  {bold(t['name'])}")
        print(f"         {dim(t['desc'])}")
        print(f"         {dim('Script:')} {t['script']}  {status}")
        if t["example"]:
            print(f"         {dim('Ex:')} {dim(t['example'][:60])}")
        print()

    # Remèdes
    divider()
    r_offset = len(cat["threats"])
    print(f"\n  {bold(green('REMÈDES'))} — Durcissement / Correctifs / Réponse\n")
    if cat["remedies"]:
        for i, r in enumerate(cat["remedies"], r_offset + 1):
            exists = script_exists(r["script"])
            status = green("✓") if exists else yellow("(non trouvé)")
            print(f"  {bold(str(i)):>4}  {green('✦')}  {bold(r['name'])}")
            print(f"         {dim(r['desc'])}")
            print(f"         {dim('Script:')} {r['script']}  {status}")
            if r["example"]:
                print(f"         {dim('Ex:')} {dim(r['example'][:60])}")
            print()
    else:
        print(f"  {dim('(aucun remède spécifique — catégorie utilitaire)')}\n")

    divider()
    all_scripts = cat["threats"] + cat["remedies"]
    return all_scripts


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return "q"

# ─── Lancement d'un script ────────────────────────────────────────────────────

def launch_script(entry: dict):
    path = resolve(entry["script"])
    if not path.exists():
        print(yellow(f"\n  [AVERT] Script introuvable : {path}"))
        ask("  Appuyez sur Entrée pour continuer...")
        return

    print(f"\n  {bold(green('Lancer :'))} {entry['name']}")
    print(f"  {dim('Script :')} {entry['script']}")
    if entry.get("example"):
        print(f"  {dim('Exemple :')} {entry['example']}\n")

    raw = ask(f"  Arguments (laisser vide pour --help) : ")
    args_list = raw.split() if raw else ["--help"]

    cmd = [sys.executable, str(path)] + args_list
    print(f"\n  {dim('Commande :')} {' '.join(cmd)}")
    divider("─", dim)
    print()
    try:
        subprocess.run(cmd, cwd=str(BASE))
    except Exception as e:
        print(red(f"  Erreur : {e}"))
    print()
    ask("  Appuyez sur Entrée pour revenir au menu...")

# ─── Pipeline guidé ───────────────────────────────────────────────────────────

PIPELINES = [
    {
        "name": "Audit web complet",
        "desc": "SSL → En-têtes → SQLi → XSS → Répertoires → Règles WAF",
        "steps": [
            ("03_Vulnerability_Assessment/ssl_checker.py",       "--host example.com"),
            ("03_Vulnerability_Assessment/http_headers_analyzer.py", "--url https://example.com"),
            ("10_Web_Security/sqli_detector.py",                 "--url 'https://example.com?id=INJECT'"),
            ("10_Web_Security/xss_scanner.py",                   "--url https://example.com --forms"),
            ("10_Web_Security/dir_bruteforcer.py",               "--url https://example.com"),
            ("07_Remediation/web_vuln_patcher.py",               "--harden-all --server nginx -o waf.conf"),
        ],
    },
    {
        "name": "Réponse à incident (IR)",
        "desc": "Collecte → Timeline → IOC → Blocage → Rapport",
        "steps": [
            ("12_Forensic_IR/artifact_collector.py",  "--categories all -o artifacts/"),
            ("12_Forensic_IR/timeline_builder.py",    "--path . --suspicious-only"),
            ("12_Forensic_IR/ioc_scanner.py",         "--ioc-file iocs.json --scan-path . --check-network"),
            ("07_Remediation/firewall_blocker.py",    "--json ir_report.json --apply"),
            ("06_Reporting/report_generator.py",      "--title 'Incident Report'"),
        ],
    },
    {
        "name": "Durcissement système",
        "desc": "Audit → Firewall → TLS → En-têtes → Patchs",
        "steps": [
            ("07_Remediation/system_hardener.py",      "--audit"),
            ("07_Remediation/ssl_hardening_config.py", "--domain example.com --profile modern --server nginx"),
            ("07_Remediation/harden_http_headers.py",  "--server nginx --csp strict"),
            ("07_Remediation/patch_manager.py",        "--audit"),
        ],
    },
    {
        "name": "Reconnaissance + Rapport",
        "desc": "Ports → Sous-domaines → WHOIS → Bannières → Rapport",
        "steps": [
            ("01_Reconnaissance/port_scanner.py",    "--target 192.168.1.1"),
            ("01_Reconnaissance/subdomain_enum.py",  "--domain example.com"),
            ("01_Reconnaissance/whois_lookup.py",    "--target example.com"),
            ("02_Network_Analysis/banner_grabber.py","--target 192.168.1.1 --ports 22,80,443"),
            ("06_Reporting/report_generator.py",     "--title 'Recon Report'"),
        ],
    },
    {
        "name": "OSINT + Protection vie privée",
        "desc": "Extraction métadonnées → Nettoyage → Vérif pseudonyme",
        "steps": [
            ("11_OSINT/metadata_extractor.py",   "--dir . --recursive"),
            ("07_Remediation/metadata_cleaner.py","--dir . --recursive"),
            ("11_OSINT/username_checker.py",      "--username monpseudo"),
            ("11_OSINT/email_harvester.py",       "--url https://example.com"),
        ],
    },
]


def show_pipelines():
    header()
    print(f"\n  {bold('PIPELINES GUIDÉS')} — Enchaînements menace → remède\n")
    divider()
    for i, p in enumerate(PIPELINES, 1):
        print(f"  {bold(str(i)):>4}  {yellow('▶▶')}  {bold(p['name'])}")
        print(f"         {dim(p['desc'])}")
        print()
    divider()
    print(f"  {dim('0')}  {dim('← Retour')}\n")

    choice = ask("  Choisir un pipeline : ")
    if choice == "0" or choice.lower() == "q":
        return

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(PIPELINES):
            show_pipeline_detail(PIPELINES[idx])
    except ValueError:
        pass


def show_pipeline_detail(pipeline: dict):
    header()
    print(f"\n  {bold(yellow('PIPELINE :'))} {pipeline['name']}")
    print(f"  {dim(pipeline['desc'])}\n")
    divider()
    for i, (script, example) in enumerate(pipeline["steps"], 1):
        name = Path(script).stem
        exists = (BASE / script).exists()
        status = green("✓") if exists else yellow("?")
        print(f"  {bold(str(i)):>4}  {status}  {bold(name):<32}  {dim(example[:36])}")
    divider()
    msg = "  Entrez le numéro d'une étape pour la lancer, ou 0 pour revenir."
    print(f"\n{dim(msg)}\n")

    choice = ask("  Étape : ")
    if choice == "0" or choice.lower() == "q":
        return
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(pipeline["steps"]):
            script_path, example = pipeline["steps"][idx]
            entry = {
                "name":    Path(script_path).stem,
                "script":  script_path,
                "desc":    "",
                "example": example,
            }
            launch_script(entry)
    except ValueError:
        pass

# ─── Menu principal ───────────────────────────────────────────────────────────

def main_menu():
    while True:
        header()
        print(f"\n  {bold('CATÉGORIES')} — Choisir un contexte d'opération\n")
        divider()
        for i, cat in enumerate(CATALOG, 1):
            print_category_line(i, cat)
        divider()
        print(f"\n  {bold('p')}  {yellow('▶▶')}  Pipelines guidés (enchaînements menace → remède)")
        print(f"  {bold('l')}  {dim('   ')}  Lister tous les scripts")
        print(f"  {bold('q')}  {dim('   ')}  Quitter\n")

        choice = ask("  Votre choix : ")

        if choice.lower() == "q":
            print(cyan("\n  À bientôt.\n"))
            break
        elif choice.lower() == "p":
            show_pipelines()
        elif choice.lower() == "l":
            show_full_list()
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(CATALOG):
                    cat_menu(CATALOG[idx])
            except ValueError:
                pass


def cat_menu(cat: dict):
    all_scripts = show_category(cat)
    print(f"  {dim('Entrez un numéro pour lancer un script, 0 pour revenir.')}\n")
    choice = ask("  Votre choix : ")
    if choice == "0" or choice.lower() == "q":
        return
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(all_scripts):
            launch_script(all_scripts[idx])
    except ValueError:
        pass


def show_full_list():
    header()
    print(f"\n  {bold('CATALOGUE COMPLET')}\n")
    for cat in CATALOG:
        color = cat["color"]
        print(f"\n  {color(cat['icon'])}  {bold(cat['name'])}")
        for t in cat["threats"]:
            exists = script_exists(t["script"])
            s = green("✓") if exists else dim("·")
            print(f"    {red('▶')} {s} {t['name']:<35} {dim(t['script'])}")
        for r in cat["remedies"]:
            exists = script_exists(r["script"])
            s = green("✓") if exists else dim("·")
            print(f"    {green('✦')} {s} {r['name']:<35} {dim(r['script'])}")
    print()
    divider()
    ask("  Appuyez sur Entrée pour revenir...")

# ─── CLI direct ───────────────────────────────────────────────────────────────

def cli_list():
    """Affiche le catalogue en mode non-interactif."""
    for cat in CATALOG:
        print(f"\n{'='*60}")
        print(f"  {cat['name']} — {cat['desc']}")
        print(f"{'='*60}")
        print("  MENACES:")
        for t in cat["threats"]:
            print(f"    ▶  {t['name']:<30}  {t['script']}")
        print("  REMÈDES:")
        for r in cat["remedies"]:
            print(f"    ✦  {r['name']:<30}  {r['script']}")


def cli_run(name: str, extra_args: str):
    """Lance directement un script par son nom."""
    for cat in CATALOG:
        for entry in cat["threats"] + cat["remedies"]:
            if entry["name"] == name:
                path = resolve(entry["script"])
                if not path.exists():
                    print(f"Script introuvable : {path}")
                    sys.exit(1)
                args = extra_args.split() if extra_args else ["--help"]
                subprocess.run([sys.executable, str(path)] + args, cwd=str(BASE))
                return
    print(f"Script '{name}' inconnu. Utilisez --list pour voir les noms.")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Lanceur interactif — CyberSec Toolkit",
        add_help=False,
    )
    parser.add_argument("--list",  action="store_true",
                        help="Lister tous les scripts sans interface")
    parser.add_argument("--run",   metavar="NOM",
                        help="Lancer directement un script par son nom")
    parser.add_argument("--args",  metavar="'...'", default="",
                        help="Arguments à passer au script (avec --run)")
    parser.add_argument("-h", "--help", action="store_true")

    args, _ = parser.parse_known_args()

    if args.help:
        parser.print_help()
        return
    if args.list:
        cli_list()
        return
    if args.run:
        cli_run(args.run, args.args)
        return

    main_menu()


if __name__ == "__main__":
    main()
