#!/usr/bin/env python3
"""
=============================================================================
 dir_bruteforcer.py — Découverte de répertoires et fichiers web
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : requests

 DESCRIPTION
 -----------
 Enumère les ressources web (répertoires, fichiers, panneaux admin, backups)
 par force brute sur une wordlist.

 Dispose d'une wordlist intégrée de ~120 entrées couvrant les chemins
 courants (admin, backup, config, API, etc.).

 USAGE
 -----
   python dir_bruteforcer.py [options]

 EXEMPLES
 --------
   python dir_bruteforcer.py --url https://site.com
   python dir_bruteforcer.py --url https://site.com --wordlist wordlist.txt
   python dir_bruteforcer.py --url https://site.com --extensions php,html,bak
   python dir_bruteforcer.py --url https://site.com -T 20 --delay 0.1
   python dir_bruteforcer.py --url https://site.com -o found.json

 OPTIONS
 -------
   --url         URL de base (ex: https://site.com)
   --wordlist    Fichier wordlist custom (une entrée par ligne)
   --extensions  Extensions à tester, séparées par virgules (défaut: aucune)
   --codes       Codes HTTP à afficher (défaut: 200,201,301,302,403)
   -T, --threads Nombre de threads (défaut: 10)
   --delay       Délai entre les requêtes en secondes (défaut: 0)
   --timeout     Timeout par requête (défaut: 8)
   --no-verify   Désactiver la vérification SSL
   --cookie      Cookie de session
   --user-agent  User-Agent personnalisé
   -o, --output  Fichier JSON de sortie

 AVERTISSEMENT LÉGAL
 -------------------
 Utilisez uniquement sur des applications que vous êtes autorisé à tester.
=============================================================================
"""

import argparse
import json
import queue
import sys
import time
import threading
import urllib.parse
from datetime import datetime

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[ERREUR] Installez 'requests' : pip install requests")
    sys.exit(1)

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

# ─── Wordlist intégrée ────────────────────────────────────────────────────────

BUILTIN_WORDLIST = [
    # Admin / login
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "cpanel", "phpmyadmin", "adminer", "manager", "dashboard",
    "backend", "control", "panel", "console", "portal",
    # API
    "api", "api/v1", "api/v2", "api/v3", "rest", "graphql",
    "swagger", "swagger-ui", "openapi", "swagger.json", "api-docs",
    # Config / debug
    "config", "configuration", ".env", ".git", ".git/config",
    ".gitignore", "web.config", "phpinfo.php", "info.php",
    "debug", "test", "dev", "staging", "beta",
    # Backup
    "backup", "backups", "bak", "old", "archive",
    "db.sql", "backup.sql", "dump.sql", "database.sql",
    "backup.zip", "backup.tar.gz", "site.zip",
    # Fichiers sensibles
    "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "server-status", "server-info",   # Apache
    "nginx_status",                    # nginx
    ".DS_Store", "Thumbs.db",
    # Auth / secrets
    "credentials", "password", "passwords", "secrets",
    ".htpasswd", ".htaccess", "auth", "authentication",
    # Monitoring / health
    "health", "healthz", "ready", "ping", "status",
    "metrics", "actuator", "actuator/health", "actuator/env",
    # Docs
    "docs", "documentation", "help", "manual",
    # Upload
    "upload", "uploads", "files", "media", "static", "assets",
    # Common CMS
    "wp-content", "wp-includes", "wp-json",
    "joomla", "administrator/index.php",
    "drupal", "user/login",
    # Misc
    "index.php", "index.html", "home", "main",
    "shell", "cmd", "command", "exec",
    "tmp", "temp", "cache", "log", "logs",
    "cgi-bin", "cgi", "scripts",
]

# ─── Scan ─────────────────────────────────────────────────────────────────────

STATUS_COLORS = {
    200: green,
    201: green,
    301: cyan,
    302: cyan,
    303: cyan,
    307: cyan,
    308: cyan,
    401: yellow,
    403: yellow,
    405: yellow,
    500: red,
    503: red,
}

_lock     = threading.Lock()
_found    = []
_total    = 0
_scanned  = 0


def probe(session, url: str, codes: set, timeout: int, verify: bool,
          cookies: dict, delay: float) -> dict | None:
    global _scanned
    try:
        resp = session.get(url, timeout=timeout, verify=verify,
                           cookies=cookies, allow_redirects=False)
        with _lock:
            _scanned += 1
        if resp.status_code in codes:
            size = len(resp.content)
            return {
                "url":    url,
                "code":   resp.status_code,
                "size":   size,
                "redirect": resp.headers.get("Location", ""),
            }
    except Exception:
        with _lock:
            _scanned += 1
    if delay:
        time.sleep(delay)
    return None


def worker(session, q: queue.Queue, codes: set, timeout: int,
           verify: bool, cookies: dict, delay: float):
    while True:
        try:
            url = q.get(timeout=1)
        except queue.Empty:
            break
        result = probe(session, url, codes, timeout, verify, cookies, delay)
        if result:
            col = STATUS_COLORS.get(result["code"], dim)
            size_str = f"{result['size']:>8} B"
            redir = f"→ {result['redirect']}" if result["redirect"] else ""
            with _lock:
                code_str = col(f"[{result['code']}]")
                print(f"  {code_str}  {bold(result['url'])}  {dim(size_str)}  {dim(redir)}")
                _found.append(result)
        q.task_done()

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    global _total

    parser = argparse.ArgumentParser(
        description="Découverte de répertoires et fichiers web par force brute",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url",        required=True)
    parser.add_argument("--wordlist",   help="Wordlist custom (une entrée par ligne)")
    parser.add_argument("--extensions", default="",
                        help="Extensions : php,html,bak,sql,txt")
    parser.add_argument("--codes",      default="200,201,301,302,403,401",
                        help="Codes HTTP à afficher")
    parser.add_argument("-T", "--threads", type=int, default=10)
    parser.add_argument("--delay",      type=float, default=0.0)
    parser.add_argument("--timeout",    type=int, default=8)
    parser.add_argument("--no-verify",  action="store_true")
    parser.add_argument("--cookie",     default="")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (DirBrute; authorized-pentest)")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()

    base = args.url.rstrip("/")
    codes = {int(c.strip()) for c in args.codes.split(",") if c.strip().isdigit()}
    exts  = [e.strip().lstrip(".") for e in args.extensions.split(",") if e.strip()]
    verify  = not args.no_verify
    cookies = dict(c.split("=", 1) for c in args.cookie.split(";") if "=" in c) if args.cookie else {}

    # Charger la wordlist
    if args.wordlist:
        try:
            words = [l.strip() for l in open(args.wordlist, encoding="utf-8") if l.strip()]
        except Exception as e:
            print(red(f"[ERREUR] {e}")); sys.exit(1)
    else:
        words = BUILTIN_WORDLIST

    # Générer toutes les URLs à tester
    urls = []
    for word in words:
        urls.append(f"{base}/{word}")
        for ext in exts:
            # Éviter de doubler l'extension
            if not word.endswith(f".{ext}"):
                urls.append(f"{base}/{word}.{ext}")

    _total = len(urls)

    print(cyan("=" * 65))
    print(cyan("  Dir Bruteforcer"))
    print(cyan(f"  Cible   : {base}"))
    print(cyan(f"  URLs    : {_total}  |  Threads : {args.threads}"))
    print(cyan(f"  Codes   : {args.codes}"))
    print(cyan("=" * 65 + "\n"))

    session = requests.Session()
    session.headers["User-Agent"] = args.user_agent

    q = queue.Queue()
    for url in urls:
        q.put(url)

    threads = []
    for _ in range(min(args.threads, _total)):
        t = threading.Thread(
            target=worker,
            args=(session, q, codes, args.timeout, verify, cookies, args.delay),
            daemon=True,
        )
        t.start()
        threads.append(t)

    q.join()

    print(f"\n{cyan('─'*65)}")
    print(f"  Scanné : {_scanned}/{_total}  |  Trouvé : {bold(str(len(_found)))}")
    print(cyan("─" * 65))

    if args.output and _found:
        out = {
            "timestamp": datetime.now().isoformat(),
            "target":    base,
            "total_tested": _total,
            "found":     _found,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(green(f"\n[+] Rapport : {args.output}"))


if __name__ == "__main__":
    main()
