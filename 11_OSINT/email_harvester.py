#!/usr/bin/env python3
"""
=============================================================================
 email_harvester.py — Collecte d'adresses email depuis un site web
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : requests

 DESCRIPTION
 -----------
 Crawle récursivement un site web pour extraire toutes les adresses email
 présentes dans le HTML. Vérifie également les pages couramment exposées
 (/contact, /about, /team, /support, etc.).

 USAGE
 -----
   python email_harvester.py [options]

 EXEMPLES
 --------
   python email_harvester.py --domain example.com
   python email_harvester.py --domain example.com --depth 3 --threads 5
   python email_harvester.py --domain example.com --no-verify -o emails.json

 OPTIONS
 -------
   --domain    Domaine cible (ex: example.com)
   --depth     Profondeur de crawl (défaut: 2)
   --threads   Threads de crawl (défaut: 5)
   --timeout   Timeout par requête (défaut: 8)
   --no-verify Désactiver la vérification SSL
   -o, --output Fichier JSON de sortie

 AVERTISSEMENT LÉGAL
 -------------------
 Respectez les CGU des sites et les législations sur la vie privée (RGPD).
=============================================================================
"""

import argparse
import json
import queue
import re
import sys
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
def cyan(t):   return f"{Fore.CYAN}{t}{Style.RESET_ALL}" if COLOR else t
def bold(t):   return f"{Style.BRIGHT}{t}{Style.RESET_ALL}" if COLOR else t
def dim(t):    return f"{Style.DIM}{t}{Style.RESET_ALL}" if COLOR else t

EMAIL_RE  = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
HREF_RE   = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script>", re.DOTALL | re.IGNORECASE)
STYLE_RE  = re.compile(r"<style[^>]*>.*?</style>",  re.DOTALL | re.IGNORECASE)

COMMON_PATHS = [
    "/contact", "/contact-us", "/contactus", "/about", "/about-us",
    "/team", "/our-team", "/staff", "/support", "/help",
    "/info", "/company", "/who-we-are",
]

# Domaines à ignorer dans les emails (faux positifs courants)
IGNORED_DOMAINS = {
    "example.com", "domain.com", "email.com", "yourdomain.com",
    "sentry.io", "amazonaws.com", "cloudfront.net", "w3.org",
    "schema.org", "openssl.org",
}

_lock    = threading.Lock()
_emails  = set()
_visited = set()


def fetch(session, url: str, timeout: int, verify: bool) -> str:
    try:
        resp = session.get(url, timeout=timeout, verify=verify,
                           allow_redirects=True)
        if "text" in resp.headers.get("Content-Type", ""):
            return resp.text
    except Exception:
        pass
    return ""


def extract_emails(text: str, domain: str) -> set[str]:
    # Supprimer scripts et styles (réduire les faux positifs)
    clean = SCRIPT_RE.sub("", STYLE_RE.sub("", text))
    found = set()
    for match in EMAIL_RE.finditer(clean):
        email = match.group(0).lower().strip(".")
        em_domain = email.split("@")[-1]
        # Ignorer les emails sur des domaines évidents de placeholder
        if em_domain not in IGNORED_DOMAINS:
            found.add(email)
    return found


def extract_links(text: str, base_url: str, domain: str) -> list[str]:
    links = []
    base = urllib.parse.urlparse(base_url)
    for m in HREF_RE.finditer(text):
        href = m.group(1).strip()
        if href.startswith("mailto:"):
            continue
        parsed = urllib.parse.urlparse(href)
        if not parsed.netloc:
            # Lien relatif
            full = urllib.parse.urljoin(base_url, href)
        elif parsed.netloc == domain or parsed.netloc == f"www.{domain}":
            full = href
        else:
            continue
        # Nettoyer les fragments et paramètres complexes
        clean = urllib.parse.urlunparse(parsed._replace(fragment=""))
        if clean not in _visited:
            links.append(clean)
    return links


def crawl_worker(session, q: queue.Queue, domain: str,
                 max_depth: int, timeout: int, verify: bool):
    while True:
        try:
            url, depth = q.get(timeout=2)
        except queue.Empty:
            break
        with _lock:
            if url in _visited:
                q.task_done()
                continue
            _visited.add(url)

        text = fetch(session, url, timeout, verify)
        if not text:
            q.task_done()
            continue

        new_emails = extract_emails(text, domain)
        if new_emails:
            with _lock:
                for e in new_emails:
                    if e not in _emails:
                        _emails.add(e)
                        print(f"  {green('[+]')} {bold(e)}  {dim(f'(depuis {url[:60]})')}")

        if depth < max_depth:
            for link in extract_links(text, url, domain):
                with _lock:
                    if link not in _visited:
                        q.put((link, depth + 1))
        q.task_done()


def main():
    parser = argparse.ArgumentParser(
        description="Collecte d'adresses email depuis un site web (OSINT)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--domain",   required=True, help="Domaine cible (ex: example.com)")
    parser.add_argument("--depth",    type=int, default=2, help="Profondeur de crawl (défaut: 2)")
    parser.add_argument("--threads",  type=int, default=5)
    parser.add_argument("--timeout",  type=int, default=8)
    parser.add_argument("--no-verify",action="store_true")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()

    domain  = args.domain.lstrip("www.").lower()
    base_url = f"https://{domain}"
    verify  = not args.no_verify

    print(cyan("=" * 65))
    print(cyan("  Email Harvester"))
    print(cyan(f"  Domaine   : {domain}"))
    print(cyan(f"  Profond.  : {args.depth}  |  Threads : {args.threads}"))
    print(cyan("=" * 65 + "\n"))

    session = requests.Session()
    session.headers["User-Agent"] = (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    )

    q: queue.Queue = queue.Queue()
    q.put((base_url, 0))
    # Ajouter les pages communes
    for path in COMMON_PATHS:
        q.put((base_url + path, 0))

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(
            target=crawl_worker,
            args=(session, q, domain, args.depth, args.timeout, verify),
            daemon=True,
        )
        t.start()
        threads.append(t)

    q.join()

    print(f"\n{cyan('─'*65)}")
    print(f"  Pages visitées : {len(_visited)}  |  Emails trouvés : {bold(str(len(_emails)))}")
    if _emails:
        print(f"\n  {bold('Emails collectés :')}")
        for e in sorted(_emails):
            print(f"    {green('●')} {e}")
    print(cyan("─" * 65))

    if args.output:
        out = {
            "timestamp":     datetime.now().isoformat(),
            "domain":        domain,
            "pages_visited": len(_visited),
            "emails":        sorted(_emails),
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(green(f"\n[+] Rapport : {args.output}"))


if __name__ == "__main__":
    main()
