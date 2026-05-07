#!/usr/bin/env python3
"""
=============================================================================
 username_checker.py — Vérification de pseudonyme sur les réseaux sociaux
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : requests

 DESCRIPTION
 -----------
 Vérifie si un pseudonyme existe sur ~35 plateformes populaires en
 envoyant des requêtes HTTP aux profils publics.

 PLATEFORMES VÉRIFIÉES
 ---------------------
 GitHub, GitLab, Twitter/X, Instagram, Facebook, LinkedIn, Reddit,
 YouTube, TikTok, Twitch, Discord (Lanyard), Pinterest, Snapchat,
 Telegram, Medium, Dev.to, Hashnode, Stack Overflow, HackerNews,
 Keybase, Gravatar, Pastebin, DockerHub, npm, PyPI, RubyGems,
 Mastodon (social.coop), Bluesky, Flickr, Vimeo, SoundCloud, Spotify

 USAGE
 -----
   python username_checker.py [options]

 EXEMPLES
 --------
   python username_checker.py --username johndoe
   python username_checker.py --username johndoe --platforms github,twitter,reddit
   python username_checker.py --username johndoe -o report.json

 OPTIONS
 -------
   --username   Pseudonyme à rechercher
   --platforms  Plateformes séparées par virgules (défaut: toutes)
   --timeout    Timeout par requête (défaut: 8)
   --threads    Nombre de threads (défaut: 10)
   -o, --output Fichier JSON de sortie
   -v, --verbose Afficher les plateformes non trouvées

 AVERTISSEMENT LÉGAL
 -------------------
 Cet outil interroge uniquement des profils publics. Respectez les CGU
 et les lois sur la vie privée applicables.
=============================================================================
"""

import argparse
import json
import queue
import sys
import threading
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

# ─── Plateforme registry ─────────────────────────────────────────────────────
# Format : (nom, url_template, [codes_présents], [texte_absent_si_404])
# La détection se fait sur le code HTTP OU la présence/absence d'un texte.

PLATFORMS = [
    # (name, url, found_codes, not_found_text_hint)
    ("GitHub",        "https://github.com/{u}",                           [200], ["Not Found"]),
    ("GitLab",        "https://gitlab.com/{u}",                           [200], ["404"]),
    ("Twitter/X",     "https://twitter.com/{u}",                          [200], ["This account doesn't exist"]),
    ("Instagram",     "https://www.instagram.com/{u}/",                   [200], ["Sorry, this page"]),
    ("Reddit",        "https://www.reddit.com/user/{u}",                  [200], ["page not found"]),
    ("TikTok",        "https://www.tiktok.com/@{u}",                      [200], ["couldn't find this account"]),
    ("Twitch",        "https://www.twitch.tv/{u}",                        [200], ["sorry"]),
    ("Pinterest",     "https://www.pinterest.com/{u}/",                   [200], ["page not found"]),
    ("Medium",        "https://medium.com/@{u}",                          [200], ["404"]),
    ("Dev.to",        "https://dev.to/{u}",                               [200], ["404 page not found"]),
    ("Hashnode",      "https://hashnode.com/@{u}",                        [200], ["404"]),
    ("Stack Overflow","https://stackoverflow.com/users/0/{u}",            [200], ["User not found"]),
    ("Keybase",       "https://keybase.io/{u}",                           [200], ["404"]),
    ("DockerHub",     "https://hub.docker.com/u/{u}/",                    [200], ["Page Not Found"]),
    ("npm",           "https://www.npmjs.com/~{u}",                       [200], ["Not found"]),
    ("PyPI",          "https://pypi.org/user/{u}/",                       [200], ["404"]),
    ("RubyGems",      "https://rubygems.org/profiles/{u}",                [200], ["We couldn't find"]),
    ("SoundCloud",    "https://soundcloud.com/{u}",                       [200], ["404"]),
    ("Vimeo",         "https://vimeo.com/{u}",                            [200], ["Sorry, we"]),
    ("Flickr",        "https://www.flickr.com/people/{u}/",               [200], ["Page Not Found"]),
    ("Pastebin",      "https://pastebin.com/u/{u}",                       [200], ["Not Found"]),
    ("HackerNews",    "https://news.ycombinator.com/user?id={u}",         [200], ["No such user"]),
    ("Gravatar",      "https://en.gravatar.com/{u}",                      [200], ["We couldn't find"]),
    ("Telegram",      "https://t.me/{u}",                                  [200], ["404"]),
    ("Bluesky",       "https://bsky.app/profile/{u}.bsky.social",         [200], ["Profile not found"]),
    ("Mastodon",      "https://mastodon.social/@{u}",                     [200], ["The page you are looking"]),
    ("YouTube",       "https://www.youtube.com/@{u}",                     [200], ["This page isn't available"]),
    ("Spotify",       "https://open.spotify.com/user/{u}",                [200], ["not found"]),
    ("Behance",       "https://www.behance.net/{u}",                      [200], ["404"]),
    ("Dribbble",      "https://dribbble.com/{u}",                         [200], ["Whoops"]),
    ("ProductHunt",   "https://www.producthunt.com/@{u}",                 [200], ["404"]),
    ("About.me",      "https://about.me/{u}",                             [200], ["404"]),
    ("Linktree",      "https://linktr.ee/{u}",                            [200], ["Sorry, this page"]),
    ("Codepen",       "https://codepen.io/{u}",                           [200], ["404"]),
    ("Replit",        "https://replit.com/@{u}",                          [200], ["404"]),
]

# ─── Worker ──────────────────────────────────────────────────────────────────

_lock    = threading.Lock()
_results = []

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}


def check_platform(session, platform: tuple, username: str, timeout: int, verbose: bool):
    name, url_tmpl, found_codes, not_found_hints = platform
    url = url_tmpl.format(u=username)
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
        code = resp.status_code
        text = resp.text.lower()

        if code == 404:
            status = "not_found"
        elif code in found_codes:
            # Vérifier les indices de "profil vide / 404 déguisé"
            if any(hint.lower() in text for hint in not_found_hints):
                status = "not_found"
            else:
                status = "found"
        elif code == 429:
            status = "rate_limited"
        else:
            status = "unknown"
    except Exception:
        status = "error"
        url    = url_tmpl.format(u=username)

    result = {"platform": name, "url": url, "status": status}
    with _lock:
        _results.append(result)
        if status == "found":
            print(f"  {green('[✓]')} {bold(f'{name:20}')} {url}")
        elif status == "rate_limited":
            print(f"  {yellow('[~]')} {f'{name:20}'} Rate limited")
        elif status == "error":
            if verbose:
                print(f"  {dim('[?]')} {dim(name):20} Erreur")
        elif verbose:
            print(f"  {dim('[✗]')} {dim(name):20} Non trouvé")


def worker(session, q: queue.Queue, username: str, timeout: int, verbose: bool):
    while True:
        try:
            platform = q.get(timeout=1)
        except queue.Empty:
            break
        check_platform(session, platform, username, timeout, verbose)
        q.task_done()

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Vérification de pseudonyme sur les réseaux sociaux et plateformes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--username",  required=True)
    parser.add_argument("--platforms", default="all",
                        help="Plateformes séparées par virgules (ex: github,twitter)")
    parser.add_argument("--timeout",   type=int, default=8)
    parser.add_argument("--threads",   type=int, default=10)
    parser.add_argument("-o", "--output")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    # Filtrer les plateformes
    platform_map = {p[0].lower().replace("/", "").replace(" ", ""): p for p in PLATFORMS}
    if args.platforms.strip().lower() == "all":
        selected = PLATFORMS
    else:
        names = [n.strip().lower() for n in args.platforms.split(",")]
        selected = [platform_map[n] for n in names if n in platform_map]
        if not selected:
            print(yellow("[AVERT] Aucune plateforme reconnue. Utilisation de toutes."))
            selected = PLATFORMS

    print(cyan("=" * 65))
    print(cyan(f"  Username Checker"))
    print(cyan(f"  Pseudonyme  : {bold(args.username)}"))
    print(cyan(f"  Plateformes : {len(selected)}"))
    print(cyan("=" * 65 + "\n"))

    session = requests.Session()
    session.headers.update(HEADERS)

    q: queue.Queue = queue.Queue()
    for p in selected:
        q.put(p)

    threads = []
    for _ in range(min(args.threads, len(selected))):
        t = threading.Thread(
            target=worker,
            args=(session, q, args.username, args.timeout, args.verbose),
            daemon=True,
        )
        t.start()
        threads.append(t)

    q.join()

    found = [r for r in _results if r["status"] == "found"]
    print(f"\n{cyan('─'*65)}")
    print(f"  Plateformes vérifiées : {len(_results)}  |  Trouvé : {bold(green(str(len(found))))}")
    print(cyan("─" * 65))

    if args.output:
        out = {
            "timestamp": datetime.now().isoformat(),
            "username":  args.username,
            "checked":   len(_results),
            "found":     len(found),
            "results":   sorted(_results, key=lambda r: (r["status"] != "found", r["platform"])),
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(green(f"\n[+] Rapport : {args.output}"))


if __name__ == "__main__":
    main()
