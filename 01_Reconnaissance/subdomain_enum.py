#!/usr/bin/env python3
"""
=============================================================================
 subdomain_enum.py — Énumération de sous-domaines par dictionnaire
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : dnspython  (pip install dnspython)

 DESCRIPTION
 -----------
 Tente de résoudre des sous-domaines d'un domaine cible en utilisant une
 liste de mots (wordlist). Pour chaque sous-domaine trouvé, récupère les
 enregistrements DNS A, AAAA et CNAME.

 USAGE
 -----
   python subdomain_enum.py -d <domaine> -w <wordlist> [options]

 EXEMPLES
 --------
   python subdomain_enum.py -d exemple.com -w wordlist.txt
   python subdomain_enum.py -d exemple.com -w wordlist.txt -T 50 -o found.txt
   python subdomain_enum.py -d exemple.com -w wordlist.txt --dns 8.8.8.8

 OPTIONS
 -------
   -d, --domain    Domaine cible (obligatoire)
   -w, --wordlist  Chemin vers la wordlist de sous-domaines (obligatoire)
   -T, --threads   Threads simultanés (défaut: 30)
   --dns           Serveur DNS à utiliser (défaut: résolveur système)
   --timeout       Timeout DNS en secondes (défaut: 2.0)
   -o, --output    Fichier de sortie
   -v, --verbose   Afficher les tentatives en cours
   --json          Exporter également en JSON

 WORDLISTS RECOMMANDÉES
 ----------------------
   - SecLists : https://github.com/danielmiessler/SecLists
     (Discovery/DNS/subdomains-top1million-5000.txt)
   - Une wordlist minimale est générée automatiquement si aucune n'est fournie

 AVERTISSEMENT LÉGAL
 --------------------
 À utiliser uniquement sur des domaines que vous possédez ou pour lesquels
 vous avez une autorisation explicite.
=============================================================================
"""

import argparse
import json
import sys
import threading
import time
from queue import Queue, Empty
from datetime import datetime

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[ERREUR] Le module 'dnspython' est requis : pip install dnspython")
    sys.exit(1)

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# ─── Couleurs ────────────────────────────────────────────────────────────────

def green(t):  return f"{Fore.GREEN}{t}{Style.RESET_ALL}" if COLOR else t
def red(t):    return f"{Fore.RED}{t}{Style.RESET_ALL}" if COLOR else t
def yellow(t): return f"{Fore.YELLOW}{t}{Style.RESET_ALL}" if COLOR else t
def cyan(t):   return f"{Fore.CYAN}{t}{Style.RESET_ALL}" if COLOR else t

# ─── Wordlist par défaut (courte) ─────────────────────────────────────────────

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "api",
    "dev", "staging", "test", "demo", "beta", "admin", "panel",
    "vpn", "remote", "rdp", "ssh", "git", "gitlab", "github",
    "jenkins", "jira", "confluence", "wiki", "docs", "support",
    "blog", "shop", "store", "cdn", "static", "assets", "media",
    "ns1", "ns2", "mx", "mx1", "mx2", "db", "database", "sql",
    "mysql", "redis", "mongo", "elastic", "kibana", "grafana",
    "monitor", "status", "health", "login", "auth", "sso", "oauth",
    "internal", "intranet", "portal", "extranet", "proxy", "secure",
]

# ─── Variables partagées ─────────────────────────────────────────────────────

found = []
found_lock = threading.Lock()
print_lock = threading.Lock()
counter = {"total": 0}
counter_lock = threading.Lock()

# ─── Fonctions ───────────────────────────────────────────────────────────────

def make_resolver(dns_server: str | None, timeout: float) -> dns.resolver.Resolver:
    """Crée un résolveur DNS configuré."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    if dns_server:
        resolver.nameservers = [dns_server]
    return resolver


def resolve_subdomain(resolver: dns.resolver.Resolver, fqdn: str, verbose: bool) -> dict | None:
    """Tente de résoudre un FQDN. Retourne les IPs si trouvé, sinon None."""
    for rtype in ("A", "AAAA", "CNAME"):
        try:
            answers = resolver.resolve(fqdn, rtype)
            addrs = [str(r) for r in answers]
            return {"fqdn": fqdn, "type": rtype, "records": addrs}
        except (dns.exception.DNSException, Exception):
            continue
    return None


def worker(domain: str, queue: Queue, resolver: dns.resolver.Resolver,
           verbose: bool) -> None:
    """Thread worker : consomme les sous-domaines depuis la file."""
    while True:
        try:
            word = queue.get(timeout=1)
        except Empty:
            break
        fqdn = f"{word}.{domain}"
        with counter_lock:
            counter["total"] += 1
        result = resolve_subdomain(resolver, fqdn, verbose)
        if result:
            line = f"  [TROUVÉ]  {fqdn:45s}  {result['type']:5s}  →  {', '.join(result['records'])}"
            with print_lock:
                print(green(line))
            with found_lock:
                found.append(result)
        elif verbose:
            with print_lock:
                print(f"  [ ... ]   {fqdn}")
        queue.task_done()

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Énumération de sous-domaines par dictionnaire",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--domain",   required=True, help="Domaine cible")
    parser.add_argument("-w", "--wordlist", help="Fichier wordlist (un mot par ligne)")
    parser.add_argument("-T", "--threads",  type=int, default=30, help="Threads (défaut: 30)")
    parser.add_argument("--dns",            help="Serveur DNS (ex: 8.8.8.8)")
    parser.add_argument("--timeout",        type=float, default=2.0, help="Timeout DNS (s)")
    parser.add_argument("-o", "--output",   help="Fichier de sortie")
    parser.add_argument("-v", "--verbose",  action="store_true", help="Mode verbeux")
    parser.add_argument("--json",           action="store_true", help="Exporter en JSON")
    args = parser.parse_args()

    # Chargement de la wordlist
    if args.wordlist:
        try:
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(red(f"[ERREUR] Wordlist introuvable : {args.wordlist}"))
            sys.exit(1)
    else:
        print(yellow("[INFO] Aucune wordlist fournie, utilisation de la liste intégrée."))
        words = DEFAULT_WORDLIST

    resolver = make_resolver(args.dns, args.timeout)
    queue = Queue()
    for w in words:
        queue.put(w)

    print(cyan("=" * 65))
    print(cyan(f"  Énumération de sous-domaines — {args.domain}"))
    print(cyan(f"  Mots    : {len(words)}"))
    print(cyan(f"  Threads : {args.threads}"))
    print(cyan(f"  DNS     : {args.dns or 'résolveur système'}"))
    print(cyan(f"  Démarré : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(cyan("=" * 65))

    start = time.time()
    threads = []
    for _ in range(min(args.threads, len(words))):
        t = threading.Thread(
            target=worker,
            args=(args.domain, queue, resolver, args.verbose),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    elapsed = time.time() - start
    print(cyan("\n" + "=" * 65))
    print(cyan(f"  Terminé en {elapsed:.2f}s  |  Testés: {counter['total']}  |  Trouvés: {len(found)}"))
    print(cyan("=" * 65))

    if args.output and found:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(f"Sous-domaines — {args.domain}\n")
            f.write(f"Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for r in found:
                f.write(f"{r['fqdn']}  {r['type']}  {', '.join(r['records'])}\n")
        print(green(f"\nRésultats sauvegardés : {args.output}"))

    if args.json:
        json_path = (args.output.rsplit(".", 1)[0] + ".json") if args.output else f"subdomain_enum_{args.domain}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "domain": args.domain,
                "date": datetime.now().isoformat(),
                "tested": counter["total"],
                "results": found,
            }, f, indent=2, ensure_ascii=False)
        print(green(f"[+] JSON sauvegardé : {json_path}"))


if __name__ == "__main__":
    main()
