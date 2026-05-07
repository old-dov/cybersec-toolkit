#!/usr/bin/env python3
"""
=============================================================================
 dns_analyzer.py — Analyse complète des enregistrements DNS
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : dnspython  (pip install dnspython)

 DESCRIPTION
 -----------
 Interroge et affiche tous les types d'enregistrements DNS d'un domaine :
 A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA.
 Identifie également les technologies hébergées (SPF, DKIM, DMARC, etc.)

 USAGE
 -----
   python dns_analyzer.py -d <domaine> [options]

 EXEMPLES
 --------
   python dns_analyzer.py -d exemple.com
   python dns_analyzer.py -d exemple.com --all --dns 1.1.1.1
   python dns_analyzer.py -d exemple.com -o dns_report.txt

 OPTIONS
 -------
   -d, --domain   Domaine cible (obligatoire)
   --dns          Serveur DNS à utiliser (défaut: résolveur système)
   --all          Requêter tous les types d'enregistrements
   --timeout      Timeout en secondes (défaut: 5)
   -o, --output   Fichier de sortie
   --json         Exporter en JSON

 TYPES INTERROGÉS PAR DÉFAUT
 ---------------------------
   A, AAAA, MX, NS, TXT, SOA, CNAME

 AVEC --all
 ----------
   + PTR, SRV, CAA, DNSKEY, DS, NAPTR

 AVERTISSEMENT LÉGAL
 --------------------
 Les requêtes DNS sont passives et légales sur des domaines publics.
=============================================================================
"""

import argparse
import json
import sys
from datetime import datetime

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    import dns.rdatatype
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

def cyan(t):   return f"{Fore.CYAN}{t}{Style.RESET_ALL}" if COLOR else t
def green(t):  return f"{Fore.GREEN}{t}{Style.RESET_ALL}" if COLOR else t
def yellow(t): return f"{Fore.YELLOW}{t}{Style.RESET_ALL}" if COLOR else t
def red(t):    return f"{Fore.RED}{t}{Style.RESET_ALL}" if COLOR else t
def bold(t):   return f"{Style.BRIGHT}{t}{Style.RESET_ALL}" if COLOR else t

# ─── Types d'enregistrements ─────────────────────────────────────────────────

BASE_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
EXTRA_TYPES = ["PTR", "SRV", "CAA", "DNSKEY", "DS", "NAPTR"]

# ─── Analyses spécialisées ───────────────────────────────────────────────────

def analyze_txt(records: list) -> list:
    """Identifie SPF, DKIM, DMARC, Google, etc. dans les enregistrements TXT."""
    findings = []
    for r in records:
        txt = str(r).lower()
        if "v=spf1" in txt:
            findings.append(f"  → SPF détecté  : {r}")
        elif "v=dmarc1" in txt:
            findings.append(f"  → DMARC détecté: {r}")
        elif "v=dkim1" in txt:
            findings.append(f"  → DKIM détecté : {r}")
        elif "google-site-verification" in txt:
            findings.append(f"  → Google Workspace/Search Console")
        elif "ms=" in txt:
            findings.append(f"  → Microsoft O365 vérifié")
        elif "docusign" in txt:
            findings.append(f"  → DocuSign détecté")
    return findings


def query_record(resolver: dns.resolver.Resolver, domain: str, rtype: str) -> list:
    """Effectue une requête DNS et retourne les enregistrements sous forme de chaînes."""
    try:
        answers = resolver.resolve(domain, rtype)
        return [str(r) for r in answers]
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except dns.exception.DNSException:
        return []
    except Exception:
        return []


def print_section(title: str, records: list, extra_info: list = None) -> None:
    """Affiche une section de résultats DNS."""
    print(f"\n  {bold(cyan(f'[ {title} ]'))}")
    if not records:
        print(f"    {yellow('Aucun enregistrement')}")
        return
    for r in records:
        print(f"    {green(r)}")
    if extra_info:
        for info in extra_info:
            print(f"    {yellow(info)}")

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyse complète des enregistrements DNS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--domain",  required=True, help="Domaine cible")
    parser.add_argument("--dns",           help="Serveur DNS (ex: 8.8.8.8)")
    parser.add_argument("--all",           action="store_true", help="Requêter tous les types")
    parser.add_argument("--timeout",       type=float, default=5.0, help="Timeout (s)")
    parser.add_argument("-o", "--output",  help="Fichier de sortie texte")
    parser.add_argument("--json",          action="store_true", help="Exporter en JSON")
    args = parser.parse_args()

    resolver = dns.resolver.Resolver()
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout
    if args.dns:
        resolver.nameservers = [args.dns]

    rtypes = BASE_TYPES + (EXTRA_TYPES if args.all else [])

    print(cyan("=" * 65))
    print(cyan(f"  Analyse DNS — {args.domain}"))
    print(cyan(f"  Serveur DNS : {args.dns or 'résolveur système'}"))
    print(cyan(f"  Types      : {', '.join(rtypes)}"))
    print(cyan(f"  Date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(cyan("=" * 65))

    report = {"domain": args.domain, "date": datetime.now().isoformat(), "records": {}}

    for rtype in rtypes:
        records = query_record(resolver, args.domain, rtype)
        report["records"][rtype] = records
        extra = analyze_txt(records) if rtype == "TXT" else None
        print_section(rtype, records, extra)

    # Récapitulatif rapide
    print(cyan("\n" + "=" * 65))
    print(cyan("  Récapitulatif"))
    print(cyan("=" * 65))
    for rtype, recs in report["records"].items():
        status = green(f"{len(recs)} enr.") if recs else yellow("aucun")
        print(f"  {rtype:<10} : {status}")

    # Sauvegarde texte
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(f"Analyse DNS — {args.domain}\n")
            f.write(f"Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for rtype, recs in report["records"].items():
                f.write(f"[{rtype}]\n")
                for r in recs:
                    f.write(f"  {r}\n")
                f.write("\n")
        print(green(f"\n[+] Rapport sauvegardé : {args.output}"))

    if args.json:
        json_path = (args.output.rsplit(".", 1)[0] + ".json") if args.output else f"dns_{args.domain}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(green(f"[+] JSON sauvegardé : {json_path}"))


if __name__ == "__main__":
    main()
