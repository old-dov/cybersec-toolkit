#!/usr/bin/env python3
"""
=============================================================================
 whois_lookup.py — Recherche WHOIS pour domaines et adresses IP
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : python-whois  (pip install python-whois)

 DESCRIPTION
 -----------
 Effectue une requête WHOIS sur un domaine ou une adresse IP et présente
 les informations clés de façon lisible : registrar, dates, contacts,
 serveurs de noms, statut, etc.

 USAGE
 -----
   python whois_lookup.py -t <domaine_ou_IP> [options]

 EXEMPLES
 --------
   python whois_lookup.py -t google.com
   python whois_lookup.py -t 8.8.8.8
   python whois_lookup.py -t exemple.com -o rapport.txt --json

 OPTIONS
 -------
   -t, --target   Domaine ou IP cible (obligatoire)
   -o, --output   Fichier de sortie (texte brut)
   --json         Exporter également en JSON
   -v, --verbose  Afficher tous les champs bruts

 INFORMATIONS EXTRAITES
 ----------------------
   - Registrar, IANA ID
   - Dates : création, expiration, mise à jour
   - Statut du domaine
   - Serveurs de noms (NS)
   - Titulaire, organisation, email
   - Pays, ville, état

 AVERTISSEMENT LÉGAL
 --------------------
 Les données WHOIS sont publiques. Leur utilisation doit respecter les
 conditions d'utilisation des registres concernés.
=============================================================================
"""

import argparse
import json
import sys
from datetime import datetime

try:
    import whois
except ImportError:
    print("[ERREUR] Le module 'python-whois' est requis : pip install python-whois")
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

# ─── Helpers ─────────────────────────────────────────────────────────────────

def fmt_date(val) -> str:
    """Formate une date ou liste de dates."""
    if val is None:
        return "N/A"
    if isinstance(val, list):
        val = val[0]
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(val)


def fmt_list(val) -> str:
    """Formate une valeur scalaire ou liste en chaîne lisible."""
    if val is None:
        return "N/A"
    if isinstance(val, list):
        # Dédoublonner et tronquer si trop long
        unique = list(dict.fromkeys(str(v) for v in val if v))
        if len(unique) > 5:
            return ", ".join(unique[:5]) + f" ... (+{len(unique)-5})"
        return ", ".join(unique) if unique else "N/A"
    return str(val) if val else "N/A"


def print_field(label: str, value: str, width: int = 22) -> None:
    label_fmt = f"  {label:<{width}}: "
    print(f"{cyan(label_fmt)}{value}")

# ─── Affichage ───────────────────────────────────────────────────────────────

def display_whois(data: whois.WhoisEntry, target: str) -> dict:
    """Affiche et retourne les données WHOIS formatées."""
    print(cyan("\n" + "=" * 62))
    print(cyan(f"  Résultat WHOIS — {target}"))
    print(cyan(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(cyan("=" * 62))

    # Champs principaux
    fields = [
        ("Domaine",          fmt_list(getattr(data, "domain_name",    None))),
        ("Registrar",        fmt_list(getattr(data, "registrar",       None))),
        ("IANA ID",          fmt_list(getattr(data, "registrar_iana_id", None))),
        ("Statut",           fmt_list(getattr(data, "status",          None))),
        ("Créé le",          fmt_date(getattr(data, "creation_date",   None))),
        ("Expire le",        fmt_date(getattr(data, "expiration_date", None))),
        ("Mis à jour le",    fmt_date(getattr(data, "updated_date",    None))),
        ("Serveurs NS",      fmt_list(getattr(data, "name_servers",    None))),
        ("DNSSEC",           fmt_list(getattr(data, "dnssec",          None))),
        ("Titulaire",        fmt_list(getattr(data, "name",            None))),
        ("Organisation",     fmt_list(getattr(data, "org",             None))),
        ("Email",            fmt_list(getattr(data, "emails",          None))),
        ("Pays",             fmt_list(getattr(data, "country",         None))),
        ("État / Province",  fmt_list(getattr(data, "state",           None))),
        ("Ville",            fmt_list(getattr(data, "city",            None))),
        ("Adresse",          fmt_list(getattr(data, "address",         None))),
        ("Téléphone",        fmt_list(getattr(data, "phone",           None))),
        ("Whois serveur",    fmt_list(getattr(data, "whois_server",    None))),
        ("Référent URL",     fmt_list(getattr(data, "referral_url",    None))),
    ]

    summary = {}
    for label, value in fields:
        if value and value != "N/A":
            print_field(label, value)
            summary[label] = value

    print(cyan("=" * 62 + "\n"))
    return summary


def display_raw(data: whois.WhoisEntry) -> None:
    """Affiche tous les champs bruts retournés par python-whois."""
    print(yellow("\n[VERBOSE] Données brutes :"))
    for key, val in data.items():
        if val:
            print(f"  {key}: {val}")

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Recherche WHOIS pour domaines et adresses IP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target",  required=True, help="Domaine ou IP cible")
    parser.add_argument("-o", "--output",  help="Fichier de sortie texte")
    parser.add_argument("--json",          action="store_true", help="Exporter en JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Afficher tous les champs")
    args = parser.parse_args()

    print(f"[*] Requête WHOIS pour : {args.target} ...")
    try:
        data = whois.whois(args.target)
    except whois.parser.PywhoisError as e:
        print(red(f"[ERREUR] WHOIS échoué : {e}"))
        sys.exit(1)
    except Exception as e:
        print(red(f"[ERREUR] {e}"))
        sys.exit(1)

    if data is None or not any(data.values()):
        print(yellow("[!] Aucune donnée WHOIS retournée. Domaine peut-être non enregistré."))
        sys.exit(0)

    summary = display_whois(data, args.target)

    if args.verbose:
        display_raw(data)

    # Sauvegarde texte
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(f"WHOIS — {args.target}\n")
            f.write(f"Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for label, value in summary.items():
                f.write(f"{label:<22}: {value}\n")
        print(green(f"[+] Sauvegardé : {args.output}"))

    # Sauvegarde JSON
    if args.json:
        json_path = (args.output.rsplit(".", 1)[0] + ".json") if args.output else f"whois_{args.target}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({"target": args.target, "date": datetime.now().isoformat(), "data": summary}, f, indent=2, ensure_ascii=False)
        print(green(f"[+] JSON sauvegardé : {json_path}"))


if __name__ == "__main__":
    main()
