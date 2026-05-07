#!/usr/bin/env python3
"""
=============================================================================
 web_vuln_patcher.py — Générateur de règles WAF / correctifs web
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : aucune (stdlib uniquement)

 DESCRIPTION
 -----------
 Génère des règles de protection (WAF / ModSecurity / nginx) basées sur
 les résultats de sqli_detector.py et xss_scanner.py.

 SORTIES GÉNÉRÉES
 ----------------
   ModSecurity v3   → Règles SecRule (OWASP CRS style)
   nginx            → Blocs location {} avec filtres
   Apache .htaccess → RewriteRule / Header directives
   CSP Header       → Content-Security-Policy adaptée
   Rapport JSON     → Résumé des vulnérabilités et correctifs

 USAGE
 -----
   python web_vuln_patcher.py [options]

 EXEMPLES
 --------
   python web_vuln_patcher.py --sqli sqli_report.json
   python web_vuln_patcher.py --xss xss_report.json
   python web_vuln_patcher.py --sqli sqli.json --xss xss.json --server nginx
   python web_vuln_patcher.py --sqli sqli.json --server modsecurity -o waf_rules.conf
   python web_vuln_patcher.py --harden-all --server nginx -o nginx_security.conf

 OPTIONS
 -------
   --sqli FILE       JSON de sqli_detector.py
   --xss FILE        JSON de xss_scanner.py
   --server          Cible : nginx, apache, modsecurity (défaut: modsecurity)
   --harden-all      Générer un jeu complet de règles génériques OWASP
   -o, --output      Fichier de sortie (conf ou JSON)

 AVERTISSEMENT LÉGAL
 -------------------
 Testez les règles WAF dans un environnement de staging. Des faux positifs
 peuvent bloquer des utilisateurs légitimes.
=============================================================================
"""

import argparse
import json
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
def cyan(t):   return f"{Fore.CYAN}{t}{Style.RESET_ALL}" if COLOR else t
def bold(t):   return f"{Style.BRIGHT}{t}{Style.RESET_ALL}" if COLOR else t
def dim(t):    return f"{Style.DIM}{t}{Style.RESET_ALL}" if COLOR else t

# ─── Chargement des rapports ──────────────────────────────────────────────────

def load_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(yellow(f"  [AVERT] Impossible de lire {path} : {e}"))
        return {}


def extract_sqli_urls(data: dict) -> list:
    """Extrait les URLs/paramètres vulnérables du rapport sqli_detector."""
    vulns = []
    for r in data.get("results", []):
        if r.get("status") in ("VULNERABLE", "POSSIBLE"):
            vulns.append({
                "url":   r.get("url", ""),
                "param": r.get("parameter", ""),
                "type":  r.get("type", ""),
            })
    return vulns


def extract_xss_urls(data: dict) -> list:
    """Extrait les URLs/paramètres vulnérables du rapport xss_scanner."""
    vulns = []
    for r in data.get("results", []):
        if r.get("vulnerable"):
            vulns.append({
                "url":   r.get("url", ""),
                "param": r.get("parameter", ""),
                "payload": r.get("payload", ""),
            })
    return vulns

# ─── Générateurs ModSecurity ──────────────────────────────────────────────────

MODSEC_HEADER = """\
# =============================================================================
# Règles ModSecurity générées par web_vuln_patcher.py
# Date : {date}
# ATTENTION : Testez en mode "DetectionOnly" avant de passer en "On"
# =============================================================================

SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecDefaultAction "phase:2,log,deny,status:403"

"""

MODSEC_SQLI_RULES = """\
# ── Règles Anti-SQLi ──────────────────────────────────────────────────────────
SecRule ARGS "@detectSQLi" \\
    "id:10001,phase:2,log,deny,status:403,\\
    msg:'SQL Injection Attack Detected',\\
    tag:'application-multi',\\
    tag:'language-multi',\\
    tag:'attack-sqli',\\
    severity:'CRITICAL'"

SecRule ARGS|ARGS_NAMES "@rx (?i:(union|select|insert|update|delete|drop|truncate|exec|execute|xp_cmdshell|information_schema|sysobjects|syscolumns))" \\
    "id:10002,phase:2,log,deny,status:403,\\
    msg:'SQL Keyword Detected',\\
    severity:'HIGH'"

SecRule ARGS "@rx (?i:(--|#|;|/\\*|\\*/|'|\\%27|\\%22|\"|or\\s+1=1|and\\s+1=1))" \\
    "id:10003,phase:2,log,deny,status:403,\\
    msg:'SQL Injection Pattern',\\
    severity:'HIGH'"

"""

MODSEC_XSS_RULES = """\
# ── Règles Anti-XSS ──────────────────────────────────────────────────────────
SecRule ARGS "@detectXSS" \\
    "id:10010,phase:2,log,deny,status:403,\\
    msg:'XSS Attack Detected',\\
    tag:'attack-xss',\\
    severity:'CRITICAL'"

SecRule ARGS "@rx (?i:(<script|javascript:|vbscript:|data:text/html|on\\w+\\s*=|eval\\s*\\(|expression\\s*\\())" \\
    "id:10011,phase:2,log,deny,status:403,\\
    msg:'XSS Pattern Detected',\\
    severity:'HIGH'"

SecRule REQUEST_HEADERS:Content-Type "@rx (?i:text/html)" \\
    "id:10012,phase:1,pass,\\
    setvar:tx.content_type_is_html=1"

"""

MODSEC_GENERIC = """\
# ── Règles génériques OWASP ───────────────────────────────────────────────────
# Path Traversal
SecRule REQUEST_URI|ARGS "@rx (?i:(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%252e%252e%252f))" \\
    "id:10020,phase:2,log,deny,status:403,msg:'Path Traversal'"

# Command Injection
SecRule ARGS "@rx (?i:(;|&&|\\|\\||`|\\$\\(|\\$\\{|\\bexec\\b|\\bsystem\\b|\\bpassthru\\b|\\bshell_exec\\b))" \\
    "id:10021,phase:2,log,deny,status:403,msg:'Command Injection'"

# File Inclusion
SecRule ARGS "@rx (?i:(php://|file://|ftp://|expect://|phar://|data://|zip://))" \\
    "id:10022,phase:2,log,deny,status:403,msg:'PHP Wrapper / File Inclusion'"

# SSRF
SecRule ARGS "@rx (?i:(169\\.254\\.|127\\.0\\.0\\.|::1|localhost|0\\.0\\.0\\.0))" \\
    "id:10023,phase:2,log,deny,status:403,msg:'Potential SSRF'"

# HTTP Method restriction
SecRule REQUEST_METHOD "!@within GET POST HEAD OPTIONS" \\
    "id:10024,phase:1,log,deny,status:405,msg:'HTTP Method Not Allowed'"

"""

# ─── Générateur nginx ─────────────────────────────────────────────────────────

NGINX_HEADER = """\
# =============================================================================
# Configuration sécurité nginx — web_vuln_patcher.py
# Date : {date}
# =============================================================================

"""

NGINX_SQLI = """\
# ── Protection SQLi ───────────────────────────────────────────────────────────
set $sqli_block 0;
if ($args ~* "(union|select|insert|update|delete|drop|exec|xp_cmdshell)") { set $sqli_block 1; }
if ($args ~* "('|--|;|/\\*|or 1=1|and 1=1)") { set $sqli_block 1; }
if ($sqli_block = 1) { return 403; }

"""

NGINX_XSS = """\
# ── Protection XSS ───────────────────────────────────────────────────────────
set $xss_block 0;
if ($args ~* "(<script|javascript:|vbscript:|onerror|onload|eval\\()") { set $xss_block 1; }
if ($xss_block = 1) { return 403; }

# En-têtes de sécurité XSS
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'" always;

"""

NGINX_GENERIC = """\
# ── Protections génériques ────────────────────────────────────────────────────
# Bloquer les agents malveillants courants
if ($http_user_agent ~* "(nikto|sqlmap|dirbuster|nmap|masscan|zap|burpsuite)") {
    return 403;
}
# Limiter les méthodes HTTP
if ($request_method !~ ^(GET|POST|HEAD|OPTIONS)$) {
    return 405;
}
# Bloquer l'accès aux fichiers sensibles
location ~* \\.(git|env|log|bak|sql|swp|htpasswd)$ {
    deny all;
    return 404;
}
# Bloquer path traversal
if ($request_uri ~* "\\.\\./") { return 403; }

# En-têtes de sécurité supplémentaires
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

"""

# ─── Générateur Apache ────────────────────────────────────────────────────────

APACHE_HEADER = """\
# =============================================================================
# Configuration sécurité Apache (.htaccess) — web_vuln_patcher.py
# Date : {date}
# =============================================================================

RewriteEngine On

"""

APACHE_SQLI = """\
# ── Protection SQLi ───────────────────────────────────────────────────────────
RewriteCond %{QUERY_STRING} (union|select|insert|update|delete|drop|exec) [NC,OR]
RewriteCond %{QUERY_STRING} ('|--|;|/\\*) [NC]
RewriteRule ^ - [F,L]

"""

APACHE_XSS = """\
# ── Protection XSS ───────────────────────────────────────────────────────────
RewriteCond %{QUERY_STRING} (<script|javascript:|onerror|onload|eval\\() [NC]
RewriteRule ^ - [F,L]

Header always set X-XSS-Protection "1; mode=block"
Header always set X-Content-Type-Options "nosniff"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'"

"""

APACHE_GENERIC = """\
# ── Protections génériques ────────────────────────────────────────────────────
<FilesMatch "\\.(git|env|log|bak|sql|swp|htpasswd)$">
    Require all denied
</FilesMatch>

RewriteCond %{REQUEST_METHOD} !^(GET|POST|HEAD|OPTIONS) [NC]
RewriteRule ^ - [F,L]

Header always set X-Frame-Options "DENY"
Header always set Referrer-Policy "no-referrer-when-downgrade"

"""

# ─── Génération CSP ───────────────────────────────────────────────────────────

def gen_csp(strict: bool = True) -> str:
    if strict:
        return (
            "Content-Security-Policy: default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
    return "Content-Security-Policy: default-src 'self';"

# ─── Affichage et export ──────────────────────────────────────────────────────

def build_config(server: str, has_sqli: bool, has_xss: bool, harden_all: bool) -> str:
    date = datetime.now().strftime("%Y-%m-%d %H:%M")
    if server == "modsecurity":
        parts = [MODSEC_HEADER.format(date=date)]
        if has_sqli: parts.append(MODSEC_SQLI_RULES)
        if has_xss:  parts.append(MODSEC_XSS_RULES)
        if harden_all: parts.append(MODSEC_GENERIC)
    elif server == "nginx":
        parts = [NGINX_HEADER.format(date=date)]
        if has_sqli: parts.append(NGINX_SQLI)
        if has_xss:  parts.append(NGINX_XSS)
        if harden_all: parts.append(NGINX_GENERIC)
    else:  # apache
        parts = [APACHE_HEADER.format(date=date)]
        if has_sqli: parts.append(APACHE_SQLI)
        if has_xss:  parts.append(APACHE_XSS)
        if harden_all: parts.append(APACHE_GENERIC)
    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser(
        description="Générateur de règles WAF depuis les résultats de scan web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--sqli",       metavar="FILE",
                        help="JSON de sqli_detector.py")
    parser.add_argument("--xss",        metavar="FILE",
                        help="JSON de xss_scanner.py")
    parser.add_argument("--server",     choices=["nginx", "apache", "modsecurity"],
                        default="modsecurity")
    parser.add_argument("--harden-all", action="store_true",
                        help="Inclure les règles génériques OWASP")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()

    print(cyan("=" * 65))
    print(cyan("  Web Vuln Patcher — Générateur de règles WAF"))
    print(cyan(f"  Serveur cible : {args.server}"))
    print(cyan("=" * 65 + "\n"))

    sqli_vulns, xss_vulns = [], []

    if args.sqli:
        data = load_json(args.sqli)
        sqli_vulns = extract_sqli_urls(data)
        print(f"  SQLi — {len(sqli_vulns)} vulnérabilité(s) trouvée(s) dans {args.sqli}")
        for v in sqli_vulns[:5]:
            print(f"    {yellow('→')} {v['url']} [{v.get('type', '')}]")

    if args.xss:
        data = load_json(args.xss)
        xss_vulns = extract_xss_urls(data)
        print(f"  XSS  — {len(xss_vulns)} vulnérabilité(s) trouvée(s) dans {args.xss}")
        for v in xss_vulns[:5]:
            print(f"    {yellow('→')} {v['url']} [param: {v.get('param', '?')}]")

    if not sqli_vulns and not xss_vulns and not args.harden_all:
        print(yellow("\n  Aucune vulnérabilité fournie. Utilisez --harden-all pour générer des règles génériques."))
        sys.exit(0)

    has_sqli = bool(sqli_vulns) or args.harden_all
    has_xss  = bool(xss_vulns)  or args.harden_all

    config = build_config(args.server, has_sqli, has_xss, args.harden_all)

    if args.output:
        Path(args.output).write_text(config, encoding="utf-8")
        print(green(f"\n[+] Configuration générée : {args.output}"))
    else:
        print(f"\n{cyan('─'*65)}")
        print(config)

    # Afficher la CSP recommandée
    print(cyan("─" * 65))
    print(bold("  CSP Header recommandée :"))
    print(f"  {gen_csp(strict=True)}\n")


if __name__ == "__main__":
    main()
