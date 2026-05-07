#!/usr/bin/env python3
"""
=============================================================================
 harden_http_headers.py — Génération de config sécurité HTTP
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : stdlib uniquement

 DESCRIPTION
 -----------
 Remédie aux vulnérabilités détectées par http_headers_analyzer.py en
 générant automatiquement les blocs de configuration pour les serveurs
 web courants (nginx, Apache, IIS, Caddy).

 Peut lire directement le JSON exporté par http_headers_analyzer.py
 pour ne générer que les en-têtes manquants/invalides.

 PIPELINE
 --------
   1. python ../03_Vulnerability_Assessment/http_headers_analyzer.py \
             -u https://exemple.com --json -o headers.json
   2. python harden_http_headers.py --json headers.json --server nginx

 USAGE
 -----
   python harden_http_headers.py [options]

 EXEMPLES
 --------
   # Générer la config complète pour nginx
   python harden_http_headers.py --server nginx

   # Ne corriger que les en-têtes manquants (depuis le scan JSON)
   python harden_http_headers.py --server apache --json headers.json

   # Générer pour IIS (web.config)
   python harden_http_headers.py --server iis -o security-headers.config

   # Afficher sans sauvegarder
   python harden_http_headers.py --server caddy --preview

 OPTIONS
 -------
   --server    Serveur cible : nginx, apache, iis, caddy (défaut: nginx)
   --json      JSON exporté par http_headers_analyzer.py (optionnel)
   --domain    Domaine cible (pour CSP et HSTS preload)
   --csp       Niveau de CSP : strict, moderate, permissive (défaut: moderate)
   --hsts-age  Durée max-age HSTS en secondes (défaut: 31536000 = 1 an)
   --no-hsts-preload  Désactiver la directive preload de HSTS
   -o, --output  Fichier de sortie
   --preview   Afficher seulement, sans sauvegarder

 INTÉGRATION RAPIDE
 ------------------
   nginx  : include /etc/nginx/snippets/security-headers.conf;
   apache : Include /etc/apache2/conf-available/security-headers.conf
   caddy  : import security-headers.caddy
=============================================================================
"""

import argparse
import json
import sys
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

def green(t):  return f"{Fore.GREEN}{t}{Style.RESET_ALL}" if COLOR else t
def yellow(t): return f"{Fore.YELLOW}{t}{Style.RESET_ALL}" if COLOR else t
def cyan(t):   return f"{Fore.CYAN}{t}{Style.RESET_ALL}" if COLOR else t
def red(t):    return f"{Fore.RED}{t}{Style.RESET_ALL}" if COLOR else t
def bold(t):   return f"{Style.BRIGHT}{t}{Style.RESET_ALL}" if COLOR else t

# ─── Valeurs des en-têtes ─────────────────────────────────────────────────────

def build_header_values(domain: str, csp_level: str, hsts_age: int, hsts_preload: bool) -> dict:
    csp_policies = {
        "strict": (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        ),
        "moderate": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self'; "
            "frame-ancestors 'self'; "
            "base-uri 'self';"
        ),
        "permissive": (
            "default-src 'self' https:; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; "
            "style-src 'self' 'unsafe-inline' https:; "
            "img-src * data:; "
            "font-src * data:; "
            "connect-src *; "
            "frame-ancestors 'self';"
        ),
    }

    hsts_value = f"max-age={hsts_age}; includeSubDomains"
    if hsts_preload:
        hsts_value += "; preload"

    return {
        "Strict-Transport-Security": hsts_value,
        "Content-Security-Policy":   csp_policies.get(csp_level, csp_policies["moderate"]),
        "X-Content-Type-Options":    "nosniff",
        "X-Frame-Options":           "DENY",
        "Referrer-Policy":           "strict-origin-when-cross-origin",
        "Permissions-Policy":        "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Opener-Policy":   "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "X-XSS-Protection":          "0",  # Désactivé (obsolète, remplacé par CSP)
    }

# ─── Générateurs de configuration ─────────────────────────────────────────────

def gen_nginx(headers: dict, to_fix: set | None) -> str:
    lines = [
        "# ════════════════════════════════════════════════════════",
        f"# Sécurité HTTP — nginx — généré le {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "# Source : harden_http_headers.py",
        "# Usage  : include /etc/nginx/snippets/security-headers.conf;",
        "# ════════════════════════════════════════════════════════",
        "",
    ]
    for name, value in headers.items():
        if to_fix and name not in to_fix:
            lines.append(f"# [déjà correct] add_header {name} \"...\";")
            continue
        # nginx : guillemets nécessaires si la valeur contient des espaces
        lines.append(f'add_header {name} "{value}" always;')
    lines += [
        "",
        "# Supprimer les en-têtes qui exposent la version du serveur",
        "server_tokens off;",
        "more_clear_headers Server;         # nécessite ngx_headers_more",
        "more_clear_headers X-Powered-By;",
    ]
    return "\n".join(lines)


def gen_apache(headers: dict, to_fix: set | None) -> str:
    lines = [
        "# ════════════════════════════════════════════════════════",
        f"# Sécurité HTTP — Apache — généré le {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "# Source : harden_http_headers.py",
        "# Usage  : Include /etc/apache2/conf-available/security-headers.conf",
        "#          Activer : a2enmod headers",
        "# ════════════════════════════════════════════════════════",
        "",
        "<IfModule mod_headers.c>",
    ]
    for name, value in headers.items():
        if to_fix and name not in to_fix:
            lines.append(f"    # [déjà correct] Header always set {name} \"...\"")
            continue
        lines.append(f'    Header always set {name} "{value}"')
    lines += [
        "",
        "    # Masquer la version d'Apache",
        '    Header always unset Server',
        '    Header always unset X-Powered-By',
        "</IfModule>",
        "",
        "# Désactiver la signature Apache",
        "ServerSignature Off",
        "ServerTokens Prod",
    ]
    return "\n".join(lines)


def gen_iis(headers: dict, to_fix: set | None) -> str:
    lines = [
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<!--",
        f"  Sécurité HTTP — IIS web.config — généré le {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "  Source : harden_http_headers.py",
        "  Placement : racine du site IIS",
        "-->",
        "<configuration>",
        "  <system.webServer>",
        "    <httpProtocol>",
        "      <customHeaders>",
    ]
    for name, value in headers.items():
        if to_fix and name not in to_fix:
            lines.append(f"        <!-- [déjà correct] {name} -->")
            continue
        # Échapper les guillemets XML
        safe_val = value.replace("&", "&amp;").replace('"', "&quot;")
        lines.append(f'        <add name="{name}" value="{safe_val}" />')
    lines += [
        "      </customHeaders>",
        "      <redirectHeaders>",
        "        <!-- Supprimer X-Powered-By -->",
        '        <remove name="X-Powered-By" />',
        "      </redirectHeaders>",
        "    </httpProtocol>",
        "    <security>",
        "      <requestFiltering removeServerHeader=\"true\" />",
        "    </security>",
        "  </system.webServer>",
        "</configuration>",
    ]
    return "\n".join(lines)


def gen_caddy(headers: dict, to_fix: set | None) -> str:
    lines = [
        "# ════════════════════════════════════════════════════════",
        f"# Sécurité HTTP — Caddy — généré le {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "# Source : harden_http_headers.py",
        "# Usage  : import security-headers.caddy  (dans votre Caddyfile)",
        "# ════════════════════════════════════════════════════════",
        "",
        "header {",
    ]
    for name, value in headers.items():
        if to_fix and name not in to_fix:
            lines.append(f"    # [déjà correct] {name}")
            continue
        lines.append(f'    {name} "{value}"')
    lines += [
        "",
        "    # Supprimer les en-têtes de divulgation",
        "    -Server",
        "    -X-Powered-By",
        "}",
    ]
    return "\n".join(lines)


GENERATORS = {
    "nginx":  gen_nginx,
    "apache": gen_apache,
    "iis":    gen_iis,
    "caddy":  gen_caddy,
}

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Génération de configuration sécurité HTTP pour serveurs web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--server",         default="nginx",
                        choices=["nginx", "apache", "iis", "caddy"],
                        help="Serveur web cible (défaut: nginx)")
    parser.add_argument("--json",           dest="json_file",
                        help="JSON exporté par http_headers_analyzer.py")
    parser.add_argument("--domain",         default="example.com",
                        help="Domaine (pour CSP/HSTS)")
    parser.add_argument("--csp",            default="moderate",
                        choices=["strict", "moderate", "permissive"],
                        help="Niveau CSP (défaut: moderate)")
    parser.add_argument("--hsts-age",       type=int, default=31536000,
                        help="HSTS max-age en secondes (défaut: 31536000)")
    parser.add_argument("--no-hsts-preload", action="store_true",
                        help="Désactiver HSTS preload")
    parser.add_argument("-o", "--output",   help="Fichier de sortie")
    parser.add_argument("--preview",        action="store_true",
                        help="Afficher sans sauvegarder")
    args = parser.parse_args()

    print(cyan("=" * 65))
    print(cyan(f"  HTTP Headers Hardening — serveur : {args.server.upper()}"))
    print(cyan(f"  CSP niveau : {args.csp}  |  HSTS max-age : {args.hsts_age}s"))
    print(cyan("=" * 65 + "\n"))

    # Identifier les en-têtes à corriger depuis le JSON du scanner
    to_fix = None
    if args.json_file:
        try:
            with open(args.json_file, "r", encoding="utf-8") as f:
                scan = json.load(f)
            # Ne prendre que les invalides ou absents
            to_fix = {
                h["name"] for h in scan.get("security_headers", [])
                if not h.get("valid", False)
            }
            print(yellow(f"  [INFO] {len(to_fix)} en-têtes à corriger d'après le scan :"))
            for name in sorted(to_fix):
                print(f"    → {name}")
            print()
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(red(f"  [AVERT] Impossible de lire {args.json_file} : {e}"))
            print(yellow("  → Génération de la configuration complète.\n"))

    headers = build_header_values(
        domain=args.domain,
        csp_level=args.csp,
        hsts_age=args.hsts_age,
        hsts_preload=not args.no_hsts_preload,
    )

    gen_fn = GENERATORS[args.server]
    config = gen_fn(headers, to_fix)

    # Affichage
    print(bold(cyan(f"[ Configuration générée — {args.server} ]\n")))
    print(config)

    if not args.preview:
        ext_map = {"nginx": "conf", "apache": "conf", "iis": "config", "caddy": "caddy"}
        default_out = f"security-headers-{args.server}.{ext_map[args.server]}"
        out_path = args.output or default_out
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(config)
        print(green(f"\n[+] Configuration sauvegardée : {out_path}"))

        print(cyan("\n[ Instructions d'intégration ]"))
        instructions = {
            "nginx":  f"  1. Copiez le fichier dans /etc/nginx/snippets/\n"
                      f"  2. Dans votre bloc 'server {{}}', ajoutez : include /etc/nginx/snippets/{out_path};\n"
                      f"  3. Testez : nginx -t  |  Rechargez : systemctl reload nginx",
            "apache": f"  1. Copiez dans /etc/apache2/conf-available/\n"
                      f"  2. Activez : a2enconf {out_path}  &&  a2enmod headers\n"
                      f"  3. Rechargez : systemctl reload apache2",
            "iis":    f"  1. Placez web.config à la racine de votre site IIS\n"
                      f"  2. Rechargez IIS : iisreset /noforce",
            "caddy":  f"  1. Dans votre Caddyfile, ajoutez : import {out_path}\n"
                      f"  2. Rechargez : caddy reload",
        }
        print(instructions[args.server])


if __name__ == "__main__":
    main()
