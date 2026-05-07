#!/usr/bin/env python3
"""
=============================================================================
 ssl_hardening_config.py — Génération de configuration SSL/TLS sécurisée
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : stdlib uniquement

 DESCRIPTION
 -----------
 Remédie aux problèmes détectés par ssl_checker.py en générant une
 configuration SSL/TLS conforme aux recommandations ANSSI / Mozilla
 SSL Configuration Generator (profil Intermediate ou Modern).

 Génère des configurations pour nginx, Apache et HAProxy.

 PROFILS
 -------
   modern       TLS 1.3 uniquement — clients récents (2020+)
   intermediate TLS 1.2 + 1.3 — recommandé pour la plupart des sites
   old          TLS 1.0+ — compatibilité maximale (non recommandé)

 PIPELINE
 --------
   1. python ../03_Vulnerability_Assessment/ssl_checker.py -t exemple.com \
             -o ssl.txt
   2. python ssl_hardening_config.py --server nginx --domain exemple.com \
             --profile intermediate

 USAGE
 -----
   python ssl_hardening_config.py [options]

 EXEMPLES
 --------
   python ssl_hardening_config.py --server nginx --domain exemple.com
   python ssl_hardening_config.py --server apache --profile modern --domain monsite.fr
   python ssl_hardening_config.py --server nginx --domain exemple.com \
     --cert /etc/letsencrypt/live/exemple.com/fullchain.pem \
     --key  /etc/letsencrypt/live/exemple.com/privkey.pem \
     -o /etc/nginx/snippets/ssl-exemple.com.conf

 OPTIONS
 -------
   --server      Serveur : nginx, apache, haproxy (défaut: nginx)
   --domain      Domaine cible (obligatoire)
   --profile     Profil : modern, intermediate, old (défaut: intermediate)
   --cert        Chemin vers le certificat (défaut: Let's Encrypt)
   --key         Chemin vers la clé privée (défaut: Let's Encrypt)
   --dhparam     Chemin vers le fichier DH (généré si absent)
   -o, --output  Fichier de sortie
   --preview     Afficher sans sauvegarder

 RÉFÉRENCES
 ----------
   - Mozilla SSL Config Generator : https://ssl-config.mozilla.org/
   - ANSSI : https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-tls/
=============================================================================
"""

import argparse
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

# ─── Profils TLS ─────────────────────────────────────────────────────────────

PROFILES = {
    "modern": {
        "label":    "Modern (Mozilla)",
        "protocols_nginx":  "TLSv1.3",
        "protocols_apache": "TLSv1.3",
        "ciphers_nginx":    "",  # TLS 1.3 gère ses propres ciphers
        "ciphers_apache":   "",
        "hsts_age":  "63072000",
        "notes":    "Compatible avec : Firefox 63+, Chrome 70+, iOS 12.2+, Android 10+",
        "warning":  None,
    },
    "intermediate": {
        "label":    "Intermediate (Mozilla) — RECOMMANDÉ",
        "protocols_nginx":  "TLSv1.2 TLSv1.3",
        "protocols_apache": "TLSv1.2 TLSv1.3",
        "ciphers_nginx": (
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:"
            "DHE-RSA-CHACHA20-POLY1305"
        ),
        "ciphers_apache": (
            "ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 "
            "ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 "
            "ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305 "
            "DHE-RSA-AES128-GCM-SHA256 DHE-RSA-AES256-GCM-SHA384"
        ),
        "hsts_age":  "63072000",
        "notes":    "Compatible avec : Firefox 27+, Chrome 30+, IE 11+, iOS 9+, Android 4.4.2+",
        "warning":  None,
    },
    "old": {
        "label":    "Old (compatibilité maximale — NON recommandé)",
        "protocols_nginx":  "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3",
        "protocols_apache": "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3",
        "ciphers_nginx": (
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:"
            "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
        ),
        "ciphers_apache": (
            "ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 "
            "AES128-GCM-SHA256 AES256-GCM-SHA384 AES128-SHA AES256-SHA"
        ),
        "hsts_age":  "0",
        "notes":    "Compatible avec : IE8/WinXP+, Java 7+",
        "warning":  "⚠ TLS 1.0 et 1.1 sont obsolètes. Utilisez ce profil uniquement si nécessaire.",
    },
}

# ─── Générateurs ─────────────────────────────────────────────────────────────

def gen_nginx(domain: str, cert: str, key: str, dhparam: str, profile: dict) -> str:
    protocols = profile["protocols_nginx"]
    ciphers   = profile["ciphers_nginx"]
    hsts_age  = profile["hsts_age"]

    cipher_block = ""
    if ciphers:
        cipher_block = f"\nssl_ciphers '{ciphers}';\nssl_prefer_server_ciphers off;"

    dhparam_block = ""
    if dhparam and profile != PROFILES["modern"]:
        dhparam_block = f"\nssl_dhparam {dhparam};"

    return f"""# ════════════════════════════════════════════════════════
# Configuration SSL/TLS — nginx — {profile['label']}
# Domaine : {domain}
# Généré  : {datetime.now().strftime('%Y-%m-%d %H:%M')}
# Réf.    : https://ssl-config.mozilla.org/
# ════════════════════════════════════════════════════════
# Usage   : include /etc/nginx/snippets/ssl-{domain}.conf;

# ── Certificat ──────────────────────────────────────────
ssl_certificate     {cert};
ssl_certificate_key {key};
{dhparam_block}
# ── Protocoles et chiffrements ──────────────────────────
ssl_protocols {protocols};{cipher_block}

# ── Optimisation de session ─────────────────────────────
ssl_session_timeout 1d;
ssl_session_cache   shared:MozSSL:10m;  # ~40 000 sessions
ssl_session_tickets off;

# ── OCSP Stapling ───────────────────────────────────────
ssl_stapling        on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout    5s;

# ── HSTS (HTTP Strict Transport Security) ───────────────
# ⚠ Testez sur un sous-domaine avant d'activer preload !
add_header Strict-Transport-Security "max-age={hsts_age}; includeSubDomains; preload" always;

# ── Redirection HTTP → HTTPS (dans un bloc server séparé)
# server {{
#     listen 80;
#     server_name {domain};
#     return 301 https://$host$request_uri;
# }}
"""


def gen_apache(domain: str, cert: str, key: str, dhparam: str, profile: dict) -> str:
    protocols = profile["protocols_apache"]
    ciphers   = profile["ciphers_apache"]
    hsts_age  = profile["hsts_age"]

    cipher_block = f"\n    SSLCipherSuite {ciphers}\n    SSLHonorCipherOrder off" if ciphers else ""
    dhparam_block = f"\n    # DH Parameters\n    SSLOpenSSLConfCmd DHParameters \"{dhparam}\"" if dhparam else ""

    return f"""# ════════════════════════════════════════════════════════
# Configuration SSL/TLS — Apache — {profile['label']}
# Domaine : {domain}
# Généré  : {datetime.now().strftime('%Y-%m-%d %H:%M')}
# Activer : a2enmod ssl headers
# ════════════════════════════════════════════════════════

<VirtualHost *:443>
    ServerName {domain}

    # ── Certificat ──────────────────────────────────────
    SSLEngine on
    SSLCertificateFile    {cert}
    SSLCertificateKeyFile {key}
    {dhparam_block}

    # ── Protocoles ──────────────────────────────────────
    SSLProtocol           -all +{protocols.replace(' ', ' +')}
    {cipher_block}

    # ── OCSP Stapling ───────────────────────────────────
    SSLUseStapling         on
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors off
    # SSLStaplingCache doit être déclaré hors VirtualHost :
    # SSLStaplingCache "shmcb:/var/run/ocsp(128000)"

    # ── Session TLS ─────────────────────────────────────
    SSLSessionTickets off

    # ── HSTS ────────────────────────────────────────────
    <IfModule mod_headers.c>
        Header always set Strict-Transport-Security "max-age={hsts_age}; includeSubDomains; preload"
    </IfModule>

    # ── Votre configuration site ici ────────────────────
    DocumentRoot /var/www/html
</VirtualHost>

# ── Redirection HTTP → HTTPS ─────────────────────────────
<VirtualHost *:80>
    ServerName {domain}
    Redirect permanent / https://{domain}/
</VirtualHost>
"""


def gen_haproxy(domain: str, cert: str, key: str, dhparam: str, profile: dict) -> str:
    hsts_age = profile["hsts_age"]
    tls_options = "no-sslv3 no-tlsv10 no-tlsv11"
    if profile == PROFILES["old"]:
        tls_options = "no-sslv3"

    ciphers = profile["ciphers_nginx"]  # même format
    cipher_line = f"\n    ssl-default-bind-ciphers {ciphers}" if ciphers else ""

    return f"""# ════════════════════════════════════════════════════════
# Configuration SSL/TLS — HAProxy — {profile['label']}
# Domaine : {domain}
# Généré  : {datetime.now().strftime('%Y-%m-%d %H:%M')}
# ════════════════════════════════════════════════════════
# Concaténer cert + key + chaîne CA dans un seul .pem :
#   cat fullchain.pem privkey.pem > /etc/haproxy/certs/{domain}.pem

global
    ssl-default-bind-options {tls_options}
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256{cipher_line}
    ssl-default-server-options {tls_options}
    tune.ssl.default-dh-param 2048

frontend https_front
    bind *:443 ssl crt /etc/haproxy/certs/{domain}.pem alpn h2,http/1.1
    bind *:80
    http-request redirect scheme https unless {{ ssl_fc }}
    http-response set-header Strict-Transport-Security "max-age={hsts_age}; includeSubDomains; preload"

    default_backend web_back

backend web_back
    server app 127.0.0.1:8080 check
"""

GENERATORS = {
    "nginx":   gen_nginx,
    "apache":  gen_apache,
    "haproxy": gen_haproxy,
}

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Génération de configuration SSL/TLS sécurisée",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--server",   default="nginx",
                        choices=["nginx", "apache", "haproxy"])
    parser.add_argument("--domain",   required=True, help="Domaine cible")
    parser.add_argument("--profile",  default="intermediate",
                        choices=["modern", "intermediate", "old"])
    parser.add_argument("--cert",     help="Chemin certificat (défaut: Let's Encrypt)")
    parser.add_argument("--key",      help="Chemin clé privée (défaut: Let's Encrypt)")
    parser.add_argument("--dhparam",  help="Chemin fichier DH (ex: /etc/ssl/dhparam.pem)")
    parser.add_argument("-o", "--output", help="Fichier de sortie")
    parser.add_argument("--preview",  action="store_true")
    args = parser.parse_args()

    profile = PROFILES[args.profile]
    cert = args.cert or f"/etc/letsencrypt/live/{args.domain}/fullchain.pem"
    key  = args.key  or f"/etc/letsencrypt/live/{args.domain}/privkey.pem"

    print(cyan("=" * 65))
    print(cyan(f"  SSL/TLS Hardening — {args.server.upper()} — {args.domain}"))
    print(cyan(f"  Profil  : {profile['label']}"))
    print(cyan(f"  Notes   : {profile['notes']}"))
    if profile.get("warning"):
        print(yellow(f"  {profile['warning']}"))
    print(cyan("=" * 65 + "\n"))

    gen_fn = GENERATORS[args.server]
    config = gen_fn(args.domain, cert, key, args.dhparam or "", profile)

    print(bold(cyan(f"[ Configuration SSL/TLS — {args.server} ]\n")))
    print(config)

    if not args.preview:
        ext = "conf" if args.server in ("nginx", "apache") else "cfg"
        default_out = f"ssl-{args.domain}-{args.server}.{ext}"
        out_path = args.output or default_out
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(config)
        print(green(f"\n[+] Configuration sauvegardée : {out_path}"))

        # Commandes utiles
        print(cyan("\n[ Commandes utiles ]\n"))
        if args.server == "nginx":
            print(f"  # Générer le fichier DH (une seule fois, peut prendre du temps)")
            print(f"  openssl dhparam -out /etc/ssl/dhparam.pem 2048\n")
            print(f"  # Tester la configuration nginx")
            print(f"  nginx -t\n")
            print(f"  # Recharger nginx")
            print(f"  systemctl reload nginx\n")
            print(f"  # Tester la configuration SSL en ligne")
            print(f"  # https://www.ssllabs.com/ssltest/analyze.html?d={args.domain}")
        elif args.server == "apache":
            print(f"  # Activer les modules requis")
            print(f"  a2enmod ssl headers\n")
            print(f"  # Tester la configuration Apache")
            print(f"  apache2ctl configtest\n")
            print(f"  # Recharger Apache")
            print(f"  systemctl reload apache2")


if __name__ == "__main__":
    main()
