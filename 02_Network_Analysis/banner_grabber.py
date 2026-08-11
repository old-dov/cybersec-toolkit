#!/usr/bin/env python3
"""
=============================================================================
 banner_grabber.py — Récupération de bannières de services TCP
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : stdlib uniquement

 DESCRIPTION
 -----------
 Se connecte aux ports TCP spécifiés d'un hôte et tente de récupérer la
 bannière de service exposée. Utile pour identifier les versions de
 logiciels (SSH, FTP, SMTP, HTTP, etc.) et détecter des versions
 vulnérables.

 USAGE
 -----
   python banner_grabber.py -t <hôte> -p <ports> [options]

 EXEMPLES
 --------
   python banner_grabber.py -t 192.168.1.1 -p 21,22,25,80,443,8080
   python banner_grabber.py -t exemple.com -p 1-100 --timeout 3
   python banner_grabber.py -t 10.0.0.5 -p 22,80 -o bannières.txt

 OPTIONS
 -------
   -t, --target    Hôte ou IP cible (obligatoire)
   -p, --ports     Ports à sonder : "21,22,80" ou "1-100" (obligatoire)
   --timeout       Timeout en secondes (défaut: 3.0)
   -o, --output    Fichier de sortie
   -v, --verbose   Afficher aussi les ports sans bannière
   --json          Exporter également en JSON

 PROBES INTÉGRÉES
 ----------------
   HTTP, HTTPS, FTP, SSH, SMTP, POP3, IMAP, RDP, MySQL, PostgreSQL,
   Redis, MongoDB, Telnet (sonde générique)

 AVERTISSEMENT LÉGAL
 --------------------
 Le banner grabbing est une technique active. N'utilisez ce script que
 sur des systèmes dont vous avez l'autorisation.
=============================================================================
"""

import argparse
import json
import socket
import ssl
import sys
import threading
import time
from datetime import datetime
from queue import Queue, Empty

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# ─── Couleurs ────────────────────────────────────────────────────────────────

def green(t):  return f"{Fore.GREEN}{t}{Style.RESET_ALL}" if COLOR else t
def yellow(t): return f"{Fore.YELLOW}{t}{Style.RESET_ALL}" if COLOR else t
def cyan(t):   return f"{Fore.CYAN}{t}{Style.RESET_ALL}" if COLOR else t
def red(t):    return f"{Fore.RED}{t}{Style.RESET_ALL}" if COLOR else t

# ─── Probes HTTP ─────────────────────────────────────────────────────────────

def http_probe(host: str, port: int) -> bytes:
    return f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()

def smtp_probe(_h, _p) -> bytes:
    return b""  # SMTP envoie sa bannière sans probe

def generic_probe(_h, _p) -> bytes:
    return b"\r\n"

# Sonde par port
PORT_PROBES = {
    21:   generic_probe,   # FTP
    22:   generic_probe,   # SSH
    23:   generic_probe,   # Telnet
    25:   smtp_probe,      # SMTP
    80:   http_probe,      # HTTP
    110:  generic_probe,   # POP3
    143:  generic_probe,   # IMAP
    443:  http_probe,      # HTTPS (avec SSL)
    587:  smtp_probe,      # SMTP Submission
    993:  generic_probe,   # IMAPS
    995:  generic_probe,   # POP3S
    3306: generic_probe,   # MySQL
    5432: generic_probe,   # PostgreSQL
    6379: b"PING\r\n",     # Redis
    8080: http_probe,
    8443: http_probe,
}

# ─── Variables partagées ─────────────────────────────────────────────────────

results = []
results_lock = threading.Lock()
print_lock = threading.Lock()

# ─── Fonctions ───────────────────────────────────────────────────────────────

def grab(host: str, port: int, timeout: float) -> str:
    """Tente de grabber la bannière d'un port. Gère HTTP(S) et TCP brut.

    Deux phases distinctes : une erreur/timeout à la connexion (port fermé,
    filtré, ou hôte qui ne répond pas) doit compter comme port fermé (None),
    alors qu'une erreur/timeout après connexion réussie (probe envoyée, pas
    de réponse) veut dire port ouvert mais silencieux ("") — les confondre
    faisait remonter en masse des ports fermés/filtrés comme "ouverts"."""
    try:
        use_ssl = port in (443, 8443, 993, 995)
        raw = socket.create_connection((host, port), timeout=timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                s = ctx.wrap_socket(raw, server_hostname=host)
            except Exception:
                raw.close()
                return None
        else:
            s = raw
    except OSError:
        return None  # Port fermé / filtré / hôte injoignable

    try:
        with s:
            probe_fn = PORT_PROBES.get(port, generic_probe)
            probe = probe_fn(host, port) if callable(probe_fn) else probe_fn
            if probe:
                s.sendall(probe)
            if not use_ssl:
                time.sleep(0.3)
            s.settimeout(timeout)
            return s.recv(2048).decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""  # Connecté mais pas de bannière reçue


def scan_port(host: str, ip: str, port: int, timeout: float, verbose: bool) -> None:
    banner = grab(host, port, timeout)
    if banner is None:
        if verbose:
            with print_lock:
                print(f"  [FERMÉ]   {port}/TCP")
        return

    first_line = banner.split("\n")[0][:120] if banner else "(pas de bannière)"
    entry = {"port": port, "banner": banner}

    with results_lock:
        results.append(entry)
    with print_lock:
        print(green(f"  [OUVERT]  {port:>5}/TCP"))
        if first_line:
            print(f"            {first_line}")
        if len(banner.split(chr(10))) > 1:
            for line in banner.split("\n")[1:4]:
                if line.strip():
                    print(f"            {line.strip()}")


def worker(host: str, ip: str, queue: Queue, timeout: float, verbose: bool) -> None:
    while True:
        try:
            port = queue.get(timeout=1)
        except Empty:
            break
        scan_port(host, ip, port, timeout, verbose)
        queue.task_done()


def parse_ports(s: str) -> list:
    ports = []
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return ports

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Récupération de bannières de services TCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target",  required=True, help="Hôte ou IP cible")
    parser.add_argument("-p", "--ports",   required=True, help="Ports : '21,22,80' ou '1-100'")
    parser.add_argument("--timeout",       type=float, default=3.0, help="Timeout (s, défaut: 3)")
    parser.add_argument("-o", "--output",  help="Fichier de sortie")
    parser.add_argument("-v", "--verbose", action="store_true", help="Afficher les ports fermés")
    parser.add_argument("--json",          action="store_true", help="Exporter en JSON")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(red(f"[ERREUR] Impossible de résoudre : {args.target}"))
        sys.exit(1)

    ports = parse_ports(args.ports)

    print(cyan("=" * 62))
    print(cyan(f"  Banner Grabber — {args.target} ({ip})"))
    print(cyan(f"  Ports    : {args.ports}  ({len(ports)} cibles)"))
    print(cyan(f"  Timeout  : {args.timeout}s"))
    print(cyan(f"  Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(cyan("=" * 62))

    queue = Queue()
    for p in ports:
        queue.put(p)

    start = time.time()
    threads = []
    for _ in range(min(50, len(ports))):
        t = threading.Thread(
            target=worker,
            args=(args.target, ip, queue, args.timeout, args.verbose),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    elapsed = time.time() - start
    print(cyan(f"\n  Terminé en {elapsed:.2f}s  |  Ports avec bannière : {len(results)}"))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(f"Banner Grabber — {args.target} ({ip})\n")
            f.write(f"Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for r in results:
                f.write(f"Port {r['port']}/TCP :\n{r['banner']}\n\n{'─'*50}\n\n")
        print(green(f"[+] Sauvegardé : {args.output}"))

    if args.json:
        json_path = (args.output.rsplit(".", 1)[0] + ".json") if args.output else f"banner_grabber_{args.target}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "target": args.target,
                "ip": ip,
                "date": datetime.now().isoformat(),
                "ports_scanned": args.ports,
                "results": results,
            }, f, indent=2, ensure_ascii=False)
        print(green(f"[+] JSON sauvegardé : {json_path}"))


if __name__ == "__main__":
    main()
