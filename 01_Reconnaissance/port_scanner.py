#!/usr/bin/env python3
"""
=============================================================================
 port_scanner.py — Scanner de ports TCP multi-thread
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : stdlib uniquement (socket, threading, argparse, colorama optionnel)

 DESCRIPTION
 -----------
 Scanne les ports TCP d'une cible (hôte ou IP) en utilisant plusieurs
 threads pour accélérer l'opération. Pour chaque port ouvert, tente une
 récupération de bannière de service.

 USAGE
 -----
   python port_scanner.py -t <cible> [options]

 EXEMPLES
 --------
   python port_scanner.py -t 192.168.1.1
   python port_scanner.py -t exemple.com -p 1-1024 -T 200 -o resultats.txt
   python port_scanner.py -t 10.0.0.5 -p 22,80,443,8080 --timeout 2
   python port_scanner.py -t 192.168.1.1 -o resultats.txt --json

 OPTIONS
 -------
   -t, --target    Hôte ou IP cible (obligatoire)
   -p, --ports     Plage de ports : "1-1024" ou liste "22,80,443" (défaut: 1-1024)
   -T, --threads   Nombre de threads simultanés (défaut: 100, max recommandé: 500)
   --timeout       Délai de connexion en secondes (défaut: 1.0)
   -o, --output    Fichier de sortie pour les résultats (optionnel)
   -b, --banner    Activer la récupération de bannières (peut ralentir le scan)
   -v, --verbose   Afficher également les ports fermés
   --json          Exporter également en JSON

 AVERTISSEMENT LÉGAL
 --------------------
 À utiliser uniquement sur des systèmes pour lesquels vous avez
 une autorisation explicite. Le scan non autorisé est illégal.
=============================================================================
"""

import socket
import threading
import argparse
import json
import sys
import time
from queue import Queue
from datetime import datetime

# Tentative d'import de colorama pour la colorisation (optionnel)
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# ─── Couleurs (fallback si colorama absent) ──────────────────────────────────

def green(text):
    return f"{Fore.GREEN}{text}{Style.RESET_ALL}" if COLOR else text

def red(text):
    return f"{Fore.RED}{text}{Style.RESET_ALL}" if COLOR else text

def yellow(text):
    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}" if COLOR else text

def cyan(text):
    return f"{Fore.CYAN}{text}{Style.RESET_ALL}" if COLOR else text

# ─── Services connus ─────────────────────────────────────────────────────────

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

# ─── Variables partagées ─────────────────────────────────────────────────────

results = []
results_lock = threading.Lock()
print_lock = threading.Lock()

# ─── Fonctions ───────────────────────────────────────────────────────────────

def grab_banner(ip: str, port: int, timeout: float) -> str:
    """Tente de récupérer la bannière d'un service sur le port donné."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # Envoyer une requête HTTP basique pour les ports web
            if port in (80, 8080, 8000, 8888):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 443:
                return "[HTTPS — bannière SSL non décodée]"
            else:
                s.send(b"\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:120] if banner else ""
    except Exception:
        return ""


def scan_port(ip: str, port: int, timeout: float, grab: bool, verbose: bool) -> None:
    """Tente une connexion TCP sur le port et enregistre le résultat."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
        if result == 0:
            service = COMMON_SERVICES.get(port, "inconnu")
            banner = grab_banner(ip, port, timeout) if grab else ""
            line = f"  [OUVERT]  Port {port:>5}/TCP  — {service}"
            if banner:
                line += f"\n              Bannière : {banner}"
            with print_lock:
                print(green(line))
            with results_lock:
                results.append({"port": port, "state": "open", "service": service, "banner": banner})
        elif verbose:
            with print_lock:
                print(red(f"  [FERMÉ]   Port {port:>5}/TCP"))
    except Exception:
        pass


def worker(ip: str, queue: Queue, timeout: float, grab: bool, verbose: bool) -> None:
    """Thread worker : consomme les ports depuis la file."""
    while not queue.empty():
        try:
            port = queue.get(timeout=1)
            scan_port(ip, port, timeout, grab, verbose)
            queue.task_done()
        except Exception:
            break


def parse_ports(port_arg: str):
    """Convertit une chaîne de ports ('1-1024' ou '22,80,443') en liste."""
    ports = []
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scanner de ports TCP multi-thread",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exemple: python port_scanner.py -t 192.168.1.1 -p 1-1024 -T 200"
    )
    parser.add_argument("-t", "--target",  required=True, help="Hôte ou IP cible")
    parser.add_argument("-p", "--ports",   default="1-1024", help="Ports à scanner (défaut: 1-1024)")
    parser.add_argument("-T", "--threads", type=int, default=100, help="Threads simultanés (défaut: 100)")
    parser.add_argument("--timeout",       type=float, default=1.0, help="Timeout connexion en s (défaut: 1.0)")
    parser.add_argument("-o", "--output",  help="Fichier de sortie")
    parser.add_argument("-b", "--banner",  action="store_true", help="Récupérer les bannières de service")
    parser.add_argument("-v", "--verbose", action="store_true", help="Afficher les ports fermés")
    parser.add_argument("--json",          action="store_true", help="Exporter en JSON")
    args = parser.parse_args()

    # Résolution DNS
    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(red(f"[ERREUR] Impossible de résoudre : {args.target}"))
        sys.exit(1)

    ports = parse_ports(args.ports)
    threads_count = min(args.threads, 500)

    print(cyan("=" * 60))
    print(cyan(f"  Scanner de ports — {args.target} ({ip})"))
    print(cyan(f"  Ports     : {args.ports}  ({len(ports)} cibles)"))
    print(cyan(f"  Threads   : {threads_count}"))
    print(cyan(f"  Timeout   : {args.timeout}s"))
    print(cyan(f"  Bannières : {'Oui' if args.banner else 'Non'}"))
    print(cyan(f"  Démarrage : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(cyan("=" * 60))

    queue = Queue()
    for p in ports:
        queue.put(p)

    start = time.time()
    threads = []
    for _ in range(threads_count):
        t = threading.Thread(
            target=worker,
            args=(ip, queue, args.timeout, args.banner, args.verbose),
            daemon=True
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    elapsed = time.time() - start
    open_ports = [r for r in results if r["state"] == "open"]

    print(cyan("\n" + "=" * 60))
    print(cyan(f"  Scan terminé en {elapsed:.2f}s"))
    print(cyan(f"  Ports ouverts : {len(open_ports)} / {len(ports)}"))
    print(cyan("=" * 60))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(f"Scan de ports — {args.target} ({ip})\n")
            f.write(f"Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Ports scannés : {args.ports}\n\n")
            for r in open_ports:
                f.write(f"Port {r['port']}/TCP  OUVERT  {r['service']}")
                if r["banner"]:
                    f.write(f"\n  Bannière: {r['banner']}")
                f.write("\n")
        print(green(f"\nRésultats sauvegardés dans : {args.output}"))

    if args.json:
        json_path = (args.output.rsplit(".", 1)[0] + ".json") if args.output else f"port_scanner_{args.target}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "target": args.target,
                "ip": ip,
                "date": datetime.now().isoformat(),
                "ports_scanned": args.ports,
                "results": open_ports,
            }, f, indent=2, ensure_ascii=False)
        print(green(f"[+] JSON sauvegardé : {json_path}"))


if __name__ == "__main__":
    main()
