#!/usr/bin/env python3
"""
=============================================================================
 network_mapper.py — Cartographie des hôtes actifs sur un réseau
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : stdlib uniquement

 DESCRIPTION
 -----------
 Découvre les hôtes actifs sur un réseau local (CIDR) en combinant :
   1. Ping ICMP (via sous-processus système, compatible multi-OS)
   2. Tentative de connexion TCP sur ports courants (fallback si ICMP bloqué)
 Pour chaque hôte trouvé, tente une résolution DNS inverse (PTR).

 USAGE
 -----
   python network_mapper.py -n <réseau_CIDR> [options]

 EXEMPLES
 --------
   python network_mapper.py -n 192.168.1.0/24
   python network_mapper.py -n 10.0.0.0/24 -T 100 -o hosts.txt
   python network_mapper.py -n 172.16.0.0/24 --tcp-fallback -p 22,80,445

 OPTIONS
 -------
   -n, --network       Réseau en notation CIDR (obligatoire)
   -T, --threads       Threads simultanés (défaut: 50)
   --timeout           Timeout ping en secondes (défaut: 1)
   --tcp-fallback      Utiliser TCP si ICMP échoue (ports: 22,80,443,445)
   -p, --tcp-ports     Ports TCP pour le fallback (défaut: 22,80,443,445)
   -o, --output        Fichier de sortie
   --json              Exporter également en JSON

 AVERTISSEMENT LÉGAL
 --------------------
 Utilisez ce script uniquement sur des réseaux que vous administrez ou
 pour lesquels vous avez une autorisation explicite.
=============================================================================
"""

import argparse
import ipaddress
import json
import platform
import socket
import subprocess
import sys
import threading
import time
from queue import Queue, Empty
from datetime import datetime

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

# ─── Détection OS ─────────────────────────────────────────────────────────────

IS_WINDOWS = platform.system().lower() == "windows"

# ─── Variables partagées ─────────────────────────────────────────────────────

alive_hosts = []
alive_lock = threading.Lock()
print_lock = threading.Lock()

# ─── Fonctions ───────────────────────────────────────────────────────────────

def ping(ip: str, timeout: int) -> bool:
    """Ping ICMP via la commande système (compatible Win/Mac/Linux)."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), str(ip)]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        return result.returncode == 0
    except Exception:
        return False


def tcp_check(ip: str, ports: list, timeout: float) -> bool:
    """Vérifie si l'hôte répond sur au moins un port TCP."""
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((str(ip), port)) == 0:
                    return True
        except Exception:
            continue
    return False


def reverse_dns(ip: str) -> str:
    """Résolution DNS inverse (PTR)."""
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except Exception:
        return ""


def check_host(ip: str, timeout: int, tcp_fallback: bool, tcp_ports: list) -> None:
    """Vérifie si un hôte est actif et enregistre le résultat."""
    is_alive = ping(ip, timeout)
    if not is_alive and tcp_fallback:
        is_alive = tcp_check(ip, tcp_ports, float(timeout))

    if is_alive:
        hostname = reverse_dns(ip)
        with alive_lock:
            alive_hosts.append({"ip": ip, "hostname": hostname})
        with print_lock:
            display = f"  [ACTIF]  {ip:<18} {hostname}"
            print(green(display))


def worker(queue: Queue, timeout: int, tcp_fallback: bool, tcp_ports: list) -> None:
    """Thread worker."""
    while True:
        try:
            ip = queue.get(timeout=1)
        except Empty:
            break
        check_host(str(ip), timeout, tcp_fallback, tcp_ports)
        queue.task_done()

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Cartographie des hôtes actifs sur un réseau",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-n", "--network",   required=True, help="Réseau CIDR (ex: 192.168.1.0/24)")
    parser.add_argument("-T", "--threads",   type=int, default=50, help="Threads (défaut: 50)")
    parser.add_argument("--timeout",         type=int, default=1, help="Timeout ping (s, défaut: 1)")
    parser.add_argument("--tcp-fallback",    action="store_true", help="TCP fallback si ICMP bloqué")
    parser.add_argument("-p", "--tcp-ports", default="22,80,443,445", help="Ports TCP pour fallback")
    parser.add_argument("-o", "--output",    help="Fichier de sortie")
    parser.add_argument("--json",            action="store_true", help="Exporter en JSON")
    args = parser.parse_args()

    try:
        network = ipaddress.ip_network(args.network, strict=False)
    except ValueError as e:
        print(red(f"[ERREUR] Réseau invalide : {e}"))
        sys.exit(1)

    tcp_ports = [int(p.strip()) for p in args.tcp_ports.split(",")]
    hosts = list(network.hosts())

    print(cyan("=" * 60))
    print(cyan(f"  Network Mapper — {args.network}"))
    print(cyan(f"  Hôtes à tester : {len(hosts)}"))
    print(cyan(f"  Threads        : {args.threads}"))
    print(cyan(f"  Timeout        : {args.timeout}s"))
    print(cyan(f"  TCP fallback   : {'Oui (' + args.tcp_ports + ')' if args.tcp_fallback else 'Non'}"))
    print(cyan(f"  Démarré        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(cyan("=" * 60))

    queue = Queue()
    for h in hosts:
        queue.put(str(h))

    start = time.time()
    threads = []
    for _ in range(min(args.threads, len(hosts))):
        t = threading.Thread(
            target=worker,
            args=(queue, args.timeout, args.tcp_fallback, tcp_ports),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    elapsed = time.time() - start
    alive_hosts.sort(key=lambda x: [int(p) for p in x["ip"].split(".")])

    print(cyan("\n" + "=" * 60))
    print(cyan(f"  Terminé en {elapsed:.2f}s  |  Hôtes actifs : {len(alive_hosts)} / {len(hosts)}"))
    print(cyan("=" * 60))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(f"Network Map — {args.network}\n")
            f.write(f"Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Hôtes actifs : {len(alive_hosts)} / {len(hosts)}\n\n")
            for h in alive_hosts:
                f.write(f"{h['ip']:<18}  {h['hostname']}\n")
        print(green(f"\n[+] Résultats sauvegardés : {args.output}"))

    if args.json:
        json_path = (args.output.rsplit(".", 1)[0] + ".json") if args.output else f"network_mapper_{args.network.replace('/', '_')}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "network": args.network,
                "date": datetime.now().isoformat(),
                "hosts_tested": len(hosts),
                "results": alive_hosts,
            }, f, indent=2, ensure_ascii=False)
        print(green(f"[+] JSON sauvegardé : {json_path}"))


if __name__ == "__main__":
    main()
