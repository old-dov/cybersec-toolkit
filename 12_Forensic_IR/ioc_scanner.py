#!/usr/bin/env python3
"""
=============================================================================
 ioc_scanner.py — Scanner d'Indicateurs de Compromission (IOC)
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : requests (optionnel, pour résolution DNS externe)

 DESCRIPTION
 -----------
 Compare un système ou un répertoire contre une liste d'IOC (Indicators
 of Compromise) issues du threat intel :

   Hachages MD5/SHA1/SHA256  → comparaison avec les fichiers du disque
   Adresses IP               → comparaison avec les connexions réseau
   Domaines                  → résolution DNS + connexions actives

 FORMATS IOC SUPPORTÉS
 ---------------------
   JSON  : {"hashes": [...], "ips": [...], "domains": [...]}
   Texte : un IOC par ligne (auto-détection du type)

 USAGE
 -----
   python ioc_scanner.py [options]

 EXEMPLES
 --------
   python ioc_scanner.py --ioc-file iocs.json --scan-path /var/www
   python ioc_scanner.py --ioc-file iocs.txt --scan-path . --check-network
   python ioc_scanner.py --ioc-file iocs.json --scan-path / --recursive -o report.json

 OPTIONS
 -------
   --ioc-file      Fichier IOC (JSON ou texte)
   --scan-path     Répertoire à scanner pour les hachages
   --check-network Vérifier les connexions réseau actives
   --recursive     Scanner récursivement
   --threads       Threads pour le scan fichiers (défaut: 4)
   -o, --output    Fichier JSON de sortie

 AVERTISSEMENT LÉGAL
 -------------------
 Cet outil est réservé à l'analyse forensique légale. Ne l'utilisez que
 sur des systèmes que vous êtes autorisé à investiguer.
=============================================================================
"""

import argparse
import hashlib
import ipaddress
import json
import queue
import re
import socket
import subprocess
import sys
import threading
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
def red(t):    return f"{Fore.RED}{t}{Style.RESET_ALL}" if COLOR else t
def cyan(t):   return f"{Fore.CYAN}{t}{Style.RESET_ALL}" if COLOR else t
def bold(t):   return f"{Style.BRIGHT}{t}{Style.RESET_ALL}" if COLOR else t
def dim(t):    return f"{Style.DIM}{t}{Style.RESET_ALL}" if COLOR else t

# ─── Chargement des IOC ───────────────────────────────────────────────────────

HASH_RE   = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
IP_RE     = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]{3,39}$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def load_iocs(path: str) -> dict:
    """Charge un fichier IOC JSON ou texte."""
    p = Path(path)
    raw = p.read_text(encoding="utf-8", errors="replace")

    # Essayer JSON
    try:
        data = json.loads(raw)
        iocs = {
            "hashes":  set(h.lower() for h in data.get("hashes", [])),
            "ips":     set(data.get("ips", [])),
            "domains": set(d.lower() for d in data.get("domains", [])),
        }
        return iocs
    except json.JSONDecodeError:
        pass

    # Format texte (un IOC par ligne)
    iocs = {"hashes": set(), "ips": set(), "domains": set()}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if HASH_RE.match(line):
            iocs["hashes"].add(line.lower())
        elif IP_RE.match(line):
            iocs["ips"].add(line)
        elif DOMAIN_RE.match(line):
            iocs["domains"].add(line.lower())
    return iocs

# ─── Hachage fichiers ─────────────────────────────────────────────────────────

def hash_file(path: Path) -> dict:
    """Calcule MD5, SHA1 et SHA256 d'un fichier."""
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            "md5":    md5.hexdigest(),
            "sha1":   sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
    except (PermissionError, OSError):
        return {}


_file_lock = threading.Lock()
_file_hits: list = []
_files_scanned = [0]


def file_worker(q: queue.Queue, ioc_hashes: set):
    while True:
        try:
            path = q.get(timeout=1)
        except queue.Empty:
            break
        hashes = hash_file(path)
        with _file_lock:
            _files_scanned[0] += 1
        for algo, digest in hashes.items():
            if digest in ioc_hashes:
                hit = {
                    "type":      "hash",
                    "algorithm": algo,
                    "value":     digest,
                    "file":      str(path),
                    "severity":  "critical",
                }
                with _file_lock:
                    _file_hits.append(hit)
                print(f"  {red('[IOC HIT]')} {bold('HASH')} {algo.upper()}:{digest[:16]}…  {path}")
        q.task_done()


def scan_hashes(scan_path: str, ioc_hashes: set, recursive: bool, threads: int) -> list:
    root = Path(scan_path)
    pattern = "**/*" if recursive else "*"
    files = [p for p in root.glob(pattern) if p.is_file()]
    print(f"  Fichiers à scanner : {len(files)}")

    q: queue.Queue = queue.Queue()
    for f in files:
        q.put(f)

    workers = []
    for _ in range(min(threads, max(1, len(files)))):
        t = threading.Thread(target=file_worker, args=(q, ioc_hashes), daemon=True)
        t.start()
        workers.append(t)
    q.join()
    return _file_hits[:]

# ─── Scan réseau ──────────────────────────────────────────────────────────────

def get_active_connections() -> list:
    """Retourne les connexions réseau actives (cross-platform)."""
    import platform
    connections = []
    os_name = platform.system()
    try:
        if os_name == "Windows":
            out = subprocess.check_output(
                ["netstat", "-n", "-o"], text=True, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            out = subprocess.check_output(
                ["netstat", "-tn"], text=True, stderr=subprocess.DEVNULL
            )
        ip_port_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})[:\.](\d+)")
        for line in out.splitlines():
            for m in ip_port_re.finditer(line):
                ip = m.group(1)
                if ip not in ("0.0.0.0", "127.0.0.1", "::1"):
                    connections.append(ip)
    except Exception:
        pass
    return list(set(connections))


def scan_network(ioc_ips: set, ioc_domains: set) -> list:
    hits = []
    active_ips = get_active_connections()
    print(f"  Connexions actives détectées : {len(active_ips)}")

    # Vérifier IPs
    for ip in active_ips:
        if ip in ioc_ips:
            hit = {
                "type": "ip",
                "value": ip,
                "context": "connexion réseau active",
                "severity": "critical",
            }
            hits.append(hit)
            print(f"  {red('[IOC HIT]')} {bold('IP')} {ip} — connexion active malveillante détectée")

    # Résolution inverse des domaines IOC
    for domain in ioc_domains:
        try:
            resolved_ips = socket.getaddrinfo(domain, None)
            for res in resolved_ips:
                ip = res[4][0]
                if ip in active_ips:
                    hit = {
                        "type": "domain",
                        "value": domain,
                        "resolved_ip": ip,
                        "context": "domaine IOC résolu en IP de connexion active",
                        "severity": "critical",
                    }
                    hits.append(hit)
                    print(f"  {red('[IOC HIT]')} {bold('DOMAIN')} {domain} → {ip} connexion active")
                    break
        except Exception:
            pass

    return hits

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scanner d'Indicateurs de Compromission (IOC)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--ioc-file",      required=True,
                        help="Fichier IOC (JSON ou texte)")
    parser.add_argument("--scan-path",     default=".",
                        help="Répertoire à scanner (hachages)")
    parser.add_argument("--check-network", action="store_true",
                        help="Vérifier les connexions réseau actives")
    parser.add_argument("--recursive",     action="store_true")
    parser.add_argument("--threads",       type=int, default=4)
    parser.add_argument("-o", "--output")
    args = parser.parse_args()

    print(cyan("=" * 65))
    print(cyan("  IOC Scanner — Indicators of Compromise"))
    print(cyan("=" * 65 + "\n"))

    # Charger IOC
    print(f"  Chargement des IOC : {args.ioc_file}")
    iocs = load_iocs(args.ioc_file)
    print(f"  {len(iocs['hashes'])} hachages  |  "
          f"{len(iocs['ips'])} IPs  |  {len(iocs['domains'])} domaines\n")

    all_hits = []

    # Scan fichiers
    if iocs["hashes"]:
        print(bold(cyan("\n[1/2] Scan des hachages de fichiers...")))
        hits = scan_hashes(args.scan_path, iocs["hashes"], args.recursive, args.threads)
        all_hits.extend(hits)

    # Scan réseau
    if args.check_network and (iocs["ips"] or iocs["domains"]):
        print(bold(cyan("\n[2/2] Scan des connexions réseau...")))
        hits = scan_network(iocs["ips"], iocs["domains"])
        all_hits.extend(hits)

    # Résumé
    print(f"\n{cyan('─'*65)}")
    if all_hits:
        print(red(bold(f"  ⚠  {len(all_hits)} IOC DÉTECTÉ(S) — ACTION REQUISE")))
    else:
        print(green(f"  ✓  Aucun IOC détecté ({_files_scanned[0]} fichiers scannés)"))
    print(cyan("─" * 65))

    if args.output:
        report = {
            "timestamp":      datetime.now().isoformat(),
            "ioc_file":       args.ioc_file,
            "scan_path":      args.scan_path,
            "files_scanned":  _files_scanned[0],
            "ioc_counts":     {k: len(v) for k, v in iocs.items()},
            "hits":           all_hits,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(green(f"\n[+] Rapport : {args.output}"))


if __name__ == "__main__":
    main()
