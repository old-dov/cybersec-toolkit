#!/usr/bin/env python3
"""
=============================================================================
 hash_generator.py — Génération et vérification de hachages cryptographiques
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : stdlib uniquement (hashlib)

 DESCRIPTION
 -----------
 Génère des hachages cryptographiques de fichiers ou de textes, et permet
 de vérifier l'intégrité de fichiers en comparant leur hash à une valeur
 de référence. Supporte MD5, SHA-1, SHA-256, SHA-512 et BLAKE2.

 USAGE
 -----
   python hash_generator.py [commande] [options]

 COMMANDES
 ---------
   hash      Générer le hash d'un fichier ou d'un texte (défaut)
   verify    Vérifier l'intégrité d'un fichier
   compare   Comparer deux fichiers pour vérifier s'ils sont identiques

 EXEMPLES
 --------
   # Hacher un fichier avec tous les algorithmes
   python hash_generator.py hash -f fichier.zip --all

   # Hacher un texte
   python hash_generator.py hash -t "mon texte secret" --algo sha256

   # Vérifier l'intégrité
   python hash_generator.py verify -f fichier.zip --algo sha256 --expected abc123...

   # Comparer deux fichiers
   python hash_generator.py compare -f1 original.bin -f2 copie.bin

   # Générer un fichier de checksums
   python hash_generator.py hash -f fichier.zip --all -o checksums.txt

 OPTIONS HASH
 ------------
   -f, --file      Fichier à hacher
   -t, --text      Texte à hacher
   --algo          Algorithme : md5, sha1, sha224, sha256, sha384, sha512,
                                blake2b, blake2s (défaut: sha256)
   --all           Calculer tous les algorithmes disponibles
   -o, --output    Fichier de sortie

 OPTIONS VERIFY
 --------------
   -f, --file      Fichier à vérifier
   --algo          Algorithme utilisé (défaut: sha256)
   --expected      Hash de référence attendu
   --checksum-file Fichier de checksums (format sha256sum)

 NOTES DE SÉCURITÉ
 -----------------
   - MD5 et SHA-1 sont CASSÉS cryptographiquement. Ne les utilisez
     pas pour la sécurité. Préférez SHA-256 ou SHA-512.
   - BLAKE2b est plus rapide que SHA-2 et sûr pour la plupart des usages.
=============================================================================
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# ─── Couleurs ────────────────────────────────────────────────────────────────

def green(t):  return f"{Fore.GREEN}{t}{Style.RESET_ALL}" if COLOR else t
def yellow(t): return f"{Fore.YELLOW}{t}{Style.RESET_ALL}" if COLOR else t
def red(t):    return f"{Fore.RED}{t}{Style.RESET_ALL}" if COLOR else t
def cyan(t):   return f"{Fore.CYAN}{t}{Style.RESET_ALL}" if COLOR else t
def bold(t):   return f"{Style.BRIGHT}{t}{Style.RESET_ALL}" if COLOR else t

# ─── Algorithmes disponibles ─────────────────────────────────────────────────

ALGORITHMS = {
    "md5":     ("MD5",     "⚠ OBSOLÈTE — Ne pas utiliser pour la sécurité"),
    "sha1":    ("SHA-1",   "⚠ CASSÉ — Ne pas utiliser pour la sécurité"),
    "sha224":  ("SHA-224", "OK"),
    "sha256":  ("SHA-256", "✓ Recommandé"),
    "sha384":  ("SHA-384", "✓ Recommandé"),
    "sha512":  ("SHA-512", "✓ Recommandé (le plus sûr)"),
    "blake2b": ("BLAKE2b", "✓ Rapide et sûr"),
    "blake2s": ("BLAKE2s", "✓ Rapide et sûr (32 bits)"),
}

CHUNK_SIZE = 65536  # 64 Ko

# ─── Fonctions ───────────────────────────────────────────────────────────────

def hash_file(filepath: str, algo: str) -> str:
    """Calcule le hash d'un fichier par chunks (gère les gros fichiers)."""
    h = hashlib.new(algo)
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                h.update(chunk)
        return h.hexdigest()
    except FileNotFoundError:
        print(red(f"[ERREUR] Fichier introuvable : {filepath}"))
        sys.exit(1)
    except PermissionError:
        print(red(f"[ERREUR] Permission refusée : {filepath}"))
        sys.exit(1)


def hash_text(text: str, algo: str) -> str:
    """Calcule le hash d'une chaîne de texte."""
    h = hashlib.new(algo)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def format_size(size: int) -> str:
    """Formate une taille de fichier de façon lisible."""
    for unit in ["o", "Ko", "Mo", "Go", "To"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} Po"


def security_note(algo: str) -> str:
    """Retourne une note de sécurité pour l'algorithme."""
    note = ALGORITHMS.get(algo.lower(), ("", ""))[1]
    if "OBSOLÈTE" in note or "CASSÉ" in note:
        return yellow(f"  [{note}]")
    return green(f"  [{note}]")

# ─── Sous-commandes ───────────────────────────────────────────────────────────

def cmd_hash(args) -> None:
    """Génère le hash d'un fichier ou d'un texte."""
    if not args.file and not args.text:
        print(red("[ERREUR] Fournissez -f <fichier> ou -t <texte>"))
        sys.exit(1)

    algos = list(ALGORITHMS.keys()) if args.all else [args.algo.lower()]
    results = {}

    print(cyan("=" * 65))
    if args.file:
        size = Path(args.file).stat().st_size if Path(args.file).exists() else 0
        print(cyan(f"  Hash Generator — {args.file}  ({format_size(size)})"))
    else:
        print(cyan(f"  Hash Generator — texte ({len(args.text.encode())} octets)"))
    print(cyan(f"  Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(cyan("=" * 65 + "\n"))

    for algo in algos:
        display_name = ALGORITHMS.get(algo, (algo, ""))[0]
        if args.file:
            digest = hash_file(args.file, algo)
        else:
            digest = hash_text(args.text, algo)
        results[algo] = digest
        print(f"  {bold(display_name):<12} : {green(digest)}")
        print(security_note(algo))
        print()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            source = args.file or f'"{args.text}"'
            f.write(f"# Hash — {source}\n")
            f.write(f"# Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for algo, digest in results.items():
                f.write(f"{digest}  ({ALGORITHMS[algo][0]})  {source}\n")
        print(green(f"[+] Checksums sauvegardés : {args.output}"))


def cmd_verify(args) -> None:
    """Vérifie l'intégrité d'un fichier par comparaison de hash."""
    if args.checksum_file:
        # Format : hash  filename (une ligne par fichier)
        mismatches = 0
        with open(args.checksum_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) < 2:
                    continue
                expected_hash, filename = parts[0], parts[-1].strip()
                algo = args.algo.lower()
                actual = hash_file(filename, algo)
                if actual.lower() == expected_hash.lower():
                    print(green(f"  [✓ OK]    {filename}"))
                else:
                    print(red(f"  [✗ FAIL]  {filename}"))
                    print(red(f"    Attendu  : {expected_hash}"))
                    print(red(f"    Calculé  : {actual}"))
                    mismatches += 1
        if mismatches == 0:
            print(green(f"\n[✓] Tous les hashes correspondent."))
        else:
            print(red(f"\n[✗] {mismatches} fichier(s) corrompu(s) ou altéré(s) !"))
        return

    if not args.file or not args.expected:
        print(red("[ERREUR] Fournissez -f <fichier> et --expected <hash>"))
        sys.exit(1)

    algo = args.algo.lower()
    print(f"  Fichier  : {args.file}")
    print(f"  Algo     : {ALGORITHMS.get(algo, (algo, ''))[0]}")
    print(f"  Attendu  : {args.expected}\n")
    print("  [*] Calcul en cours...")

    actual = hash_file(args.file, algo)
    print(f"  Calculé  : {actual}")

    if actual.lower() == args.expected.lower().strip():
        print(green(f"\n  [✓] INTÉGRITÉ VÉRIFIÉE — Le fichier n'a pas été altéré."))
    else:
        print(red(f"\n  [✗] INTÉGRITÉ COMPROMISE — Le fichier a été modifié !"))
        # Trouver le premier octet différent
        exp = args.expected.lower().strip()
        for i, (a, b) in enumerate(zip(actual, exp)):
            if a != b:
                print(yellow(f"     Première différence à la position {i} du hash"))
                break


def cmd_compare(args) -> None:
    """Compare deux fichiers pour vérifier s'ils sont identiques."""
    algo = "sha256"
    print(f"  Fichier 1 : {args.file1}")
    print(f"  Fichier 2 : {args.file2}\n")
    print("  [*] Calcul des hashes SHA-256...")

    h1 = hash_file(args.file1, algo)
    h2 = hash_file(args.file2, algo)
    s1 = Path(args.file1).stat().st_size
    s2 = Path(args.file2).stat().st_size

    print(f"  SHA-256 F1 : {h1}")
    print(f"  SHA-256 F2 : {h2}")
    print(f"  Taille  F1 : {format_size(s1)}")
    print(f"  Taille  F2 : {format_size(s2)}")

    if h1 == h2:
        print(green(f"\n  [✓] Les deux fichiers sont IDENTIQUES."))
    else:
        print(red(f"\n  [✗] Les fichiers sont DIFFÉRENTS."))
        if s1 != s2:
            print(yellow(f"     Différence de taille : {abs(s2 - s1):,} octets"))

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Génération et vérification de hachages cryptographiques",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = False

    # Commande hash (défaut)
    h = subparsers.add_parser("hash", help="Générer un hash")
    h.add_argument("-f", "--file",  help="Fichier à hacher")
    h.add_argument("-t", "--text",  help="Texte à hacher")
    h.add_argument("--algo",        default="sha256", choices=list(ALGORITHMS.keys()))
    h.add_argument("--all",         action="store_true", help="Tous les algorithmes")
    h.add_argument("-o", "--output", help="Fichier de sortie")

    # Commande verify
    v = subparsers.add_parser("verify", help="Vérifier l'intégrité")
    v.add_argument("-f", "--file",          help="Fichier à vérifier")
    v.add_argument("--algo",                default="sha256", choices=list(ALGORITHMS.keys()))
    v.add_argument("--expected",            help="Hash de référence")
    v.add_argument("--checksum-file",       help="Fichier de checksums")

    # Commande compare
    c = subparsers.add_parser("compare", help="Comparer deux fichiers")
    c.add_argument("-f1", "--file1", required=True)
    c.add_argument("-f2", "--file2", required=True)

    args = parser.parse_args()

    print(cyan("=" * 65))
    print(cyan("  Hash Generator"))
    print(cyan("=" * 65))

    command = args.command or "hash"
    if command == "hash" or args.command is None:
        # Support sans sous-commande (rétrocompatibilité)
        if args.command is None:
            parser.print_help()
            sys.exit(0)
        cmd_hash(args)
    elif command == "verify":
        cmd_verify(args)
    elif command == "compare":
        cmd_compare(args)


if __name__ == "__main__":
    main()
