#!/usr/bin/env python3
"""
=============================================================================
 file_encryptor.py — Chiffrement/déchiffrement de fichiers (AES-256-GCM)
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : cryptography  (pip install cryptography)

 DESCRIPTION
 -----------
 Chiffre et déchiffre des fichiers en utilisant AES-256 en mode GCM
 (Galois/Counter Mode), qui garantit à la fois la confidentialité et
 l'authenticité des données (AEAD — Authenticated Encryption).

 La clé de chiffrement est dérivée d'un mot de passe via PBKDF2-HMAC-SHA256
 avec un sel aléatoire et 600 000 itérations (recommandation NIST 2024).

 STRUCTURE DU FICHIER CHIFFRÉ
 -----------------------------
   [4 octets : magic "ENCF"]
   [2 octets : version]
   [16 octets : sel PBKDF2]
   [12 octets : nonce AES-GCM]
   [N octets  : données chiffrées + tag GCM (16 octets)]

 USAGE
 -----
   python file_encryptor.py <commande> [options]

 COMMANDES
 ---------
   encrypt    Chiffrer un fichier
   decrypt    Déchiffrer un fichier

 EXEMPLES
 --------
   python file_encryptor.py encrypt -i document.pdf -o document.enc
   python file_encryptor.py decrypt -i document.enc -o document.pdf
   python file_encryptor.py encrypt -i rapport.txt -o rapport.enc --password "MonMotDePasse"
   python file_encryptor.py encrypt -i dossier.zip  (chiffre en place : dossier.zip.enc)

 OPTIONS ENCRYPT
 ---------------
   -i, --input     Fichier source (obligatoire)
   -o, --output    Fichier de sortie (défaut: <input>.enc)
   --password      Mot de passe (si omis : demandé de façon sécurisée)
   --delete        Supprimer le fichier source après chiffrement

 OPTIONS DECRYPT
 ---------------
   -i, --input     Fichier chiffré (obligatoire)
   -o, --output    Fichier de sortie (obligatoire)
   --password      Mot de passe (si omis : demandé de façon sécurisée)
   --delete        Supprimer le fichier chiffré après déchiffrement

 AVERTISSEMENT
 -------------
 Conservez votre mot de passe précieusement. Il est IMPOSSIBLE de
 récupérer les données sans le mot de passe original.
=============================================================================
"""

import argparse
import getpass
import os
import struct
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("[ERREUR] Le module 'cryptography' est requis : pip install cryptography")
    sys.exit(1)

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

# ─── Constantes ──────────────────────────────────────────────────────────────

MAGIC = b"ENCF"
VERSION = b"\x00\x01"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32          # 256 bits
PBKDF2_ITERATIONS = 600_000
CHUNK_SIZE = 64 * 1024  # 64 Ko par chunk

# ─── Fonctions cryptographiques ───────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    """Dérive une clé AES-256 depuis le mot de passe via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def get_password(confirm: bool = False) -> str:
    """Demande le mot de passe de façon sécurisée (sans écho)."""
    password = getpass.getpass("  Mot de passe : ")
    if not password:
        print(red("[ERREUR] Le mot de passe ne peut pas être vide."))
        sys.exit(1)
    if confirm:
        confirm_pw = getpass.getpass("  Confirmer    : ")
        if password != confirm_pw:
            print(red("[ERREUR] Les mots de passe ne correspondent pas."))
            sys.exit(1)
    return password

# ─── Chiffrement ─────────────────────────────────────────────────────────────

def encrypt_file(input_path: str, output_path: str, password: str, delete_source: bool) -> None:
    """Chiffre un fichier avec AES-256-GCM."""
    src = Path(input_path)
    if not src.exists():
        print(red(f"[ERREUR] Fichier introuvable : {input_path}"))
        sys.exit(1)

    file_size = src.stat().st_size
    print(f"  Fichier source  : {input_path}  ({file_size:,} octets)")
    print(f"  Fichier chiffré : {output_path}")
    print(f"  Dérivation clé  : PBKDF2-HMAC-SHA256 ({PBKDF2_ITERATIONS:,} itérations)")
    print(f"  Chiffrement     : AES-256-GCM\n")
    print("  [*] Dérivation de la clé...")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)

    print("  [*] Chiffrement en cours...")
    aesgcm = AESGCM(key)

    with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
        # En-tête
        f_out.write(MAGIC)
        f_out.write(VERSION)
        f_out.write(salt)
        f_out.write(nonce)
        # Chiffrement des données en une passe (fichiers jusqu'à quelques Go)
        plaintext = f_in.read()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        f_out.write(ciphertext)

    out_size = Path(output_path).stat().st_size
    print(green(f"\n  [✓] Chiffrement réussi !"))
    print(f"  Taille sortie   : {out_size:,} octets (+ {out_size - file_size:+,} octets de surcharge)")

    if delete_source:
        # Écrasement sécurisé avant suppression
        with open(input_path, "ba+", buffering=0) as f:
            length = f.seek(0, 2)
            f.seek(0)
            f.write(os.urandom(length))
        os.remove(input_path)
        print(yellow(f"  [!] Fichier source supprimé : {input_path}"))

# ─── Déchiffrement ────────────────────────────────────────────────────────────

def decrypt_file(input_path: str, output_path: str, password: str, delete_source: bool) -> None:
    """Déchiffre un fichier chiffré avec AES-256-GCM."""
    src = Path(input_path)
    if not src.exists():
        print(red(f"[ERREUR] Fichier introuvable : {input_path}"))
        sys.exit(1)

    print(f"  Fichier chiffré   : {input_path}")
    print(f"  Fichier déchiffré : {output_path}\n")
    print("  [*] Lecture de l'en-tête...")

    with open(input_path, "rb") as f_in:
        magic = f_in.read(4)
        if magic != MAGIC:
            print(red("[ERREUR] Format de fichier invalide (pas un fichier .enc généré par ce script)"))
            sys.exit(1)

        version = f_in.read(2)
        salt = f_in.read(SALT_LEN)
        nonce = f_in.read(NONCE_LEN)
        ciphertext = f_in.read()

    print("  [*] Dérivation de la clé...")
    key = derive_key(password, salt)

    print("  [*] Déchiffrement et vérification de l'authenticité...")
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        print(red("\n  [✗] ÉCHEC : Mot de passe incorrect ou fichier corrompu/altéré."))
        print(yellow("  La vérification d'authenticité GCM a échoué."))
        sys.exit(1)

    with open(output_path, "wb") as f_out:
        f_out.write(plaintext)

    print(green(f"\n  [✓] Déchiffrement réussi !"))
    print(f"  Taille restaurée  : {len(plaintext):,} octets")

    if delete_source:
        os.remove(input_path)
        print(yellow(f"  [!] Fichier chiffré supprimé : {input_path}"))

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Chiffrement/déchiffrement AES-256-GCM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt
    enc = subparsers.add_parser("encrypt", help="Chiffrer un fichier")
    enc.add_argument("-i", "--input",    required=True, help="Fichier à chiffrer")
    enc.add_argument("-o", "--output",   help="Fichier de sortie (.enc)")
    enc.add_argument("--password",       help="Mot de passe (déconseillé en CLI, préférez la saisie interactive)")
    enc.add_argument("--delete",         action="store_true", help="Supprimer le fichier source")

    # Decrypt
    dec = subparsers.add_parser("decrypt", help="Déchiffrer un fichier")
    dec.add_argument("-i", "--input",    required=True, help="Fichier chiffré")
    dec.add_argument("-o", "--output",   required=True, help="Fichier de sortie")
    dec.add_argument("--password",       help="Mot de passe")
    dec.add_argument("--delete",         action="store_true", help="Supprimer le fichier chiffré")

    args = parser.parse_args()

    print(cyan("=" * 60))
    print(cyan(f"  File Encryptor — AES-256-GCM"))
    print(cyan(f"  Commande : {args.command}"))
    print(cyan("=" * 60 + "\n"))

    password = args.password or (
        get_password(confirm=True) if args.command == "encrypt" else get_password(confirm=False)
    )

    if args.command == "encrypt":
        output = args.output or (args.input + ".enc")
        encrypt_file(args.input, output, password, args.delete)

    elif args.command == "decrypt":
        decrypt_file(args.input, args.output, password, args.delete)


if __name__ == "__main__":
    main()
