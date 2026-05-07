#!/usr/bin/env python3
"""
=============================================================================
 metadata_cleaner.py — Suppression de métadonnées de fichiers
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : Pillow>=10.3.0 (optionnel, pour images JPEG/PNG)

 DESCRIPTION
 -----------
 Supprime les métadonnées sensibles des fichiers (EXIF images, propriétés
 PDF, métadonnées Office) pour protéger la vie privée avant publication.

 TYPES DE FICHIERS SUPPORTÉS
 ----------------------------
   JPEG/JPG   → Suppression de toutes les données EXIF (GPS, appareil, auteur)
   PNG        → Suppression des chunks tEXt/iTXt/zTXt
   PDF        → Réinitialisation des champs de métadonnées (re-écriture)
   DOCX/XLSX  → Suppression des propriétés core.xml et app.xml

 USAGE
 -----
   python metadata_cleaner.py [options]

 EXEMPLES
 --------
   python metadata_cleaner.py --file photo.jpg
   python metadata_cleaner.py --file document.pdf --output clean_doc.pdf
   python metadata_cleaner.py --dir ./photos --recursive
   python metadata_cleaner.py --file report.docx --output clean_report.docx

 OPTIONS
 -------
   --file       Fichier unique à nettoyer
   --dir        Répertoire à nettoyer
   --recursive  Traiter les sous-répertoires
   --output     Fichier/dossier de sortie (défaut: _clean suffixe)
   --types      Extensions ciblées (défaut: jpg,jpeg,png,pdf,docx,xlsx)
   --in-place   Modifier les fichiers en place (ATTENTION : irréversible)
   --dry-run    Simuler sans modifier

 AVERTISSEMENT LÉGAL
 -------------------
 Faites toujours une sauvegarde avant utilisation avec --in-place.
=============================================================================
"""

import argparse
import io
import json
import os
import shutil
import struct
import sys
import zipfile
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

# ─── JPEG : suppression EXIF ─────────────────────────────────────────────────

APP1_MARKER = b"\xff\xe1"
SOI_MARKER  = b"\xff\xd8"
EOI_MARKER  = b"\xff\xd9"


def clean_jpeg_exif(data: bytes) -> bytes:
    """Retire tous les segments APP1 (EXIF) d'un JPEG sans Pillow."""
    if not data.startswith(SOI_MARKER):
        return data

    result = bytearray(SOI_MARKER)
    i = 2
    while i < len(data) - 1:
        if data[i] != 0xFF:
            break
        marker = data[i:i+2]
        if marker == EOI_MARKER:
            result.extend(EOI_MARKER)
            break
        if i + 4 > len(data):
            break
        length = struct.unpack(">H", data[i+2:i+4])[0]
        seg_end = i + 2 + length
        # Supprimer APP1 (EXIF) et APP2–APP15 (métadonnées)
        if marker[1] in range(0xE1, 0xF0):
            pass  # Ignorer le segment
        else:
            result.extend(data[i:seg_end])
        i = seg_end
    return bytes(result)


def clean_jpeg_pillow(path: Path, out_path: Path):
    """Supprime EXIF via Pillow (reconstruction de l'image sans métadonnées)."""
    try:
        from PIL import Image
        img = Image.open(path)
        # Convertir pour supprimer les métadonnées
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=95, exif=b"")
        out_path.write_bytes(buf.getvalue())
        return True, "Pillow"
    except ImportError:
        return False, "pillow_unavailable"
    except Exception as e:
        return False, str(e)


def strip_jpeg(path: Path, out_path: Path, dry_run: bool) -> dict:
    result = {"file": str(path), "type": "jpeg", "status": "ok", "method": ""}
    if dry_run:
        result["status"] = "dry-run"
        return result
    ok, method = clean_jpeg_pillow(path, out_path)
    if ok:
        result["method"] = method
    else:
        # Fallback: méthode manuelle
        data = path.read_bytes()
        cleaned = clean_jpeg_exif(data)
        out_path.write_bytes(cleaned)
        result["method"] = "manual_exif_strip"
        original_size = len(data)
        cleaned_size  = len(cleaned)
        result["bytes_removed"] = original_size - cleaned_size
    return result

# ─── PNG : suppression chunks texte ─────────────────────────────────────────

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
META_CHUNKS   = {b"tEXt", b"iTXt", b"zTXt", b"eXIf"}


def strip_png(path: Path, out_path: Path, dry_run: bool) -> dict:
    result = {"file": str(path), "type": "png", "status": "ok", "chunks_removed": 0}
    if dry_run:
        result["status"] = "dry-run"
        return result
    data = path.read_bytes()
    if not data.startswith(PNG_SIGNATURE):
        result["status"] = "not_png"
        return result

    output = bytearray(PNG_SIGNATURE)
    i = 8
    removed = 0
    while i < len(data) - 12:
        length = struct.unpack(">I", data[i:i+4])[0]
        chunk_type = data[i+4:i+8]
        chunk_data = data[i+8:i+8+length]
        crc        = data[i+8+length:i+12+length]
        if chunk_type in META_CHUNKS:
            removed += 1
        else:
            output.extend(data[i:i+12+length])
        i += 12 + length

    out_path.write_bytes(bytes(output))
    result["chunks_removed"] = removed
    return result

# ─── PDF : nettoyage des métadonnées ─────────────────────────────────────────

import re as _re

PDF_META_PATTERN = _re.compile(
    r"(/(?:Title|Author|Subject|Keywords|Creator|Producer|CreationDate|ModDate))"
    r"\s*\(([^)]*)\)"
)


def strip_pdf(path: Path, out_path: Path, dry_run: bool) -> dict:
    result = {"file": str(path), "type": "pdf", "status": "ok", "fields_cleared": 0}
    if dry_run:
        result["status"] = "dry-run"
        return result
    try:
        content = path.read_bytes()
        text    = content.decode("latin-1", errors="replace")
        count   = [0]

        def replace_meta(m):
            count[0] += 1
            return f"{m.group(1)} ()"

        cleaned = PDF_META_PATTERN.sub(replace_meta, text)
        out_path.write_bytes(cleaned.encode("latin-1", errors="replace"))
        result["fields_cleared"] = count[0]
    except Exception as e:
        result["status"] = "error"
        result["error"]  = str(e)
    return result

# ─── Office (docx/xlsx/pptx) ─────────────────────────────────────────────────

CORE_XML_CLEAN = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:dcterms="http://purl.org/dc/terms/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
</cp:coreProperties>
"""

APP_XML_CLEAN = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Office</Application>
</Properties>
"""


def strip_office(path: Path, out_path: Path, dry_run: bool) -> dict:
    result = {"file": str(path), "type": "office", "status": "ok", "xmls_cleared": 0}
    if dry_run:
        result["status"] = "dry-run"
        return result
    try:
        buf = io.BytesIO()
        with zipfile.ZipFile(path, "r") as zin, \
             zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == "docProps/core.xml":
                    data = CORE_XML_CLEAN.encode("utf-8")
                    result["xmls_cleared"] += 1
                elif item.filename == "docProps/app.xml":
                    data = APP_XML_CLEAN.encode("utf-8")
                    result["xmls_cleared"] += 1
                zout.writestr(item, data)
        out_path.write_bytes(buf.getvalue())
    except zipfile.BadZipFile:
        result["status"] = "not_office"
    except Exception as e:
        result["status"] = "error"
        result["error"]  = str(e)
    return result

# ─── Dispatch ────────────────────────────────────────────────────────────────

def _output_path(src: Path, output_arg: str | None, in_place: bool) -> Path:
    if in_place:
        return src
    if output_arg:
        out = Path(output_arg)
        if out.is_dir():
            return out / src.name
        return out
    # Suffixe _clean
    return src.with_stem(src.stem + "_clean")


def clean_file(path: Path, out_path: Path, dry_run: bool) -> dict | None:
    ext = path.suffix.lower()
    if ext in (".jpg", ".jpeg"):
        return strip_jpeg(path, out_path, dry_run)
    elif ext == ".png":
        return strip_png(path, out_path, dry_run)
    elif ext == ".pdf":
        return strip_pdf(path, out_path, dry_run)
    elif ext in (".docx", ".xlsx", ".pptx", ".odt", ".ods"):
        return strip_office(path, out_path, dry_run)
    return None

# ─── Main ────────────────────────────────────────────────────────────────────

DEFAULT_TYPES = {".jpg", ".jpeg", ".png", ".pdf", ".docx", ".xlsx", ".pptx"}


def main():
    parser = argparse.ArgumentParser(
        description="Suppression de métadonnées sensibles (EXIF, PDF, Office)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="Fichier unique")
    src.add_argument("--dir",  help="Répertoire à traiter")
    parser.add_argument("--recursive", action="store_true")
    parser.add_argument("--output",    help="Fichier ou dossier de sortie")
    parser.add_argument("--types",     default="",
                        help="Extensions (ex: jpg,pdf,docx)")
    parser.add_argument("--in-place",  action="store_true",
                        help="Modifier en place (irréversible)")
    parser.add_argument("--dry-run",   action="store_true")
    args = parser.parse_args()

    exts = (
        {f".{e.strip().lstrip('.')}" for e in args.types.split(",") if e.strip()}
        or DEFAULT_TYPES
    )

    print(cyan("=" * 65))
    print(cyan("  Metadata Cleaner — Suppression de métadonnées"))
    if args.dry_run:
        print(yellow("  MODE DRY-RUN — aucun fichier modifié"))
    if args.in_place:
        print(yellow("  MODE IN-PLACE — fichiers originaux écrasés"))
    print(cyan("=" * 65 + "\n"))

    files = []
    if args.file:
        files = [Path(args.file)]
    else:
        root    = Path(args.dir)
        pattern = "**/*" if args.recursive else "*"
        files   = [p for p in root.glob(pattern)
                   if p.is_file() and p.suffix.lower() in exts]
    print(f"  {len(files)} fichier(s) à traiter\n")

    results = []
    for src_path in files:
        out_path = _output_path(src_path, args.output, args.in_place)
        res = clean_file(src_path, out_path, args.dry_run)
        if res is None:
            continue
        results.append(res)
        status = res.get("status", "?")
        if status in ("ok",):
            print(f"  {green('✓')} {src_path.name} → {out_path.name}")
        elif status == "dry-run":
            print(f"  {yellow('[DRY]')} {src_path.name}")
        else:
            print(f"  {red('✗')} {src_path.name} : {status}")

    ok_count  = sum(1 for r in results if r.get("status") == "ok")
    err_count = sum(1 for r in results if r.get("status") not in ("ok", "dry-run"))
    print(f"\n{cyan('─'*65)}")
    print(f"  Nettoyé : {green(str(ok_count))}  |  Erreurs : {red(str(err_count)) if err_count else '0'}")
    print(cyan("─" * 65))


if __name__ == "__main__":
    main()
