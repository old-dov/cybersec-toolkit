#!/usr/bin/env python3
"""
=============================================================================
 metadata_extractor.py — Extraction de métadonnées de fichiers
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : Pillow>=10.3.0 (optionnel, pour EXIF images)

 DESCRIPTION
 -----------
 Extrait les métadonnées de différents types de fichiers :

   Images JPEG/TIFF  → EXIF (auteur, appareil, GPS, logiciel, dates)
   Images PNG        → Chunks texte (Auteur, Copyright, Description)
   PDF               → En-têtes de métadonnées (Auteur, Créateur, Sujet)
   Fichiers Office   → Balises XML [Content_Types].xml, app.xml, core.xml
   Tout fichier      → Taille, dates, permissions, MIME type

 USAGE
 -----
   python metadata_extractor.py [options]

 EXEMPLES
 --------
   python metadata_extractor.py --file photo.jpg
   python metadata_extractor.py --file document.pdf
   python metadata_extractor.py --dir /path/to/files
   python metadata_extractor.py --dir . --recursive -o meta.json

 OPTIONS
 -------
   --file      Fichier unique à analyser
   --dir       Répertoire à analyser
   --recursive Analyser les sous-dossiers
   --types     Extensions à cibler (défaut: jpg,jpeg,png,pdf,docx,xlsx,pptx)
   -o, --output Fichier JSON de sortie

 AVERTISSEMENT LÉGAL
 -------------------
 Cet outil est destiné à l'analyse légale de fichiers que vous possédez
 ou êtes autorisé à analyser.
=============================================================================
"""

import argparse
import io
import json
import mimetypes
import os
import re
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
def cyan(t):   return f"{Fore.CYAN}{t}{Style.RESET_ALL}" if COLOR else t
def bold(t):   return f"{Style.BRIGHT}{t}{Style.RESET_ALL}" if COLOR else t
def dim(t):    return f"{Style.DIM}{t}{Style.RESET_ALL}" if COLOR else t

# ─── Extraction EXIF (images) ────────────────────────────────────────────────

EXIF_TAGS_OF_INTEREST = {
    0x010f: "Make",
    0x0110: "Model",
    0x0131: "Software",
    0x013b: "Artist",
    0x8298: "Copyright",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x0132: "DateTime",
    0x013e: "WhitePoint",
    0x8827: "ISOSpeedRatings",
    0x9286: "UserComment",
    0xa420: "ImageUniqueID",
    0xa430: "CameraOwnerName",
    0xa431: "BodySerialNumber",
    0xa432: "LensSpecification",
    0xa433: "LensMake",
    0xa434: "LensModel",
    # GPS
    0x8825: "GPSInfo",
}

GPS_TAGS = {
    1: "GPSLatitudeRef", 2: "GPSLatitude",
    3: "GPSLongitudeRef", 4: "GPSLongitude",
    5: "GPSAltitudeRef", 6: "GPSAltitude",
    7: "GPSTimeStamp",
    29: "GPSDateStamp",
}


def _ifd_rational(data: bytes, offset: int, little: bool) -> float:
    fmt = "<" if little else ">"
    num = struct.unpack_from(fmt + "I", data, offset)[0]
    den = struct.unpack_from(fmt + "I", data, offset + 4)[0]
    return num / den if den else 0.0


def _dms_to_decimal(dms: list, ref: str) -> float | None:
    if not dms or len(dms) < 3:
        return None
    d = dms[0]
    m = dms[1] / 60.0
    s = dms[2] / 3600.0
    val = d + m + s
    if ref in ("S", "W"):
        val = -val
    return round(val, 7)


def extract_exif_pillow(path: Path) -> dict:
    """Extraction EXIF via Pillow (si disponible)."""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
        img = Image.open(path)
        raw_exif = img._getexif()
        if not raw_exif:
            return {}
        meta = {}
        gps_raw = {}
        for tag_id, value in raw_exif.items():
            tag_name = TAGS.get(tag_id, str(tag_id))
            if tag_id == 0x8825 and isinstance(value, dict):
                gps_raw = value
            elif tag_name in {v for v in EXIF_TAGS_OF_INTEREST.values()}:
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="replace").strip()
                    except Exception:
                        value = value.hex()
                meta[tag_name] = str(value)[:200]
        # GPS
        if gps_raw:
            lat_dms  = [float(x) for x in gps_raw.get(2, [])]
            lat_ref  = gps_raw.get(1, "")
            lon_dms  = [float(x) for x in gps_raw.get(4, [])]
            lon_ref  = gps_raw.get(3, "")
            lat = _dms_to_decimal(lat_dms, lat_ref)
            lon = _dms_to_decimal(lon_dms, lon_ref)
            if lat and lon:
                meta["GPS_Latitude"]  = lat
                meta["GPS_Longitude"] = lon
                meta["GPS_Maps_URL"]  = f"https://maps.google.com/?q={lat},{lon}"
        return meta
    except ImportError:
        return {"_note": "Installez Pillow pour l'extraction EXIF : pip install Pillow"}
    except Exception as e:
        return {"_error": str(e)}


def extract_png_text(path: Path) -> dict:
    """Extraction des chunks tEXt/iTXt d'un PNG sans dépendance externe."""
    meta = {}
    try:
        data = path.read_bytes()
        if data[:8] != b"\x89PNG\r\n\x1a\n":
            return meta
        i = 8
        while i < len(data) - 12:
            length = struct.unpack(">I", data[i:i+4])[0]
            chunk  = data[i+4:i+8]
            body   = data[i+8:i+8+length]
            if chunk in (b"tEXt", b"iTXt"):
                try:
                    sep = body.index(b"\x00")
                    key = body[:sep].decode("latin-1")
                    val = body[sep+1:].decode("utf-8", errors="replace").strip("\x00")
                    if key and val:
                        meta[key] = val[:200]
                except Exception:
                    pass
            i += 12 + length
    except Exception:
        pass
    return meta

# ─── Extraction PDF ───────────────────────────────────────────────────────────

PDF_META_KEYS = [
    "/Title", "/Author", "/Subject", "/Keywords",
    "/Creator", "/Producer", "/CreationDate", "/ModDate",
]

def extract_pdf_meta(path: Path) -> dict:
    meta = {}
    try:
        content = path.read_bytes()
        text = content[:32768].decode("latin-1", errors="replace")
        # Rechercher le bloc /Info ou les balises directes
        for key in PDF_META_KEYS:
            pattern = re.compile(re.escape(key) + r"\s*\(([^)]{1,300})\)")
            m = pattern.search(text)
            if m:
                clean_key = key.lstrip("/")
                meta[clean_key] = m.group(1).strip()
        # Chercher aussi dans le XMP
        xmp_match = re.search(r"<x:xmpmeta.*?</x:xmpmeta>", text, re.DOTALL)
        if xmp_match:
            xmp = xmp_match.group(0)
            for tag in ["dc:creator", "dc:title", "dc:description", "xmp:CreateDate"]:
                m2 = re.search(rf"<{re.escape(tag)}[^>]*>([^<]+)</{re.escape(tag)}>", xmp)
                if m2:
                    meta[tag] = m2.group(1).strip()
    except Exception as e:
        meta["_error"] = str(e)
    return meta

# ─── Extraction Office (docx, xlsx, pptx) ────────────────────────────────────

def extract_office_meta(path: Path) -> dict:
    meta = {}
    try:
        with zipfile.ZipFile(path, "r") as z:
            names = z.namelist()
            for xml_path in ("docProps/core.xml", "docProps/app.xml"):
                if xml_path not in names:
                    continue
                xml = z.read(xml_path).decode("utf-8", errors="replace")
                # Extraire toutes les balises simples
                for m in re.finditer(r"<(?:[\w:]+:)?([\w]+)>([^<]{1,300})</", xml):
                    key, val = m.group(1), m.group(2).strip()
                    if val and not val.startswith("<"):
                        meta[key] = val
    except zipfile.BadZipFile:
        pass
    except Exception as e:
        meta["_error"] = str(e)
    return meta

# ─── Extraction générale ──────────────────────────────────────────────────────

def file_base_meta(path: Path) -> dict:
    stat = path.stat()
    mime, _ = mimetypes.guess_type(str(path))
    return {
        "filename":  path.name,
        "path":      str(path.resolve()),
        "size_bytes": stat.st_size,
        "size_hr":   _human_size(stat.st_size),
        "mtime":     datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "ctime":     datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "mime":      mime or "unknown",
        "extension": path.suffix.lower(),
    }


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def extract_file(path: Path) -> dict:
    meta = file_base_meta(path)
    ext = path.suffix.lower()
    specific = {}

    if ext in (".jpg", ".jpeg", ".tif", ".tiff"):
        specific = extract_exif_pillow(path)
    elif ext == ".png":
        specific = extract_png_text(path)
        if not specific:
            specific = extract_exif_pillow(path)
    elif ext == ".pdf":
        specific = extract_pdf_meta(path)
    elif ext in (".docx", ".xlsx", ".pptx", ".odt", ".ods"):
        specific = extract_office_meta(path)

    if specific:
        meta["metadata"] = specific
    return meta

# ─── Main ────────────────────────────────────────────────────────────────────

DEFAULT_TYPES = {".jpg", ".jpeg", ".png", ".pdf", ".docx", ".xlsx", ".pptx", ".tiff", ".tif"}

def main():
    parser = argparse.ArgumentParser(
        description="Extraction de métadonnées de fichiers (images, PDF, Office)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="Fichier unique")
    src.add_argument("--dir",  help="Répertoire à analyser")
    parser.add_argument("--recursive", action="store_true")
    parser.add_argument("--types",     default="",
                        help="Extensions ciblées (ex: jpg,pdf,docx)")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()

    exts = {f".{e.strip().lstrip('.')}" for e in args.types.split(",") if e.strip()} or DEFAULT_TYPES

    print(cyan("=" * 65))
    print(cyan("  Metadata Extractor"))
    print(cyan("=" * 65 + "\n"))

    files = []
    if args.file:
        files = [Path(args.file)]
    else:
        root = Path(args.dir)
        pattern = "**/*" if args.recursive else "*"
        files = [p for p in root.glob(pattern)
                 if p.is_file() and p.suffix.lower() in exts]
        print(f"  {len(files)} fichier(s) trouvé(s) dans {root}\n")

    all_results = []
    for f in files:
        if not f.exists():
            print(yellow(f"  [AVERT] Fichier introuvable : {f}"))
            continue
        result = extract_file(f)
        all_results.append(result)
        print(f"  {bold(f.name)}")
        print(f"    Taille : {result['size_hr']}  |  MIME : {result['mime']}")
        print(f"    Modifié: {result['mtime']}")
        if "metadata" in result:
            meta = result["metadata"]
            for k, v in list(meta.items())[:10]:
                if not k.startswith("_"):
                    val_str = str(v)[:80]
                    col = cyan if "GPS" in k or "Author" in k or "Creator" in k else dim
                    print(f"    {col(k):30} {val_str}")
            if len(meta) > 10:
                print(f"    {dim(f'... +{len(meta)-10} autres champs')}")
        print()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "total":     len(all_results),
                "files":     all_results,
            }, f, indent=2, ensure_ascii=False)
        print(green(f"\n[+] Rapport : {args.output}"))


if __name__ == "__main__":
    main()
