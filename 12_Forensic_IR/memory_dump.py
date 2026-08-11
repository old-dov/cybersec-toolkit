#!/usr/bin/env python3
"""
=============================================================================
 memory_dump.py — Dump mémoire d'un processus (forensique)
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / Linux (Python 3.8+) — macOS non supporté (restrictions SIP)
 Dépend.  : aucune (stdlib uniquement, ctypes)

 DESCRIPTION
 -----------
 Capture la mémoire d'un processus en cours d'exécution pour analyse
 forensique différée (recherche de secrets en clair, reconstruction
 d'artefacts volatils, réponse à incident sur un process suspect...).

   Windows → MiniDumpWriteDump (dbghelp.dll) : format .dmp standard,
             lisible avec WinDbg, Volatility3 ou l'Analyseur de vidage
             mémoire de Windows.
   Linux   → lecture de /proc/<pid>/maps + /proc/<pid>/mem : dump brut des
             régions lisibles, accompagné d'un fichier .maps (sidecar) qui
             conserve les plages d'adresses d'origine pour la reconstruction.

 Nécessite des privilèges administrateur/root pour dumper un processus
 n'appartenant pas à l'utilisateur courant.

 USAGE
 -----
   python memory_dump.py --target <PID_ou_nom_processus> [options]

 EXEMPLES
 --------
   python memory_dump.py --target 4821
   python memory_dump.py --target notepad.exe
   python memory_dump.py --target sshd -o /tmp/ir/sshd.raw

 OPTIONS
 -------
   -t, --target   PID (numérique) ou nom de processus (premier trouvé)
   -o, --output   Fichier de sortie (défaut: memdump_<pid>_<horodatage>.dmp/.raw)

 AVERTISSEMENT LÉGAL
 --------------------
 La mémoire d'un processus peut contenir des secrets en clair (mots de passe,
 clés privées, tokens de session). N'utilisez cet outil que sur des systèmes
 pour lesquels vous disposez d'une autorisation explicite, dans le cadre
 d'une investigation forensique légitime ou d'un test d'intrusion autorisé.
 Traitez tout fichier produit comme une donnée sensible.
=============================================================================
"""

import argparse
import ctypes
import json
import platform
import shutil
import subprocess
import sys
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

OS = platform.system()

# ─── Résolution PID / nom de processus ─────────────────────────────────────

def resolve_pid(target: str) -> tuple[int | None, str | None, str]:
    """Retourne (pid, nom_processus, message_erreur). target est soit un PID
    numérique, soit un nom de processus (le premier trouvé est utilisé)."""
    if target.isdigit():
        pid = int(target)
        name = _process_name(pid)
        if name is None:
            return None, None, f"Aucun processus actif avec le PID {pid}."
        return pid, name, ""

    if OS == "Windows":
        try:
            out = subprocess.check_output(
                ["tasklist", "/FI", f"IMAGENAME eq {target}", "/FO", "CSV", "/NH"],
                text=True, stderr=subprocess.DEVNULL, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception as e:
            return None, None, f"tasklist a échoué : {e}"
        line = out.strip().splitlines()[0] if out.strip() else ""
        # Une vraie ligne CSV tasklist commence toujours par un guillemet ;
        # le message "aucune tâche trouvée" est du texte libre localisé
        # (anglais "INFO: ...", français "Information : ..."...) — ne pas
        # dépendre de la langue pour le détecter.
        if not line.startswith('"'):
            return None, None, f"Aucun processus nommé « {target} » trouvé."
        fields = [f.strip('"') for f in line.split('","')]
        if len(fields) < 2:
            return None, None, f"Sortie tasklist inattendue pour « {target} »."
        return int(fields[1]), fields[0], ""

    # Linux — parcourt /proc/<pid>/comm
    for proc_dir in Path("/proc").glob("[0-9]*"):
        comm_path = proc_dir / "comm"
        try:
            comm = comm_path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if comm == target or comm == target[:15]:  # comm est tronqué à 15 caractères par le noyau
            return int(proc_dir.name), comm, ""
    return None, None, f"Aucun processus nommé « {target} » trouvé."


def _process_name(pid: int) -> str | None:
    if OS == "Windows":
        try:
            out = subprocess.check_output(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                text=True, stderr=subprocess.DEVNULL, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:
            return None
        line = out.strip().splitlines()[0] if out.strip() else ""
        if not line.startswith('"'):
            return None
        return line.split('","')[0].strip('"')

    comm_path = Path(f"/proc/{pid}/comm")
    try:
        return comm_path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None

# ─── Dump Windows (MiniDumpWriteDump) ──────────────────────────────────────

def dump_windows(pid: int, out_path: Path) -> tuple[bool, str]:
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)

    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    dbghelp.MiniDumpWriteDump.restype = wintypes.BOOL
    dbghelp.MiniDumpWriteDump.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.HANDLE, ctypes.c_int,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]

    PROCESS_ALL_ACCESS = 0x1F0FFF
    GENERIC_WRITE = 0x40000000
    CREATE_ALWAYS = 2
    FILE_ATTRIBUTE_NORMAL = 0x80
    MINI_DUMP_WITH_FULL_MEMORY = 2
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if h_process is None:
        return False, (
            f"OpenProcess a échoué (code {ctypes.get_last_error()}) — "
            "privilèges insuffisants ? Relancez en administrateur."
        )
    try:
        h_file = kernel32.CreateFileW(
            str(out_path), GENERIC_WRITE, 0, None, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None
        )
        if h_file is None or h_file == INVALID_HANDLE_VALUE:
            return False, f"Création du fichier de sortie échouée (code {ctypes.get_last_error()})."
        try:
            ok = dbghelp.MiniDumpWriteDump(
                h_process, pid, h_file, MINI_DUMP_WITH_FULL_MEMORY, None, None, None
            )
            if not ok:
                return False, f"MiniDumpWriteDump a échoué (code {ctypes.get_last_error()})."
            return True, ""
        finally:
            kernel32.CloseHandle(h_file)
    finally:
        kernel32.CloseHandle(h_process)

# ─── Dump Linux (/proc/<pid>/mem) ──────────────────────────────────────────

def dump_linux(pid: int, out_path: Path) -> tuple[bool, str]:
    maps_path = Path(f"/proc/{pid}/maps")
    mem_path = Path(f"/proc/{pid}/mem")

    try:
        regions = []
        for line in maps_path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) < 2 or "r" not in parts[1]:
                continue
            start_s, end_s = parts[0].split("-")
            regions.append((int(start_s, 16), int(end_s, 16)))
    except OSError as e:
        return False, f"Lecture de {maps_path} impossible : {e} (processus introuvable ou permissions insuffisantes)."

    skipped = 0
    dumped = 0
    try:
        with open(mem_path, "rb") as mem, open(out_path, "wb") as out:
            for start, end in regions:
                try:
                    mem.seek(start)
                    out.write(mem.read(end - start))
                    dumped += 1
                except OSError:
                    # Certaines régions (ex. [vvar]) sont listées lisibles mais
                    # refusent la lecture directe — on les ignore et on continue.
                    skipped += 1
    except OSError as e:
        return False, f"Lecture de {mem_path} impossible : {e} (root requis pour un processus d'un autre utilisateur ?)."

    shutil.copy(maps_path, str(out_path) + ".maps")
    note = f"{dumped}/{len(regions)} région(s) mémoire dumpée(s)"
    if skipped:
        note += f", {skipped} ignorée(s) (non lisibles malgré les permissions déclarées)"
    return True, note

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Dump mémoire d'un processus à des fins forensiques",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target", required=True,
                         help="PID (numérique) ou nom de processus")
    parser.add_argument("-o", "--output", help="Fichier de sortie")
    args = parser.parse_args()

    print(cyan("=" * 65))
    print(cyan("  Memory Dump — Forensic IR"))
    print(cyan(f"  OS     : {OS} {platform.release()}"))
    print(cyan("=" * 65))

    if OS == "Darwin":
        print(red(
            "\n[ERREUR] macOS n'est pas supporté : l'accès à la mémoire d'un "
            "processus tiers y est restreint par SIP (System Integrity "
            "Protection) et nécessite des entitlements/outils dédiés "
            "(ex. osxpmem) hors du périmètre stdlib de ce script."
        ))
        sys.exit(1)

    pid, proc_name, err = resolve_pid(args.target)
    if pid is None:
        print(red(f"\n[ERREUR] {err}"))
        sys.exit(1)

    print(f"\n[*] Cible : {proc_name} (PID {pid})")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = ".dmp" if OS == "Windows" else ".raw"
    out_path = Path(args.output) if args.output else Path(f"memdump_{pid}_{timestamp}{ext}")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Sortie : {out_path.resolve()}")
    print("[*] Dump en cours (peut prendre du temps selon la taille du processus)...")

    dump_fn = dump_windows if OS == "Windows" else dump_linux
    ok, message = dump_fn(pid, out_path)

    if not ok:
        print(red(f"\n[ERREUR] {message}"))
        sys.exit(1)

    size = out_path.stat().st_size if out_path.exists() else 0
    print(green(f"\n[+] Dump terminé : {out_path.resolve()} ({size:,} octets)"))
    if message:
        print(f"    {message}")

    meta = {
        "target": args.target, "pid": pid, "process_name": proc_name,
        "os": f"{OS} {platform.release()}", "output_path": str(out_path.resolve()),
        "size_bytes": size, "timestamp": datetime.now().isoformat(), "note": message,
    }
    meta_path = Path(str(out_path) + ".meta.json")
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"    Métadonnées : {meta_path.resolve()}")

    print(cyan("\n" + "─" * 65))
    print(yellow("  Rappel : ce fichier peut contenir des secrets en clair — "
                 "traitez-le comme une donnée sensible."))
    print(cyan("─" * 65))


if __name__ == "__main__":
    main()
