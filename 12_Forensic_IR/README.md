# 12 — Forensic / Incident Response (IR)

> ⚠️ **Avertissement légal** : Ces outils sont destinés à l'investigation numérique légale et à la réponse aux incidents sur des systèmes que vous êtes autorisé à analyser. Toute investigation sur un système tiers sans autorisation est illégale.

Scripts d'investigation numérique (forensique) et de réponse aux incidents. Conçus pour être **non intrusifs** et **préserver l'intégrité** des preuves numériques.

---

## Principes forensiques respectés

- **Lecture seule** : aucune modification des systèmes analysés
- **Traçabilité** : timestamps et hachages des artefacts collectés
- **Chain of custody** : chaque rapport inclut la date, l'OS et l'utilisateur

---

## Scripts

### `ioc_scanner.py` — Scan d'Indicateurs de Compromission (IOC)

Compare des hachages de fichiers, des adresses IP et des domaines contre une liste d'IOC (threat intel). Compatible avec les formats MISP, OpenIOC et listes simples.

**Usage :**
```bash
# Créer un fichier IOC (format JSON)
# {"hashes": ["md5hash..."], "ips": ["1.2.3.4"], "domains": ["evil.com"]}

python ioc_scanner.py --ioc-file iocs.json --scan-path /var/www
python ioc_scanner.py --ioc-file iocs.json --scan-path . --check-network
python ioc_scanner.py --ioc-file iocs.json --scan-path /home -o ir-report.json
```

---

### `timeline_builder.py` — Construction de timeline forensique

Construit une timeline chronologique des accès/modifications de fichiers pour identifier les activités suspectes pendant une fenêtre temporelle donnée.

**Usage :**
```bash
python timeline_builder.py --path /var/www
python timeline_builder.py --path /home/user --start "2026-01-01" --end "2026-05-07"
python timeline_builder.py --path . --suspicious-only -o timeline.json
```

---

### `artifact_collector.py` — Collecte d'artefacts système

Collecte automatiquement les artefacts forensiques pertinents selon l'OS : logs système, historiques shell, tâches planifiées, connexions réseau actives, processus, artefacts navigateur.

**Usage :**
```bash
python artifact_collector.py                        # Tout collecter
python artifact_collector.py --categories logs,network,processes
python artifact_collector.py -o artifacts/          # Dossier de sortie
```

---

### `memory_dump.py` — Dump mémoire d'un processus

Capture la mémoire d'un processus en cours pour analyse forensique différée (secrets en clair, artefacts volatils). Windows via `MiniDumpWriteDump` (format `.dmp` standard, compatible WinDbg/Volatility3) ; Linux via `/proc/<pid>/mem` (dump brut + `.maps` sidecar). macOS non supporté (restrictions SIP).

**Usage :**
```bash
python memory_dump.py --target 4821                 # par PID
python memory_dump.py --target notepad.exe           # par nom de processus
python memory_dump.py --target sshd -o /tmp/ir/sshd.raw
```

> ⚠️ Le fichier produit peut contenir des secrets en clair (mots de passe, clés, tokens) — à traiter comme une donnée sensible.

---

## Pipeline IR recommandé

```
Incident détecté
      ↓
python artifact_collector.py -o artifacts/    (collecte immédiate)
      ↓
python timeline_builder.py --path /var/www    (timeline de la zone compromise)
      ↓
04_Log_Analysis/log_parser.py                 (analyse des logs)
04_Log_Analysis/failed_login_detector.py      (tentatives de connexion)
      ↓
python ioc_scanner.py --ioc-file iocs.json    (confrontation threat intel)
      ↓
07_Remediation/firewall_blocker.py            (blocage des IPs identifiées)
      ↓
06_Reporting/report_generator.py              (rapport final)
```
