# Scripts de Cybersécurité

Collection de scripts d'automatisation pour la cybersécurité, compatibles **Windows**, **macOS** et **Linux**.

> ⚠️ **Avertissement légal** : Ces scripts sont destinés exclusivement à des audits de sécurité **autorisés**. Toute utilisation non autorisée sur des systèmes tiers est illégale. L'auteur décline toute responsabilité en cas d'utilisation abusive.

---

## Démarrage rapide

```bash
pip install -r requirements.txt
python cybersec_launcher.py          # Menu interactif menace → remède
python cybersec_launcher.py --list   # Catalogue complet
```

## Prérequis

- **Python 3.8+** — https://www.python.org/downloads/
- Dépendances : `pip install -r requirements.txt`
- Pillow (optionnel, EXIF images) : `pip install Pillow`

---

## Structure

```
[Scripts (cybersec)]/
│
├── cybersec_launcher.py            # ★ Lanceur interactif (menace → remède)
│
├── 01_Reconnaissance/              # Collecte d'informations sur une cible
│   ├── port_scanner.py             # Scan de ports TCP multi-thread
│   ├── subdomain_enum.py           # Énumération de sous-domaines
│   └── whois_lookup.py             # Recherche WHOIS domaine/IP
│
├── 02_Network_Analysis/            # Analyse réseau et services
│   ├── network_mapper.py           # Cartographie des hôtes (ARP/ICMP)
│   ├── dns_analyzer.py             # Analyse complète DNS (MX, SPF, DKIM…)
│   └── banner_grabber.py           # Récupération de bannières de services
│
├── 03_Vulnerability_Assessment/    # Évaluation de vulnérabilités
│   ├── ssl_checker.py              # Audit SSL/TLS (protocoles, certificats)
│   ├── http_headers_analyzer.py    # Vérification des en-têtes HTTP de sécurité
│   └── open_redirect_checker.py    # Détection de redirections ouvertes
│
├── 04_Log_Analysis/                # Analyse de journaux systèmes
│   ├── log_parser.py               # Parseur de logs multi-format
│   └── failed_login_detector.py    # Détection de tentatives de brute-force
│
├── 05_Cryptography/                # Outils cryptographiques
│   ├── file_encryptor.py           # Chiffrement/déchiffrement de fichiers (AES-256-GCM)
│   └── hash_generator.py           # Génération et vérification de hachages
│
├── 06_Reporting/                   # Génération de rapports
│   └── report_generator.py         # Rapport HTML/JSON à partir de scans
│
├── 07_Remediation/                 # Correctifs et durcissement
│   ├── harden_http_headers.py      # Config en-têtes HTTP sécurisés (nginx/apache/IIS)
│   ├── ssl_hardening_config.py     # Config TLS durcie (nginx/apache/haproxy)
│   ├── firewall_blocker.py         # Blocage IP multi-OS (iptables/nftables/pf/Windows)
│   ├── system_hardener.py          # Audit et durcissement système (SSH, sysctl, comptes)
│   ├── patch_manager.py            # Gestion des mises à jour de sécurité (apt/dnf/brew/winget)
│   ├── web_vuln_patcher.py         # Génération de règles WAF (ModSecurity/nginx/apache)
│   └── metadata_cleaner.py         # Suppression métadonnées (EXIF, PDF, Office)
│
├── 08_Exploitation/                # Tests d'exploitation (pentest autorisé)
│   ├── exploit_suggester.py        # Suggestion CVEs via NVD API pour services détectés
│   └── payload_encoder.py          # Encodage multi-format (base64, hex, unicode, ROT13…)
│
├── 09_Post_Exploitation/           # Post-exploitation / Élévation de privilèges
│   ├── privesc_checker.py          # Audit local des vecteurs de privesc (SUID, sudo, cron)
│   └── env_secrets_scanner.py      # Détection de secrets exposés (clés API, tokens)
│
├── 10_Web_Security/                # Sécurité applicative web
│   ├── sqli_detector.py            # Détection SQLi (error/boolean/time-based)
│   ├── xss_scanner.py              # Scanner XSS réfléchi (params + formulaires)
│   └── dir_bruteforcer.py          # Découverte de répertoires/fichiers cachés
│
├── 11_OSINT/                       # Renseignement en sources ouvertes
│   ├── email_harvester.py          # Collecte d'emails publics par crawl
│   ├── username_checker.py         # Vérification pseudonyme sur ~35 plateformes
│   └── metadata_extractor.py       # Extraction métadonnées (EXIF GPS, auteur PDF/Office)
│
└── 12_Forensic_IR/                 # Investigation numérique / Réponse aux incidents
    ├── ioc_scanner.py              # Scanner d'IOC (hachages, IPs, domaines malveillants)
    ├── timeline_builder.py         # Timeline forensique des fichiers (mtime/ctime/atime)
    └── artifact_collector.py       # Collecte d'artefacts système (logs, cron, réseau…)
```

---

## Organisation Menace → Remède

| Menace détectée | Outil d'analyse | Remède |
|---|---|---|
| Ports/services exposés | `port_scanner`, `banner_grabber` | `firewall_blocker`, `system_hardener` |
| Mauvaise config TLS | `ssl_checker` | `ssl_hardening_config` |
| En-têtes HTTP manquants | `http_headers_analyzer` | `harden_http_headers`, `web_vuln_patcher` |
| Brute-force / accès anormal | `failed_login_detector` | `firewall_blocker`, `system_hardener` |
| CVE sur services actifs | `exploit_suggester` | `patch_manager` |
| Injection SQL / XSS | `sqli_detector`, `xss_scanner` | `web_vuln_patcher` |
| Privesc local | `privesc_checker` | `system_hardener`, `patch_manager` |
| Secrets exposés | `env_secrets_scanner` | rotation manuelle + `system_hardener` |
| Métadonnées sensibles | `metadata_extractor` | `metadata_cleaner` |
| Incident en cours (IOC) | `ioc_scanner`, `artifact_collector` | `firewall_blocker`, `report_generator` |

---

## Pipelines recommandés

```bash
# Audit web complet
python cybersec_launcher.py --run ssl_checker --args "--host example.com"
python cybersec_launcher.py --run sqli_detector --args "--url 'https://example.com?id=INJECT'"
python cybersec_launcher.py --run web_vuln_patcher --args "--harden-all --server nginx -o waf.conf"

# Réponse à incident
python cybersec_launcher.py --run artifact_collector --args "--categories all -o artifacts/"
python cybersec_launcher.py --run ioc_scanner --args "--ioc-file iocs.json --scan-path . --check-network"
python cybersec_launcher.py --run firewall_blocker --args "--json ir_report.json --apply"

# Durcissement système
python cybersec_launcher.py --run system_hardener --args "--audit"
python cybersec_launcher.py --run patch_manager --args "--audit --apply"
```

## Installation rapide

```bash
git clone https://github.com/old-dov/cybersec-toolkit.git
cd cybersec-toolkit
pip install -r requirements.txt
pip install Pillow          # optionnel, pour l'extraction EXIF
python cybersec_launcher.py
```
