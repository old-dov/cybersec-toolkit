# 04 — Log Analysis

Scripts d'analyse de journaux systèmes pour détecter les comportements suspects.

| Script | Description | Dépendances |
|--------|-------------|-------------|
| `log_parser.py` | Parseur de logs multi-format avec détection de patterns suspects | stdlib |
| `failed_login_detector.py` | Détection de tentatives de force brute dans les logs d'authentification | stdlib |

## Utilisation rapide

```bash
# Linux / macOS
python log_parser.py -f /var/log/syslog --format syslog
python failed_login_detector.py -f /var/log/auth.log --threshold 5

# Windows
python log_parser.py -f C:\Windows\System32\winevt\Logs\Security.evtx --format windows
python failed_login_detector.py -f auth.log --threshold 10 -o rapport.txt
```

## Logs supportés

- **syslog** : `/var/log/syslog`, `/var/log/messages`
- **auth** : `/var/log/auth.log`, `/var/log/secure`
- **apache** : Combined Log Format
- **nginx** : Combined Log Format
- **windows** : Fichiers `.evtx` (nécessite `python-evtx`)
- **custom** : Pattern regex personnalisé
