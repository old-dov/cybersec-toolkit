# 07 — Remediation (Scripts de patch)

Scripts de remédiation automatisés pour corriger les vulnérabilités détectées par les outils des dossiers précédents. Ils forment le **pipeline complet** : Scanner → Détecter → Patcher.

## Pipeline recommandé

```
01_Reconnaissance    →  découvrir les ports / services
03_Vulnerability     →  identifier les failles (SSL, headers, redirects)
04_Log_Analysis      →  détecter les attaques en cours
         ↓
07_Remediation       →  générer et appliquer les correctifs
```

## Scripts

| Script | Remédie à | Dépendances |
|--------|-----------|-------------|
| `harden_http_headers.py` | En-têtes HTTP manquants (03_Vulnerability) | stdlib |
| `ssl_hardening_config.py` | Configuration SSL/TLS faible (03_Vulnerability) | stdlib |
| `firewall_blocker.py` | IPs malveillantes (04_Log_Analysis, brute force) | stdlib |
| `system_hardener.py` | Durcissement système général multi-OS | stdlib |

## Utilisation rapide

```bash
# Générer la config nginx pour sécuriser les en-têtes HTTP
python harden_http_headers.py --server nginx --output /etc/nginx/snippets/security-headers.conf

# Générer la config TLS optimale
python ssl_hardening_config.py --server nginx --domain exemple.com --output tls.conf

# Bloquer des IPs depuis un JSON de brute force
python firewall_blocker.py --json ../04_Log_Analysis/brute_force.json --action block

# Audit + durcissement système
python system_hardener.py --audit
python system_hardener.py --apply --dry-run
```

## ⚠️ Important

- Les scripts qui modifient le système nécessitent des **droits administrateur** (root/sudo/Administrator)
- Utilisez toujours `--dry-run` pour **prévisualiser** les changements avant de les appliquer
- **Sauvegardez** votre configuration avant tout changement
