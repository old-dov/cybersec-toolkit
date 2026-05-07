# 06 — Reporting

Scripts de génération de rapports de sécurité à partir des résultats des autres outils.

| Script | Description | Dépendances |
|--------|-------------|-------------|
| `report_generator.py` | Génère un rapport HTML/JSON consolidé | `jinja2` |

## Utilisation rapide

```bash
# Générer un rapport HTML à partir de fichiers JSON exportés par les autres scripts
python report_generator.py \
  --title "Audit XYZ" \
  --target exemple.com \
  --ports resultats_ports.json \
  --ssl resultats_ssl.json \
  --headers resultats_headers.json \
  --output rapport_audit.html
```

## Format de sortie

Le rapport HTML contient :
- Résumé exécutif avec score de sécurité global
- Tableau des ports ouverts
- Analyse SSL/TLS
- En-têtes HTTP
- Recommandations priorisées
