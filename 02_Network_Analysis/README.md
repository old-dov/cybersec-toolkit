# 02 — Network Analysis

Scripts d'analyse réseau : cartographie d'hôtes, résolution DNS, récupération de bannières.

| Script | Description | Dépendances |
|--------|-------------|-------------|
| `network_mapper.py` | Découverte d'hôtes actifs sur un réseau | stdlib |
| `dns_analyzer.py` | Analyse complète des enregistrements DNS | `dnspython` |
| `banner_grabber.py` | Récupération de bannières de services TCP | stdlib |

## Utilisation rapide

```bash
python network_mapper.py -n 192.168.1.0/24
python dns_analyzer.py -d exemple.com --all
python banner_grabber.py -t 192.168.1.1 -p 21,22,25,80,443,8080
```

## Éthique & légalité

Le scan réseau doit être effectué **uniquement sur votre propre infrastructure** ou avec une autorisation écrite. Le scan de réseaux tiers sans permission est illégal.
