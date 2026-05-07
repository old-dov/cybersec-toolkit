# 01 — Reconnaissance

Scripts de collecte d'informations (phase OSINT / reconnaissance passive et active).

| Script | Description | Dépendances |
|--------|-------------|-------------|
| `port_scanner.py` | Scan TCP multi-thread avec détection de bannières | stdlib |
| `subdomain_enum.py` | Énumération de sous-domaines par dictionnaire | `dnspython` |
| `whois_lookup.py` | Requête WHOIS sur domaine ou adresse IP | `python-whois` |

## Utilisation rapide

```bash
python port_scanner.py -t 192.168.1.1 -p 1-1024 -T 200
python subdomain_enum.py -d exemple.com -w wordlist.txt
python whois_lookup.py -t exemple.com
```

## Éthique & légalité

Utilisez ces outils uniquement sur des cibles pour lesquelles vous avez une **autorisation écrite**. Le scan de ports non autorisé est illégal dans de nombreux pays.
