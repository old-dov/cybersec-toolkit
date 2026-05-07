# 10 — Web Security

> ⚠️ **Avertissement légal** : Ces outils sont réservés aux tests sur des applications web que vous êtes **autorisé à tester** (bug bounty, audit contractuel, environnement de développement, CTF). L'utilisation non autorisée est illégale.

Scripts de détection de vulnérabilités web courantes : injections, XSS, découverte de ressources cachées.

---

## Scripts

### `sqli_detector.py` — Détection d'injection SQL

Teste des paramètres d'URL ou de formulaire pour détecter des injections SQL via trois techniques :
- **Error-based** : messages d'erreur SQL dans la réponse
- **Boolean-based** : différences de réponse entre conditions vraie/fausse
- **Time-based** : délai de réponse anormal (`SLEEP`, `WAITFOR`, `pg_sleep`)

**Usage :**
```bash
# URL avec marqueur de paramètre
python sqli_detector.py --url "https://site.com/item?id=INJECT"

# Méthode POST
python sqli_detector.py --url "https://site.com/login" --method POST --data "user=admin&pass=INJECT"

# Tous les types + sortie JSON
python sqli_detector.py --url "https://site.com/search?q=INJECT" --type all -o sqli.json
```

---

### `xss_scanner.py` — Détection de XSS réfléchi

Injecte des payloads XSS dans les paramètres d'URL et champs de formulaire, et détecte si le payload est reflété non échappé dans la réponse.

**Usage :**
```bash
python xss_scanner.py --url "https://site.com/search?q=TEST"
python xss_scanner.py --url "https://site.com/search?q=TEST" --forms
python xss_scanner.py --url "https://site.com/" --forms --deep -o xss.json
```

---

### `dir_bruteforcer.py` — Découverte de répertoires et fichiers cachés

Énumère les ressources web accessibles par force brute sur une wordlist. Détecte les fichiers de configuration, backups, panneaux d'administration, etc.

**Usage :**
```bash
python dir_bruteforcer.py --url https://site.com
python dir_bruteforcer.py --url https://site.com --wordlist wordlist.txt
python dir_bruteforcer.py --url https://site.com --extensions php,html,bak,sql -T 20
python dir_bruteforcer.py --url https://site.com -o found.json
```

---

## Pipeline recommandé

```
03_Vulnerability_Assessment/http_headers_analyzer.py  (audit général)
                    ↓
10_Web_Security/dir_bruteforcer.py       (surface d'attaque)
10_Web_Security/sqli_detector.py         (paramètres trouvés)
10_Web_Security/xss_scanner.py           (formulaires trouvés)
                    ↓
06_Reporting/report_generator.py         (rapport final)
```
