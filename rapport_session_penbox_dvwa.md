# Rapport de session — PenBox / Cible DVWA

**Date** : 2026-08-11
**Contexte** : Débogage d'accès à une cible DVWA de test et correction de trois bugs bloquants dans PenBox (Cybersec Script Suite), suite à une session de développement avec l'homologue VSCode.

---

## 1. Contexte initial

DVWA (Damn Vulnerable Web App), déployée en conteneur Docker sur le VPS, était inaccessible (connexion refusée sur le port exposé). Objectif : rétablir l'accès, sécuriser l'exposition, puis valider les modules PenBox contre cette cible.

---

## 2. Problème 1 — Conteneur DVWA arrêté (code de sortie 128)

### Diagnostic

```bash
sudo docker ps -a | grep -i dvwa
sudo docker logs --tail 50 <nom_conteneur_dvwa>
```

### Cause identifiée

Fichier PID Apache obsolète suite à un arrêt non propre (`Unclean shutdown of previous Apache run`), empêchant Apache de démarrer dans le délai imparti (20s) → le conteneur s'arrêtait en boucle.

### Correctif

Redémarrage simple du conteneur (le fichier PID stale est régénéré au lancement) :

```bash
sudo docker start <nom_conteneur_dvwa>
```

**Statut : résolu.** Le conteneur reste stable après redémarrage.

---

## 3. Sécurisation de l'exposition DVWA (WireGuard-only)

Constat : le port DVWA était exposé sur `0.0.0.0` (accessible depuis tout Internet), avec logs montrant des scans automatisés externes (zgrab, Palo Alto Cortex Xpanse, InternetMeasurement, etc.) atteignant `login.php`.

### Correctif — recréation du conteneur avec binding restreint à l'IP WireGuard du VPS

Vérification préalable (pas de volume monté, pas de compose file → conteneur éphémère, recréation sans risque de perte de données) :

```bash
sudo docker inspect <nom_conteneur_dvwa> --format '{{.HostConfig.PortBindings}}'
sudo docker inspect <nom_conteneur_dvwa> --format '{{.Mounts}}'
find / -iname "*dvwa*" -name "docker-compose*.yml" 2>/dev/null
```

Recréation avec bind restreint :

```bash
sudo docker stop <nom_conteneur_dvwa> && sudo docker rm <nom_conteneur_dvwa>
sudo docker run -d --name <nom_conteneur_dvwa> --restart unless-stopped -p <IP_WireGuard_VPS>:<port>:80 vulnerables/web-dvwa
```

Nettoyage des règles UFW publiques devenues inutiles :

```bash
sudo ufw status numbered
sudo ufw delete <numero_regle_v6>
sudo ufw delete <numero_regle_v4>
sudo ufw status numbered
```

**Statut : résolu.** DVWA n'est désormais accessible que via le tunnel WireGuard, même principe que PwnDoc. Règles UFW publiques sur le port supprimées et vérifiées.

**Point en suspens (hors périmètre de cette session)** : le port 4444/tcp (Metasploit) reste ouvert publiquement dans UFW — déjà identifié comme prioritaire lors d'une session précédente, à traiter séparément.

---

## 4. Problème 2 — Erreur `dnspython` persistante malgré installation correcte

### Symptôme

`subdomain_enum` échouait systématiquement avec :
```
[ERREUR] Le module 'dnspython' est requis : pip install dnspython
```
... malgré `dnspython` confirmé installé et importable dans l'environnement virtuel du projet (`.venv-penbox`).

### Démarche de diagnostic

```powershell
& ".venv-penbox\Scripts\python.exe" -m pip install dnspython
& ".venv-penbox\Scripts\python.exe" -c "import dns.resolver; print('OK', dns.__file__)"
Get-ChildItem -Recurse -Filter "subdomain_enum.py"
Get-Content -LiteralPath "<chemin>\penbox\runner.py"
Get-ChildItem -Recurse -Filter "*.py" | Select-String -Pattern "python_exe\s*="
Get-Content -LiteralPath "<chemin>\penbox\ui\jobs.py" -Skip 135 -First 55
```

### Cause racine

Le raccourci de lancement (icône barre des tâches) pointait vers un interpréteur Python **géré par `uv`**, distinct du venv du projet :
```
%APPDATA%\Roaming\uv\python\cpython-3.12-windows-x86_64-none\pythonw.exe
```

`penbox_launch.pyw` contournait un bug connu de `uv` (le `pythonw.exe` généré dans `.venv-penbox` est en subsystem CONSOLE au lieu de GUI) en lançant l'app avec le `pythonw.exe` d'`uv`, et en injectant le `site-packages` du venv via `site.addsitedir()` — **mais uniquement pour le process courant**. Cet ajout n'est pas hérité par les sous-processus lancés via `subprocess.Popen(sys.executable, ...)` dans `runner.py`, qui reçoivent donc l'interpréteur `uv` nu, sans les dépendances du venv (`dnspython`, etc.).

### Vérification de non-régression avant correctif

```powershell
Get-ChildItem -Recurse -Filter "*.py*" -Exclude "*.venv-penbox*" | Select-String -Pattern "sys\.executable"
```
→ confirmé : `sys.executable` n'est utilisé nulle part ailleurs pour relancer l'UI elle-même (uniquement dans `runner.py` / `ui/jobs.py` pour lancer les scripts enfants).

### Correctif appliqué

Dans `penbox_launch.pyw`, juste après la définition de `ROOT` :

```python
ROOT = Path(__file__).resolve().parent
sys.executable = str(ROOT / ".venv-penbox" / "Scripts" / "python.exe")
```

Ceci force tous les sous-processus lancés ensuite (recon, exploitation, etc.) à hériter du bon interpréteur, sans changer l'exécutable utilisé pour l'UI elle-même (déjà lancée par le `pythonw.exe` d'`uv` au moment où cette ligne s'exécute).

**Statut : résolu et validé** — `subdomain_enum` et `whois_lookup` s'exécutent désormais sans erreur.

---

## 5. Problème 3 — Erreur de syntaxe dans `dir_bruteforcer.py`

### Symptôme

```
File "...\10_Web_Security\dir_bruteforcer.py", line 187
SyntaxError: unexpected character after line continuation character
```

### Cause

F-string imbriquée avec guillemet échappé invalide :
```python
print(f"  {col(f'[{result[\"code\"]}]')}  {bold(result['url'])}  {dim(size_str)}  {dim(redir)}")
```

### Correctif appliqué

Extraction de la sous-expression dans une variable intermédiaire pour éliminer l'imbrication de guillemets :

```python
code_str = col(f"[{result['code']}]")
print(f"  {code_str}  {bold(result['url'])}  {dim(size_str)}  {dim(redir)}")
```

**Statut : résolu et validé.**

---

## 6. Modules PenBox testés et validés contre la cible DVWA

| Catégorie | Outil | Résultat |
|---|---|---|
| Reconnaissance | `port_scanner` | OK — 22, 80, 443 détectés (hors plage 1-1024, port DVWA non testé) |
| Reconnaissance | `subdomain_enum` | OK (après correctif §4) — 0 résultat, attendu (IP privée) |
| Reconnaissance | `whois_lookup` | OK (après correctif §4) — contact IANA générique, attendu (IP privée) |
| Analyse réseau | `banner_grabber` | OK |
| Analyse réseau | `network_mapper` | OK |
| Sécurité Web | `dir_bruteforcer` | OK (après correctif §5) — arborescence DVWA cohérente (403 sur fichiers sensibles, 302 vers login) |
| Sécurité Web | `sqli_detector` | OK — **7 vecteurs SQLi détectés** sur `vulnerabilities/sqli/` (error-based, boolean-based), avec cookie de session authentifié |
| Sécurité Web | `xss_scanner` | OK — testé sur la racine (pas de paramètre injectable), pas encore testé sur une page vulnérable authentifiée |

### Méthode pour cibler une page authentifiée (SQLi/XSS)

```powershell
& ".venv-penbox\Scripts\python.exe" "10_Web_Security\sqli_detector.py" --url "<url_cible>?id=INJECT&Submit=Submit" --cookie "security=low; PHPSESSID=<session_id>"
```

---

## 7. Suite possible

- Retester `xss_scanner` contre une page XSS réfléchie authentifiée (`vulnerabilities/xss_r/`), même méthode de cookie que pour `sqli_detector`.
- Traiter le port 4444/tcp encore ouvert publiquement dans UFW (Metasploit, priorité déjà identifiée).
- Poursuivre les tests des catégories restantes de PenBox (Exploitation, Post-exploitation, Forensic/IR, OSINT, Cryptographie, Évaluation de vulnérabilités) contre DVWA.
