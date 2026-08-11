# P-Box — Desktop GUI wrapping the cybersec script collection

## Contexte

Le repo contient ~24 scripts CLI Python de pentest/audit répartis sur 9 catégories, actuellement lancés un par un via `cybersec_launcher.py` (un menu terminal qui fait des `subprocess`). L'objectif est une **appli desktop PySide6 nommée "P-Box"** où on choisit une ou des cibles, on choisit les scripts à lancer dessus, on exécute, et on voit les résultats sous forme de **listes détaillées et lisibles** (triables, filtrables, avec une vue détail par finding) plutôt qu'en scrollant du texte console brut — c'est le cœur de la demande, pas juste "une GUI avec des boutons".

Un état des lieux des 24 scripts (`01_Reconnaissance` … `12_Forensic_IR`) montre une situation hétérogène côté sortie :
- La plupart supportent déjà une sortie JSON structurée (`--json`, ou JSON inconditionnel via `-o`).
- Six n'ont **aucune sortie structurée**, texte seul : `port_scanner.py`, `subdomain_enum.py`, `network_mapper.py`, `banner_grabber.py`, `ssl_checker.py`, `open_redirect_checker.py`.
- Pas de schéma commun unique, mais une convention informelle existe déjà (le helper `finding(name, category, risk, detail, note)` de `privesc_checker.py`, et ce que `06_Reporting/report_generator.py` attend déjà : des listes de dicts avec un champ `risk`/`valid`, ex. ports en `{port, service, banner}`, headers en `{name, valid, risk, value}`).
- `13_File_Upload_Bypass_Access` n'a pas de scripts CLI (webshells PHP) — hors périmètre.
- Chaque script est subprocess-only (argparse + print, pas de fonctions importables) — la GUI doit les piloter comme des processus, pas les importer.

**Blocage environnement trouvé** : le `python` par défaut sur cette machine est en **32 bits** (`Python312-32`), mais PySide6 ne fournit que des wheels `win_amd64` — impossible à installer dessus. Un interpréteur 64 bits est dispo via le lanceur `py` (`-V:3.14`) ou `uv`. P-Box a besoin de son propre venv 64 bits.

## Approche

### 0. Setup environnement
Créer un venv dédié avec un interpréteur 64 bits (`uv venv --python 3.12` via le CPython déjà géré par uv, la version la plus testée avec PySide6). Ajouter `PySide6` à `requirements.txt`.

Ajouter un script de **bootstrap** (`setup.bat` / `setup.sh`) qui automatise `uv venv` + `pip install -r requirements.txt`, pour garantir que tout utilisateur installe la bonne version 64 bits sans avoir à connaître le détail du blocage 32/64 bits.

### 1. Standardiser la sortie JSON (patch additif, 6 scripts)
Pour `port_scanner.py`, `subdomain_enum.py`, `network_mapper.py`, `banner_grabber.py`, `ssl_checker.py`, `open_redirect_checker.py` : ajouter un flag `--json` qui sérialise les **données déjà construites en interne pour l'affichage** (ex. la liste `results` de port_scanner, le dict `get_cert_info()` de ssl_checker) vers le fichier `-o` en JSON — en reprenant le pattern déjà utilisé dans `whois_lookup.py` / `dns_analyzer.py` / `http_headers_analyzer.py`. Aucun changement de logique de scan, comportement texte par défaut inchangé, ~10–20 lignes ajoutées par script.

### 2. Nouveau package `pbox/` (l'appli, ne touche pas aux dossiers de scripts sinon)

- **`pbox/catalog.yaml`** (remplace `catalog.py`) — registre des scripts en config externe, pas en code Python : pour chacun des 24, sa catégorie, son flag d'argument cible (`-t`, `--domain`, `--url`, `--dir`, …), le type de cible attendu (ip/domain/url/cidr/file/dir), son mécanisme de sortie JSON (`--json`+`-o` vs `-o` inconditionnel), et un **timeout par défaut** (secondes). Adapté de la structure `CATALOG` existante dans `cybersec_launcher.py` (réutilise noms/descriptions/exemples). Un petit `pbox/catalog.py` résiduel se contente de charger/valider ce YAML (schéma minimal) — ajouter ou ajuster un script ne demande alors plus de toucher au code Python.

- **`pbox/store.py`** — SQLite (stdlib `sqlite3`, pas de nouvelle dépendance) avec les tables :
  `projects`, `targets(id, project_id, value, type, notes, source_run_id NULL)`,
  `runs(id, target_id, tool_name, status, started_at, finished_at, output_json_path, timed_out)`,
  `findings(id, run_id, name, category, risk, detail, note, raw_json)`.
  `targets.source_run_id` (nullable) trace qu'une cible a été créée par chaînage depuis un run précédent plutôt que saisie à la main.
  C'est la table `findings` qui alimente les "listes détaillées et lisibles" — une ligne par finding, requêtable/triable par cible, outil, risque. Le détail (`raw_json`) est rendu de façon **générique** (clé:valeur récursif) côté UI, donc ajouter un script avec des champs spécifiques ne demande aucune modif de l'UI de détail.

- **`pbox/normalizers.py`** — un **registre de fonctions** (`dict[str, Callable[[dict], list[Finding]]]`, peuplé via un décorateur `@register("port_scanner")`) plutôt qu'une hiérarchie de classes : chaque script garde une fonction de mapping courte, JSON brut → liste de `Finding(name, category, risk, detail, note, raw)`, réutilisant la logique d'extraction déjà présente dans `report_generator.py` (ports/headers/ssl/logs/brute). Le registre permet d'ajouter un normaliseur pour un nouveau script sans toucher aux autres ni gonfler un fichier unique — une vraie hiérarchie de classes n'apporte rien tant que les mappers restent de simples transformations JSON→liste.

- **`pbox/runner.py`** — `QProcess`-based job queue :
  - construit l'argv par script+cible depuis le catalogue, exécute avec une concurrence bornée (3 en parallèle par défaut) ;
  - **stdout et stderr sont capturés et streamés séparément** (`setProcessChannelMode` non fusionné) — la console UI affiche les deux dans des zones distinctes, stderr mis en évidence (erreurs de connexion/permissions typiques en sécu) ;
  - **timeout par job** : `QTimer` armé à la valeur du catalogue (override possible dans l'UI avant lancement) ; à expiration, `kill()` le process, marque le run `timed_out`, et l'action est aussi disponible manuellement via un bouton **"Kill"** par job dans la console ;
  - à la complétion, charge le fichier JSON de sortie, le passe au normaliseur du registre, écrit les findings dans le store, émet un signal Qt pour rafraîchir l'UI ;
  - **chaînage** : pour certains outils marqués `produces_targets: true` dans le catalogue (ex. `subdomain_enum.py`), une action explicite "Envoyer vers Cibles" transforme les findings du run en nouvelles lignes `targets` (avec `source_run_id`), immédiatement sélectionnables pour lancer d'autres scripts dessus (ex. sous-domaines → `ssl_checker.py`/`http_headers_analyzer.py`) — c'est le chaînage indispensable en pentest, pas un import automatique silencieux (l'utilisateur valide la liste avant import, pour éviter d'engager des dizaines de scans par accident).

### 3. `pbox/ui/` — l'interface

- **Left dock — Cibles** : ajouter/éditer/supprimer des cibles (avec type, validé par regex selon le type — IPv4/IPv6, domaine, URL, CIDR — avant d'être acceptée, pour éviter qu'une valeur malformée ne finisse dans l'argv du subprocess), groupées par projet/origine (manuelle vs chaînée), multi-sélection pour batch runs.
- **Centre — Catalogue de scripts** : arbre cochable groupé par catégorie, recherche, description + exemples, bouton "Lancer la sélection".
- **Dock bas — Console** : onglets par job avec stdout/stderr distincts, bouton **Kill** par job, indicateur d'état visuel par run (🔵 en cours / ✅ terminé / 🔴 échec ou timeout), **barre de progression globale** (X/Y jobs terminés) quand plusieurs runs sont en file.
- **Main tab — Résultats** :
  - `QTableView` + `QAbstractTableModel` sur la requête SQLite `findings`. Colonnes : Cible · Outil · Catégorie · Risque (badge coloré) · Nom · Détail · Horodatage. Triable sur chaque colonne.
  - Filtres : recherche libre, cases à cocher par risque, dropdown outil/catégorie, groupement par cible.
  - Clic sur une ligne → panneau de détail (`QSplitter`) : finding complet + rendu générique clé:valeur du `raw_json` (pas de code UI par script).
  - Bouton "Envoyer vers Cibles" sur les findings de type cible (cf. chaînage ci-dessus).
  - Export HTML (template Jinja2 adapté de `report_generator.py`) et CSV.
- **Dashboard (amélioration future, hors MVP)** : mini vue d'ensemble par projet (camembert répartition Critique/Haut/Moyen/Bas). Utile mais pas bloquant tant que le tri/filtre par risque de l'onglet Résultats couvre le besoin immédiat — à ajouter dans une itération suivante plutôt que de gonfler le scope initial.
- Modal de disclaimer légal au premier lancement, reprenant l'avertissement du `README.md` racine.

### 4. Point d'entrée
`pbox_app.py` à la racine du repo (même convention que `cybersec_launcher.py`), lance la `QApplication` PySide6 et la fenêtre principale.

## Sécurité — validation des entrées
Même si `QProcess` exécute avec une liste d'arguments (pas de shell string, donc pas d'injection shell classique), une cible malformée pourrait être interprétée comme un flag (ex. une valeur commençant par `-`) ou casser un script en aval. Chaque type de cible (ip/domain/url/cidr/file/dir) a une regex de validation stricte appliquée **avant** tout passage en argv, au moment de la saisie dans le panneau Cibles et lors d'un import par chaînage.

## Fichiers touchés
- Nouveaux : `pbox/__init__.py`, `pbox/catalog.yaml`, `pbox/catalog.py` (loader/validateur du YAML), `pbox/store.py`, `pbox/normalizers.py`, `pbox/runner.py`, `pbox/ui/main_window.py`, `pbox/ui/results_model.py`, `pbox/ui/targets_panel.py`, `pbox/ui/catalog_panel.py`, `pbox/ui/console_panel.py`, `pbox/ui/detail_pane.py`, `pbox/ui/export.py`, `pbox_app.py`, `setup.bat`/`setup.sh`
- Modifiés (additif seulement) : `requirements.txt` (+PySide6), et les 6 scripts texte-only listés ci-dessus (+flag `--json`).
- Lecture/référence seulement : `cybersec_launcher.py` (réutilisation des données CATALOG), `06_Reporting/report_generator.py` (réutilisation du template HTML + logique de score/champs), `09_Post_Exploitation/privesc_checker.py` (référence de forme des findings).

## Vérification
1. `uv venv` (64 bits) via `setup.bat`/`setup.sh` → `pip install -r requirements.txt` → confirmer que `import PySide6` fonctionne.
2. Lancer `pbox_app.py`, créer un projet, ajouter une cible **locale/autorisée** (`127.0.0.1` pour port_scanner, un fichier de test local pour hash_generator/metadata_extractor) — pas de scan de hôtes tiers pendant les tests.
3. Tester la validation des cibles : saisir une valeur malformée (ex. `-t` comme "IP") et confirmer qu'elle est rejetée avant tout lancement de subprocess.
4. Lancer 2–3 scripts couvrant patchés (port_scanner) et déjà-JSON (hash_generator + log_parser sur fichier factice local) ; confirmer : console affiche stdout/stderr séparément, Résultats se peuple, tri/filtre fonctionnent, détail générique + JSON brut visibles, exports HTML/CSV valides.
5. Tester le timeout : lancer un job avec un timeout très court (ex. 1s) et confirmer qu'il est tué automatiquement, marqué `timed_out`, et que le bouton Kill manuel fonctionne sur un autre job en cours.
6. Tester le chaînage : lancer `subdomain_enum.py` sur une cible locale/factice, envoyer les résultats vers Cibles, confirmer que les nouvelles cibles apparaissent marquées comme issues d'un chaînage et sont utilisables pour un nouveau run.
7. Confirmer que les 6 scripts patchés fonctionnent toujours à l'identique en standalone sans `--json` (pas de régression sur l'usage CLI/launcher existant).
