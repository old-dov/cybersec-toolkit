# File Upload — Payloads & techniques

Collection de payloads réutilisables pour les vulnérabilités d'**upload de fichiers**
(labs PortSwigger *File upload vulnerabilities*, tests sur environnements autorisés).

> ⚠️ **Cadre d'usage.** Ces payloads sont destinés **exclusivement** aux
> environnements pour lesquels tu disposes d'une autorisation explicite :
> labs PortSwigger, VPS Free Hive, machines de test avec consentement écrit.
> Un web shell déposé sur un système tiers sans autorisation est une intrusion
> caractérisée. En mission de pentest autorisée : documenter chaque dépôt et
> **nettoyer** les artefacts en fin de mission.

---

## Contenu

| Fichier | Rôle |
|---|---|
| `webshell_read.php` | Lit **un** fichier précis (`file_get_contents`). Le plus discret. |
| `webshell_read_markers.php` | Idem, mais encadre la sortie de marqueurs START/END. Pour les contextes bruités (polyglotte, binaire). |
| `webshell_cmd.php` | Exécute une commande arbitraire via `?cmd=`. Polyvalent mais bruyant. |
| `htaccess_bypass` | À renommer `.htaccess` — mappe une extension bidon vers PHP (Apache). |
| `payloads_extensions.txt` | Aide-mémoire des variantes d'extension et techniques de bypass. |
| `polyglot_gen.sh` | Génère un polyglotte image+PHP (bash/WSL). Pour les labs à vérif de contenu. |
| `polyglot_gen.ps1` | Idem en PowerShell (Windows natif). |

---

## Arbre de décision rapide

1. **Aucune validation ?** → `webshell_read.php` direct.
2. **Extension `.php` bloquée (blacklist) ?**
   - Tenter les variantes : `.phtml`, `.php5`, `.pht`… (voir `payloads_extensions.txt`)
   - Sinon : `.htaccess` + shell en `.l33t`.
3. **Content-Type vérifié ?** → forcer `Content-Type: image/jpeg` dans Burp,
   garder `filename="exploit.php"`.
4. **Contenu vérifié (getimagesize / vraie image) ?** → polyglotte :
   `./polyglot_gen.sh -i image.jpg -o polyglot.php` (métadonnées exiftool, robuste)
   ou `--gif` pour la version rapide sans image source.
   → **En contexte binaire, encadrer la sortie de marqueurs** (voir
   `webshell_read_markers.php`) et récupérer via `grep -ao 'START.*END'`,
   sinon le secret est illisible au milieu des octets de l'image.
5. **Fichier stocké mais pas exécuté ?** → penser path traversal dans `filename`.

---

## Rappel défense (côté analyste / GRC)

Ce que ces techniques révèlent, et les contre-mesures à recommander en audit :

- **Whitelist > blacklist** — n'autoriser qu'une liste fermée d'extensions.
- **Revalider côté serveur** — extension *et* type MIME *et* signature.
- **Renommer** les fichiers (nom aléatoire) pour casser le contrôle de l'attaquant.
- **Stocker hors webroot** ou dans un dossier **sans exécution de scripts**
  (config serveur, pas un `.htaccess` que l'utilisateur pourrait écraser).
- **Détection** — un agent type Wazuh peut alerter sur la création d'un `.php`
  inattendu dans un dossier d'upload, ou une exécution suspecte.

Correspondances référentiels : ISO 27001 A.8.26 (exigences de sécurité
applicative), recommandations ANSSI sur le filtrage des entrées, OWASP
*File Upload Cheat Sheet*.
