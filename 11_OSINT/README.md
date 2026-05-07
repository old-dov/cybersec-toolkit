# 11 — OSINT (Open Source Intelligence)

> ⚠️ **Avertissement légal** : Ces outils collectent des informations publiquement disponibles. Leur utilisation doit respecter les conditions d'utilisation des plateformes interrogées, le RGPD, et les lois locales sur la vie privée.

Scripts de collecte d'informations passives à partir de sources ouvertes (OSINT). Aucune interaction intrusive avec les cibles.

---

## Scripts

### `email_harvester.py` — Collecte d'adresses email

Crawle un site web pour extraire les adresses email présentes dans les pages HTML. Vérifie également les pages courantes (`/contact`, `/about`, `/team`, etc.).

**Usage :**
```bash
python email_harvester.py --domain example.com
python email_harvester.py --domain example.com --depth 3 --threads 5
python email_harvester.py --domain example.com -o emails.json
```

---

### `username_checker.py` — Vérification de pseudonyme multi-plateformes

Vérifie l'existence d'un nom d'utilisateur sur ~30 plateformes populaires (GitHub, Twitter/X, Reddit, Instagram, LinkedIn, etc.).

**Usage :**
```bash
python username_checker.py --username johndoe
python username_checker.py --username johndoe --platforms github,reddit,twitter
python username_checker.py --username johndoe -o report.json
```

---

### `metadata_extractor.py` — Extraction de métadonnées de fichiers

Extrait les métadonnées de fichiers : auteur, logiciel, dates de création, coordonnées GPS (images), commentaires cachés, etc.

**Formats supportés :**
- Images : JPEG, PNG, TIFF (EXIF via Pillow — optionnel)
- PDF : en-têtes et métadonnées
- Documents Office : balises XML
- Tout fichier texte : statistiques générales

**Usage :**
```bash
python metadata_extractor.py --file document.pdf
python metadata_extractor.py --dir /path/to/files --recursive
python metadata_extractor.py --file photo.jpg -o meta.json
```

---

## Pipeline recommandé

```
01_Reconnaissance/whois_lookup.py        (infos domaine)
                  ↓
11_OSINT/email_harvester.py              (emails exposés)
11_OSINT/username_checker.py             (présence en ligne)
11_OSINT/metadata_extractor.py           (fichiers collectés)
                  ↓
06_Reporting/report_generator.py         (rapport final)
```
