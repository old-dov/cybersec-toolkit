# 05 — Cryptography

Scripts cryptographiques pour sécuriser des données et vérifier leur intégrité.

| Script | Description | Dépendances |
|--------|-------------|-------------|
| `file_encryptor.py` | Chiffrement/déchiffrement de fichiers AES-256-GCM | `cryptography` |
| `hash_generator.py` | Génération et vérification de hachages (MD5, SHA1/256/512) | stdlib |

## Utilisation rapide

```bash
# Chiffrement AES-256-GCM
python file_encryptor.py encrypt -i document.pdf -o document.enc
python file_encryptor.py decrypt -i document.enc -o document_dechiffre.pdf

# Hachages
python hash_generator.py -f fichier.zip --all
python hash_generator.py -t "texte à hacher" --algo sha256
python hash_generator.py verify -f fichier.zip --hash abc123... --algo sha256
```

## Sécurité

- `file_encryptor.py` utilise **AES-256-GCM** (chiffrement authentifié)
- La clé est dérivée du mot de passe via **PBKDF2-HMAC-SHA256** (600 000 itérations)
- Les hachages MD5/SHA1 sont inclus pour compatibilité mais **non recommandés** pour la sécurité
