# 🚀 PenBox - Liste des Évolutions et Nouvelles Fonctionnalités

Ce document rassemble les idées d'améliorations pour la suite de pentest PenBox. À utiliser comme base de discussion avec Claude pour générer le code des futurs modules (PySide6, logique Python, etc.).

---

## 🔒 1. Sécurité & Gestion des Connexions

### [Priorité Haute] durcissement SSH / SFTP
- **Problématique actuelle :** L'application accepte aveuglément toutes les clés d'hôte inconnues (vulnérabilité MITM).
- **Fonctionnalités à ajouter :**
  - Gestion d'un fichier `known_hosts` local.
  - Fenêtre pop-up d'alerte au premier scan affichant l'empreinte (Fingerprint) de la cible.
  - Option "Mode Strict" ou "Mode Tolérant" dans les paramètres généraux.

### [Priorité Moyenne] Gestionnaire de Profils (Credentials Vault)
- **Fonctionnalités à ajouter :**
  - Sauvegarde des configurations distantes fréquentes (IP, Port, User, Clé SSH).
  - Chiffrement du fichier de configuration en local via la bibliothèque `cryptography` (chiffrement symétrique Fernet avec un mot de passe maître).

---

## 🛠️ 2. Automatisation & Amélioration du Workflow

### [Priorité Haute] Gestion des Timeouts au niveau applicatif
- **Problématique actuelle :** Des scripts (ex: `whois_lookup.py`) bloquent l'UI et nécessitent un Kill manuel qui met 20 secondes à abandonner.
- **Fonctionnalités à ajouter :**
  - Intégration d'un paramètre de timeout natif dans l'appel `subprocess` ou `asyncio` de PenBox.
  - Interruption propre et immédiate du thread Python associé sans attendre le timeout du système d'exploitation.

### [Priorité Moyenne] Création de "Playbooks" (Scénarios)
- **Fonctionnalités à ajouter :**
  - Possibilité de sauvegarder une sélection groupée de scripts du Catalogue sous un nom précis (ex: Playbook "Recon Externe Rapide").
  - Un menu déroulant ou un onglet dédié dans le panneau Catalogue pour charger un Playbook en un clic.

### [Priorité Basse] Chaînage intelligent étendu
- **Fonctionnalités à ajouter :**
  - Automatisation du pipeline : permettre à un script de nourrir automatiquement le script suivant.
  - *Exemple :* `subdomain_enum` termine -> envoie automatiquement ses résultats valides à `ssl_checker` ou `port_scanner` sans intervention humaine.

---

## 🖥️ 3. Interface Utilisateur (UI/UX) & Console

### [Priorité Moyenne] Recherche et Filtrage dans la Console
- **Fonctionnalités à ajouter :**
  - Ajout d'une barre de recherche textuelle (`QLineEdit`) en bas des onglets de la Console.
  - Support des expressions régulières (Regex) et coloration des termes trouvés pour isoler rapidement les erreurs ou les succès.

### [Priorité Basse] Tableau de bord des ressources (Resource Widget)
- **Fonctionnalités à ajouter :**
  - Petit indicateur visuel (Barre de progression ou Widget) affichant l'utilisation CPU/RAM de la machine locale.
  - Compteur des processus Python (`jobs`) actifs en arrière-plan pour aider l'utilisateur à calibrer sa parallélisation.

---

## 📊 4. Gestion des Résultats & Reporting

### [Priorité Moyenne] Audit et Historique des Sessions
- **Fonctionnalités à ajouter :**
  - Persistance des données : sauvegarde automatique de chaque "Run" dans une base SQLite locale ou des fichiers JSON datés.
  - Onglet "Historique" pour recharger les résultats d'un scan effectué il y a plusieurs jours.

### [Priorité Moyenne] Édition des Findings (Faux-Positifs & Surcharges)
- **Fonctionnalités à ajouter :**
  - Clic droit sur une ligne du panneau "Résultats" pour marquer un élément comme *Faux-Positif* (griser la ligne).
  - Possibilité de modifier manuellement le niveau de risque avant l'export (ex: passer de "Medium" à "High" selon le contexte métier).
  - Comparateur de scans (Diff) pour identifier l'apparition de nouvelles vulnérabilités entre deux dates.
