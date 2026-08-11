"""Validation stricte des valeurs de cible avant tout passage en argv de sous-processus."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
# Chemin local léger : pas de caractères de contrôle, pas vide, pas de nul byte.
_PATH_RE = re.compile(r"^[^\x00-\x1f]{1,4096}$")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_target(value: str, target_type: str) -> tuple[bool, str]:
    """Retourne (ok, message_erreur). message_erreur == "" si ok."""
    value = (value or "").strip()
    if not value:
        return False, "Valeur vide"
    if value.startswith("-"):
        return False, "La valeur ne peut pas commencer par '-' (serait interprétée comme une option)"

    if target_type == "ip":
        return (True, "") if _is_ip(value) else (False, "Adresse IP invalide")

    if target_type == "host":
        if _is_ip(value) or _HOSTNAME_RE.match(value):
            return True, ""
        return False, "Doit être une IP ou un nom d'hôte valide"

    if target_type == "domain":
        return (True, "") if _DOMAIN_RE.match(value) else (False, "Domaine invalide (ex: exemple.com)")

    if target_type == "cidr":
        try:
            ipaddress.ip_network(value, strict=False)
            return True, ""
        except ValueError:
            return False, "Notation CIDR invalide (ex: 192.168.1.0/24)"

    if target_type == "url":
        parsed = urlparse(value)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return True, ""
        return False, "URL invalide (doit commencer par http:// ou https://)"

    if target_type in ("file", "dir"):
        return (True, "") if _PATH_RE.match(value) else (False, "Chemin invalide")

    if target_type == "username":
        return (True, "") if _USERNAME_RE.match(value) else (False, "Nom d'utilisateur invalide")

    # Type inconnu : on retombe sur le garde-fou générique (pas de '-' en tête).
    return True, ""
