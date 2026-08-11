"""Loader/validator for penbox/catalog.yaml — the registry of wrapped CLI scripts."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = Path(__file__).resolve().parent / "catalog.yaml"

INPUT_MODES = {"target", "multi_target", "file_input", "payload", "none"}
JSON_MODES = {"flag", "inline", "none"}
TARGET_TYPES = {"host", "ip", "domain", "url", "cidr", "file", "dir", "username", None}

# "host" accepte aussi bien une IP qu'un nom de domaine (résolu par le script lui-même).
TYPE_COMPAT = {
    "host": {"host", "ip", "domain"},
}


def target_type_matches(target_row_type: str, spec_target_type: str | None) -> bool:
    if spec_target_type is None:
        return False
    return target_row_type in TYPE_COMPAT.get(spec_target_type, {spec_target_type})


@dataclass
class ToolSpec:
    id: str
    path: str
    category: str
    desc: str
    input_mode: str
    json_mode: str
    target_flag: str | None = None
    target_type: str | None = None
    output_flag: str = "-o"
    extra_args: list[str] = field(default_factory=list)
    default_timeout_s: int = 60
    produces_targets: bool = False
    example: str = ""
    # Port optionnel, réglable par l'utilisateur au lancement (ex: ssl_checker sur un
    # port TLS non standard). None = le script n'expose pas de port surchargeable.
    port_flag: str | None = None
    default_port: int | None = None
    # True pour les scripts qui sortent avec le code 1 quand ils TROUVENT quelque
    # chose (ex: env_secrets_scanner, privesc_checker — convention type grep),
    # pas seulement en cas d'erreur réelle. Un run reste "ok" si le JSON attendu
    # a bien été produit et parsé, même avec exit_code=1.
    nonzero_exit_ok: bool = False

    def script_path(self) -> Path:
        return REPO_ROOT / self.path


class CatalogError(ValueError):
    pass


def _validate_entry(entry: dict) -> None:
    required = {"id", "path", "category", "desc", "input_mode", "json_mode"}
    missing = required - entry.keys()
    if missing:
        raise CatalogError(f"Entrée catalogue incomplète ({entry.get('id', '?')}) : champs manquants {missing}")
    if entry["input_mode"] not in INPUT_MODES:
        raise CatalogError(f"{entry['id']}: input_mode invalide '{entry['input_mode']}' (attendu: {INPUT_MODES})")
    if entry["json_mode"] not in JSON_MODES:
        raise CatalogError(f"{entry['id']}: json_mode invalide '{entry['json_mode']}' (attendu: {JSON_MODES})")
    if entry.get("target_type") not in TARGET_TYPES:
        raise CatalogError(f"{entry['id']}: target_type invalide '{entry.get('target_type')}' (attendu: {TARGET_TYPES})")
    if entry["input_mode"] in ("target", "multi_target") and not entry.get("target_flag"):
        raise CatalogError(f"{entry['id']}: input_mode='{entry['input_mode']}' requiert 'target_flag'")


def load_catalog(path: str | Path | None = None) -> dict[str, ToolSpec]:
    """Charge et valide catalog.yaml. Lève CatalogError si le schéma est invalide."""
    catalog_path = Path(path) if path else CATALOG_PATH
    with open(catalog_path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, list):
        raise CatalogError("catalog.yaml doit être une liste d'entrées")

    tools: dict[str, ToolSpec] = {}
    seen_ids: set[str] = set()
    for entry in raw:
        _validate_entry(entry)
        if entry["id"] in seen_ids:
            raise CatalogError(f"id dupliqué dans le catalogue : {entry['id']}")
        seen_ids.add(entry["id"])

        spec = ToolSpec(
            id=entry["id"],
            path=entry["path"],
            category=entry["category"],
            desc=entry["desc"],
            input_mode=entry["input_mode"],
            json_mode=entry["json_mode"],
            target_flag=entry.get("target_flag"),
            target_type=entry.get("target_type"),
            output_flag=entry.get("output_flag", "-o"),
            extra_args=list(entry.get("extra_args", [])),
            default_timeout_s=entry.get("default_timeout_s", 60),
            produces_targets=entry.get("produces_targets", False),
            example=entry.get("example", ""),
            port_flag=entry.get("port_flag"),
            default_port=entry.get("default_port"),
            nonzero_exit_ok=entry.get("nonzero_exit_ok", False),
        )
        if not spec.script_path().exists():
            raise CatalogError(f"{spec.id}: script introuvable à {spec.script_path()}")
        tools[spec.id] = spec

    return tools
