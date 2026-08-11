"""Registre de normaliseurs JSON brut -> list[Finding], un par script (ou générique en repli).

Reprend le schéma finding(name, category, risk, detail, note) de
09_Post_Exploitation/privesc_checker.py comme forme cible commune.
"""

from __future__ import annotations

from typing import Callable

from penbox.store import Finding

_REGISTRY: dict[str, Callable[[dict], list[Finding]]] = {}

DANGEROUS_PORTS = {23: "Telnet", 21: "FTP", 3389: "RDP", 5900: "VNC", 6379: "Redis", 27017: "MongoDB"}
WEAK_PROTOCOLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}


def register(tool_id: str):
    def deco(fn: Callable[[dict], list[Finding]]):
        _REGISTRY[tool_id] = fn
        return fn

    return deco


def normalize(tool_id: str, raw: dict | list) -> list[Finding]:
    fn = _REGISTRY.get(tool_id)
    if fn is not None:
        return fn(raw)
    return _normalize_generic(tool_id, raw)


def _normalize_generic(tool_id: str, raw: dict | list) -> list[Finding]:
    """Repli pour les scripts sans normaliseur dédié : cherche une liste de résultats
    connue, sinon retourne un finding unique qui enveloppe le JSON brut."""
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = None
        for key in ("results", "findings", "vulnerabilities", "hits", "data"):
            val = raw.get(key)
            if isinstance(val, list):
                items = val
                break
        if items is None:
            return [Finding(name=tool_id, category=tool_id, risk="info", detail="", raw=raw)]
    else:
        return []

    findings = []
    for item in items:
        if isinstance(item, dict):
            name = str(item.get("name") or item.get("fqdn") or item.get("ip") or item.get("port") or tool_id)
            risk = str(item.get("risk", "info"))
            detail = str(item.get("detail") or item.get("banner") or "")
            findings.append(Finding(name=name, category=tool_id, risk=risk, detail=detail, raw=item))
        else:
            findings.append(Finding(name=str(item), category=tool_id, risk="info", raw={"value": item}))
    return findings


@register("port_scanner")
def _normalize_port_scanner(raw: dict) -> list[Finding]:
    out = []
    for r in raw.get("results", []):
        port = r.get("port")
        service = r.get("service", "?")
        risk = "high" if port in DANGEROUS_PORTS else "info"
        detail = f"Bannière: {r['banner']}" if r.get("banner") else ""
        out.append(Finding(name=f"Port {port}/TCP ouvert ({service})", category="port", risk=risk, detail=detail, raw=r))
    return out


@register("subdomain_enum")
def _normalize_subdomain_enum(raw: dict) -> list[Finding]:
    out = []
    for r in raw.get("results", []):
        records = ", ".join(r.get("records", []))
        out.append(Finding(
            name=r.get("fqdn", "?"), category="subdomain", risk="info",
            detail=f"{r.get('type', '')}: {records}", raw=r,
        ))
    return out


@register("network_mapper")
def _normalize_network_mapper(raw: dict) -> list[Finding]:
    out = []
    for r in raw.get("results", []):
        out.append(Finding(
            name=r.get("ip", "?"), category="host", risk="info",
            detail=r.get("hostname", ""), raw=r,
        ))
    return out


@register("banner_grabber")
def _normalize_banner_grabber(raw: dict) -> list[Finding]:
    out = []
    for r in raw.get("results", []):
        port = r.get("port")
        risk = "high" if port in DANGEROUS_PORTS else "info"
        out.append(Finding(
            name=f"Port {port}/TCP", category="banner", risk=risk,
            detail=(r.get("banner") or "")[:200], raw=r,
        ))
    return out


@register("whois_lookup")
def _normalize_whois(raw: dict) -> list[Finding]:
    data = raw.get("data", {})
    return [Finding(name=k, category="whois", risk="info", detail=str(v), raw={k: v}) for k, v in data.items()]


@register("dns_analyzer")
def _normalize_dns(raw: dict) -> list[Finding]:
    out = []
    for rtype, values in raw.get("records", {}).items():
        for v in values:
            out.append(Finding(name=f"{rtype} record", category="dns", risk="info", detail=str(v), raw={"type": rtype, "value": v}))
    return out


@register("http_headers_analyzer")
def _normalize_http_headers(raw: dict) -> list[Finding]:
    out = []
    for h in raw.get("security_headers", []):
        risk = h.get("risk", "info") if not h.get("valid", True) else "info"
        out.append(Finding(
            name=h.get("name", "?"), category="header", risk=risk,
            detail=str(h.get("value", "")), note="présent" if h.get("present") else "absent", raw=h,
        ))
    for d in raw.get("disclosure", []):
        out.append(Finding(name=f"Fuite d'info: {d.get('header')}", category="disclosure", risk="low", detail=str(d.get("value", "")), raw=d))
    return out


@register("ssl_checker")
def _normalize_ssl_checker(raw: dict) -> list[Finding]:
    out = []
    days_left = raw.get("Jours restants")
    if days_left is not None:
        risk = "critical" if days_left < 0 else ("high" if days_left < 30 else "info")
        out.append(Finding(name="Expiration certificat", category="ssl", risk=risk, detail=f"{days_left} jours restants", raw=raw))
    proto = raw.get("Protocole")
    if proto:
        risk = "critical" if proto in WEAK_PROTOCOLS else "info"
        out.append(Finding(name="Protocole TLS", category="ssl", risk=risk, detail=proto, raw={"Protocole": proto}))
    if raw.get("Cipher suite"):
        out.append(Finding(name="Cipher suite", category="ssl", risk="info", detail=raw["Cipher suite"], raw={"Cipher suite": raw["Cipher suite"]}))
    return out


@register("open_redirect_checker")
def _normalize_open_redirect(raw: dict) -> list[Finding]:
    out = []
    for v in raw.get("vulnerabilities", []):
        out.append(Finding(
            name=f"Open Redirect: {v.get('payload')}", category="open_redirect", risk="high",
            detail=f"→ {v.get('redirect_to')}", raw=v,
        ))
    return out


@register("privesc_checker")
def _normalize_privesc(raw: dict) -> list[Finding]:
    out = []
    for f in raw.get("findings", []):
        out.append(Finding(
            name=f.get("name", "?"), category=f.get("category", "privesc"),
            risk=f.get("risk", "info"), detail=f.get("detail", ""), note=f.get("note", ""), raw=f,
        ))
    return out


@register("log_parser")
def _normalize_log_parser(raw: dict) -> list[Finding]:
    out = []
    for ip, count in (raw.get("top_ips") or []):
        out.append(Finding(name=f"IP fréquente: {ip}", category="log", risk="info", detail=f"{count} occurrences", raw={"ip": ip, "count": count}))
    threats = raw.get("threats") or {}
    for label, count in threats.items():
        if count:
            out.append(Finding(name=f"Menace: {label}", category="log", risk="medium", detail=f"{count} occurrences", raw={label: count}))
    return out

