#!/usr/bin/env python3
"""
=============================================================================
 report_generator.py — Générateur de rapports de sécurité HTML/JSON
=============================================================================
 Auteur   : [votre nom]
 Version  : 1.0
 OS       : Windows / macOS / Linux (Python 3.8+)
 Dépend.  : jinja2  (pip install jinja2)

 DESCRIPTION
 -----------
 Consolide les résultats JSON exportés par les autres scripts de la
 collection en un rapport HTML professionnel et un rapport JSON structuré.
 Calcule un score de risque global et génère des recommandations priorisées.

 USAGE
 -----
   python report_generator.py [options]

 EXEMPLES
 --------
   # Rapport complet
   python report_generator.py \
     --title "Audit de sécurité — exemple.com" \
     --target exemple.com \
     --ports scan_ports.json \
     --ssl ssl_check.json \
     --headers headers.json \
     --dns dns_report.json \
     --logs log_report.json \
     --output rapport.html

   # Rapport minimal (cible + ports)
   python report_generator.py --target monsite.fr --ports ports.json --output rapport.html

   # Rapport JSON uniquement
   python report_generator.py --target monsite.fr --ports ports.json --json-only

 OPTIONS
 -------
   --title     Titre du rapport (défaut: "Rapport de sécurité")
   --target    Cible auditée (obligatoire)
   --auditor   Nom de l'auditeur
   --ports     JSON exporté par port_scanner.py
   --ssl       JSON exporté par ssl_checker.py
   --headers   JSON exporté par http_headers_analyzer.py
   --dns       JSON exporté par dns_analyzer.py
   --logs      JSON exporté par log_parser.py
   --brute     JSON exporté par failed_login_detector.py
   --output    Fichier HTML de sortie (défaut: rapport_<date>.html)
   --json-only Exporter uniquement en JSON

 SCORE DE RISQUE
 ---------------
   0–30   : CRITIQUE (rouge)
   31–60  : ÉLEVÉ (orange)
   61–80  : MOYEN (jaune)
   81–100 : FAIBLE (vert)
=============================================================================
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

try:
    from jinja2 import Environment, BaseLoader
except ImportError:
    print("[ERREUR] Le module 'jinja2' est requis : pip install jinja2")
    sys.exit(1)

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

def green(t):  return f"{Fore.GREEN}{t}{Style.RESET_ALL}" if COLOR else t
def cyan(t):   return f"{Fore.CYAN}{t}{Style.RESET_ALL}" if COLOR else t
def red(t):    return f"{Fore.RED}{t}{Style.RESET_ALL}" if COLOR else t

# ─── Template HTML ────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ title }}</title>
<style>
  :root {
    --crit: #e74c3c; --high: #e67e22; --med: #f39c12;
    --low: #27ae60;  --info: #3498db; --bg: #1a1a2e;
    --card: #16213e; --border: #0f3460; --text: #e0e0e0;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: var(--bg);
         color: var(--text); padding: 20px; }
  h1 { color: #4fc3f7; border-bottom: 2px solid var(--border);
       padding-bottom: 10px; margin-bottom: 20px; font-size: 1.8em; }
  h2 { color: #81d4fa; margin: 25px 0 10px; font-size: 1.2em; }
  h3 { color: #b0bec5; margin: 15px 0 8px; }
  .meta { background: var(--card); border: 1px solid var(--border);
          border-radius: 8px; padding: 15px; margin-bottom: 20px;
          display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .meta span { color: #90a4ae; font-size: 0.9em; }
  .meta strong { color: var(--text); }
  .score-box { text-align: center; background: var(--card);
               border-radius: 12px; padding: 25px; margin: 20px 0;
               border: 2px solid var(--border); }
  .score-num { font-size: 4em; font-weight: bold; }
  .score-label { font-size: 1.2em; margin-top: 5px; }
  .score-crit { color: var(--crit); }
  .score-high { color: var(--high); }
  .score-med  { color: var(--med); }
  .score-low  { color: var(--low); }
  .section { background: var(--card); border: 1px solid var(--border);
             border-radius: 8px; padding: 15px; margin-bottom: 15px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
  th { background: var(--border); color: #4fc3f7; padding: 8px 12px;
       text-align: left; }
  td { padding: 7px 12px; border-bottom: 1px solid #0f3460; }
  tr:hover td { background: rgba(15,52,96,0.4); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
           font-size: 0.8em; font-weight: bold; }
  .badge-crit { background: var(--crit); color: white; }
  .badge-high { background: var(--high); color: white; }
  .badge-med  { background: var(--med); color: #1a1a1a; }
  .badge-low  { background: var(--low); color: white; }
  .badge-ok   { background: #2ecc71; color: white; }
  .badge-info { background: var(--info); color: white; }
  .reco { border-left: 4px solid var(--crit); padding: 10px 15px;
          margin: 8px 0; background: rgba(231,76,60,0.1); border-radius: 0 6px 6px 0; }
  .reco.high { border-color: var(--high); background: rgba(230,126,34,0.1); }
  .reco.med  { border-color: var(--med);  background: rgba(243,156,18,0.1); }
  .reco.low  { border-color: var(--low);  background: rgba(39,174,96,0.1); }
  .reco-title { font-weight: bold; margin-bottom: 3px; }
  .reco-body  { font-size: 0.9em; color: #b0bec5; }
  footer { text-align: center; color: #546e7a; font-size: 0.8em;
           margin-top: 30px; padding-top: 15px;
           border-top: 1px solid var(--border); }
  .open  { color: #e74c3c; }
  .ok    { color: #2ecc71; }
  .warn  { color: #f39c12; }
</style>
</head>
<body>

<h1>🔒 {{ title }}</h1>

<!-- Métadonnées -->
<div class="meta">
  <div><span>Cible :</span> <strong>{{ target }}</strong></div>
  <div><span>Date :</span> <strong>{{ date }}</strong></div>
  <div><span>Auditeur :</span> <strong>{{ auditor }}</strong></div>
  <div><span>Score global :</span> <strong>{{ score }}/100</strong></div>
</div>

<!-- Score -->
<div class="score-box">
  <div class="score-num score-{{ score_class }}">{{ score }}</div>
  <div class="score-label score-{{ score_class }}">{{ score_label }}</div>
  <div style="color: #546e7a; font-size: 0.85em; margin-top: 8px;">Score de sécurité global (0 = très risqué, 100 = très sûr)</div>
</div>

<!-- Ports ouverts -->
{% if ports %}
<div class="section">
  <h2>🔌 Ports ouverts ({{ ports|length }})</h2>
  <table>
    <tr><th>Port</th><th>Service</th><th>Bannière</th></tr>
    {% for p in ports %}
    <tr>
      <td class="open">{{ p.port }}/TCP</td>
      <td>{{ p.service }}</td>
      <td style="font-family: monospace; font-size:0.85em;">{{ p.banner[:80] if p.banner else '—' }}</td>
    </tr>
    {% endfor %}
  </table>
</div>
{% endif %}

<!-- SSL/TLS -->
{% if ssl %}
<div class="section">
  <h2>🔐 Analyse SSL/TLS</h2>
  <table>
    {% for k, v in ssl.items() %}
    <tr><td style="color: #90a4ae; width: 40%">{{ k }}</td><td>{{ v }}</td></tr>
    {% endfor %}
  </table>
</div>
{% endif %}

<!-- En-têtes HTTP -->
{% if headers %}
<div class="section">
  <h2>📋 En-têtes HTTP de sécurité</h2>
  <table>
    <tr><th>En-tête</th><th>Statut</th><th>Risque</th><th>Valeur</th></tr>
    {% for h in headers %}
    <tr>
      <td>{{ h.name }}</td>
      <td>
        {% if h.valid %}
          <span class="badge badge-ok">✓ OK</span>
        {% elif h.present %}
          <span class="badge badge-med">⚠ Invalide</span>
        {% else %}
          <span class="badge badge-{{ 'crit' if h.risk == 'HIGH' else 'high' if h.risk == 'MEDIUM' else 'med' }}">✗ Absent</span>
        {% endif %}
      </td>
      <td><span class="badge badge-{{ 'crit' if h.risk == 'HIGH' else 'high' if h.risk == 'MEDIUM' else 'med' }}">{{ h.risk }}</span></td>
      <td style="font-family:monospace;font-size:0.8em;">{{ (h.value or '—')[:80] }}</td>
    </tr>
    {% endfor %}
  </table>
</div>
{% endif %}

<!-- Logs -->
{% if logs %}
<div class="section">
  <h2>📄 Analyse de logs</h2>
  <table>
    <tr><th>Métrique</th><th>Valeur</th></tr>
    <tr><td>Lignes analysées</td><td>{{ logs.total_lines }}</td></tr>
    <tr><td>Erreurs HTTP</td><td>{{ logs.error_count }}</td></tr>
    <tr><td>Lignes suspectes</td><td class="{{ 'open' if logs.suspicious_count > 0 else 'ok' }}">{{ logs.suspicious_count }}</td></tr>
    {% for threat, count in logs.threats.items() %}
    <tr><td>Menace : {{ threat }}</td><td class="open">{{ count }}</td></tr>
    {% endfor %}
  </table>
</div>
{% endif %}

<!-- Brute force -->
{% if brute %}
<div class="section">
  <h2>🔑 Tentatives de force brute</h2>
  {% if brute.alert_count == 0 %}
    <p class="ok">✓ Aucune activité de force brute détectée.</p>
  {% else %}
  <table>
    <tr><th>IP</th><th>Tentatives</th><th>Première vue</th><th>Dernière vue</th></tr>
    {% for a in brute.alerts[:20] %}
    <tr>
      <td class="open">{{ a.ip }}</td>
      <td class="open">{{ a.total }}</td>
      <td>{{ a.first_seen }}</td>
      <td>{{ a.last_seen }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}
</div>
{% endif %}

<!-- Recommandations -->
<div class="section">
  <h2>💡 Recommandations</h2>
  {% for reco in recommendations %}
  <div class="reco {{ reco.level }}">
    <div class="reco-title">
      <span class="badge badge-{{ 'crit' if reco.level == 'critical' else 'high' if reco.level == 'high' else 'med' if reco.level == 'med' else 'low' }}">
        {{ reco.priority }}
      </span>
      {{ reco.title }}
    </div>
    <div class="reco-body">{{ reco.description }}</div>
  </div>
  {% endfor %}
  {% if not recommendations %}
  <p class="ok">✓ Aucune recommandation critique identifiée.</p>
  {% endif %}
</div>

<footer>
  Rapport généré par <strong>report_generator.py</strong> — Collection de scripts cybersécurité<br>
  {{ date }} | Pour usage autorisé uniquement
</footer>
</body>
</html>"""

# ─── Fonctions ───────────────────────────────────────────────────────────────

def load_json(path: str | None) -> dict | None:
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[AVERT] Fichier JSON introuvable : {path} — ignoré")
        return None
    except json.JSONDecodeError as e:
        print(f"[AVERT] JSON invalide ({path}) : {e} — ignoré")
        return None


def compute_score(ports_data, ssl_data, headers_data, logs_data, brute_data) -> tuple[int, list]:
    """Calcule le score de sécurité (0-100) et génère les recommandations."""
    score = 100
    recommendations = []

    # ── Ports ─────────────────────────────────────────────────────────────────
    if ports_data:
        dangerous_ports = {23: "Telnet", 21: "FTP", 3389: "RDP", 5900: "VNC",
                           6379: "Redis", 27017: "MongoDB"}
        for p in ports_data:
            port_num = p.get("port", 0)
            if port_num in dangerous_ports:
                score -= 10
                recommendations.append({
                    "level": "critical",
                    "priority": "P1 — CRITIQUE",
                    "title": f"Port dangereux exposé : {port_num}/{dangerous_ports[port_num]}",
                    "description": f"Le service {dangerous_ports[port_num]} sur le port {port_num} "
                                   f"ne devrait pas être exposé sur Internet. Fermez ce port ou "
                                   f"restreignez l'accès via pare-feu.",
                })

    # ── SSL/TLS ───────────────────────────────────────────────────────────────
    if ssl_data:
        days_left = int(ssl_data.get("Jours restants", 9999))
        protocol = ssl_data.get("Protocole", "")
        if days_left < 0:
            score -= 20
            recommendations.append({
                "level": "critical",
                "priority": "P1 — CRITIQUE",
                "title": "Certificat SSL expiré",
                "description": f"Le certificat est expiré depuis {-days_left} jours. "
                               f"Renouvelez-le immédiatement (Let's Encrypt, etc.).",
            })
        elif days_left < 30:
            score -= 10
            recommendations.append({
                "level": "high",
                "priority": "P2 — ÉLEVÉ",
                "title": f"Certificat SSL expire dans {days_left} jours",
                "description": "Planifiez le renouvellement du certificat avant son expiration.",
            })
        if "TLSv1.0" in protocol or "TLSv1.1" in protocol:
            score -= 15
            recommendations.append({
                "level": "high",
                "priority": "P2 — ÉLEVÉ",
                "title": f"Protocole obsolète : {protocol}",
                "description": "Désactivez TLS 1.0 et TLS 1.1. Utilisez uniquement TLS 1.2 et 1.3.",
            })

    # ── En-têtes HTTP ──────────────────────────────────────────────────────────
    if headers_data:
        missing_high = [h for h in headers_data if not h.get("valid") and h.get("risk") == "HIGH"]
        missing_med  = [h for h in headers_data if not h.get("valid") and h.get("risk") == "MEDIUM"]
        score -= len(missing_high) * 8
        score -= len(missing_med) * 4
        for h in missing_high:
            recommendations.append({
                "level": "high",
                "priority": "P2 — ÉLEVÉ",
                "title": f"En-tête manquant : {h['name']}",
                "description": f"Ajoutez l'en-tête '{h['name']}' à votre serveur web. "
                               f"Rôle : protège contre les attaques XSS et injections de contenu.",
            })

    # ── Logs ──────────────────────────────────────────────────────────────────
    if logs_data:
        suspects = logs_data.get("suspicious_count", 0)
        if suspects > 100:
            score -= 15
            recommendations.append({
                "level": "high",
                "priority": "P2 — ÉLEVÉ",
                "title": f"{suspects} lignes suspectes dans les logs",
                "description": "Des tentatives d'attaque (SQLi, XSS, path traversal) ont été détectées. "
                               "Analysez et bloquez les IPs sources.",
            })

    # ── Brute force ───────────────────────────────────────────────────────────
    if brute_data and brute_data.get("alert_count", 0) > 0:
        nb = brute_data["alert_count"]
        score -= min(nb * 5, 20)
        recommendations.append({
            "level": "critical",
            "priority": "P1 — CRITIQUE",
            "title": f"Attaque par force brute détectée ({nb} IP(s))",
            "description": "Des tentatives de connexion massives ont été détectées. "
                           "Blocquez les IPs concernées (fail2ban, iptables) et activez "
                           "l'authentification à deux facteurs (2FA).",
        })

    score = max(0, min(100, score))
    return score, recommendations


def score_info(score: int) -> tuple[str, str]:
    """Retourne la classe CSS et le label selon le score."""
    if score >= 81: return "low",  "RISQUE FAIBLE"
    if score >= 61: return "med",  "RISQUE MOYEN"
    if score >= 31: return "high", "RISQUE ÉLEVÉ"
    return "crit", "RISQUE CRITIQUE"

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Générateur de rapports de sécurité HTML/JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--title",    default="Rapport de sécurité")
    parser.add_argument("--target",   required=True, help="Cible auditée")
    parser.add_argument("--auditor",  default="[Non renseigné]")
    parser.add_argument("--ports",    help="JSON port_scanner")
    parser.add_argument("--ssl",      help="JSON ssl_checker")
    parser.add_argument("--headers",  help="JSON http_headers_analyzer")
    parser.add_argument("--dns",      help="JSON dns_analyzer")
    parser.add_argument("--logs",     help="JSON log_parser")
    parser.add_argument("--brute",    help="JSON failed_login_detector")
    parser.add_argument("--output",   help="Fichier HTML de sortie")
    parser.add_argument("--json-only", action="store_true", help="JSON uniquement")
    args = parser.parse_args()

    print(cyan("=" * 60))
    print(cyan(f"  Report Generator — {args.target}"))
    print(cyan("=" * 60))

    # Chargement des données
    ports_raw   = load_json(args.ports)
    ssl_raw     = load_json(args.ssl)
    headers_raw = load_json(args.headers)
    dns_raw     = load_json(args.dns)
    logs_raw    = load_json(args.logs)
    brute_raw   = load_json(args.brute)

    # Extraction des ports
    ports_list = None
    if ports_raw:
        # Compatibilité avec le format JSON du port_scanner
        if isinstance(ports_raw, list):
            ports_list = ports_raw
        elif "open_ports" in ports_raw:
            ports_list = ports_raw["open_ports"]

    # Extraction des headers
    headers_list = None
    if headers_raw:
        headers_list = headers_raw.get("security_headers", [])

    # Extraction SSL (format simple clé-valeur)
    ssl_display = None
    if ssl_raw:
        ssl_display = {k: v for k, v in ssl_raw.items()
                       if k not in ("date", "target") and v}

    # Score
    score, recommendations = compute_score(
        ports_list, ssl_display, headers_list, logs_raw, brute_raw
    )
    score_class, score_label = score_info(score)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Données template
    context = {
        "title":           args.title,
        "target":          args.target,
        "auditor":         args.auditor,
        "date":            now,
        "score":           score,
        "score_class":     score_class,
        "score_label":     score_label,
        "ports":           ports_list or [],
        "ssl":             ssl_display,
        "headers":         headers_list or [],
        "logs":            logs_raw,
        "brute":           brute_raw,
        "dns":             dns_raw,
        "recommendations": recommendations,
    }

    # Rapport JSON
    json_report = {
        "title": args.title,
        "target": args.target,
        "auditor": args.auditor,
        "date": now,
        "score": score,
        "risk_level": score_label,
        "recommendations_count": len(recommendations),
        "recommendations": recommendations,
        "raw": {
            "ports": ports_list,
            "ssl": ssl_display,
            "headers": headers_list,
            "logs": logs_raw,
            "brute": brute_raw,
        }
    }

    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"rapport_{args.target.replace('.', '_')}_{date_str}"

    # Sauvegarde JSON
    json_path = base_name + ".json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_report, f, indent=2, ensure_ascii=False)
    print(green(f"[+] JSON sauvegardé : {json_path}"))

    if not args.json_only:
        # Génération HTML
        env = Environment(loader=BaseLoader())
        template = env.from_string(HTML_TEMPLATE)
        html = template.render(**context)

        html_path = args.output or (base_name + ".html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(green(f"[+] Rapport HTML sauvegardé : {html_path}"))

    print(f"\n  Score de sécurité : {score}/100 — {score_label}")
    print(f"  Recommandations   : {len(recommendations)}")


if __name__ == "__main__":
    main()
