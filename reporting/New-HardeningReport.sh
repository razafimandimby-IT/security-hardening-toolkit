#!/usr/bin/env bash
# ==============================================================================
# Security Hardening Toolkit - Generation de rapport Linux
# ==============================================================================
# Description: Genere un rapport HTML professionnel a partir des resultats JSON
#              de l'audit Linux (check-compliance.sh).
#
# Auteur  : Louis Denis RAZAFIMANDIMBY
# Version : 1.0.0
#
# Usage:
#   ./New-HardeningReport.sh --input ./audit-results.json --output ./rapport.html
#   ./New-HardeningReport.sh --input ./audit.json --output ./report.html --title "Audit PROD"
# ==============================================================================

set -euo pipefail

SCRIPT_VERSION="1.0.0"
INPUT_FILE=""
OUTPUT_FILE=""
REPORT_TITLE="Rapport de Conformite - Security Hardening Toolkit"
COMPANY_NAME=""

GREEN='\033[0;32m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    echo "Usage: $0 --input FILE --output FILE [options]"
    echo ""
    echo "Options:"
    echo "  --input FILE      Fichier JSON de resultats d'audit (obligatoire)"
    echo "  --output FILE     Fichier HTML de sortie (obligatoire)"
    echo "  --title TITLE     Titre personnalise du rapport"
    echo "  --company NAME    Nom de l'entreprise"
    echo "  --help            Affiche cette aide"
    echo ""
    echo "Exemple:"
    echo "  $0 --input audit.json --output rapport.html"
    exit 0
}

# Traitement des arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --input) INPUT_FILE="$2"; shift 2 ;;
        --output) OUTPUT_FILE="$2"; shift 2 ;;
        --title) REPORT_TITLE="$2"; shift 2 ;;
        --company) COMPANY_NAME="$2"; shift 2 ;;
        --help|-h) usage ;;
        *) log_error "Option inconnue: $1"; usage ;;
    esac
done

if [ -z "$INPUT_FILE" ] || [ -z "$OUTPUT_FILE" ]; then
    log_error "Options --input et --output requises"
    usage
fi

if [ ! -f "$INPUT_FILE" ]; then
    log_error "Fichier introuvable: ${INPUT_FILE}"
    exit 1
fi

# Verifier la disponibilite de python3
if ! command -v python3 &>/dev/null; then
    log_error "python3 est requis pour generer le rapport HTML"
    exit 1
fi

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo -e "${WHITE}  SECURITY HARDENING TOOLKIT - GENERATION DE RAPPORT${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo ""

log_info "Generation du rapport HTML a partir de: ${INPUT_FILE}"

# Utiliser python3 pour generer le rapport HTML
python3 << PYTHON_SCRIPT
import json
import sys
import os
from datetime import datetime

try:
    with open("${INPUT_FILE}", 'r') as f:
        data = json.load(f)
except Exception as e:
    print(f"Erreur lors du chargement du fichier JSON: {e}")
    sys.exit(1)

# Extraire les donnees
summary = data.get('summary', {})
results = data.get('results', [])
hostname = data.get('hostname', 'unknown')
os_name = data.get('os', 'unknown')
timestamp = data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
version = data.get('version', '1.0.0')

score = summary.get('score', 0)
pass_count = summary.get('pass', 0)
fail_count = summary.get('fail', 0)
warning_count = summary.get('warning', 0)
total = summary.get('total', 0)

score_color = '#4caf50'
if score < 80:
    score_color = '#ff9800'
if score < 60:
    score_color = '#f44336'

if score >= 90:
    score_label = 'Excellent'
elif score >= 80:
    score_label = 'Tres bien'
elif score >= 70:
    score_label = 'Bien'
elif score >= 60:
    score_label = 'Moyen'
else:
    score_label = 'Critique'

# Generer les lignes de resultats
result_rows = ''
for r in results:
    status = r.get('status', 'INFO')
    badge = {
        'PASS': '<span style="background:#4caf50;color:#fff;padding:2px 6px;border-radius:3px;font-size:0.8em;font-weight:bold">PASS</span>',
        'FAIL': '<span style="background:#f44336;color:#fff;padding:2px 6px;border-radius:3px;font-size:0.8em;font-weight:bold">FAIL</span>',
        'WARNING': '<span style="background:#ff9800;color:#fff;padding:2px 6px;border-radius:3px;font-size:0.8em;font-weight:bold">WARN</span>',
        'ERROR': '<span style="background:#e91e63;color:#fff;padding:2px 6px;border-radius:3px;font-size:0.8em;font-weight:bold">ERROR</span>',
        'INFO': '<span style="background:#2196f3;color:#fff;padding:2px 6px;border-radius:3px;font-size:0.8em;font-weight:bold">INFO</span>',
    }.get(status, '')

    remediation = r.get('remediation', '')
    remediation_html = f'<code style="font-size:0.85em;word-break:break-all">{remediation}</code>' if remediation and status == 'FAIL' else ''

    result_rows += f"""
                <tr>
                    <td>{r.get('check_id', '')}</td>
                    <td>{r.get('category', '')}</td>
                    <td>{r.get('description', '')}</td>
                    <td>{r.get('expected', '')}</td>
                    <td>{r.get('actual', '')}</td>
                    <td>{badge}</td>
                    <td>{remediation_html}</td>
                </tr>"""

# Generer le regroupement par categorie
categories = {}
for r in results:
    cat = r.get('category', 'Autre')
    if cat not in categories:
        categories[cat] = {'pass': 0, 'fail': 0, 'warn': 0, 'total': 0}
    s = r.get('status', 'INFO')
    if s == 'PASS':
        categories[cat]['pass'] += 1
    elif s == 'FAIL':
        categories[cat]['fail'] += 1
    elif s == 'WARNING':
        categories[cat]['warn'] += 1
    categories[cat]['total'] += 1

cat_rows = ''
for cat, vals in sorted(categories.items()):
    cat_score = round((vals['pass'] / vals['total'] * 100), 1) if vals['total'] > 0 else 0
    cat_color = '#4caf50' if cat_score >= 80 else ('#ff9800' if cat_score >= 60 else '#f44336')
    cat_rows += f"""
                <tr>
                    <td style="font-weight:600">{cat}</td>
                    <td style="color:#4caf50;font-weight:bold">{vals['pass']}</td>
                    <td style="color:#f44336;font-weight:bold">{vals['fail']}</td>
                    <td style="color:#ff9800;font-weight:bold">{vals['warn']}</td>
                    <td style="color:{cat_color};font-weight:bold">{cat_score}%</td>
                </tr>"""

# Echecs critiques
critical_items = [r for r in results if r.get('status') == 'FAIL' and r.get('check_id', '').startswith(('KERNEL', 'SSH', 'SVC'))]
critical_html = ''
if critical_items:
    critical_html = f"""
            <div class="section">
                <h2>Echecs critiques</h2>
                <div class="alert alert-danger">
                    <strong>{len(critical_items)} echecs identifiees</strong> necessitant une action corrective
                </div>
                <ul>
                    {"".join(f'<li><strong>{r.get("check_id","")}:</strong> {r.get("description","")}</li>' for r in critical_items[:10])}
                </ul>
            </div>"""

# Info systeme
system_info = f"""
            <div class="system-info">
                <h2>Informations systeme</h2>
                <table>
                    <tr><td><strong>Nom de la machine</strong></td><td>{hostname}</td></tr>
                    <tr><td><strong>Systeme</strong></td><td>{os_name}</td></tr>
                    <tr><td><strong>Date d audit</strong></td><td>{timestamp}</td></tr>
                    <tr><td><strong>Outil</strong></td><td>Security Hardening Toolkit v{version}</td></tr>
                </table>
            </div>"""

# Recommendations
recommendations = f"""
            <div class="section">
                <h2>Recommandations</h2>
                <ul>
                    <li><strong>{fail_count} non-conformites</strong> a corriger</li>
                    <li>Executer: <code>sudo ./linux/remediate.sh --report {os.path.basename('${INPUT_FILE}')}</code></li>
                    <li>Planifier un audit regulier (recommandation mensuelle)</li>
                    <li>Consulter la documentation dans <code>docs/</code></li>
                </ul>
            </div>"""

# Assembler le HTML
html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{report_title}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',sans-serif;background:#f0f2f5;color:#1a202c;line-height:1.6;padding:20px}}
.container{{max-width:1400px;margin:0 auto}}
.header{{background:linear-gradient(135deg,#1a202c,#2d3748,#4a5568);color:#fff;padding:40px;border-radius:16px;margin-bottom:30px;text-align:center}}
.header h1{{font-size:2.2em;font-weight:700;margin-bottom:8px}}
.header .subtitle{{color:#a0aec0;font-size:1.1em;margin-bottom:5px}}
.header .meta{{color:#718096;font-size:0.85em}}
.score-section{{background:#fff;border-radius:16px;padding:40px;margin-bottom:30px;box-shadow:0 4px 6px rgba(0,0,0,0.07);text-align:center}}
.gauge{{width:200px;height:200px;border-radius:50%;background:conic-gradient({score_color} 0deg {score*3.6}deg,#e2e8f0 {score*3.6}deg 360deg);display:flex;align-items:center;justify-content:center;margin:0 auto 20px}}
.gauge-inner{{width:155px;height:155px;border-radius:50%;background:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center}}
.gauge-value{{font-size:3em;font-weight:800;line-height:1;color:{score_color}}}
.gauge-label{{font-size:0.9em;color:#718096;margin-top:5px}}
.gauge-desc{{font-size:1.1em;color:#4a5568;font-weight:600}}
.stats-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:30px}}
.stat-card{{background:#fff;padding:20px;border-radius:12px;text-align:center;box-shadow:0 2px 4px rgba(0,0,0,0.05)}}
.stat-card .num{{font-size:2.5em;font-weight:700}}
.stat-card .lbl{{font-size:0.8em;color:#718096;margin-top:5px}}
.num-pass{{color:#4caf50}}
.num-fail{{color:#f44336}}
.num-warn{{color:#ff9800}}
.num-total{{color:#2196f3}}
.section{{background:#fff;border-radius:16px;padding:25px 30px;margin-bottom:25px;box-shadow:0 2px 4px rgba(0,0,0,0.05)}}
.section h2{{font-size:1.4em;color:#2d3748;margin-bottom:20px;padding-bottom:10px;border-bottom:2px solid #e2e8f0}}
table{{width:100%;border-collapse:collapse}}
th{{background:#1a202c;color:#fff;padding:12px 15px;text-align:left;font-size:0.85em;text-transform:uppercase;letter-spacing:0.5px}}
td{{padding:10px 15px;border-bottom:1px solid #e2e8f0;font-size:0.9em}}
tr:hover{{background:#f7fafc}}
.table-wrap{{overflow-x:auto}}
.system-info table td{{border:none;padding:6px 15px}}
.system-info table td:first-child{{width:250px}}
.alert{{padding:15px 20px;border-radius:8px;margin:10px 0}}
.alert-danger{{background:#fef2f2;border:1px solid #fecaca;color:#dc2626}}
code{{background:#f1f5f9;padding:2px 6px;border-radius:3px;font-size:0.9em}}
ul{{padding-left:20px;line-height:2}}
.footer{{text-align:center;padding:30px;color:#a0aec0;font-size:0.85em}}
@@media(max-width:768px){{.stats-grid{{grid-template-columns:repeat(2,1fr)}}}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>Security Hardening Toolkit</h1>
<div class="subtitle">"""+report_title+"""</div>
<div class="meta">"""+ (f"{company_name} | " if "${COMPANY_NAME}" else "") +f"""{hostname} | {timestamp}</div>
</div>

<div class="score-section">
<div class="gauge"><div class="gauge-inner"><div class="gauge-value">{score}%</div><div class="gauge-label">Score global</div></div></div>
<div class="gauge-desc" style="color:{score_color}">{score_label}</div>
<p style="color:#718096;margin-top:10px">{pass_count}/{total} tests reussis</p>
</div>

<div class="stats-grid">
<div class="stat-card"><div class="num num-pass">{pass_count}</div><div class="lbl">PASS</div></div>
<div class="stat-card"><div class="num num-fail">{fail_count}</div><div class="lbl">FAIL</div></div>
<div class="stat-card"><div class="num num-warn">{warning_count}</div><div class="lbl">WARNINGS</div></div>
<div class="stat-card"><div class="num num-total">{total}</div><div class="lbl">TOTAL</div></div>
</div>

{system_info}

<div class="section">
<h2>Resultats par categorie</h2>
<table><thead><tr><th>Categorie</th><th>Pass</th><th>Fail</th><th>Warn</th><th>Score</th></tr></thead>
<tbody>{cat_rows}</tbody></table>
</div>

{critical_html}
{recommendations}

<div class="section">
<h2>Details des verifications ({total} tests)</h2>
<div class="table-wrap">
<table><thead><tr><th>ID</th><th>Categorie</th><th>Description</th><th>Attendu</th><th>Actuel</th><th>Statut</th><th>Remediation</th></tr></thead>
<tbody>{result_rows}</tbody></table>
</div>
</div>

<div class="footer">
<p>Security Hardening Toolkit v{version}</p>
<p>Developpe par Louis Denis RAZAFIMANDIMBY</p>
<p>Genere le {timestamp}</p>
</div>
</div>
</body>
</html>"""

report_title = "${REPORT_TITLE}".replace('"', '&quot;') if "${REPORT_TITLE}" != "${REPORT_TITLE}" else "${REPORT_TITLE}"
company_name = "${COMPANY_NAME}".replace('"', '&quot;') if "${COMPANY_NAME}" != "${COMPANY_NAME}" else "${COMPANY_NAME}"

# Re-generation avec les bonnes variables shell
html = html.replace('REPORT_TITLE_PLACEHOLDER', report_title)
html = html.replace('COMPANY_NAME_PLACEHOLDER', company_name if company_name else '')

with open("${OUTPUT_FILE}", 'w', encoding='utf-8') as f:
    f.write(html)

print(f"Rapport genere: ${OUTPUT_FILE}")
print(f"Score de conformite: {score}% ({score_label})")

PYTHON_SCRIPT

log_success "Rapport genere: ${OUTPUT_FILE}"
