<#
.SYNOPSIS
    Genere un rapport HTML professionnel a partir des resultats de conformite.

.DESCRIPTION
    Transforme les resultats JSON de l'audit (Test-WindowsCompliance.ps1) en un
    rapport HTML formaté avec scores, jauges visuelles, graphiques CSS et
    recommandations detaillees.

.PARAMETER DataPath
    Chemin vers le fichier JSON contenant les resultats d'audit.

.PARAMETER OutputPath
    Chemin du fichier HTML de sortie.

.PARAMETER TemplatePath
    Chemin vers un template HTML personnalise (optionnel).

.PARAMETER Title
    Titre personnalise pour le rapport.

.PARAMETER CompanyName
    Nom de l'entreprise/organisation pour le rapport.

.EXAMPLE
    .\New-HardeningReport.ps1 -DataPath .\audit-results.json -OutputPath .\SecurityReport.html

.EXAMPLE
    .\New-HardeningReport.ps1 -DataPath .\audit.json -OutputPath .\report.html -Title "Audit Serveur PROD-01"

.NOTES
    Auteur  : Louis Denis RAZAFIMANDIMBY
    Version : 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$DataPath,

    [Parameter(Mandatory=$true)]
    [string]$OutputPath,

    [Parameter(Mandatory=$false)]
    [string]$TemplatePath = "",

    [Parameter(Mandatory=$false)]
    [string]$Title = "Rapport de Conformite - Security Hardening Toolkit",

    [Parameter(Mandatory=$false)]
    [string]$CompanyName = ""
)

function Write-ColorOutput {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host $Message -ForegroundColor $Color
}

function Get-ReportData {
    Write-ColorOutput "Chargement des donnees: $DataPath" -Color Cyan

    if (-not (Test-Path -Path $DataPath)) {
        Write-ColorOutput "ERREUR: Fichier introuvable: $DataPath" -Color Red
        exit 1
    }

    try {
        $data = Get-Content -Path $DataPath -Raw | ConvertFrom-Json
        Write-ColorOutput "Donnees chargees avec succes." -Color Green
        return $data
    }
    catch {
        Write-ColorOutput "ERREUR lors du chargement: $($_.Exception.Message)" -Color Red
        exit 1
    }
}

function New-HtmlReport {
    param($Data, $OutputPath, $Title, $CompanyName)

    Write-ColorOutput "Generation du rapport HTML..." -Color Cyan

    # Extraire les donnees
    $summary = $Data.summary
    $results = $Data.results
    $system = $Data.system
    $score = [math]::Round($summary.Score, 1)
    $totalChecks = $summary.TotalChecks
    $passCount = $summary.PassCount
    $failCount = $summary.FailCount
    $warningCount = $summary.WarningCount

    $scoreColor = if ($score -ge 80) { "#4caf50" } elseif ($score -ge 60) { "#ff9800" } else { "#f44336" }
    $scoreLabel = if ($score -ge 90) { "Excellent" } elseif ($score -ge 80) { "Tres bien" } elseif ($score -ge 70) { "Bien" } elseif ($score -ge 60) { "Moyen" } else { "Critique" }

    # Generer les categories
    $catRows = ""
    foreach ($cat in $summary.Categories) {
        $catScoreColor = if ($cat.Score -ge 80) { "#4caf50" } elseif ($cat.Score -ge 60) { "#ff9800" } else { "#f44336" }
        $catRows += @"
                <tr>
                    <td style="font-weight:600">$($cat.Category)</td>
                    <td><span class="badge badge-pass">$($cat.Pass)</span></td>
                    <td><span class="badge badge-fail">$($cat.Fail)</span></td>
                    <td><span class="badge badge-warning">$($cat.Warning)</span></td>
                    <td>
                        <div class="mini-bar">
                            <div class="mini-bar-fill" style="width:$($cat.Score)%;background:$catScoreColor"></div>
                        </div>
                        <span style="font-weight:bold;color:$catScoreColor">$($cat.Score)%</span>
                    </td>
                </tr>
"@
    }

    # Generer les resultats detailles
    $resultRows = ""
    foreach ($r in $results) {
        $statusBadge = switch ($r.Status) {
            "PASS"    { '<span class="badge badge-pass">PASS</span>' }
            "FAIL"    { '<span class="badge badge-fail">FAIL</span>' }
            "WARNING" { '<span class="badge badge-warning">WARNING</span>' }
            "ERROR"   { '<span class="badge badge-error">ERROR</span>' }
            default   { '<span class="badge badge-info">INFO</span>' }
        }

        $severityBadge = switch ($r.Severity) {
            "Critical" { '<span class="badge severity-c">CRITICAL</span>' }
            "High"     { '<span class="badge severity-h">HIGH</span>' }
            "Medium"   { '<span class="badge severity-m">MEDIUM</span>' }
            "Low"      { '<span class="badge severity-l">LOW</span>' }
            default    { "" }
        }

        $remediationHtml = if ($r.Remediation -and $r.Status -eq "FAIL") {
            "<code style='font-size:0.85em;word-break:break-all'>$([System.Web.HttpUtility]::HtmlEncode($r.Remediation))</code>"
        } else { "" }

        $resultRows += @"
                <tr>
                    <td>$($r.CheckId)</td>
                    <td>$($r.Category)</td>
                    <td>$($r.Description)</td>
                    <td>$($r.Expected)</td>
                    <td>$($r.Actual)</td>
                    <td>$statusBadge</td>
                    <td>$severityBadge</td>
                    <td>$remediationHtml</td>
                </tr>
"@
    }

    # Generer la liste des echecs critiques
    $criticalFailsHtml = ""
    $criticalFails = $results | Where-Object { $_.Severity -eq "Critical" -and $_.Status -eq "FAIL" }
    if ($criticalFails) {
        $criticalFailsHtml = @"
            <div class="section">
                <h2>Echecs critiques</h2>
                <div class="alert alert-danger">
                    <strong>$($criticalFails.Count) echecs critiques</strong> necessitant une attention immediate
                </div>
                <ul>
"@
        foreach ($cf in $criticalFails) {
            $criticalFailsHtml += @"
                    <li><strong>$($cf.CheckId):</strong> $($cf.Description) - <code>$([System.Web.HttpUtility]::HtmlEncode($cf.Remediation))</code></li>
"@
        }
        $criticalFailsHtml += @"
                </ul>
            </div>
"@
    }

    # Info systeme
    $systemInfoHtml = @"
            <div class="system-info">
                <h2>Informations systeme</h2>
                <table>
                    <tr><td><strong>Nom de la machine</strong></td><td>$($system.ComputerName)</td></tr>
                    <tr><td><strong>Systeme d exploitation</strong></td><td>$($system.OSName)</td></tr>
                    <tr><td><strong>Version</strong></td><td>$($system.OSVersion) (Build $($system.OSBuild))</td></tr>
                    <tr><td><strong>Architecture</strong></td><td>$($system.OSArchitecture)</td></tr>
                    <tr><td><strong>Domaine</strong></td><td>$($system.Domain)</td></tr>
                    <tr><td><strong>PowerShell</strong></td><td>$($system.PowerShellVersion)</td></tr>
                    <tr><td><strong>Memoire</strong></td><td>$($system.TotalMemoryGB) Go</td></tr>
                    <tr><td><strong>Date d audit</strong></td><td>$($system.AuditDate)</td></tr>
                </table>
            </div>
"@

    # Recommendations
    $remediationCount = $failCount
    $recommendationsHtml = @"
            <div class="section">
                <h2>Recommandations</h2>
                <ul>
                    <li><strong>$($remediationCount) non-conformites</strong> identifiees necessitant une action corrective</li>
                    <li>Executer le script de remediation: <code>.\windows\Remediate-WindowsIssues.ps1 -ReportPath "$DataPath"</code></li>
                    <li>Planifier un audit regulier (recommandation: mensuel)</li>
                    <li>Consulter la documentation dans <code>docs/</code> pour plus de details</li>
                </ul>
            </div>
"@

    # Assembler le HTML complet
    $duration = ""
    if ($summary.Duration) {
        $ts = [TimeSpan]::new($summary.Duration.Ticks)
        $duration = "$($ts.Minutes)m $($ts.Seconds)s"
    }

    $html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #f0f2f5;
            color: #1a202c;
            line-height: 1.6;
            padding: 0;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }

        /* Header */
        .header {
            background: linear-gradient(135deg, #1a202c 0%, #2d3748 50%, #4a5568 100%);
            color: white;
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2.2em; font-weight: 700; margin-bottom: 8px; }
        .header .subtitle { color: #a0aec0; font-size: 1.1em; margin-bottom: 5px; }
        .header .meta { color: #718096; font-size: 0.85em; }

        /* Score */
        .score-section {
            background: white;
            border-radius: 16px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.07);
            text-align: center;
        }
        .gauge {
            width: 200px; height: 200px;
            border-radius: 50%;
            background: conic-gradient($scoreColor 0deg $($score*3.6)deg, #e2e8f0 $($score*3.6)deg 360deg);
            display: flex; align-items: center; justify-content: center;
            margin: 0 auto 20px;
            position: relative;
        }
        .gauge-inner {
            width: 155px; height: 155px;
            border-radius: 50%;
            background: white;
            display: flex; flex-direction: column;
            align-items: center; justify-content: center;
        }
        .gauge-value { font-size: 3em; font-weight: 800; line-height: 1; }
        .gauge-label { font-size: 0.9em; color: #718096; margin-top: 5px; }
        .gauge-desc { font-size: 1.1em; color: #4a5568; font-weight: 600; }

        /* Stats grid */
        .stats-grid {
            display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white; padding: 20px; border-radius: 12px;
            text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .stat-card .num { font-size: 2em; font-weight: 700; }
        .stat-card .lbl { font-size: 0.8em; color: #718096; margin-top: 5px; }
        .num-pass { color: #4caf50; }
        .num-fail { color: #f44336; }
        .num-warn { color: #ff9800; }
        .num-total { color: #2196f3; }

        /* Sections */
        .section {
            background: white; border-radius: 16px; padding: 25px 30px;
            margin-bottom: 25px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .section h2 {
            font-size: 1.4em; color: #2d3748; margin-bottom: 20px;
            padding-bottom: 10px; border-bottom: 2px solid #e2e8f0;
        }

        /* Tables */
        table { width: 100%; border-collapse: collapse; }
        th {
            background: #1a202c; color: white; padding: 12px 15px;
            text-align: left; font-size: 0.85em;
            text-transform: uppercase; letter-spacing: 0.5px;
        }
        td { padding: 10px 15px; border-bottom: 1px solid #e2e8f0; font-size: 0.9em; }
        tr:hover { background: #f7fafc; }
        .table-wrap { overflow-x: auto; }

        /* Badges */
        .badge {
            display: inline-block; padding: 3px 8px; border-radius: 4px;
            font-size: 0.8em; font-weight: 700; text-transform: uppercase;
        }
        .badge-pass { background: #c8e6c9; color: #2e7d32; }
        .badge-fail { background: #ffcdd2; color: #c62828; }
        .badge-warning { background: #ffe0b2; color: #e65100; }
        .badge-error { background: #f8bbd0; color: #880e4f; }
        .badge-info { background: #b3e5fc; color: #01579b; }
        .severity-c { background: #f44336; color: white; }
        .severity-h { background: #ff9800; color: white; }
        .severity-m { background: #2196f3; color: white; }
        .severity-l { background: #607d8b; color: white; }

        /* Mini bar */
        .mini-bar { height: 8px; background: #e2e8f0; border-radius: 4px; overflow: hidden; display: inline-block; width: 80px; margin-right: 8px; vertical-align: middle; }
        .mini-bar-fill { height: 100%; border-radius: 4px; }

        /* Alert */
        .alert { padding: 15px 20px; border-radius: 8px; margin: 10px 0; }
        .alert-danger { background: #fef2f2; border: 1px solid #fecaca; color: #dc2626; }
        .alert-success { background: #f0fdf4; border: 1px solid #bbf7d0; color: #16a34a; }
        .alert-warning { background: #fffbeb; border: 1px solid #fde68a; color: #d97706; }

        /* System info */
        .system-info table td { border: none; padding: 6px 15px; }
        .system-info table td:first-child { width: 250px; }

        /* Footer */
        .footer {
            text-align: center; padding: 30px; color: #a0aec0;
            font-size: 0.85em;
        }

        /* Responsive */
        @@media (max-width: 768px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .header { padding: 25px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>Security Hardening Toolkit</h1>
            <div class="subtitle">$Title</div>
            <div class="meta">
                $(if ($CompanyName) { "$CompanyName | " })Systeme: $($system.ComputerName) | Date: $($system.AuditDate)
            </div>
        </div>

        <!-- Score -->
        <div class="score-section">
            <div class="gauge">
                <div class="gauge-inner">
                    <div class="gauge-value" style="color:$scoreColor">$score%</div>
                    <div class="gauge-label">Score global</div>
                </div>
            </div>
            <div class="gauge-desc" style="color:$scoreColor">$scoreLabel</div>
            <p style="color:#718096;margin-top:10px">
                $passCount sur $($totalChecks - $summary.InfoCount) tests reussis
            </p>
        </div>

        <!-- Stats -->
        <div class="stats-grid">
            <div class="stat-card"><div class="num num-pass">$passCount</div><div class="lbl">PASS</div></div>
            <div class="stat-card"><div class="num num-fail">$failCount</div><div class="lbl">FAIL</div></div>
            <div class="stat-card"><div class="num num-warn">$warningCount</div><div class="lbl">WARNINGS</div></div>
            <div class="stat-card"><div class="num num-total">$totalChecks</div><div class="lbl">TOTAL</div></div>
            <div class="stat-card"><div class="num" style="color:#9c27b0">$($summary.Categories.Count)</div><div class="lbl">CATEGORIES</div></div>
        </div>

        <!-- System info -->
        $systemInfoHtml

        <!-- Categories -->
        <div class="section">
            <h2>Resultats par categorie</h2>
            <table>
                <thead>
                    <tr><th>Categorie</th><th>Pass</th><th>Fail</th><th>Warn</th><th>Score</th></tr>
                </thead>
                <tbody>
                    $catRows
                </tbody>
            </table>
        </div>

        <!-- Critical failures -->
        $criticalFailsHtml

        <!-- Recommendations -->
        $recommendationsHtml

        <!-- Detail results -->
        <div class="section">
            <h2>Details des verifications ($totalChecks tests)</h2>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Categorie</th>
                            <th>Description</th>
                            <th>Attendu</th>
                            <th>Actuel</th>
                            <th>Statut</th>
                            <th>Severite</th>
                            <th>Remediation</th>
                        </tr>
                    </thead>
                    <tbody>
                        $resultRows
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>Security Hardening Toolkit v1.0.0</p>
            <p>Developpe par Louis Denis RAZAFIMANDIMBY</p>
            <p>Genere le $($system.AuditDate) | Duree: $duration</p>
        </div>
    </div>
</body>
</html>
"@

    # Ecrire le fichier HTML
    $html | Out-File -FilePath $OutputPath -Encoding utf8

    Write-ColorOutput "Rapport genere avec succes: $OutputPath" -Color Green
    Write-ColorOutput "Score de conformite: $score% ($scoreLabel)" -Color $(
        if ($score -ge 80) { "Green" } elseif ($score -ge 60) { "Yellow" } else { "Red" }
    )

    # Ouvrir le rapport dans le navigateur par defaut
    try {
        Start-Process -FilePath $OutputPath -ErrorAction SilentlyContinue
        Write-ColorOutput "Ouverture du rapport dans le navigateur..." -Color Gray
    }
    catch {
        # Silently continue
    }
}

# ============================================================================
# EXECUTION PRINCIPALE
# ============================================================================

Write-ColorOutput "═══════════════════════════════════════════════════════════" -Color Cyan
Write-ColorOutput "  SECURITY HARDENING TOOLKIT - GENERATION DE RAPPORT" -Color White
Write-ColorOutput "═══════════════════════════════════════════════════════════" -Color Cyan
Write-ColorOutput "" -Color White

$reportData = Get-ReportData
New-HtmlReport -Data $reportData -OutputPath $OutputPath -Title $Title -CompanyName $CompanyName
