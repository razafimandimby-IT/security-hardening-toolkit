<#
.SYNOPSIS
    Corrige automatiquement les ecarts de securite identifies lors de l'audit Windows.

.DESCRIPTION
    Ce script lit les resultats d'un audit de conformite (format JSON) et applique
    automatiquement les remediations necessaires pour chaque verification echouee.
    Il genere un rapport de remediation indiquant les corrections appliquees.

.PARAMETER ReportPath
    Chemin vers le fichier JSON genere par Test-WindowsCompliance.ps1 contenant
    les resultats de l'audit.

.PARAMETER Categories
    Filtre la remediation par categories specifiques (ex: "AccountPolicies,Firewall").

.PARAMETER Severity
    Niveau de severite minimum a remedier (Critical, High, Medium, Low).

.PARAMETER LogPath
    Chemin du fichier de log de remediation.

.PARAMETER Backup
    Sauvegarde la configuration avant de la modifier.

.PARAMETER AutoRestart
    Redemarre le systeme automatiquement si necessaire.

.EXAMPLE
    .\Remediate-WindowsIssues.ps1 -ReportPath C:\Reports\audit-result.json
    Lit le rapport d'audit et applique toutes les remediations necessaires.

.EXAMPLE
    .\Remediate-WindowsIssues.ps1 -ReportPath .\audit.json -Categories "PasswordPolicy,AuditPolicy"
    Applique les remediations uniquement pour les categories specifiees.

.EXAMPLE
    .\Remediate-WindowsIssues.ps1 -ReportPath .\audit.json -Severity Critical -Backup
    Applique les remediations critiques uniquement avec sauvegarde prealable.

.NOTES
    Auteur  : Louis Denis RAZAFIMANDIMBY
    Version : 1.0.0
    Requiert : Windows Server 2016/2019/2022 ou Windows 10/11 (elevation admin)
    Depend de : Test-WindowsCompliance.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ReportPath,

    [Parameter(Mandatory=$false)]
    [string]$Categories = "*",

    [Parameter(Mandatory=$false)]
    [ValidateSet("Critical", "High", "Medium", "Low")]
    [string]$Severity = "Low",

    [Parameter(Mandatory=$false)]
    [string]$LogPath = "",

    [Parameter(Mandatory=$false)]
    [switch]$Backup = $true,

    [Parameter(Mandatory=$false)]
    [switch]$AutoRestart = $false
)

# ============================================================================
# INITIALISATION
# ============================================================================

$script:remediationResults = @()
$script:backupPath = ""

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    $colorMap = @{"INFO"="Cyan"; "WARNING"="Yellow"; "ERROR"="Red"; "SUCCESS"="Green"; "ACTION"="Magenta"}
    $color = if ($colorMap.ContainsKey($Level)) { $colorMap[$Level] } else { "White" }
    Write-Host $logMessage -ForegroundColor $color

    if ($script:logFile -and (Test-Path -Path $script:logFile)) {
        Add-Content -Path $script:logFile -Value $logMessage
    }
}

function Initialize-Environment {
    # Verification elevation
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "ERREUR : Ce script necessite des droits administrateur." -ForegroundColor Red
        exit 1
    }

    # Verification du fichier de rapport
    if (-not (Test-Path -Path $ReportPath)) {
        Write-Log "Fichier de rapport introuvable : $ReportPath" -Level ERROR
        exit 1
    }

    # Configuration du log
    if (-not $LogPath) {
        $script:logFile = Join-Path -Path $env:TEMP -ChildPath "Remediation-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    } else {
        $script:logFile = $LogPath
    }

    $logDir = Split-Path -Path $script:logFile -Parent
    if ($logDir -and -not (Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    New-Item -ItemType File -Path $script:logFile -Force | Out-Null

    Write-Log "=== Security Hardening Toolkit - Remediation ===" -Level INFO
    Write-Log "Rapport source : $ReportPath" -Level INFO
    Write-Log "Severite minimale : $Severity" -Level INFO

    # Chargement des resultats
    try {
        $script:auditResult = Get-Content -Path $ReportPath -Raw | ConvertFrom-Json
        Write-Log "Rapport charge avec succes : $($script:auditResult.results.Count) verifications" -Level SUCCESS
    }
    catch {
        Write-Log "Erreur lors du chargement du rapport : $($_.Exception.Message)" -Level ERROR
        exit 1
    }

    # Preparation du backup
    if ($Backup) {
        $script:backupPath = Join-Path -Path $env:SystemDrive -ChildPath "HardeningBackups\Remediation-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        New-Item -ItemType Directory -Path $script:backupPath -Force | Out-Null
        Write-Log "Sauvegarde dans : $script:backupPath" -Level INFO
    }
}

# ============================================================================
# FONCTIONS DE BACKUP
# ============================================================================

function Backup-RegistryKey {
    param([string]$KeyPath)
    if (-not $Backup -or -not (Test-Path -Path "Registry::$KeyPath")) { return }

    $backupFile = Join-Path -Path $script:backupPath -ChildPath "registry-$(Split-Path $KeyPath -Leaf).reg"
    try {
        & reg export $KeyPath $backupFile /y 2>&1 | Out-Null
        Write-Log "Registre sauvegarde : $KeyPath" -Level INFO
    }
    catch { Write-Log "Echec sauvegarde registre $KeyPath" -Level WARNING }
}

function Backup-ServiceState {
    param([string]$ServiceName)
    if (-not $Backup) { return }

    $backupFile = Join-Path -Path $script:backupPath -ChildPath "services-backup.csv"
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            "$ServiceName,$($svc.StartType),$($svc.Status)" | Out-File -FilePath $backupFile -Append
        }
    }
    catch { }
}

# ============================================================================
# FONCTIONS DE REMEDIATION
# ============================================================================

function Get-FailedChecks {
    <#
    .SYNOPSIS
        Recupere la liste des verifications echouees depuis le rapport d'audit.
    #>

    $failedChecks = $script:auditResult.results | Where-Object {
        $_.Status -eq "FAIL" -and
        ($Categories -eq "*" -or $_.Category -in ($Categories -split ',' | ForEach-Object { $_.Trim() }))
    }

    # Filtrer par severite
    $severityLevels = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3 }
    $minLevel = $severityLevels[$Severity]
    $failedChecks = $failedChecks | Where-Object {
        $level = $severityLevels[$_.Severity]
        $level -ge $minLevel
    }

    return $failedChecks
}

function Invoke-Remediation {
    <#
    .SYNOPSIS
        Execute la remediation pour un check echoue specifique.
    #>
    param(
        [string]$CheckId,
        [string]$Category,
        [string]$Description,
        [string]$Remediation
    )

    Write-Log "Remediation : $Description ($CheckId)" -Level ACTION

    try {
        switch -Wildcard ($CheckId) {
            # === Password Policy ===
            "1.1.*" {
                $infFile = Join-Path -Path $env:TEMP -ChildPath "remediation.inf"
                $sdbFile = Join-Path -Path $env:TEMP -ChildPath "remediation.sdb"

                Backup-RegistryKey -KeyPath "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"

                $infContent = @"
[Unicode]
Unicode=yes
[System Access]
"@
                switch ($CheckId) {
                    "1.1.1" { $infContent += "`nMinimumPasswordLength = $($script:auditResult.summary.config.password_min_length)" }
                    "1.1.2" { $infContent += "`nPasswordComplexity = 1" }
                    "1.1.3" { $infContent += "`nPasswordHistorySize = 24" }
                    "1.1.4" { $infContent += "`nMaximumPasswordAge = 60" }
                }
                $infContent += "`n[Version]`nsignature=`"`$CHICAGO$`"`nRevision=1"

                $infContent | Out-File -FilePath $infFile -Encoding ascii -Force
                & secedit /import /db $sdbFile /cfg $infFile 2>$null
                & secedit /configure /db $sdbFile /cfg $infFile /areas SECURITYPOLICY 2>$null

                Remove-Item $infFile -Force -ErrorAction SilentlyContinue
                Remove-Item $sdbFile -Force -ErrorAction SilentlyContinue

                Add-RemediationResult -CheckId $CheckId -Status "APPLIED" -Description $Description
            }

            # === Account Lockout ===
            "1.2.*" {
                $infFile = Join-Path -Path $env:TEMP -ChildPath "remediation_lockout.inf"
                $sdbFile = Join-Path -Path $env:TEMP -ChildPath "remediation_lockout.sdb"

                $infContent = @"
[Unicode]
Unicode=yes
[System Access]
"@
                switch ($CheckId) {
                    "1.2.1" { $infContent += "`nLockoutBadCount = 5" }
                    "1.2.2" { $infContent += "`nLockoutDuration = 30`nResetLockoutCount = 30" }
                }
                $infContent += "`n[Version]`nsignature=`"`$CHICAGO$`"`nRevision=1"

                $infContent | Out-File -FilePath $infFile -Encoding ascii -Force
                & secedit /import /db $sdbFile /cfg $infFile 2>$null
                & secedit /configure /db $sdbFile /cfg $infFile /areas SECURITYPOLICY 2>$null

                Remove-Item $infFile -Force -ErrorAction SilentlyContinue
                Remove-Item $sdbFile -Force -ErrorAction SilentlyContinue

                Add-RemediationResult -CheckId $CheckId -Status "APPLIED" -Description $Description
            }

            # === Audit Policy ===
            "2.1.*" {
                $subCategoryMap = @{
                    "2.1.1" = "Credential Validation"
                    "2.1.2" = "User Account Management"
                    "2.1.3" = "Security Group Management"
                    "2.1.4" = "Logon"
                    "2.1.5" = "Audit Policy Change"
                    "2.1.6" = "System Integrity"
                    "2.1.7" = "Sensitive Privilege Use"
                    "2.1.8" = "Process Creation"
                }

                $subCategory = $subCategoryMap[$CheckId]
                if ($subCategory) {
                    $expected = $Description -replace '.*Expected:\s*',''
                    $success = if ($expected -match "Success") { "enable" } else { "disable" }
                    $failure = if ($expected -match "Failure") { "enable" } else { "disable" }

                    & auditpol /set /subcategory:"$subCategory" /success:$success /failure:$failure 2>$null
                    Add-RemediationResult -CheckId $CheckId -Status "APPLIED" -Description $Description
                }
            }

            # === Windows Defender ===
            "3.1.*" {
                $defenderSettings = @{
                    "3.1.1" = @{Name="DisableRealtimeMonitoring"; Value=0}
                    "3.1.2" = @{Name="MAPSReporting"; Value=2}
                    "3.1.3" = @{Name="PUAProtection"; Value=1}
                    "3.1.4" = @{Name="DisableEmailScanning"; Value=0; Param="EnableEmailScanning"}
                    "3.1.5" = @{Name="DisableRemovableDriveScanning"; Value=0}
                    "3.1.6" = @{Name="EnableControlledFolderAccess"; Value=1}
                }

                if ($defenderSettings.ContainsKey($CheckId)) {
                    $setting = $defenderSettings[$CheckId]
                    $params = @{}
                    $params[$setting.Name] = $setting.Value
                    if ($setting.Param) { $params[$setting.Param] = $true }

                    Set-MpPreference @params -ErrorAction Stop
                    Add-RemediationResult -CheckId $CheckId -Status "APPLIED" -Description $Description
                }
            }

            # === Firewall ===
            "4.*" {
                # Activer le pare-feu pour tous les profils
                if ($Description -match "Actif") {
                    $profile = ($Description -split "-")[0].Trim()
                    if ($profile -match "Domain|Private|Public") {
                        Set-NetFirewallProfile -Name $profile -Enabled True -ErrorAction Stop
                    } else {
                        Set-NetFirewallProfile -All -Enabled True -ErrorAction Stop
                    }
                    Add-RemediationResult -CheckId $CheckId -Status "APPLIED" -Description $Description
                }
                # Configurer le comportement par defaut
                if ($Description -match "Entrant par defaut") {
                    $profile = ($Description -split "-")[0].Trim()
                    if ($profile -match "Domain|Private|Public") {
                        & netsh advfirewall set $profile firewallpolicy blockinbound,allowoutbound 2>$null
                    } else {
                        @("Domain", "Private", "Public") | ForEach-Object {
                            & netsh advfirewall set $_ firewallpolicy blockinbound,allowoutbound 2>$null
                        }
                    }
                    Add-RemediationResult -CheckId $CheckId -Status "APPLIED" -Description $Description
                }
            }

            # === Services ===
            "5.*" {
                $serviceName = $CheckId -replace "^5\.",""
                Backup-ServiceState -ServiceName $serviceName

                try {
                    Stop-Service -Name $serviceName -Force -ErrorAction Stop
                    Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop
                    Add-RemediationResult -CheckId $CheckId -Status "APPLIED" -Description $Description
                }
                catch {
                    Add-RemediationResult -CheckId $CheckId -Status "FAILED" -Description $Description -ErrorDetails $_.Exception.Message
                }
            }

            # === Registry ===
            "6.*" {
                $registryMap = @{
                    "6.1.1" = @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Value=1}
                    "6.1.2" = @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Value=2}
                    "6.2.1" = @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Value=5}
                    "6.2.2" = @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"; Value=1}
                    "6.2.3" = @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Value=1}
                    "6.2.4" = @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="NoLMHash"; Value=1}
                    "6.2.5" = @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LimitBlankPasswordUse"; Value=1}
                    "6.3.1" = @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="AutoDisconnect"; Value=15}
                    "6.3.2" = @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RestrictNullSessAccess"; Value=1}
                    "6.3.3" = @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="SMBServerNameHardeningLevel"; Value=1}
                    "6.4.1" = @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="UserAuthentication"; Value=1}
                    "6.4.2" = @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="SecurityLayer"; Value=2}
                    "6.4.3" = @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="MinEncryptionLevel"; Value=3}
                    "6.5.1" = @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableICMPRedirect"; Value=0}
                    "6.5.2" = @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="DisableIPSourceRouting"; Value=2}
                    "6.5.3" = @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="SynAttackProtect"; Value=1}
                    "6.5.4" = @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableDeadGWDetect"; Value=0}
                }

                if ($registryMap.ContainsKey($CheckId)) {
                    $reg = $registryMap[$CheckId]
                    Backup-RegistryKey -KeyPath $reg.Path

                    if (-not (Test-Path -Path $reg.Path)) {
                        $parent = Split-Path -Path $reg.Path -Parent
                        $leaf = Split-Path -Path $reg.Path -Leaf
                        New-Item -Path $parent -Name $leaf -Force | Out-Null
                    }
                    Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Type DWord -Force
                    Add-RemediationResult -CheckId $CheckId -Status "APPLIED" -Description $Description
                }
            }

            # === Logging ===
            "7.1.*" {
                $loggingMap = @{
                    "7.1.1" = @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name="EnableScriptBlockLogging"; Value=1}
                    "7.1.2" = @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; Name="EnableModuleLogging"; Value=1}
                    "7.1.3" = @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\PowerShellTranscription"; Name="EnableTranscripting"; Value=1}
                    "7.1.4" = @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"; Name="MaxSize"; Value=2097152}
                }

                if ($loggingMap.ContainsKey($CheckId)) {
                    $reg = $loggingMap[$CheckId]
                    Backup-RegistryKey -KeyPath $reg.Path

                    if (-not (Test-Path -Path $reg.Path)) {
                        $parent = Split-Path -Path $reg.Path -Parent
                        $leaf = Split-Path -Path $reg.Path -Leaf
                        New-Item -Path $parent -Name $leaf -Force | Out-Null
                    }
                    Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Type DWord -Force
                    Add-RemediationResult -CheckId $CheckId -Status "APPLIED" -Description $Description
                }
            }

            # === SMB ===
            "8.1.*" {
                if ($CheckId -eq "8.1.1") {
                    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
                    Add-RemediationResult -CheckId $CheckId -Status "APPLIED" -Description $Description
                }
                if ($CheckId -eq "8.1.2") {
                    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
                    Add-RemediationResult -CheckId $CheckId -Status "APPLIED" -Description $Description
                }
            }

            default {
                Add-RemediationResult -CheckId $CheckId -Status "SKIPPED" -Description $Description
                Write-Log "Aucune remediation automatique disponible pour $CheckId" -Level WARNING
            }
        }
    }
    catch {
        Write-Log "Erreur lors de la remediation $CheckId : $($_.Exception.Message)" -Level ERROR
        Add-RemediationResult -CheckId $CheckId -Status "FAILED" -Description $Description -ErrorDetails $_.Exception.Message
    }
}

function Add-RemediationResult {
    param(
        [string]$CheckId,
        [string]$Status,
        [string]$Description,
        [string]$ErrorDetails = ""
    )

    $result = [PSCustomObject]@{
        CheckId = $CheckId
        Description = $Description
        Status = $Status
        ErrorDetails = $ErrorDetails
        RemediationDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }

    $script:remediationResults += $result

    $statusColor = switch ($Status) {
        "APPLIED" { "Green" }
        "SKIPPED" { "Yellow" }
        "FAILED"  { "Red" }
        default   { "Gray" }
    }

    Write-Host "  [$Status] $CheckId - $Description" -ForegroundColor $statusColor
}

# ============================================================================
# RAPPORT DE REMEDIATION
# ============================================================================

function Show-RemediationSummary {
    Write-Host " " -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "           RESUME DE LA REMEDIATION" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

    $total = $script:remediationResults.Count
    $applied = ($script:remediationResults | Where-Object { $_.Status -eq "APPLIED" }).Count
    $skipped = ($script:remediationResults | Where-Object { $_.Status -eq "SKIPPED" }).Count
    $failed = ($script:remediationResults | Where-Object { $_.Status -eq "FAILED" }).Count

    Write-Host "  Total des corrections necessaires : $total" -ForegroundColor White
    Write-Host "  Appliquees avec succes          : $applied" -ForegroundColor Green
    Write-Host "  Ignorees (non automatisees)     : $skipped" -ForegroundColor Yellow
    Write-Host "  En erreur                        : $failed" -ForegroundColor Red

    if ($failed -gt 0) {
        Write-Host " " -ForegroundColor White
        Write-Host "REMEDIATIONS EN ERREUR :" -ForegroundColor Red
        foreach ($fail in ($script:remediationResults | Where-Object { $_.Status -eq "FAILED" })) {
            Write-Host "  [x] $($fail.CheckId) - $($fail.Description)" -ForegroundColor Red
            Write-Host "      Erreur : $($fail.ErrorDetails)" -ForegroundColor Yellow
        }
    }

    if ($Backup) {
        Write-Host " " -ForegroundColor White
        Write-Host "Sauvegarde disponible dans : $script:backupPath" -ForegroundColor Gray
    }

    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

    # Recommander un redemarrage si des modifications critiques ont ete appliquees
    if ($applied -gt 0) {
        Write-Host " " -ForegroundColor White
        Write-Host "Recommandation : Un redemarrage est recommande pour appliquer" -ForegroundColor Yellow
        Write-Host "toutes les modifications de securite." -ForegroundColor Yellow

        if ($AutoRestart) {
            Write-Host "Redemarrage automatique dans 30 secondes..." -ForegroundColor Red
            shutdown /r /t 30 /c "Redemarrage pour appliquer les remediations de securite"
        }
    }
}

# ============================================================================
# POINT D'ENTREE
# ============================================================================

Write-Host "██████████████████████████████████████████████████████████████" -ForegroundColor Cyan
Write-Host "██       SECURITY HARDENING TOOLKIT - REMEDIATION          ██" -ForegroundColor White
Write-Host "██████████████████████████████████████████████████████████████" -ForegroundColor Cyan
Write-Host " " -ForegroundColor White

Initialize-Environment

# Recuperer les checks en echec
$failedChecks = Get-FailedChecks

if ($failedChecks.Count -eq 0) {
    Write-Log "Aucune non-conformite a remedier pour les criteres selectionnes." -Level SUCCESS
    exit 0
}

Write-Log "$($failedChecks.Count) non-conformites identifiees a corriger" -Level WARNING

# Confirmation
Write-Host " " -ForegroundColor Yellow
Write-Host "Ces modifications vont modifier la configuration du systeme." -ForegroundColor Yellow
$confirmation = Read-Host "Voulez-vous continuer ? (O/N)"
if ($confirmation -notmatch "^(O|o)$") {
    Write-Log "Remediation annulee par l'utilisateur." -Level WARNING
    exit 0
}

Write-Host " " -ForegroundColor White
Write-Host "Demarrage de la remediation..." -ForegroundColor Cyan

# Appliquer les remediations
foreach ($check in $failedChecks) {
    Invoke-Remediation -CheckId $check.CheckId -Category $check.Category `
        -Description $check.Description -Remediation $check.Remediation
}

# Afficher le resume
Show-RemediationSummary

Write-Log "Remediation terminee." -Level SUCCESS
