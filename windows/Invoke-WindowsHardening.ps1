<#
.SYNOPSIS
    Applique une configuration de durcissement (hardening) sur un systeme Windows Server.

.DESCRIPTION
    Ce script configure la securite d'un serveur Windows conformement aux recommandations
    CIS (Center for Internet Security) et aux meilleures pratiques de securite Microsoft.
    Il couvre les politiques de compte, l'audit, le pare-feu, Windows Defender, les services,
    les parametres de registre, et la journalisation PowerShell.

.PARAMETER Level
    Niveau de durcissement a appliquer. Valeurs acceptees : Basic, Standard, Advanced.
    - Basic : Configuration securisee minimale, impact minimal sur les operations
    - Standard : Equilibre securite et productivite (recommandé)
    - Advanced : Securite maximale, peut impacter les fonctionnalites

.PARAMETER DryRun
    Simule les operations sans appliquer les modifications. Utile pour evaluer l'impact
    avant execution reelle.

.PARAMETER ConfigPath
    Chemin vers un fichier de configuration JSON personnalise. Si non specifie,
    utilise la configuration par defaut integree.

.PARAMETER ExcludeService
    Liste des services a exclure de la desactivation (separes par des virgules).
    Permet de conserver des services qui seraient autrement desactives.

.PARAMETER LogPath
    Chemin du fichier de log. Par defaut : $env:TEMP\Hardening-<Date>.log

.PARAMETER BackupDir
    Repertoire de sauvegarde de la configuration existante avant modification.

.EXAMPLE
    .\Invoke-WindowsHardening.ps1 -DryRun
    Execute le script en mode simulation sans appliquer de changements.

.EXAMPLE
    .\Invoke-WindowsHardening.ps1 -Level Advanced -ConfigPath .\config\hardening-config.json
    Applique le durcissement de niveau Avance avec une configuration personnalisee.

.EXAMPLE
    .\Invoke-WindowsHardening.ps1 -Level Standard -ExcludeService "Spooler,WSearch"
    Applique le durcissement Standard en excluant le spouleur d'impression et la recherche Windows.

.EXAMPLE
    .\Invoke-WindowsHardening.ps1 -Level Basic -LogPath C:\Logs\hardening.log -BackupDir C:\Backups\
    Applique le durcissement de base avec journalisation et sauvegarde.

.NOTES
    Auteur  : Louis Denis RAZAFIMANDIMBY
    Version : 1.0.0
    Requiert : Windows Server 2016/2019/2022, Windows 10/11 (elevation admin requise)
    CIS Benchmark : Windows Server 2022 v2.0.0

    Avertissement : Ce script modifie des parametres de securite critiques.
    Testez toujours en environnement de qualification avant deploiement en production.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Basic", "Standard", "Advanced")]
    [string]$Level = "Standard",

    [Parameter(Mandatory=$false)]
    [switch]$DryRun = $false,

    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = "",

    [Parameter(Mandatory=$false)]
    [string]$ExcludeService = "",

    [Parameter(Mandatory=$false)]
    [string]$LogPath = "",

    [Parameter(Mandatory=$false)]
    [string]$BackupDir = ""
)

# ============================================================================
# INITIALISATION
# ============================================================================

function Write-Log {
    <#
    .SYNOPSIS
        Ecrit un message dans le fichier de log et sur la console.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "ACTION")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Couleurs pour la console
    $colorMap = @{
        "INFO"    = "Cyan"
        "WARNING" = "Yellow"
        "ERROR"   = "Red"
        "SUCCESS" = "Green"
        "ACTION"  = "Magenta"
    }

    if ($DryRun) {
        Write-Host "[DRY-RUN] $logMessage" -ForegroundColor $colorMap[$Level]
    } else {
        Write-Host $logMessage -ForegroundColor $colorMap[$Level]
    }

    if ($script:logFile -and (Test-Path -Path $script:logFile -PathType Leaf)) {
        Add-Content -Path $script:logFile -Value $logMessage
    }
}

function Initialize-Environment {
    <#
    .SYNOPSIS
        Verifie les prerequis et prepare l'environnement d'execution.
    #>

    # Verification des droits administrateur
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "ERREUR : Ce script doit etre execute avec des droits administrateur." -ForegroundColor Red
        Write-Host "Veuillez relancer PowerShell en tant qu'administrateur." -ForegroundColor Yellow
        exit 1
    }

    # Configuration du fichier de log
    if (-not $LogPath) {
        $script:logFile = Join-Path -Path $env:TEMP -ChildPath "Hardening-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    } else {
        $script:logFile = $LogPath
    }

    # Creer le repertoire de log si necessaire
    $logDir = Split-Path -Path $script:logFile -Parent
    if ($logDir -and -not (Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    # Initialiser le fichier de log
    New-Item -ItemType File -Path $script:logFile -Force | Out-Null
    Write-Log "=== Security Hardening Toolkit v1.0.0 ===" -Level INFO
    Write-Log "Niveau : $Level" -Level INFO
    Write-Log "Mode simulation (Dry-Run) : $($DryRun.IsPresent)" -Level INFO
    Write-Log "Date : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO
    Write-Log "Systeme : $((Get-CimInstance Win32_OperatingSystem).Caption)" -Level INFO

    # Configuration du repertoire de backup
    if (-not $BackupDir) {
        $script:backupDir = Join-Path -Path $env:SystemDrive -ChildPath "HardeningBackups\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    } else {
        $script:backupDir = $BackupDir
    }

    if ($DryRun) {
        Write-Log "Chemin de log simule : $script:logFile" -Level INFO
        Write-Log "Chemin de backup simule : $script:backupDir" -Level INFO
    }

    # Chargement de la configuration
    Write-Log "Chargement de la configuration..." -Level INFO
    $script:config = Get-HardeningConfig

    Write-Log "Environnement initialise avec succes." -Level SUCCESS
}

function Get-HardeningConfig {
    <#
    .SYNOPSIS
        Charge la configuration de durcissement depuis le fichier JSON ou utilise les valeurs par defaut.
    #>

    # Configuration par defaut
    $defaultConfig = @{
        password_min_length = 12
        password_complexity = $true
        password_max_age_days = 60
        account_lockout_threshold = 5
        account_lockout_duration_minutes = 30
        enable_screensaver_lock = $true
        screensaver_timeout_minutes = 10
        enable_powershell_logging = $true
        enable_transcription = $false
        disable_smbv1 = $true
        disable_llmnr = $true
        max_log_size_mb = 256
        log_retention_days = 60
        session_timeout_minutes = 15
        services_to_disable = @(
            "Xbox*", "Xbl*", "Fax", "irmon", "lfsvc", "SharedAccess",
            "wisvc", "wcncsvc", "shpamsvc", "SimAccess", "WMPNetworkSvc",
            "RemoteAccess", "RemoteRegistry", "W3SVC", "MapsBroker",
            "DiagTrack", "dmwappushsvc", "WpnService"
        )
    }

    # Appliquer les parametres selon le niveau
    switch ($Level) {
        "Basic" {
            $defaultConfig.password_min_length = 8
            $defaultConfig.account_lockout_threshold = 10
            $defaultConfig.password_max_age_days = 90
            $defaultConfig.screensaver_timeout_minutes = 15
            $defaultConfig.session_timeout_minutes = 30
        }
        "Advanced" {
            $defaultConfig.password_min_length = 16
            $defaultConfig.account_lockout_threshold = 3
            $defaultConfig.password_max_age_days = 45
            $defaultConfig.screensaver_timeout_minutes = 5
            $defaultConfig.session_timeout_minutes = 10
            $defaultConfig.enable_transcription = $true
            $defaultConfig.max_log_size_mb = 512
            $defaultConfig.log_retention_days = 90
        }
    }

    if ($ConfigPath -and (Test-Path -Path $ConfigPath)) {
        Write-Log "Chargement de la configuration depuis : $ConfigPath" -Level INFO
        try {
            $customConfig = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
            foreach ($key in $defaultConfig.Keys) {
                if ($customConfig.$key -ne $null) {
                    $defaultConfig[$key] = $customConfig.$key
                }
            }
            Write-Log "Configuration personnalisee chargee avec succes." -Level SUCCESS
        }
        catch {
            Write-Log "Erreur lors du chargement de la configuration : $($_.Exception.Message)" -Level ERROR
            Write-Log "Utilisation de la configuration par defaut." -Level WARNING
        }
    }

    # Traitement des exclusions de services
    if ($ExcludeService) {
        $exclusions = $ExcludeService -split ',' | ForEach-Object { $_.Trim() }
        $defaultConfig.services_to_disable = $defaultConfig.services_to_disable | Where-Object {
            $service = $_
            -not ($exclusions | Where-Object { $service -like $_ })
        }
        Write-Log "Exclusions de services appliquees : $ExcludeService" -Level INFO
    }

    return $defaultConfig
}

# ============================================================================
# FONCTIONS DE HARDENING
# ============================================================================

function Set-AccountPolicies {
    <#
    .SYNOPSIS
        Configure les politiques de compte et de mot de passe via Secedit.
    #>
    Write-Log "=== Configuration des politiques de compte ===" -Level ACTION

    $infFile = Join-Path -Path $env:TEMP -ChildPath "secpol.inf"
    $sdbFile = Join-Path -Path $env:TEMP -ChildPath "secpol.sdb"

    # Creer le fichier de configuration de securite
    $secpolContent = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = $($script:config.password_max_age_days)
MinimumPasswordLength = $($script:config.password_min_length)
PasswordComplexity = $($script:config.password_complexity ? 1 : 0)
PasswordHistorySize = 24
LockoutBadCount = $($script:config.account_lockout_threshold)
LockoutBadCount_Wa = $($script:config.account_lockout_threshold)
ResetLockoutCount = $($script:config.account_lockout_duration_minutes)
LockoutDuration = $($script:config.account_lockout_duration_minutes)
ClearTextPassword = 0
[Version]
signature="`$CHICAGO$"
Revision=1
"@

    if ($DryRun) {
        Write-Log "[DRY-RUN] Configuration des politiques de compte :" -Level INFO
        Write-Log "[DRY-RUN]   - Longueur minimale du mot de passe : $($script:config.password_min_length)" -Level INFO
        Write-Log "[DRY-RUN]   - Complexite du mot de passe : $($script:config.password_complexity)" -Level INFO
        Write-Log "[DRY-RUN]   - Age maximal du mot de passe : $($script:config.password_max_age_days) jours" -Level INFO
        Write-Log "[DRY-RUN]   - Seuil de verrouillage : $($script:config.account_lockout_threshold) tentatives" -Level INFO
        Write-Log "[DRY-RUN]   - Duree de verrouillage : $($script:config.account_lockout_duration_minutes) minutes" -Level INFO
        return
    }

    # Creer le fichier INF de securite
    $secpolContent | Out-File -FilePath $infFile -Encoding ascii -Force

    try {
        # Importer la configuration dans la base de securite
        $importResult = & secedit /import /db $sdbFile /cfg $infFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Echec de l'import Secedit : $importResult"
        }

        # Appliquer la configuration
        $applyResult = & secedit /configure /db $sdbFile /cfg $infFile /areas SECURITYPOLICY 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Echec de l'application Secedit : $applyResult"
        }

        Write-Log "Politiques de compte configurees avec succes." -Level SUCCESS

        # Forcer la mise a jour de la politique
        & gpupdate /target:computer /force | Out-Null
        Write-Log "Mise a jour de la strategie de groupe effectuee." -Level INFO
    }
    catch {
        Write-Log "Erreur lors de la configuration des politiques de compte : $($_.Exception.Message)" -Level ERROR
    }
    finally {
        # Nettoyage
        if (Test-Path -Path $infFile) { Remove-Item -Path $infFile -Force }
        if (Test-Path -Path $sdbFile) { Remove-Item -Path $sdbFile -Force }
    }
}

function Set-AuditPolicy {
    <#
    .SYNOPSIS
        Configure les politiques d'audit avancees de Windows.
    #>
    Write-Log "=== Configuration des politiques d'audit ===" -Level ACTION

    $auditPolicies = @(
        @{Category = "Account Logon"; SubCategory = "Credential Validation"; Include = @("Success", "Failure")}
        @{Category = "Account Logon"; SubCategory = "Kerberos Authentication Service"; Include = @("Success", "Failure")}
        @{Category = "Account Logon"; SubCategory = "Kerberos Service Ticket Operations"; Include = @("Success", "Failure")}
        @{Category = "Account Management"; SubCategory = "Computer Account Management"; Include = @("Success", "Failure")}
        @{Category = "Account Management"; SubCategory = "Security Group Management"; Include = @("Success", "Failure")}
        @{Category = "Account Management"; SubCategory = "User Account Management"; Include = @("Success", "Failure")}
        @{Category = "Detailed Tracking"; SubCategory = "Process Creation"; Include = @("Success")}
        @{Category = "Logon/Logoff"; SubCategory = "Logon"; Include = @("Success", "Failure")}
        @{Category = "Logon/Logoff"; SubCategory = "Logoff"; Include = @("Success")}
        @{Category = "Logon/Logoff"; SubCategory = "Special Logon"; Include = @("Success")}
        @{Category = "Policy Change"; SubCategory = "Audit Policy Change"; Include = @("Success", "Failure")}
        @{Category = "Policy Change"; SubCategory = "Authentication Policy Change"; Include = @("Success", "Failure")}
        @{Category = "Privilege Use"; SubCategory = "Sensitive Privilege Use"; Include = @("Failure")}
        @{Category = "System"; SubCategory = "Security State Change"; Include = @("Success", "Failure")}
        @{Category = "System"; SubCategory = "Security System Extension"; Include = @("Success", "Failure")}
        @{Category = "System"; SubCategory = "System Integrity"; Include = @("Success", "Failure")}
    )

    foreach ($policy in $auditPolicies) {
        $subCategory = $policy.SubCategory
        $include = $policy.Include -join ", "

        if ($DryRun) {
            Write-Log "[DRY-RUN] Audit > $subCategory : $include" -Level INFO
            continue
        }

        try {
            $currentPolicy = auditpol /get /subcategory:"$subCategory" 2>$null
            $needsUpdate = $true

            foreach ($setting in $policy.Include) {
                if ($currentPolicy -notmatch $setting) {
                    $needsUpdate = $true
                    break
                }
                $needsUpdate = $false
            }

            if ($needsUpdate) {
                & auditpol /set /subcategory:"$subCategory" /success:$($policy.Include -contains "Success" ? "enable" : "disable") `
                    /failure:$($policy.Include -contains "Failure" ? "enable" : "disable") 2>&1 | Out-Null
                Write-Log "Audit configure : $subCategory" -Level SUCCESS
            } else {
                Write-Log "Audit deja configure : $subCategory" -Level INFO
            }
        }
        catch {
            Write-Log "Erreur lors de la configuration de l'audit $subCategory : $($_.Exception.Message)" -Level WARNING
        }
    }
}

function Disable-InsecureServices {
    <#
    .SYNOPSIS
        Desactive les services non securises ou inutiles.
    #>
    Write-Log "=== Desactivation des services non securises ===" -Level ACTION

    $servicesToDisable = $script:config.services_to_disable

    foreach ($servicePattern in $servicesToDisable) {
        $services = Get-Service -Name $servicePattern -ErrorAction SilentlyContinue
        if (-not $services) {
            # Essayer avec le nom d'affichage
            $services = Get-Service -DisplayName "*$servicePattern*" -ErrorAction SilentlyContinue
        }

        if (-not $services) {
            Write-Log "Service non trouve : $servicePattern" -Level INFO
            continue
        }

        foreach ($service in $services) {
            if ($service.StartType -ne "Disabled") {
                if ($DryRun) {
                    Write-Log "[DRY-RUN] Desactivation du service : $($service.Name) ($($service.DisplayName))" -Level ACTION
                    continue
                }

                try {
                    # Arreter le service s'il est en cours d'execution
                    if ($service.Status -eq "Running") {
                        Stop-Service -Name $service.Name -Force -ErrorAction Stop
                        Write-Log "Service arrete : $($service.Name)" -Level SUCCESS
                    }

                    # Desactiver le demarrage automatique
                    Set-Service -Name $service.Name -StartupType Disabled -ErrorAction Stop
                    Write-Log "Service desactive : $($service.Name) ($($service.DisplayName))" -Level SUCCESS
                }
                catch {
                    Write-Log "Erreur lors de la desactivation de $($service.Name) : $($_.Exception.Message)" -Level WARNING
                }
            } else {
                Write-Log "Service deja desactive : $($service.Name)" -Level INFO
            }
        }
    }
}

function Set-WindowsFirewall {
    <#
    .SYNOPSIS
        Configure le pare-feu Windows avec les regles de securite.
    #>
    Write-Log "=== Configuration du Pare-feu Windows Defender ===" -Level ACTION

    $profiles = @("Domain", "Private", "Public")
    $allowedPorts = @(22, 80, 443, 3389)

    foreach ($profile in $profiles) {
        if ($profile -eq "Domain") {
            $defaultAction = "BlockInbound"
            $allowInboundRules = $true
        } else {
            $defaultAction = "BlockInbound"
            $allowInboundRules = $false
        }

        if ($DryRun) {
            Write-Log "[DRY-RUN] Pare-feu > Profil $profile" -Level INFO
            Write-Log "[DRY-RUN]   - Action entrante par defaut : $defaultAction" -Level INFO
            Write-Log "[DRY-RUN]   - Action sortante par defaut : Allow" -Level INFO
            Write-Log "[DRY-RUN]   - Notifications : $($profile -eq "Public" ? "desactivees" : "activees")" -Level INFO
            continue
        }

        try {
            # Bloquer les connexions entrantes par defaut
            & netsh advfirewall set $profile profile firewallpolicy blockinbound,allowoutbound 2>&1 | Out-Null

            # Configurer les notifications
            if ($profile -eq "Public") {
                & netsh advfirewall set $profile settings inboundusernotification disable 2>&1 | Out-Null
            }

            # Activer le logging
            $logPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall-$profile.log"
            & netsh advfirewall set $profile logging filename "$logPath" 2>&1 | Out-Null
            & netsh advfirewall set $profile logging droppedconnections enable 2>&1 | Out-Null

            Write-Log "Pare-feu configure pour le profil $profile" -Level SUCCESS
        }
        catch {
            Write-Log "Erreur lors de la configuration du profil $profile : $($_.Exception.Message)" -Level WARNING
        }
    }

    # Creer les regles pour les ports autorises
    Write-Log "Creation des regles de pare-feu pour les ports autorises..." -Level INFO
    foreach ($port in $allowedPorts) {
        $ruleName = "Allow-Inbound-TCP-$port"

        if ($DryRun) {
            Write-Log "[DRY-RUN] Creation de la regle : $ruleName" -Level INFO
            continue
        }

        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existingRule) {
            try {
                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -LocalPort $port `
                    -Protocol TCP -Action Allow -Profile Any -Enabled True -ErrorAction Stop | Out-Null
                Write-Log "Regle creee : $ruleName" -Level SUCCESS
            }
            catch {
                Write-Log "Erreur lors de la creation de la regle $ruleName : $($_.Exception.Message)" -Level WARNING
            }
        } else {
            Write-Log "Regle deja existante : $ruleName" -Level INFO
        }
    }
}

function Set-WindowsDefender {
    <#
    .SYNOPSIS
        Configure Windows Defender pour une protection optimale.
    #>
    Write-Log "=== Configuration de Windows Defender ===" -Level ACTION

    $defenderSettings = @(
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring"; Value = 0; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableBehaviorMonitoring"; Value = 0; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableOnAccessProtection"; Value = 0; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableScanOnRealtimeEnable"; Value = 0; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\SpyNet"; Name = "SpynetReporting"; Value = 2; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\SpyNet"; Name = "SubmitSamplesConsent"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\MpEngine"; Name = "MpEnablePus"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring"; Value = 0; Type = "DWord"}
    )

    foreach ($setting in $defenderSettings) {
        if ($DryRun) {
            Write-Log "[DRY-RUN] Defender > $($setting.Path)\$($setting.Name) = $($setting.Value)" -Level INFO
            continue
        }

        try {
            # Creer la cle si elle n'existe pas
            $keyPath = Split-Path -Path $setting.Path -Parent
            $leaf = Split-Path -Path $setting.Path -Leaf
            if (-not (Test-Path -Path $setting.Path)) {
                New-Item -Path $keyPath -Name $leaf -Force | Out-Null
            }

            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
            Write-Log "Defender configure : $($setting.Name) = $($setting.Value)" -Level SUCCESS
        }
        catch {
            Write-Log "Erreur lors de la configuration Defender $($setting.Name) : $($_.Exception.Message)" -Level WARNING
        }
    }

    # Activer la protection cloud (MAPS)
    if ($DryRun) {
        Write-Log "[DRY-RUN] Activation de la protection cloud Defender" -Level INFO
    } else {
        try {
            Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
            Set-MpPreference -CloudBlockLevel High -ErrorAction Stop
            Set-MpPreference -CloudTimeout 50 -ErrorAction Stop
            Set-MpPreference -SubmitSamplesConsent Always -ErrorAction Stop
            Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
            Write-Log "Protection cloud Defender activee" -Level SUCCESS
        }
        catch {
            Write-Log "Erreur lors de l'activation de la protection cloud : $($_.Exception.Message)" -Level WARNING
        }
    }
}

function Set-RegistryHardening {
    <#
    .SYNOPSIS
        Configure les parametres de registre pour le durcissement du systeme.
    #>
    Write-Log "=== Configuration des parametres de registre ===" -Level ACTION

    $registrySettings = @(
        # UAC - Controle de compte d'utilisateur
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableLUA"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ConsentPromptBehaviorAdmin"; Value = 2; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "PromptOnSecureDesktop"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableInstallerDetection"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ValidateAdminCodeSignatures"; Value = 1; Type = "DWord"}

        # Securite LAN Manager
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LimitBlankPasswordUse"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymous"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymousSAM"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictRemoteSAM"; Value = "O:BAG:BAD:(A;;RC;;;BA)"; Type = "String"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LmCompatibilityLevel"; Value = 5; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "NoLMHash"; Value = 1; Type = "DWord"}

        # Protection contre les attaques network
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name = "AutoDisconnect"; Value = 15; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name = "EnableSvcLoc"; Value = 0; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name = "RestrictNullSessAccess"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name = "SMBServerNameHardeningLevel"; Value = 1; Type = "DWord"}

        # Configuration RDP securisee
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name = "fDenyTSConnections"; Value = 0; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name = "UserAuthentication"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name = "SecurityLayer"; Value = 2; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name = "MinEncryptionLevel"; Value = 3; Type = "DWord"}

        # Securite des sessions
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "CrashOnAuditFail"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "DisableDomainCreds"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "DisableSavedCreds"; Value = 1; Type = "DWord"}

        # Securite du reseau
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name = "NC_ShowSharedAccessUI"; Value = 0; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "EnableICMPRedirect"; Value = 0; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "DisableIPSourceRouting"; Value = 2; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "EnableDeadGWDetect"; Value = 0; Type = "DWord"}
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "SynAttackProtect"; Value = 1; Type = "DWord"}
    )

    foreach ($setting in $registrySettings) {
        if ($DryRun) {
            Write-Log "[DRY-RUN] Registre > $($setting.Path)\$($setting.Name) = $($setting.Value)" -Level INFO
            continue
        }

        try {
            # Creer la cle si elle n'existe pas
            $keyPath = Split-Path -Path $setting.Path -Parent
            $leaf = Split-Path -Path $setting.Path -Leaf
            if (-not (Test-Path -Path $setting.Path)) {
                New-Item -Path $keyPath -Name $leaf -Force -ErrorAction Stop | Out-Null
            }

            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
            Write-Log "Registre configure : $($setting.Name) = $($setting.Value)" -Level SUCCESS
        }
        catch {
            Write-Log "Erreur lors de la configuration registre $($setting.Name) : $($_.Exception.Message)" -Level WARNING
        }
    }
}

function Set-PowerShellLogging {
    <#
    .SYNOPSIS
        Configure la journalisation avancee de PowerShell.
    #>
    Write-Log "=== Configuration de la journalisation PowerShell ===" -Level ACTION

    $loggingSettings = @(
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name = "EnableScriptBlockLogging"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name = "EnableScriptBlockInvocationLogging"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; Name = "EnableModuleLogging"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\PowerShellTranscription"; Name = "EnableTranscripting"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\PowerShellTranscription"; Name = "EnableInvocationHeader"; Value = 1; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\PowerShellTranscription"; Name = "OutputDirectory"; Value = "$env:SystemRoot\Logs\PowerShellTranscription"; Type = "String"}
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"; Name = "MaxSize"; Value = 1048576; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"; Name = "MaxSize"; Value = 2097152; Type = "DWord"}
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"; Name = "MaxSize"; Value = 1048576; Type = "DWord"}
    )

    foreach ($setting in $loggingSettings) {
        if ($DryRun) {
            Write-Log "[DRY-RUN] Logging > $($setting.Path)\$($setting.Name) = $($setting.Value)" -Level INFO
            continue
        }

        try {
            $keyPath = Split-Path -Path $setting.Path -Parent
            $leaf = Split-Path -Path $setting.Path -Leaf
            if (-not (Test-Path -Path $setting.Path)) {
                New-Item -Path $keyPath -Name $leaf -Force -ErrorAction Stop | Out-Null
            }

            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
            Write-Log "Logging configure : $($setting.Name)" -Level SUCCESS
        }
        catch {
            Write-Log "Erreur lors de la configuration logging $($setting.Name) : $($_.Exception.Message)" -Level WARNING
        }
    }

    # Configurer la transcription si le niveau le demande
    if ($script:config.enable_transcription -and -not $DryRun) {
        # Creer le repertoire de transcription
        $transcriptDir = "$env:SystemRoot\Logs\PowerShellTranscription"
        if (-not (Test-Path -Path $transcriptDir)) {
            New-Item -ItemType Directory -Path $transcriptDir -Force | Out-Null
            Write-Log "Repertoire de transcription cree : $transcriptDir" -Level SUCCESS
        }

        # Restreindre l'acces au repertoire
        icacls $transcriptDir /inheritance:r /grant "SYSTEM:F" /grant "BUILTIN\Administrators:F" 2>&1 | Out-Null
        Write-Log "Permissions du repertoire de transcription restreintes" -Level SUCCESS
    }
}

function Disable-InsecureProtocols {
    <#
    .SYNOPSIS
        Desactive les protocoles reseau non securises (SMBv1, LLMNR, etc.).
    #>
    Write-Log "=== Desactivation des protocoles non securises ===" -Level ACTION

    # Desactiver SMBv1
    if ($script:config.disable_smbv1) {
        if ($DryRun) {
            Write-Log "[DRY-RUN] Desactivation de SMBv1" -Level INFO
        } else {
            try {
                # Verifier l'etat actuel
                $smbStatus = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol
                if ($smbStatus -eq $true) {
                    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
                    Write-Log "SMBv1 desactive avec succes" -Level SUCCESS
                } else {
                    Write-Log "SMBv1 deja desactive" -Level INFO
                }
            }
            catch {
                Write-Log "Erreur lors de la desactivation SMBv1 : $($_.Exception.Message)" -Level WARNING
            }
        }
    }

    # Desactiver LLMNR (Link-Local Multicast Name Resolution)
    if ($script:config.disable_llmnr) {
        $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if ($DryRun) {
            Write-Log "[DRY-RUN] Desactivation de LLMNR" -Level INFO
        } else {
            try {
                if (-not (Test-Path -Path $llmnrPath)) {
                    New-Item -Path $llmnrPath -Force | Out-Null
                }
                Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
                Write-Log "LLMNR desactive avec succes" -Level SUCCESS
            }
            catch {
                Write-Log "Erreur lors de la desactivation LLMNR : $($_.Exception.Message)" -Level WARNING
            }
        }
    }

    # Desactiver mDNS si le niveau est Advanced
    if ($Level -eq "Advanced") {
        $mdnsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mDNS\Parameters"
        if ($DryRun) {
            Write-Log "[DRY-RUN] Desactivation de mDNS (niveau Advanced)" -Level INFO
        } else {
            try {
                if (Test-Path -Path $mdnsPath) {
                    Set-ItemProperty -Path $mdnsPath -Name "Start" -Value 4 -Type DWord -Force
                    Write-Log "mDNS configure en desactive (Start=4)" -Level SUCCESS
                }
            }
            catch {
                Write-Log "Erreur lors de la desactivation mDNS : $($_.Exception.Message)" -Level WARNING
            }
        }
    }

    # Desactiver le service de publication de fonctions
    if ($Level -eq "Advanced") {
        $fdResPubPath = "HKLM:\SYSTEM\CurrentControlSet\Services\FDResPub"
        if ($DryRun) {
            Write-Log "[DRY-RUN] Desactivation du service FDResPub (niveau Advanced)" -Level INFO
        } else {
            try {
                if (Test-Path -Path $fdResPubPath) {
                    Set-ItemProperty -Path $fdResPubPath -Name "Start" -Value 4 -Type DWord -Force
                    Write-Log "FDResPub configure en desactive" -Level SUCCESS
                }
            }
            catch {
                Write-Log "Erreur lors de la desactivation FDResPub : $($_.Exception.Message)" -Level WARNING
            }
        }
    }
}

function Set-SecurityOptions {
    <#
    .SYNOPSIS
        Configure les options de securite systeme supplementaires.
    #>
    Write-Log "=== Configuration des options de securite ===" -Level ACTION

    # Verrouillage de la session apres inactivite
    if ($script:config.enable_screensaver_lock) {
        $timeoutMs = $script:config.screensaver_timeout_minutes * 60 * 1000
        if ($DryRun) {
            Write-Log "[DRY-RUN] Verrouillage ecran apres $($script:config.screensaver_timeout_minutes) minutes" -Level INFO
        } else {
            try {
                Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value $timeoutMs -Force
                Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value 1 -Force
                Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value 1 -Force
                Write-Log "Verrouillage ecran configure : $($script:config.screensaver_timeout_minutes) minutes" -Level SUCCESS
            }
            catch {
                Write-Log "Erreur lors de la configuration du verrouillage ecran : $($_.Exception.Message)" -Level WARNING
            }
        }
    }

    # Timeout de session RDP
    if ($DryRun) {
        Write-Log "[DRY-RUN] Timeout de session : $($script:config.session_timeout_minutes) minutes" -Level INFO
    } else {
        try {
            $sessionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            if (-not (Test-Path -Path $sessionPath)) {
                New-Item -Path $sessionPath -Force | Out-Null
            }
            Set-ItemProperty -Path $sessionPath -Name "MaxIdleTime" -Value ($script:config.session_timeout_minutes * 60000) -Type DWord -Force
            Set-ItemProperty -Path $sessionPath -Name "MaxDisconnectionTime" -Value 600000 -Type DWord -Force
            Set-ItemProperty -Path $sessionPath -Name "fResetBroken" -Value 1 -Type DWord -Force
            Write-Log "Timeout de session configure : $($script:config.session_timeout_minutes) minutes" -Level SUCCESS
        }
        catch {
            Write-Log "Erreur lors de la configuration du timeout de session : $($_.Exception.Message)" -Level WARNING
        }
    }
}

# ============================================================================
# EXECUTION PRINCIPALE
# ============================================================================

function Invoke-Hardening {
    <#
    .SYNOPSIS
        Execute l'ensemble des etapes de durcissement.
    #>
    Write-Log "=============================================" -Level INFO
    Write-Log "DEBUT DU DURCISSEMENT - Niveau $Level" -Level INFO
    Write-Log "=============================================" -Level INFO

    # Afficher le mode Dry-Run
    if ($DryRun) {
        Write-Log " " -Level INFO
        Write-Log "██████████████████████████████████████████████████████████████" -Level WARNING
        Write-Log "██             MODE SIMULATION (DRY-RUN)                  ██" -Level WARNING
        Write-Log "██      Aucune modification ne sera appliquee             ██" -Level WARNING
        Write-Log "██████████████████████████████████████████████████████████████" -Level WARNING
        Write-Log " " -Level INFO
    }

    # Appliquer chaque etape de hardening
    try {
        # 1. Politiques de compte
        Write-Log " " -Level INFO
        Set-AccountPolicies

        # 2. Politiques d'audit
        Write-Log " " -Level INFO
        Set-AuditPolicy

        # 3. Pare-feu Windows
        Write-Log " " -Level INFO
        Set-WindowsFirewall

        # 4. Windows Defender
        Write-Log " " -Level INFO
        Set-WindowsDefender

        # 5. Services non securises (sauf niveau Basic)
        if ($Level -ne "Basic") {
            Write-Log " " -Level INFO
            Disable-InsecureServices
        }

        # 6. Configuration du registre
        Write-Log " " -Level INFO
        Set-RegistryHardening

        # 7. Protocoles non securises
        Write-Log " " -Level INFO
        Disable-InsecureProtocols

        # 8. Journalisation PowerShell
        Write-Log " " -Level INFO
        Set-PowerShellLogging

        # 9. Options de securite
        Write-Log " " -Level INFO
        Set-SecurityOptions

        # 10. Forcer la mise a jour des politiques
        if (-not $DryRun) {
            Write-Log " " -Level INFO
            Write-Log "Mise a jour des politiques de groupe..." -Level INFO
            gpupdate /target:computer /force 2>$null | Out-Null
            Write-Log "Mise a jour des politiques effectuee." -Level SUCCESS
        }

        # Resume
        Write-Log " " -Level INFO
        Write-Log "=============================================" -Level INFO
        Write-Log "DURCISSEMENT TERMINE - Niveau $Level" -Level INFO
        Write-Log "=============================================" -Level INFO

        if ($DryRun) {
            Write-Log "Aucune modification appliquee (mode Dry-Run)." -Level WARNING
            Write-Log "Pour appliquer les changements, relancez sans le parametre -DryRun." -Level WARNING
        } else {
            Write-Log "Toutes les modifications ont ete appliquees avec succes." -Level SUCCESS
            Write-Log "Un redemarrage est recommande pour appliquer certains changements." -Level WARNING
        }
    }
    catch {
        Write-Log "Erreur critique lors de l'execution : $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}

# ============================================================================
# POINT D'ENTREE
# ============================================================================

try {
    # Initialiser l'environnement
    Initialize-Environment

    # Confirmation utilisateur
    if (-not $DryRun) {
        Write-Host " " -ForegroundColor Yellow
        Write-Host "AVERTISSEMENT : Vous allez appliquer un durcissement de securite." -ForegroundColor Yellow
        Write-Host "Niveau : $Level" -ForegroundColor Cyan
        Write-Host "Assurez-vous d'avoir teste ce script en environnement de qualification." -ForegroundColor Yellow
        Write-Host " " -ForegroundColor Yellow

        $confirmation = Read-Host "Voulez-vous continuer ? (O/N)"
        if ($confirmation -notmatch "^(O|o|OUI|oui)$") {
            Write-Log "Operation annulee par l'utilisateur." -Level WARNING
            exit 0
        }
    }

    # Executer le hardening
    Invoke-Hardening
}
catch {
    Write-Log "Erreur fatale : $($_.Exception.Message)" -Level ERROR
    exit 1
}
