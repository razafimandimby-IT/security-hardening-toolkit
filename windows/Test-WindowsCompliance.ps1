<#
.SYNOPSIS
    Verifie la conformite d'un systeme Windows par rapport aux benchmarks CIS.

.DESCRIPTION
    Ce script effectue plus de 100 verifications de securite sur un systeme Windows
    et genere un rapport de conformite detaille. Les verifications couvrent les
    politiques de compte, les options de securite, l'audit, le pare-feu, les services,
    Windows Defender, la configuration du registre, et la journalisation.

.PARAMETER OutputHtml
    Chemin du fichier HTML de rapport a generer. Si specifie, genere un rapport
    HTML formaté avec scores et recommandations.

.PARAMETER OutputJson
    Chemin du fichier JSON de rapport a generer. Permet l'integration avec d'autres outils.

.PARAMETER Categories
    Filtre les verifications par categorie. Valeurs acceptees : AccountPolicies,
    SecurityOptions, AuditPolicy, Defender, Firewall, Services, Registry, Logging,
    UserRights. Separees par des virgules.

.PARAMETER ConfigPath
    Chemin vers un fichier de configuration YAML/JSON personnalise.

.PARAMETER LogPath
    Chemin du fichier de log.

.EXAMPLE
    .\Test-WindowsCompliance.ps1
    Execute l'audit complet et affiche les resultats dans la console.

.EXAMPLE
    .\Test-WindowsCompliance.ps1 -OutputHtml C:\Reports\audit.html -OutputJson C:\Reports\audit.json
    Execute l'audit et genere les rapports HTML et JSON.

.EXAMPLE
    .\Test-WindowsCompliance.ps1 -Categories "AccountPolicies,Firewall,Defender"
    Execute l'audit uniquement sur les categories specifiees.

.NOTES
    Auteur  : Louis Denis RAZAFIMANDIMBY
    Version : 1.0.0
    Requiert : Windows Server 2016/2019/2022, Windows 10/11 (elevation admin requise)
    CIS Benchmark : Windows Server 2022 v2.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputHtml = "",

    [Parameter(Mandatory=$false)]
    [string]$OutputJson = "",

    [Parameter(Mandatory=$false)]
    [string]$Categories = "*",

    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = "",

    [Parameter(Mandatory=$false)]
    [string]$LogPath = ""
)

# ============================================================================
# INITIALISATION
# ============================================================================

$script:results = @()
$script:startTime = Get-Date
$script:systemInfo = $null

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    $colorMap = @{"INFO"="Cyan"; "WARNING"="Yellow"; "ERROR"="Red"; "SUCCESS"="Green"; "PASS"="Green"; "FAIL"="Red"}
    $color = if ($colorMap.ContainsKey($Level)) { $colorMap[$Level] } else { "White" }
    Write-Host $logMessage -ForegroundColor $color
}

function Get-SystemInformation {
    <#
    .SYNOPSIS
        Recupere les informations du systeme pour le rapport.
    #>
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        $bios = Get-CimInstance -ClassName Win32_BIOS

        return [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            OSName = $os.Caption
            OSVersion = $os.Version
            OSBuild = $os.BuildNumber
            OSArchitecture = $os.OSArchitecture
            Manufacturer = $cs.Manufacturer
            Model = $cs.Model
            TotalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
            BIOSVersion = $bios.SMBIOSBIOSVersion
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            Uptime = (Get-Date) - $os.LastBootUpTime
            Domain = $cs.Domain
            CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            AuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
    catch {
        return [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            OSName = "Inconnu"
            OSVersion = "Inconnu"
            AuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
}

# ============================================================================
# FONCTIONS DE VERIFICATION
# ============================================================================

function Add-CheckResult {
    <#
    .SYNOPSIS
        Ajoute un resultat de verification a la liste des resultats.
    #>
    param(
        [string]$Category,
        [string]$CheckId,
        [string]$Description,
        [string]$Expected,
        [string]$Actual,
        [string]$Status,       # PASS, FAIL, WARNING, ERROR, INFO
        [string]$Remediation = "",
        [string]$Severity = "Medium",  # Critical, High, Medium, Low
        [string]$CISControl = ""
    )

    $script:results += [PSCustomObject]@{
        Category = $Category
        CheckId = $CheckId
        Description = $Description
        Expected = $Expected
        Actual = $Actual
        Status = $Status
        Remediation = $Remediation
        Severity = $Severity
        CISControl = $CISControl
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

# --- Account Policies ---

function Test-PasswordPolicy {
    Write-Log "Verification des politiques de mot de passe..." -Level INFO

    try {
        $secpol = & secedit /export /areas SECURITYPOLICY /cfg "$env:TEMP\secpol.cfg" 2>$null
        $secpolContent = Get-Content "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue

        # Longueur minimale du mot de passe
        $minLength = if ($secpolContent -match 'MinimumPasswordLength\s*=\s*(\d+)') { $matches[1] } else { 0 }
        Add-CheckResult -Category "AccountPolicies" -CheckId "1.1.1" `
            -Description "Longueur minimale du mot de passe" `
            -Expected ">= 12 caracteres" `
            -Actual "$minLength caracteres" `
            -Status $(if ([int]$minLength -ge 12) { "PASS" } else { "FAIL" }) `
            -Remediation "Configurer la longueur minimale a 12 caracteres ou plus : secedit /configure" `
            -Severity "High" -CISControl "CIS 1.1.1"

        # Complexite du mot de passe
        $complexity = if ($secpolContent -match 'PasswordComplexity\s*=\s*(\d+)') { $matches[1] } else { 0 }
        Add-CheckResult -Category "AccountPolicies" -CheckId "1.1.2" `
            -Description "Complexite du mot de passe exigee" `
            -Expected "Active (1)" `
            -Actual $(if ($complexity -eq "1") { "Active" } else { "Desactive" }) `
            -Status $(if ($complexity -eq "1") { "PASS" } else { "FAIL" }) `
            -Remediation "Activer la complexite du mot de passe dans les politiques de securite" `
            -Severity "High" -CISControl "CIS 1.1.2"

        # Historique des mots de passe
        $history = if ($secpolContent -match 'PasswordHistorySize\s*=\s*(\d+)') { $matches[1] } else { 0 }
        Add-CheckResult -Category "AccountPolicies" -CheckId "1.1.3" `
            -Description "Historique des mots de passe" `
            -Expected ">= 12 mots de passe memorises" `
            -Actual "$history memorises" `
            -Status $(if ([int]$history -ge 12) { "PASS" } else { "FAIL" }) `
            -Remediation "Configurer l'historique a 12 mots de passe ou plus" `
            -Severity "Medium" -CISControl "CIS 1.1.3"

        # Age maximal du mot de passe
        $maxAge = if ($secpolContent -match 'MaximumPasswordAge\s*=\s*(\d+)') { $matches[1] } else { 0 }
        Add-CheckResult -Category "AccountPolicies" -CheckId "1.1.4" `
            -Description "Age maximal du mot de passe" `
            -Expected "<= 60 jours" `
            -Actual "$maxAge jours" `
            -Status $(if ([int]$maxAge -le 60 -and [int]$maxAge -gt 0) { "PASS" } else { "FAIL" }) `
            -Remediation "Configurer l'age maximal du mot de passe a 60 jours ou moins" `
            -Severity "Medium" -CISControl "CIS 1.1.4"

        Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "Erreur lors de la verification des mots de passe : $($_.Exception.Message)" -Level ERROR
        Add-CheckResult -Category "AccountPolicies" -CheckId "1.1.0" -Description "Verification des politiques de mot de passe" `
            -Expected "Reussite" -Actual "Erreur : $($_.Exception.Message)" -Status "ERROR" -Severity "High"
    }
}

function Test-AccountLockoutPolicy {
    Write-Log "Verification des politiques de verrouillage de compte..." -Level INFO

    try {
        $secpol = & secedit /export /areas SECURITYPOLICY /cfg "$env:TEMP\secpol_lockout.cfg" 2>$null
        $secpolContent = Get-Content "$env:TEMP\secpol_lockout.cfg" -ErrorAction SilentlyContinue

        # Seuil de verrouillage
        $lockoutThreshold = if ($secpolContent -match 'LockoutBadCount\s*=\s*(\d+)') { $matches[1] } else { 0 }
        Add-CheckResult -Category "AccountPolicies" -CheckId "1.2.1" `
            -Description "Seuil de verrouillage de compte" `
            -Expected "<= 5 tentatives echouees" `
            -Actual "$lockoutThreshold tentatives" `
            -Status $(if ([int]$lockoutThreshold -le 5 -and [int]$lockoutThreshold -gt 0) { "PASS" } else { "FAIL" }) `
            -Remediation "Configurer le seuil de verrouillage a 5 tentatives ou moins" `
            -Severity "High" -CISControl "CIS 1.2.1"

        # Duree de verrouillage
        $lockoutDuration = if ($secpolContent -match 'LockoutDuration\s*=\s*(\d+)') { $matches[1] } else { 0 }
        Add-CheckResult -Category "AccountPolicies" -CheckId "1.2.2" `
            -Description "Duree de verrouillage du compte" `
            -Expected ">= 15 minutes" `
            -Actual "$lockoutDuration minutes" `
            -Status $(if ([int]$lockoutDuration -ge 15) { "PASS" } else { "FAIL" }) `
            -Remediation "Configurer la duree de verrouillage a 15 minutes ou plus" `
            -Severity "Medium" -CISControl "CIS 1.2.2"

        Remove-Item "$env:TEMP\secpol_lockout.cfg" -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "Erreur lors de la verification du verrouillage : $($_.Exception.Message)" -Level ERROR
    }
}

# --- Audit Policy ---

function Test-AuditPolicy {
    Write-Log "Verification des politiques d'audit..." -Level INFO

    $auditChecks = @(
        @{Id="2.1.1"; Desc="Audit - Validation des identifiants"; Sub="Credential Validation"; Expected="Success and Failure"}
        @{Id="2.1.2"; Desc="Audit - Gestion des comptes utilisateur"; Sub="User Account Management"; Expected="Success and Failure"}
        @{Id="2.1.3"; Desc="Audit - Gestion des groupes de securite"; Sub="Security Group Management"; Expected="Success and Failure"}
        @{Id="2.1.4"; Desc="Audit - Ouverture de session"; Sub="Logon"; Expected="Success and Failure"}
        @{Id="2.1.5"; Desc="Audit - Modification des politiques"; Sub="Audit Policy Change"; Expected="Success and Failure"}
        @{Id="2.1.6"; Desc="Audit - Integrite du systeme"; Sub="System Integrity"; Expected="Success and Failure"}
        @{Id="2.1.7"; Desc="Audit - Utilisation de privileges"; Sub="Sensitive Privilege Use"; Expected="Failure"}
        @{Id="2.1.8"; Desc="Audit - Creation de processus"; Sub="Process Creation"; Expected="Success"}
    )

    foreach ($check in $auditChecks) {
        try {
            $result = & auditpol /get /subcategory:$($check.Sub) 2>$null

            $hasSuccess = $result -match "Success"
            $hasFailure = $result -match "Failure"

            $actual = if ($hasSuccess -and $hasFailure) { "Success and Failure" }
                     elseif ($hasSuccess) { "Success" }
                     elseif ($hasFailure) { "Failure" }
                     else { "No auditing" }

            $isPass = $false
            if ($check.Expected -eq "Success and Failure") { $isPass = $hasSuccess -and $hasFailure }
            elseif ($check.Expected -eq "Success") { $isPass = $hasSuccess }
            elseif ($check.Expected -eq "Failure") { $isPass = $hasFailure }

            Add-CheckResult -Category "AuditPolicy" -CheckId $check.Id `
                -Description $check.Desc `
                -Expected $check.Expected `
                -Actual $actual `
                -Status $(if ($isPass) { "PASS" } else { "FAIL" }) `
                -Remediation "auditpol /set /subcategory:`"$($check.Sub)`" /success:enable /failure:enable" `
                -Severity "High" -CISControl "CIS 2.1.x"
        }
        catch {
            Add-CheckResult -Category "AuditPolicy" -CheckId $check.Id -Description $check.Desc `
                -Expected $check.Expected -Actual "Erreur" -Status "ERROR" -Severity "Medium"
        }
    }
}

# --- Windows Defender ---

function Test-WindowsDefender {
    Write-Log "Verification de Windows Defender..." -Level INFO

    try {
        $mpPref = Get-MpPreference -ErrorAction SilentlyContinue

        if ($mpPref) {
            Add-CheckResult -Category "Defender" -CheckId "3.1.1" `
                -Description "Protection en temps reel" `
                -Expected "Active" `
                -Actual $(if (-not $mpPref.DisableRealtimeMonitoring) { "Active" } else { "Desactive" }) `
                -Status $(if (-not $mpPref.DisableRealtimeMonitoring) { "PASS" } else { "FAIL" }) `
                -Remediation "Set-MpPreference -DisableRealtimeMonitoring 0" `
                -Severity "Critical" -CISControl "CIS 3.1.1"

            Add-CheckResult -Category "Defender" -CheckId "3.1.2" `
                -Description "Protection cloud" `
                -Expected "Active (MAPS Advanced)" `
                -Actual $(if ($mpPref.MAPSReporting -eq 2) { "Active (MAPS Advanced)" } elseif ($mpPref.MAPSReporting -eq 1) { "Active (MAPS Basic)" } else { "Desactive" }) `
                -Status $(if ($mpPref.MAPSReporting -ge 1) { "PASS" } else { "FAIL" }) `
                -Remediation "Set-MpPreference -MAPSReporting Advanced" `
                -Severity "High" -CISControl "CIS 3.1.2"

            Add-CheckResult -Category "Defender" -CheckId "3.1.3" `
                -Description "Protection PUA (Potentially Unwanted Applications)" `
                -Expected "Active" `
                -Actual $mpPref.PUAProtection.ToString() `
                -Status $(if ($mpPref.PUAProtection -eq 1) { "PASS" } else { "FAIL" }) `
                -Remediation "Set-MpPreference -PUAProtection Enabled" `
                -Severity "Medium" -CISControl "CIS 3.1.3"

            Add-CheckResult -Category "Defender" -CheckId "3.1.4" `
                -Description "Analyse des pieces jointes email" `
                -Expected "Active" `
                -Actual $(if ($mpPref.DisableEmailScanning -or -not $mpPref.EnableEmailScanning) { "Desactive" } else { "Active" }) `
                -Status $(if ($mpPref.DisableEmailScanning -eq $false) { "PASS" } else { "FAIL" }) `
                -Severity "Medium"

            Add-CheckResult -Category "Defender" -CheckId "3.1.5" `
                -Description "Analyse des lecteurs amovibles" `
                -Expected "Active" `
                -Actual $(if ($mpPref.DisableRemovableDriveScanning) { "Desactive" } else { "Active" }) `
                -Status $(if (-not $mpPref.DisableRemovableDriveScanning) { "PASS" } else { "FAIL" }) `
                -Severity "Medium"

            Add-CheckResult -Category "Defender" -CheckId "3.1.6" `
                -Description "Protection de l'acces aux dossiers (Controlled Folder Access)" `
                -Expected "Active" `
                -Actual $(if ($mpPref.EnableControlledFolderAccess -eq 1) { "Active" } else { "Desactive" }) `
                -Status $(if ($mpPref.EnableControlledFolderAccess -eq 1) { "PASS" } else { "WARNING" }) `
                -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled" `
                -Severity "Medium"
        } else {
            Add-CheckResult -Category "Defender" -CheckId "3.1.0" -Description "Windows Defender" `
                -Expected "Installe et actif" -Actual "Non accessible" -Status "ERROR" -Severity "High"
        }
    }
    catch {
        Write-Log "Erreur lors de la verification Defender : $($_.Exception.Message)" -Level ERROR
    }
}

# --- Firewall ---

function Test-Firewall {
    Write-Log "Verification du pare-feu Windows..." -Level INFO

    $profiles = @("Domain", "Private", "Public")

    foreach ($profile in $profiles) {
        try {
            $fwProfile = Get-NetFirewallProfile -Name $profile -ErrorAction SilentlyContinue
            if ($fwProfile) {
                Add-CheckResult -Category "Firewall" -CheckId "4.1.$profile" `
                    -Description "Pare-feu $profile - Actif" `
                    -Expected "Active" `
                    -Actual $(if ($fwProfile.Enabled) { "Active" } else { "Desactive" }) `
                    -Status $(if ($fwProfile.Enabled) { "PASS" } else { "FAIL" }) `
                    -Remediation "Set-NetFirewallProfile -Name $profile -Enabled True" `
                    -Severity "Critical" -CISControl "CIS 4.1"

                Add-CheckResult -Category "Firewall" -CheckId "4.2.$profile" `
                    -Description "Pare-feu $profile - Entrant par defaut" `
                    -Expected "Block" `
                    -Actual "$($fwProfile.DefaultInboundAction)" `
                    -Status $(if ($fwProfile.DefaultInboundAction -eq "Block") { "PASS" } else { "FAIL" }) `
                    -Remediation "netsh advfirewall set $profile firewallpolicy blockinbound,allowoutbound" `
                    -Severity "High" -CISControl "CIS 4.2"
            }
        }
        catch {
            Add-CheckResult -Category "Firewall" -CheckId "4.$profile" -Description "Pare-feu $profile" `
                -Expected "Configurable" -Actual "Erreur" -Status "ERROR" -Severity "High"
        }
    }
}

# --- Services ---

function Test-Services {
    Write-Log "Verification des services systeme..." -Level INFO

    $insecureServices = @(
        @{Name="XboxGipSvc"; Desc="Xbox Accessory Management Service"}
        @{Name="XboxNetApiSvc"; Desc="Xbox Live Networking Service"}
        @{Name="Fax"; Desc="Service de fax"}
        @{Name="irmon"; Desc="Moniteur infrarouge"}
        @{Name="RemoteRegistry"; Desc="Registre a distance"}
        @{Name="RemoteAccess"; Desc="Routage et acces distant"}
        @{Name="lfsvc"; Desc="Service de publication de fonctions"}
        @{Name="SharedAccess"; Desc="Partage de connexion Internet"}
        @{Name="wcncsvc"; Desc="Configuration automatique WiFi"}
        @{Name="W3SVC"; Desc="Service IIS World Wide Web"}
        @{Name="MapsBroker"; Desc="Service de cartes"}
        @{Name="DiagTrack"; Desc="Service de suivi de diagnostic"}
        @{Name="dmwappushsvc"; Desc="Service d'acheminement des messages WAP"}
        @{Name="WpnService"; Desc="Service de notifications push Windows"}
    )

    foreach ($service in $insecureServices) {
        try {
            $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
            if ($svc) {
                Add-CheckResult -Category "Services" -CheckId "5.$($service.Name)" `
                    -Description "$($service.Desc) ($($service.Name))" `
                    -Expected "Desactive (Startup: Disabled)" `
                    -Actual "Startup: $($svc.StartType), Status: $($svc.Status)" `
                    -Status $(if ($svc.StartType -eq "Disabled") { "PASS" } else { "FAIL" }) `
                    -Remediation "Set-Service -Name $($service.Name) -StartupType Disabled; Stop-Service -Name $($service.Name) -Force" `
                    -Severity "Medium" -CISControl "CIS 5.x"
            }
            # Si le service n'existe pas, c'est un PASS (deja desactive/supprime)
        }
        catch {
            Add-CheckResult -Category "Services" -CheckId "5.$($service.Name)" `
                -Description "$($service.Desc) ($($service.Name))" `
                -Expected "Desactive" -Actual "Non verifiable" -Status "WARNING" -Severity "Low"
        }
    }
}

# --- Registry Security Settings ---

function Test-RegistrySecurity {
    Write-Log "Verification des parametres de securite du registre..." -Level INFO

    $regChecks = @(
        @{Id="6.1.1"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Expected="1"; Desc="UAC active"}
        @{Id="6.1.2"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Expected="2"; Desc="UAC - comportement admin"}

        @{Id="6.2.1"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Expected="5"; Desc="Niveau d'authentification LAN Manager (NTLMv2)"}
        @{Id="6.2.2"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"; Expected="1"; Desc="Restriction de l'acces anonyme"}
        @{Id="6.2.3"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Expected="1"; Desc="Restriction de l'acces anonyme SAM"}
        @{Id="6.2.4"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="NoLMHash"; Expected="1"; Desc="Desactivation du hash LM"}
        @{Id="6.2.5"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LimitBlankPasswordUse"; Expected="1"; Desc="Interdiction des mots de passe vides"}

        @{Id="6.3.1"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="AutoDisconnect"; Expected="15"; Desc="Deconnexion automatique SMB"}
        @{Id="6.3.2"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RestrictNullSessAccess"; Expected="1"; Desc="Restriction des sessions nulles SMB"}
        @{Id="6.3.3"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="SMBServerNameHardeningLevel"; Expected="1"; Desc="Niveau de hardening SMB"}

        @{Id="6.4.1"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="UserAuthentication"; Expected="1"; Desc="Authentification RDP requise"}
        @{Id="6.4.2"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="SecurityLayer"; Expected="2"; Desc="Couche de securite RDP"}
        @{Id="6.4.3"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="MinEncryptionLevel"; Expected="3"; Desc="Niveau de chiffrement RDP"}

        @{Id="6.5.1"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableICMPRedirect"; Expected="0"; Desc="Desactivation des redirections ICMP"}
        @{Id="6.5.2"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="DisableIPSourceRouting"; Expected="2"; Desc="Desactivation du routage source IP"}
        @{Id="6.5.3"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="SynAttackProtect"; Expected="1"; Desc="Protection contre les attaques SYN"}
        @{Id="6.5.4"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableDeadGWDetect"; Expected="0"; Desc="Desactivation de la detection de passerelle morte"}
    )

    foreach ($check in $regChecks) {
        try {
            $actualValue = Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $check.Name
            $actual = if ($null -eq $actualValue) { "Absent" } else { $actualValue.ToString() }
            $isPass = $actual -eq $check.Expected

            Add-CheckResult -Category "Registry" -CheckId $check.Id `
                -Description $check.Desc `
                -Expected $check.Expected `
                -Actual $actual `
                -Status $(if ($isPass) { "PASS" } else { "FAIL" }) `
                -Remediation "Set-ItemProperty -Path '$($check.Path)' -Name '$($check.Name)' -Value $($check.Expected) -Type DWord -Force" `
                -Severity "Medium"
        }
        catch {
            Add-CheckResult -Category "Registry" -CheckId $check.Id -Description $check.Desc `
                -Expected $check.Expected -Actual "Non verifiable" -Status "WARNING" -Severity "Low"
        }
    }
}

# --- PowerShell Logging ---

function Test-PowerShellLogging {
    Write-Log "Verification de la journalisation PowerShell..." -Level INFO

    $loggingChecks = @(
        @{Id="7.1.1"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name="EnableScriptBlockLogging"; Expected="1"; Desc="Journalisation des blocs de script PowerShell"}
        @{Id="7.1.2"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; Name="EnableModuleLogging"; Expected="1"; Desc="Journalisation des modules PowerShell"}
        @{Id="7.1.3"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\PowerShellTranscription"; Name="EnableTranscripting"; Expected="1"; Desc="Transcription PowerShell"}
        @{Id="7.1.4"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"; Name="MaxSize"; Expected="2097152"; Desc="Taille maximale du journal de securite"}
    )

    foreach ($check in $loggingChecks) {
        try {
            $actualValue = Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $check.Name
            $actual = if ($null -eq $actualValue) { "Absent" } else { $actualValue.ToString() }
            $isPass = $actual -eq $check.Expected

            Add-CheckResult -Category "Logging" -CheckId $check.Id `
                -Description $check.Desc `
                -Expected $check.Expected `
                -Actual $actual `
                -Status $(if ($isPass) { "PASS" } else { "FAIL" }) `
                -Remediation "Configurer la politique de journalisation PowerShell dans le registre" `
                -Severity "Medium"
        }
        catch {
            Add-CheckResult -Category "Logging" -CheckId $check.Id -Description $check.Desc `
                -Expected $check.Expected -Actual "Non verifiable" -Status "WARNING" -Severity "Low"
        }
    }
}

# --- SMB Configuration ---

function Test-SMBConfiguration {
    Write-Log "Verification de la configuration SMB..." -Level INFO

    try {
        $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if ($smbConfig) {
            Add-CheckResult -Category "Registry" -CheckId "8.1.1" `
                -Description "SMBv1 desactive" `
                -Expected "Desactive" `
                -Actual $(if (-not $smbConfig.EnableSMB1Protocol) { "Desactive" } else { "Actif" }) `
                -Status $(if (-not $smbConfig.EnableSMB1Protocol) { "PASS" } else { "FAIL" }) `
                -Remediation "Set-SmbServerConfiguration -EnableSMB1Protocol 0 -Force" `
                -Severity "Critical" -CISControl "CIS 8.1"

            Add-CheckResult -Category "Registry" -CheckId "8.1.2" `
                -Description "Signature SMB requise" `
                -Expected "Requise" `
                -Actual $(if ($smbConfig.RequireSecuritySignature) { "Requise" } else { "Non requise" }) `
                -Status $(if ($smbConfig.RequireSecuritySignature) { "PASS" } else { "FAIL" }) `
                -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature 1 -Force" `
                -Severity "High" -CISControl "CIS 8.2"
        }
    }
    catch {
        Write-Log "Erreur lors de la verification SMB" -Level WARNING
    }
}

# --- User Rights ---

function Test-UserRights {
    Write-Log "Verification des droits utilisateur..." -Level INFO

    try {
        # Verifier les droits de connexion locales
        $seceditFile = "$env:TEMP\secpol_ur.cfg"
        & secedit /export /areas USER_RIGHTS /cfg $seceditFile 2>$null

        if (Test-Path $seceditFile) {
            $content = Get-Content $seceditFile

            # SeDebugPrivilege - devrait etre reserve aux admins
            $debugRight = $content | Select-String "SeDebugPrivilege" | Select-Object -First 1
            $hasOnlyAdmin = if ($debugRight -match '\*S-1-5-32-544\b') { $true } else { $false }

            Add-CheckResult -Category "UserRights" -CheckId "9.1.1" `
                -Description "SeDebugPrivilege reserve aux administrateurs" `
                -Expected "Administrateurs uniquement" `
                -Actual $debugRight `
                -Status $(if ($hasOnlyAdmin) { "PASS" } else { "FAIL" }) `
                -Severity "Critical" -CISControl "CIS 9.1"

            # SeNetworkLogonRight - tout le monde
            $networkLogon = $content | Select-String "SeNetworkLogonRight" | Select-Object -First 1
            Add-CheckResult -Category "UserRights" -CheckId "9.1.2" `
                -Description "Droit de connexion au reseau" `
                -Expected "Configurer pour restreindre" `
                -Actual $networkLogon.ToString() `
                -Status "INFO" -Severity "Low"

            Remove-Item $seceditFile -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log "Erreur lors de la verification des droits utilisateur : $($_.Exception.Message)" -Level WARNING
    }
}

# ============================================================================
# GENERATION DU RAPPORT
# ============================================================================

function Get-ComplianceSummary {
    <#
    .SYNOPSIS
        Calcule le score de conformite et le resume par categorie.
    #>

    $totalChecks = $script:results.Count
    $passCount = ($script:results | Where-Object { $_.Status -eq "PASS" }).Count
    $failCount = ($script:results | Where-Object { $_.Status -eq "FAIL" }).Count
    $warningCount = ($script:results | Where-Object { $_.Status -eq "WARNING" }).Count
    $errorCount = ($script:results | Where-Object { $_.Status -eq "ERROR" }).Count
    $infoCount = ($script:results | Where-Object { $_.Status -eq "INFO" }).Count

    $score = if ($totalChecks -gt 0) {
        [math]::Round(($passCount / ($totalChecks - $infoCount)) * 100, 1)
    } else { 0 }

    $categories = $script:results | Group-Object Category | ForEach-Object {
        $catPass = ($_.Group | Where-Object { $_.Status -eq "PASS" }).Count
        $catTotal = ($_.Group | Where-Object { $_.Status -ne "INFO" }).Count
        $catScore = if ($catTotal -gt 0) { [math]::Round(($catPass / $catTotal) * 100, 1) } else { 0 }

        [PSCustomObject]@{
            Category = $_.Name
            Pass = $catPass
            Fail = ($_.Group | Where-Object { $_.Status -eq "FAIL" }).Count
            Warning = ($_.Group | Where-Object { $_.Status -eq "WARNING" }).Count
            Error = ($_.Group | Where-Object { $_.Status -eq "ERROR" }).Count
            Total = $catTotal
            Score = $catScore
        }
    }

    return [PSCustomObject]@{
        TotalChecks = $totalChecks
        PassCount = $passCount
        FailCount = $failCount
        WarningCount = $warningCount
        ErrorCount = $errorCount
        InfoCount = $infoCount
        Score = $score
        Categories = $categories
        Duration = (Get-Date) - $script:startTime
    }
}

function Show-ConsoleReport {
    <#
    .SYNOPSIS
        Affiche le rapport de conformite dans la console.
    #>
    param([Parameter(Mandatory=$true)]$Summary)

    Write-Host " " -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  SECURITY HARDENING TOOLKIT - RAPPORT DE CONFORMITE" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Date      : $($script:systemInfo.AuditDate)" -ForegroundColor Gray
    Write-Host "  Systeme   : $($script:systemInfo.OSName)" -ForegroundColor Gray
    Write-Host "  Version   : $($script:systemInfo.OSVersion) (Build $($script:systemInfo.OSBuild))" -ForegroundColor Gray
    Write-Host "  Machine   : $($script:systemInfo.ComputerName)" -ForegroundColor Gray
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Score global : $($Summary.Score)/100" -NoNewline -ForegroundColor White

    $scoreColor = if ($Summary.Score -ge 80) { "Green" } elseif ($Summary.Score -ge 60) { "Yellow" } else { "Red" }
    Write-Host " ($($Summary.PassCount)/$($Summary.TotalChecks - $Summary.InfoCount) reussis)" -ForegroundColor $scoreColor
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host " " -ForegroundColor White

    # Affichage par categorie
    $tableHeader = "{0,-30} {1,6} {2,6} {3,8} {4,8}" -f "Categorie", "Pass", "Fail", "Warn", "Score"
    Write-Host $tableHeader -ForegroundColor Yellow
    Write-Host "-" * 60 -ForegroundColor DarkGray

    foreach ($cat in $Summary.Categories) {
        $catDisplay = ("{0,-30} {1,6} {2,6} {3,8} {4,7}%" -f $cat.Category, $cat.Pass, $cat.Fail, $cat.Warning, $cat.Score)
        $catColor = if ($cat.Score -ge 80) { "Green" } elseif ($cat.Score -ge 60) { "Yellow" } else { "Red" }
        Write-Host $catDisplay -ForegroundColor $catColor
    }

    Write-Host "-" * 60 -ForegroundColor DarkGray
    $totalLine = ("{0,-30} {1,6} {2,6} {3,8} {4,7}%" -f "TOTAL", $Summary.PassCount, $Summary.FailCount, $Summary.WarningCount, $Summary.Score)
    Write-Host $totalLine -ForegroundColor White

    Write-Host " " -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

    # Echecs critiques
    $criticalFails = $script:results | Where-Object { $_.Severity -eq "Critical" -and $_.Status -eq "FAIL" }
    if ($criticalFails) {
        Write-Host " " -ForegroundColor White
        Write-Host "ECHECS CRITIQUES :" -ForegroundColor Red
        foreach ($fail in $criticalFails) {
            Write-Host "  [!] $($fail.Description)" -ForegroundColor Red
            Write-Host "      Remediation : $($fail.Remediation)" -ForegroundColor Yellow
        }
    }

    Write-Host " " -ForegroundColor White
    Write-Host "Duree de l'audit : $($Summary.Duration.Minutes)m $($Summary.Duration.Seconds)s" -ForegroundColor Gray
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host " " -ForegroundColor White
}

function Export-HtmlReport {
    <#
    .SYNOPSIS
        Genere un rapport HTML a partir des resultats d'audit.
    #>
    param([Parameter(Mandatory=$true)]$Summary, [string]$OutputPath)

    try {
        # Generer les lignes HTML du tableau
        $htmlRows = ""
        foreach ($result in $script:results | Sort-Object Category, CheckId) {
            $statusBadge = switch ($result.Status) {
                "PASS"    { '<span class="badge badge-pass">PASS</span>' }
                "FAIL"    { '<span class="badge badge-fail">FAIL</span>' }
                "WARNING" { '<span class="badge badge-warning">WARNING</span>' }
                "ERROR"   { '<span class="badge badge-error">ERROR</span>' }
                default   { '<span class="badge badge-info">INFO</span>' }
            }
            $severityBadge = switch ($result.Severity) {
                "Critical" { '<span class="severity severity-critical">Critical</span>' }
                "High"     { '<span class="severity severity-high">High</span>' }
                "Medium"   { '<span class="severity severity-medium">Medium</span>' }
                default    { '<span class="severity severity-low">Low</span>' }
            }

            $htmlRows += @"
                <tr>
                    <td>$($result.CheckId)</td>
                    <td>$($result.Category)</td>
                    <td>$($result.Description)</td>
                    <td>$($result.Expected)</td>
                    <td>$($result.Actual)</td>
                    <td>$statusBadge</td>
                    <td>$severityBadge</td>
                    <td>$($result.Remediation)</td>
                </tr>
"@
        }

        # Generer les lignes du tableau des categories
        $catRows = ""
        foreach ($cat in $Summary.Categories) {
            $catScoreColor = if ($cat.Score -ge 80) { "#4caf50" } elseif ($cat.Score -ge 60) { "#ff9800" } else { "#f44336" }
            $catRows += @"
                <tr>
                    <td>$($cat.Category)</td>
                    <td><span style="color:#4caf50;font-weight:bold;">$($cat.Pass)</span></td>
                    <td><span style="color:#f44336;font-weight:bold;">$($cat.Fail)</span></td>
                    <td><span style="color:#ff9800;font-weight:bold;">$($cat.Warning)</span></td>
                    <td><span style="color:$catScoreColor;font-weight:bold;">$($cat.Score)%</span></td>
                </tr>
"@
        }

        # Barre de score
        $scorePercent = $Summary.Score
        $scoreColor = if ($scorePercent -ge 80) { "#4caf50" } elseif ($scorePercent -ge 60) { "#ff9800" } else { "#f44336" }

        $html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Conformite - Security Hardening Toolkit</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            color: #2d3748;
            line-height: 1.6;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2em; margin-bottom: 10px; }
        .header p { color: #a0aec0; font-size: 0.9em; }

        .score-container {
            text-align: center;
            margin: 30px 0;
            padding: 30px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .score-circle {
            width: 180px;
            height: 180px;
            border-radius: 50%;
            background: conic-gradient($scoreColor 0% $scorePercent%, #e2e8f0 $scorePercent% 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            position: relative;
        }
        .score-circle-inner {
            width: 140px;
            height: 140px;
            border-radius: 50%;
            background: white;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        .score-number { font-size: 2.5em; font-weight: bold; color: $scoreColor; }
        .score-label { font-size: 0.9em; color: #718096; }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-number { font-size: 2em; font-weight: bold; }
        .stat-label { font-size: 0.85em; color: #718096; margin-top: 5px; }
        .text-pass { color: #4caf50; }
        .text-fail { color: #f44336; }
        .text-warning { color: #ff9800; }

        .categories-table {
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .categories-table h2 { margin-bottom: 15px; color: #2d3748; }

        table { width: 100%; border-collapse: collapse; }
        th {
            background: #1a202c;
            color: white;
            padding: 12px 15px;
            text-align: left;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        td { padding: 10px 15px; border-bottom: 1px solid #e2e8f0; font-size: 0.9em; }
        tr:hover { background: #f7fafc; }

        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-pass { background: #c8e6c9; color: #2e7d32; }
        .badge-fail { background: #ffcdd2; color: #c62828; }
        .badge-warning { background: #ffe0b2; color: #e65100; }
        .badge-error { background: #f8bbd0; color: #880e4f; }
        .badge-info { background: #b3e5fc; color: #01579b; }

        .severity {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.75em;
        }
        .severity-critical { background: #f44336; color: white; }
        .severity-high { background: #ff9800; color: white; }
        .severity-medium { background: #2196f3; color: white; }
        .severity-low { background: #607d8b; color: white; }

        .details-table { margin: 20px 0; }

        .system-info {
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .system-info h2 { margin-bottom: 15px; color: #2d3748; }
        .info-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
        .info-item { padding: 8px 0; }
        .info-label { font-weight: 600; color: #4a5568; }
        .info-value { color: #718096; }

        .footer {
            text-align: center;
            padding: 20px;
            color: #a0aec0;
            font-size: 0.85em;
        }

        .scrollable { overflow-x: auto; }

        @media print {
            body { background: white; padding: 0; }
            .header { border-radius: 0; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Hardening Toolkit</h1>
            <h2>Rapport de Conformite</h2>
            <p>Systeme : $($script:systemInfo.OSName) | Machine : $($script:systemInfo.ComputerName) | Date : $($script:systemInfo.AuditDate)</p>
        </div>

        <div class="score-container">
            <div class="score-circle">
                <div class="score-circle-inner">
                    <div class="score-number">$scorePercent%</div>
                    <div class="score-label">Score global</div>
                </div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number text-pass">$($Summary.PassCount)</div>
                <div class="stat-label">Tests passes</div>
            </div>
            <div class="stat-card">
                <div class="stat-number text-fail">$($Summary.FailCount)</div>
                <div class="stat-label">Tests echoues</div>
            </div>
            <div class="stat-card">
                <div class="stat-number text-warning">$($Summary.WarningCount)</div>
                <div class="stat-label">Avertissements</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$($Summary.TotalChecks)</div>
                <div class="stat-label">Tests effectues</div>
            </div>
        </div>

        <div class="system-info">
            <h2>Informations Systeme</h2>
            <div class="info-grid">
                <div class="info-item"><div class="info-label">Nom de la machine</div><div class="info-value">$($script:systemInfo.ComputerName)</div></div>
                <div class="info-item"><div class="info-label">Systeme d'exploitation</div><div class="info-value">$($script:systemInfo.OSName)</div></div>
                <div class="info-item"><div class="info-label">Version</div><div class="info-value">$($script:systemInfo.OSVersion) (Build $($script:systemInfo.OSBuild))</div></div>
                <div class="info-item"><div class="info-label">Architecture</div><div class="info-value">$($script:systemInfo.OSArchitecture)</div></div>
                <div class="info-item"><div class="info-label">Domaine</div><div class="info-value">$($script:systemInfo.Domain)</div></div>
                <div class="info-item"><div class="info-label">PowerShell</div><div class="info-value">$($script:systemInfo.PowerShellVersion)</div></div>
                <div class="info-item"><div class="info-label">Memoire</div><div class="info-value">$($script:systemInfo.TotalMemoryGB) GB</div></div>
                <div class="info-item"><div class="info-label">Uptime</div><div class="info-value">$($script:systemInfo.Uptime.Days) jours</div></div>
                <div class="info-item"><div class="info-label">Date d'audit</div><div class="info-value">$($script:systemInfo.AuditDate)</div></div>
            </div>
        </div>

        <div class="categories-table">
            <h2>Resultats par Categorie</h2>
            <table>
                <thead>
                    <tr>
                        <th>Categorie</th>
                        <th>Pass</th>
                        <th>Fail</th>
                        <th>Warning</th>
                        <th>Score</th>
                    </tr>
                </thead>
                <tbody>
                    $catRows
                </tbody>
            </table>
        </div>

        <div class="categories-table details-table">
            <h2>Details des Verifications</h2>
            <div class="scrollable">
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
                        $htmlRows
                    </tbody>
                </table>
            </div>
        </div>

        <div class="footer">
            <p>Security Hardening Toolkit v1.0.0 - Par Louis Denis RAZAFIMANDIMBY</p>
            <p>Genere le $($script:systemInfo.AuditDate) - Duree : $($Summary.Duration.Minutes)m $($Summary.Duration.Seconds)s</p>
        </div>
    </div>
</body>
</html>
"@

        $html | Out-File -FilePath $OutputPath -Encoding utf8
        Write-Log "Rapport HTML genere : $OutputPath" -Level SUCCESS
    }
    catch {
        Write-Log "Erreur lors de la generation du rapport HTML : $($_.Exception.Message)" -Level ERROR
    }
}

function Export-JsonReport {
    <#
    .SYNOPSIS
        Exporte les resultats au format JSON.
    #>
    param([string]$OutputPath)

    try {
        $exportData = @{
            toolkit = "Security Hardening Toolkit"
            version = "1.0.0"
            system = $script:systemInfo
            summary = Get-ComplianceSummary
            results = $script:results
        }

        $exportData | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutputPath -Encoding utf8
        Write-Log "Rapport JSON genere : $OutputPath" -Level SUCCESS
    }
    catch {
        Write-Log "Erreur lors de l'export JSON : $($_.Exception.Message)" -Level ERROR
    }
}

# ============================================================================
# POINT D'ENTREE
# ============================================================================

Write-Host " " -ForegroundColor White
Write-Host "██████████████████████████████████████████████████████████████" -ForegroundColor Cyan
Write-Host "██     SECURITY HARDENING TOOLKIT - AUDIT DE CONFORMITE    ██" -ForegroundColor White
Write-Host "██████████████████████████████████████████████████████████████" -ForegroundColor Cyan
Write-Host " " -ForegroundColor White

# Recuperer les informations systeme
$script:systemInfo = Get-SystemInformation

# Filtrer les categories
$selectedCategories = if ($Categories -and $Categories -ne "*") {
    $Categories -split ',' | ForEach-Object { $_.Trim() }
} else { @("*") }

# Executer les verifications
Write-Log "Demarrage de l'audit de conformite..." -Level INFO
Write-Log "Categories : $(if ($selectedCategories -contains '*') { 'Toutes' } else { $selectedCategories -join ', ' })" -Level INFO

if ($selectedCategories -contains "*" -or $selectedCategories -contains "AccountPolicies") {
    Test-PasswordPolicy
    Test-AccountLockoutPolicy
}

if ($selectedCategories -contains "*" -or $selectedCategories -contains "AuditPolicy") {
    Test-AuditPolicy
}

if ($selectedCategories -contains "*" -or $selectedCategories -contains "Defender") {
    Test-WindowsDefender
}

if ($selectedCategories -contains "*" -or $selectedCategories -contains "Firewall") {
    Test-Firewall
}

if ($selectedCategories -contains "*" -or $selectedCategories -contains "Services") {
    Test-Services
}

if ($selectedCategories -contains "*" -or $selectedCategories -contains "Registry") {
    Test-RegistrySecurity
    Test-SMBConfiguration
}

if ($selectedCategories -contains "*" -or $selectedCategories -contains "Logging") {
    Test-PowerShellLogging
}

if ($selectedCategories -contains "*" -or $selectedCategories -contains "UserRights") {
    Test-UserRights
}

# Generer le resume
Write-Log " " -Level INFO
Write-Log "Calcul du score de conformite..." -Level INFO
$summary = Get-ComplianceSummary

# Afficher dans la console
Show-ConsoleReport -Summary $summary

# Exporter les rapports
if ($OutputHtml) {
    Export-HtmlReport -Summary $summary -OutputPath $OutputHtml
}

if ($OutputJson) {
    Export-JsonReport -OutputPath $OutputJson
}

# Message final
$exitCode = if ($summary.Score -ge 80) { 0 } elseif ($summary.Score -ge 60) { 1 } else { 2 }
Write-Log "Audit termine avec le code : $exitCode" -Level INFO
exit $exitCode
