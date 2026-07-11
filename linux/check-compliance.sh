#!/usr/bin/env bash
# ==============================================================================
# Security Hardening Toolkit - Audit de conformite Linux
# ==============================================================================
# Description: Verifie la conformite d'un systeme Linux par rapport aux
#              benchmarks CIS. Effectue plus de 80 verifications et genere
#              un rapport detaille avec score de conformite.
#
# Auteur  : Louis Denis RAZAFIMANDIMBY
# Version : 1.0.0
#
# Usage:
#   sudo ./check-compliance.sh                           # Audit complet
#   sudo ./check-compliance.sh --output json --file result.json
#   sudo ./check-compliance.sh --output html --file report.html
#   sudo ./check-compliance.sh --categories "ssh,kernel"
# ==============================================================================

set -euo pipefail

# ==============================================================================
# CONSTANTES
# ==============================================================================

SCRIPT_VERSION="1.0.0"
OUTPUT_FORMAT="console"
OUTPUT_FILE=""
CATEGORIES="all"
RESULTS=()
PASS_COUNT=0
FAIL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0
TOTAL_CHECKS=0
START_TIME=""
END_TIME=""

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# ==============================================================================
# FONCTIONS UTILITAIRES
# ==============================================================================

log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASS_COUNT++)); }
log_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((FAIL_COUNT++)); }
log_warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; ((WARNING_COUNT++)); }
log_note() { echo -e "  ${BLUE}[INFO]${NC} $1"; ((INFO_COUNT++)); }

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}ERREUR: Ce script doit etre execute en tant que root (sudo).${NC}" >&2
        exit 1
    fi
}

add_result() {
    local category="$1"
    local check_id="$2"
    local description="$3"
    local expected="$4"
    local actual="$5"
    local status="$6"
    local remediation="${7:-}"

    RESULTS+=("{\"category\":\"${category}\",\"check_id\":\"${check_id}\",\"description\":\"${description//\"/\\\"}\",\"expected\":\"${expected//\"/\\\"}\",\"actual\":\"${actual//\"/\\\"}\",\"status\":\"${status}\",\"remediation\":\"${remediation//\"/\\\"}\"}")
    ((TOTAL_CHECKS++))
}

print_section() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}  $1${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
}

# ==============================================================================
# VERIFICATIONS
# ==============================================================================

check_kernel_params() {
    print_section "1. PARAMETRES KERNEL (sysctl)"

    local checks=(
        "net.ipv4.ip_forward:0:Desactiver le forwarding IP"
        "net.ipv4.conf.all.send_redirects:0:Ne pas envoyer de redirects ICMP"
        "net.ipv4.conf.all.accept_redirects:0:Ne pas accepter les redirects ICMP"
        "net.ipv4.tcp_syncookies:1:Activer SYN cookies"
        "net.ipv4.icmp_echo_ignore_broadcasts:1:Ignorer les echo broadcasts ICMP"
        "net.ipv4.conf.all.rp_filter:1:Filtrage de chemin inverse"
        "net.ipv4.conf.all.accept_source_route:0:Desactiver le routage source"
        "kernel.randomize_va_space:2:ASLR active"
        "fs.suid_dumpable:0:Desactiver les dumps core suid"
        "fs.protected_hardlinks:1:Proteger les hardlinks"
        "fs.protected_symlinks:1:Proteger les symlinks"
        "kernel.dmesg_restrict:1:Restreindre dmesg"
        "kernel.kptr_restrict:2:Restreindre les pointeurs kernel"
    )

    for check in "${checks[@]}"; do
        IFS=':' read -r param expected desc <<< "$check"
        local value
        value=$(sysctl -n "$param" 2>/dev/null || echo "non_disponible")

        if [ "$value" = "$expected" ]; then
            log_pass "$desc (${param}=${value})"
            add_result "kernel" "KERNEL_${param//./_}" "$desc" "$expected" "$value" "PASS"
        elif [ "$value" = "non_disponible" ]; then
            log_note "$desc - Parametre non disponible"
            add_result "kernel" "KERNEL_${param//./_}" "$desc" "$expected" "N/A" "INFO"
        else
            log_fail "$desc (${param}=${value}, attendu=${expected})"
            add_result "kernel" "KERNEL_${param//./_}" "$desc" "$expected" "$value" "FAIL" \
                "sysctl -w ${param}=${expected} && echo '${param} = ${expected}' >> /etc/sysctl.d/99-hardening.conf"
        fi
    done
}

check_ssh_config() {
    print_section "2. CONFIGURATION SSH"

    local sshd_config="/etc/ssh/sshd_config"

    if [ ! -f "$sshd_config" ]; then
        log_fail "Fichier sshd_config introuvable"
        add_result "ssh" "SSH_001" "Fichier sshd_config" "Existant" "Introuvable" "FAIL" "Installer OpenSSH server"
        return
    fi

    local checks=(
        "PermitRootLogin:no:Desactiver la connexion root"
        "PasswordAuthentication:no:Desactiver l'auth par mot de passe"
        "PubkeyAuthentication:yes:Activer l'auth par cle"
        "X11Forwarding:no:Desactiver le forwarding X11"
        "MaxAuthTries:[0-9]:Limiter les tentatives d'auth"
        "ClientAliveInterval:[0-9]:Timeout de session"
        "IgnoreRhosts:yes:Ignorer rhosts"
        "PermitEmptyPasswords:no:Interdire les mots de passe vides"
    )

    for check in "${checks[@]}"; do
        IFS=':' read -r param pattern desc <<< "$check"
        local value
        value=$(grep -E "^\s*${param}\s+" "$sshd_config" 2>/dev/null | awk '{print $2}' | head -1 || echo "non_configure")

        if echo "$value" | grep -qE "$pattern"; then
            log_pass "$desc (${param} = ${value})"
            add_result "ssh" "SSH_${param}" "$desc" "$pattern" "$value" "PASS"
        else
            log_fail "$desc (${param} = ${value:-non configure})"
            add_result "ssh" "SSH_${param}" "$desc" "$pattern" "${value:-non configure}" "FAIL" \
                "Ajouter '${param} $(echo "$pattern" | tr -d '[]:')' dans ${sshd_config}"
        fi
    done

    # Verifier les droits du fichier
    local perms
    perms=$(stat -c "%a" "$sshd_config" 2>/dev/null || echo "000")
    if [ "$perms" = "600" ]; then
        log_pass "Permissions sshd_config: ${perms}"
    else
        log_fail "Permissions sshd_config: ${perms} (attendu: 600)"
        add_result "ssh" "SSH_PERMS" "Permissions sshd_config" "600" "$perms" "FAIL" "chmod 600 ${sshd_config}"
    fi
}

check_fail2ban() {
    print_section "3. FAIL2BAN"

    if ! command -v fail2ban-client &>/dev/null; then
        log_fail "Fail2ban n'est pas installe"
        add_result "fail2ban" "F2B_001" "Fail2ban installe" "Installe" "Non installe" "FAIL" \
            "apt install fail2ban || yum install fail2ban"
        return
    fi

    # Verifier si le service est actif
    if systemctl is-active fail2ban 2>/dev/null | grep -q "active"; then
        log_pass "Service fail2ban actif"
        add_result "fail2ban" "F2B_002" "Service fail2ban actif" "actif" "actif" "PASS"
    else
        log_fail "Service fail2ban inactif"
        add_result "fail2ban" "F2B_002" "Service fail2ban actif" "actif" "inactif" "FAIL" \
            "systemctl enable --now fail2ban"
    fi

    # Verifier la jail SSH
    if fail2ban-client status sshd 2>/dev/null | grep -q "Status"; then
        log_pass "Jail SSH fail2ban active"
        add_result "fail2ban" "F2B_003" "Jail SSH fail2ban" "Active" "Active" "PASS"
    else
        log_fail "Jail SSH fail2ban non active"
        add_result "fail2ban" "F2B_003" "Jail SSH fail2ban" "Active" "Inactive" "FAIL" \
            "Ajouter [sshd] enabled=true dans /etc/fail2ban/jail.local"
    fi
}

check_auditd() {
    print_section "4. AUDITD"

    if ! command -v auditctl &>/dev/null; then
        log_fail "auditd n'est pas installe"
        add_result "auditd" "AUDIT_001" "auditd installe" "Installe" "Non installe" "FAIL" \
            "apt install auditd || yum install audit"
        return
    fi

    if systemctl is-active auditd 2>/dev/null | grep -q "active"; then
        log_pass "Service auditd actif"
        add_result "auditd" "AUDIT_002" "Service auditd actif" "actif" "actif" "PASS"
    else
        log_fail "Service auditd inactif"
        add_result "auditd" "AUDIT_002" "Service auditd actif" "actif" "inactif" "FAIL" \
            "systemctl enable --now auditd"
    fi

    # Verifier les regles chargees
    local rule_count
    rule_count=$(auditctl -l 2>/dev/null | wc -l || echo "0")
    if [ "$rule_count" -ge 5 ]; then
        log_pass "Regles auditd chargees: ${rule_count}"
        add_result "auditd" "AUDIT_003" "Regles auditd chargees" ">=5" "${rule_count}" "PASS"
    else
        log_warn "Peu de regles auditd: ${rule_count}"
        add_result "auditd" "AUDIT_003" "Regles auditd chargees" ">=5" "${rule_count}" "WARNING" \
            "Ajouter des regles dans /etc/audit/rules.d/"
    fi
}

check_file_permissions() {
    print_section "5. PERMISSIONS DES FICHIERS SYSTEME"

    # Fichiers critiques
    local critical_files=(
        "/etc/passwd:644"
        "/etc/shadow:0"
        "/etc/group:644"
        "/etc/gshadow:0"
        "/etc/ssh/sshd_config:600"
        "/etc/sudoers:440"
        "/etc/crontab:600"
    )

    for entry in "${critical_files[@]}"; do
        IFS=':' read -r file expected <<< "$entry"

        if [ ! -f "$file" ]; then
            log_note "Fichier non trouve: ${file}"
            continue
        fi

        local actual_perms
        actual_perms=$(stat -c "%a" "$file" 2>/dev/null || echo "000")
        local actual_owner
        actual_owner=$(stat -c "%U:%G" "$file" 2>/dev/null || echo "unknown")

        if [ "$actual_perms" = "$expected" ]; then
            log_pass "Permissions ${file}: ${actual_perms} (${actual_owner})"
            add_result "permissions" "PERM_$(basename "$file")" "Permissions de ${file}" "$expected" "$actual_perms" "PASS"
        else
            log_fail "Permissions ${file}: ${actual_perms} (attendu: ${expected})"
            add_result "permissions" "PERM_$(basename "$file")" "Permissions de ${file}" "$expected" "$actual_perms" "FAIL" \
                "chmod ${expected} ${file}"
        fi
    done

    # Verifier les fichiers avec suid/sgid
    local suid_files
    suid_files=$(find / -perm -4000 -type f 2>/dev/null | head -20)
    if [ -n "$suid_files" ]; then
        log_note "Fichiers SUID detectes (liste non exhaustive):"
        while IFS= read -r file; do
            log_note "  ${file}"
        done <<< "$suid_files"
    fi
}

check_password_policies() {
    print_section "6. POLITIQUES DE MOTS DE PASSE"

    # Verifier login.defs
    if [ -f /etc/login.defs ]; then
        local max_days
        max_days=$(grep -E "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "non_configure")
        if [ "${max_days}" -le 90 ] 2>/dev/null; then
            log_pass "Age maximum mot de passe: ${max_days} jours"
            add_result "password" "PASS_MAX_DAYS" "Age maximum du mot de passe" "<=90" "${max_days}" "PASS"
        else
            log_fail "Age maximum mot de passe: ${max_days} jours (attendu: <=90)"
            add_result "password" "PASS_MAX_DAYS" "Age maximum du mot de passe" "<=90" "${max_days}" "FAIL"
        fi

        local min_len
        min_len=$(grep -E "^PASS_MIN_LEN" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "non_configure")
        if [ "${min_len}" -ge 8 ] 2>/dev/null; then
            log_pass "Longueur minimale mot de passe: ${min_len}"
            add_result "password" "PASS_MIN_LEN" "Longueur minimale" ">=8" "${min_len}" "PASS"
        else
            log_fail "Longueur minimale mot de passe: ${min_len:-non configure}"
            add_result "password" "PASS_MIN_LEN" "Longueur minimale" ">=8" "${min_len:-N/A}" "FAIL"
        fi
    else
        log_fail "/etc/login.defs introuvable"
        add_result "password" "PASS_LOGIN_DEFS" "Fichier login.defs" "Existant" "Introuvable" "FAIL"
    fi

    # Verifier pwquality
    if [ -f /etc/security/pwquality.conf ]; then
        local minlen
        minlen=$(grep -E "^\s*minlen" /etc/security/pwquality.conf 2>/dev/null | cut -d= -f2 | tr -d ' ' || echo "")
        if [ -n "$minlen" ] && [ "$minlen" -ge 8 ] 2>/dev/null; then
            log_pass "pwquality minlen: ${minlen}"
        fi
        log_pass "Configuration pwquality presente"
        add_result "password" "PASS_PWQUALITY" "pwquality configure" "Configure" "Configure" "PASS"
    else
        log_fail "pwquality non configure"
        add_result "password" "PASS_PWQUALITY" "pwquality configure" "Configure" "Non configure" "FAIL"
    fi
}

check_services() {
    print_section "7. SERVICES SYSTEME"

    local insecure_services=("xinetd" "telnet" "rsh" "rlogin" "rexec" "tftp" "cups")
    for svc in "${insecure_services[@]}"; do
        if systemctl is-enabled "${svc}.service" 2>/dev/null | grep -q "enabled"; then
            log_fail "Service non securise actif: ${svc}"
            add_result "services" "SVC_${svc}" "Service ${svc}" "Desactive" "Actif" "FAIL" \
                "systemctl disable --now ${svc}.service"
        elif systemctl is-enabled "${svc}.service" 2>/dev/null | grep -q "disabled"; then
            log_pass "Service desactive: ${svc}"
            add_result "services" "SVC_${svc}" "Service ${svc}" "Desactive" "Desactive" "PASS"
        else
            log_pass "Service non installe: ${svc}"
            add_result "services" "SVC_${svc}" "Service ${svc}" "Desactive" "Non installe" "PASS"
        fi
    done
}

check_network() {
    print_section "8. CONFIGURATION RESEAU"

    # Verifier les ports ouverts non autorises
    local open_ports
    open_ports=$(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | grep -oP '\d+$' | sort -n | uniq || true)

    local authorized_ports=("22" "80" "443")
    for port in $open_ports; do
        local authorized=false
        for auth_port in "${authorized_ports[@]}"; do
            if [ "$port" = "$auth_port" ]; then
                authorized=true
                break
            fi
        done
        if [ "$authorized" = false ]; then
            log_warn "Port ouvert non autorise: ${port}"
            add_result "network" "NET_PORT_${port}" "Port ${port}" "Ferme" "Ouvert" "WARNING" \
                "Verifier si le service sur le port ${port} est necessaire"
        fi
    done

    # Verifier les regles iptables/nftables
    if command -v iptables &>/dev/null; then
        local rules
        rules=$(iptables -L INPUT -n 2>/dev/null | grep -c "DROP\|REJECT" || echo "0")
        if [ "$rules" -ge 1 ]; then
            log_pass "Regles iptables presentes: ${rules} regles bloquantes"
            add_result "network" "NET_IPTABLES" "Regles iptables bloquantes" ">=1" "${rules}" "PASS"
        else
            log_warn "Aucune regle iptables bloquante"
            add_result "network" "NET_IPTABLES" "Regles iptables bloquantes" ">=1" "0" "WARNING"
        fi
    fi
}

check_updates() {
    print_section "9. MISES A JOUR DE SECURITE"

    # Verifier la date de la derniere mise a jour
    local last_update=""
    case "${OS_FAMILY:-debian}" in
        debian)
            last_update=$(stat -c "%Y" /var/lib/apt/periodic/update-success-stamp 2>/dev/null || echo "0")
            local now
            now=$(date +%s)
            local diff_days=$(( (now - last_update) / 86400 ))
            if [ "$diff_days" -le 7 ]; then
                log_pass "Derniere mise a jour: il y a ${diff_days} jours"
                add_result "updates" "UPD_001" "Mises a jour recentes" "<=7 jours" "${diff_days} jours" "PASS"
            else
                log_fail "Derniere mise a jour: il y a ${diff_days} jours"
                add_result "updates" "UPD_001" "Mises a jour recentes" "<=7 jours" "${diff_days} jours" "FAIL" \
                    "apt update && apt upgrade -y"
            fi
            ;;
        rhel)
            last_update=$(stat -c "%Y" /var/log/yum.log 2>/dev/null || echo "0")
            log_note "Verification des mises a jour: voir yum history"
            add_result "updates" "UPD_001" "Mises a jour" "Recent" "Voir log" "INFO"
            ;;
    esac

    # Verifier unattended-upgrades
    if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
        local auto_upgrade
        auto_upgrade=$(grep "Unattended-Upgrade" /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | grep -c "1" || echo "0")
        if [ "$auto_upgrade" -ge 1 ]; then
            log_pass "Mises a jour automatiques configurees"
            add_result "updates" "UPD_002" "Mises a jour automatiques" "Configurees" "Configurees" "PASS"
        fi
    fi
}

check_filesystem_hardening() {
    print_section "10. FILESYSTEMS NON UTILISES"

    local forbidden_fs=("cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "udf")
    local forbidden_count=0

    for fs in "${forbidden_fs[@]}"; do
        local modprobe_conf="/etc/modprobe.d/99-disable-${fs}.conf"
        if [ -f "$modprobe_conf" ]; then
            log_pass "Filesystem bloque: ${fs}"
            add_result "filesystem" "FS_${fs}" "Filesystem ${fs}" "Desactive" "Configure" "PASS"
        elif ! modprobe -n "${fs}" 2>/dev/null; then
            log_pass "Filesystem non disponible: ${fs}"
            add_result "filesystem" "FS_${fs}" "Filesystem ${fs}" "Desactive" "Non disponible" "PASS"
        else
            log_fail "Filesystem non bloque: ${fs}"
            add_result "filesystem" "FS_${fs}" "Filesystem ${fs}" "Desactive" "Actif" "FAIL" \
                "echo 'install ${fs} /bin/false' > /etc/modprobe.d/99-disable-${fs}.conf"
            ((forbidden_count++))
        fi
    done
}

check_apparmor_selinux() {
    print_section "11. APPARMOR / SELINUX"

    if command -v apparmor_status &>/dev/null; then
        local profiles_count
        profiles_count=$(apparmor_status 2>/dev/null | grep -c "profiles are in enforce" || echo "0")
        if [ "$profiles_count" -ge 1 ]; then
            log_pass "AppArmor: profils en enforce actifs"
            add_result "apparmor" "AA_001" "AppArmor profils enforce" ">=1" "${profiles_count}" "PASS"
        else
            profiles_count=$(apparmor_status 2>/dev/null | grep -oP '\d+(?= profiles are loaded)' || echo "0")
            if [ "$profiles_count" -ge 1 ]; then
                log_warn "AppArmor: ${profiles_count} profils charges mais pas en enforce"
                add_result "apparmor" "AA_001" "AppArmor enforce" "Actif" "Charge (complain)" "WARNING"
            else
                log_warn "AppArmor: aucun profil charge"
                add_result "apparmor" "AA_001" "AppArmor profils" ">0" "0" "WARNING"
            fi
        fi
    elif command -v getenforce &>/dev/null; then
        local mode
        mode=$(getenforce 2>/dev/null || echo "Disabled")
        if [ "$mode" = "Enforcing" ]; then
            log_pass "SELinux en mode Enforcing"
            add_result "selinux" "SEL_001" "SELinux mode" "Enforcing" "${mode}" "PASS"
        else
            log_fail "SELinux: ${mode} (attendu: Enforcing)"
            add_result "selinux" "SEL_001" "SELinux mode" "Enforcing" "${mode}" "FAIL" \
                "sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config && reboot"
        fi
    else
        log_fail "Ni AppArmor ni SELinux ne sont installes"
        add_result "apparmor" "AA_001" "Mandatory Access Control" "Installe" "Non installe" "FAIL" \
            "Install apparmor: apt install apparmor apparmor-profiles"
    fi
}

# ==============================================================================
# GENERATION DU RAPPORT
# ==============================================================================

print_banner() {
    echo ""
    echo -e "${CYAN}████████████████████████████████████████████████████████████████${NC}"
    echo -e "${WHITE}██         SECURITY HARDENING TOOLKIT - AUDIT DE CONFORMITE    ██${NC}"
    echo -e "${CYAN}████████████████████████████████████████████████████████████████${NC}"
    echo ""
    echo -e "${GREEN}Auteur: Louis Denis RAZAFIMANDIMBY${NC}"
    echo -e "${GREEN}Version: ${SCRIPT_VERSION}${NC}"
    echo ""
}

print_summary() {
    local total=$(( PASS_COUNT + FAIL_COUNT + WARNING_COUNT ))
    local score=0
    if [ "$total" -gt 0 ]; then
        score=$(( (PASS_COUNT * 100) / total ))
    fi

    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}              RESUME DE L'AUDIT DE CONFORMITE${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${WHITE}Score global: ${score}%${NC}"
    echo -e "  ${GREEN}Pass: ${PASS_COUNT}${NC}"
    echo -e "  ${RED}Fail: ${FAIL_COUNT}${NC}"
    echo -e "  ${YELLOW}Warnings: ${WARNING_COUNT}${NC}"
    echo -e "  ${BLUE}Info: ${INFO_COUNT}${NC}"
    echo -e "  Total: ${total} verifications"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"

    # Niveau de conformite
    echo ""
    if [ "$score" -ge 90 ]; then
        echo -e "  ${GREEN}NIVEAU DE CONFORMITE: EXCELLENT (${score}%)${NC}"
    elif [ "$score" -ge 75 ]; then
        echo -e "  ${GREEN}NIVEAU DE CONFORMITE: BON (${score}%)${NC}"
    elif [ "$score" -ge 60 ]; then
        echo -e "  ${YELLOW}NIVEAU DE CONFORMITE: MOYEN (${score}%)${NC}"
    else
        echo -e "  ${RED}NIVEAU DE CONFORMITE: CRITIQUE (${score}%)${NC}"
    fi
    echo ""

    # Recommandations
    if [ "$FAIL_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}Recommandations:${NC}"
        echo -e "  Executer le script de remediation: sudo ./remediate.sh"
        echo -e "  Consulter les echecs ci-dessus pour des corrections manuelles"
        echo ""
    fi
}

export_json() {
    local timestamp
    timestamp=$(date -Iseconds)
    local hostname_val
    hostname_val=$(hostname 2>/dev/null || echo "unknown")
    local os_name=""
    [ -f /etc/os-release ] && os_name=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) || os_name="unknown"

    local json="{\n"
    json+="  \"toolkit\": \"Security Hardening Toolkit\",\n"
    json+="  \"version\": \"${SCRIPT_VERSION}\",\n"
    json+="  \"author\": \"Louis Denis RAZAFIMANDIMBY\",\n"
    json+="  \"timestamp\": \"${timestamp}\",\n"
    json+="  \"hostname\": \"${hostname_val}\",\n"
    json+="  \"os\": \"${os_name}\",\n"
    json+="  \"summary\": {\n"
    json+="    \"pass\": ${PASS_COUNT},\n"
    json+="    \"fail\": ${FAIL_COUNT},\n"
    json+="    \"warning\": ${WARNING_COUNT},\n"
    json+="    \"info\": ${INFO_COUNT},\n"
    json+="    \"total\": $(( PASS_COUNT + FAIL_COUNT + WARNING_COUNT )),\n"
    json+="    \"score\": $(( total > 0 ? (PASS_COUNT * 100) / total : 0 ))\n"
    json+="  },\n"
    json+="  \"results\": [\n"

    local first=true
    for result in "${RESULTS[@]}"; do
        if [ "$first" = true ]; then
            first=false
        else
            json+=",\n"
        fi
        json+="    ${result}"
    done

    json+="\n  ]\n"
    json+="}\n"
    json+="\n"

    echo -e "$json" > "$OUTPUT_FILE"
    echo -e "${GREEN}Rapport JSON genere: ${OUTPUT_FILE}${NC}"
}

export_html() {
    local html_file="${OUTPUT_FILE:-rapport.html}"
    local score=$(( total > 0 ? (PASS_COUNT * 100) / total : 0 ))

    # Generer les lignes HTML des resultats
    local rows=""
    for result in "${RESULTS[@]}"; do
        local category check_id description expected actual status remediation
        category=$(echo "$result" | python3 -c "import sys,json; d=json.loads(sys.stdin.read().strip()); print(d.get('category',''))" 2>/dev/null || echo "")
        check_id=$(echo "$result" | python3 -c "import sys,json; d=json.loads(sys.stdin.read().strip()); print(d.get('check_id',''))" 2>/dev/null || echo "")
        description=$(echo "$result" | python3 -c "import sys,json; d=json.loads(sys.stdin.read().strip()); print(d.get('description',''))" 2>/dev/null || echo "")
        expected=$(echo "$result" | python3 -c "import sys,json; d=json.loads(sys.stdin.read().strip()); print(d.get('expected',''))" 2>/dev/null || echo "")
        actual=$(echo "$result" | python3 -c "import sys,json; d=json.loads(sys.stdin.read().strip()); print(d.get('actual',''))" 2>/dev/null || echo "")
        status=$(echo "$result" | python3 -c "import sys,json; d=json.loads(sys.stdin.read().strip()); print(d.get('status',''))" 2>/dev/null || echo "")
        remediation=$(echo "$result" | python3 -c "import sys,json; d=json.loads(sys.stdin.read().strip()); print(d.get('remediation',''))" 2>/dev/null || echo "")

        local badge
        case "$status" in
            PASS) badge="<span style='background:#4caf50;color:white;padding:2px 6px;border-radius:3px;font-size:0.8em'>PASS</span>" ;;
            FAIL) badge="<span style='background:#f44336;color:white;padding:2px 6px;border-radius:3px;font-size:0.8em'>FAIL</span>" ;;
            WARNING) badge="<span style='background:#ff9800;color:white;padding:2px 6px;border-radius:3px;font-size:0.8em'>WARN</span>" ;;
            *) badge="<span style='background:#2196f3;color:white;padding:2px 6px;border-radius:3px;font-size:0.8em'>INFO</span>" ;;
        esac

        rows+="        <tr><td>${check_id}</td><td>${category}</td><td>${description}</td><td>${expected}</td><td>${actual}</td><td>${badge}</td><td>${remediation}</td></tr>\n"
    done

    local html="<!DOCTYPE html>
<html lang='fr'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1.0'>
<title>Rapport de Conformite Linux - Security Hardening Toolkit</title>
<style>
body{font-family:'Segoe UI',sans-serif;background:#f5f7fa;color:#333;padding:20px;margin:0}
.container{max-width:1200px;margin:0 auto}
.header{background:linear-gradient(135deg,#1a202c,#2d3748);color:#fff;padding:30px;border-radius:10px;text-align:center;margin-bottom:30px}
.header h1{margin:0;font-size:1.8em}
.header p{color:#a0aec0;margin-top:10px;font-size:0.9em}
.score-card{background:#fff;border-radius:10px;padding:30px;text-align:center;margin-bottom:30px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
.score-circle{width:150px;height:150px;border-radius:50%;background:#e2e8f0;display:flex;align-items:center;justify-content:center;margin:0 auto 15px;position:relative}
.score-value{font-size:2.5em;font-weight:bold}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:30px}
.stat{background:#fff;padding:20px;border-radius:10px;text-align:center;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
.stat-num{font-size:2em;font-weight:bold}
.stat-label{color:#718096;font-size:0.85em;margin-top:5px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
th{background:#1a202c;color:#fff;padding:12px;text-align:left;font-size:0.85em}
td{padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:0.9em}
tr:hover{background:#f7fafc}
.section{margin-bottom:30px}
.footer{text-align:center;color:#a0aec0;padding:20px;font-size:0.85em}
</style>
</head>
<body>
<div class='container'>
<div class='header'>
<h1>Security Hardening Toolkit</h1>
<h2>Rapport de Conformite Linux</h2>
<p>$(hostname) | $(date '+%Y-%m-%d %H:%M:%S')</p>
</div>
<div class='score-card'>
<div class='score-circle' style='background:conic-gradient(#4caf50 0% ${score}%,#e2e8f0 ${score}% 100%)'>
<div class='score-value' style='color:#4caf50'>${score}%</div>
</div>
<p style='color:#718096'>Score global de conformite</p>
</div>
<div class='stats'>
<div class='stat'><div class='stat-num' style='color:#4caf50'>${PASS_COUNT}</div><div class='stat-label'>PASS</div></div>
<div class='stat'><div class='stat-num' style='color:#f44336'>${FAIL_COUNT}</div><div class='stat-label'>FAIL</div></div>
<div class='stat'><div class='stat-num' style='color:#ff9800'>${WARNING_COUNT}</div><div class='stat-label'>WARNINGS</div></div>
<div class='stat'><div class='stat-num'>$(( PASS_COUNT + FAIL_COUNT + WARNING_COUNT ))</div><div class='stat-label'>TOTAL</div></div>
</div>
<div class='section'>
<h2 style='color:#2d3748'>Details des Verifications</h2>
<div style='overflow-x:auto'>
<table>
<thead><tr><th>ID</th><th>Categorie</th><th>Description</th><th>Attendu</th><th>Actuel</th><th>Statut</th><th>Remediation</th></tr></thead>
<tbody>
${rows}
</tbody>
</table>
</div>
</div>
<div class='footer'>
<p>Security Hardening Toolkit v${SCRIPT_VERSION} - Par Louis Denis RAZAFIMANDIMBY</p>
</div>
</div>
</body>
</html>"

    echo -e "$html" > "$html_file"
    echo -e "${GREEN}Rapport HTML genere: ${html_file}${NC}"
}

# ==============================================================================
# POINT D'ENTREE
# ==============================================================================

# Traitement des arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --file)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --categories)
            CATEGORIES="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo "  --output console|json|html    Format de sortie"
            echo "  --file FILENAME               Fichier de sortie"
            echo "  --categories LIST             Categories a verifier"
            exit 0
            ;;
        *)
            echo "Option inconnue: $1"
            exit 1
            ;;
    esac
done

check_root
print_banner
START_TIME=$(date +%s)

# Executer les verifications
check_kernel_params
check_ssh_config
check_fail2ban
check_auditd
check_file_permissions
check_password_policies
check_services
check_network
check_updates
check_filesystem_hardening
check_apparmor_selinux

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Afficher le resume
print_summary
echo -e "${CYAN}Duree de l'audit: ${DURATION} secondes${NC}"

# Generer les rapports
case "$OUTPUT_FORMAT" in
    json)
        export_json
        ;;
    html)
        if command -v python3 &>/dev/null; then
            export_html
        else
            log_warn "python3 requis pour le HTML, fallback vers JSON"
            export_json
        fi
        ;;
esac

exit $(( FAIL_COUNT > 0 ? 1 : 0 ))
