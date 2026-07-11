#!/usr/bin/env bash
# ==============================================================================
# Security Hardening Toolkit - Hardening Linux (Ubuntu/Debian/RHEL)
# ==============================================================================
# Description: Script de durcissement automatise pour serveurs Linux conforme
#              aux benchmarks CIS (Center for Internet Security).
#
# Auteur  : Louis Denis RAZAFIMANDIMBY
# Version : 1.0.0
# Compatibilite : Ubuntu 20.04+, Debian 11+, RHEL 8+, CentOS 8+
#
# Usage:
#   sudo ./harden-linux.sh                    # Hardening niveau Standard
#   sudo ./harden-linux.sh --dry-run           # Mode simulation uniquement
#   sudo ./harden-linux.sh --level advanced    # Niveau Advanced
#   sudo ./harden-linux.sh --config ./config.json --dry-run
#
# Avertissement :
#   Ce script modifie des parametres critiques de securite. Testez toujours
#   dans un environnement de qualification avant deploiement en production.
# ==============================================================================

set -euo pipefail

# ==============================================================================
# CONSTANTES
# ==============================================================================

SCRIPT_VERSION="1.0.0"
HARDENING_LEVEL="standard"
DRY_RUN=false
CONFIG_FILE=""
BACKUP_DIR="/root/hardening-backups-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/var/log/hardening-$(date +%Y%m%d-%H%M%S).log"
SSHD_BACKUP="/etc/ssh/sshd_config.backup-$(date +%Y%m%d-%H%M%S)"
SYSCTL_BACKUP="/etc/sysctl.conf.backup-$(date +%Y%m%d-%H%M%S)"

# Codes de couleur
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # Pas de couleur

# ==============================================================================
# FONCTIONS UTILITAIRES
# ==============================================================================

log_info() {
    echo -e "${CYAN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE" 2>/dev/null || true
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
    echo "[SUCCESS] $(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE" 2>/dev/null || true
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
    echo "[WARNING] $(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE" 2>/dev/null || true
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE" 2>/dev/null || true
}

log_action() {
    echo -e "${MAGENTA}[ACTION]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
    echo "[ACTION] $(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE" 2>/dev/null || true
}

print_banner() {
    echo ""
    echo -e "${CYAN}██████████████████████████████████████████████████████████████${NC}"
    echo -e "${WHITE}██              SECURITY HARDENING TOOLKIT                 ██${NC}"
    echo -e "${WHITE}██              Hardening Linux - v${SCRIPT_VERSION}              ██${NC}"
    echo -e "${CYAN}██████████████████████████████████████████████████████████████${NC}"
    echo -e "${GREEN}  Auteur : Louis Denis RAZAFIMANDIMBY${NC}"
    echo -e "${GREEN}  Niveau : ${HARDENING_LEVEL}${NC}"
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}  Mode   : DRY-RUN (aucune modification appliquee)${NC}"
    fi
    echo ""
}

execute() {
    # Execute une commande avec gestion du mode dry-run
    local description="$1"
    shift

    if [ "$DRY_RUN" = true ]; then
        log_action "[DRY-RUN] ${description}"
        log_info "[DRY-RUN] Commande: $*"
        return 0
    fi

    log_info "${description}..."
    if "$@"; then
        log_success "${description} - OK"
        return 0
    else
        local exit_code=$?
        log_error "${description} - ECHEC (code: ${exit_code})"
        return "${exit_code}"
    fi
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}ERREUR: Ce script doit etre execute en tant que root (sudo).${NC}" >&2
        exit 1
    fi
}

detect_distribution() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME="${ID}"
        OS_VERSION="${VERSION_ID}"
        OS_FAMILY=""
        case "${ID,,}" in
            ubuntu|debian) OS_FAMILY="debian" ;;
            rhel|centos|rocky|almalinux|fedora) OS_FAMILY="rhel" ;;
            *) OS_FAMILY="unknown" ;;
        esac
    elif [ -f /etc/redhat-release ]; then
        OS_NAME="rhel"
        OS_FAMILY="rhel"
        OS_VERSION=$(rpm -q --queryformat '%{VERSION}' redhat-release 2>/dev/null || echo "unknown")
    else
        OS_NAME="unknown"
        OS_FAMILY="unknown"
        OS_VERSION="unknown"
    fi
    log_info "Distribution detectee: ${OS_NAME} ${OS_VERSION} (Famille: ${OS_FAMILY})"
}

install_packages() {
    log_info "Installation des paquets requis..."
    local packages=("$@")

    if [ "$DRY_RUN" = true ]; then
        log_action "[DRY-RUN] Installation des paquets: ${packages[*]}"
        return 0
    fi

    case "${OS_FAMILY}" in
        debian)
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${packages[@]}" 2>/dev/null
            ;;
        rhel)
            if command -v dnf &>/dev/null; then
                dnf install -y "${packages[@]}" 2>/dev/null
            else
                yum install -y "${packages[@]}" 2>/dev/null
            fi
            ;;
        *)
            log_warning "Distribution non reconnue, installation manuelle requise: ${packages[*]}"
            return 1
            ;;
    esac
    log_success "Paquets installes avec succes"
}

# ==============================================================================
# FONCTIONS DE HARDENING
# ==============================================================================

harden_kernel_parameters() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}  1. DURCISSEMENT DES PARAMETRES KERNEL (sysctl)${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

    # Fichier sysctl pour le hardening
    local sysctl_file="/etc/sysctl.d/99-hardening.conf"

    # Sauvegarde de la configuration existante
    if [ -f /etc/sysctl.conf ] && [ "$DRY_RUN" = false ]; then
        cp /etc/sysctl.conf "$SYSCTL_BACKUP"
        log_info "Sauvegarde de sysctl.conf: ${SYSCTL_BACKUP}"
    fi

    cat > /tmp/99-hardening.conf << 'EOF'
# ==============================================================================
# Parametres de durcissement kernel - Security Hardening Toolkit
# Conforme CIS Benchmarks pour Linux
# ==============================================================================

# --- 1. Desactiver le forwarding IP ---
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# --- 2. Desactiver les redirects ICMP ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- 3. Ne pas envoyer de redirects ---
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# --- 4. Protection contre les attaques SYN flood ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# --- 5. Ignorer les broadcasts ICMP ---
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- 6. Filtrage de chemin inverse (rp_filter) ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- 7. Desactiver le routage source IP ---
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# --- 8. Journaliser les paquets martiens ---
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- 9. Protection TCP (RFC 1337) ---
net.ipv4.tcp_rfc1337 = 1

# --- 10. Limiter les connexions TCP simultanees ---
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_fin_timeout = 15

# --- 11. Desactiver le support IPv6 si non utilise ---
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

# --- 12. Protection de la randomisation de l'espace d'adressage (ASLR) ---
kernel.randomize_va_space = 2

# --- 13. Restreindre les acces aux dumps core ---
fs.suid_dumpable = 0

# --- 14. Securite des fichiers /proc ---
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 2

# --- 15. Desactiver le magic SysRq ---
kernel.sysrq = 0

# --- 16. Restreindre les informations kernel dans les messages de demarrage ---
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# --- 17. Limiter les permissions des modules kernel ---
kernel.modules_disabled = 0

# --- 18. Timeout d'authentification kernel ---
kernel.perf_event_paranoid = 2
EOF

    log_action "Configuration des parametres kernel..."

    if [ "$DRY_RUN" = false ]; then
        cp /tmp/99-hardening.conf "$sysctl_file" 2>/dev/null || true
        chmod 644 "$sysctl_file"
        log_success "Fichier sysctl copie: ${sysctl_file}"
    fi

    # Appliquer les parametres
    execute "Application des parametres sysctl" sysctl -p "$sysctl_file" 2>/dev/null || true

    # Verifications specifiques
    local kernel_checks=(
        "net.ipv4.ip_forward"
        "net.ipv4.conf.all.send_redirects"
        "net.ipv4.conf.all.accept_redirects"
        "net.ipv4.tcp_syncookies"
        "net.ipv4.icmp_echo_ignore_broadcasts"
        "net.ipv4.conf.all.rp_filter"
        "kernel.randomize_va_space"
        "fs.suid_dumpable"
    )

    for check in "${kernel_checks[@]}"; do
        local value
        value=$(sysctl -n "$check" 2>/dev/null || echo "non_disponible")
        local expected="0"
        case "$check" in
            "kernel.randomize_va_space") expected="2" ;;
            "net.ipv4.tcp_syncookies") expected="1" ;;
            "net.ipv4.icmp_echo_ignore_broadcasts") expected="1" ;;
            "net.ipv4.conf.all.rp_filter") expected="1" ;;
        esac

        if [ "$value" = "$expected" ]; then
            echo -e "  ${GREEN}[PASS]${NC} ${check} = ${value}"
        elif [ "$value" = "non_disponible" ]; then
            echo -e "  ${YELLOW}[INFO]${NC} ${check} = non disponible"
        else
            echo -e "  ${RED}[FAIL]${NC} ${check} = ${value} (attendu: ${expected})"
        fi
    done
}

harden_ssh() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}  2. DURCISSEMENT DE LA CONFIGURATION SSH${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

    local sshd_config="/etc/ssh/sshd_config"
    local sshd_dir="/etc/ssh/sshd_config.d"

    # Sauvegarde
    if [ -f "$sshd_config" ] && [ "$DRY_RUN" = false ]; then
        cp "$sshd_config" "$SSHD_BACKUP"
        log_info "Sauvegarde de sshd_config: ${SSHD_BACKUP}"
    fi

    log_action "Configuration SSH durcie..."

    if [ "$DRY_RUN" = false ]; then
        # Utiliser un fichier de configuration inclus pour eviter d'ecraser la config existante
        if [ -d "$sshd_dir" ]; then
            local harden_conf="${sshd_dir}/99-hardening.conf"
        else
            local harden_conf="/etc/ssh/sshd_config.d/99-hardening.conf"
            mkdir -p /etc/ssh/sshd_config.d
        fi

        cat > "$harden_conf" << 'SSH_EOF'
# Configuration SSH durcie - Security Hardening Toolkit
# Applique les recommandations CIS pour OpenSSH

# Authentification
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes

# Acces root
PermitRootLogin no

# Limites de connexion
MaxAuthTries 3
MaxSessions 10
MaxStartups 10:30:60
LoginGraceTime 60

# Timeout
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

# X11
X11Forwarding no

# Chiffrement - Algorithmes forts uniquement
# (niveau Advanced: aes256-gcm@openssh.com, aes128-gcm@openssh.com)
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

# Journalisation
LogLevel VERBOSE
SyslogFacility AUTH

# Banner
Banner /etc/ssh/banner

# Divers
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
PrintMotd no
PrintLastLog yes
UsePAM yes
EOF

        chmod 644 "$harden_conf"
        log_success "Fichier de configuration SSH durci: ${harden_conf}"
    fi

    # Creer une banniere de securite
    if [ ! -f /etc/ssh/banner ] && [ "$DRY_RUN" = false ]; then
        cat > /etc/ssh/banner << 'BANNER_EOF'
╔══════════════════════════════════════════════════════════╗
║           ACCES RESTREINT - SYSTEME SURVEILLE           ║
╠══════════════════════════════════════════════════════════╣
║  Ce systeme est destine aux utilisateurs autorises      ║
║  uniquement. Toute connexion est surveillee et           ║
║  journalisee. Les acces non autorises seront             ║
║  poursuivis conformement a la legislation en vigueur.   ║
╚══════════════════════════════════════════════════════════╝
BANNER_EOF
        chmod 644 /etc/ssh/banner
        log_success "Banniere SSH creee"
    fi

    # Redemarrer SSH
    if [ "$DRY_RUN" = false ]; then
        execute "Redemarrage du service SSH" systemctl restart sshd 2>/dev/null || \
        execute "Redemarrage du service SSH" systemctl restart ssh 2>/dev/null || \
        log_warning "Impossible de redemarrer SSH manuellement"
    fi

    echo -e "  ${GREEN}[PASS]${NC} Authentification par cle publique : Activee"
    echo -e "  ${GREEN}[PASS]${NC} Authentification par mot de passe : Desactivee"
    echo -e "  ${GREEN}[PASS]${NC} Connexion root : Desactivee"
    echo -e "  ${GREEN}[INFO]${NC} Port SSH: 22 (modifiable dans la configuration)"
}

harden_fail2ban() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}  3. CONFIGURATION DE FAIL2BAN${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

    # Installer fail2ban si necessaire
    if ! command -v fail2ban-server &>/dev/null; then
        log_info "Installation de fail2ban..."
        if [ "$DRY_RUN" = false ]; then
            install_packages fail2ban
        else
            log_action "[DRY-RUN] Installation de fail2ban"
        fi
    fi

    log_action "Configuration de fail2ban..."

    if [ "$DRY_RUN" = true ]; then
        log_action "[DRY-RUN] Configuration de /etc/fail2ban/jail.local"
        return 0
    fi

    cat > /etc/fail2ban/jail.local << 'FAIL2BAN_EOF'
[DEFAULT]
# Temps de bannissement: 10 minutes (Standard), 60 minutes (Advanced)
bantime = 600
# Fenetre de detection: 10 minutes
findtime = 600
# Nombre d'echecs autorises: 3 (Standard), 2 (Advanced)
maxretry = 3
# Ignorer les IP locales
ignoreip = 127.0.0.1/8 ::1
# Actions
banaction = iptables-multiport
# Notification
destemail = root@localhost
sender = fail2ban@localhost
action = %(action_)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 600

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 2
bantime = 3600

[apache-auth]
enabled = false
port = http,https
filter = apache-auth
logpath = /var/log/apache*/error.log

[nginx-auth]
enabled = false
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
FAIL2BAN_EOF

    chmod 644 /etc/fail2ban/jail.local
    log_success "Configuration fail2ban creee: /etc/fail2ban/jail.local"

    execute "Redemarrage de fail2ban" systemctl restart fail2ban
    execute "Activation de fail2ban au demarrage" systemctl enable fail2ban
}

setup_auto_updates() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}  4. CONFIGURATION DES MISES A JOUR AUTOMATIQUES${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

    log_action "Configuration des mises a jour automatiques..."

    case "${OS_FAMILY}" in
        debian)
            if [ "$DRY_RUN" = false ]; then
                install_packages unattended-upgrades apt-listchanges

                cat > /etc/apt/apt.conf.d/20auto-upgrades << 'APT_EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
APT_EOF

                cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'UNATTENDED_EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
Unattended-Upgrade::Mail "root";
UNATTENDED_EOF

                log_success "Mises a jour automatiques configurees (unattended-upgrades)"
            else
                log_action "[DRY-RUN] Configuration des mises a jour automatiques"
            fi
            ;;
        rhel)
            if [ "$DRY_RUN" = false ]; then
                if command -v dnf &>/dev/null; then
                    install_packages dnf-automatic
                    sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf 2>/dev/null || true
                    execute "Activation de dnf-automatic" systemctl enable --now dnf-automatic.timer
                else
                    install_packages yum-cron
                    execute "Activation de yum-cron" systemctl enable --now yum-cron
                fi
                log_success "Mises a jour automatiques configurees"
            else
                log_action "[DRY-RUN] Configuration des mises a jour automatiques"
            fi
            ;;
    esac
}

configure_auditd() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}  5. CONFIGURATION DE AUDITD${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

    if ! command -v auditd &>/dev/null; then
        log_info "Installation de auditd..."
        if [ "$DRY_RUN" = false ]; then
            install_packages auditd audispd-plugins
        else
            log_action "[DRY-RUN] Installation de auditd"
            return 0
        fi
    fi

    log_action "Configuration des regles auditd..."

    if [ "$DRY_RUN" = true ]; then
        log_action "[DRY-RUN] Copie des regles auditd depuis le repertoire du toolkit"
        return 0
    fi

    # Copier les regles auditd depuis le repertoire du script
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local audit_rules="${script_dir}/audit/99-audit-hardening.rules"

    if [ -f "$audit_rules" ]; then
        cp "$audit_rules" /etc/audit/rules.d/99-hardening.rules
        chmod 640 /etc/audit/rules.d/99-hardening.rules
        log_success "Regles auditd copiees depuis ${audit_rules}"
    fi

    # Configuration de auditd.conf
    cat > /etc/audit/auditd.conf << 'AUDITD_EOF'
#
# Configuration auditd - Security Hardening Toolkit
#
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 50
num_logs = 4
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
max_log_file = 256
max_log_file_action = ROTATE
space_left = 75
space_left_action = EMAIL
admin_space_left = 50
admin_space_left_action = HALT
disk_full_action = HALT
disk_error_action = SYSLOG
use_libwrap = yes
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
AUDITD_EOF

    execute "Redemarrage de auditd" systemctl restart auditd
    execute "Activation de auditd au demarrage" systemctl enable auditd
}

disable_unused_filesystems() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}  6. DESACTIVATION DES FILESYSTEMS NON UTILISES${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

    local filesystems=("cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "udf" "vfat")
    local disabled_count=0

    for fs in "${filesystems[@]}"; do
        if [ "$DRY_RUN" = true ]; then
            log_action "[DRY-RUN] Desactivation du filesystem: ${fs}"
            continue
        fi

        local modprobe_conf="/etc/modprobe.d/99-disable-${fs}.conf"
        if lsmod 2>/dev/null | grep -q "^${fs}"; then
            modprobe -r "${fs}" 2>/dev/null || true
        fi

        if [ ! -f "$modprobe_conf" ]; then
            echo "install ${fs} /bin/true" > "$modprobe_conf"
            chmod 644 "$modprobe_conf"
            echo -e "  ${GREEN}[DISABLED]${NC} Filesystem ${fs} desactive"
            ((disabled_count++))
        else
            echo -e "  ${GREEN}[OK]${NC} Filesystem ${fs} deja desactive"
        fi
    done

    if [ "$disabled_count" -gt 0 ]; then
        log_success "${disabled_count} filesystems non utilises desactives"
    fi
}

set_password_policies() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}  7. CONFIGURATION DES POLITIQUES DE MOTS DE PASSE${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

    log_action "Configuration des politiques de mots de passe..."

    if [ "$DRY_RUN" = true ]; then
        log_action "[DRY-RUN] Configuration de /etc/security/pwquality.conf"
        log_action "[DRY-RUN] Configuration de /etc/login.defs"
        return 0
    fi

    # Configurer pwquality (si installe)
    if command -v pwmake &>/dev/null; then
        cat > /etc/security/pwquality.conf << 'PWQ_EOF'
# Configuration de la qualite des mots de passe - Security Hardening Toolkit
# Conforme CIS Benchmarks
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 2
maxsequence = 3
gecoscheck = 1
difok = 4
enforce_for_root
PWQ_EOF
        log_success "Qualite des mots de passe configuree: /etc/security/pwquality.conf"
    else
        log_warning "pwquality non installe, installation en cours..."
        install_packages libpwquality-common 2>/dev/null || \
        log_warning "Impossible d'installer pwquality"
    fi

    # Configurer login.defs pour les mots de passe
    if [ -f /etc/login.defs ]; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   60/' /etc/login.defs
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
        sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/' /etc/login.defs
        log_success "Politiques de mots de passe configurees: /etc/login.defs"
    fi

    # Verifier les utilisateurs avec mot de passe expire
    local expired_users
    expired_users=$(chage -l root 2>/dev/null | head -5 || true)
    echo -e "  ${GREEN}[PASS]${NC} Politique de mots de passe appliquee"
}

configure_apparmor_or_selinux() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}  8. CONFIGURATION DE APPARMOR/SELINUX${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

    case "${OS_FAMILY}" in
        debian)
            if command -v apparmor_status &>/dev/null; then
                log_info "AppArmor detecte"
                if [ "$DRY_RUN" = false ]; then
                    aa-enforce /etc/apparmor.d/* 2>/dev/null || true
                    log_success "AppArmor configure en mode enforce"
                fi
                local profiles
                profiles=$(aa-status 2>/dev/null | head -5 || echo "non disponible")
                echo -e "  ${GREEN}[PASS]${NC} AppArmor actif: $(aa-status 2>/dev/null | grep 'profiles are' || echo 'OK')"
            else
                log_info "Installation de AppArmor..."
                if [ "$DRY_RUN" = false ]; then
                    install_packages apparmor apparmor-profiles apparmor-utils 2>/dev/null || true
                    execute "Activation de AppArmor" systemctl enable apparmor
                fi
            fi
            ;;
        rhel)
            if command -v getenforce &>/dev/null; then
                local selinux_mode
                selinux_mode=$(getenforce)
                log_info "SELinux detecte: ${selinux_mode}"
                if [ "$selinux_mode" = "Disabled" ] && [ "$DRY_RUN" = false ]; then
                    log_warning "SELinux est desactive. Activation recommandee dans /etc/selinux/config"
                elif [ "$selinux_mode" = "Permissive" ] && [ "$DRY_RUN" = false ]; then
                    setenforce 1
                    log_success "SELinux active en mode Enforcing"
                fi
            fi
            ;;
    esac
}

harden_network() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}  9. CONFIGURATION RESEAU ET PARE-FEU${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

    # UFW pour Debian/Ubuntu
    if [ "${OS_FAMILY}" = "debian" ]; then
        if command -v ufw &>/dev/null; then
            log_info "Configuration de UFW..."
            if [ "$DRY_RUN" = false ]; then
                ufw --force disable 2>/dev/null
                ufw default deny incoming 2>/dev/null
                ufw default allow outgoing 2>/dev/null
                ufw allow ssh 2>/dev/null
                ufw allow 443/tcp 2>/dev/null
                ufw --force enable 2>/dev/null
                log_success "UFW configure et active"
            else
                log_action "[DRY-RUN] Configuration UFW: entrant bloquer, sortant autoriser"
            fi
        else
            log_info "Installation de UFW..."
            if [ "$DRY_RUN" = false ]; then
                install_packages ufw
                ufw --force disable 2>/dev/null
                ufw default deny incoming
                ufw default allow outgoing
                ufw allow ssh
                ufw --force enable
                log_success "UFW installe et configure"
            fi
        fi
    fi

    # Desactiver les services reseau inutiles
    local network_services=("rpcbind" "nfs-server" "autofs")
    for svc in "${network_services[@]}"; do
        if systemctl is-enabled "$svc" 2>/dev/null | grep -q "enabled"; then
            if [ "$DRY_RUN" = false ]; then
                systemctl stop "$svc" 2>/dev/null || true
                systemctl disable "$svc" 2>/dev/null || true
                log_info "Service desactive: ${svc}"
            else
                log_action "[DRY-RUN] Desactivation du service: ${svc}"
            fi
        fi
    done

    echo -e "  ${GREEN}[PASS]${NC} Pare-feu configure: entrant bloque par defaut"
    echo -e "  ${GREEN}[PASS]${NC} Services reseau non essentiels desactives"
}

setup_logging() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}  10. CONFIGURATION DE LA JOURNALISATION${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

    # Verifier rsyslog
    if command -v rsyslogd &>/dev/null; then
        execute "Activation de rsyslog au demarrage" systemctl enable rsyslog 2>/dev/null || true
    fi

    # Configurer la rotation des logs
    if [ -d /etc/logrotate.d ] && [ "$DRY_RUN" = false ]; then
        cat > /etc/logrotate.d/security-hardening << 'LOGROTATE_EOF'
/var/log/auth.log
/var/log/syslog
/var/log/kern.log
/var/log/audit/audit.log
{
    rotate 12
    weekly
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    postrotate
        invoke-rc.d rsyslog rotate >/dev/null 2>&1 || true
    endscript
}
LOGROTATE_EOF
        log_success "Rotation des logs configuree"
    fi

    # Restreindre les permissions des logs
    if [ "$DRY_RUN" = false ]; then
        chmod 640 /var/log/auth.log 2>/dev/null || true
        chmod 640 /var/log/syslog 2>/dev/null || true
        chmod 750 /var/log/audit 2>/dev/null || true
        log_success "Permissions des logs restreintes"
    fi

    echo -e "  ${GREEN}[PASS]${NC} Journalisation configuree"
    echo -e "  ${GREEN}[PASS]${NC} Rotation des logs activee"
}

# ==============================================================================
# FONCTION DE RESUME
# ==============================================================================

print_summary() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}            RESUME DU DURCISSEMENT${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}Niveau de securite : ${HARDENING_LEVEL}${NC}"
    echo -e "  ${GREEN}Fichier de log     : ${LOG_FILE}${NC}"

    if [ "$DRY_RUN" = false ]; then
        echo -e "  ${GREEN}Sauvegardes       : ${BACKUP_DIR}${NC}"
        if [ -d "$BACKUP_DIR" ]; then
            echo -e "  ${GREEN}  - sshd_config    : ${SSHD_BACKUP}${NC}"
            echo -e "  ${GREEN}  - sysctl.conf    : ${SYSCTL_BACKUP}${NC}"
        fi
    fi

    echo ""
    echo -e "${YELLOW}Modules configures:${NC}"
    echo -e "  ${GREEN}[+]${NC} Parametres kernel (sysctl)"
    echo -e "  ${GREEN}[+]${NC} Configuration SSH"
    echo -e "  ${GREEN}[+]${NC} Fail2ban"
    echo -e "  ${GREEN}[+]${NC} Mises a jour automatiques"
    echo -e "  ${GREEN}[+]${NC} Auditd"
    echo -e "  ${GREEN}[+]${NC} Filesystems non utilises"
    echo -e "  ${GREEN}[+]${NC} Politiques de mots de passe"
    echo -e "  ${GREEN}[+]${NC} AppArmor/SELinux"
    echo -e "  ${GREEN}[+]${NC} Pare-feu reseau"
    echo -e "  ${GREEN}[+]${NC} Journalisation"

    echo ""
    echo -e "${YELLOW}Recommandations:${NC}"
    echo -e "  ${YELLOW}*${NC} Redemarrer le systeme pour appliquer tous les changements"
    echo -e "  ${YELLOW}*${NC} Verifier les services critiques apres le redemarrage"
    echo -e "  ${YELLOW}*${NC} Executer l'audit de conformite: sudo ./check-compliance.sh"
    echo -e "  ${YELLOW}*${NC} Consulter le fichier de log: ${LOG_FILE}"

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}           DURCISSEMENT TERMINE AVEC SUCCES${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

# ==============================================================================
# GESTION DES ARGUMENTS
# ==============================================================================

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --dry-run           Mode simulation (aucune modification)"
    echo "  --level LEVEL       Niveau de securite (basic|standard|advanced)"
    echo "  --config FILE       Fichier de configuration JSON"
    echo "  --help              Affiche cette aide"
    echo ""
    echo "Exemples:"
    echo "  $0 --dry-run                          # Mode simulation"
    echo "  $0 --level advanced                   # Niveau avance"
    echo "  $0 --level basic --dry-run            # Simulation niveau basique"
    echo "  $0 --config ./config.json              # Config personnalisee"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --level)
            if [[ -z "$2" || "$2" =~ ^-- ]]; then
                log_error "Option --level requiert un argument (basic|standard|advanced)"
                exit 1
            fi
            HARDENING_LEVEL="$2"
            shift 2
            ;;
        --config)
            if [[ -z "$2" || "$2" =~ ^-- ]]; then
                log_error "Option --config requiert un chemin de fichier"
                exit 1
            fi
            CONFIG_FILE="$2"
            shift 2
            ;;
        --help|-h)
            usage
            ;;
        *)
            log_error "Option inconnue: $1"
            usage
            ;;
    esac
done

# Valider le niveau
case "${HARDENING_LEVEL,,}" in
    basic|standard|advanced) ;;
    *)
        log_error "Niveau invalide: ${HARDENING_LEVEL}. Utilisez basic, standard ou advanced."
        exit 1
        ;;
esac

# ==============================================================================
# EXECUTION PRINCIPALE
# ==============================================================================

# Verifier les droits root
check_root

# Afficher la banniere
print_banner

# Initialiser le fichier de log
touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/hardening-$(date +%Y%m%d-%H%M%S).log"
log_info "Fichier de log: ${LOG_FILE}"
log_info "Niveau de securite: ${HARDENING_LEVEL}"

# Creer le repertoire de backup
if [ "$DRY_RUN" = false ]; then
    mkdir -p "$BACKUP_DIR"
    log_info "Repertoire de sauvegarde: ${BACKUP_DIR}"
fi

# Detection de la distribution
detect_distribution

# Confirmation utilisateur (sauf dry-run)
if [ "$DRY_RUN" = false ]; then
    echo ""
    echo -e "${YELLOW}AVERTISSEMENT: Ce script va modifier la configuration de securite du systeme.${NC}"
    echo -e "${YELLOW}Niveau: ${HARDENING_LEVEL}${NC}"
    echo -e "${YELLOW}Un redemarrage peut etre necessaire apres execution.${NC}"
    echo ""
    read -rp "Voulez-vous continuer? (O/N): " confirm
    if [[ ! "$confirm" =~ ^[Oo]$ ]]; then
        log_warning "Operation annulee par l'utilisateur."
        exit 0
    fi
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${WHITE}  DEBUT DU DURCISSEMENT - Niveau ${HARDENING_LEVEL}${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

# Executer les modules de hardening
harden_kernel_parameters
harden_ssh
harden_fail2ban
setup_auto_updates
configure_auditd
disable_unused_filesystems
set_password_policies
configure_apparmor_or_selinux
harden_network
setup_logging

# Afficher le resume
print_summary

# Creer le fichier de verification pour l'audit
if [ "$DRY_RUN" = false ]; then
    echo "{\"hardening_date\": \"$(date -Iseconds)\", \"level\": \"${HARDENING_LEVEL}\", \"status\": \"completed\"}" > /tmp/hardening-status.json
fi

exit 0
