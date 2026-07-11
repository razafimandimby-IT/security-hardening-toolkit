#!/usr/bin/env bash
# ==============================================================================
# Security Hardening Toolkit - Remediation Linux
# ==============================================================================
# Description: Corrige automatiquement les ecarts de securite identifies par
#              l'audit de conformite (check-compliance.sh). Prend en entree
#              le rapport JSON genere par l'audit.
#
# Auteur  : Louis Denis RAZAFIMANDIMBY
# Version : 1.0.0
#
# Usage:
#   sudo ./remediate.sh --report ./audit-result.json
#   sudo ./remediate.sh --report ./audit-result.json --categories "ssh,kernel"
#   sudo ./remediate.sh --report ./audit-result.json --dry-run
# ==============================================================================

set -euo pipefail

# ==============================================================================
# CONSTANTES
# ==============================================================================

SCRIPT_VERSION="1.0.0"
REPORT_FILE=""
CATEGORIES="all"
DRY_RUN=false
BACKUP_DIR="/root/remediation-backup-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/var/log/remediation-$(date +%Y%m%d-%H%M%S).log"
REMEDIATED_COUNT=0
SKIPPED_COUNT=0
FAILED_COUNT=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# ==============================================================================
# FONCTIONS
# ==============================================================================

log_info() { echo -e "${CYAN}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }
log_action() { echo -e "${WHITE}[ACTION]${NC} $1" | tee -a "$LOG_FILE"; }

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}ERREUR: Ce script necessite les droits root (sudo).${NC}" >&2
        exit 1
    fi
}

backup_file() {
    local file="$1"
    if [ ! -f "$file" ]; then
        return 0
    fi
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Sauvegarde de ${file}"
        return 0
    fi
    mkdir -p "$BACKUP_DIR"
    cp "$file" "${BACKUP_DIR}/"
    log_info "Sauvegarde: ${file} -> ${BACKUP_DIR}/"
}

# ==============================================================================
# FONCTIONS DE REMEDIATION
# ==============================================================================

remediate_kernel_param() {
    local param="$1"
    local value="$2"
    local sysctl_file="/etc/sysctl.d/99-hardening.conf"

    log_action "Correction: sysctl ${param}=${value}"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] sysctl -w ${param}=${value}"
        log_info "[DRY-RUN] echo '${param} = ${value}' >> ${sysctl_file}"
        ((SKIPPED_COUNT++))
        return 0
    fi

    # Appliquer immediatement
    if sysctl -w "${param}=${value}" 2>/dev/null; then
        # Rendre permanent
        if [ -f "$sysctl_file" ]; then
            # Remplacer ou ajouter
            if grep -q "^${param}" "$sysctl_file" 2>/dev/null; then
                sed -i "s/^${param}.*/${param} = ${value}/" "$sysctl_file"
            else
                echo "${param} = ${value}" >> "$sysctl_file"
            fi
        else
            echo "${param} = ${value}" > "$sysctl_file"
        fi
        log_success "Parametre kernel configure: ${param}=${value}"
        ((REMEDIATED_COUNT++))
    else
        log_error "Echec configuration: ${param}=${value}"
        ((FAILED_COUNT++))
    fi
}

remediate_ssh_setting() {
    local param="$1"
    local value="$2"
    local sshd_config="/etc/ssh/sshd_config"
    local sshd_harden="/etc/ssh/sshd_config.d/99-hardening.conf"

    log_action "Correction SSH: ${param} ${value}"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Configuration SSH: ${param} ${value}"
        ((SKIPPED_COUNT++))
        return 0
    fi

    backup_file "$sshd_config"

    mkdir -p /etc/ssh/sshd_config.d 2>/dev/null || true

    # Utiliser le fichier inclus
    if [ -n "$param" ] && [ -n "$value" ]; then
        if grep -q "^${param}" "$sshd_harden" 2>/dev/null; then
            sed -i "s/^${param}.*/${param} ${value}/" "$sshd_harden"
        else
            echo "${param} ${value}" >> "$sshd_harden"
        fi
        log_success "SSH configure: ${param} ${value}"
        ((REMEDIATED_COUNT++))
    fi
}

remediate_service() {
    local service="$1"
    log_action "Desactivation du service: ${service}"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] systemctl disable --now ${service}"
        ((SKIPPED_COUNT++))
        return 0
    fi

    if systemctl is-enabled "${service}" 2>/dev/null | grep -q "enabled"; then
        systemctl stop "${service}" 2>/dev/null || true
        systemctl disable "${service}" 2>/dev/null || true
        log_success "Service desactive: ${service}"
        ((REMEDIATED_COUNT++))
    else
        log_info "Service deja desactive: ${service}"
        ((SKIPPED_COUNT++))
    fi
}

remediate_file_permissions() {
    local file="$1"
    local expected_perm="$2"

    log_action "Correction permissions: ${file} -> ${expected_perm}"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] chmod ${expected_perm} ${file}"
        ((SKIPPED_COUNT++))
        return 0
    fi

    if [ -f "$file" ]; then
        backup_file "$file"
        chmod "${expected_perm}" "$file" 2>/dev/null && {
            log_success "Permissions corrigees: ${file} (${expected_perm})"
            ((REMEDIATED_COUNT++))
        } || {
            log_error "Echec correction permissions: ${file}"
            ((FAILED_COUNT++))
        }
    fi
}

remediate_password_policy() {
    log_action "Correction des politiques de mots de passe..."

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Configuration de /etc/login.defs et /etc/security/pwquality.conf"
        ((SKIPPED_COUNT++))
        return 0
    fi

    # login.defs
    if [ -f /etc/login.defs ]; then
        backup_file /etc/login.defs
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   60/' /etc/login.defs
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
        sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/' /etc/login.defs
    fi

    # pwquality.conf
    cat > /etc/security/pwquality.conf.d/99-hardening.conf << 'PWQ_EOF'
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 2
difok = 4
PWQ_EOF

    log_success "Politiques de mots de passe corrigees"
    ((REMEDIATED_COUNT++))
}

remediate_filesystem() {
    local fs="$1"
    local modprobe_conf="/etc/modprobe.d/99-disable-${fs}.conf"

    log_action "Blocage du filesystem: ${fs}"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] echo 'install ${fs} /bin/true' > ${modprobe_conf}"
        log_info "[DRY-RUN] modprobe -r ${fs}"
        ((SKIPPED_COUNT++))
        return 0
    fi

    if modprobe -r "${fs}" 2>/dev/null; then
        echo "install ${fs} /bin/true" > "$modprobe_conf"
        chmod 644 "$modprobe_conf"
        log_success "Filesystem bloque: ${fs}"
        ((REMEDIATED_COUNT++))
    else
        log_error "Echec blocage filesystem: ${fs}"
        ((FAILED_COUNT++))
    fi
}

remediate_auto_updates() {
    log_action "Configuration des mises a jour automatiques..."

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Configuration unattended-upgrades / dnf-automatic"
        ((SKIPPED_COUNT++))
        return 0
    fi

    if command -v apt-get &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades apt-listchanges 2>/dev/null || true
        cat > /etc/apt/apt.conf.d/20auto-upgrades << 'APT_EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
APT_EOF
        log_success "Mises a jour automatiques configurees (unattended-upgrades)"
        ((REMEDIATED_COUNT++))
    elif command -v dnf &>/dev/null; then
        dnf install -y dnf-automatic 2>/dev/null || true
        systemctl enable --now dnf-automatic.timer 2>/dev/null || true
        log_success "Mises a jour automatiques configurees (dnf-automatic)"
        ((REMEDIATED_COUNT++))
    fi
}

remediate_apparmor() {
    log_action "Configuration AppArmor..."

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Activation AppArmor"
        ((SKIPPED_COUNT++))
        return 0
    fi

    if command -v apparmor_status &>/dev/null; then
        if command -v aa-enforce &>/dev/null; then
            aa-enforce /etc/apparmor.d/* 2>/dev/null || true
            log_success "Profils AppArmor actives en enforce"
            ((REMEDIATED_COUNT++))
        fi
    fi
}

# ==============================================================================
# PARSING DU RAPPORT D'AUDIT
# ==============================================================================

parse_and_remediate() {
    if [ ! -f "$REPORT_FILE" ]; then
        log_error "Fichier de rapport introuvable: ${REPORT_FILE}"
        exit 1
    fi

    # Verifier la disponibilite de python3 ou jq
    if command -v python3 &>/dev/null; then
        log_info "Analyse du rapport avec python3..."
        local total_fails
        total_fails=$(python3 -c "import json; data=json.load(open('${REPORT_FILE}')); fails=[r for r in data.get('results',[]) if r.get('status')=='FAIL']; print(len(fails))" 2>/dev/null || echo "0")

        if [ "$total_fails" -eq 0 ]; then
            log_success "Aucune non-conformite a remedier dans le rapport."
            return 0
        fi

        log_warning "${total_fails} non-conformites identifiees"

        # Extraire et traiter chaque echec
        python3 -c "
import json
data = json.load(open('${REPORT_FILE}'))
for r in data.get('results', []):
    if r.get('status') == 'FAIL':
        print(f\"{r.get('check_id','')}|{r.get('category','')}|{r.get('description','')}|{r.get('expected','')}|{r.get('actual','')}|{r.get('remediation','')}\")
" | while IFS='|' read -r check_id category description expected actual remediation; do
            [ -z "$check_id" ] && continue

            # Filtrer par categorie
            if [ "$CATEGORIES" != "all" ]; then
                local cat_match=false
                IFS=',' read -ra CAT_LIST <<< "$CATEGORIES"
                for cat in "${CAT_LIST[@]}"; do
                    if [[ "${category,,}" == *"${cat,,}"* ]]; then
                        cat_match=true
                        break
                    fi
                done
                if [ "$cat_match" = false ]; then
                    continue
                fi
            fi

            echo ""
            log_info "Traitement de: ${description} (${check_id})"

            case "$check_id" in
                KERNEL_*)
                    local param
                    param=$(echo "$check_id" | sed 's/KERNEL_//' | tr '_' '.')
                    remediate_kernel_param "$param" "$expected"
                    ;;

                SSH_*)
                    local ssh_param
                    ssh_param=$(echo "$check_id" | sed 's/SSH_//')
                    remediate_ssh_setting "$ssh_param" "$expected"
                    ;;

                SVC_*)
                    local svc_name
                    svc_name=$(echo "$check_id" | sed 's/SVC_//')
                    remediate_service "${svc_name}.service"
                    ;;

                PERM_*)
                    local file_name="/etc/${check_id#PERM_}"
                    [ -f "$file_name" ] && remediate_file_permissions "$file_name" "$expected"
                    ;;

                PASS_*)
                    remediate_password_policy
                    ;;

                FS_*)
                    local fs_name
                    fs_name=$(echo "$check_id" | sed 's/FS_//')
                    remediate_filesystem "$fs_name"
                    ;;

                UPD_*)
                    if [ "$check_id" = "UPD_002" ]; then
                        remediate_auto_updates
                    fi
                    ;;

                AA_*)
                    remediate_apparmor
                    ;;

                *)
                    log_warning "Aucune remediation automatique pour ${check_id}"
                    ((SKIPPED_COUNT++))
                    ;;
            esac
        done

    elif command -v jq &>/dev/null; then
        log_warning "jq disponible mais le parsing guide est moins precis. Utilisez python3 pour un meilleur resultat."
        local fail_count
        fail_count=$(jq '.results | map(select(.status == "FAIL")) | length' "$REPORT_FILE" 2>/dev/null || echo "0")
        if [ "$fail_count" -eq 0 ]; then
            log_success "Aucune non-conformite a remedier."
        else
            log_warning "${fail_count} non-conformites trouvees. Installer python3 pour une remediation automatique complete."
            log_action "Veuillez consulter les resultats manuellement ou installer python3."
        fi
    else
        log_error "python3 ou jq requis pour parser le rapport JSON."
        log_info "Installez python3: apt install python3 ou yum install python3"
        exit 1
    fi
}

# ==============================================================================
# RAPPORT DE REMEDIATION
# ==============================================================================

print_summary() {
    local total=$((REMEDIATED_COUNT + SKIPPED_COUNT + FAILED_COUNT))

    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}              RESUME DE LA REMEDIATION${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}Appliquees       : ${REMEDIATED_COUNT}${NC}"
    echo -e "  ${YELLOW}Ignorees         : ${SKIPPED_COUNT}${NC}"
    echo -e "  ${RED}En erreur        : ${FAILED_COUNT}${NC}"
    echo -e "  ${WHITE}Total            : ${total}${NC}"

    if [ "$DRY_RUN" = false ] && [ "$REMEDIATED_COUNT" -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}Sauvegardes dans: ${BACKUP_DIR}${NC}"
    fi

    echo ""
    if [ "$REMEDIATED_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}Recommandation: Executer l'audit de verification: ./check-compliance.sh${NC}"
    fi
    echo ""
}

# ==============================================================================
# POINT D'ENTREE
# ==============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --report)
            REPORT_FILE="$2"
            shift 2
            ;;
        --categories)
            CATEGORIES="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo "  --report FILE         Fichier JSON de l'audit (obligatoire)"
            echo "  --categories LIST     Categories a remedier (defaut: all)"
            echo "  --dry-run             Mode simulation"
            echo ""
            echo "Exemple: sudo ./remediate.sh --report /tmp/audit.json"
            exit 0
            ;;
        *)
            echo "Option inconnue: $1"
            exit 1
            ;;
    esac
done

if [ -z "$REPORT_FILE" ]; then
    echo -e "${RED}ERREUR: Option --report requise${NC}"
    echo "Usage: $0 --report <fichier_audit.json> [--categories <liste>] [--dry-run]"
    exit 1
fi

check_root

echo ""
echo -e "${CYAN}████████████████████████████████████████████████████████████████${NC}"
echo -e "${WHITE}██           SECURITY HARDENING TOOLKIT - REMEDIATION        ██${NC}"
echo -e "${CYAN}████████████████████████████████████████████████████████████████${NC}"
echo ""
echo -e "Auteur: Louis Denis RAZAFIMANDIMBY"
echo -e "Version: ${SCRIPT_VERSION}"
echo ""

touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/remediation-$(date +%Y%m%d-%H%M%S).log"
log_info "Fichier de log: ${LOG_FILE}"
log_info "Rapport source: ${REPORT_FILE}"

if [ "$DRY_RUN" = true ]; then
    echo ""
    echo -e "${YELLOW}████ MODE DRY-RUN: Aucune modification ne sera appliquee ████${NC}"
    echo ""
fi

# Confirmation
if [ "$DRY_RUN" = false ]; then
    echo ""
    echo -e "${YELLOW}Ce script va modifier la configuration du systeme pour corriger${NC}"
    echo -e "${YELLOW}les ecarts de securite identifies par l'audit.${NC}"
    read -rp "Voulez-vous continuer? (O/N): " confirm
    if [[ ! "$confirm" =~ ^[Oo]$ ]]; then
        log_info "Operation annulee par l'utilisateur."
        exit 0
    fi
    echo ""
fi

parse_and_remediate

print_summary

exit $((FAILED_COUNT > 0 ? 1 : 0))
