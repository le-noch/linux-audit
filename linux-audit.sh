#!/bin/bash
#===============================================================================
# Script: linux-audit.sh
# Description: Collecte d'informations systeme et performances via SSH
#              pour audits d'administration Linux
# Compatibilite: RHEL6+, CentOS, Debian, Ubuntu, Oracle Linux
# Bash: Compatible 3.x+
#===============================================================================

#-------------------------------------------------------------------------------
# SECTION 1: VARIABLES GLOBALES ET CONFIGURATION
#-------------------------------------------------------------------------------

# Couleurs ANSI (compatible bash 3.x)
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'  # No Color

# Seuils d'alerte (configurables)
THRESH_RAM_WARN=75
THRESH_RAM_CRIT=85
THRESH_SWAP_WARN=30
THRESH_SWAP_CRIT=50
THRESH_CPU_WARN=70
THRESH_CPU_CRIT=85
THRESH_LOAD_WARN=1.0
THRESH_LOAD_CRIT=1.5
THRESH_IOWAIT_WARN=15
THRESH_IOWAIT_CRIT=25
THRESH_DISK_WARN=80
THRESH_DISK_CRIT=90

# Variables de travail
REMOTE_HOST=""
REMOTE_USER="root"
REMOTE_PORT="22"
SSH_KEY=""
SSH_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=yes"
TIMESTAMP=$(date +%Y%m%d)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Tableaux pour stocker les alertes (compatible bash 3.x)
ALERTS_CRITICAL=""
ALERTS_WARNING=""

# Variables pour les donnees collectees
NB_CPUS=1
DISTRO_NAME=""
DISTRO_VERSION=""
REMOTE_HOSTNAME=""

#-------------------------------------------------------------------------------
# SECTION 2: FONCTIONS UTILITAIRES
#-------------------------------------------------------------------------------

usage() {
    echo "Usage: $0 [OPTIONS] <hostname_ou_ip>"
    echo ""
    echo "Options:"
    echo "  -u, --user USER     Utilisateur SSH (defaut: root)"
    echo "  -p, --port PORT     Port SSH (defaut: 22)"
    echo "  -i, --identity KEY  Fichier de cle SSH"
    echo "  -h, --help          Affiche cette aide"
    echo ""
    echo "Exemples:"
    echo "  $0 serveur.example.com"
    echo "  $0 -u admin -p 2222 192.168.1.100"
    echo "  $0 -u admin -i ~/.ssh/id_rsa serveur.example.com"
    exit 1
}

print_line() {
    printf '%80s\n' | tr ' ' '='
}

print_header() {
    local title="$1"
    echo ""
    printf "${BOLD}${BLUE}[ %s ]${NC}\n" "$title"
}

print_info() {
    printf "  %-14s: %s\n" "$1" "$2"
}

print_warning() {
    printf "${YELLOW}[WARNING]${NC} %s\n" "$1"
}

print_error() {
    printf "${RED}[ERREUR]${NC} %s\n" "$1"
}

print_success() {
    printf "${GREEN}[OK]${NC} %s\n" "$1"
}

print_alert_critical() {
    printf "${RED}[CRITIQUE]${NC} %s\n" "$1"
}

print_alert_warning() {
    printf "${YELLOW}[WARNING]${NC}  %s\n" "$1"
}

add_alert_critical() {
    if [ -z "$ALERTS_CRITICAL" ]; then
        ALERTS_CRITICAL="$1"
    else
        ALERTS_CRITICAL="${ALERTS_CRITICAL}|$1"
    fi
}

add_alert_warning() {
    if [ -z "$ALERTS_WARNING" ]; then
        ALERTS_WARNING="$1"
    else
        ALERTS_WARNING="${ALERTS_WARNING}|$1"
    fi
}

# Execution de commande SSH
ssh_exec() {
    local cmd="$1"
    local opts="$SSH_OPTS"

    if [ -n "$SSH_KEY" ]; then
        opts="$opts -i $SSH_KEY"
    fi

    ssh $opts -p "$REMOTE_PORT" "${REMOTE_USER}@${REMOTE_HOST}" "$cmd" 2>/dev/null
}

# Verification si une commande existe sur le serveur distant
remote_cmd_exists() {
    local cmd="$1"
    ssh_exec "command -v $cmd >/dev/null 2>&1 && echo 'yes' || echo 'no'" | grep -q "yes"
}

# Test de connexion SSH
test_ssh_connection() {
    local opts="$SSH_OPTS"

    if [ -n "$SSH_KEY" ]; then
        opts="$opts -i $SSH_KEY"
    fi

    if ssh $opts -p "$REMOTE_PORT" "${REMOTE_USER}@${REMOTE_HOST}" "echo 'OK'" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Comparaison de nombres flottants (compatible bash 3.x)
float_ge() {
    # $1 >= $2 ?
    local result
    result=$(echo "$1 $2" | awk '{if ($1 >= $2) print "1"; else print "0"}')
    [ "$result" = "1" ]
}

float_gt() {
    # $1 > $2 ?
    local result
    result=$(echo "$1 $2" | awk '{if ($1 > $2) print "1"; else print "0"}')
    [ "$result" = "1" ]
}

#-------------------------------------------------------------------------------
# SECTION 3: FONCTIONS DE COLLECTE
#-------------------------------------------------------------------------------

detect_distro() {
    local distro_info

    # Essayer /etc/os-release (moderne)
    distro_info=$(ssh_exec "cat /etc/os-release 2>/dev/null")
    if [ -n "$distro_info" ]; then
        DISTRO_NAME=$(echo "$distro_info" | grep "^NAME=" | head -1 | cut -d'=' -f2 | tr -d '"')
        DISTRO_VERSION=$(echo "$distro_info" | grep "^VERSION_ID=" | head -1 | cut -d'=' -f2 | tr -d '"')
        return 0
    fi

    # Essayer /etc/redhat-release (RHEL/CentOS)
    distro_info=$(ssh_exec "cat /etc/redhat-release 2>/dev/null")
    if [ -n "$distro_info" ]; then
        DISTRO_NAME=$(echo "$distro_info" | awk '{print $1, $2}')
        DISTRO_VERSION=$(echo "$distro_info" | grep -oE '[0-9]+\.[0-9]+' | head -1)
        return 0
    fi

    # Essayer /etc/debian_version (Debian)
    distro_info=$(ssh_exec "cat /etc/debian_version 2>/dev/null")
    if [ -n "$distro_info" ]; then
        DISTRO_NAME="Debian"
        DISTRO_VERSION="$distro_info"
        return 0
    fi

    DISTRO_NAME="Unknown"
    DISTRO_VERSION="Unknown"
}

collect_system_info() {
    print_header "INFORMATIONS SYSTEME"

    REMOTE_HOSTNAME=$(ssh_exec "hostname" 2>/dev/null)
    local kernel=$(ssh_exec "uname -r" 2>/dev/null)
    local arch=$(ssh_exec "uname -m" 2>/dev/null)
    local uptime_info=$(ssh_exec "uptime -p 2>/dev/null || uptime" 2>/dev/null)
    local date_info=$(ssh_exec "date '+%Y-%m-%d %H:%M:%S %Z'" 2>/dev/null)

    detect_distro

    print_info "Hostname" "$REMOTE_HOSTNAME"
    print_info "Distribution" "${DISTRO_NAME} ${DISTRO_VERSION}"
    print_info "Kernel" "$kernel"
    print_info "Architecture" "$arch"
    print_info "Uptime" "$uptime_info"
    print_info "Date systeme" "$date_info"
}

collect_cpu_info() {
    print_header "CPU"

    local cpu_model=""
    local cpu_cores=""
    local cpu_threads=""
    local cpu_sockets=""

    # Essayer lscpu d'abord
    if remote_cmd_exists "lscpu"; then
        local lscpu_output=$(ssh_exec "LANG=C lscpu")
        cpu_model=$(echo "$lscpu_output" | grep "Model name:" | sed 's/Model name:[[:space:]]*//')
        cpu_sockets=$(echo "$lscpu_output" | grep "Socket(s):" | awk '{print $2}')
        cpu_cores=$(echo "$lscpu_output" | grep "Core(s) per socket:" | awk '{print $4}')
        cpu_threads=$(echo "$lscpu_output" | grep "CPU(s):" | head -1 | awk '{print $2}')

        if [ -n "$cpu_sockets" ] && [ -n "$cpu_cores" ]; then
            local total_cores=$((cpu_sockets * cpu_cores))
            NB_CPUS=${cpu_threads:-$total_cores}
        fi
    else
        # Fallback sur /proc/cpuinfo
        cpu_model=$(ssh_exec "grep 'model name' /proc/cpuinfo | head -1 | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
        cpu_threads=$(ssh_exec "grep -c ^processor /proc/cpuinfo")
        NB_CPUS=${cpu_threads:-1}
    fi

    print_info "Modele" "${cpu_model:-N/A}"
    print_info "Sockets" "${cpu_sockets:-N/A}"
    print_info "Coeurs/Socket" "${cpu_cores:-N/A}"
    print_info "Threads (CPUs)" "${cpu_threads:-N/A}"

    # Utilisation CPU actuelle (moyenne sur 1 seconde)
    local cpu_usage=$(ssh_exec "
        read cpu user nice system idle iowait irq softirq steal guest guest_nice < /proc/stat
        sleep 1
        read cpu user2 nice2 system2 idle2 iowait2 irq2 softirq2 steal2 guest2 guest_nice2 < /proc/stat

        total1=\$((user + nice + system + idle + iowait + irq + softirq + steal))
        total2=\$((user2 + nice2 + system2 + idle2 + iowait2 + irq2 + softirq2 + steal2))

        idle_diff=\$((idle2 - idle))
        total_diff=\$((total2 - total1))

        if [ \$total_diff -gt 0 ]; then
            usage=\$(( (total_diff - idle_diff) * 100 / total_diff ))
            echo \$usage
        else
            echo 0
        fi
    ")

    local cpu_usage_display="${cpu_usage:-0}%"

    # Analyse CPU
    if [ -n "$cpu_usage" ] && [ "$cpu_usage" -ge "$THRESH_CPU_CRIT" ] 2>/dev/null; then
        cpu_usage_display="${cpu_usage}%  ${RED}ALERTE: > ${THRESH_CPU_CRIT}%${NC}"
        add_alert_critical "CPU utilise a ${cpu_usage}% (seuil critique: ${THRESH_CPU_CRIT}%)"
    elif [ -n "$cpu_usage" ] && [ "$cpu_usage" -ge "$THRESH_CPU_WARN" ] 2>/dev/null; then
        cpu_usage_display="${cpu_usage}%  ${YELLOW}WARNING: > ${THRESH_CPU_WARN}%${NC}"
        add_alert_warning "CPU utilise a ${cpu_usage}% (seuil warning: ${THRESH_CPU_WARN}%)"
    fi

    printf "  %-14s: %b\n" "Utilisation" "$cpu_usage_display"

    # I/O Wait
    local iowait=$(ssh_exec "
        awk '/^cpu / {print \$5}' /proc/stat
        sleep 1
        awk '/^cpu / {print \$5}' /proc/stat
    " | {
        read iowait1
        read iowait2
        # Calcul simplifie du iowait
        total1=$(ssh_exec "awk '/^cpu / {sum=0; for(i=2;i<=NF;i++) sum+=\$i; print sum}' /proc/stat")
        echo "0"  # Placeholder - calcul complexe
    })

    # Methode alternative pour I/O wait via vmstat
    local vmstat_output=$(ssh_exec "vmstat 1 2 2>/dev/null | tail -1")
    if [ -n "$vmstat_output" ]; then
        iowait=$(echo "$vmstat_output" | awk '{print $16}')
        if [ -z "$iowait" ] || ! echo "$iowait" | grep -qE '^[0-9]+$'; then
            # Format vmstat different selon les versions
            iowait=$(echo "$vmstat_output" | awk '{print $(NF-1)}')
        fi
    fi

    if [ -n "$iowait" ] && echo "$iowait" | grep -qE '^[0-9]+$'; then
        local iowait_display="${iowait}%"

        if [ "$iowait" -ge "$THRESH_IOWAIT_CRIT" ] 2>/dev/null; then
            iowait_display="${iowait}%  ${RED}ALERTE: > ${THRESH_IOWAIT_CRIT}%${NC}"
            add_alert_critical "I/O Wait a ${iowait}% (seuil critique: ${THRESH_IOWAIT_CRIT}%)"
        elif [ "$iowait" -ge "$THRESH_IOWAIT_WARN" ] 2>/dev/null; then
            iowait_display="${iowait}%  ${YELLOW}WARNING: > ${THRESH_IOWAIT_WARN}%${NC}"
            add_alert_warning "I/O Wait a ${iowait}% (seuil warning: ${THRESH_IOWAIT_WARN}%)"
        fi

        printf "  %-14s: %b\n" "I/O Wait" "$iowait_display"
    fi
}

collect_memory_info() {
    print_header "MEMOIRE"

    local meminfo=$(ssh_exec "cat /proc/meminfo")

    # Extraire les valeurs en kB
    local mem_total_kb=$(echo "$meminfo" | grep "^MemTotal:" | awk '{print $2}')
    local mem_free_kb=$(echo "$meminfo" | grep "^MemFree:" | awk '{print $2}')
    local mem_available_kb=$(echo "$meminfo" | grep "^MemAvailable:" | awk '{print $2}')
    local mem_buffers_kb=$(echo "$meminfo" | grep "^Buffers:" | awk '{print $2}')
    local mem_cached_kb=$(echo "$meminfo" | grep "^Cached:" | awk '{print $2}')

    # Convertir en MB
    local mem_total_mb=$((mem_total_kb / 1024))
    local mem_free_mb=$((mem_free_kb / 1024))
    local mem_buffers_mb=$((mem_buffers_kb / 1024))
    local mem_cached_mb=$((mem_cached_kb / 1024))

    # Calcul de la memoire utilisee
    local mem_used_mb
    local mem_used_percent

    if [ -n "$mem_available_kb" ] && [ "$mem_available_kb" -gt 0 ] 2>/dev/null; then
        # Kernel moderne avec MemAvailable
        local mem_available_mb=$((mem_available_kb / 1024))
        mem_used_mb=$((mem_total_mb - mem_available_mb))
        mem_used_percent=$((mem_used_mb * 100 / mem_total_mb))
    else
        # Kernel ancien (RHEL6) - calcul manuel
        mem_used_mb=$((mem_total_mb - mem_free_mb - mem_buffers_mb - mem_cached_mb))
        mem_used_percent=$((mem_used_mb * 100 / mem_total_mb))
    fi

    print_info "RAM Totale" "${mem_total_mb} MB"

    local mem_used_display="${mem_used_mb} MB (${mem_used_percent}%)"

    # Analyse RAM
    if [ "$mem_used_percent" -ge "$THRESH_RAM_CRIT" ] 2>/dev/null; then
        mem_used_display="${mem_used_mb} MB (${mem_used_percent}%)  ${RED}ALERTE: > ${THRESH_RAM_CRIT}%${NC}"
        add_alert_critical "RAM utilisee a ${mem_used_percent}% (seuil critique: ${THRESH_RAM_CRIT}%)"
    elif [ "$mem_used_percent" -ge "$THRESH_RAM_WARN" ] 2>/dev/null; then
        mem_used_display="${mem_used_mb} MB (${mem_used_percent}%)  ${YELLOW}WARNING: > ${THRESH_RAM_WARN}%${NC}"
        add_alert_warning "RAM utilisee a ${mem_used_percent}% (seuil warning: ${THRESH_RAM_WARN}%)"
    fi

    printf "  %-14s: %b\n" "RAM Utilisee" "$mem_used_display"
    print_info "RAM Libre" "${mem_free_mb} MB"
    print_info "Buffers" "${mem_buffers_mb} MB"
    print_info "Cached" "${mem_cached_mb} MB"
}

collect_swap_info() {
    print_header "SWAP"

    local meminfo=$(ssh_exec "cat /proc/meminfo")

    local swap_total_kb=$(echo "$meminfo" | grep "^SwapTotal:" | awk '{print $2}')
    local swap_free_kb=$(echo "$meminfo" | grep "^SwapFree:" | awk '{print $2}')

    local swap_total_mb=$((swap_total_kb / 1024))
    local swap_free_mb=$((swap_free_kb / 1024))
    local swap_used_mb=$((swap_total_mb - swap_free_mb))

    if [ "$swap_total_mb" -eq 0 ] 2>/dev/null; then
        print_info "Swap" "Non configure"
        return
    fi

    local swap_used_percent=$((swap_used_mb * 100 / swap_total_mb))

    print_info "Swap Total" "${swap_total_mb} MB"

    local swap_used_display="${swap_used_mb} MB (${swap_used_percent}%)"

    # Analyse Swap
    if [ "$swap_used_percent" -ge "$THRESH_SWAP_CRIT" ] 2>/dev/null; then
        swap_used_display="${swap_used_mb} MB (${swap_used_percent}%)  ${RED}ALERTE: > ${THRESH_SWAP_CRIT}%${NC}"
        add_alert_critical "Swap utilise a ${swap_used_percent}% (seuil critique: ${THRESH_SWAP_CRIT}%)"
    elif [ "$swap_used_percent" -ge "$THRESH_SWAP_WARN" ] 2>/dev/null; then
        swap_used_display="${swap_used_mb} MB (${swap_used_percent}%)  ${YELLOW}WARNING: > ${THRESH_SWAP_WARN}%${NC}"
        add_alert_warning "Swap utilise a ${swap_used_percent}% (seuil warning: ${THRESH_SWAP_WARN}%)"
    fi

    printf "  %-14s: %b\n" "Swap Utilise" "$swap_used_display"
    print_info "Swap Libre" "${swap_free_mb} MB"
}

collect_load_info() {
    print_header "LOAD AVERAGE"

    local loadavg=$(ssh_exec "cat /proc/loadavg")
    local load1=$(echo "$loadavg" | awk '{print $1}')
    local load5=$(echo "$loadavg" | awk '{print $2}')
    local load15=$(echo "$loadavg" | awk '{print $3}')

    print_info "Load 1/5/15" "$load1 / $load5 / $load15"
    print_info "Nb CPUs" "$NB_CPUS"

    # Calcul du ratio load/cpu
    local ratio=$(echo "$load1 $NB_CPUS" | awk '{printf "%.2f", $1 / $2}')

    local ratio_display="$ratio"

    # Analyse Load
    if float_ge "$ratio" "$THRESH_LOAD_CRIT"; then
        ratio_display="${ratio}  ${RED}ALERTE: > ${THRESH_LOAD_CRIT}${NC}"
        add_alert_critical "Load average ratio a ${ratio} (seuil critique: ${THRESH_LOAD_CRIT})"
    elif float_ge "$ratio" "$THRESH_LOAD_WARN"; then
        ratio_display="${ratio}  ${YELLOW}WARNING: > ${THRESH_LOAD_WARN}${NC}"
        add_alert_warning "Load average ratio a ${ratio} (seuil warning: ${THRESH_LOAD_WARN})"
    fi

    printf "  %-14s: %b\n" "Ratio Load/CPU" "$ratio_display"
}

collect_disk_info() {
    print_header "DISQUES ET SYSTEMES DE FICHIERS"

    # df pour l'espace disque
    local df_output=$(ssh_exec "LANG=C df -hP 2>/dev/null | grep -vE '^Filesystem|tmpfs|cdrom|devtmpfs'")

    echo ""
    printf "  %-30s %8s %8s %8s %6s\n" "Filesystem" "Size" "Used" "Avail" "Use%"
    printf "  %-30s %8s %8s %8s %6s\n" "------------------------------" "--------" "--------" "--------" "------"

    echo "$df_output" | while read line; do
        local fs=$(echo "$line" | awk '{print $1}')
        local size=$(echo "$line" | awk '{print $2}')
        local used=$(echo "$line" | awk '{print $3}')
        local avail=$(echo "$line" | awk '{print $4}')
        local use_percent=$(echo "$line" | awk '{print $5}' | tr -d '%')
        local mount=$(echo "$line" | awk '{print $6}')

        # Tronquer le nom du filesystem si trop long
        if [ ${#fs} -gt 30 ]; then
            fs="...${fs: -27}"
        fi

        local alert_flag=""
        if [ -n "$use_percent" ] && [ "$use_percent" -ge "$THRESH_DISK_CRIT" ] 2>/dev/null; then
            alert_flag="${RED}CRIT${NC}"
            add_alert_critical "Disque $mount utilise a ${use_percent}% (seuil: ${THRESH_DISK_CRIT}%)"
        elif [ -n "$use_percent" ] && [ "$use_percent" -ge "$THRESH_DISK_WARN" ] 2>/dev/null; then
            alert_flag="${YELLOW}WARN${NC}"
            add_alert_warning "Disque $mount utilise a ${use_percent}% (seuil: ${THRESH_DISK_WARN}%)"
        fi

        if [ -n "$alert_flag" ]; then
            printf "  %-30s %8s %8s %8s %5s%% %b\n" "$fs" "$size" "$used" "$avail" "$use_percent" "$alert_flag"
        else
            printf "  %-30s %8s %8s %8s %5s%%\n" "$fs" "$size" "$used" "$avail" "$use_percent"
        fi
    done

    # Statistiques I/O depuis /proc/diskstats
    echo ""
    print_header "STATISTIQUES I/O DISQUES"

    local diskstats=$(ssh_exec "cat /proc/diskstats 2>/dev/null")

    if [ -n "$diskstats" ]; then
        printf "  %-12s %12s %12s %12s\n" "Device" "Reads" "Writes" "IO_ms"
        printf "  %-12s %12s %12s %12s\n" "------------" "------------" "------------" "------------"

        # Filtrer seulement les disques principaux (sd*, vd*, nvme*, xvd*)
        echo "$diskstats" | awk '$3 ~ /^(sd[a-z]|vd[a-z]|nvme[0-9]+n[0-9]+|xvd[a-z])$/ {
            printf "  %-12s %12s %12s %12s\n", $3, $4, $8, $13
        }'
    fi
}

collect_network_info() {
    print_header "RESEAU"

    local ip_output=""

    # Essayer ip addr d'abord
    if remote_cmd_exists "ip"; then
        ip_output=$(ssh_exec "ip -4 addr show 2>/dev/null | grep -E 'inet |^[0-9]+:' | grep -v '127.0.0.1'")
    fi

    # Fallback sur ifconfig
    if [ -z "$ip_output" ] && remote_cmd_exists "ifconfig"; then
        ip_output=$(ssh_exec "ifconfig 2>/dev/null | grep -E '^[a-z]|inet ' | grep -v '127.0.0.1'")
    fi

    if [ -n "$ip_output" ]; then
        echo "$ip_output" | while read line; do
            echo "  $line"
        done
    else
        print_warning "Impossible de recuperer les informations reseau"
    fi

    # Statistiques interfaces
    echo ""
    local netdev=$(ssh_exec "cat /proc/net/dev 2>/dev/null | tail -n +3 | grep -v lo:")

    if [ -n "$netdev" ]; then
        printf "  %-12s %15s %15s\n" "Interface" "RX bytes" "TX bytes"
        printf "  %-12s %15s %15s\n" "------------" "---------------" "---------------"

        echo "$netdev" | while read line; do
            local iface=$(echo "$line" | awk -F: '{print $1}' | tr -d ' ')
            local rx_bytes=$(echo "$line" | awk '{print $2}')
            local tx_bytes=$(echo "$line" | awk '{print $10}')

            # Convertir en format lisible
            local rx_human=$(echo "$rx_bytes" | awk '{
                if ($1 >= 1073741824) printf "%.2f GB", $1/1073741824
                else if ($1 >= 1048576) printf "%.2f MB", $1/1048576
                else if ($1 >= 1024) printf "%.2f KB", $1/1024
                else printf "%d B", $1
            }')
            local tx_human=$(echo "$tx_bytes" | awk '{
                if ($1 >= 1073741824) printf "%.2f GB", $1/1073741824
                else if ($1 >= 1048576) printf "%.2f MB", $1/1048576
                else if ($1 >= 1024) printf "%.2f KB", $1/1024
                else printf "%d B", $1
            }')

            printf "  %-12s %15s %15s\n" "$iface" "$rx_human" "$tx_human"
        done
    fi
}

collect_process_info() {
    print_header "TOP PROCESSUS"

    echo ""
    echo "  Top 5 processus par CPU:"
    printf "  %-8s %-8s %-8s %-8s %s\n" "USER" "PID" "%CPU" "%MEM" "COMMAND"
    printf "  %-8s %-8s %-8s %-8s %s\n" "--------" "--------" "--------" "--------" "---------------"

    local top_cpu=$(ssh_exec "ps aux --sort=-%cpu 2>/dev/null | head -6 | tail -5")
    if [ -n "$top_cpu" ]; then
        echo "$top_cpu" | while read line; do
            local user=$(echo "$line" | awk '{print $1}')
            local pid=$(echo "$line" | awk '{print $2}')
            local cpu=$(echo "$line" | awk '{print $3}')
            local mem=$(echo "$line" | awk '{print $4}')
            local cmd=$(echo "$line" | awk '{print $11}' | cut -c1-30)
            printf "  %-8s %-8s %-8s %-8s %s\n" "$user" "$pid" "$cpu" "$mem" "$cmd"
        done
    fi

    echo ""
    echo "  Top 5 processus par Memoire:"
    printf "  %-8s %-8s %-8s %-8s %s\n" "USER" "PID" "%CPU" "%MEM" "COMMAND"
    printf "  %-8s %-8s %-8s %-8s %s\n" "--------" "--------" "--------" "--------" "---------------"

    local top_mem=$(ssh_exec "ps aux --sort=-%mem 2>/dev/null | head -6 | tail -5")
    if [ -n "$top_mem" ]; then
        echo "$top_mem" | while read line; do
            local user=$(echo "$line" | awk '{print $1}')
            local pid=$(echo "$line" | awk '{print $2}')
            local cpu=$(echo "$line" | awk '{print $3}')
            local mem=$(echo "$line" | awk '{print $4}')
            local cmd=$(echo "$line" | awk '{print $11}' | cut -c1-30)
            printf "  %-8s %-8s %-8s %-8s %s\n" "$user" "$pid" "$cpu" "$mem" "$cmd"
        done
    fi
}

#-------------------------------------------------------------------------------
# SECTION 4: COLLECTE SAR (SYSSTAT)
#-------------------------------------------------------------------------------

detect_sar_path() {
    local sar_paths="/var/log/sa /var/log/sysstat"

    for path in $sar_paths; do
        local check=$(ssh_exec "[ -d '$path' ] && ls $path/sa?? 2>/dev/null | head -1")
        if [ -n "$check" ]; then
            echo "$path"
            return 0
        fi
    done

    return 1
}

collect_sar_data() {
    print_header "COLLECTE DONNEES SAR (SYSSTAT)"

    # Verifier si sar est disponible
    if ! remote_cmd_exists "sar"; then
        print_warning "sysstat n'est pas installe sur ce serveur - donnees SAR non disponibles"
        return 1
    fi

    # Detecter le chemin des fichiers SAR
    local sar_path
    sar_path=$(detect_sar_path)

    if [ -z "$sar_path" ]; then
        print_warning "Aucun fichier SAR trouve dans /var/log/sa ou /var/log/sysstat"
        return 1
    fi

    print_info "Chemin SAR" "$sar_path"

    # Lister les fichiers disponibles
    local sar_files=$(ssh_exec "ls -rt ${sar_path}/sa?? 2>/dev/null | wc -l")
    print_info "Fichiers SAR" "${sar_files} fichier(s) trouve(s)"

    # Nom du fichier de sortie
    local output_file="${TIMESTAMP}-${REMOTE_HOSTNAME}-sar.gz"

    echo "  Extraction des donnees SAR en cours..."

    # Executer la commande sar sur tous les fichiers et compresser
    ssh_exec "for i in \$(ls -rt ${sar_path}/sa?? 2>/dev/null); do LANG=C sar -A -f \$i 2>/dev/null; done | gzip -c" > "$output_file"

    if [ -s "$output_file" ]; then
        local file_size=$(ls -lh "$output_file" | awk '{print $5}')
        print_success "Donnees SAR exportees: $output_file (${file_size})"
    else
        print_warning "Fichier SAR vide ou erreur lors de la collecte"
        rm -f "$output_file"
        return 1
    fi
}

#-------------------------------------------------------------------------------
# SECTION 5: SYNTHESE DES ALERTES
#-------------------------------------------------------------------------------

print_alert_summary() {
    echo ""
    print_line
    printf "${BOLD}                         SYNTHESE DES ALERTES${NC}\n"
    print_line

    local has_alerts=0

    # Afficher les alertes critiques
    if [ -n "$ALERTS_CRITICAL" ]; then
        has_alerts=1
        echo "$ALERTS_CRITICAL" | tr '|' '\n' | while read alert; do
            if [ -n "$alert" ]; then
                print_alert_critical "$alert"
            fi
        done
    fi

    # Afficher les alertes warning
    if [ -n "$ALERTS_WARNING" ]; then
        has_alerts=1
        echo "$ALERTS_WARNING" | tr '|' '\n' | while read alert; do
            if [ -n "$alert" ]; then
                print_alert_warning "$alert"
            fi
        done
    fi

    if [ "$has_alerts" -eq 0 ]; then
        print_success "Aucune alerte detectee - tous les indicateurs sont dans les seuils normaux"
    fi
}

#-------------------------------------------------------------------------------
# SECTION 6: FONCTION PRINCIPALE
#-------------------------------------------------------------------------------

parse_arguments() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -u|--user)
                REMOTE_USER="$2"
                shift 2
                ;;
            -p|--port)
                REMOTE_PORT="$2"
                shift 2
                ;;
            -i|--identity)
                SSH_KEY="$2"
                shift 2
                ;;
            -h|--help)
                usage
                ;;
            -*)
                print_error "Option inconnue: $1"
                usage
                ;;
            *)
                REMOTE_HOST="$1"
                shift
                ;;
        esac
    done

    if [ -z "$REMOTE_HOST" ]; then
        print_error "Hostname ou IP requis"
        usage
    fi
}

main() {
    # Parser les arguments
    parse_arguments "$@"

    # En-tete du rapport
    echo ""
    print_line
    printf "${BOLD}                    AUDIT SYSTEME LINUX - %s${NC}\n" "$REMOTE_HOST"
    printf "                    Date: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
    print_line

    # Test de connexion SSH
    echo ""
    echo "Connexion SSH vers ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PORT}..."

    if ! test_ssh_connection; then
        print_error "Impossible de se connecter au serveur $REMOTE_HOST"
        print_error "Verifiez: hostname, utilisateur, port, cle SSH, et que le serveur est accessible"
        exit 1
    fi

    print_success "Connexion SSH etablie"

    # Collecte des informations
    collect_system_info
    collect_cpu_info
    collect_memory_info
    collect_swap_info
    collect_load_info
    collect_disk_info
    collect_network_info
    collect_process_info

    # Collecte SAR
    collect_sar_data

    # Synthese des alertes
    print_alert_summary

    # Pied de page
    echo ""
    print_line
    printf "${BOLD}                         FIN DU RAPPORT${NC}\n"
    print_line
    echo ""
}

# Point d'entree
main "$@"
