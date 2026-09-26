#!/bin/bash
#===============================================================================
# Script: linux-audit.sh
# Version: 1.0.0
# Description: Collecte d'informations systeme et performances via SSH
#              pour audits d'administration Linux
# Compatibilite: RHEL6+, CentOS, Debian, Ubuntu, Oracle Linux
# Bash: Compatible 3.x+
# Auteur: Aurélien DREVET
# Généré avec l'assistance de Claude (Anthropic) via Claude Code
# Licence: MIT (voir fichier LICENSE)
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
# I/O disques temps reel (iostat / diskstats)
THRESH_DISKIO_UTIL_WARN=70
THRESH_DISKIO_UTIL_CRIT=90
THRESH_DISKIO_AWAIT_WARN=50
# Pics I/O dans l'historique SAR (sar -d)
THRESH_SAR_UTIL=80
THRESH_SAR_AWAIT=30

# Variables de travail
REMOTE_HOST=""
REMOTE_USER="root"
REMOTE_PORT="22"
SSH_KEY=""
SSH_PASSWORD=""
# Arguments SSH: tableau (bash 3 compatible) construit par build_ssh_args,
# pour que les chemins contenant des espaces restent un seul argument
SSH_ARGS=()
TIMESTAMP=$(date +%Y%m%d)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Variables pour la sortie HTML
HTML_OUTPUT=""
HTML_CONTENT=""

# Tableaux pour stocker les alertes (compatible bash 3.x)
ALERTS_CRITICAL=""
ALERTS_WARNING=""

# Variables pour les donnees collectees
NB_CPUS=1
DISTRO_NAME=""
DISTRO_VERSION=""
REMOTE_HOSTNAME=""
SAR_IO_ANOMALIES=""
SAR_IO_ANALYZED=0

# Repertoire de travail local (marqueurs d'echec SSH, socket de multiplexage)
WORK_DIR=""
SSH_CONTROL=""

# Commandes disponibles sur le serveur distant (inventaire unique)
REMOTE_CMDS=""
# Chemin des fichiers SAR (detecte une seule fois)
SAR_PATH=""

#-------------------------------------------------------------------------------
# SECTION 2: FONCTIONS UTILITAIRES
#-------------------------------------------------------------------------------

usage() {
    echo "Usage: $0 [OPTIONS] <hostname_ou_ip>"
    echo ""
    echo "Options:"
    echo "  -u, --user USER       Utilisateur SSH (defaut: root)"
    echo "  -p, --port PORT       Port SSH (defaut: 22)"
    echo "  -P, --password [PWD]  Authentification par mot de passe (necessite sshpass)"
    echo "                        Si PWD omis: variable d'environnement SSHPASS si"
    echo "                        definie, sinon prompt interactif. PWD en argument est"
    echo "                        deconseille (visible dans ps et l'historique du shell)"
    echo "  -i, --identity KEY    Fichier de cle SSH"
    echo "  -h, --help            Affiche cette aide"
    echo ""
    echo "Exemples:"
    echo "  $0 serveur.example.com"
    echo "  $0 -u admin -p 2222 192.168.1.100"
    echo "  $0 -u admin -i ~/.ssh/id_rsa serveur.example.com"
    echo "  $0 -u admin -P serveur.example.com          # Prompt pour le mot de passe"
    echo "  SSHPASS='secret' $0 -u admin -P serveur.example.com  # Non interactif"
    echo ""
    echo "Un rapport HTML est automatiquement genere: YYYYMMDD-Hostname-audit.html"
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

# Politique de verification de la cle d'hote: accept-new (OpenSSH >= 7.6)
# enregistre la cle d'un hote inconnu mais REFUSE une cle qui a change
# (attaque MITM); "no" accepterait silencieusement les deux.
SSH_HOSTKEY_POLICY="accept-new"
detect_hostkey_policy() {
    if ! ssh -o StrictHostKeyChecking=accept-new -G localhost >/dev/null 2>&1; then
        SSH_HOSTKEY_POLICY="no"
        print_warning "Client OpenSSH < 7.6: cles d'hote acceptees sans verification (StrictHostKeyChecking=no)"
    fi
}

# Construction des arguments SSH communs
build_ssh_args() {
    SSH_ARGS=(-o ConnectTimeout=10 -o StrictHostKeyChecking="$SSH_HOSTKEY_POLICY" -p "$REMOTE_PORT")
    if [ -z "$SSH_PASSWORD" ]; then
        # Sans mot de passe: jamais de prompt interactif
        SSH_ARGS=("${SSH_ARGS[@]}" -o BatchMode=yes)
    fi
    if [ -n "$SSH_KEY" ]; then
        SSH_ARGS=("${SSH_ARGS[@]}" -i "$SSH_KEY")
    fi
}

# Lance ssh avec les arguments communs (et sshpass en mode mot de passe).
# sshpass -e: le mot de passe passe par l'environnement, pas par la ligne de
# commande (invisible dans ps)
run_ssh() {
    if [ -n "$SSH_PASSWORD" ]; then
        SSHPASS="$SSH_PASSWORD" sshpass -e ssh "${SSH_ARGS[@]}" "$@"
    else
        ssh "${SSH_ARGS[@]}" "$@"
    fi
}

# Tests numeriques (les valeurs distantes ne sont jamais considerees comme sures)
is_int() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    return 0
}

is_num() {
    # Nombre decimal positif (ex: 12, 3.5, 0.25)
    echo "$1" | grep -qE '^[0-9]+(\.[0-9]+)?$'
}

# Execution de commande SSH
# Un code retour 255 signifie une erreur de transport SSH (connexion perdue,
# authentification refusee...): on pose un marqueur dans WORK_DIR, car ssh_exec
# s'execute le plus souvent dans une substitution $(...) ou une variable globale
# serait perdue. check_ssh_alive() interrompt ensuite l'audit.
ssh_exec() {
    local cmd="$1"

    # Le script est envoye sur stdin a "sh -s": le shell de login distant
    # (bash, tcsh, fish...) n'a qu'a lancer sh, et les commandes s'executent
    # toujours en shell POSIX. Le bloc { } </dev/null est lu en entier par sh
    # avant execution: aucune commande ne peut consommer la suite du script.
    # Prelude: locale C (un LC_* transmis par SendEnv casserait le parsing)
    # et /sbin dans le PATH (absent du PATH non-root sur RHEL: ip, ifconfig).
    # "--" empeche un utilisateur ou un hote commencant par "-" d'etre
    # interprete comme une option ssh
    run_ssh -- "${REMOTE_USER}@${REMOTE_HOST}" "sh -s" 2>/dev/null <<EOF
{
LC_ALL=C; LANG=C; export LC_ALL LANG
PATH="\$PATH:/sbin:/usr/sbin:/usr/local/sbin"; export PATH
$cmd
} </dev/null
EOF
    local rc=$?
    if [ "$rc" -eq 255 ] && [ -n "$WORK_DIR" ]; then
        : > "$WORK_DIR/ssh_failed"
    fi
    return $rc
}

# Interrompt l'audit si une commande SSH a echoue au niveau transport:
# mieux vaut aucun rapport qu'un rapport rempli de valeurs vides.
check_ssh_alive() {
    if [ -n "$WORK_DIR" ] && [ -f "$WORK_DIR/ssh_failed" ]; then
        echo ""
        print_error "Connexion SSH perdue pendant la collecte ($1) - audit interrompu"
        print_error "Aucun rapport genere: les donnees collectees seraient incompletes"
        exit 3
    fi
}

# Inventaire unique des commandes utiles sur le serveur distant
detect_remote_cmds() {
    REMOTE_CMDS=$(ssh_exec "for c in lscpu iostat ip ifconfig sar vmstat getconf; do command -v \$c >/dev/null 2>&1 && echo \$c; done" | tr '\n' ' ')
    check_ssh_alive "inventaire des commandes"
}

# Verification si une commande existe sur le serveur distant (d'apres
# l'inventaire: une coupure SSH n'est pas confondue avec une commande absente)
remote_cmd_exists() {
    case " $REMOTE_CMDS " in
        *" $1 "*) return 0 ;;
    esac
    return 1
}

# Connexion SSH maitre: toutes les commandes suivantes reutilisent la meme
# connexion (une seule authentification au lieu d'une quarantaine, moins de
# bruit dans les journaux d'auth, pas de blocage MaxStartups/fail2ban).
# En cas d'echec (socket trop long, multiplexage interdit), on continue sans.
open_ssh_master() {
    [ -n "$WORK_DIR" ] || return 1
    SSH_CONTROL="$WORK_DIR/cm"
    if run_ssh -o ControlMaster=yes -o ControlPath="$SSH_CONTROL" -o ControlPersist=no -fN \
            -- "${REMOTE_USER}@${REMOTE_HOST}" >/dev/null 2>&1 && [ -S "$SSH_CONTROL" ]; then
        SSH_ARGS=("${SSH_ARGS[@]}" -o ControlPath="$SSH_CONTROL" -o ControlMaster=no)
        return 0
    fi
    SSH_CONTROL=""
    return 1
}

close_ssh_master() {
    if [ -n "$SSH_CONTROL" ] && [ -S "$SSH_CONTROL" ]; then
        ssh -o ControlPath="$SSH_CONTROL" -O exit -- "${REMOTE_USER}@${REMOTE_HOST}" >/dev/null 2>&1
    fi
}

# Test de connexion SSH: en cas d'echec, les messages de ssh (cle d'hote
# modifiee, authentification refusee...) sont affiches a l'utilisateur
test_ssh_connection() {
    local err
    err=$(run_ssh -- "${REMOTE_USER}@${REMOTE_HOST}" "echo 'OK'" 2>&1 >/dev/null)
    local rc=$?
    if [ "$rc" -ne 0 ] && [ -n "$err" ]; then
        echo "$err" | sed 's/^/  ssh: /' | head -20
    fi
    return $rc
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
# SECTION 2B: FONCTIONS HTML
#-------------------------------------------------------------------------------

html_append() {
    # Sans rapport HTML demande, les fonctions html_* ne font rien
    [ -n "$HTML_OUTPUT" ] || return 0
    HTML_CONTENT="${HTML_CONTENT}$1"
}

html_escape() {
    # printf et non echo: une valeur "-n" ou "-e" ne doit pas etre prise pour une option
    printf '%s\n' "$1" | sed "s/&/\\&amp;/g; s/</\\&lt;/g; s/>/\\&gt;/g; s/\"/\\&quot;/g; s/'/\\&#39;/g"
}

html_init() {
    # Echapper les valeurs distantes (hostname) pour eviter toute injection HTML
    local title=$(html_escape "$1")
    local date=$(html_escape "$2")
    HTML_CONTENT="<!DOCTYPE html>
<html lang=\"fr\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>Audit Linux - ${title}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e8e8e8;
            min-height: 100vh;
            padding: 20px;
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #0f3460 0%, #16213e 100%);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            border: 1px solid #1f4068;
        }
        .header h1 { color: #00d9ff; font-size: 2em; margin-bottom: 10px; }
        .header .date { color: #a0a0a0; font-size: 0.95em; }
        .section {
            background: rgba(255,255,255,0.03);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .section h2 {
            color: #00d9ff;
            font-size: 1.3em;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #1f4068;
        }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 10px; }
        .info-row {
            display: flex;
            padding: 8px 12px;
            background: rgba(0,0,0,0.2);
            border-radius: 6px;
        }
        .info-label { color: #a0a0a0; min-width: 140px; font-weight: 500; }
        .info-value { color: #fff; flex: 1; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }
        th { background: rgba(0,217,255,0.1); color: #00d9ff; font-weight: 600; }
        tr:hover { background: rgba(255,255,255,0.03); }
        .alert-section { margin-top: 20px; }
        .alert {
            padding: 12px 15px;
            border-radius: 8px;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
        }
        .alert-critical {
            background: linear-gradient(135deg, rgba(255,71,87,0.2) 0%, rgba(255,71,87,0.1) 100%);
            border-left: 4px solid #ff4757;
        }
        .alert-warning {
            background: linear-gradient(135deg, rgba(255,193,7,0.2) 0%, rgba(255,193,7,0.1) 100%);
            border-left: 4px solid #ffc107;
        }
        .alert-ok {
            background: linear-gradient(135deg, rgba(46,213,115,0.2) 0%, rgba(46,213,115,0.1) 100%);
            border-left: 4px solid #2ed573;
        }
        .alert-icon { margin-right: 12px; font-size: 1.2em; }
        .alert-critical .alert-icon { color: #ff4757; }
        .alert-warning .alert-icon { color: #ffc107; }
        .alert-ok .alert-icon { color: #2ed573; }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 600;
        }
        .badge-critical { background: #ff4757; color: #fff; }
        .badge-warning { background: #ffc107; color: #000; }
        .badge-ok { background: #2ed573; color: #fff; }
        .progress-bar {
            height: 8px;
            background: rgba(255,255,255,0.1);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 5px;
        }
        .progress-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
        .progress-ok { background: linear-gradient(90deg, #2ed573, #7bed9f); }
        .progress-warn { background: linear-gradient(90deg, #ffc107, #ffda79); }
        .progress-crit { background: linear-gradient(90deg, #ff4757, #ff6b81); }
        .progress-stacked { display: flex; height: 100%; }
        .progress-used { background: linear-gradient(90deg, #e84393, #fd79a8); border-radius: 4px 0 0 4px; }
        .progress-cache { background: linear-gradient(90deg, #0984e3, #74b9ff); }
        .progress-buffer { background: linear-gradient(90deg, #00cec9, #81ecec); border-radius: 0 4px 4px 0; }
        .memory-legend { display: flex; gap: 20px; margin-top: 10px; flex-wrap: wrap; }
        .legend-item { display: flex; align-items: center; gap: 6px; font-size: 0.85em; }
        .legend-color { width: 14px; height: 14px; border-radius: 3px; }
        .legend-used { background: linear-gradient(90deg, #e84393, #fd79a8); }
        .legend-cache { background: linear-gradient(90deg, #0984e3, #74b9ff); }
        .legend-buffer { background: linear-gradient(90deg, #00cec9, #81ecec); }
        .legend-free { background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.3); }
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }
        .table-process th:nth-child(3), .table-process th:nth-child(4) { text-align: right; }
        .table-process td:nth-child(3), .table-process td:nth-child(4) { text-align: right; }
        .table-process td { font-family: monospace; font-size: 0.9em; }
        .table-process td:nth-child(1), .table-process td:nth-child(2) { font-family: inherit; }
        .table-process td:nth-child(5) { font-family: inherit; }
        .cpu-chart-container { margin-top: 20px; }
        .cpu-chart-title { color: #a0a0a0; font-size: 1em; margin-bottom: 10px; }
        .cpu-chart { background: rgba(0,0,0,0.3); border-radius: 8px; padding: 15px; }
        .cpu-chart svg { width: 100%; height: 200px; }
        .cpu-legend { display: flex; gap: 15px; margin-top: 10px; flex-wrap: wrap; justify-content: center; }
        .cpu-legend-item { display: flex; align-items: center; gap: 5px; font-size: 0.8em; }
        .cpu-legend-color { width: 12px; height: 12px; border-radius: 2px; }
        .color-user { fill: #e84393; }
        .color-nice { fill: #a29bfe; }
        .color-system { fill: #fd79a8; }
        .color-iowait { fill: #ffeaa7; }
        .color-steal { fill: #ff7675; }
        .color-idle { fill: #55a3dc; }
        .bg-user { background: #e84393; }
        .bg-nice { background: #a29bfe; }
        .bg-system { background: #fd79a8; }
        .bg-iowait { background: #ffeaa7; }
        .bg-steal { background: #ff7675; }
        .bg-idle { background: #55a3dc; }
        @media (max-width: 768px) {
            .info-grid { grid-template-columns: 1fr; }
            .header h1 { font-size: 1.5em; }
        }
    </style>
</head>
<body>
    <div class=\"container\">
        <div class=\"header\">
            <h1>Audit Systeme Linux</h1>
            <div class=\"date\">Serveur: <strong>${title}</strong> | Date: ${date}</div>
        </div>
"
}

html_section_start() {
    local title="$1"
    html_append "        <div class=\"section\">
            <h2>${title}</h2>
"
}

html_section_end() {
    html_append "        </div>
"
}

html_info_start() {
    html_append "            <div class=\"info-grid\">
"
}

html_info_end() {
    html_append "            </div>
"
}

html_info_row() {
    local label="$1"
    local value="$2"
    local escaped_value=$(html_escape "$value")
    html_append "                <div class=\"info-row\">
                    <span class=\"info-label\">${label}</span>
                    <span class=\"info-value\">${escaped_value}</span>
                </div>
"
}

html_info_row_with_badge() {
    local label="$1"
    local value="$2"
    local badge_type="$3"  # ok, warning, critical
    local badge_text="$4"
    local escaped_value=$(html_escape "$value")
    local badge_html=""
    if [ -n "$badge_type" ]; then
        badge_html=" <span class=\"badge badge-${badge_type}\">${badge_text}</span>"
    fi
    html_append "                <div class=\"info-row\">
                    <span class=\"info-label\">${label}</span>
                    <span class=\"info-value\">${escaped_value}${badge_html}</span>
                </div>
"
}

html_progress_row() {
    local label="$1"
    local value="$2"
    local percent="$3"
    local status="$4"  # ok, warn, crit
    local escaped_value=$(html_escape "$value")
    # percent finit dans un attribut style: uniquement un entier 0-100
    is_int "$percent" || percent=0
    [ "$percent" -gt 100 ] && percent=100
    case "$status" in ok|warn|crit) ;; *) status="ok" ;; esac
    html_append "                <div class=\"info-row\" style=\"flex-direction: column;\">
                    <div style=\"display: flex; justify-content: space-between;\">
                        <span class=\"info-label\">${label}</span>
                        <span class=\"info-value\">${escaped_value}</span>
                    </div>
                    <div class=\"progress-bar\">
                        <div class=\"progress-fill progress-${status}\" style=\"width: ${percent}%;\"></div>
                    </div>
                </div>
"
}

html_table_start() {
    local headers="$1"  # comma-separated headers
    local header_html=""
    local IFS=','
    for header in $headers; do
        header_html="${header_html}                    <th>${header}</th>
"
    done
    html_append "            <table>
                <thead><tr>
${header_html}                </tr></thead>
                <tbody>
"
}

html_table_row() {
    local cells="$1"      # pipe-separated cells (echappees automatiquement)
    local class="$2"
    local badge_html="$3" # HTML de confiance genere en interne (badge), ajoute en derniere cellule
    local class_attr=""
    local cell_html=""
    if [ -n "$class" ]; then
        class_attr=" class=\"${class}\""
    fi
    # read -a plutot que "for cell in $cells": pas d'expansion glob sur les
    # valeurs distantes (ex: "[kworker/0:1]" contre les fichiers du cwd local)
    local cell_list
    IFS='|' read -r -a cell_list <<< "$cells"
    local cell
    for cell in "${cell_list[@]}"; do
        cell_html="${cell_html}                    <td>$(html_escape "$cell")</td>
"
    done
    if [ -n "$badge_html" ]; then
        cell_html="${cell_html}                    <td>${badge_html}</td>
"
    fi
    html_append "                <tr${class_attr}>
${cell_html}                </tr>
"
}

html_table_end() {
    html_append "                </tbody>
            </table>
"
}

html_alert() {
    local type="$1"  # critical, warning, ok
    local message="$2"
    local icon=""
    case "$type" in
        critical) icon="&#9888;" ;;
        warning) icon="&#9888;" ;;
        ok) icon="&#10004;" ;;
    esac
    local escaped_msg=$(html_escape "$message")
    html_append "            <div class=\"alert alert-${type}\">
                <span class=\"alert-icon\">${icon}</span>
                <span>${escaped_msg}</span>
            </div>
"
}

html_finish() {
    html_append "        <div class=\"footer\">
            <p>Rapport genere par linux-audit.sh | Claude (Anthropic)</p>
        </div>
    </div>
</body>
</html>"
}

write_html_report() {
    if [ -n "$HTML_OUTPUT" ]; then
        echo "$HTML_CONTENT" > "$HTML_OUTPUT"
        print_success "Rapport HTML genere: $HTML_OUTPUT"
    fi
}

# Generer le graphique SVG CPU depuis les donnees SAR (dernières 24h)
generate_cpu_sar_chart() {
    local sar_path="$1"

    if [ -z "$sar_path" ]; then
        return 1
    fi

    # Collecter les donnees SAR CPU des dernieres 24h
    # Format: heure|%user|%nice|%system|%iowait|%steal|%idle
    local remote_script
    # Fichier SAR le plus recent par date de modification (et non le dernier
    # dans l'ordre du glob: sa31 passerait devant sa05 en debut de mois)
    read -r -d '' remote_script <<EOS
today_file=\$(ls -t ${sar_path}/sa[0-9][0-9] ${sar_path}/sa[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9] 2>/dev/null | head -1)
[ -n "\$today_file" ] || exit 0
# LC_ALL=C garantit format US (decimales avec point)
# Colonnes sar -u: time [AM/PM selon config sysstat] CPU %user %nice %system %iowait %steal %idle
# Seules les lignes "all" avec des valeurs numeriques sont gardees: exclut
# l'en-tete et les lignes "LINUX RESTART" (sysstat < 11.1.4)
LC_ALL=C sar -u -f "\$today_file" 2>/dev/null | awk '
    \$1 ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\$/ {
        o = (\$2 == "AM" || \$2 == "PM") ? 1 : 0
        if (\$(2+o) == "all" && \$(3+o) ~ /^[0-9.]+\$/)
            print \$1"|"\$(3+o)"|"\$(4+o)"|"\$(5+o)"|"\$(6+o)"|"\$(7+o)"|"\$(8+o)
    }' | tail -144
EOS
    # Revalidation locale (donnees distantes): heure HH:MM:SS et 6 nombres
    local cpu_data=$(ssh_exec "$remote_script" | awk -F'|' '
        NF == 7 && $1 ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/ {
            for (i = 2; i <= 7; i++) if ($i !~ /^[0-9]+(\.[0-9]+)?$/) next
            print
        }')

    if [ -z "$cpu_data" ]; then
        return 1
    fi

    # Compter le nombre de points
    local num_points=$(echo "$cpu_data" | wc -l)
    if [ "$num_points" -lt 2 ]; then
        return 1
    fi

    # Dimensions du graphique
    local width=800
    local height=180
    local margin_left=40
    local margin_right=10
    local margin_top=10
    local margin_bottom=25
    local chart_width=$((width - margin_left - margin_right))
    local chart_height=$((height - margin_top - margin_bottom))

    # Points des aires empilees (de bas en haut: user, nice, system, iowait,
    # steal, idle), calcules en une seule passe awk: une ligne par serie
    local all_points=$(echo "$cpu_data" | awk -F'|' -v n="$num_points" -v cw="$chart_width" -v ch="$chart_height" -v ml="$margin_left" -v mt="$margin_top" '
        {
            x = (NR - 1) * cw / (n - 1) + ml
            cum = 0
            for (i = 2; i <= 7; i++) {
                cum += $i
                pts[i] = pts[i] sprintf("%.1f,%.1f ", x, mt + ch - cum * ch / 100)
            }
        }
        END { for (i = 2; i <= 7; i++) print pts[i] }')
    local points_user=$(echo "$all_points" | sed -n 1p)
    local points_nice=$(echo "$all_points" | sed -n 2p)
    local points_system=$(echo "$all_points" | sed -n 3p)
    local points_iowait=$(echo "$all_points" | sed -n 4p)
    local points_steal=$(echo "$all_points" | sed -n 5p)
    local points_idle=$(echo "$all_points" | sed -n 6p)

    # Ligne de base (y = hauteur max)
    local baseline_y=$((margin_top + chart_height))
    local x_start=$margin_left
    local x_end=$((margin_left + chart_width))

    # Construire les chemins SVG (du haut vers le bas pour l'empilement)
    # idle (le plus haut - 100%)
    local path_idle="M${x_start},${baseline_y} L${points_idle}L${x_end},${baseline_y} Z"
    # steal
    local path_steal="M${x_start},${baseline_y} L${points_steal}L${x_end},${baseline_y} Z"
    # iowait
    local path_iowait="M${x_start},${baseline_y} L${points_iowait}L${x_end},${baseline_y} Z"
    # system
    local path_system="M${x_start},${baseline_y} L${points_system}L${x_end},${baseline_y} Z"
    # nice
    local path_nice="M${x_start},${baseline_y} L${points_nice}L${x_end},${baseline_y} Z"
    # user (le plus bas)
    local path_user="M${x_start},${baseline_y} L${points_user}L${x_end},${baseline_y} Z"

    # Extraire premiere et derniere heure pour les labels
    local first_time=$(echo "$cpu_data" | head -1 | cut -d'|' -f1)
    local last_time=$(echo "$cpu_data" | tail -1 | cut -d'|' -f1)

    # Generer le SVG complet
    html_append "            <div class=\"cpu-chart-container\">
                <h3 class=\"cpu-chart-title\">Historique CPU (dernieres 24h - SAR)</h3>
                <div class=\"cpu-chart\">
                    <svg viewBox=\"0 0 ${width} ${height}\" preserveAspectRatio=\"xMidYMid meet\">
                        <!-- Grille horizontale -->
                        <line x1=\"${margin_left}\" y1=\"${margin_top}\" x2=\"${x_end}\" y2=\"${margin_top}\" stroke=\"#444\" stroke-width=\"0.5\"/>
                        <line x1=\"${margin_left}\" y1=\"$((margin_top + chart_height/4))\" x2=\"${x_end}\" y2=\"$((margin_top + chart_height/4))\" stroke=\"#333\" stroke-width=\"0.5\"/>
                        <line x1=\"${margin_left}\" y1=\"$((margin_top + chart_height/2))\" x2=\"${x_end}\" y2=\"$((margin_top + chart_height/2))\" stroke=\"#333\" stroke-width=\"0.5\"/>
                        <line x1=\"${margin_left}\" y1=\"$((margin_top + 3*chart_height/4))\" x2=\"${x_end}\" y2=\"$((margin_top + 3*chart_height/4))\" stroke=\"#333\" stroke-width=\"0.5\"/>
                        <line x1=\"${margin_left}\" y1=\"${baseline_y}\" x2=\"${x_end}\" y2=\"${baseline_y}\" stroke=\"#444\" stroke-width=\"0.5\"/>

                        <!-- Aires empilees (ordre inverse: du fond vers le premier plan) -->
                        <path d=\"${path_idle}\" class=\"color-idle\" opacity=\"0.8\"/>
                        <path d=\"${path_steal}\" class=\"color-steal\" opacity=\"0.8\"/>
                        <path d=\"${path_iowait}\" class=\"color-iowait\" opacity=\"0.8\"/>
                        <path d=\"${path_system}\" class=\"color-system\" opacity=\"0.8\"/>
                        <path d=\"${path_nice}\" class=\"color-nice\" opacity=\"0.8\"/>
                        <path d=\"${path_user}\" class=\"color-user\" opacity=\"0.8\"/>

                        <!-- Axes labels -->
                        <text x=\"$((margin_left - 5))\" y=\"$((margin_top + 4))\" fill=\"#888\" font-size=\"10\" text-anchor=\"end\">100%</text>
                        <text x=\"$((margin_left - 5))\" y=\"$((margin_top + chart_height/2 + 4))\" fill=\"#888\" font-size=\"10\" text-anchor=\"end\">50%</text>
                        <text x=\"$((margin_left - 5))\" y=\"$((baseline_y))\" fill=\"#888\" font-size=\"10\" text-anchor=\"end\">0%</text>

                        <!-- Time labels -->
                        <text x=\"${margin_left}\" y=\"$((baseline_y + 15))\" fill=\"#888\" font-size=\"10\" text-anchor=\"start\">${first_time}</text>
                        <text x=\"${x_end}\" y=\"$((baseline_y + 15))\" fill=\"#888\" font-size=\"10\" text-anchor=\"end\">${last_time}</text>
                    </svg>
                </div>
                <div class=\"cpu-legend\">
                    <div class=\"cpu-legend-item\"><div class=\"cpu-legend-color bg-user\"></div><span>%user</span></div>
                    <div class=\"cpu-legend-item\"><div class=\"cpu-legend-color bg-nice\"></div><span>%nice</span></div>
                    <div class=\"cpu-legend-item\"><div class=\"cpu-legend-color bg-system\"></div><span>%system</span></div>
                    <div class=\"cpu-legend-item\"><div class=\"cpu-legend-color bg-iowait\"></div><span>%iowait</span></div>
                    <div class=\"cpu-legend-item\"><div class=\"cpu-legend-color bg-steal\"></div><span>%steal</span></div>
                    <div class=\"cpu-legend-item\"><div class=\"cpu-legend-color bg-idle\"></div><span>%idle</span></div>
                </div>
            </div>
"
    return 0
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

    # REMOTE_HOSTNAME peut deja etre defini dans main()
    [ -z "$REMOTE_HOSTNAME" ] && REMOTE_HOSTNAME=$(ssh_exec "hostname" 2>/dev/null)
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

    # HTML output
    if [ -n "$HTML_OUTPUT" ]; then
        html_section_start "Informations Systeme"
        html_info_start
        html_info_row "Hostname" "$REMOTE_HOSTNAME"
        html_info_row "Distribution" "${DISTRO_NAME} ${DISTRO_VERSION}"
        html_info_row "Kernel" "$kernel"
        html_info_row "Architecture" "$arch"
        html_info_row "Uptime" "$uptime_info"
        html_info_row "Date systeme" "$date_info"
        html_info_end
        html_section_end
    fi
}

collect_cpu_info() {
    print_header "CPU"

    local cpu_model=""
    local cpu_cores=""
    local cpu_threads=""
    local cpu_sockets=""

    # Essayer lscpu d'abord
    if remote_cmd_exists "lscpu"; then
        # LC_ALL (et non LANG): un LC_* transmis par SSH (SendEnv) l'emporterait
        local lscpu_output=$(ssh_exec "LC_ALL=C lscpu")
        cpu_model=$(echo "$lscpu_output" | grep "^Model name:" | head -1 | sed 's/Model name:[[:space:]]*//')
        # Libelles variables: "Socket(s):" ou "CPU socket(s):" (RHEL6)
        cpu_sockets=$(echo "$lscpu_output" | grep -E "^(CPU )?[Ss]ocket\(s\):" | head -1 | awk '{print $NF}')
        cpu_cores=$(echo "$lscpu_output" | grep "^Core(s) per socket:" | head -1 | awk '{print $NF}')
        cpu_threads=$(echo "$lscpu_output" | grep "^CPU(s):" | head -1 | awk '{print $NF}')
    else
        # Fallback sur /proc/cpuinfo
        cpu_model=$(ssh_exec "grep 'model name' /proc/cpuinfo | head -1 | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
    fi

    # Nombre de CPU logiques pour le ratio load/CPU: independant des libelles
    # lscpu (ARM, anciennes versions) pour ne jamais rester a 1 par defaut
    if ! is_int "$cpu_threads" || [ "$cpu_threads" -lt 1 ]; then
        cpu_threads=$(ssh_exec "getconf _NPROCESSORS_ONLN 2>/dev/null || grep -c ^processor /proc/cpuinfo")
    fi
    if is_int "$cpu_threads" && [ "$cpu_threads" -ge 1 ]; then
        NB_CPUS=$cpu_threads
    else
        cpu_threads=""
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

    is_int "$cpu_usage" || cpu_usage=""
    local cpu_usage_display="${cpu_usage:-N/A}%"
    [ -z "$cpu_usage" ] && cpu_usage_display="N/A"
    local cpu_status="ok"
    local cpu_badge=""

    # Analyse CPU
    if [ -n "$cpu_usage" ] && [ "$cpu_usage" -ge "$THRESH_CPU_CRIT" ] 2>/dev/null; then
        cpu_usage_display="${cpu_usage}%  ${RED}ALERTE: > ${THRESH_CPU_CRIT}%${NC}"
        add_alert_critical "CPU utilise a ${cpu_usage}% (seuil critique: ${THRESH_CPU_CRIT}%)"
        cpu_status="crit"
        cpu_badge="critical"
    elif [ -n "$cpu_usage" ] && [ "$cpu_usage" -ge "$THRESH_CPU_WARN" ] 2>/dev/null; then
        cpu_usage_display="${cpu_usage}%  ${YELLOW}WARNING: > ${THRESH_CPU_WARN}%${NC}"
        add_alert_warning "CPU utilise a ${cpu_usage}% (seuil warning: ${THRESH_CPU_WARN}%)"
        cpu_status="warn"
        cpu_badge="warning"
    fi

    printf "  %-14s: %b\n" "Utilisation" "$cpu_usage_display"

    # I/O Wait via vmstat: la colonne 'wa' est reperee dynamiquement dans
    # l'en-tete car sa position varie selon les versions de vmstat
    local iowait=""
    local vmstat_output=$(ssh_exec "vmstat 1 2 2>/dev/null")
    if [ -n "$vmstat_output" ]; then
        iowait=$(echo "$vmstat_output" | awk 'NR==2 {for(i=1;i<=NF;i++) if($i=="wa") col=i} END {if (col > 0) print $col}')
    fi

    local iowait_status="ok"
    local iowait_badge=""

    if [ -n "$iowait" ] && echo "$iowait" | grep -qE '^[0-9]+$'; then
        local iowait_display="${iowait}%"

        if [ "$iowait" -ge "$THRESH_IOWAIT_CRIT" ] 2>/dev/null; then
            iowait_display="${iowait}%  ${RED}ALERTE: > ${THRESH_IOWAIT_CRIT}%${NC}"
            add_alert_critical "I/O Wait a ${iowait}% (seuil critique: ${THRESH_IOWAIT_CRIT}%)"
            iowait_status="crit"
            iowait_badge="critical"
        elif [ "$iowait" -ge "$THRESH_IOWAIT_WARN" ] 2>/dev/null; then
            iowait_display="${iowait}%  ${YELLOW}WARNING: > ${THRESH_IOWAIT_WARN}%${NC}"
            add_alert_warning "I/O Wait a ${iowait}% (seuil warning: ${THRESH_IOWAIT_WARN}%)"
            iowait_status="warn"
            iowait_badge="warning"
        fi

        printf "  %-14s: %b\n" "I/O Wait" "$iowait_display"
    fi

    # HTML output
    if [ -n "$HTML_OUTPUT" ]; then
        html_section_start "CPU"
        html_info_start
        html_info_row "Modele" "${cpu_model:-N/A}"
        html_info_row "Sockets" "${cpu_sockets:-N/A}"
        html_info_row "Coeurs/Socket" "${cpu_cores:-N/A}"
        html_info_row "Threads (CPUs)" "${cpu_threads:-N/A}"
        html_info_end
        html_append "            <div class=\"info-grid\" style=\"margin-top: 15px;\">
"
        if [ -n "$cpu_badge" ]; then
            html_progress_row "Utilisation CPU" "${cpu_usage:-0}%" "${cpu_usage:-0}" "$cpu_status"
        else
            html_progress_row "Utilisation CPU" "${cpu_usage:-0}%" "${cpu_usage:-0}" "ok"
        fi
        if [ -n "$iowait" ] && echo "$iowait" | grep -qE '^[0-9]+$'; then
            html_progress_row "I/O Wait" "${iowait}%" "$iowait" "$iowait_status"
        fi
        html_info_end

        # Ajouter le graphique historique CPU si SAR disponible
        if [ -n "$SAR_PATH" ]; then
            generate_cpu_sar_chart "$SAR_PATH"
        fi

        html_section_end
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

    if ! is_int "$mem_total_kb" || [ "$mem_total_kb" -lt 1024 ]; then
        print_warning "Impossible de lire /proc/meminfo - section memoire ignoree"
        if [ -n "$HTML_OUTPUT" ]; then
            html_section_start "Memoire"
            html_alert "warning" "Impossible de lire /proc/meminfo"
            html_section_end
        fi
        return
    fi
    is_int "$mem_free_kb" || mem_free_kb=0
    is_int "$mem_buffers_kb" || mem_buffers_kb=0
    is_int "$mem_cached_kb" || mem_cached_kb=0
    is_int "$mem_available_kb" || mem_available_kb=""

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
    local mem_status="ok"

    # Analyse RAM
    if [ "$mem_used_percent" -ge "$THRESH_RAM_CRIT" ] 2>/dev/null; then
        mem_used_display="${mem_used_mb} MB (${mem_used_percent}%)  ${RED}ALERTE: > ${THRESH_RAM_CRIT}%${NC}"
        add_alert_critical "RAM utilisee a ${mem_used_percent}% (seuil critique: ${THRESH_RAM_CRIT}%)"
        mem_status="crit"
    elif [ "$mem_used_percent" -ge "$THRESH_RAM_WARN" ] 2>/dev/null; then
        mem_used_display="${mem_used_mb} MB (${mem_used_percent}%)  ${YELLOW}WARNING: > ${THRESH_RAM_WARN}%${NC}"
        add_alert_warning "RAM utilisee a ${mem_used_percent}% (seuil warning: ${THRESH_RAM_WARN}%)"
        mem_status="warn"
    fi

    printf "  %-14s: %b\n" "RAM Utilisee" "$mem_used_display"
    print_info "RAM Libre" "${mem_free_mb} MB"
    print_info "Buffers" "${mem_buffers_mb} MB"
    print_info "Cached" "${mem_cached_mb} MB"

    # HTML output
    if [ -n "$HTML_OUTPUT" ]; then
        # Calcul des pourcentages pour la barre empilee
        local used_real_mb=$((mem_used_mb - mem_buffers_mb - mem_cached_mb))
        if [ "$used_real_mb" -lt 0 ]; then
            used_real_mb=$mem_used_mb
        fi
        local used_real_percent=$((used_real_mb * 100 / mem_total_mb))
        local buffers_percent=$((mem_buffers_mb * 100 / mem_total_mb))
        local cached_percent=$((mem_cached_mb * 100 / mem_total_mb))

        html_section_start "Memoire"
        html_info_start
        html_info_row "RAM Totale" "${mem_total_mb} MB"
        html_info_end

        # Barre de progression empilee avec couleurs distinctes
        html_append "            <div style=\"margin: 15px 0;\">
                <div style=\"display: flex; justify-content: space-between; margin-bottom: 5px;\">
                    <span class=\"info-label\">Utilisation RAM</span>
                    <span class=\"info-value\">${mem_used_mb} MB / ${mem_total_mb} MB (${mem_used_percent}%)</span>
                </div>
                <div class=\"progress-bar\" style=\"height: 20px;\">
                    <div class=\"progress-stacked\">
                        <div class=\"progress-used\" style=\"width: ${used_real_percent}%;\"></div>
                        <div class=\"progress-cache\" style=\"width: ${cached_percent}%;\"></div>
                        <div class=\"progress-buffer\" style=\"width: ${buffers_percent}%;\"></div>
                    </div>
                </div>
                <div class=\"memory-legend\">
                    <div class=\"legend-item\"><div class=\"legend-color legend-used\"></div><span>Utilisee: ${used_real_mb} MB</span></div>
                    <div class=\"legend-item\"><div class=\"legend-color legend-cache\"></div><span>Cache: ${mem_cached_mb} MB</span></div>
                    <div class=\"legend-item\"><div class=\"legend-color legend-buffer\"></div><span>Buffers: ${mem_buffers_mb} MB</span></div>
                    <div class=\"legend-item\"><div class=\"legend-color legend-free\"></div><span>Libre: ${mem_free_mb} MB</span></div>
                </div>
            </div>
"

        # Alerte si necessaire
        if [ "$mem_used_percent" -ge "$THRESH_RAM_CRIT" ] 2>/dev/null; then
            html_alert "critical" "RAM utilisee a ${mem_used_percent}% (seuil critique: ${THRESH_RAM_CRIT}%)"
        elif [ "$mem_used_percent" -ge "$THRESH_RAM_WARN" ] 2>/dev/null; then
            html_alert "warning" "RAM utilisee a ${mem_used_percent}% (seuil warning: ${THRESH_RAM_WARN}%)"
        fi

        html_section_end
    fi
}

collect_swap_info() {
    print_header "SWAP"

    local meminfo=$(ssh_exec "cat /proc/meminfo")

    local swap_total_kb=$(echo "$meminfo" | grep "^SwapTotal:" | awk '{print $2}')
    local swap_free_kb=$(echo "$meminfo" | grep "^SwapFree:" | awk '{print $2}')

    if ! is_int "$swap_total_kb" || ! is_int "$swap_free_kb"; then
        print_warning "Impossible de lire les informations de swap"
        if [ -n "$HTML_OUTPUT" ]; then
            html_section_start "Swap"
            html_alert "warning" "Impossible de lire les informations de swap"
            html_section_end
        fi
        return
    fi

    local swap_total_mb=$((swap_total_kb / 1024))
    local swap_free_mb=$((swap_free_kb / 1024))
    local swap_used_mb=$((swap_total_mb - swap_free_mb))

    if [ "$swap_total_mb" -eq 0 ] 2>/dev/null; then
        print_info "Swap" "Non configure"
        # HTML output
        if [ -n "$HTML_OUTPUT" ]; then
            html_section_start "Swap"
            html_info_start
            html_info_row "Swap" "Non configure"
            html_info_end
            html_section_end
        fi
        return
    fi

    local swap_used_percent=$((swap_used_mb * 100 / swap_total_mb))

    print_info "Swap Total" "${swap_total_mb} MB"

    local swap_used_display="${swap_used_mb} MB (${swap_used_percent}%)"
    local swap_status="ok"

    # Analyse Swap
    if [ "$swap_used_percent" -ge "$THRESH_SWAP_CRIT" ] 2>/dev/null; then
        swap_used_display="${swap_used_mb} MB (${swap_used_percent}%)  ${RED}ALERTE: > ${THRESH_SWAP_CRIT}%${NC}"
        add_alert_critical "Swap utilise a ${swap_used_percent}% (seuil critique: ${THRESH_SWAP_CRIT}%)"
        swap_status="crit"
    elif [ "$swap_used_percent" -ge "$THRESH_SWAP_WARN" ] 2>/dev/null; then
        swap_used_display="${swap_used_mb} MB (${swap_used_percent}%)  ${YELLOW}WARNING: > ${THRESH_SWAP_WARN}%${NC}"
        add_alert_warning "Swap utilise a ${swap_used_percent}% (seuil warning: ${THRESH_SWAP_WARN}%)"
        swap_status="warn"
    fi

    printf "  %-14s: %b\n" "Swap Utilise" "$swap_used_display"
    print_info "Swap Libre" "${swap_free_mb} MB"

    # HTML output
    if [ -n "$HTML_OUTPUT" ]; then
        html_section_start "Swap"
        html_info_start
        html_info_row "Swap Total" "${swap_total_mb} MB"
        html_info_end
        html_append "            <div class=\"info-grid\" style=\"margin-top: 10px;\">
"
        html_progress_row "Swap Utilise" "${swap_used_mb} MB (${swap_used_percent}%)" "$swap_used_percent" "$swap_status"
        html_info_end
        html_info_start
        html_info_row "Swap Libre" "${swap_free_mb} MB"
        html_info_end
        html_section_end
    fi
}

collect_load_info() {
    print_header "LOAD AVERAGE"

    local loadavg=$(ssh_exec "cat /proc/loadavg")
    local load1=$(echo "$loadavg" | awk '{print $1}')
    local load5=$(echo "$loadavg" | awk '{print $2}')
    local load15=$(echo "$loadavg" | awk '{print $3}')

    if ! is_num "$load1" || ! is_num "$load5" || ! is_num "$load15"; then
        print_warning "Impossible de lire /proc/loadavg - section load ignoree"
        if [ -n "$HTML_OUTPUT" ]; then
            html_section_start "Load Average"
            html_alert "warning" "Impossible de lire /proc/loadavg"
            html_section_end
        fi
        return
    fi
    if ! is_int "$NB_CPUS" || [ "$NB_CPUS" -lt 1 ]; then
        NB_CPUS=1
    fi

    print_info "Load 1/5/15" "$load1 / $load5 / $load15"
    print_info "Nb CPUs" "$NB_CPUS"

    # Calcul du ratio load/cpu (valeurs validees ci-dessus)
    local ratio=$(awk -v l="$load1" -v n="$NB_CPUS" 'BEGIN {printf "%.2f", l / n}')

    local ratio_display="$ratio"
    local load_status="ok"
    local load_badge=""

    # Analyse Load
    if float_ge "$ratio" "$THRESH_LOAD_CRIT"; then
        ratio_display="${ratio}  ${RED}ALERTE: > ${THRESH_LOAD_CRIT}${NC}"
        add_alert_critical "Load average ratio a ${ratio} (seuil critique: ${THRESH_LOAD_CRIT})"
        load_status="crit"
        load_badge="CRITIQUE"
    elif float_ge "$ratio" "$THRESH_LOAD_WARN"; then
        ratio_display="${ratio}  ${YELLOW}WARNING: > ${THRESH_LOAD_WARN}${NC}"
        add_alert_warning "Load average ratio a ${ratio} (seuil warning: ${THRESH_LOAD_WARN})"
        load_status="warn"
        load_badge="WARNING"
    fi

    printf "  %-14s: %b\n" "Ratio Load/CPU" "$ratio_display"

    # HTML output
    if [ -n "$HTML_OUTPUT" ]; then
        html_section_start "Load Average"
        html_info_start
        html_info_row "Load 1/5/15" "$load1 / $load5 / $load15"
        html_info_row "Nb CPUs" "$NB_CPUS"
        if [ -n "$load_badge" ]; then
            html_info_row_with_badge "Ratio Load/CPU" "$ratio" "$load_status" "$load_badge"
        else
            html_info_row "Ratio Load/CPU" "$ratio"
        fi
        html_info_end
        html_section_end
    fi
}

collect_disk_info() {
    print_header "DISQUES ET SYSTEMES DE FICHIERS"

    # df pour l'espace disque (avec type de filesystem)
    # Filtrage sur la colonne type et non par grep sur toute la ligne: les
    # pseudo-fs et images en lecture seule (snaps squashfs, ISO...) sont
    # toujours pleins a 100% et declencheraient de fausses alertes CRITIQUES
    local df_output=$(ssh_exec "LC_ALL=C df -ThP 2>/dev/null | awk 'NR > 1 && \$2 !~ /^(tmpfs|devtmpfs|squashfs|iso9660|udf|overlay|nsfs|ramfs)\$/'")

    echo ""
    printf "  %-25s %-8s %8s %8s %8s %6s\n" "Filesystem" "Type" "Size" "Used" "Avail" "Use%"
    printf "  %-25s %-8s %8s %8s %8s %6s\n" "-------------------------" "--------" "--------" "--------" "--------" "------"

    html_section_start "Disques et Systemes de Fichiers"
    html_table_start "Filesystem,Type,Taille,Utilise,Disponible,Usage,Statut"

    # Une seule passe pour la console et le HTML; "mount" recoit le reste de
    # la ligne (points de montage contenant des espaces)
    local fs fstype size used avail use_percent mount
    while read -r fs fstype size used avail use_percent mount; do
        [ -z "$fs" ] && continue
        use_percent=${use_percent%\%}

        # Tronquer le nom du filesystem si trop long
        if [ ${#fs} -gt 25 ]; then
            fs="...${fs: -22}"
        fi

        local alert_flag=""
        local status_badge="<span class=\"badge badge-ok\">OK</span>"
        if is_int "$use_percent" && [ "$use_percent" -ge "$THRESH_DISK_CRIT" ]; then
            alert_flag="${RED}CRIT${NC}"
            status_badge="<span class=\"badge badge-critical\">CRITIQUE</span>"
            add_alert_critical "Disque $mount utilise a ${use_percent}% (seuil: ${THRESH_DISK_CRIT}%)"
        elif is_int "$use_percent" && [ "$use_percent" -ge "$THRESH_DISK_WARN" ]; then
            alert_flag="${YELLOW}WARN${NC}"
            status_badge="<span class=\"badge badge-warning\">WARNING</span>"
            add_alert_warning "Disque $mount utilise a ${use_percent}% (seuil: ${THRESH_DISK_WARN}%)"
        fi

        printf "  %-25s %-8s %8s %8s %8s %5s%% %b\n" "$fs" "$fstype" "$size" "$used" "$avail" "$use_percent" "$alert_flag"
        html_table_row "${mount}|${fstype}|${size}|${used}|${avail}|${use_percent}%" "" "$status_badge"
    done <<< "$df_output"

    html_table_end
    html_section_end

    # Statistiques I/O temps reel (iostat-like)
    echo ""
    print_header "STATISTIQUES I/O DISQUES (temps reel - 5 sec)"

    # io_data est normalise quelle que soit la source:
    #   device rMB/s wMB/s await(ms) %util
    local io_data=""
    local remote_script=""

    if remote_cmd_exists "iostat"; then
        # Colonnes reperees par leur nom dans l'en-tete (disposition variable
        # selon la version de sysstat). Si await est scinde en r_await/w_await
        # (sysstat >= 12), on le pondere par r/s et w/s: une moyenne simple
        # diviserait par deux la latence d'un disque qui ne fait qu'ecrire.
        read -r -d '' remote_script <<'EOS'
out=$(LC_ALL=C iostat -xdmy 5 1 2>/dev/null)
# sysstat < 10 (RHEL6) ne connait pas -y: deux rapports, on garde le second
[ -n "$out" ] || out=$(LC_ALL=C iostat -xdm 5 2 2>/dev/null | awk '/^Device/ {n++} n == 2')
echo "$out" | awk '
    /^Device/ {
        split("", col)
        for (i = 1; i <= NF; i++) col[$i] = i
        ok = ("rMB/s" in col) && ("wMB/s" in col) && ("%util" in col) && ("r/s" in col) && ("w/s" in col)
        next
    }
    ok && $1 ~ /^(sd|vd|hd|xvd|nvme|dm-|mmcblk|md)[0-9a-z]/ {
        rs = $col["r/s"]; ws = $col["w/s"]
        if ("await" in col) {
            aw = $col["await"]
        } else if (("r_await" in col) && ("w_await" in col)) {
            aw = (rs + ws > 0) ? (rs * $col["r_await"] + ws * $col["w_await"]) / (rs + ws) : 0
        } else {
            aw = 0
        }
        printf "%s %.2f %.2f %.1f %.1f\n", $1, $col["rMB/s"], $col["wMB/s"], aw, $col["%util"]
    }' | head -20
EOS
        io_data=$(ssh_exec "$remote_script")
    fi

    if [ -z "$io_data" ]; then
        # Fallback: calcul depuis /proc/diskstats (mesure sur 5 secondes)
        # Champs: $4 lectures, $6 secteurs lus, $7 ms lecture, $8 ecritures,
        #         $10 secteurs ecrits, $11 ms ecriture, $13 ms occupe
        # await = temps d'attente cumule / nombre de requetes (comme iostat)
        print_info "Note" "iostat non disponible, calcul depuis /proc/diskstats"
        read -r -d '' remote_script <<'EOS'
s1=$(cat /proc/diskstats)
sleep 5
s2=$(cat /proc/diskstats)
printf '%s\n--\n%s\n' "$s1" "$s2" | awk '
    $1 == "--" { second = 1; next }
    !second { r[$3] = $4; rs[$3] = $6; rt[$3] = $7; w[$3] = $8; ws[$3] = $10; wt[$3] = $11; io[$3] = $13; next }
    ($3 in r) && $3 ~ /^(sd[a-z]+|vd[a-z]+|hd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|dm-[0-9]+|mmcblk[0-9]+|md[0-9]+)$/ {
        ios = ($4 - r[$3]) + ($8 - w[$3])
        ticks = ($7 - rt[$3]) + ($11 - wt[$3])
        await = (ios > 0) ? ticks / ios : 0
        util = ($13 - io[$3]) / 5000 * 100
        if (util > 100) util = 100
        printf "%s %.2f %.2f %.1f %.1f\n", $3, ($6 - rs[$3]) * 512 / 1048576 / 5, ($10 - ws[$3]) * 512 / 1048576 / 5, await, util
    }'
EOS
        io_data=$(ssh_exec "$remote_script")
    fi

    html_section_start "Statistiques I/O Disques (temps reel - 5 sec)"
    if [ -n "$io_data" ]; then
        printf "  %-12s %10s %10s %8s %8s %8s\n" "Device" "rMB/s" "wMB/s" "await" "%util" "Statut"
        printf "  %-12s %10s %10s %8s %8s %8s\n" "------------" "----------" "----------" "--------" "--------" "--------"
        html_table_start "Device,rMB/s,wMB/s,await (ms),%util,Statut"

        local dev rmb wmb await util
        while read -r dev rmb wmb await util; do
            [ -z "$dev" ] && continue
            is_num "$util" || util=0
            is_num "$await" || await=0

            local alert_flag=""
            local status_badge="<span class=\"badge badge-ok\">OK</span>"
            if float_ge "$util" "$THRESH_DISKIO_UTIL_CRIT"; then
                alert_flag="${RED}CRIT${NC}"
                status_badge="<span class=\"badge badge-critical\">SATURATION</span>"
                add_alert_critical "Disque $dev: utilisation a ${util}% (saturation)"
            elif float_ge "$util" "$THRESH_DISKIO_UTIL_WARN"; then
                alert_flag="${YELLOW}WARN${NC}"
                status_badge="<span class=\"badge badge-warning\">CHARGE</span>"
                add_alert_warning "Disque $dev: utilisation a ${util}%"
            elif float_ge "$await" "$THRESH_DISKIO_AWAIT_WARN"; then
                alert_flag="${YELLOW}WARN${NC}"
                status_badge="<span class=\"badge badge-warning\">LATENCE</span>"
                add_alert_warning "Disque $dev: latence elevee (await=${await}ms)"
            fi

            printf "  %-12s %10s %10s %8s %8s %b\n" "$dev" "$rmb" "$wmb" "${await}ms" "${util}%" "$alert_flag"
            html_table_row "${dev}|${rmb}|${wmb}|${await}|${util}%" "" "$status_badge"
        done <<< "$io_data"
        html_table_end
    else
        print_warning "Impossible de collecter les statistiques I/O"
        html_append "            <p>Aucune statistique I/O disponible</p>
"
    fi
    html_section_end
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

    html_section_start "Reseau"

    if [ -n "$ip_output" ]; then
        local line
        while IFS= read -r line; do
            echo "  $line"
        done <<< "$ip_output"
        html_append "            <h3 style=\"color: #a0a0a0; font-size: 1em; margin-bottom: 10px;\">Adresses IP</h3>
            <pre style=\"background: rgba(0,0,0,0.3); padding: 15px; border-radius: 6px; overflow-x: auto; color: #e8e8e8;\">$(html_escape "$ip_output")</pre>
"
    else
        print_warning "Impossible de recuperer les informations reseau"
    fi

    # Statistiques interfaces
    # "iface:" est remplace par "iface " avant le decoupage: sur les anciens
    # noyaux le compteur RX est colle au nom ("eth0:123456789")
    echo ""
    local netdev=$(ssh_exec "tail -n +3 /proc/net/dev 2>/dev/null | sed 's/:/ /' | awk '\$1 != \"lo\" {print \$1, \$2, \$10}'")

    if [ -n "$netdev" ]; then
        # IPs par interface (une seule recuperation pour console et HTML)
        local ip_list=""
        if remote_cmd_exists "ip"; then
            ip_list=$(ssh_exec "ip -4 addr show 2>/dev/null | awk '/inet / {sub(/\\/.*/, \"\", \$2); print \$NF, \$2}'")
        fi

        printf "  %-12s %-18s %15s %15s\n" "Interface" "Adresse IP" "RX bytes" "TX bytes"
        printf "  %-12s %-18s %15s %15s\n" "------------" "------------------" "---------------" "---------------"
        html_append "            <h3 style=\"color: #a0a0a0; font-size: 1em; margin: 15px 0 10px 0;\">Statistiques Interfaces</h3>
"
        html_table_start "Interface,Adresse IP,RX,TX"

        local iface rx_bytes tx_bytes
        while read -r iface rx_bytes tx_bytes; do
            [ -z "$iface" ] && continue

            # Trouver l'IP de cette interface (comparaison exacte, sans regex)
            local iface_ip=$(echo "$ip_list" | awk -v i="$iface" '$1 == i {print $2; exit}')
            [ -z "$iface_ip" ] && iface_ip="-"

            # Convertir en format lisible
            local rx_human=$(human_bytes "$rx_bytes")
            local tx_human=$(human_bytes "$tx_bytes")

            printf "  %-12s %-18s %15s %15s\n" "$iface" "$iface_ip" "$rx_human" "$tx_human"
            html_table_row "${iface}|${iface_ip}|${rx_human}|${tx_human}"
        done <<< "$netdev"
        html_table_end
    fi

    html_section_end
}

# Octets -> format lisible (B, KB, MB, GB)
human_bytes() {
    is_int "$1" || { echo "-"; return; }
    awk -v b="$1" 'BEGIN {
        if (b >= 1073741824) printf "%.2f GB", b / 1073741824
        else if (b >= 1048576) printf "%.2f MB", b / 1048576
        else if (b >= 1024) printf "%.2f KB", b / 1024
        else printf "%d B", b
    }'
}

# Affiche un tableau de processus (console + HTML) en une seule passe
# $1: titre, $2: en-tetes HTML (virgules), $3: donnees "user pid v1 v2 cmd"
# $4: largeur des colonnes valeurs en console, $5/$6: en-tetes console
print_process_table() {
    local title="$1" html_headers="$2" data="$3" width="$4" h1="$5" h2="$6"

    echo ""
    echo "  ${title}:"
    printf "  %-8s %-8s %-${width}s %-${width}s %s\n" "USER" "PID" "$h1" "$h2" "COMMAND"
    local dashes=$(printf "%${width}s" "" | tr ' ' '-')
    printf "  %-8s %-8s %-${width}s %-${width}s %s\n" "--------" "--------" "$dashes" "$dashes" "---------------"

    html_append "            <h3 style=\"color: #a0a0a0; font-size: 1em; margin: 15px 0 10px 0;\">$(html_escape "$title")</h3>
            <div class=\"table-process\">
"
    html_table_start "$html_headers"
    local user pid v1 v2 cmd
    while read -r user pid v1 v2 cmd; do
        [ -z "$user" ] && continue
        printf "  %-8s %-8s %-${width}s %-${width}s %s\n" "$user" "$pid" "$v1" "$v2" "$(echo "$cmd" | cut -c1-30)"
        html_table_row "${user}|${pid}|${v1}|${v2}|$(echo "$cmd" | cut -c1-40)"
    done <<< "$data"
    html_table_end
    html_append "            </div>
"
}

collect_process_info() {
    print_header "TOP PROCESSUS"
    html_section_start "Top Processus"

    # Colonnes: user pid %cpu %mem commande (premier mot de la commande)
    local top_cpu=$(ssh_exec "ps aux --sort=-%cpu 2>/dev/null | awk 'NR > 1 && NR <= 6 {print \$1, \$2, \$3, \$4, \$11}'")
    print_process_table "Top 5 processus par CPU" "User,PID,%CPU,%MEM,Commande" "$top_cpu" 8 "%CPU" "%MEM"

    local top_mem=$(ssh_exec "ps aux --sort=-%mem 2>/dev/null | awk 'NR > 1 && NR <= 6 {print \$1, \$2, \$3, \$4, \$11}'")
    print_process_table "Top 5 processus par Memoire" "User,PID,%CPU,%MEM,Commande" "$top_mem" 8 "%CPU" "%MEM"

    # Compteurs /proc/[pid]/io cumules depuis le demarrage de chaque processus
    # (pas un debit instantane). Lisibles uniquement pour ses propres
    # processus quand on n'est pas root.
    local top_io=$(ssh_exec "for p in /proc/[0-9]*; do pid=\${p##*/}; [ -r \$p/io ] || continue; rb=\$(awk '/^read_bytes:/{print \$2}' \$p/io 2>/dev/null); wb=\$(awk '/^write_bytes:/{print \$2}' \$p/io 2>/dev/null); [ -n \"\$rb\" ] && [ -n \"\$wb\" ] || continue; t=\$((\$rb+\$wb)); [ \$t -gt 0 ] || continue; u=\$(stat -c '%U' \$p 2>/dev/null); u=\${u:-?}; c=\$(cat \$p/comm 2>/dev/null); c=\${c:-?}; printf '%d %s %s %d %d %s\n' \$t \"\$u\" \$pid \$((\$rb/1024)) \$((\$wb/1024)) \"\$c\"; done 2>/dev/null | sort -rn | head -5 | awk '{print \$2,\$3,\$4,\$5,\$6}'")
    print_process_table "Top 5 processus par I/O Disque (cumul depuis leur demarrage)" "User,PID,READ (Ko),WRITE (Ko),Commande" "$top_io" 12 "READ(Ko)" "WRITE(Ko)"

    html_section_end
}

#-------------------------------------------------------------------------------
# SECTION 4: COLLECTE SAR (SYSSTAT)
#-------------------------------------------------------------------------------

# Detecte le repertoire des fichiers SAR et le stocke dans SAR_PATH
# (appele une seule fois, hors substitution de commande)
detect_sar_path() {
    SAR_PATH=$(ssh_exec "for d in /var/log/sa /var/log/sysstat; do for f in \$d/sa[0-9][0-9] \$d/sa[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]; do [ -f \"\$f\" ] && { echo \$d; exit 0; }; done; done")
    [ -n "$SAR_PATH" ]
}

# Analyse historique des I/O disques depuis SAR
analyze_sar_io_history() {
    local sar_path="$1"
    local io_anomalies=""

    print_header "ANALYSE HISTORIQUE I/O (SAR)"

    if [ -z "$sar_path" ]; then
        print_warning "Analyse historique non disponible (pas de donnees SAR)"
        return 1
    fi

    echo "  Analyse des pics I/O sur l'historique SAR..."

    # Une seule passe awk par fichier (et un seul sar -d): l'ancienne boucle
    # shell lancait une dizaine de processus par ligne sur le serveur audite.
    # - colonnes reperees par nom sur la ligne d'en-tete (horodatee et dont
    #   un champ vaut exactement "DEV"), jamais sur la banniere
    # - sar -p: noms de devices lisibles (sda, dm-0, vg-lv) au lieu de dev8-0
    # - sortie: TYPE|cle de tri YYYYMMDD|date DD/MM/YYYY|heure|dev|%util|await|valeur
    # - LINES|n: nombre de mesures analysees (distingue "pas de donnees")
    local remote_script
    read -r -d '' remote_script <<'EOS'
for f in $(ls -rt $SAR_DIR/sa[0-9][0-9] $SAR_DIR/sa[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9] 2>/dev/null); do
    LC_ALL=C sar -d -p -f "$f" 2>/dev/null | awk -v ut="$UT" -v aw="$AW" '
        NR == 1 {
            # Banniere: "Linux <kernel> (<host>) MM/DD/YY ..."
            for (i = 1; i <= NF; i++) if ($i ~ /^[0-9][0-9]\/[0-9][0-9]\/[0-9][0-9]([0-9][0-9])?$/) {
                split($i, d, "/"); y = d[3]; if (length(y) == 2) y = "20" y
                date = d[2] "/" d[1] "/" y; key = y d[1] d[2]
            }
            next
        }
        $1 !~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/ { next }
        {
            o = ($2 == "AM" || $2 == "PM") ? 1 : 0
            # En-tete: un champ vaut exactement "DEV" (sa position varie:
            # 2e colonne, ou derniere avec -p sur sysstat >= 12)
            hdr = 0; for (i = 1; i <= NF; i++) if ($i == "DEV") hdr = 1
        }
        hdr { split("", col); for (i = 1; i <= NF; i++) col[$i] = i; next }
        !("DEV" in col) || !("%util" in col) { next }
        {
            u = $col["%util"]; a = ("await" in col) ? $col["await"] : 0
            if (u !~ /^[0-9.]+$/ || a !~ /^[0-9.]+$/) next
            lines++
            t = o ? $1 " " $2 : $1
            if (u + 0 >= ut) print "UTIL|" key "|" date "|" t "|" $col["DEV"] "|%util=" u "%|await=" a "ms|" u
            else if (a + 0 >= aw) print "AWAIT|" key "|" date "|" t "|" $col["DEV"] "|%util=" u "%|await=" a "ms|" a
        }
        END { print "LINES|" lines + 0 }'
done
EOS
    io_anomalies=$(ssh_exec "SAR_DIR='$sar_path'; UT='$THRESH_SAR_UTIL'; AW='$THRESH_SAR_AWAIT'
$remote_script")

    local analyzed=$(echo "$io_anomalies" | awk -F'|' '$1 == "LINES" {n += $2} END {print n + 0}')

    # Top 10 par type (tri numerique en locale C: decimales a point), puis
    # tri chronologique inverse sur la cle YYYYMMDD + heure
    local util_anomalies=$(echo "$io_anomalies" | grep '^UTIL|' | LC_ALL=C sort -t'|' -k8,8 -rn | head -10)
    local await_anomalies=$(echo "$io_anomalies" | grep '^AWAIT|' | LC_ALL=C sort -t'|' -k8,8 -rn | head -10)
    io_anomalies=$(printf '%s\n%s\n' "$util_anomalies" "$await_anomalies" | grep -v '^$' | LC_ALL=C sort -t'|' -k2,2r -k4,4r | cut -d'|' -f1,3-7)

    SAR_IO_ANALYZED=$analyzed

    if [ "$analyzed" -eq 0 ]; then
        print_warning "Aucune mesure disque (sar -d) dans l'historique SAR - analyse impossible"
    elif [ -n "$io_anomalies" ]; then
        local count=$(echo "$io_anomalies" | wc -l | tr -d ' ')
        print_warning "Detecte $count pic(s) I/O anormaux dans l'historique SAR ($analyzed mesures analysees)"
        echo ""
        printf "  %-12s %-10s %-10s %-12s %-12s\n" "Date" "Heure" "Device" "%util" "await"
        printf "  %-12s %-10s %-10s %-12s %-12s\n" "------------" "----------" "----------" "------------" "------------"

        local type date time dev util await
        while IFS='|' read -r type date time dev util await; do
            printf "  %-12s %-10s %-10s %-12s %-12s\n" "$date" "$time" "$dev" "$util" "$await"
        done <<< "$io_anomalies"

        # Ajouter une alerte globale
        add_alert_warning "Pics I/O historiques detectes (${count} occurrences) - voir section Analyse SAR"
    else
        print_success "Aucun pic I/O anormal detecte dans l'historique SAR ($analyzed mesures analysees)"
    fi

    # Stocker pour HTML
    SAR_IO_ANOMALIES="$io_anomalies"

    return 0
}

collect_sar_data() {
    print_header "COLLECTE DONNEES SAR (SYSSTAT)"

    local sar_available=0
    local sar_path=""
    local sar_files=""
    local output_file=""
    local file_size=""

    # Verifier si sar est disponible
    if ! remote_cmd_exists "sar"; then
        print_warning "sysstat n'est pas installe sur ce serveur - donnees SAR non disponibles"
    else
        # Chemin des fichiers SAR (detecte une fois dans main)
        sar_path="$SAR_PATH"

        if [ -z "$sar_path" ]; then
            print_warning "Aucun fichier SAR trouve dans /var/log/sa ou /var/log/sysstat"
        else
            sar_available=1
            print_info "Chemin SAR" "$sar_path"

            # Lister les fichiers disponibles (format ancien sa01 et nouveau sa20260125)
            sar_files=$(ssh_exec "ls -rt ${sar_path}/sa[0-9][0-9] ${sar_path}/sa[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9] 2>/dev/null | wc -l")
            print_info "Fichiers SAR" "${sar_files} fichier(s) trouve(s)"

            # Nom du fichier de sortie
            output_file="${TIMESTAMP}-${REMOTE_HOSTNAME}-sar.gz"

            echo "  Extraction des donnees SAR en cours..."

            # Executer la commande sar sur tous les fichiers et compresser
            # Support format ancien (sa01) et nouveau (sa20260125)
            # LC_ALL=C garantit un format US (dates MM/DD/YY, decimales avec point)
            ssh_exec "for i in \$(ls -rt ${sar_path}/sa[0-9][0-9] ${sar_path}/sa[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9] 2>/dev/null); do LC_ALL=C sar -A -f \$i 2>/dev/null; done | gzip -c" > "$output_file"

            if [ -s "$output_file" ]; then
                file_size=$(ls -lh "$output_file" | awk '{print $5}')
                print_success "Donnees SAR exportees: $output_file (${file_size})"
            else
                print_warning "Fichier SAR vide ou erreur lors de la collecte"
                rm -f "$output_file"
                sar_available=0
            fi

            # Analyse historique des I/O
            analyze_sar_io_history "$sar_path"
        fi
    fi

    # HTML output
    if [ -n "$HTML_OUTPUT" ]; then
        html_section_start "Donnees SAR (Sysstat)"
        html_info_start
        if [ "$sar_available" -eq 1 ]; then
            html_info_row "Statut" "Disponible"
            html_info_row "Chemin SAR" "$sar_path"
            html_info_row "Fichiers SAR" "${sar_files} fichier(s)"
            html_info_row "Export" "${output_file} (${file_size})"
        else
            html_info_row "Statut" "Non disponible"
            html_info_row "Note" "sysstat n'est pas installe ou aucun fichier SAR trouve"
        fi
        html_info_end

        # Section analyse I/O historique
        if [ -n "$SAR_IO_ANOMALIES" ]; then
            html_append "            <h3 style=\"color: #ff6b6b; font-size: 1em; margin: 20px 0 10px 0;\">Pics I/O Historiques Detectes</h3>
"
            html_table_start "Date,Heure,Device,%util,await,Cause"
            while IFS='|' read -r type date time dev util await; do
                [ -z "$type" ] && continue
                if [ "$type" = "UTIL" ]; then
                    html_table_row "${date}|${time}|${dev}|${util}|${await}" "" "<span class=\"badge badge-critical\">%util</span>"
                else
                    html_table_row "${date}|${time}|${dev}|${util}|${await}" "" "<span class=\"badge badge-warning\">await</span>"
                fi
            done <<< "$SAR_IO_ANOMALIES"
            html_table_end
        elif [ "$sar_available" -eq 1 ] && [ "$SAR_IO_ANALYZED" -eq 0 ]; then
            html_alert "warning" "Aucune mesure disque (sar -d) dans l'historique SAR - analyse impossible"
        elif [ "$sar_available" -eq 1 ]; then
            html_alert "ok" "Aucun pic I/O anormal detecte dans l'historique SAR (${SAR_IO_ANALYZED} mesures analysees)"
        fi

        html_section_end
    fi

    return 0
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

    # HTML output
    if [ -n "$HTML_OUTPUT" ]; then
        html_section_start "Synthese des Alertes"
        html_append "            <div class=\"alert-section\">
"

        if [ -n "$ALERTS_CRITICAL" ]; then
            local alerts_crit=$(echo "$ALERTS_CRITICAL" | tr '|' '\n')
            while IFS= read -r alert; do
                if [ -n "$alert" ]; then
                    html_alert "critical" "$alert"
                fi
            done <<< "$alerts_crit"
        fi

        if [ -n "$ALERTS_WARNING" ]; then
            local alerts_warn=$(echo "$ALERTS_WARNING" | tr '|' '\n')
            while IFS= read -r alert; do
                if [ -n "$alert" ]; then
                    html_alert "warning" "$alert"
                fi
            done <<< "$alerts_warn"
        fi

        if [ -z "$ALERTS_CRITICAL" ] && [ -z "$ALERTS_WARNING" ]; then
            html_alert "ok" "Aucune alerte detectee - tous les indicateurs sont dans les seuils normaux"
        fi

        html_append "            </div>
"
        html_section_end
    fi
}

#-------------------------------------------------------------------------------
# SECTION 6: FONCTION PRINCIPALE
#-------------------------------------------------------------------------------

parse_arguments() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -u|--user)
                if [ $# -lt 2 ]; then print_error "Option $1 requiert une valeur"; usage; fi
                REMOTE_USER="$2"
                shift 2
                ;;
            -p|--port)
                if [ $# -lt 2 ]; then print_error "Option $1 requiert une valeur"; usage; fi
                REMOTE_PORT="$2"
                shift 2
                ;;
            -i|--identity)
                if [ $# -lt 2 ]; then print_error "Option $1 requiert une valeur"; usage; fi
                SSH_KEY="$2"
                shift 2
                ;;
            -P|--password)
                # $2 est un mot de passe s'il ne commence pas par '-' et que ce
                # n'est pas le hostname: "-P serveur" (dernier argument, hote
                # pas encore vu) demande le mot de passe au lieu d'avaler l'hote
                if [ -n "$2" ] && [ "${2#-}" = "$2" ] && { [ -n "$REMOTE_HOST" ] || [ $# -gt 2 ]; }; then
                    SSH_PASSWORD="$2"
                    shift 2
                elif [ -n "$SSHPASS" ]; then
                    # Mot de passe fourni par l'environnement (non interactif)
                    SSH_PASSWORD="$SSHPASS"
                    shift 1
                else
                    # Pas de mot de passe fourni, demander interactivement
                    # IFS= et -r: espaces et antislashs conserves tels quels
                    printf "Password: "
                    IFS= read -rs SSH_PASSWORD
                    echo ""
                    shift 1
                fi
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

    # Refuser les valeurs qui seraient lues comme des options par ssh
    case "$REMOTE_USER" in
        -*|*@*|'') print_error "Utilisateur SSH invalide: $REMOTE_USER"; usage ;;
    esac
    if ! is_int "$REMOTE_PORT" || [ "$REMOTE_PORT" -lt 1 ] || [ "$REMOTE_PORT" -gt 65535 ]; then
        print_error "Port SSH invalide: $REMOTE_PORT"
        usage
    fi
    if [ -n "$SSH_KEY" ] && [ ! -r "$SSH_KEY" ]; then
        print_error "Cle SSH illisible: $SSH_KEY"
        exit 1
    fi

    detect_hostkey_policy
    build_ssh_args
}

cleanup() {
    close_ssh_master
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
}

main() {
    # Rapports et export SAR lisibles uniquement par l'utilisateur: ils
    # contiennent des informations d'infrastructure sensibles
    umask 077

    # Parser les arguments
    parse_arguments "$@"

    WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/linux-audit.XXXXXX") || {
        print_error "Impossible de creer un repertoire temporaire"
        exit 3
    }
    trap cleanup EXIT

    # Verifier si sshpass est disponible quand on utilise un mot de passe
    if [ -n "$SSH_PASSWORD" ]; then
        if ! command -v sshpass >/dev/null 2>&1; then
            print_error "sshpass n'est pas installe. Installez-le avec:"
            echo "  - Debian/Ubuntu: sudo apt-get install sshpass"
            echo "  - RHEL/CentOS:   sudo yum install sshpass"
            echo "  - macOS:         brew install hudochenkov/sshpass/sshpass"
            exit 1
        fi
    fi

    # En-tete du rapport
    echo ""
    print_line
    printf "${BOLD}                    AUDIT SYSTEME LINUX - %s${NC}\n" "$REMOTE_HOST"
    printf "                    Date: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
    print_line

    # Test de connexion SSH
    echo ""
    echo "Connexion SSH vers ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PORT}..."

    open_ssh_master
    if ! test_ssh_connection; then
        print_error "Impossible de se connecter au serveur $REMOTE_HOST"
        print_error "Verifiez: hostname, utilisateur, port, cle SSH, et que le serveur est accessible"
        exit 1
    fi

    if [ -n "$SSH_CONTROL" ]; then
        print_success "Connexion SSH etablie (multiplexee)"
    else
        print_success "Connexion SSH etablie"
    fi

    detect_remote_cmds
    if remote_cmd_exists "sar"; then
        detect_sar_path
    fi

    # Recuperer le hostname pour le nom du fichier HTML
    # Assainir: le hostname vient du serveur distant, ne garder que des
    # caracteres surs pour un nom de fichier local (pas de / ni ..)
    REMOTE_HOSTNAME=$(ssh_exec "hostname" 2>/dev/null | head -1 | tr -cd 'A-Za-z0-9._-' | cut -c1-64)
    if [ -z "$REMOTE_HOSTNAME" ]; then
        REMOTE_HOSTNAME=$(echo "$REMOTE_HOST" | tr -cd 'A-Za-z0-9._-' | cut -c1-64)
    fi

    # Initialiser le rapport HTML automatiquement
    HTML_OUTPUT="${TIMESTAMP}-${REMOTE_HOSTNAME}-audit.html"
    html_init "$REMOTE_HOSTNAME" "$(date '+%Y-%m-%d %H:%M:%S')"

    # Collecte des informations
    collect_system_info;  check_ssh_alive "informations systeme"
    collect_cpu_info;     check_ssh_alive "CPU"
    collect_memory_info;  check_ssh_alive "memoire"
    collect_swap_info;    check_ssh_alive "swap"
    collect_load_info;    check_ssh_alive "load average"
    collect_disk_info;    check_ssh_alive "disques"
    collect_network_info; check_ssh_alive "reseau"
    collect_process_info; check_ssh_alive "processus"

    # Collecte SAR
    collect_sar_data;     check_ssh_alive "SAR"

    # Synthese des alertes
    print_alert_summary

    # Finaliser et ecrire le rapport HTML
    html_finish
    write_html_report

    # Pied de page
    echo ""
    print_line
    printf "${BOLD}                         FIN DU RAPPORT${NC}\n"
    print_line
    echo ""
}

# Point d'entree
main "$@"
