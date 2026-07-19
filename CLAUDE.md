# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`linux-audit.sh` is a bash script that audits remote Linux servers via SSH, collecting system information, performance metrics, and SAR (sysstat) historical data. It generates both terminal output with colored alerts and a standalone HTML report.

## Running the Script

```bash
# Basic usage
./linux-audit.sh hostname_or_ip

# With SSH options
./linux-audit.sh -u admin -p 2222 -i ~/.ssh/id_rsa hostname

# With password authentication (requires sshpass)
./linux-audit.sh -u admin -P hostname           # interactive prompt
./linux-audit.sh -u admin -P 'secret' hostname   # password as argument
```

No build or test commands - this is a single bash script.

## Architecture

The script (~2000 lines) is organized into numbered sections:

| Section | Lines | Purpose |
|---------|-------|---------|
| 1 | ~1-60 | Global variables, thresholds, colors |
| 2 | ~63-202 | Utility functions (print_*, ssh_exec, alerts) |
| 2B | ~203-668 | HTML generation functions (html_*) |
| 3 | ~669-1600 | Data collection functions (collect_*) |
| 4 | ~1601-1803 | SAR/sysstat data collection and analysis |
| 5 | ~1804-1873 | Alert summary generation |
| 6 | ~1874-end | Main function, argument parsing |

### Key Functions

- `ssh_exec()` - Executes commands on remote server via SSH
- `detect_distro()` - Detects Linux distribution (RHEL, Debian, Ubuntu, Oracle, etc.)
- `detect_sar_path()` - Locates SAR data files (supports old and new sysstat paths)
- `collect_*()` - Data collection functions:
  - `collect_system_info()` - OS, kernel, hostname, uptime
  - `collect_cpu_info()` - CPU model, cores, current usage
  - `collect_memory_info()` - RAM usage, buffers, cache
  - `collect_swap_info()` - Swap usage and top swap consumers
  - `collect_load_info()` - Load averages vs CPU count
  - `collect_disk_info()` - Filesystem usage with type column
  - `collect_network_info()` - Interfaces, IPs, routing
  - `collect_process_info()` - Top processes by CPU/memory/disk I/O
  - `collect_sar_data()` - Historical SAR metrics
- `html_*()` - HTML generation helpers that append to `HTML_CONTENT` global variable
- `generate_cpu_sar_chart()` - Generates SVG stacked area chart from SAR CPU data (shows %user, %system, %iowait, %idle)
- `analyze_sar_io_history()` - Detects I/O anomalies from historical SAR data using dynamic column detection

### Data Flow

1. SSH connection established to remote host
2. Each `collect_*()` function runs commands via `ssh_exec()`
3. Console output printed immediately with colored alerts
4. HTML content accumulated in `HTML_CONTENT` variable
5. At end, HTML written to `YYYYMMDD-Hostname-audit.html`

## Privilege Requirements

No root required on either machine:
- **Local machine**: any user with `ssh`/`gzip` available can run the script
- **Remote machine**: any SSH user works; all collected data comes from world-readable sources (`/proc/meminfo`, `/proc/cpuinfo`, `/proc/loadavg`, `/proc/diskstats`, `/proc/net/dev`, `df`, `ps`, `uname`, etc.)

Two limitations apply for non-root remote users:
- **Disk I/O per process** (`collect_process_info`): `/proc/[pid]/io` is only readable by the process owner or root. A non-root user will only see I/O stats for their own processes. The script handles this gracefully with `[ -r $p/io ] || continue`.
- **SAR data** (`collect_sar_data`): SAR files in `/var/log/sa/` or `/var/log/sysstat/` may require membership in the `adm` group (Debian/Ubuntu) or explicit read permissions (RHEL/CentOS). If unreadable, the SAR section is skipped with a warning.

The default SSH user is `root` (convenience default only), overridable with `-u`.

## Technical Constraints

### Bash 3.x Compatibility (RHEL6 Support)
- No associative arrays (`declare -A`)
- No lowercase/uppercase expansion (`${var,,}`, `${var^^}`)
- Use pipe-delimited strings instead of arrays for alert storage

### SAR Data Parsing
- Always use `LC_ALL=C` for SAR commands to ensure consistent US format (dot decimal separator, MM/DD/YY dates)
- Column detection must be dynamic - sysstat versions have different column layouts for metrics like `await` and `%util`
- Support both old (`/var/log/sa/sa01`) and new (`/var/log/sysstat/sa20260125`) SAR file naming
- I/O anomaly detection uses multiple criteria: high await (>20ms) OR high %util (>80%), not just one metric

### Subshell Variable Scope
- Avoid `echo | while read` pattern - variables set in subshell are lost
- Use `while read <<< "$var"` (here-strings) instead

## Threshold Configuration

Alert thresholds are defined at the top of the script (lines ~23-35):
```bash
THRESH_RAM_WARN=75    THRESH_RAM_CRIT=85
THRESH_SWAP_WARN=30   THRESH_SWAP_CRIT=50
THRESH_CPU_WARN=70    THRESH_CPU_CRIT=85
THRESH_LOAD_WARN=1.0  THRESH_LOAD_CRIT=1.5
THRESH_IOWAIT_WARN=15 THRESH_IOWAIT_CRIT=25
THRESH_DISK_WARN=80   THRESH_DISK_CRIT=90
```

## Output Files

The script generates:
- `YYYYMMDD-Hostname-audit.html` - Standalone HTML report with embedded CSS, includes:
  - Interactive sections with collapsible details
  - SVG CPU history chart (stacked area: %user, %system, %iowait, %idle)
  - Color-coded alerts matching terminal output
- `YYYYMMDD-Hostname-sar.gz` - Compressed SAR data export (if sysstat available)

## Companion Files

- `linux-audit.sh.1` — **man page** (roff) du script ; à mettre à jour en même temps que le script quand options/sortie changent
- `linux-audit.README` — README texte historique (distribué avec le script)
- `README.md` — README GitHub ; à maintenir **en même temps** que ce CLAUDE.md (convention du dépôt racine)
- `LICENSE` — licence du projet

## Code Style

- French comments throughout (legacy codebase)
- Functions prefixed by purpose: `print_*`, `html_*`, `collect_*`
- Global variables in UPPER_CASE
- Local variables declared with `local` keyword
