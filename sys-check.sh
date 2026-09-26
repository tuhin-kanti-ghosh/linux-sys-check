#!/usr/bin/env bash
#
# sys-check.sh — quick Linux compromise/health check
# Runs a set of manual security checks (network, processes, persistence,
# SSH keys, login history) and prints a readable report, flagging anything
# that looks off. Not a replacement for rkhunter/chkrootkit/ClamAV/Lynis —
# use this for a fast manual look, use those for signature-based scanning.
#
# Usage: ./sys-check.sh [--no-log]
#
# Tested target: Arch-based systems (CachyOS/Arch/Manjaro). Should work on
# most systemd-based distros; a couple of checks are skipped gracefully if
# a tool isn't installed.

set -uo pipefail

# ---------- setup ----------

RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
GREEN=$'\033[0;32m'
CYAN=$'\033[1;36m'
BOLD=$'\033[1m'
NC=$'\033[0m'

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="sys-check_${TIMESTAMP}.log"
NO_LOG=false
[[ "${1:-}" == "--no-log" ]] && NO_LOG=true

FLAG_COUNT=0

if ! $NO_LOG; then
    exec > >(tee "$LOGFILE") 2>&1
fi

section() {
    echo
    echo "${BOLD}${CYAN}== $1 ==${NC}"
}

flag() {
    echo "  ${RED}[SUSPICIOUS]${NC} $1"
    FLAG_COUNT=$((FLAG_COUNT + 1))
}

warn() {
    echo "  ${YELLOW}[CHECK]${NC} $1"
}

ok() {
    echo "  ${GREEN}[OK]${NC} $1"
}

have() {
    command -v "$1" >/dev/null 2>&1
}

echo "${BOLD}Linux System Check — $(date)${NC}"
echo "Host: $(hostname)  |  User: $(whoami)  |  Kernel: $(uname -r)"

# ---------- network connections ----------

section "Network Connections"
if have ss; then
    ss -tupn 2>/dev/null | tail -n +2 | while read -r line; do
        echo "  $line"
    done

    # flag connections on high/uncommon ports with an established state
    SUSP_CONN=$(ss -tupn 2>/dev/null | awk 'NR>1 && $1=="ESTAB" {print}' | \
        grep -Ev ':(22|53|80|443|123)\s' || true)
    if [[ -n "$SUSP_CONN" ]]; then
        warn "Established connections on non-standard ports found above — review manually"
    else
        ok "No obviously unusual established connections"
    fi
else
    warn "ss not found, skipping network check"
fi

# ---------- listening ports ----------

section "Listening Ports"
if have ss; then
    ss -tulpn 2>/dev/null | tail -n +2
else
    warn "ss not found, skipping"
fi

# ---------- processes ----------

section "Top Processes (CPU)"
ps aux --sort=-%cpu | head -n 11

section "Top Processes (Memory)"
ps aux --sort=-%mem | head -n 11

section "Root Processes Running From Suspicious Paths"
ROOT_TMP=$(ps -eo user,pid,cmd | awk '$1=="root"' | \
    grep -E '(/tmp/|/dev/shm/|/var/tmp/)' || true)
if [[ -n "$ROOT_TMP" ]]; then
    echo "$ROOT_TMP"
    flag "Root process(es) executing from /tmp, /dev/shm, or /var/tmp — investigate immediately"
else
    ok "No root processes running from temp directories"
fi

# ---------- persistence: cron ----------

section "Cron Jobs (current user)"
crontab -l 2>/dev/null || echo "  No user crontab"

section "Cron Jobs (root)"
if [[ "$(whoami)" == "root" ]] || have sudo; then
    sudo crontab -l 2>/dev/null || echo "  No root crontab (or insufficient privileges)"
fi

section "System-wide Cron Directories"
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [[ -d "$d" ]]; then
        echo "  $d:"
        ls -la "$d" 2>/dev/null | tail -n +2 | sed 's/^/    /'
    fi
done

# ---------- persistence: systemd ----------

section "Enabled systemd Services"
if have systemctl; then
    systemctl list-units --type=service --state=running --no-pager | head -n -6
    echo
    warn "Scan the list above for service names you don't recognize"
else
    warn "systemctl not found, skipping"
fi

section "Recently Modified systemd Unit Files (last 30 days)"
find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -mtime -30 2>/dev/null | while read -r f; do
    echo "  $f  ($(stat -c '%y' "$f" 2>/dev/null | cut -d'.' -f1))"
done

# ---------- SSH ----------

section "SSH Authorized Keys"
for keyfile in "$HOME/.ssh/authorized_keys" /root/.ssh/authorized_keys; do
    if [[ -f "$keyfile" ]]; then
        echo "  $keyfile:"
        awk '{ if (length($0) > 60) print "    " substr($0,1,60)"...[truncated]"; else print "    "$0 }' "$keyfile" 2>/dev/null
    fi
done
warn "Verify every key above is one you personally added"

section "SSH Config Check"
if [[ -f /etc/ssh/sshd_config ]]; then
    grep -E '^(PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config 2>/dev/null | sed 's/^/  /'
fi

# ---------- login history ----------

section "Recent Logins"
last -a 2>/dev/null | head -n 15

section "Failed Login Attempts"
if have journalctl; then
    journalctl -u sshd --since "-7 days" 2>/dev/null | grep -i "failed\|invalid" | tail -n 20
elif [[ -f /var/log/auth.log ]]; then
    grep -i "failed\|invalid" /var/log/auth.log 2>/dev/null | tail -n 20
else
    warn "No accessible auth log found"
fi

# ---------- users ----------

section "User Accounts (UID 0 or 1000+)"
awk -F: '($3==0 || $3>=1000) && $3!=65534 {print "  "$1" (UID "$3", shell: "$7")"}' /etc/passwd

section "Accounts With Login Shells"
grep -E '/(bash|sh|zsh|fish)$' /etc/passwd | awk -F: '{print "  "$1}'

# ---------- disk / world-writable ----------

section "World-Writable Files in Sensitive Locations"
WW=$(find /etc /usr/bin /usr/sbin /bin /sbin -xdev -type f -perm -0002 2>/dev/null | head -n 20)
if [[ -n "$WW" ]]; then
    echo "$WW" | sed 's/^/  /'
    flag "World-writable files found in system binary/config directories"
else
    ok "No world-writable files found in checked locations"
fi

# ---------- summary ----------

section "Summary"
if [[ $FLAG_COUNT -eq 0 ]]; then
    echo "  ${GREEN}No automatic red flags raised.${NC} Still worth skimming the sections above by eye."
else
    echo "  ${RED}${FLAG_COUNT} item(s) flagged for review — search this output for [SUSPICIOUS].${NC}"
fi

if ! $NO_LOG; then
    echo
    echo "Full report saved to: ${BOLD}$LOGFILE${NC}"
fi

echo
echo "For deeper scanning, consider running: rkhunter --check | chkrootkit | clamscan -r / | lynis audit system"
