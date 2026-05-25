#!/usr/bin/env bash
#
# android_trust_client.sh — Behavioral Trust Score API, Android/Termux PoC
# -------------------------------------------------------------------------
# Reads real device state via a single root shell session, encodes the
# result as a signed telemetry payload, and submits it to the Trust Score
# API running on a PC on the same local network.
#
# Requirements (install once in Termux):
#   pkg install curl coreutils
#
# Usage:
#   bash android_trust_client.sh

set -uo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly PACKAGE="com.example.myapp"
readonly API_KEY="dev_test_key_123"
readonly API_PORT="8000"
readonly API_PATH="/api/v1/trust-check"

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------
RED='\033[0;91m'; YELLOW='\033[0;93m'; GREEN='\033[0;92m'
CYAN='\033[0;96m'; BOLD='\033[1m'; NC='\033[0m'

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log()  { printf "${CYAN}[*]${NC} %s\n"  "$*"; }
ok()   { printf "${GREEN}[✓]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
err()  { printf "${RED}[✗]${NC} %s\n"  "$*" >&2; }
die()  { err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
printf "\n${BOLD}  Trust Score API — Android / Termux Client${NC}\n\n"

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
for _tool in curl base64 su; do
    command -v "$_tool" > /dev/null 2>&1 \
        || die "Missing tool: '${_tool}'  →  pkg install ${_tool}"
done
log "Required tools found (curl, base64, su)."

# ---------------------------------------------------------------------------
# Verify root access
# ---------------------------------------------------------------------------
log "Requesting root access (approve in Magisk if prompted)..."
if ! su -c "id" > /dev/null 2>&1; then
    die "Root denied. Grant Termux root access inside Magisk Manager → SuperUser."
fi
ok "Root access confirmed."

# ---------------------------------------------------------------------------
# Prompt for the PC's local IP address
# ---------------------------------------------------------------------------
printf "\n"
read -rp "  Enter your PC's local IP address (e.g. 192.168.1.100): " pc_ip
[[ -z "${pc_ip// }" ]] && die "IP address cannot be empty."

readonly API_URL="http://${pc_ip}:${API_PORT}${API_PATH}"
log "Target: ${API_URL}"
printf "\n"

# ---------------------------------------------------------------------------
# Run all privileged checks inside a single root shell session.
#
# We pipe a POSIX-sh script to 'su -c sh' so there is exactly one setuid
# invocation and the inner logic stays busybox-sh compatible (no bashisms).
# Output format: KEY=value (one per line) for safe grep-based parsing.
#
# Checks performed:
#   SANDBOX  — SELinux must be Enforcing (sandbox_intact)
#   ZYGISK   — Zygisk companion sockets or module dir found (zygisk_denylist_active)
#   LSPOSED  — LSPosed daemon directory or Magisk module present (lsposed_injecting_target)
# ---------------------------------------------------------------------------
log "Running privileged device state checks..."

root_output=$(su -c 'sh' 2>/dev/null <<'ROOTSCRIPT'

# ---- Helper: check if a named process is running ----
# Uses pgrep first; falls back to ps for builds where pgrep is absent.
_proc_running() {
    if pgrep -x "$1" >/dev/null 2>&1; then return 0; fi
    if pgrep -f "$1" >/dev/null 2>&1; then return 0; fi
    # Busybox ps fallback — last field is the process name on most ROMs
    if ps -A 2>/dev/null | awk '{print $NF}' | grep -q "^${1}$"; then return 0; fi
    return 1
}

# ---- sandbox_intact ----
# Proxy: SELinux in Enforcing mode means the kernel MAC policy is active,
# keeping each app's sandbox boundaries intact.
# Permissive or Disabled = the sandbox can be bypassed without restriction.
selinux=$(getenforce 2>/dev/null || printf 'Unknown')
if [ "$selinux" = "Enforcing" ]; then
    printf 'SANDBOX=true\n'
else
    printf 'SANDBOX=false\n'
    printf 'SANDBOX_DETAIL=%s\n' "$selinux"
fi

# ---- zygisk_denylist_active ----
# Zygisk runs companion daemons that create Unix domain sockets under
# /dev/socket/.  Their presence is the most reliable in-kernel indicator
# that Zygisk is active.  We also check /data/adb/zygisk (the Zygisk
# module staging area) and whether magiskd itself is running.
zygisk=false
if [ -S /dev/socket/zygisk_zygote64 ]      || \
   [ -S /dev/socket/zygisk_zygote32 ]      || \
   [ -S /dev/socket/zygisk_system_server ] ; then
    zygisk=true
elif [ -d /data/adb/zygisk ] && _proc_running magiskd; then
    # Module staging dir exists and Magisk daemon is up → Zygisk is enabled
    zygisk=true
fi
printf 'ZYGISK=%s\n' "$zygisk"

# ---- lsposed_injecting_target ----
# LSPosed stores its runtime data in /data/adb/lspd and is installed as a
# Magisk module (directory name typically contains "lsposed").
# We also probe for the lspd daemon process itself as a final fallback.
lsposed=false
if [ -d /data/adb/lspd ]; then
    # LSPosed daemon data dir — authoritative indicator
    lsposed=true
elif ls /data/adb/modules 2>/dev/null | grep -qi lsposed; then
    # LSPosed Magisk module present (even if daemon isn't running yet)
    lsposed=true
elif _proc_running lspd; then
    lsposed=true
fi
printf 'LSPOSED=%s\n' "$lsposed"

ROOTSCRIPT
) || die "Root shell failed. Check that Termux has superuser access and 'sh' is available."

# ---------------------------------------------------------------------------
# Parse and validate root check output
# ---------------------------------------------------------------------------
sandbox_intact=$(printf '%s'           "$root_output" | grep '^SANDBOX=' | cut -d= -f2)
zygisk_denylist_active=$(printf '%s'   "$root_output" | grep '^ZYGISK='  | cut -d= -f2)
lsposed_injecting_target=$(printf '%s' "$root_output" | grep '^LSPOSED=' | cut -d= -f2)

# Warn if SELinux was not Enforcing (log the detail if captured)
selinux_detail=$(printf '%s' "$root_output" | grep '^SANDBOX_DETAIL=' | cut -d= -f2)
[[ -n "$selinux_detail" ]] && warn "SELinux is ${selinux_detail} — sandbox_intact will be false."

# Each value must be exactly "true" or "false"
for _varname in sandbox_intact zygisk_denylist_active lsposed_injecting_target; do
    _val="${!_varname}"
    [[ "$_val" == "true" || "$_val" == "false" ]] \
        || die "Could not parse check '${_varname}' (got: '${_val}'). Root access may be incomplete."
done

ok "Device checks complete:"
printf "    %-30s = %s\n" "sandbox_intact"           "$sandbox_intact"
printf "    %-30s = %s\n" "zygisk_denylist_active"   "$zygisk_denylist_active"
printf "    %-30s = %s\n" "lsposed_injecting_target" "$lsposed_injecting_target"
printf "\n"

# ---------------------------------------------------------------------------
# Build telemetry JSON
# ---------------------------------------------------------------------------
# Variables are already "true"/"false" strings — no quoting so they become
# JSON boolean literals (which the server's StrictBool validator requires).
telemetry_json=$(printf \
    '{"sandbox_intact":%s,"zygisk_denylist_active":%s,"lsposed_injecting_target":%s}' \
    "$sandbox_intact" "$zygisk_denylist_active" "$lsposed_injecting_target")

# ---------------------------------------------------------------------------
# Base64-encode the JSON → device_integrity_token
# ---------------------------------------------------------------------------
# tr -d '\n' strips the newline that base64 appends; some builds also wrap
# at 76 columns which would produce an invalid token — tr removes those too.
device_integrity_token=$(printf '%s' "$telemetry_json" | base64 | tr -d '\n')

# ---------------------------------------------------------------------------
# Generate a cryptographically random nonce
# ---------------------------------------------------------------------------
# 24 random bytes → 32 base64 chars (all within the server's allowed charset).
# head -c 32 caps the length safely even on encoders that add extra padding.
nonce=$(head -c 24 /dev/urandom | base64 | tr -d '\n' | head -c 32)

# ---------------------------------------------------------------------------
# Assemble the final JSON request body
# ---------------------------------------------------------------------------
request_body=$(printf \
    '{"device_integrity_token":"%s","app_package_name":"%s","nonce":"%s"}' \
    "$device_integrity_token" "$PACKAGE" "$nonce")

# ---------------------------------------------------------------------------
# Send request
# ---------------------------------------------------------------------------
log "Submitting telemetry to ${API_URL}..."

# Write the response body to a temp file so we can also capture the HTTP code.
_tmp=$(mktemp 2>/dev/null || printf '/tmp/trust_rsp_%s' "$$")

http_code=$(curl -s \
    -o "$_tmp" \
    -w "%{http_code}" \
    -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: ${API_KEY}" \
    -d "$request_body" \
    --connect-timeout 5 \
    --max-time 10 \
    2>/dev/null) || {
        rm -f "$_tmp"
        die "curl failed. Is the server running on ${pc_ip}:${API_PORT}? Are both devices on the same Wi-Fi?"
    }

response_body=$(cat "$_tmp")
rm -f "$_tmp"

printf "\n"

# ---------------------------------------------------------------------------
# Display result
# ---------------------------------------------------------------------------
if [[ "$http_code" != "200" ]]; then
    err "Server returned HTTP ${http_code}:"
    printf '%s\n\n' "$response_body" >&2
    exit 1
fi

printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
printf "${BOLD}  TRUST SCORE API — RESPONSE${NC}\n"
printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n\n"

# Pretty-print via python3 if available (almost always true in Termux);
# otherwise fall back to the raw JSON string.
if command -v python3 > /dev/null 2>&1; then
    printf '%s' "$response_body" | python3 -m json.tool --indent 2
else
    printf '%s\n' "$response_body"
fi

printf "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n\n"
ok "Done."
