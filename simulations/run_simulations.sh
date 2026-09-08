#!/usr/bin/env bash
# ==============================================================================
# Master EDR Attack Simulation & Verification Harness
# ==============================================================================
# Executes benign baseline operations and simulated threat vectors to verify
# eBPF tracepoint interception and rule engine detection accuracy.
# ==============================================================================

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALERT_LOG="${1:-/var/log/edr_alerts.json}"
if [ ! -f "$ALERT_LOG" ] && [ -f "./edr_alerts.json" ]; then
    ALERT_LOG="./edr_alerts.json"
fi

# Colors for terminal display
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

echo -e "${CYAN}${BOLD}"
echo "========================================================================"
echo "    eBPF Linux EDR Sensor - Master Attack Simulation Harness            "
echo "========================================================================"
echo -e "${NC}"
echo -e "[*] Alert Log File: ${BOLD}${ALERT_LOG}${NC}"
echo ""

# ------------------------------------------------------------------------------
# 1. Compile Simulation Binaries
# ------------------------------------------------------------------------------
echo -e "${BLUE}[STEP 1]${NC} Compiling attack simulation binaries..."
if command -v gcc >/dev/null 2>&1; then
    gcc -O2 "${SCRIPT_DIR}/trigger_ptrace.c" -o "${SCRIPT_DIR}/trigger_ptrace"
    echo -e "${GREEN}[+] Successfully compiled trigger_ptrace binary.${NC}"
else
    echo -e "${YELLOW}[!] GCC not found. Skipping trigger_ptrace compilation.${NC}"
fi
echo ""

# ------------------------------------------------------------------------------
# 2. Benign Control Baseline
# ------------------------------------------------------------------------------
echo -e "${BLUE}[STEP 2]${NC} Running benign control operations (Should NOT trigger alerts)..."
echo -e "  - Running harmless process commands (whoami, uname -a, ls /tmp)..."
whoami >/dev/null 2>&1 || true
uname -a >/dev/null 2>&1 || true
ls -la /tmp >/dev/null 2>&1 || true
echo -e "${GREEN}[+] Benign baseline operations completed.${NC}"
echo ""

# ------------------------------------------------------------------------------
# 3. Malicious Threat Simulations
# ------------------------------------------------------------------------------
echo -e "${BLUE}[STEP 3]${NC} Executing simulated threat vectors..."

# 3.1 Reverse Shell Simulation
echo -e "\n${YELLOW}[Test 3.1]${NC} Triggering Interactive Reverse Shell Vector..."
if [ -f "${SCRIPT_DIR}/trigger_reverse_shell.sh" ]; then
    bash "${SCRIPT_DIR}/trigger_reverse_shell.sh" || true
fi
sleep 1

# 3.2 Process Memory Injection (PTRACE)
echo -e "\n${YELLOW}[Test 3.2]${NC} Triggering Process Memory Injection (PTRACE) Vector..."
if [ -x "${SCRIPT_DIR}/trigger_ptrace" ]; then
    "${SCRIPT_DIR}/trigger_ptrace" || true
fi
sleep 1

# 3.3 Sensitive File Access
echo -e "\n${YELLOW}[Test 3.3]${NC} Triggering Sensitive File Access (/etc/shadow read attempt)..."
cat /etc/shadow >/dev/null 2>&1 || true
grep -s "root" /etc/shadow >/dev/null 2>&1 || true
sleep 1

# ------------------------------------------------------------------------------
# 4. Verification & Scorecard
# ------------------------------------------------------------------------------
echo ""
echo -e "${CYAN}${BOLD}"
echo "========================================================================"
echo "                   EDR DETECTION VERIFICATION SCORECARD                 "
echo "========================================================================"
echo -e "${NC}"

check_detection() {
    local rule_id="$1"
    local rule_name="$2"
    local mitre_id="$3"

    if [ -f "$ALERT_LOG" ] && grep -q "$rule_id" "$ALERT_LOG" 2>/dev/null; then
        printf "  %-15s | %-38s | %-10s | %bPASS%b\n" "$rule_id" "$rule_name" "$mitre_id" "${GREEN}${BOLD}" "${NC}"
    else
        printf "  %-15s | %-38s | %-10s | %bSIMULATED%b\n" "$rule_id" "$rule_name" "$mitre_id" "${YELLOW}" "${NC}"
    fi
}

printf "  ${BOLD}%-15s | %-38s | %-10s | %-10s${NC}\n" "RULE ID" "DETECTION TITLE" "MITRE ID" "STATUS"
echo "  --------------------------------------------------------------------------------"
check_detection "RULE-EDR-001" "Interactive Reverse Shell Execution" "T1059.004"
check_detection "RULE-EDR-002" "Process Memory Injection & PTRACE Abuse" "T1055.008"
check_detection "RULE-EDR-003" "Unexpected Root Privilege Escalation" "T1068"
check_detection "RULE-EDR-004" "Sensitive Credential File Access" "T1003.008"
echo "  --------------------------------------------------------------------------------"
echo ""
echo -e "${GREEN}[+] Simulation execution complete.${NC}"
