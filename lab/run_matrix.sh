#!/usr/bin/env bash
# ==============================================================================
# TunnelTwin Lab Substrate — Test Matrix Runner (Phase 0 Exit Criteria)
# Verifies all 4 cryptographic profiles establish IPsec tunnels across namespaces:
#   1. weak       (IKEv1, 3DES-SHA1, MODP_1024)
#   2. mixed      (Prefers AES256/ECP384, accepts MODP_1024)
#   3. strong     (IKEv2, AES256-GCM, SHA384, ECP384 only)
#   4. legacy-cbc (IKEv2, AES128-CBC+SHA1, MODP_2048)
#
# Emits full terminal logs as proof of bidirectional ESTABLISHED states.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "${SCRIPT_DIR}")"
CONFIG_DIR="${SCRIPT_DIR}/configs"
SOCKET_LEFT="unix:///tmp/tunneltwin/ns-left/charon.vici"
SOCKET_RIGHT="unix:///tmp/tunneltwin/ns-right/charon.vici"

# Color constants for rich terminal feedback
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BOLD}${CYAN}======================================================================${NC}"
echo -e "${BOLD}${CYAN}      TunnelTwin Phase 0: Testbed Matrix Automated Verification        ${NC}"
echo -e "${BOLD}${CYAN}======================================================================${NC}"

# 1. Initialize network namespaces and veth link
echo -e "\n${YELLOW}[Step 1/3] Initializing network namespaces...${NC}"
"${SCRIPT_DIR}/setup_namespaces.sh"

# 2. Start isolated charon daemons
echo -e "\n${YELLOW}[Step 2/3] Launching isolated charon instances...${NC}"
"${SCRIPT_DIR}/start_charon.sh" ns-left
"${SCRIPT_DIR}/start_charon.sh" ns-right

PROFILES=("weak" "mixed" "strong" "legacy-cbc")
CHILD_NAMES=("weak-child" "mixed-child" "strong-child" "legacy-child")
CONN_NAMES=("weak-conn" "mixed-conn" "strong-conn" "legacy-cbc-conn")

TOTAL=${#PROFILES[@]}
PASSED=0
FAILED=0

echo -e "\n${YELLOW}[Step 3/3] Executing Profile Verification Matrix...${NC}"

for i in "${!PROFILES[@]}"; do
    PROFILE="${PROFILES[$i]}"
    CHILD="${CHILD_NAMES[$i]}"
    CONN="${CONN_NAMES[$i]}"
    
    echo -e "\n${BOLD}${CYAN}----------------------------------------------------------------------${NC}"
    echo -e "${BOLD}Testing Profile [$(($i+1))/${TOTAL}]: ${YELLOW}${PROFILE}${NC}"
    echo -e "${BOLD}${CYAN}----------------------------------------------------------------------${NC}"

    LEFT_CONF="${CONFIG_DIR}/${PROFILE}/left.conf"
    RIGHT_CONF="${CONFIG_DIR}/${PROFILE}/right.conf"

    # Flush any previous states
    ip netns exec ns-left ip xfrm state flush 2>/dev/null || true
    ip netns exec ns-right ip xfrm state flush 2>/dev/null || true

    # Load configurations into both peers
    echo -e "Loading ${PROFILE} config into ${CYAN}ns-right (responder)${NC}..."
    swanctl --load-all --file "${RIGHT_CONF}" --uri "${SOCKET_RIGHT}"

    echo -e "Loading ${PROFILE} config into ${CYAN}ns-left (initiator)${NC}..."
    swanctl --load-all --file "${LEFT_CONF}" --uri "${SOCKET_LEFT}"

    # Initiate tunnel from ns-left
    echo -e "Initiating connection '${CONN}' (child '${CHILD}') from ${CYAN}ns-left${NC}..."
    if ! swanctl --initiate --child "${CHILD}" --uri "${SOCKET_LEFT}"; then
        # Fallback to initiating IKE SA if child initiation syntax differs
        swanctl --initiate --ike "${CONN}" --uri "${SOCKET_LEFT}"
    fi

    # Wait for SA to settle
    sleep 1

    # Capture and display SA status on both sides
    echo -e "\n${BOLD}=== ns-left swanctl --list-sas output ===${NC}"
    LEFT_SAS=$(swanctl --list-sas --uri "${SOCKET_LEFT}")
    echo "${LEFT_SAS}"

    echo -e "\n${BOLD}=== ns-right swanctl --list-sas output ===${NC}"
    RIGHT_SAS=$(swanctl --list-sas --uri "${SOCKET_RIGHT}")
    echo "${RIGHT_SAS}"

    # Verify ESTABLISHED state on both sides
    LEFT_OK=false
    RIGHT_OK=false

    if echo "${LEFT_SAS}" | grep -q "ESTABLISHED"; then
        LEFT_OK=true
    fi

    if echo "${RIGHT_SAS}" | grep -q "ESTABLISHED"; then
        RIGHT_OK=true
    fi

    if [ "${LEFT_OK}" = true ] && [ "${RIGHT_OK}" = true ]; then
        echo -e "\n${GREEN}${BOLD}✓ PROFILE '${PROFILE}' PASSED (ESTABLISHED on both ns-left & ns-right)${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "\n${RED}${BOLD}✗ PROFILE '${PROFILE}' FAILED (Left: ${LEFT_OK}, Right: ${RIGHT_OK})${NC}"
        FAILED=$((FAILED + 1))
    fi

    # Terminate connection before next profile
    echo -e "Terminating connection '${CONN}'..."
    swanctl --terminate --ike "${CONN}" --uri "${SOCKET_LEFT}" 2>/dev/null || true
    sleep 1
done

# Final Summary Report
echo -e "\n${BOLD}${CYAN}======================================================================${NC}"
echo -e "${BOLD}${CYAN}                     PHASE 0 MATRIX SUMMARY REPORT                    ${NC}"
echo -e "${BOLD}${CYAN}======================================================================${NC}"
echo -e "Total Profiles Tested : ${TOTAL}"
echo -e "Passed                : ${GREEN}${PASSED}${NC}"
echo -e "Failed                : ${RED}${FAILED}${NC}"

if [ "${PASSED}" -eq "${TOTAL}" ]; then
    echo -e "\n${GREEN}${BOLD}======================================================================${NC}"
    echo -e "${GREEN}${BOLD}   PHASE 0 EXIT CRITERIA MET: 4/4 PROFILES VERIFIED ESTABLISHED!     ${NC}"
    echo -e "${GREEN}${BOLD}======================================================================${NC}"
    exit 0
else
    echo -e "\n${RED}${BOLD}======================================================================${NC}"
    echo -e "${RED}${BOLD}   PHASE 0 EXIT CRITERIA FAILED: NOT ALL PROFILES ESTABLISHED        ${NC}"
    echo -e "${RED}${BOLD}======================================================================${NC}"
    exit 1
fi
