#!/usr/bin/env bash
# ==============================================================================
# TunnelTwin Lab Substrate — Phase 3 Live Twin Check & Remediation Proof Runner
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Must be run as root (e.g. sudo bash lab/run_phase3_twin.sh)" >&2
    exit 1
fi

python3 "${SCRIPT_DIR}/run_phase3_twin.py" "$@"