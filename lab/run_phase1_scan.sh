#!/usr/bin/env bash
# ==============================================================================
# TunnelTwin Lab Substrate — Phase 1 Live Namespace Integration Scan Runner
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "${SCRIPT_DIR}")"

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Must be run as root (e.g. sudo bash lab/run_phase1_scan.sh)" >&2
    exit 1
fi

python3 "${SCRIPT_DIR}/run_phase1_scan.py"
