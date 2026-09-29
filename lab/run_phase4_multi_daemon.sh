#!/usr/bin/env bash
# ==============================================================================
# TunnelTwin Lab Substrate — Phase 4 Multi-Daemon Diversity Proof Runner
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This runner requires root privileges for network namespace manipulation." >&2
    exit 1
fi

export PYTHONPATH="${PROJECT_ROOT}:${PYTHONPATH:-}"

echo "Executing TunnelTwin Phase 4 Live Proof..."
exec python3 "${SCRIPT_DIR}/run_phase4_multi_daemon.py" "$@"
