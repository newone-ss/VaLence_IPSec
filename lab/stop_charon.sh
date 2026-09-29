#!/usr/bin/env bash
# ==============================================================================
# TunnelTwin Lab Substrate — Stop Charon Daemon per Namespace
# Safely terminates charon in the given namespace and cleans runtime files.
# ==============================================================================

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <namespace (e.g. ns-left or ns-right)>" >&2
    exit 1
fi

NS="$1"
RUN_DIR="/tmp/tunneltwin/${NS}"

if [ -f "${RUN_DIR}/charon.pid" ]; then
    PID=$(cat "${RUN_DIR}/charon.pid")
    kill -9 "${PID}" 2>/dev/null || true
    rm -f "${RUN_DIR}/charon.pid"
fi

rm -f "${RUN_DIR}/charon.vici"
echo "charon stopped for namespace '${NS}'"
