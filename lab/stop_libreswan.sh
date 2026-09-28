#!/usr/bin/env bash
# ==============================================================================
# TunnelTwin Lab Substrate — Stop Libreswan (Pluto) Daemon per Namespace
# Safely terminates pluto in the given namespace and cleans runtime files.
# ==============================================================================

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <namespace (e.g. ns-libreswan or ns-right)>" >&2
    exit 1
fi

NS="$1"
RUN_DIR="/tmp/tunneltwin/${NS}"
PLUTO_RUNDIR="${RUN_DIR}/run"

if [ -f "${PLUTO_RUNDIR}/pluto.pid" ]; then
    PID=$(cat "${PLUTO_RUNDIR}/pluto.pid" 2>/dev/null || true)
    if [ -n "${PID}" ]; then
        kill -9 "${PID}" 2>/dev/null || true
    fi
    rm -f "${PLUTO_RUNDIR}/pluto.pid"
fi

rm -f "${PLUTO_RUNDIR}/pluto.ctl"

# Flush XFRM state and policies in the namespace
ip netns exec "${NS}" ip xfrm state flush 2>/dev/null || true
ip netns exec "${NS}" ip xfrm policy flush 2>/dev/null || true

echo "Libreswan pluto stopped for namespace '${NS}'"
