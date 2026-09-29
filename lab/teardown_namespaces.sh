#!/usr/bin/env bash
# ==============================================================================
# TunnelTwin Lab Substrate — Teardown Script
# Safely halts charon daemons, cleans up network namespaces and temporary sockets.
# ==============================================================================

set -euo pipefail

NS_LEFT="ns-left"
NS_RIGHT="ns-right"
RUN_DIR="/tmp/tunneltwin"

echo "[TunnelTwin Lab] Halting charon instances and tearing down namespaces..."

# Kill charon processes
if [ -f "${RUN_DIR}/ns-left/charon.pid" ]; then
    kill -9 "$(cat "${RUN_DIR}/ns-left/charon.pid")" 2>/dev/null || true
fi

if [ -f "${RUN_DIR}/ns-right/charon.pid" ]; then
    kill -9 "$(cat "${RUN_DIR}/ns-right/charon.pid")" 2>/dev/null || true
fi

# Fallback kill of any charon matching tunneltwin path
pkill -f "tunneltwin" 2>/dev/null || true

# Flush XFRM states and policies before deleting namespaces
ip netns exec "${NS_LEFT}" ip xfrm state flush 2>/dev/null || true
ip netns exec "${NS_LEFT}" ip xfrm policy flush 2>/dev/null || true
ip netns exec "${NS_RIGHT}" ip xfrm state flush 2>/dev/null || true
ip netns exec "${NS_RIGHT}" ip xfrm policy flush 2>/dev/null || true

# Delete network namespaces
ip netns del "${NS_LEFT}" 2>/dev/null || true
ip netns del "${NS_RIGHT}" 2>/dev/null || true

# Remove runtime sockets and configs
rm -rf "${RUN_DIR}"

echo "[TunnelTwin Lab] Teardown complete. All namespaces and sockets destroyed."
