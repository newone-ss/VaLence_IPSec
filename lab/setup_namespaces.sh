#!/usr/bin/env bash
# ==============================================================================
# TunnelTwin Lab Substrate — Network Namespace Setup Script
# Creates two isolated Linux network namespaces (ns-left & ns-right)
# joined by a veth pair with dedicated /30 point-to-point addressing.
# ==============================================================================

set -euo pipefail

NS_LEFT="ns-left"
NS_RIGHT="ns-right"
VETH_LEFT="veth-left"
VETH_RIGHT="veth-right"
IP_LEFT="10.0.1.1/30"
IP_RIGHT="10.0.1.2/30"

echo "[TunnelTwin Lab] Configuring Linux network namespaces..."

# 1. Clean up any existing namespaces with identical names
ip netns del "${NS_LEFT}" 2>/dev/null || true
ip netns del "${NS_RIGHT}" 2>/dev/null || true

# 2. Create the two namespaces
ip netns add "${NS_LEFT}"
ip netns add "${NS_RIGHT}"

# 3. Create veth peer pair
ip link add "${VETH_LEFT}" type veth peer name "${VETH_RIGHT}"

# 4. Move veth endpoints into respective namespaces
ip link set "${VETH_LEFT}" netns "${NS_LEFT}"
ip link set "${VETH_RIGHT}" netns "${NS_RIGHT}"

# 5. Bring up loopback interfaces
ip netns exec "${NS_LEFT}" ip link set dev lo up
ip netns exec "${NS_RIGHT}" ip link set dev lo up

# 6. Assign point-to-point IPs and bring up veth interfaces
ip netns exec "${NS_LEFT}" ip addr add "${IP_LEFT}" dev "${VETH_LEFT}"
ip netns exec "${NS_LEFT}" ip link set dev "${VETH_LEFT}" up

ip netns exec "${NS_RIGHT}" ip addr add "${IP_RIGHT}" dev "${VETH_RIGHT}"
ip netns exec "${NS_RIGHT}" ip link set dev "${VETH_RIGHT}" up

# 7. Enable IP forwarding and disable rp_filter for IPsec routing
for ns in "${NS_LEFT}" "${NS_RIGHT}"; do
    ip netns exec "${ns}" sysctl -q -w net.ipv4.ip_forward=1 || true
    ip netns exec "${ns}" sysctl -q -w net.ipv4.conf.all.rp_filter=0 || true
    ip netns exec "${ns}" sysctl -q -w net.ipv4.conf.default.rp_filter=0 || true
done

# 8. Verify L3 connectivity across veth link
echo "[TunnelTwin Lab] Testing ICMP ping between ${NS_LEFT} (10.0.1.1) and ${NS_RIGHT} (10.0.1.2)..."
if ip netns exec "${NS_LEFT}" ping -c 2 -W 1 10.0.1.2 >/dev/null 2>&1; then
    echo "[TunnelTwin Lab] SUCCESS: Point-to-point veth link established and verified."
else
    echo "[TunnelTwin Lab] ERROR: ICMP ping failed between namespaces!" >&2
    exit 1
fi
