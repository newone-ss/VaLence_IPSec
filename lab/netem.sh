#!/usr/bin/env bash
# TunnelTwin Phase 5 capture harness.
# Linux only. Usage:
#   ./netem.sh capture <profile> <condition> <seconds>
#   ./netem.sh clear   <iface>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/lab/captures"

declare -A NETEM=(
  [clean]=""
  [jitter]="delay 20ms 10ms distribution normal"
  [loss]="loss 5%"
  [reorder]="delay 10ms reorder 25% 50%"
  [jitter+loss]="delay 20ms 10ms loss 2%"
)

iface_for_profile() {
  case "$1" in
    weak|mixed|strong|legacy-cbc) echo "veth-left" ;;
    *) echo "unknown profile $1" >&2; exit 2 ;;
  esac
}

cmd_capture() {
  local profile="$1" condition="$2" secs="$3"
  local iface; iface="$(iface_for_profile "${profile}")"
  local spec="${NETEM[${condition}]:-}"
  mkdir -p "${OUT}/${profile}/${condition}"

  local child conn
  case "${profile}" in
    weak) child="weak-child"; conn="weak-conn" ;;
    mixed) child="mixed-child"; conn="mixed-conn" ;;
    strong) child="strong-child"; conn="strong-conn" ;;
    legacy-cbc) child="legacy-child"; conn="legacy-cbc-conn" ;;
  esac

  # Ensure charon is running and tunnel established
  "${ROOT}/lab/start_charon.sh" ns-left >/dev/null 2>&1 || true
  "${ROOT}/lab/start_charon.sh" ns-right >/dev/null 2>&1 || true
  swanctl --load-all --file "${ROOT}/lab/configs/${profile}/right.conf" --uri unix:///tmp/tunneltwin/ns-right/charon.vici >/dev/null 2>&1 || true
  swanctl --load-all --file "${ROOT}/lab/configs/${profile}/left.conf" --uri unix:///tmp/tunneltwin/ns-left/charon.vici >/dev/null 2>&1 || true
  swanctl --initiate --child "${child}" --uri unix:///tmp/tunneltwin/ns-left/charon.vici >/dev/null 2>&1 || \
  swanctl --initiate --ike "${conn}" --uri unix:///tmp/tunneltwin/ns-left/charon.vici >/dev/null 2>&1 || true

  if [[ -n "${spec}" ]]; then
    ip netns exec ns-left tc qdisc del dev "${iface}" root 2>/dev/null || true
    ip netns exec ns-left tc qdisc add dev "${iface}" root netem ${spec}
  fi

  ip netns exec ns-left tcpdump -i "${iface}" -w "${OUT}/${profile}/${condition}/cap.pcap" \
          -s 0 -U 'ip proto \esp or udp port 500 or udp port 4500' >/dev/null 2>&1 &
  local tcpd=$!

  # Generate traffic through tunnel under impairment
  for ((s=0; s<secs; s++)); do
    ip netns exec ns-left ping -c 3 -i 0.1 -W 1 10.0.1.2 >/dev/null 2>&1 || true
    sleep 0.5
  done

  kill "${tcpd}" 2>/dev/null || true
  wait "${tcpd}" 2>/dev/null || true

  [[ -n "${spec}" ]] && ip netns exec ns-left tc qdisc del dev "${iface}" root 2>/dev/null || true

  swanctl --terminate --ike "${conn}" --uri unix:///tmp/tunneltwin/ns-left/charon.vici >/dev/null 2>&1 || true
  "${ROOT}/lab/stop_charon.sh" ns-left >/dev/null 2>&1 || true
  "${ROOT}/lab/stop_charon.sh" ns-right >/dev/null 2>&1 || true
  ip netns exec ns-left ip xfrm state flush 2>/dev/null || true
  ip netns exec ns-right ip xfrm state flush 2>/dev/null || true

  echo "wrote ${OUT}/${profile}/${condition}/cap.pcap"
}

cmd_clear() {
  ip netns exec ns-left tc qdisc del dev "$1" root 2>/dev/null || true
}

case "${1:-}" in
  capture) shift; cmd_capture "$@" ;;
  clear)   shift; cmd_clear   "$@" ;;
  *) echo "usage: $0 {capture|clear} ..." >&2; exit 2 ;;
esac