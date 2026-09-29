#!/usr/bin/env bash
# TunnelTwin Phase 5 capture generator.
# Linux only. Generates labelled ESP captures for all four CORE profiles
# under two traffic patterns: bulk (iperf3) and chatty (small packets).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/lab/captures"
SCRIPTS="${ROOT}/lab"

PROFILES=(weak mixed strong legacy-cbc)
CHILD_NAMES=(weak-child mixed-child strong-child legacy-child)
CONN_NAMES=(weak-conn mixed-conn strong-conn legacy-cbc-conn)
PATTERNS=(bulk chatty)

# Ensure namespace lab is up
"${SCRIPTS}/setup_namespaces.sh"

for p_idx in 0 1 2 3; do
  profile="${PROFILES[p_idx]}"
  child="${CHILD_NAMES[p_idx]}"
  conn="${CONN_NAMES[p_idx]}"

  for pattern in "${PATTERNS[@]}"; do
    echo "=== Generating ${profile}/${pattern} ==="

    # Start charon on both sides
    "${SCRIPTS}/start_charon.sh" ns-left
    "${SCRIPTS}/start_charon.sh" ns-right

    LEFT_CONF="${ROOT}/lab/configs/${profile}/left.conf"
    RIGHT_CONF="${ROOT}/lab/configs/${profile}/right.conf"

    swanctl --load-all --file "${RIGHT_CONF}" --uri unix:///tmp/tunneltwin/ns-right/charon.vici
    swanctl --load-all --file "${LEFT_CONF}" --uri unix:///tmp/tunneltwin/ns-left/charon.vici

    # Establish child SA (ESP tunnel)
    swanctl --initiate --child "${child}" --uri unix:///tmp/tunneltwin/ns-left/charon.vici || \
    swanctl --initiate --ike "${conn}" --uri unix:///tmp/tunneltwin/ns-left/charon.vici

    mkdir -p "${OUT}/${profile}/${pattern}"

    for iteration in 1 2 3; do
      echo "  -> Iteration ${iteration}/3"
      CAP_FILE="${OUT}/${profile}/${pattern}/cap_${iteration}_$(date +%s).pcap"

      # Start capture inside ns-left on veth-left
      ip netns exec ns-left tcpdump -i veth-left -w "${CAP_FILE}" -s 0 -U 'ip proto \esp or udp port 500 or udp port 4500' >/dev/null 2>&1 &
      TCPDUMP_PID=$!
      sleep 0.5

      if [[ "${pattern}" == "bulk" ]]; then
        ip netns exec ns-right iperf3 -s -D >/dev/null 2>&1 || true
        sleep 0.5
        ip netns exec ns-left iperf3 -c 10.0.1.2 -t 3 -P 2 >/dev/null 2>&1 || true
        ip netns exec ns-right pkill -9 iperf3 2>/dev/null || true
      else
        for burst in {1..3}; do
          ip netns exec ns-left ping -c 5 -i 0.1 10.0.1.2 >/dev/null 2>&1 || true
          sleep 0.2
        done
      fi

      sleep 0.5
      kill "${TCPDUMP_PID}" 2>/dev/null || true
      wait "${TCPDUMP_PID}" 2>/dev/null || true
      echo "  wrote ${CAP_FILE}"
    done

    # Tear down
    swanctl --terminate --ike "${conn}" --uri unix:///tmp/tunneltwin/ns-left/charon.vici 2>/dev/null || true
    "${SCRIPTS}/stop_charon.sh" ns-left 2>/dev/null || true
    "${SCRIPTS}/stop_charon.sh" ns-right 2>/dev/null || true
    ip netns exec ns-left ip xfrm state flush 2>/dev/null || true
    ip netns exec ns-right ip xfrm state flush 2>/dev/null || true
    ip netns exec ns-left ip xfrm policy flush 2>/dev/null || true
    ip netns exec ns-right ip xfrm policy flush 2>/dev/null || true
  done
done

echo "All captures generated under ${OUT}"