#!/usr/bin/env bash
# TunnelTwin Phase 5 retransmit verification.
# Forces an IKE retransmit by applying 20% loss, captures it, and verifies
# unique_attempt_count returns 1 (not 2+).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/lab/captures/retransmit"
SCRIPTS="${ROOT}/lab"

mkdir -p "${OUT}"

# Use 'strong' profile as baseline
PROFILE="strong"

# Ensure namespace lab is up
"${SCRIPTS}/setup_namespaces.sh"

# Start charon on both sides
"${SCRIPTS}/start_charon.sh" ns-left
"${SCRIPTS}/start_charon.sh" ns-right

LEFT_CONF="${ROOT}/lab/configs/${PROFILE}/left.conf"
RIGHT_CONF="${ROOT}/lab/configs/${PROFILE}/right.conf"

swanctl --load-all --file "${LEFT_CONF}" --uri unix:///tmp/tunneltwin/ns-left/charon.vici
swanctl --load-all --file "${RIGHT_CONF}" --uri unix:///tmp/tunneltwin/ns-right/charon.vici

# Apply 20% loss to force retransmits
ip netns exec ns-left tc qdisc del dev veth-left root 2>/dev/null || true
ip netns exec ns-left tc qdisc add dev veth-left root netem loss 20%

# Start capture BEFORE initiating (to catch the initial packet + retransmits)
CAP_FILE="${OUT}/cap_$(date +%s).pcap"
ip netns exec ns-left tcpdump -i veth-left -w "${CAP_FILE}" -s 0 -U 'udp port 500 or udp port 4500' &
TCPDUMP_PID=$!

# Initiate tunnel (this will trigger retransmits due to loss)
ip netns exec ns-left swanctl --initiate --ike "${PROFILE}-conn" --uri unix:///tmp/tunneltwin/ns-left/charon.vici

# Wait a bit for retransmits to occur
sleep 10

# Stop capture
kill "${TCPDUMP_PID}" 2>/dev/null || true
wait "${TCPDUMP_PID}" 2>/dev/null || true

# Clear netem
ip netns exec ns-left tc qdisc del dev veth-left root 2>/dev/null || true

echo "wrote ${CAP_FILE}"

# Verify unique_attempt_count using Python
python3 -c "
import sys
sys.path.insert(0, '${ROOT}')
from tunneltwin.capture.pcap import iter_ike
from tunneltwin.capture.retransmit import unique_attempt_count

pkts = list(iter_ike('${CAP_FILE}'))
count = unique_attempt_count(pkts)
print(f'unique_attempt_count = {count}')
if count == 1:
    print('PASS: retransmit correctly de-duplicated')
    sys.exit(0)
else:
    print('FAIL: expected 1, got', count)
    sys.exit(1)
"

# Tear down
"${SCRIPTS}/stop_charon.sh" ns-left
"${SCRIPTS}/stop_charon.sh" ns-right