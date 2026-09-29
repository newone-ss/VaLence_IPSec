#!/usr/bin/env bash
# ==============================================================================
# TunnelTwin Lab Substrate — Start Charon Daemon per Namespace
# Spawns an isolated strongSwan charon instance inside the specified netns
# with a dedicated configuration, private tmpfs mount for /var/run,
# and independent VICI socket path.
# ==============================================================================

set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: $0 <namespace (e.g. ns-left or ns-right)> [cookie]" >&2
    exit 1
fi

NS="$1"
COOKIE_MODE="${2:-}"
RUN_DIR="/tmp/tunneltwin/${NS}"
mkdir -p "${RUN_DIR}"

COOKIE_SETTINGS=""
if [ "${COOKIE_MODE}" = "cookie" ]; then
    COOKIE_SETTINGS="    dos_protection = yes
    cookie_threshold = 1
    cookie_threshold_ip = 1"
fi

# 1. Generate isolated strongswan.conf for this specific namespace
cat << EOF > "${RUN_DIR}/strongswan.conf"
charon {
    filelog {
        daemon_log {
            path = ${RUN_DIR}/charon.log
            time_format = %b %e %T
            ike_name = yes
            default = 1
            flush_line = yes
        }
    }
${COOKIE_SETTINGS}
    plugins {
        include /etc/strongswan.d/charon/*.conf
        vici {
            socket = unix://${RUN_DIR}/charon.vici
        }
    }
}
include /etc/strongswan.d/*.conf
EOF

# 2. Stop any existing charon process in this namespace
if [ -f "${RUN_DIR}/charon.pid" ]; then
    OLD_PID=$(cat "${RUN_DIR}/charon.pid")
    kill -9 "${OLD_PID}" 2>/dev/null || true
    rm -f "${RUN_DIR}/charon.pid"
fi
rm -f "${RUN_DIR}/charon.vici"

# 3. Launch charon inside the network namespace with an isolated mount namespace for /var/run
#    This isolates /var/run/charon.pid to prevent collision between multiple netns instances.
#    Redirect stdout and stderr to /dev/null so background charon does not hold open pipes to parent runners.
ip netns exec "${NS}" unshare -m sh -c "mount -t tmpfs tmpfs /var/run && exec env STRONGSWAN_CONF=${RUN_DIR}/strongswan.conf /usr/lib/ipsec/charon" >/dev/null 2>&1 &
PID=$!
echo "${PID}" > "${RUN_DIR}/charon.pid"

# 4. Wait for VICI socket to be created
TIMEOUT=50
while [ ! -S "${RUN_DIR}/charon.vici" ]; do
    sleep 0.1
    TIMEOUT=$((TIMEOUT - 1))
    if [ "${TIMEOUT}" -le 0 ]; then
        echo "Error: charon did not initialize VICI socket in ${RUN_DIR}" >&2
        if [ -f "${RUN_DIR}/charon.log" ]; then
            cat "${RUN_DIR}/charon.log" >&2
        fi
        exit 1
    fi
done

echo "charon daemon successfully active in namespace '${NS}' (PID: ${PID}, Socket: ${RUN_DIR}/charon.vici)"
