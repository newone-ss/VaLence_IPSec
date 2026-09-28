#!/usr/bin/env bash
# ==============================================================================
# TunnelTwin Lab Substrate — Start Libreswan (Pluto) Daemon per Namespace
# Spawns an isolated Libreswan pluto instance inside the specified netns
# with a dedicated NSS database, rundir, and whack control socket.
# ==============================================================================

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <namespace (e.g. ns-libreswan or ns-right)>" >&2
    exit 1
fi

NS="$1"
RUN_DIR="/tmp/tunneltwin/${NS}"
NSS_DIR="${RUN_DIR}/nss"
PLUTO_RUNDIR="${RUN_DIR}/run"
DUMP_DIR="${RUN_DIR}/dump"
SECRETS_FILE="${RUN_DIR}/ipsec.secrets"
CONFIG_FILE="${RUN_DIR}/ipsec.conf"

mkdir -p "${NSS_DIR}" "${PLUTO_RUNDIR}" "${DUMP_DIR}"

# 1. Initialize NSS database if not present
if [ ! -f "${NSS_DIR}/cert9.db" ]; then
    certutil -N -d "sql:${NSS_DIR}" --empty-password -f /dev/null < /dev/null
fi

# 2. Stop any existing pluto process in this namespace
if [ -f "${PLUTO_RUNDIR}/pluto.pid" ]; then
    OLD_PID=$(cat "${PLUTO_RUNDIR}/pluto.pid" 2>/dev/null || true)
    if [ -n "${OLD_PID}" ]; then
        kill -9 "${OLD_PID}" 2>/dev/null || true
    fi
    rm -f "${PLUTO_RUNDIR}/pluto.pid"
fi
rm -f "${PLUTO_RUNDIR}/pluto.ctl"

# 3. Ensure base ipsec.secrets exists if not provided
if [ ! -f "${SECRETS_FILE}" ]; then
    cat << EOF > "${SECRETS_FILE}"
10.0.1.1 10.0.1.2 : PSK "TunnelTwinSuperSecretKeyPhase42026!"
EOF
fi

# 4. Ensure base ipsec.conf exists if not provided
if [ ! -f "${CONFIG_FILE}" ]; then
    cat << EOF > "${CONFIG_FILE}"
config setup
    logfile=${RUN_DIR}/pluto.log
    secretsfile=${SECRETS_FILE}
EOF
fi

# 5. Path resolution for pluto binary
PLUTO_BIN="/opt/libreswan/usr/libexec/ipsec/pluto"
if [ ! -x "${PLUTO_BIN}" ]; then
    PLUTO_BIN="/usr/libexec/ipsec/pluto"
fi
if [ ! -x "${PLUTO_BIN}" ]; then
    PLUTO_BIN=$(command -v pluto || true)
fi

if [ -z "${PLUTO_BIN}" ] || [ ! -x "${PLUTO_BIN}" ]; then
    echo "Error: Libreswan pluto binary not found." >&2
    exit 1
fi

# 6. Launch pluto inside the network namespace
ip netns exec "${NS}" "${PLUTO_BIN}" \
    --config "${CONFIG_FILE}" \
    --rundir "${PLUTO_RUNDIR}" \
    --nssdir "sql:${NSS_DIR}" \
    --secretsfile "${SECRETS_FILE}" \
    --logfile "${RUN_DIR}/pluto.log" \
    --dumpdir "${DUMP_DIR}" \
    --no-dnssec >"${RUN_DIR}/pluto_boot.log" 2>&1 &

# 7. Wait for whack control socket to appear
TIMEOUT=50
while [ ! -S "${PLUTO_RUNDIR}/pluto.ctl" ]; do
    sleep 0.1
    TIMEOUT=$((TIMEOUT - 1))
    if [ "${TIMEOUT}" -le 0 ]; then
        echo "Error: pluto did not initialize whack socket in ${PLUTO_RUNDIR}" >&2
        if [ -f "${RUN_DIR}/pluto_boot.log" ]; then
            echo "--- Pluto Boot Log ---" >&2
            cat "${RUN_DIR}/pluto_boot.log" >&2
        fi
        if [ -f "${RUN_DIR}/pluto.log" ]; then
            echo "--- Pluto Log ---" >&2
            cat "${RUN_DIR}/pluto.log" >&2
        fi
        exit 1
    fi
done

PID=$(cat "${PLUTO_RUNDIR}/pluto.pid" 2>/dev/null || echo "active")
echo "Libreswan pluto daemon successfully active in namespace '${NS}' (PID: ${PID}, Socket: ${PLUTO_RUNDIR}/pluto.ctl)"
