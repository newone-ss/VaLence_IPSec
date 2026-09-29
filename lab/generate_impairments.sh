#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Ensure namespaces are up
"${ROOT}/lab/setup_namespaces.sh"

for profile in weak mixed strong legacy-cbc; do
  for cond in clean jitter loss reorder jitter+loss; do
    echo "Capturing netem: ${profile} / ${cond}..."
    bash "${ROOT}/lab/netem.sh" capture "${profile}" "${cond}" 3
  done
done
echo "All netem captures finished."
