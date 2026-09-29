"""
TunnelTwin Phase 0 Lab Matrix Runner.
Executes the four testbed profiles across isolated network namespaces
and verifies bidirectional ESTABLISHED states.
"""

import subprocess
import sys
from pathlib import Path


def run_phase0_matrix() -> bool:
    script_path = Path(__file__).parent / "run_matrix.sh"
    cmd = ["bash", str(script_path)]
    print(f"[TunnelTwin] Executing matrix runner: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False)  # noqa: S603
    return result.returncode == 0


if __name__ == "__main__":
    success = run_phase0_matrix()
    sys.exit(0 if success else 1)
