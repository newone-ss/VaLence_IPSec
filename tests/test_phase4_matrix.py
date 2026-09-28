"""
Phase 4 Integration Test: Multi-Daemon Diversity & Behavioral Fingerprinting Proof.

Executes the real end-to-end Phase 4 exit chain against the Linux netns
testbed running strongSwan and Libreswan concurrently (no mocked data):

  1. Libreswan running in dedicated namespace.
  2. Behavioral daemon fingerprinting identifies Libreswan via packet quirks.
  3. Weak baseline finding reproduces against Libreswan.
  4. Hardened Libreswan-specific config applied.
  5. Cross-daemon tunnel establishes between strongSwan and Libreswan.
  6. Data-plane ping passes with 0% loss.
  7. Re-scan confirms finding cleared.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

PLUTO_PATHS = (
    Path("/opt/libreswan/usr/libexec/ipsec/pluto"),
    Path("/usr/libexec/ipsec/pluto"),
)
HAS_PLUTO = any(p.exists() for p in PLUTO_PATHS) or shutil.which("pluto") is not None


@pytest.mark.skipif(
    shutil.which("swanctl") is None or not HAS_PLUTO,
    reason="swanctl and Libreswan required for multi-daemon lab testbed",
)
def test_phase4_multi_daemon_diversity_and_fingerprinting():
    """
    Runs the Phase 4 live multi-daemon proof inside the Linux network namespace testbed
    and asserts the complete multi-daemon diversity and fingerprinting chain succeeds.
    """
    script_path = Path(__file__).parent.parent / "lab" / "run_phase4_multi_daemon.py"
    assert script_path.exists(), f"Phase 4 runner script missing: {script_path}"

    proc = subprocess.run(["python3", str(script_path)], capture_output=True, text=True)
    print(proc.stdout)
    if proc.stderr:
        print(proc.stderr)

    assert proc.returncode == 0, (
        f"Phase 4 live multi-daemon proof failed with exit code {proc.returncode}:\n{proc.stdout}\n{proc.stderr}"
    )
    assert "PHASE 4 EXIT CRITERIA MET" in proc.stdout
