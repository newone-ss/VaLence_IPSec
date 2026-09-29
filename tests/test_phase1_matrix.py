"""
Phase 1 Integration Test: Live Gateway Scan Verification.
Verifies active probing and elimination scan against all 5 testbed gateways:
  - 4 Phase-0 profiles (weak, mixed, strong, legacy-cbc)
  - 1 Cookie challenge profile (cookie)
"""

import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("swanctl") is None, reason="swanctl required for lab testbed")
def test_phase1_all_gateways_scanned():
    """
    Executes the Phase 1 live scan script inside the Linux network namespace testbed
    and asserts that all five gateways are correctly profiled with IKE version,
    accepted/rejected proposals, DH groups, and cookie challenge handling.
    """
    script_path = Path(__file__).parent.parent / "lab" / "run_phase1_scan.py"
    assert script_path.exists(), f"Phase 1 scan runner script missing: {script_path}"

    proc = subprocess.run(["python3", str(script_path)], capture_output=True, text=True)
    print(proc.stdout)
    if proc.stderr:
        print(proc.stderr)

    assert proc.returncode == 0, (
        f"Phase 1 live scan failed with exit code {proc.returncode}:\n{proc.stdout}\n{proc.stderr}"
    )
    assert "PHASE 1 EXIT CRITERIA MET: ALL 5 GATEWAYS VERIFIED ESTABLISHED AND REPORTED!" in proc.stdout
