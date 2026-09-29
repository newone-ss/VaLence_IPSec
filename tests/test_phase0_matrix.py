"""
Phase 0 Integration Test: Network Namespace IPsec Profile Verification.
Verifies all 4 cryptographic profiles establish bidirectional IPsec SAs.
"""

import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("swanctl") is None, reason="swanctl required for lab testbed")
def test_phase0_all_profiles_establish():
    """
    Executes the lab matrix script inside the Linux network namespace testbed
    and asserts that all four profiles successfully reach ESTABLISHED state.
    """
    script_path = Path(__file__).parent.parent / "lab" / "run_matrix.sh"
    assert script_path.exists(), f"Matrix runner script missing: {script_path}"

    proc = subprocess.run(["bash", str(script_path)], capture_output=True, text=True)
    print(proc.stdout)
    if proc.stderr:
        print(proc.stderr)

    assert proc.returncode == 0, f"Matrix runner failed with exit code {proc.returncode}:\n{proc.stdout}\n{proc.stderr}"
    assert "PHASE 0 EXIT CRITERIA MET: 4/4 PROFILES VERIFIED ESTABLISHED!" in proc.stdout
