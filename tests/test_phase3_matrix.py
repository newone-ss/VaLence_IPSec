"""
Phase 3 Integration Test: Live Twin Check & Remediation Proof.

Executes the real end-to-end Phase 3 exit chain against the Phase-0 netns
testbed (no mocked data):

  weak baseline finding reproduces -> aes256gcm-baseline config generated and
  applied -> tunnel establishes -> re-scan confirms the finding cleared.
"""

import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("swanctl") is None, reason="swanctl required for lab testbed")
def test_phase3_twin_check_clears_weak_findings():
    """
    Runs the Phase 3 live twin proof inside the Linux network namespace testbed
    and asserts the complete remediation chain succeeds on real output.
    """
    script_path = Path(__file__).parent.parent / "lab" / "run_phase3_twin.py"
    assert script_path.exists(), f"Phase 3 twin runner script missing: {script_path}"

    proc = subprocess.run(["python3", str(script_path)], capture_output=True, text=True)
    print(proc.stdout)
    if proc.stderr:
        print(proc.stderr)

    assert proc.returncode == 0, (
        f"Phase 3 live twin proof failed with exit code {proc.returncode}:\n{proc.stdout}\n{proc.stderr}"
    )
    assert "PHASE 3 EXIT CRITERIA MET" in proc.stdout
