#!/usr/bin/env python3
"""
TunnelTwin Phase 3 — Live Twin Check & Remediation Proof Runner.

Executes the complete Phase 3 exit chain against the real Phase-0 netns
testbed using the real Phase-1 active scanner (no mocked data):

  Stage 1: Load the legacy `weak` profile and confirm the weak findings
           reproduce through a live OBSERVED scan.
  Stage 2: Establish the weak baseline tunnel in the lab (old config works).
  Stage 3: Generate the hardened `aes256gcm-baseline` swanctl pair with
           tunneltwin.fix, apply it, verify the tunnel establishes on both
           peers, and pass a data-plane ping.
  Stage 4: Re-scan the same namespace and confirm the baseline findings
           cleared via TwinVerifier, then re-establish the remediated tunnel.

  NOTE: Scans are performed with the IKE SA terminated and XFRM flushed.
  An established child SA installs policies that encapsulate all traffic
  between the peer IPs (including probes), so the control plane must be in a
  clean state for the active scanner to observe the responder directly — the
  same conditions under which the Phase-1 scan was verified.

Must be executed with root privileges inside Linux / WSL2.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tunneltwin.fix import build_remediation_artifacts
from tunneltwin.fix.twin import TwinVerifier
from tunneltwin.ike.constants import TransformType
from tunneltwin.probe.allowlist import TargetAllowlist
from tunneltwin.probe.result import (
    AcceptedTransform,
    GatewayScanResult,
    IKEv1AcceptedTransform,
    ScanStatus,
)
from tunneltwin.probe.scanner import ScanConfig, scan_gateway

CONFIGS_DIR = PROJECT_ROOT / "lab" / "configs"
PHASE3_DIR = Path("/tmp/tunneltwin/phase3")
SOCKET_LEFT = "unix:///tmp/tunneltwin/ns-left/charon.vici"
SOCKET_RIGHT = "unix:///tmp/tunneltwin/ns-right/charon.vici"

TARGET_IP = "10.0.1.2"
LEFT_IP = "10.0.1.1"
BASELINE_PROFILE = "weak"
BASELINE_CONN = "weak-conn"
BASELINE_CHILD = "weak-child"
REMEDIATION_PROFILE = "aes256gcm-baseline"

# Findings that MUST reproduce on the weak baseline and MUST clear after remediation.
REQUIRED_BASELINE_FINDINGS = ("NIST-001", "NIST-004")


# ═══════════════════════════════════════════════════════════════════════
#  Scan Result Serialization (worker lives inside ns-left)
# ═══════════════════════════════════════════════════════════════════════


def scan_result_to_payload(result: GatewayScanResult) -> dict:
    """Serialize a GatewayScanResult to a JSON-safe payload."""
    return {
        "target_ip": result.target_ip,
        "target_port": result.target_port,
        "scan_status": result.scan_status.value,
        "ike_version": (result.ike_version_detected.value if result.ike_version_detected.is_known() else None),
        "cookie_required": (result.cookie_required.value if result.cookie_required.is_known() else None),
        "accepted_dh_groups": [f.value for f in result.accepted_dh_groups if f.is_known()],
        "rejected_dh_groups": [f.value for f in result.rejected_dh_groups if f.is_known()],
        "accepted_transforms": [
            {
                "transform_type": int(t.transform_type),
                "transform_id": t.transform_id,
                "key_length": t.key_length,
            }
            for t in result.accepted_transforms
        ],
        "ikev1_accepted": [
            {
                "encryption": t.encryption,
                "hash_alg": t.hash_alg,
                "auth_method": t.auth_method,
                "dh_group": t.dh_group,
                "key_length": t.key_length,
            }
            for t in result.ikev1_accepted
        ],
        "scan_start_time": result.scan_start_time,
        "scan_end_time": result.scan_end_time,
        "probe_count": result.probe_count,
        "error_message": result.error_message,
        "responder_spi": result.responder_spi.hex(),
    }


def payload_to_scan_result(payload: dict) -> GatewayScanResult:
    """Reconstruct a GatewayScanResult from a worker JSON payload."""
    result = GatewayScanResult(
        target_ip=payload["target_ip"],
        target_port=payload["target_port"],
        scan_status=ScanStatus(payload["scan_status"]),
    )

    if payload.get("ike_version"):
        result.mark_observed_ike_version(payload["ike_version"])
    if payload.get("cookie_required") is not None:
        result.mark_cookie_required(bool(payload["cookie_required"]))

    for group in payload.get("accepted_dh_groups", []):
        result.add_accepted_dh_group(group)
    for group in payload.get("rejected_dh_groups", []):
        result.add_rejected_dh_group(group)

    for transform in payload.get("accepted_transforms", []):
        result.accepted_transforms.append(
            AcceptedTransform(
                transform_type=TransformType(transform["transform_type"]),
                transform_id=transform["transform_id"],
                key_length=transform["key_length"],
            )
        )

    for v1_transform in payload.get("ikev1_accepted", []):
        result.ikev1_accepted.append(IKEv1AcceptedTransform(**v1_transform))

    result.scan_start_time = payload.get("scan_start_time", 0.0)
    result.scan_end_time = payload.get("scan_end_time", 0.0)
    result.probe_count = payload.get("probe_count", 0)
    result.error_message = payload.get("error_message", "")

    spi_hex = payload.get("responder_spi", "")
    result.responder_spi = bytes.fromhex(spi_hex) if spi_hex else b""

    return result


# ═══════════════════════════════════════════════════════════════════════
#  Scan Worker (executed inside ns-left) and Parent-Side Invocation
# ═══════════════════════════════════════════════════════════════════════


async def _live_scan() -> GatewayScanResult:
    allowlist = TargetAllowlist()
    allowlist.add(TARGET_IP, consent_verified=True, owner="lab-phase3-twin-proof")

    config = ScanConfig(
        initial_timeout_ms=500,
        max_retries=3,
        backoff_factor=1.5,
        jitter_range_ms=10,
        rate_limit_delay_ms=10,
        try_ikev1=True,
    )

    return await scan_gateway(target_ip=TARGET_IP, allowlist=allowlist, config=config, target_port=500)


def scan_worker(out_path: Path) -> int:
    """Worker entrypoint: run the live scan and write JSON evidence to disk."""
    result = asyncio.run(_live_scan())
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(scan_result_to_payload(result), indent=2), encoding="utf-8")
    return 0


def run_scan_in_namespace(out_path: Path) -> GatewayScanResult:
    """Execute this script's scan worker inside ns-left and load its JSON output."""
    worker_cmd = [
        "ip",
        "netns",
        "exec",
        "ns-left",
        sys.executable,
        str(Path(__file__).resolve()),
        "--scan-worker",
        "--out",
        str(out_path),
    ]
    proc = subprocess.run(worker_cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"Scan worker failed inside ns-left:\n{proc.stdout}\n{proc.stderr}")

    payload = json.loads(out_path.read_text(encoding="utf-8"))
    return payload_to_scan_result(payload)


# ═══════════════════════════════════════════════════════════════════════
#  Lab Control Helpers
# ═══════════════════════════════════════════════════════════════════════


def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stdout}\n{proc.stderr}")
    return proc


def setup_namespaces() -> None:
    run_cmd(["bash", str(PROJECT_ROOT / "lab" / "setup_namespaces.sh")])


def start_charon(namespace: str) -> None:
    run_cmd(["bash", str(PROJECT_ROOT / "lab" / "start_charon.sh"), namespace])


def stop_charon(namespace: str) -> None:
    run_cmd(["bash", str(PROJECT_ROOT / "lab" / "stop_charon.sh"), namespace], check=False)


def restart_charons() -> None:
    for namespace in ("ns-left", "ns-right"):
        stop_charon(namespace)
    time.sleep(0.3)
    for namespace in ("ns-left", "ns-right"):
        start_charon(namespace)


def flush_xfrm() -> None:
    for namespace in ("ns-left", "ns-right"):
        run_cmd(["ip", "netns", "exec", namespace, "ip", "xfrm", "state", "flush"], check=False)
        run_cmd(["ip", "netns", "exec", namespace, "ip", "xfrm", "policy", "flush"], check=False)


def load_swanctl_config(conf_path: Path, socket_uri: str) -> None:
    run_cmd(["swanctl", "--load-all", "--file", str(conf_path), "--uri", socket_uri])


def get_sas(socket_uri: str) -> str:
    return run_cmd(["swanctl", "--list-sas", "--uri", socket_uri], check=False).stdout


def initiate_tunnel(conn_name: str, child_name: str) -> None:
    proc = run_cmd(["swanctl", "--initiate", "--child", child_name, "--uri", SOCKET_LEFT], check=False)
    if proc.returncode != 0:
        run_cmd(["swanctl", "--initiate", "--ike", conn_name, "--uri", SOCKET_LEFT], check=False)


def wait_for_tunnel(timeout_s: float = 12.0) -> tuple[bool, bool, str, str]:
    deadline = time.time() + timeout_s
    left_ok = right_ok = False
    left_sas = right_sas = ""

    while time.time() < deadline:
        left_sas = get_sas(SOCKET_LEFT)
        right_sas = get_sas(SOCKET_RIGHT)
        left_ok = "ESTABLISHED" in left_sas and "INSTALLED" in left_sas
        right_ok = "ESTABLISHED" in right_sas and "INSTALLED" in right_sas
        if left_ok and right_ok:
            break
        time.sleep(0.5)

    return left_ok, right_ok, left_sas, right_sas


def ping_across_tunnel() -> tuple[bool, str]:
    proc = run_cmd(
        ["ip", "netns", "exec", "ns-left", "ping", "-c", "2", "-W", "1", TARGET_IP],
        check=False,
    )
    return proc.returncode == 0, proc.stdout


def tail_charon_log(namespace: str, lines: int = 20) -> str:
    log_path = Path(f"/tmp/tunneltwin/{namespace}/charon.log")
    if not log_path.exists():
        return f"(no charon log for {namespace})"
    content = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(content[-lines:])


# ═══════════════════════════════════════════════════════════════════════
#  Stage Helpers
# ═══════════════════════════════════════════════════════════════════════


def finding_ids(failures) -> list[str]:
    return [f.rule_id for f in failures]


def format_findings(failures) -> str:
    return "\n".join(f"    - [{f.rule_id}] {f.rule_name}" for f in failures)


def load_config_pair(left_conf: Path, right_conf: Path) -> None:
    """Load a configuration pair on both peers without initiating."""
    flush_xfrm()
    load_swanctl_config(right_conf, SOCKET_RIGHT)
    load_swanctl_config(left_conf, SOCKET_LEFT)


def establish_tunnel() -> tuple[bool, bool, str, str]:
    """Initiate from ns-left and wait for both peers to report ESTABLISHED."""
    initiate_tunnel(BASELINE_CONN, BASELINE_CHILD)
    return wait_for_tunnel()


def teardown_tunnel() -> None:
    """
    Remove the data path before scanning.

    An established child SA installs XFRM policies that encapsulate ALL traffic
    between the peer IPs — including probe packets sent by the Phase-1 scanner.
    Terminating the IKE SA and flushing XFRM restores a clean control-plane-only
    state so the active scanner observes the responder directly (exactly the
    conditions under which the Phase-1 scan was verified).
    """
    for socket_uri in (SOCKET_LEFT, SOCKET_RIGHT):
        run_cmd(["swanctl", "--terminate", "--ike", BASELINE_CONN, "--uri", socket_uri], check=False)
    time.sleep(0.5)
    flush_xfrm()


# ═══════════════════════════════════════════════════════════════════════
#  Main Phase 3 Twin Proof
# ═══════════════════════════════════════════════════════════════════════


def main() -> int:
    if os.geteuid() != 0:
        print("[ERROR] Phase 3 twin proof must be executed as root (network namespace access).")
        return 1

    print("=" * 80)
    print("      TunnelTwin / Valence_IPSec — Phase 3 Live Twin Check & Remediation Proof")
    print("=" * 80)
    print(f"Baseline profile   : {BASELINE_PROFILE} (IKEv1 / 3DES-SHA1 / MODP-1024)")
    print(f"Remediation profile: {REMEDIATION_PROFILE}")
    print(f"Target namespace   : ns-right ({TARGET_IP}), scan origin: ns-left ({LEFT_IP})")

    checks: dict[str, bool] = {}

    print("\n[1/5] Initializing Phase-0 lab testbed and loading the legacy weak profile...")
    setup_namespaces()
    restart_charons()

    weak_left = CONFIGS_DIR / BASELINE_PROFILE / "left.conf"
    weak_right = CONFIGS_DIR / BASELINE_PROFILE / "right.conf"
    load_config_pair(weak_left, weak_right)

    # ── Stage 1: baseline live scan reproduces the weak finding ───────
    print("\n[2/5] Running the real Phase-1 active scan against the weak baseline gateway...")
    baseline_scan = run_scan_in_namespace(PHASE3_DIR / "scan-baseline.json")
    print(baseline_scan.summary())

    verifier = TwinVerifier()
    old_score, old_failures = verifier.evaluate_scan(baseline_scan)
    old_ids = finding_ids(old_failures)
    print(f"\nBaseline posture score : {old_score}/100")
    print("Baseline findings:")
    print(format_findings(old_failures))

    checks["baseline_finding_reproduced"] = all(fid in old_ids for fid in REQUIRED_BASELINE_FINDINGS)
    if not checks["baseline_finding_reproduced"]:
        print(f"\n[FAIL] Required baseline findings {REQUIRED_BASELINE_FINDINGS} did not reproduce.")
        return 1

    # ── Stage 2: old config establishes in the lab (twin baseline) ───
    print("\n[3/5] Establishing the weak baseline tunnel in the Phase-0 lab (old config)...")
    left_ok, right_ok, left_sas, right_sas = establish_tunnel()

    print("\n=== ns-left swanctl --list-sas (weak baseline) ===")
    print(left_sas)
    print("=== ns-right swanctl --list-sas (weak baseline) ===")
    print(right_sas)

    checks["baseline_tunnel_established"] = left_ok and right_ok
    if not checks["baseline_tunnel_established"]:
        print("\n[FAIL] Weak baseline tunnel did not establish — aborting.")
        print(tail_charon_log("ns-right"))
        return 1

    print("Tearing down the weak data path before producing the remediated twin...")
    teardown_tunnel()

    # ── Stage 3: generate + apply remediated config ──────────────────
    print("\n[4/5] Generating hardened aes256gcm-baseline configuration with tunneltwin.fix...")
    left_cfg, right_cfg = build_remediation_artifacts(
        old_profile_name=BASELINE_PROFILE,
        old_left_content=weak_left.read_text(encoding="utf-8"),
        old_right_content=weak_right.read_text(encoding="utf-8"),
        target_profile=REMEDIATION_PROFILE,
        left_ip=LEFT_IP,
        right_ip=TARGET_IP,
        left_ts=f"{LEFT_IP}/32",
        right_ts=f"{TARGET_IP}/32",
    )

    PHASE3_DIR.mkdir(parents=True, exist_ok=True)
    left_conf_path = PHASE3_DIR / "remediated-left.conf"
    right_conf_path = PHASE3_DIR / "remediated-right.conf"
    left_conf_path.write_text(left_cfg.content, encoding="utf-8")
    right_conf_path.write_text(right_cfg.content, encoding="utf-8")

    print(f"Generated: {left_conf_path}")
    print(f"Generated: {right_conf_path}")
    print("\n--- Unified diff: weak (left) -> aes256gcm-baseline (left) ---")
    print(left_cfg.diff)

    print("Applying remediated configuration to both peers (fresh charons)...")
    restart_charons()
    load_config_pair(left_conf_path, right_conf_path)
    new_left_ok, new_right_ok, new_left_sas, new_right_sas = establish_tunnel()

    print("\n=== ns-left swanctl --list-sas (remediated) ===")
    print(new_left_sas)
    print("=== ns-right swanctl --list-sas (remediated) ===")
    print(new_right_sas)

    checks["remediated_tunnel_established"] = new_left_ok and new_right_ok

    ping_ok, ping_out = ping_across_tunnel()
    print("\n--- Data-plane verification: ping ns-left -> ns-right across remediated tunnel ---")
    print(ping_out.strip())
    checks["data_plane_ping"] = ping_ok

    if not (checks["remediated_tunnel_established"] and checks["data_plane_ping"]):
        print("\n[FAIL] Remediated tunnel did not establish or ping failed.")
        print(tail_charon_log("ns-right"))
        return 1

    print("Tearing down the remediated data path before the verification re-scan...")
    teardown_tunnel()

    # ── Stage 4: re-scan and confirm findings cleared ─────────────────
    print("\n[5/5] Re-scanning the same namespace with the real Phase-1 active scanner...")
    remediated_scan = run_scan_in_namespace(PHASE3_DIR / "scan-remediated.json")
    print(remediated_scan.summary())

    twin_result = verifier.verify_twin_transition(
        baseline_scan=baseline_scan,
        remediated_scan=remediated_scan,
        remediated_config=left_cfg,
        baseline_tunnel_ok=True,
        remediated_tunnel_ok=True,
        ping_verified=ping_ok,
        target_profile=REMEDIATION_PROFILE,
    )

    print("\n" + twin_result.summary())

    cleared_ids = [f.split(" ")[0] for f in twin_result.cleared_findings]
    checks["findings_cleared"] = all(fid in cleared_ids for fid in REQUIRED_BASELINE_FINDINGS)
    checks["twin_check_passed"] = twin_result.passed

    print("\nRe-establishing the remediated tunnel after the re-scan (final state verification)...")
    re_left_ok, re_right_ok, re_left_sas, _re_right_sas = establish_tunnel()
    print(re_left_sas)
    checks["remediated_tunnel_reestablished"] = re_left_ok and re_right_ok

    # Persist machine-readable evidence next to the scan JSON files
    evidence = {
        "baseline_profile": BASELINE_PROFILE,
        "remediation_profile": REMEDIATION_PROFILE,
        "baseline_score": twin_result.old_score,
        "remediated_score": twin_result.new_score,
        "baseline_findings": twin_result.old_findings,
        "remediated_findings": twin_result.new_findings,
        "cleared_findings": twin_result.cleared_findings,
        "old_tunnel_established": twin_result.old_tunnel_established,
        "new_tunnel_established": twin_result.new_tunnel_established,
        "remediated_tunnel_reestablished": checks["remediated_tunnel_reestablished"],
        "ping_verified": twin_result.ping_verified,
        "passed": twin_result.passed,
        "checks": checks,
    }
    (PHASE3_DIR / "twin-result.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")

    print("\n" + "=" * 80)
    print("        PHASE 3 EXIT CRITERIA EVALUATION (LIVE, NON-MOCKED EVIDENCE)")
    print("=" * 80)
    labels = {
        "baseline_finding_reproduced": f"Baseline findings reproduced: {', '.join(REQUIRED_BASELINE_FINDINGS)}",
        "baseline_tunnel_established": "Weak baseline tunnel established (old config applied in lab)",
        "remediated_tunnel_established": "Remediated tunnel establishes on both peers",
        "data_plane_ping": "Data-plane ping passes through remediated tunnel",
        "findings_cleared": f"Findings cleared on re-scan: {', '.join(REQUIRED_BASELINE_FINDINGS)}",
        "remediated_tunnel_reestablished": "Remediated tunnel re-establishes after re-scan",
        "twin_check_passed": "TwinCheckResult.passed",
    }
    for key in labels:
        status = "PASS" if checks.get(key) else "FAIL"
        print(f"  [{status}] {labels[key]}")

    all_passed = all(checks.values())
    print("=" * 80)
    if all_passed:
        print("PHASE 3 EXIT CRITERIA MET: weak finding present -> config remediated ->")
        print("tunnel verified on real output -> re-scan confirms the finding cleared.")
        return 0

    print("PHASE 3 EXIT CRITERIA FAILED: see checks above.")
    return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TunnelTwin Phase 3 live twin-check proof runner.")
    parser.add_argument("--scan-worker", action="store_true", help="Run the live scan worker (inside ns-left).")
    parser.add_argument("--out", type=Path, default=PHASE3_DIR / "scan.json", help="Worker JSON output path.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.scan_worker:
        sys.exit(scan_worker(args.out))
    sys.exit(main())
