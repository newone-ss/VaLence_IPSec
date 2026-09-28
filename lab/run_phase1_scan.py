#!/usr/bin/env python3
"""
TunnelTwin Phase 1 Live Namespace Integration Scan Runner.

Fulfills Phase 1 Exit Criteria:
  1. Deploys each of the four Phase-0 profiles (weak, mixed, strong, legacy-cbc)
     plus one cookie-enforcing profile (cookie) to ns-right (10.0.1.2).
  2. Executes active IKE proposal scan from ns-left using scan_gateway().
  3. Reports accepted/rejected proposals, DH groups, detected IKE version,
     cookie challenge status, and end-to-end duration.
  4. Confirms that scan completes successfully against the cookie-requiring gateway.

Must be executed with root privileges inside Linux / WSL2.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

# Add project root to sys.path so tunneltwin can be imported
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tunneltwin.probe.allowlist import TargetAllowlist
from tunneltwin.probe.result import GatewayScanResult
from tunneltwin.probe.scanner import ScanConfig, scan_gateway

CONFIGS_DIR = PROJECT_ROOT / "lab" / "configs"
RUN_DIR = Path("/tmp/tunneltwin")
SOCKET_RIGHT = "unix:///tmp/tunneltwin/ns-right/charon.vici"

PROFILES = [
    {
        "name": "weak",
        "desc": "IKEv1, 3DES-SHA1, MODP-1024",
        "expected_version": "IKEv1",
        "cookie_mode": False,
    },
    {
        "name": "mixed",
        "desc": "IKEv2, Prefers AES256/ECP384, accepts MODP-1024",
        "expected_version": "IKEv2",
        "cookie_mode": False,
    },
    {
        "name": "strong",
        "desc": "IKEv2, AES256-GCM, SHA384, ECP384 only",
        "expected_version": "IKEv2",
        "cookie_mode": False,
    },
    {
        "name": "legacy-cbc",
        "desc": "IKEv2, AES128-CBC+SHA1, MODP-2048",
        "expected_version": "IKEv2",
        "cookie_mode": False,
    },
    {
        "name": "cookie",
        "desc": "IKEv2, Anti-DoS Cookie Challenge Required (dos_protection=yes)",
        "expected_version": "IKEv2",
        "cookie_mode": True,
    },
]


def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def setup_namespaces_if_needed() -> None:
    setup_script = PROJECT_ROOT / "lab" / "setup_namespaces.sh"
    res = subprocess.run(["bash", str(setup_script)], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"Error initializing namespaces:\n{res.stderr}")
        sys.exit(1)


def start_charon(ns: str, cookie_mode: bool = False) -> None:
    start_script = PROJECT_ROOT / "lab" / "start_charon.sh"
    cmd = ["bash", str(start_script), ns]
    if cookie_mode:
        cmd.append("cookie")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Failed to start charon on {ns}:\n{res.stderr}")


def stop_charon(ns: str) -> None:
    stop_script = PROJECT_ROOT / "lab" / "stop_charon.sh"
    subprocess.run(["bash", str(stop_script), ns], capture_output=True, text=True)


def load_profile_on_right(profile_name: str) -> None:
    conf_file = CONFIGS_DIR / profile_name / "right.conf"
    if not conf_file.exists():
        raise FileNotFoundError(f"Configuration not found: {conf_file}")

    cmd = ["swanctl", "--load-all", "--file", str(conf_file), "--uri", SOCKET_RIGHT]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"swanctl load-all failed for {profile_name}:\n{res.stderr}\n{res.stdout}")


async def probe_gateway_from_ns_left(target_ip: str = "10.0.1.2") -> GatewayScanResult:
    """Run scan_gateway against target IP with double-barrier allowlist."""
    allowlist = TargetAllowlist()
    allowlist.add(target_ip, consent_verified=True, owner="lab-phase1-exit-audit")

    config = ScanConfig(
        initial_timeout_ms=500,
        max_retries=3,
        backoff_factor=1.5,
        jitter_range_ms=10,
        rate_limit_delay_ms=10,
        try_ikev1=True,
    )

    return await scan_gateway(target_ip=target_ip, allowlist=allowlist, config=config, target_port=500)


def scan_worker(profile_name: str, target_ip: str) -> GatewayScanResult:
    """Helper executed inside ns-left network namespace."""
    return asyncio.run(probe_gateway_from_ns_left(target_ip))


def main() -> int:
    if os.geteuid() != 0:
        print("[ERROR] Phase 1 integration scan must be executed as root (for network namespace access).")
        return 1

    print("=" * 80)
    print("      TunnelTwin / Valence_IPSec — Phase 1 Live Namespace Integration Scan")
    print("=" * 80)

    print("\n[1/3] Initializing Linux network namespaces (ns-left <-> ns-right)...")
    setup_namespaces_if_needed()

    results: list[tuple[dict[str, object], GatewayScanResult]] = []
    all_passed = True

    print("\n[2/3] Scanning 5 live testbed gateways (4 Phase-0 profiles + 1 Cookie gateway)...")
    for idx, p in enumerate(PROFILES, 1):
        name = str(p["name"])
        desc = str(p["desc"])
        cookie_mode = bool(p["cookie_mode"])

        print(f"\n--- [{idx}/5] Testing Gateway Profile: {name.upper()} ({desc}) ---")

        # 1. Stop any existing charon on ns-right
        stop_charon("ns-right")
        time.sleep(0.3)

        # 2. Start fresh charon on ns-right with requested mode
        start_charon("ns-right", cookie_mode=cookie_mode)

        # 3. Load connection profile into ns-right
        load_profile_on_right(name)
        time.sleep(0.5)

        # 4. Execute scan from inside ns-left network namespace
        # We spawn a python one-liner inside ns-left calling this script's internal worker
        worker_cmd = [
            "ip",
            "netns",
            "exec",
            "ns-left",
            sys.executable,
            "-c",
            f"import sys; sys.path.insert(0, '{PROJECT_ROOT}'); "
            f"import asyncio, json; "
            f"from tunneltwin.probe.allowlist import TargetAllowlist; "
            f"from tunneltwin.probe.scanner import ScanConfig, scan_gateway; "
            f"al = TargetAllowlist(); al.add('10.0.1.2', consent_verified=True, owner='lab-audit'); "
            f"cfg = ScanConfig(initial_timeout_ms=500, max_retries=3, "
            f"backoff_factor=1.5, jitter_range_ms=10, rate_limit_delay_ms=10, try_ikev1=True); "
            f"res = asyncio.run(scan_gateway('10.0.1.2', al, cfg)); "
            f"print(json.dumps({{"
            f"  'status': res.scan_status.value, "
            f"  'version': res.ike_version_detected.value, "
            f"  'accepted_dh': [f.value for f in res.accepted_dh_groups], "
            f"  'rejected_dh': [f.value for f in res.rejected_dh_groups], "
            f"  'transforms_count': len(res.accepted_transforms), "
            f"  'ikev1_count': len(res.ikev1_accepted), "
            f"  'cookie_required': res.cookie_required.value, "
            f"  'probes': res.probe_count, "
            f"  'duration_ms': res.scan_duration_ms, "
            f"  'summary': res.summary()"
            f"}}))",
        ]

        scan_proc = subprocess.run(worker_cmd, capture_output=True, text=True)
        if scan_proc.returncode != 0:
            print(f"❌ Scan execution failed in ns-left:\n{scan_proc.stderr}")
            all_passed = False
            stop_charon("ns-right")
            continue

        try:
            import json

            scan_data = json.loads(scan_proc.stdout.strip())
        except Exception as e:
            print(
                f"❌ Failed to parse scanner output:\nSTDOUT: {scan_proc.stdout}\n"
                f"STDERR: {scan_proc.stderr}\nError: {e}"
            )
            all_passed = False
            stop_charon("ns-right")
            continue

        print(scan_data.get("summary", ""))

        # Verification asserts for exit criteria
        status = scan_data["status"]
        detected_version = scan_data["version"]
        cookie_req = scan_data["cookie_required"]
        duration_ms = scan_data["duration_ms"]
        expected_ver = p["expected_version"]

        if status != "success":
            print(f"❌ Profile {name}: Scan status was '{status}', expected 'success'")
            all_passed = False
        elif detected_version != expected_ver:
            print(f"❌ Profile {name}: Detected version '{detected_version}', expected '{expected_ver}'")
            all_passed = False
        elif cookie_mode and not cookie_req:
            print(f"❌ Profile {name}: Expected cookie_required=True, got {cookie_req}")
            all_passed = False
        else:
            print(
                f"✅ Profile {name}: PASS (Version={detected_version}, Probes={scan_data['probes']}, "
                f"Duration={duration_ms:.1f}ms, Cookie={cookie_req})"
            )

        results.append((p, scan_data))
        stop_charon("ns-right")

    print("\n" + "=" * 80)
    print("                    PHASE 1 LIVE SCAN SUMMARY REPORT")
    print("=" * 80)
    print(f"{'Profile':<12} | {'IKE Ver':<8} | {'Accepted DH':<22} | {'Cookie':<8} | {'Duration':<10} | {'Status'}")
    print("-" * 80)

    for p, d in results:
        prof_name = str(p["name"])
        v = str(d.get("version") or "unknown")
        dh_list = d.get("accepted_dh", [])
        dh_str = ", ".join(dh_list) if dh_list else ("(IKEv1)" if v == "IKEv1" else "none")
        cookie_str = "YES ✅" if d.get("cookie_required") else "no"
        dur = f"{d.get('duration_ms', 0):.1f}ms"
        stat = "PASS ✅" if d.get("status") == "success" else "FAIL ❌"
        print(f"{prof_name:<12} | {v:<8} | {dh_str:<22} | {cookie_str:<8} | {dur:<10} | {stat}")

    print("=" * 80)

    if all_passed and len(results) == 5:
        print("\n🎉 PHASE 1 EXIT CRITERIA MET: ALL 5 GATEWAYS VERIFIED ESTABLISHED AND REPORTED!")
        return 0
    else:
        print("\n❌ PHASE 1 EXIT CRITERIA FAILED: One or more gateways did not pass.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
