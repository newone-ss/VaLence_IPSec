# TunnelTwin — Session Handover & Continuity Record

> **Living Context Record**: This document is read at the start of every AI session to maintain zero-amnesia continuity across development cycles. It reflects the live operational state of the TunnelTwin project (SIH 2026, Problem Statement 26160 — NTRO: AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework).

---

## 1. Current Operational State

- **Active Phase**: Phase 1 Complete — Ready for Phase 2 (Active IKE Prober Integration & Fleet Scanning)
- **Target Deadline**: 29 September 2026
- **Current Objective**: Phase 1 probe engine core is fully implemented and live-verified against all 5 network namespace profiles in WSL2 (100% pass across weak, mixed, strong, legacy-cbc, and anti-DoS cookie challenge). All 44 unit tests pass, automated test `tests/test_phase1_matrix.py` passes, and quality gates (ruff, mypy) are green.
- **Environment**: Host Windows 11 with WSL2 Ubuntu (`Ubuntu-26.04`), Linux Kernel 6.6.87.2-microsoft-standard-WSL2, full root privileges for netns and IPsec kernel operations.

---

## 2. What Is Done

- **Core Documentation System**:
  - `HANDOVER.md`: Living state and operational context.
  - `DECISIONS.md`: Architectural decision records (ADR-0001 through ADR-0007).
  - `FLOW.md`: Complete data and control flow mapping.
  - `FEATURE.md`: Feature scoping and lifecycle tracking (FEAT-001 through FEAT-005 complete).
  - `BUG.md`: Bug discovery, diagnosis, and fix tracing (BUG-001 through BUG-004 resolved).
  - `VERIFICATION.md`: Concrete test checklist & verification protocol ("no vibe checks").
  - `ROLLBACK.md`: Safety net, fast rollback recipes, and baseline state restoration plan.
- **Repository Scaffolding**:
  - `tunneltwin/{core,ike,probe,rules,fix,capture,ml,seal,api,cli,ui}`
  - `lab/`, `tests/`, `docs/`
  - `pyproject.toml` and `README.md`
- **Data Models & Provenance System**:
  - `tunneltwin/core/models.py`: Four-tier provenance tags (`OBSERVED`, `PARSED`, `INFERRED`, `UNKNOWN`), `ProvenancedFact[T]`, confidence scores for inferred facts, and normalized IPsec schema.
- **Lab Substrate & Automation**:
  - `lab/setup_namespaces.sh`: Linux network namespaces (`ns-left`, `ns-right`) linked with veth pair (`10.0.1.1/30` <-> `10.0.1.2/30`).
  - `lab/start_charon.sh`: Spawns isolated strongSwan charons per namespace using `unshare -m` private mount namespaces to prevent `/var/run/charon.pid` collisions. Added `[cookie]` mode support (`dos_protection = yes`, `cookie_threshold = 1`, `cookie_threshold_ip = 1`).
  - `lab/stop_charon.sh` and `lab/teardown_namespaces.sh`.
  - Five connection profiles in `lab/configs/`:
    - `weak`: IKEv1, 3DES-SHA1, MODP_1024
    - `mixed`: Prefers AES256/ECP384, accepts MODP_1024
    - `strong`: IKEv2, AES256-GCM, SHA384, ECP384 only
    - `legacy-cbc`: IKEv2, AES128-CBC+SHA1, MODP_2048
    - `cookie`: IKEv2, anti-DoS cookie challenge required
  - `lab/run_matrix.sh` and `lab/run_matrix.py`: Automated Phase 0 execution and verification runner.
  - `lab/run_phase1_scan.py` and `lab/run_phase1_scan.sh`: Automated Phase 1 live scan runner across all 5 profiles.
- **Phase 0 Exit Verification**:
  - Ran `lab/run_matrix.sh` and verified `swanctl --list-sas` shows `ESTABLISHED` states on both `ns-left` and `ns-right` for all 4 profiles.
  - Ran `pytest -v tests/` with 7/7 tests passing.
- **Phase 1 — Probe Engine Core & Exit Verification**:
  - `tunneltwin/ike/constants.py`: Complete IANA registry IDs for IKEv2/IKEv1 transforms, payloads, exchange types, DH groups, and notify types.
  - `tunneltwin/ike/codec.py`: Pure-Python `struct`-based IKE binary codec. Builds and parses IKEv2 IKE_SA_INIT and IKEv1 Main Mode packets with zero Scapy dependency.
  - RFC 5903 & RFC 7296 §3.4 curve compliance: generates valid EC public key points (raw uncompressed X || Y coordinates) for ECP-256, ECP-384, ECP-521, and X25519 to satisfy strongSwan `libstrongswan-openssl.so` point validation.
  - RFC 7296 §3.3 & RFC 5282 §4.2 rule compliance: AEAD proposals omit Transform Type 3 (INTEG).
  - `tunneltwin/ike/transforms.py`: Transform proposal generator for elimination scanning with exclusion support.
  - `tunneltwin/probe/allowlist.py`: Consent-gated double-barrier target allowlist (ADR-0003).
  - `tunneltwin/probe/result.py`: Scan result data models with `OBSERVED` provenance tagging.
  - `tunneltwin/probe/scanner.py`: Async UDP probe engine with IKEv2/IKEv1 elimination scanning, cookie handling (RFC 7296 §2.6), exponential backoff with jitter, and rate limiting.
  - `tests/test_ike_codec.py`: 17 unit tests for IKE codec build/parse round-trips.
  - `tests/test_probe_allowlist.py`: 11 unit tests for consent-gated allowlist.
  - `tests/test_probe_scanner.py`: 10 unit tests for scanner consent enforcement, provenance, and timing.
  - `tests/test_phase1_matrix.py`: Automated end-to-end integration test verifying live netns scan.
  - **Empirical Live Netns Scan (All 5 Profiles Passed)**:
    - `weak`: IKEv1, 3DES-CBC / SHA1 / MODP-1024, 350.5ms (PASS)
    - `mixed`: IKEv2, MODP-1024, AES-CBC-256 / SHA2-256 / PRF-SHA2-256, 291.1ms (PASS)
    - `strong`: IKEv2, ECP-384, AES-GCM-16-256 / PRF-SHA2-384, 329.7ms (PASS)
    - `legacy-cbc`: IKEv2, MODP-2048, AES-CBC-128 / SHA1 / PRF-SHA1, 303.4ms (PASS)
    - `cookie`: IKEv2, ECP-384, Cookie Needed: True (65 probes, 692.5ms) (PASS)

---

## 3. What Is In Progress

- Phase 1 exit criteria are 100% satisfied and verified.
- Ready to proceed to Phase 2 (Active IKE Prober Integration, Fleet Scanning, Output to NormalizedConnection).

---

## 4. What Is Broken / Blocking

- None. All test suites and lab runs are 100% green.

---

## 5. What to Avoid (Negative Constraints)

1. **DO NOT copy code** from public repositories (including CipherLens, IPsec Sentinel, Alchemist, CipherGuard, ipsec-Detector, SIH-160, vpnguard, VPN-Prots, IPsecAnalyzer, TunnelScope). All architecture and code must be 100% original.
2. **DO NOT omit provenance tags**. Every fact reported by the system must carry one of:
   - `observed` (from an active scan)
   - `parsed` (from an uploaded configuration)
   - `inferred` (from ML, with an explicit confidence score $\in [0.0, 1.0]$)
   - `unknown`
   *Rule evaluation constraint*: Any rule that requires an `unknown` fact MUST report `"cannot assess"`, NEVER a pass.
3. **DO NOT perform unconsented or intrusive active scanning**. Active scanning must strictly require:
   - Host present in an explicit allowlist
   - `consent` flag explicitly set to `True`
   - Non-intrusive proposal probes ONLY (no PSK dictionary attacks, no aggressive-mode credential harvesting).
4. **DO NOT use Docker or Containerlab for the Phase 0 lab testbed**. Must use native Linux network namespaces (`ip netns`) with separate `charon` instances and dedicated `swanctl` control sockets/directories.
5. **DO NOT skip ahead** to later phases before current phase exit criteria are fully satisfied and logged with concrete verification proof.

---

## 6. Phase Roadmap Status

| Phase | Description | Exit Criteria | Status |
|---|---|---|---|
| **Phase 0** | Repo & Testbed Foundation | All 4 swanctl profiles establish tunnel across namespaces; verified by `swanctl --list-sas` on both sides with logs | **PASSED (4/4)** |
| **Phase 1** | Probe Engine Core | Async UDP IKE scanner with elimination probing, cookie handling, consent-gated allowlist; 44/44 unit tests pass & 5/5 netns profiles verified | **PASSED (5/5 Live Gateways + 44/44 Tests)** |
| **Phase 2** | Active IKE Prober (Consent-Gated) | Synthesize IKEv1/v2 SA proposals, probe endpoint in allowlist, map responses with `observed` provenance | PENDING |
| **Phase 3** | Compliance & Vulnerability Engine | NIST SP 800-77r1, ANSSI, RFC 9395 rules; output `observed`/`parsed`/`unknown` tags; "cannot assess" on unknown | PENDING |
| **Phase 4** | Automated Remediation & Diff Generator | Generate hardened configuration files and unified diffs; round-trip validation with parser | PENDING |
| **Phase 5** | Passive PCAP/Live Capture Analyzer | Parse live IKE/ESP packets, detect SPI mismatches, unencrypted payloads, weak DH exchange | PENDING |
| **Phase 6** | ML Inference Engine & Confidence Tagging | Infer missing params with confidence scores $\in [0.0, 1.0]$; tag facts as `inferred` | PENDING |
| **Phase 7** | Cryptographic Seal & Integrity Verification | SHA-256 Merkle audit trail for every finding; cryptographic verification receipt | PENDING |
| **Phase 8** | API, CLI, and Web Dashboard | Fast backend API, CLI command runner, dynamic dark-mode UI with visual topology | PENDING |
| **Phase 9** | End-to-End Evaluation & Demonstration | Full automated test suite across all 4 lab profiles, compliance validation, remediation diffs, zero errors | PENDING |
