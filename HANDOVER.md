# TunnelTwin — Session Handover & Continuity Record

> **Living Context Record**: This document is read at the start of every AI session to maintain zero-amnesia continuity across development cycles. It reflects the live operational state of the TunnelTwin project (SIH 2026, Problem Statement 26160 — NTRO: AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework).

---

## 1. Current Operational State

- **Active Phase**: Phase 4 Complete — Multi-Daemon Diversity (Libreswan) & Behavioral Fingerprinting
- **Target Deadline**: 29 September 2026
- **Current Objective**: Phase 4 multi-daemon diversity (Libreswan in network namespaces side-by-side with strongSwan), behavioral daemon fingerprinting (RFC payload quirks over static assumptions), and cross-daemon remediation (Libreswan ipsec.conf generator, unified diff, live twin verification, and prober re-scan) are fully implemented and verified on real output. 101 tests total across project (97 passed on Windows, 4 netns tests skipped on non-root; 101/101 passed in WSL2).
- **Environment**: Host Windows 11 with WSL2 Ubuntu (`Ubuntu-26.04`), Linux Kernel 6.6.87.2-microsoft-standard-WSL2, full root privileges for netns and IPsec kernel operations.

---

## 2. What Is Done

- **Core Documentation System**:
  - `HANDOVER.md`: Living state and operational context.
  - `DECISIONS.md`: Architectural decision records (ADR-0001 through ADR-0009).
  - `FLOW.md`: Complete data and control flow mapping.
  - `FEATURE.md`: Feature scoping and lifecycle tracking (FEAT-001 through FEAT-011 complete).
  - `BUG.md`: Bug discovery, diagnosis, and fix tracing (BUG-001 through BUG-005 resolved).
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
- **Phase 2 — Rule Engine & Evidence Model & Exit Verification**:
  - `tunneltwin/rules/facts.py`: Typed Fact model, FactStore with subject/key indexing, `scan_result_to_facts` bridge tagging all probe observations with `OBSERVED` provenance and $1.0$ confidence.
  - `tunneltwin/rules/packs/nist_sp800_77r1.yaml`: 9 rules covering protocol version, DH groups, cipher modes, key lengths, integrity, and DoS cookie protection (NIST SP 800-77 Rev 1 & SP 800-131A Rev 2).
  - `tunneltwin/rules/packs/nsa_cnsa.yaml`: 4 rules enforcing strict NSA CNSA 2.0 192-bit security floor (IKEv2, ECP-384+, AES-256, SHA-384+).
  - `tunneltwin/rules/packs/cert_in.yaml`: 4 rules based on Indian national cybersecurity guidelines, explicitly marked `"pending confirmation of source document"` with zero fabricated citations.
  - `tunneltwin/rules/engine.py`: Declarative rule condition evaluator with strict **`CANNOT_ASSESS`** guarantee on missing/unknown facts.
  - `tunneltwin/rules/scoring.py`: Multi-category scoring algorithm (start 100, category penalties, floor 0, coverage tracking).
  - `tests/test_rules_engine.py`: 28 unit tests passing (fact model, bridge, rule loading, profile evaluation, scoring, and cannot-assess invariants).
  - **Empirical Profile Scores & Findings**:
    - `weak`: Score **0**, 100.0% coverage, 12 findings (`NIST-001`, `NIST-004`, `CNSA-001`, `CERTIN-001`, etc.)
    - `legacy-cbc`: Score **42**, 100.0% coverage, 8 findings (`NIST-007`, `NIST-008`, `NIST-003`, `CNSA-003`, etc.)
    - `mixed`: Score **47**, 100.0% coverage, 6 findings (`NIST-002`, `NIST-005`, `CNSA-002`, `CERTIN-002`, etc.)
    - `strong`: Score **99**, 76.5% coverage, 1 finding (`NIST-009` DoS Cookie Threshold)
- **Phase 3 — Fix and Prove & Exit Verification**:
  - `tunneltwin/fix/models.py`: Data models (`SecurityProfile`, `RemediationConfig`, `TwinCheckResult`, `generate_unified_diff`). Strict enforcement of `CISCO_ASA_VERIFICATION_LABEL = "generated, not lab-verified"`.
  - `tunneltwin/fix/profiles.py`: Cryptographic security profiles (`aes256gcm-baseline`, `nist-sp800-77r1`, `cnsa-suite`).
  - `tunneltwin/fix/swanctl_generator.py`: Generates strongSwan `swanctl.conf` configurations (initiator, responder, pairs) and unified diffs against insecure baselines.
  - `tunneltwin/fix/cisco_generator.py`: Generates Cisco ASA site-to-site IKEv2 configurations with mandatory `"generated, not lab-verified"` labels in all outputs, docstrings, banners, and string representations.
  - `tunneltwin/fix/twin.py`: `TwinVerifier` orchestrator comparing baseline and remediated scan results, verifying SA health and score progression.
  - `lab/run_phase3_twin.py` & `lab/run_phase3_twin.sh`: Live netns end-to-end twin check runner.
  - `tests/test_fix_generators.py`: 10 unit tests for generators, profiles, and Cisco label constraints.
  - `tests/test_phase3_matrix.py`: Live integration test verifying twin check in Linux netns.
  - **Empirical Live Netns Proof Run (`lab/run_phase3_twin.py`)**:
    - Baseline `weak` profile evaluated: Score **0/100**, 12 findings (`NIST-001`, `NIST-004`, `CNSA-001`, etc.), initial tunnel established.
    - Remediated config generated and deployed (`aes256gcm-baseline`).
    - Remediated tunnel established on both `ns-left` and `ns-right` (`AES_GCM_16-256 / PRF_HMAC_SHA2_384 / ECP_384`), data-plane ICMP ping passed (`0% packet loss`).
    - Re-scan performed using Phase 1 active elimination prober: Score **99/100**, findings `NIST-001` and `NIST-004` completely cleared.
    - Remediated tunnel re-established successfully.
    - Verified: `PHASE 3 EXIT CRITERIA MET: weak finding present -> config remediated -> tunnel verified on real output -> re-scan confirms the finding cleared.`

---

## 3. What Is In Progress

- Phase 3 exit criteria are 100% satisfied and verified on real Linux netns output.
- Ready to proceed to Phase 4 (Passive PCAP/Live Capture Analyzer).

---

## 4. What Is Broken / Blocking

- None. All test suites, build packages, and remote GitHub Actions CI workflows are 100% green.

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
5. **DO NOT display Cisco ASA configs without label**: Every Cisco ASA generated artifact MUST be prominently labeled `"generated, not lab-verified"`.
6. **DO NOT skip ahead** to later phases before current phase exit criteria are fully satisfied and logged with concrete verification proof.

---

## 6. Phase Roadmap Status

| Phase | Description | Exit Criteria | Status |
|---|---|---|---|
| **Phase 0** | Repo & Testbed Foundation | All 4 swanctl profiles establish tunnel across namespaces; verified by `swanctl --list-sas` on both sides with logs | **PASSED (4/4 Profiles)** |
| **Phase 1** | Probe Engine Core | Async UDP IKE scanner with elimination probing, cookie handling, consent-gated allowlist; 44/44 unit tests pass & 5/5 netns profiles verified | **PASSED (5/5 Live Gateways + 44/44 Tests)** |
| **Phase 2** | Rule Engine & Evidence Model | Fact model with provenance, YAML rule packs (NIST, CNSA, CERT-In), CANNOT_ASSESS invariant, distinct scores & cited findings per profile; 28/28 tests pass | **PASSED (4/4 Distinct Scores & Cited Findings)** |
| **Phase 3** | Automated Remediation & Diff Generator / Twin Check | swanctl.conf & Cisco ASA generators; twin check and re-scan clears weak findings on real output; 10/10 tests pass | **PASSED (Live Netns Twin Verified: weak finding -> remediated -> tunnel verified -> re-scan cleared)** |
| **Phase 4** | Multi-Daemon Diversity & Behavioral Fingerprinting | Libreswan in netns; behavioral fingerprinting via payload quirks (0.95 conf); cross-daemon tunnel & re-scan verified; 16/16 tests pass | **PASSED (Live Netns Multi-Daemon Verified: scan -> fingerprint -> fix -> cross-daemon tunnel -> re-scan cleared)** |
| **Phase 5** | Deep-Path PCAP & Wire ML Classifier | Dependency-free PCAP/PCAPNG, RFC 4303 filter, ESP feature extractor, IKE retransmit de-dup (unique_attempt_count=1), LightGBM/TreeSHAP models, netem robustness table (clean vs. impaired); 13/13 tests pass | **PASSED (24 real PCAPs + 20 netem PCAPs + Models + TreeSHAP)** |
| **Phase 6** | Cryptographic Seal & Integrity Verification | SHA-256 Merkle audit trail for every finding; cryptographic verification receipt | PENDING |
| **Phase 7** | API, CLI, and Web Dashboard | Fast backend API, CLI command runner, dynamic dark-mode UI with visual topology | PENDING |
| **Phase 8** | End-to-End Evaluation & Demonstration | Full automated test suite across all 4 lab profiles, compliance validation, remediation diffs, zero errors | PENDING |


