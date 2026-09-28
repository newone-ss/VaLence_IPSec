# TunnelTwin — Feature Lifecycle & Traceability (FEATURE.md)

> **Feature Traces**: For every feature across the development lifecycle, this document tracks the complete lifecycle from scoping to verification: how it was scoped, what was tried, what worked, what didn't, and how it was verified.

---

## Feature Index

| Feature ID | Name | Phase | Status | Exit Verified |
|---|---|---|---|---|
| **FEAT-001** | Linux Network Namespace Isolated Lab Substrate | Phase 0 | **COMPLETED** | Verified (PASS) |
| **FEAT-002** | Multi-Profile strongSwan Configuration Engine | Phase 0 | **COMPLETED** | Verified (PASS) |
| **FEAT-003** | Core Package Scaffolding & Provenance Data Model | Phase 0 | **COMPLETED** | Verified (PASS) |
| **FEAT-004** | Pure-Python Binary IKEv1/IKEv2 Codec & Elimination Proposals | Phase 1 | **COMPLETED** | Verified (PASS) |
| **FEAT-005** | Consent-Gated UDP Prober Engine with Elimination Scanning | Phase 1 | **COMPLETED** | Verified (PASS) |
| **FEAT-006** | Fact Model, Provenance Tracking, and Probe Scan Bridge | Phase 2 | **COMPLETED** | Verified (PASS) |
| **FEAT-007** | Standards-Based Rule Packs (NIST SP 800-77r1, NSA CNSA 2.0, CERT-In) | Phase 2 | **COMPLETED** | Verified (PASS) |
| **FEAT-008** | Declarative Rule Engine and Multi-Category Scoring Engine | Phase 2 | **COMPLETED** | Verified (PASS) |
| **FEAT-009** | strongSwan swanctl.conf Remediation Generator & Unified Diff | Phase 3 | **COMPLETED** | Verified (PASS) |
| **FEAT-010** | Cisco ASA Configuration Generator with Mandatory Verification Label | Phase 3 | **COMPLETED** | Verified (PASS) |
| **FEAT-011** | Live Twin Check & Remediation Proof Engine | Phase 3 | **COMPLETED** | Verified (PASS) |
| **FEAT-012** | Multi-Daemon Testbed Substrate (Libreswan in Network Namespaces) | Phase 4 | **COMPLETED** | Verified (PASS) |
| **FEAT-013** | Behavioral Daemon Fingerprinting Engine (RFC Payload Quirks) | Phase 4 | **COMPLETED** | Verified (PASS) |
| **FEAT-014** | Libreswan Remediation Generator & Cross-Daemon Interoperability Proof | Phase 4 | **COMPLETED** | Verified (PASS) |


---

## FEAT-001: Linux Network Namespace Isolated Lab Substrate

### 1. Scope & Objectives
- **Target**: Create two network namespaces (`ns-left`, `ns-right`) linked via a veth pair (`veth-left` <-> `veth-right`) with IP addresses `10.0.1.1/30` and `10.0.1.2/30`.
- **Constraint**: Must NOT use Docker or Containerlab. Must execute natively in Linux netns with strongSwan `charon` running independently per namespace without colliding PID/socket paths.
- **Verification Target**: Ping connectivity between namespaces, separated XFRM state tables, independent control sockets.

### 2. Implementation Approach
- Authored `lab/setup_namespaces.sh` (creates netns, veth pair, /30 IP assignments, loopbacks, sysctl forwarding, ping test).
- Authored `lab/start_charon.sh` (combines `ip netns exec` with `unshare -m` private mount namespace for isolated `/var/run/charon.pid` and custom `/tmp/tunneltwin/<ns>/charon.vici` socket).
- Authored `lab/stop_charon.sh` and `lab/teardown_namespaces.sh`.

### 3. Execution & Verification Log
- Tested ping across namespaces:
  ```text
  [TunnelTwin Lab] Testing ICMP ping between ns-left (10.0.1.1) and ns-right (10.0.1.2)...
  [TunnelTwin Lab] SUCCESS: Point-to-point veth link established and verified.
  ```
- Verified simultaneous daemon execution:
  - `ns-left` PID 470, socket `/tmp/tunneltwin/ns-left/charon.vici`
  - `ns-right` PID 494, socket `/tmp/tunneltwin/ns-right/charon.vici`
  - Both responsive via `swanctl --stats`.

---

## FEAT-002: Four-Tier Swanctl Connection Profiles

### 1. Scope & Objectives
- Author four specific cryptographic profiles for both peers:
  1. `weak`: IKEv1, 3DES-SHA1, MODP_1024.
  2. `mixed`: Prefers modern AES256-SHA384-ECP384, accepts MODP_1024.
  3. `strong`: IKEv2, AES256-GCM, SHA384, ECP384 only.
  4. `legacy-cbc`: IKEv2, AES128-CBC + SHA1, MODP_2048.
- Verify each profile establishes an active IPsec SA on both sides using `swanctl --list-sas`.

### 2. Implementation Approach
- Authored profile configurations in `lab/configs/<profile>/{left.conf, right.conf}`.
- Authored `lab/run_matrix.sh` and `lab/run_matrix.py` to automate sequential testing, SA validation, and tear down.

### 3. Execution & Verification Log
- Automated test matrix verified:
  ```text
  ======================================================================
                       PHASE 0 MATRIX SUMMARY REPORT                    
  ======================================================================
  Total Profiles Tested : 4
  Passed                : 4
  Failed                : 0

  ======================================================================
     PHASE 0 EXIT CRITERIA MET: 4/4 PROFILES VERIFIED ESTABLISHED!     
  ======================================================================
  ```
- Both `IKE_SA` and `CHILD_SA` verified `ESTABLISHED`/`INSTALLED` on `ns-left` and `ns-right` across all 4 profiles.

---

## FEAT-003: Core Repository Scaffolding & Provenance Data Models

### 1. Scope & Objectives
- Scaffold directory structure:
  - `tunneltwin/core` (Data models, provenance tagging)
  - `tunneltwin/ike` (IKE transforms, packet models)
  - `tunneltwin/probe` (Consent-gated active prober)
  - `tunneltwin/rules` (Compliance engines)
  - `tunneltwin/fix` (Automated remediation & diff generator)
  - `tunneltwin/capture` (Passive PCAP analyzer)
  - `tunneltwin/ml` (Inference engine with confidence scores)
  - `tunneltwin/seal` (Cryptographic Merkle audit trail)
  - `tunneltwin/api` (FastAPI REST backend)
  - `tunneltwin/cli` (CLI management tool)
  - `tunneltwin/ui` (Dark-mode web dashboard)
  - `lab/`, `tests/`, `docs/`
- Implemented four-tier provenance models: `OBSERVED`, `PARSED`, `INFERRED`, `UNKNOWN`.
- Implemented rule constraint: UNKNOWN facts cannot evaluate to pass.

### 2. Verification Log
- Full test suite in `tests/test_provenance.py` and `tests/test_phase0_matrix.py` passed with 7/7 tests passing in `pytest`.

---

## FEAT-004: Pure-Python Binary IKEv1/IKEv2 Codec & Elimination Proposals

### 1. Scope & Objectives
- Implement RFC-accurate IKEv1 and IKEv2 binary packet encoders/decoders without external packet manipulation libraries (Scapy).
- Complete IANA registry constants for encryption algorithms, integrity algorithms, PRFs, DH groups, payload types, exchange types, and notification messages.
- Support IKEv2 `IKE_SA_INIT` and IKEv1 `Main Mode` packet synthesis and parsing.
- Support elimination transform generator to probe cipher suites individually with exclusion lists.

### 2. Implementation Approach
- Authored `tunneltwin/ike/constants.py` with standard IANA protocol numbers and human-readable reverse lookups.
- Authored `tunneltwin/ike/codec.py` with pure `struct.pack`/`unpack` parsing, safe bounds checking, and custom `IKEParseError`.
- Authored `tunneltwin/ike/transforms.py` generating standard audit suites (NIST SP 800-77r1, CNSA 2.0, legacy, and aggressive sets) with exclusion mechanics.

### 3. Verification Log
- Authored 17 round-trip unit tests in `tests/test_ike_codec.py`:
  - IKE header build/parse
  - SA, KE, Nonce, Notify payload encoding/decoding
  - Non-ESP marker stripping for NAT-T (UDP 4500)
  - Cookie and Invalid KE response parsing
  - Malformed packet error handling
- All 17 tests passed with zero failures.
- Generated RFC 5903 compliant elliptic curve public points for ECP-256, ECP-384, ECP-521, and X25519 (raw uncompressed X || Y coordinates) to ensure strongSwan `libstrongswan-openssl.so` point validation succeeds.
- Enforced RFC 7296 §3.3 & RFC 5282 §4.2 rule that AEAD ciphers (e.g. AES-GCM) MUST NOT include Transform Type 3 (INTEG).

---

## FEAT-005: Consent-Gated UDP Prober Engine with Elimination Scanning

### 1. Scope & Objectives
- Implement double-barrier target allowlisting (IP/CIDR matching AND explicit `consent_verified=True` flag) per ADR-0003.
- Build asynchronous UDP client with exponential backoff, jitter, RFC 7296 cookie retry, and rate limiting.
- Tag all scan results with strict `OBSERVED` provenance.
- Support elimination scan: parallel DH group discovery, INVALID_KE_PAYLOAD preferred group recording, transform elimination until NO_PROPOSAL_CHOSEN.
- Fulfill Phase 1 Exit Criteria: scan 4 Phase-0 profiles plus 1 cookie-enforcing profile in live Linux network namespaces.

### 2. Implementation Approach
- Authored `tunneltwin/probe/allowlist.py` (`TargetAllowlist` with subnet containment and ownership tracking).
- Authored `tunneltwin/probe/result.py` (`GatewayScanResult`, `AcceptedTransform`, `IKEv1AcceptedTransform`, and `ScanStatus`).
- Authored `tunneltwin/probe/scanner.py` (`scan_gateway`, `_ikev2_discover_dh_groups`, `_ikev2_elimination_scan`, `_ikev1_scan`).
- Authored `lab/configs/cookie/{left.conf, right.conf}` and configured strongSwan `dos_protection = yes`, `cookie_threshold = 1`, `cookie_threshold_ip = 1` in `lab/start_charon.sh`.
- Authored `lab/run_phase1_scan.py` and `tests/test_phase1_matrix.py` to automate live netns execution.

### 3. Verification Log
- 11 unit tests for allowlist enforcement in `tests/test_probe_allowlist.py`.
- 10 unit tests for scanner logic in `tests/test_probe_scanner.py`.
- **Phase 1 Live Namespace Integration Scan (Empirical Output)**:
  ```text
  ================================================================================
                      PHASE 1 LIVE SCAN SUMMARY REPORT
  ================================================================================
  Profile      | IKE Ver  | Accepted DH            | Cookie   | Duration   | Status
  --------------------------------------------------------------------------------
  weak         | IKEv1    | (IKEv1)                | no       | 350.5ms    | PASS ✅
  mixed        | IKEv2    | MODP-1024              | no       | 291.1ms    | PASS ✅
  strong       | IKEv2    | ECP-384                | no       | 329.7ms    | PASS ✅
  legacy-cbc   | IKEv2    | MODP-2048              | no       | 303.4ms    | PASS ✅
  cookie       | IKEv2    | ECP-384                | YES ✅    | 692.5ms    | PASS ✅
  ================================================================================

  🎉 PHASE 1 EXIT CRITERIA MET: ALL 5 GATEWAYS VERIFIED ESTABLISHED AND REPORTED!
  ```
- Automated integration test `tests/test_phase1_matrix.py` verified passing in WSL2.

---

## FEAT-006: Fact Model, Provenance Tracking, and Probe Scan Bridge

### 1. Scope & Objectives
- Implement a typed Fact model where every cryptographic observation carries:
  - `subject`: Gateway identifier (`<ip>:<port>`)
  - `key`: Fact key (`ike_version`, `accepted_dh_group`, `cipher`, `integrity`, `prf`, `cookie_required`)
  - `value`: Fact value string
  - `provenance`: `OBSERVED`, `PARSED`, `INFERRED`, `UNKNOWN`
  - `confidence`: $\in [0.0, 1.0]$ (mandatory 1.0 for OBSERVED/PARSED, bounded for INFERRED)
  - `source_pointer`: Traceability back to the probe or configuration file
- Build `scan_result_to_facts`: A lossless bridge converting Phase 1 `GatewayScanResult` into indexed `FactStore`.
- Strict indexing: Multi-valued facts (multiple accepted DH groups, transforms) queryable by subject and key.

### 2. Implementation Approach
- Authored `tunneltwin/rules/facts.py` (`Fact`, `FactCategory`, `FactStore`, `scan_result_to_facts`).
- Validated `INFERRED` facts reject confidence outside $[0.0, 1.0]$ via `ValueError`.
- Added `is_known` property asserting `provenance != ProvenanceTag.UNKNOWN`.

### 3. Verification Log
- 7 unit tests in `tests/test_rules_engine.py::TestFactModel` verifying creation, confidence bounds, multi-values, and missing keys.
- 3 bridge tests in `tests/test_rules_engine.py::TestBridge` verifying lossless extraction from simulated Phase 0 scan results.

---

## FEAT-007: Standards-Based Rule Packs (NIST SP 800-77r1, NSA CNSA 2.0, CERT-In)

### 1. Scope & Objectives
- Create modular YAML rule packs citing authoritative cryptographic standards:
  - **NIST SP 800-77 Rev 1**: Protocol version, Diffie-Hellman groups, AES-GCM preference, 3DES deprecation, SHA-1 deprecation, AES-256 recommendation, DoS cookie protection (Section 4.3).
  - **NSA CNSA 2.0 Suite**: Strict 192-bit security floor (IKEv2, ECP-384+, AES-256, SHA-384+).
  - **CERT-In Advisory Pack**: Indian national cybersecurity guidelines; explicitly marked `"pending confirmation of source document"` with zero fabricated citations.
- Include YAML files in wheel/sdist packaging via `pyproject.toml` `[tool.setuptools.package-data]`.

### 2. Implementation Approach
- Authored `tunneltwin/rules/packs/nist_sp800_77r1.yaml` (9 rules).
- Authored `tunneltwin/rules/packs/nsa_cnsa.yaml` (4 rules).
- Authored `tunneltwin/rules/packs/cert_in.yaml` (4 rules).
- Updated `pyproject.toml` to package `tunneltwin.rules.packs/*.yaml`.

### 3. Verification Log
- 5 unit tests in `tests/test_rules_engine.py::TestRulePacks` verifying clean loading, required fields, and CERT-In pending citation disclaimer.
- `python -m build` verified bundling YAML assets into `.whl` and `.tar.gz`.

---

## FEAT-008: Declarative Rule Engine and Multi-Category Scoring Engine

### 1. Scope & Objectives
- Declarative rule condition evaluation: `equals`, `not_equals`, `in`, `not_in`, `version_min`.
- **`CANNOT_ASSESS` Invariant**: If any required fact is missing or `UNKNOWN`, the rule reports `AssessmentStatus.CANNOT_ASSESS`. It never generates a false PASS or false FAIL.
- **Multi-Category Scoring Algorithm**:
  - Starts at 100 points.
  - Subtracts category-weighted penalties: `protocol_version` (2.0x), `key_exchange` (1.5x), `encryption` (1.5x), `integrity` (1.2x), `exposure` (1.0x).
  - Floored at 0 points.
  - Tracks assessed coverage percentage: $\frac{\text{PASS} + \text{FAIL}}{\text{Total Rules}} \times 100\%$.
- **Exit Criteria**: The rule engine against the 4 Phase-0 profiles must produce distinct, correct scores and at least 1 finding per profile with the exact rule/clause cited.

### 2. Implementation Approach
- Authored `tunneltwin/rules/engine.py` (`Rule`, `RuleResult`, `RuleEngine`, `evaluate_rule`, `load_all_rule_packs`).
- Authored `tunneltwin/rules/scoring.py` (`CategoryScore`, `GatewayScore`, `compute_score`, `ScoringEngine`).
- Exposed public API in `tunneltwin/rules/__init__.py`.

### 3. Verification Log
- 13 unit tests across `TestRuleEvaluation`, `TestScoring`, and `TestCannotAssess` in `tests/test_rules_engine.py`.
- **Empirical Scoring & Findings Verification**:
  ```text
  weak        : score=  0, coverage=100.0%, findings=12 (NIST-001, NIST-004, CNSA-001, CERTIN-001)
  legacy-cbc  : score= 42, coverage=100.0%, findings= 8 (NIST-007, NIST-008, NIST-003, CNSA-003)
  mixed       : score= 47, coverage=100.0%, findings= 6 (NIST-002, NIST-005, CNSA-002, CERTIN-002)
  strong      : score= 99, coverage= 76.5%, findings= 1 (NIST-009 DoS Cookie Protection)
  ```
- All 4 scores strictly distinct (`weak < legacy-cbc < mixed < strong`), all 4 profiles carry cited findings, and all quality gates pass on GitHub CI.

---

## FEAT-009: strongSwan swanctl.conf Remediation Generator & Unified Diff

### 1. Scope & Objectives
- Generate valid, hardened strongSwan `swanctl.conf` configurations for target compliance profiles (`aes256gcm-baseline`, `nist-sp800-77r1`, `cnsa-suite`).
- Support initiator (left), responder (right), and paired configuration synthesis.
- Produce clean unified diffs comparing insecure baseline configurations against remediated configurations.

### 2. Implementation Approach
- Authored `tunneltwin/fix/models.py` (`SecurityProfile`, `RemediationConfig`, `generate_unified_diff`).
- Authored `tunneltwin/fix/profiles.py` defining standard profiles with IKEv2, AES-GCM-256, PRF-SHA384/256, ECP-384/256.
- Authored `tunneltwin/fix/swanctl_generator.py` (`generate_swanctl_conf`, `generate_swanctl_pair`).

### 3. Verification Log
- 3 unit tests in `tests/test_fix_generators.py::TestSwanctlGenerator` verifying content, pair generation, and unified diff output.

---

## FEAT-010: Cisco ASA Configuration Generator with Mandatory Verification Label

### 1. Scope & Objectives
- Synthesize Cisco ASA IKEv2 / IPsec site-to-site VPN configurations adhering to the same cryptographic compliance profile.
- **Mandatory Non-Functional Constraint**: Output MUST be labeled `"generated, not lab-verified"` everywhere it is displayed, formatted, or serialized.

### 2. Implementation Approach
- Authored `tunneltwin/fix/cisco_generator.py` (`generate_cisco_asa_config`).
- Enforced `CISCO_ASA_VERIFICATION_LABEL = "generated, not lab-verified"` in `content`, `verification_status`, `__str__`, `__repr__`, and `display()`.

### 3. Verification Log
- 2 unit tests in `tests/test_fix_generators.py::TestCiscoASAGenerator` asserting the label is present across all representation vectors and validating Cisco ASA IKEv2 policy, proposal, crypto map, and tunnel-group syntax.

---

## FEAT-011: Live Twin Check & Remediation Proof Engine

### 1. Scope & Objectives
- Implement the end-to-end Twin Check proof chain on live Linux network namespaces without mocked data:
  1. Old weak configuration applied in lab $\implies$ weak baseline tunnel establishes $\implies$ active scan confirms findings (`NIST-001`, `NIST-004`).
  2. Remediated configuration applied $\implies$ twin confirms tunnel still works on both peers $\implies$ ICMP ping passes across tunnel.
  3. Re-scan confirms baseline findings cleared and posture score improves from 0 to 99/100.
  4. Remediated tunnel re-established.

### 2. Implementation Approach
- Authored `tunneltwin/fix/twin.py` (`TwinVerifier`, `TwinCheckResult`).
- Authored `lab/run_phase3_twin.py` and `lab/run_phase3_twin.sh` for non-mocked live netns execution.
- Authored integration test `tests/test_phase3_matrix.py`.

### 3. Verification Log
- **Live Netns Proof Execution (`python3 lab/run_phase3_twin.py`)**:
  ```text
  ================================================================================
          PHASE 3 EXIT CRITERIA EVALUATION (LIVE, NON-MOCKED EVIDENCE)
  ================================================================================
    [PASS] Baseline findings reproduced: NIST-001, NIST-004
    [PASS] Weak baseline tunnel established (old config applied in lab)
    [PASS] Remediated tunnel establishes on both peers
    [PASS] Data-plane ping passes through remediated tunnel
    [PASS] Findings cleared on re-scan: NIST-001, NIST-004
    [PASS] Remediated tunnel re-establishes after re-scan
    [PASS] TwinCheckResult.passed
  ================================================================================
  PHASE 3 EXIT CRITERIA MET: weak finding present -> config remediated ->
  tunnel verified on real output -> re-scan confirms the finding cleared.
  ```
- Pytest integration test `tests/test_phase3_matrix.py` PASSED in WSL2.


---

## FEAT-012: Multi-Daemon Testbed Substrate (Libreswan in Network Namespaces)

### 1. Scope & Objectives
- Deploy Libreswan (pluto daemon) alongside strongSwan (charon daemon) in independent Linux network namespaces.
- Support simultaneous execution without packaging conflicts, library collisions, or socket path overlaps.
- Provide automated lifecycle scripts (`lab/start_libreswan.sh`, `lab/stop_libreswan.sh`) with isolated NSS database (`cert9.db`), private runtime directory (`/tmp/tunneltwin/<ns>/run`), and whack control socket (`pluto.ctl`).

### 2. Implementation Approach
- Resolved Ubuntu/Debian packaging conflict by isolating Libreswan binaries in `/opt/libreswan` and symlinking `/usr/libexec/ipsec` and `/usr/local/sbin/ipsec` to allow both daemons to coexist concurrently.
- Automated NSS certificate database initialization with `certutil -N` in headless empty-password mode.
- Prevented pluto lock-file race conditions by permitting pluto to manage its own PID file in runtime directories.

### 3. Verification Log
- Pluto successfully spawned in `ns-libreswan` (`PID: 466`, socket `/tmp/tunneltwin/ns-libreswan/run/pluto.ctl`) while strongSwan ran in `ns-left`.
- Clean teardown verified via `lab/stop_libreswan.sh` and XFRM policy flushing.


---

## FEAT-013: Behavioral Daemon Fingerprinting Engine (RFC Payload Quirks)

### 1. Scope & Objectives
- Detect responder daemon implementation (`strongswan`, `libreswan`, `cisco_asa`, `unknown`) purely through observable protocol behaviors, notification payload combinations, and RFC quirks rather than static assumptions or manual declarations.
- Required confidence threshold $\ge 0.70$ (empirically achieved $0.95$).
- Record classification with `OBSERVED` provenance in the fact store for downstream compliance evaluation.

### 2. Implementation Approach
- Authored `tunneltwin/probe/fingerprint.py` defining `DaemonType`, `DaemonFingerprint`, and `classify_daemon(msg, rtt_ms)`.
- Decision logic:
  * Libreswan quirk: Unsolicited `NAT_DETECTION_SOURCE_IP` (16388) and `NAT_DETECTION_DESTINATION_IP` (16389) emitted in `IKE_SA_INIT` responses without client request; strongSwan signature hash (16404) absent; notify 16418 present $\implies$ `DaemonType.LIBRESWAN` (0.95 confidence).
  * strongSwan quirk: RFC 7427 `SIGNATURE_HASH_ALGORITHMS` (16404) emitted; unsolicited NAT-D omitted $\implies$ `DaemonType.STRONGSWAN` (0.95 confidence).
  * Cisco ASA quirk: Private vendor IDs (`12f5f28c...`) or private notify codes (16400-16402) $\implies$ `DaemonType.CISCO_ASA` (0.90-1.0 confidence).
- Integrated into `tunneltwin/probe/scanner.py` and `tunneltwin/rules/facts.py` (`key="daemon_type"`).

### 3. Verification Log
- Verified against live Libreswan responder in `ns-libreswan`:
  ```text
  --> Fingerprint Result: LIBRESWAN (Confidence: 95.0%) — Evidence: Libreswan signature: Unsolicited NAT_DETECTION (16388/16389) emitted; SIGNATURE_HASH (16404) absent; Notify 16418 (REDIRECT_SUPPORTED / CHILDLESS_IKE_SA_SUPPORTED) present
      * Evidence: Libreswan signature: Unsolicited NAT_DETECTION (16388/16389) emitted; SIGNATURE_HASH (16404) absent
      * Evidence: Notify 16418 (REDIRECT_SUPPORTED / CHILDLESS_IKE_SA_SUPPORTED) present
  [OK] Libreswan behaviorally fingerprinted with >= 90% confidence via payload quirks!
  ```
- 10 unit tests in `tests/test_fingerprint.py` all passed.


---

## FEAT-014: Libreswan Remediation Generator & Cross-Daemon Interoperability Proof

### 1. Scope & Objectives
- Generate compliant `ipsec.conf` connection configurations and `ipsec.secrets` for Libreswan matching target security profiles (`aes256gcm-baseline`, `nist-sp800-77r1`, `cnsa-suite`).
- Label all Libreswan generated configurations with `lab-verified` status.
- Re-run the fix-and-prove chain against a Libreswan namespace:
  1. Weak baseline finding reproduced against Libreswan namespace (`score = 71/100`).
  2. Remediated Libreswan config applied.
  3. Cross-daemon IPsec SA established between strongSwan (`ns-left`) and Libreswan (`ns-libreswan`).
  4. Data-plane ICMP ping verified across tunnel with 0% packet loss.
  5. Active prober re-scan confirms findings cleared and score improved to 99/100.

### 2. Implementation Approach
- Authored `tunneltwin/fix/libreswan_generator.py` (`generate_libreswan_config`, `generate_libreswan_secrets`).
- Updated `SecurityProfile` in `models.py` and `profiles.py` with Libreswan algorithm syntax (`libreswan_ike`, `libreswan_esp`).
- Authored `lab/run_phase4_multi_daemon.py` and `lab/run_phase4_multi_daemon.sh`.
- Authored integration test `tests/test_phase4_matrix.py`.

### 3. Verification Log
- Cross-daemon tunnel established on live daemons:
  * strongSwan active SA: `AES_GCM_16-256/PRF_HMAC_SHA2_384/ECP_384`, Child SA `ESP:AES_GCM_16-256`.
  * Libreswan active traffic status: `#2: "swan-interop", type=ESP, add_time=1790609185, id='10.0.1.1'`.
- Data-plane ICMP ping across tunnel:
  ```text
  3 packets transmitted, 3 received, 0% packet loss, time 2052ms
  rtt min/avg/max/mdev = 0.050/0.071/0.087/0.015 ms
  ```
- Re-scan confirmed findings cleared:
  * Cleared findings: `NIST-005` (AES-GCM Preferred over AES-CBC), `CNSA-002` (Minimum ECP-384 Required), `CNSA-004` (SHA-384 Minimum Integrity).
  * Posture score improved from 71 to 99/100.
  * Re-scan reaffirmed daemon fingerprint: `LIBRESWAN (Confidence: 95.0%)`.
- `tests/test_phase4_matrix.py` PASSED in WSL2.


