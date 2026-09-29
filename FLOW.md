# TunnelTwin — End-to-End Execution Traceability (FLOW.md)

> **Execution Architecture**: This document maps the exact control and data flow across TunnelTwin modules. It illustrates how inputs (configs, active probes, PCAP captures) enter the system, how data is parsed, normalized, assessed, remediated, and rendered.

---

## 1. High-Level System Architecture

```
                  ┌────────────────────────────────────────┐
                  │              INPUT SOURCES             │
                  │  (Config Files, Active Scans, PCAPs)   │
                  └───────────────────┬────────────────────┘
                                      │
           ┌──────────────────────────┼──────────────────────────┐
           ▼                          ▼                          ▼
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│  tunneltwin.rules   │    │  tunneltwin.probe   │    │ tunneltwin.capture  │
│  (Config Parser)    │    │  (IKE Active Probe) │    │ (PCAP/Live Traffic) │
│  [Provenance:       │    │  [Provenance:       │    │ [Provenance:        │
│   PARSED]           │    │   OBSERVED]         │    │  OBSERVED]          │
└──────────┬──────────┘    └──────────┬──────────┘    └──────────┬──────────┘
           │                          │                          │
           └──────────────────────────┼──────────────────────────┘
                                      ▼
                        ┌───────────────────────────┐
                        │     tunneltwin.core       │
                        │ (Normalized Schema & Fact │
                        │   Provenance Store)       │
                        └─────────────┬─────────────┘
                                      │
              ┌───────────────────────┴───────────────────────┐
              ▼                                               ▼
┌───────────────────────────┐                   ┌───────────────────────────┐
│      tunneltwin.ml        │                   │    tunneltwin.rules       │
│  (Heuristic / Inference)  │                   │  (Compliance Assessment)  │
│  [Provenance: INFERRED    │                   │  NIST SP 800-77r1 / ANSSI │
│   + Confidence Score]     │                   │  Reports: PASS/FAIL/      │
└─────────────┬─────────────┘                   │  "CANNOT ASSESS"          │
              │                                 └─────────────┬─────────────┘
              └───────────────────────┬───────────────────────┘
                                      │
                        ┌─────────────┴─────────────┐
                        ▼                           ▼
          ┌───────────────────────────┐ ┌───────────────────────────┐
          │     tunneltwin.fix        │ │     tunneltwin.seal       │
          │  (Remediation Engine &    │ │ (Merkle Integrity Audit   │
          │   Unified Diff Generator) │ │  Trail & Proof Signer)    │
          └─────────────┬─────────────┘ └─────────────┬─────────────┘
                        │                             │
                        └──────────────┬──────────────┘
                                       ▼
                        ┌───────────────────────────┐
                        │   tunneltwin.api / cli    │
                        │    & Dashboard (UI)       │
                        └───────────────────────────┘
```

---

## 2. Module Execution Flow Matrix

| Stage | Triggering Component | Target Component | Core Functions / Methods | Data Artifact Passed |
|---|---|---|---|---|
| **0. Lab Substrate** | `lab/run_matrix.py` | `lab/setup_namespaces.sh` | `setup_netns()`, `start_charon()`, `test_profile()` | Network namespaces `ns-left`, `ns-right`, IPsec SAs |
| **1. Ingestion** | CLI / API / Lab | `tunneltwin.core.models` | `NormalizedIPsecConfig`, `ProvenanceTag` | Typed schema instances with explicit provenance tags |
| **2. Active Probing** | `tunneltwin.cli` | `tunneltwin.probe.engine` | `IKEProber.probe_target()` gated by `TargetAllowlist.verify()` | Non-intrusive proposal packets $\to$ observed cipher suites |
| **3. Compliance Check**| `tunneltwin.rules` | `tunneltwin.rules.engine` | `PolicyEngine.evaluate(target_config)` | Compliance report (Pass / Fail / Cannot Assess) |
| **4. Remediation** | `tunneltwin.fix` | `tunneltwin.fix.generator`| `RemediationEngine.generate_diff()` | Hardened config string & unified colorized diff |
| **5. Audit Sealing** | `tunneltwin.seal` | `tunneltwin.seal.merkle` | `AuditLog.append_record()`, `MerkleTree.get_root()` | Cryptographic audit receipt with SHA-256 Merkle root |

---

## 3. Current Phase (Phase 0) Execution Path

```
[lab/run_matrix.py] (Orchestrator)
        │
        ├─► Executes `lab/setup_namespaces.sh`
        │       ├─ Creates Linux netns `ns-left` & `ns-right`
        │       ├─ Creates veth pair `veth-left` <-> `veth-right`
        │       ├─ Assigns IPs: 10.0.1.1/30 (ns-left), 10.0.1.2/30 (ns-right)
        │       └─ Configures loopback and MTU
        │
        ├─► Spawns isolated strongSwan `charon` per namespace:
        │       ├─ ns-left: STRONGSWAN_CONF=/var/run/tunneltwin/ns-left/strongswan.conf
        │       └─ ns-right: STRONGSWAN_CONF=/var/run/tunneltwin/ns-right/strongswan.conf
        │
        ├─► Iterates through profiles: [weak, mixed, strong, legacy-cbc]
        │       ├─ Deploys swanctl.conf to left & right
        │       ├─ swanctl --load-all (per namespace)
        │       ├─ swanctl --initiate --ike <profile_conn> (from ns-left)
        │       ├─ swanctl --list-sas (from ns-left & ns-right)
        │       └─ Verifies ESTABLISHED state on both sides
        │
        └─► Logs full stdout/stderr verification evidence
```
