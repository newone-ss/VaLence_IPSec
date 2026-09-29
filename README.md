# Valence_IPSec

[![CI](https://github.com/newone-ss/VaLence_IPSec/actions/workflows/ci.yml/badge.svg)](https://github.com/newone-ss/VaLence_IPSec/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![Code style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Type Checked: mypy](https://img.shields.io/badge/type--check-mypy-blue)](https://mypy-lang.org/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

> **IPsec VPN Protocol Analyzer & Automated Security Assessment Framework**  
> Developed for **Smart India Hackathon (SIH) 2026** — Problem Statement **26160**  
> Organization: **National Technical Research Organisation (NTRO)**

---

## Overview

**Valence_IPSec** (engine: `tunneltwin`) is an IPsec protocol assessment and automated hardening engine designed for defense, intelligence, and enterprise network architectures. 

Traditional VPN audits suffer from a fundamental disconnect: static configuration audits miss live cryptographic negotiation realities and NAT-traversal edge cases, while black-box network scanners cannot inspect pre-shared keys, routing domains, or internal Phase 2 security associations. Valence_IPSec bridges this gap through **dual-perspective reconciliation**—merging passive configuration parsing (Cisco IOS, strongSwan, FortiOS) with safe, consent-gated active IKE probing (RFC 7296 / RFC 2409)

Every assessment fact carries strict provenance metadata, preventing false assurances by rejecting evaluations based on missing or unverified parameters.

---

## Architecture.

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
│  (Config Parser)    │    │  (IKE Active Probe) │    │ (PCAP/Live Wire)    │
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
│  (Parameter Inference)    │                   │  (Compliance Assessment)  │
│  [Provenance: INFERRED    │                   │  NIST SP 800-77r1 / ANSSI │
│   + Confidence Metric]    │                   │  Status: PASS / FAIL /    │
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

## Core Engineering Principles

### 1. Four-Tier Fact Provenance
Every parameter in the system is explicitly bound to a provenance tag:
- **`OBSERVED`**: Verified directly via active packet exchange or wire capture.
- **`PARSED`**: Extracted from static configuration files.
- **`INFERRED`**: Predicted through heuristic inference, accompanied by a numeric confidence score in `[0.0, 1.0]`.
- **`UNKNOWN`**: Unobserved or missing parameters. **Zero False Passes**: Compliance rules requiring an unknown parameter output `"cannot assess"` rather than passing by default.

### 2. Double-Barrier Consent Gating
Active probing is restricted by design. Probing operations require two simultaneous conditions:
1. Target IP or subnet must fall within a registered `TargetAllowlist`.
2. The allowlist entry must carry an explicit `consent_verified=True` authorization flag.

Probing employs single-transform elimination sweeps to map accepted cryptographic suites without aggressive-mode PSK cracking or intrusive handshake attempts.

### 3. Pure-Python Binary Codec
The IKE engine uses a zero-dependency binary encoder/decoder (`struct`-based) implementing RFC 7296 (IKEv2) and RFC 2409 (IKEv1). It natively handles:
- Payload packing/unpacking (SA, KE, Nonce, Notify).
- NAT-Traversal (NAT-T) UDP encapsulation and Non-ESP marker stripping on port 4500.
- Cookie handling (`v2N_COOKIE`) for anti-DoS mitigation (RFC 7296 §2.6).
- `INVALID_KE_PAYLOAD` negotiation retries.

### 4. Cryptographic Merkle Audit Trail
Every scan, evaluation, and remediation action generates a tamper-evident record chained into a SHA-256 Merkle tree. Outputs include verifiable cryptographic receipts proving assessment integrity.

---

## Repository Structure

```text
VaLence_IPSec/
├── tunneltwin/               # Core framework package
│   ├── core/                 # Normalized models, provenance tags, schemas
│   ├── ike/                  # Binary IKEv1/v2 codec, constants, transform generator
│   ├── probe/                # Consent-gated active UDP prober & elimination scanner
│   ├── rules/                # NIST SP 800-77r1, ANSSI, RFC 9395 compliance rules
│   ├── fix/                  # Remediation engine & vendor-specific diff generator
│   ├── capture/              # PCAP parser & live interface capture engine
│   ├── ml/                   # Parameter inference engine with confidence metrics
│   ├── seal/                 # Cryptographic Merkle audit tree & receipt generator
│   ├── api/                  # FastAPI REST service
│   ├── cli/                  # Command-line interface
│   └── ui/                   # Web interface & dashboard
├── lab/                      # Linux network namespace testbed (zero Docker)
│   ├── configs/              # Multi-tier strongSwan connection profiles
│   ├── setup_namespaces.sh   # Creates ns-left, ns-right, and veth links
│   ├── start_charon.sh       # Spawns isolated charon daemons with private tmpfs
│   ├── stop_charon.sh        # Clean daemon shutdown
│   ├── teardown_namespaces.sh# Network namespace removal
│   └── run_matrix.sh         # Automated 4-profile test runner
├── tests/                    # Test suite (unit, round-trip, matrix)
├── docs/                     # Specifications, ADRs, compliance profiles
├── CHECKLIST.md              # Fast verification checklist
├── VERIFICATION.md           # Concrete verification protocol ("no vibe checks")
├── ROLLBACK.md               # Incident response & git rollback safety net
├── HANDOVER.md               # Project lifecycle & phase transition tracker
├── FEATURE.md                # Feature scoping, execution, and verification logs
└── BUG.md                    # Bug discovery, diagnosis, and resolution traces
```

---

## Getting Started

### Prerequisites

- **Python**: 3.10, 3.11, or 3.12
- **Operating System**: Linux or WSL2 (Ubuntu 22.04+ recommended) for namespace lab testing; cross-platform (Windows, macOS, Linux) for code development and unit tests.
- **System Tools (Lab testing only)**: `iproute2`, `iptables`, `strongswan`, `strongswan-swanctl`.

### Installation

```bash
# Clone the repository
git clone https://github.com/newone-ss/VaLence_IPSec.git
cd VaLence_IPSec

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1

# Install package in editable mode with development dependencies
pip install --upgrade pip
pip install -e ".[dev]"
```

---

## Verification & Testing

Valence_IPSec maintains a strict verification protocol: every pull request and milestone must pass all quality gates cleanly.

Run the local verification suite:

```bash
# 1. Lint check
ruff check .

# 2. Format check
ruff format --check .

# 3. Static type analysis
mypy tunneltwin --ignore-missing-imports

# 4. In-memory unit test suite
pytest -v tests/ -k "not phase0"
```

### Full Verification One-Liner

```bash
ruff check . && ruff format --check . && mypy tunneltwin --ignore-missing-imports && pytest -v tests/ -k "not phase0"
```

### Linux Network Namespace Lab Testbed

The lab substrate validates IKE/IPsec behavior across isolated Linux network namespaces (`ns-left` $\leftrightarrow$ `ns-right`) over a point-to-point `veth` pair (`10.0.1.1/30` and `10.0.1.2/30`):

```bash
# Execute the automated 4-tier profile matrix (requires root / sudo in Linux/WSL2)
sudo bash lab/run_matrix.sh
```

**Profiles Tested in Matrix:**
| Profile | Protocol | Cryptographic Suite | Target Purpose |
|---|---|---|---|
| `weak` | IKEv1 | 3DES-CBC / SHA1 / MODP-1024 | Legacy vulnerability baseline |
| `mixed` | IKEv2 | AES-256-CBC / SHA384 / ECP-384 + MODP-1024 fallback | Mixed-migration compatibility |
| `strong` | IKEv2 | AES-256-GCM / SHA384 / ECP-384 | Modern high-security profile |
| `legacy-cbc` | IKEv2 | AES-128-CBC / SHA1 / MODP-2048 | Deprecated cipher audit |

---

## Programmatic Usage

### Running the Consent-Gated Scanner

```python
import asyncio
from tunneltwin.probe.allowlist import TargetAllowlist
from tunneltwin.probe.scanner import ScanConfig, scan_gateway

# 1. Define authorized target with explicit consent
allowlist = TargetAllowlist()
allowlist.add(
    "10.0.1.0/30", consent_verified=True, owner="Security-Operations-Center", description="Lab testbed gateway"
)

# 2. Configure probe timeouts and backoff
config = ScanConfig(
    initial_timeout_ms=500,
    max_retries=2,
    rate_limit_pps=10.0,
)


# 3. Execute asynchronous probe against target
async def main():
    result = await scan_gateway("10.0.1.1", allowlist, config)
    print(result.summary())


asyncio.run(main())
```

---

## Development & Operations Documentation

Valence_IPSec maintains comprehensive operational records to guarantee consistency across teams and sessions:

- **[CHECKLIST.md](CHECKLIST.md)**: Concrete pre-commit verification checklist.
- **[VERIFICATION.md](VERIFICATION.md)**: Full verification protocol with exact expected outputs and negative invariant assertions.
- **[ROLLBACK.md](ROLLBACK.md)**: Eight step-by-step rollback recipes and triage matrix for accidental regressions.
- **[HANDOVER.md](HANDOVER.md)**: Session continuity ledger tracking active phases and blockers.
- **[FEATURE.md](FEATURE.md)**: Complete feature traceability from scoping to verification.
- **[BUG.md](BUG.md)**: Discovery, root-cause diagnosis, and resolution evidence for all tracked issues.
- **[FLOW.md](FLOW.md)**: End-to-end data and control flow mapping.

---

## Security & Ethics

Valence_IPSec is designed exclusively for authorized network assessment, compliance auditing, and defensive hardening. Active scanning features cannot be executed without programmatic target allowlisting and verified organizational consent.

---

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
