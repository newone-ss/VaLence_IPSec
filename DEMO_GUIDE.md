# TunnelTwin — Judge Demonstration & Execution Guide
**Smart India Hackathon 2026 | Problem Statement 26160 (NTRO)**  
*AI-Powered IPsec VPN Protocol Analyzer & Automated Security Assessment Framework*

---

## 🎯 Executive Pitch for Judges (30-Second Opening)

> *"Good morning/afternoon, esteemed judges.  
> Across critical infrastructure, defense, and government networks, thousands of IPsec VPN tunnels protect sensitive communications. Yet, many still silently run deprecated cryptographic protocols (IKEv1, 3DES, weak Diffie-Hellman groups) vulnerable to eavesdropping and quantum attacks.  
> 
> **TunnelTwin (Valence-IPsec)** solves this with a 4-pillar zero-trust pipeline:  
> 1. **Active Non-Intrusive Probing**: Discovers supported cipher suites without needing credentials or pre-shared keys.  
> 2. **Authoritative Compliance Engine**: Evaluates tunnels strictly against NIST SP 800-77 Rev 1 and NSA CNSA Suite 2.0.  
> 3. **Digital Twin Fix-and-Prove**: Automatically generates vendor-specific hardened configuration patches and verifies them in a digital twin testbed before touching production.  
> 4. **Cryptographic Trust Layer**: Seals findings in a SHA-256 Merkle Tree signed with Ed25519, making audit tampering mathematically detectable."*

---

## 📋 Demonstration Cheat Sheet (Recommended 5-Minute Flow)

| Step | Action / Command | What It Demonstrates | Time |
| :---: | :--- | :--- | :---: |
| **1** | `python -m pytest tests/ -v` | Engineering rigor: 123 automated tests passing | 30s |
| **2** | `python -m tunneltwin.cli.main report 24` | Comprehensive audit report of real scanned gateway | 45s |
| **3** | Open `reports/report_run_24.html` | Visual, executive-ready HTML compliance dashboard | 45s |
| **4** | `python -m tunneltwin.cli.main fix 24` | Automated remediation diff (weak IKEv1 -> secure IKEv2) | 45s |
| **5** | `python -m tunneltwin.cli.main prioritize 24` | Risk-based prioritization for remediation | 30s |
| **6** | **The Tamper Test** (`verify 24` -> edit DB -> `verify 24`) | **Cryptographic Merkle Seal & Tamper Detection** | 90s |
| **7** | `python -m tunneltwin.cli.main attest 24` | Signed legal/compliance certificate with Ed25519 signature | 45s |
| **8** | `python -m tunneltwin.cli.main emulator simulate -n 50` | Scale simulation: handles 50+ enterprise nodes in seconds | 30s |

---

## 🚀 Detailed Step-by-Step Walkthrough

---

### STEP 1: Prove System Engineering & Robustness (Test Suite)

#### 💻 Command to Run:
```bash
python -m pytest tests/ -v
```

#### ❓ Why use it?
Judges frequently see hackathon projects that are just mock UIs or static scripts. This command immediately proves that TunnelTwin is a fully functional, enterprise-grade software system with comprehensive unit and integration testing.

#### ⚙️ What happens under the hood?
Pytest executes **123 automated test cases** covering:
- Binary IKEv2/IKEv1 packet encoder and decoder (`struct`-based, zero Scapy dependency).
- Consent-gated double-barrier target allowlisting.
- Declarative compliance rule evaluator (NIST, CNSA, CERT-In).
- Automated configuration patch generators (strongSwan, Libreswan, Cisco ASA).
- PCAP parser, RFC 4303 candidate cipher set solvers, and ML feature extractors.
- SQLite fleet store and Merkle tree cryptographic signature verification.

#### 🗣️ What to say to the Judge:
> *"Before demonstrating the interface, we want to show that our backend is 100% production-ready. We have 123 automated tests verifying our custom packet codec, cryptographic mathematical trees, and compliance rules with zero failures."*

---

### STEP 2: Audit a Scanned Gateway (Terminal Report)

#### 💻 Command to Run:
```bash
python -m tunneltwin.cli.main report 24
```

#### ❓ Why use it?
Shows the real findings and compliance score for an audited IPsec gateway (**ScanRun #24** in the database).

#### ⚙️ What happens under the hood?
1. Fetches observed gateway parameters (`10.0.1.2:500`, IKEv1, 3DES, MODP-1024).
2. Evaluates them against active rule packs:
   - **NIST SP 800-77 Rev 1** (prohibits 3DES, requires minimum 2048-bit DH).
   - **NSA CNSA Suite 2.0** (mandates IKEv2 and ECP-384 / AES-256).
3. Renders a Rich-formatted audit table displaying findings categorized by severity (**CRITICAL**, **HIGH**, **MEDIUM**, **INFO**) with factual provenance (`OBSERVED`).
4. Displays the proposed configuration diff and Merkle root at the bottom.

#### 🗣️ What to say to the Judge:
> *"Here is the audit result for a scanned gateway running an unhardened legacy configuration. The system identified multiple CRITICAL violations: it's using deprecated IKEv1, weak 1024-bit Diffie-Hellman keys vulnerable to precomputation, and outdated 3DES encryption. Every fact is tagged with strict cryptographic provenance—meaning we never guess."*

---

### STEP 3: Present the Executive HTML Dashboard

#### 💻 Command to Run:
```bash
python -m tunneltwin.cli.main report 24 -f html -o reports/report_run_24.html
```
*(Then double-click `reports/report_run_24.html` to open it in your browser, or open it directly).*

#### ❓ Why use it?
Technical command-line outputs are great for engineers, but CISOs, compliance officers, and executive leadership require clean, visual reporting.

#### ⚙️ What happens under the hood?
Generates a 100% self-contained, offline-compatible HTML5 document featuring:
- Executive Summary Scorecard (Total findings, critical count, compliance breakdown).
- High-contrast visual badges for NIST SP 800-77r1 and NSA CNSA 2.0 violations.
- Side-by-side unified configuration diff block.
- Embedded Merkle seal and audit receipt.

#### 🗣️ What to say to the Judge:
> *"For security managers and compliance directors, TunnelTwin automatically exports a self-contained, interactive HTML audit report. It color-codes non-compliant parameters, cites exact federal and defense standards, and provides the exact remediation patch."*

---

### STEP 4: Automated Remediation Diff (Fix-and-Prove)

#### 💻 Command to Run:
```bash
python -m tunneltwin.cli.main fix 24
```

#### ❓ Why use it?
Most vulnerability scanners only tell you what is broken. TunnelTwin **generates the solution**—a precise, vendor-specific configuration patch that upgrades the tunnel to modern security standards.

#### ⚙️ What happens under the hood?
1. Takes the open vulnerabilities (e.g. `CNSA-001`, `NIST-002`, `NIST-004`).
2. Selects the appropriate security baseline profile (`aes256gcm-baseline`: IKEv2, AES-256-GCM, SHA-384, ECP-384).
3. Synthesizes a valid, hardened configuration file (`swanctl.conf`) and generates a unified `git diff` comparing the insecure baseline with the hardened configuration.
4. *(In our Linux lab testbed, this patched configuration was deployed into a Digital Twin namespace, established the tunnel, and re-scanned—raising the security score from 0 to 99).*

#### 🗣️ What to say to the Judge:
> *"TunnelTwin doesn't just detect vulnerabilities—it fixes them. Here is an automated unified diff for strongSwan. It upgrades the gateway from insecure IKEv1/3DES to modern IKEv2 with AES-256-GCM and Curve P-384. In our digital twin testbed, we verified that this patch brought the tunnel up with zero packet loss and raised the compliance score from 0 to 99."*

---

### STEP 5: Remediation Prioritization Matrix

#### 💻 Command to Run:
```bash
python -m tunneltwin.cli.main prioritize 24
```

#### ❓ Why use it?
Security teams with limited time cannot fix 20 issues simultaneously. They need to know which finding to remediate first to maximize risk reduction.

#### ⚙️ What happens under the hood?
Calculates an exploitability and impact score for each finding, sorting them so that critical cryptographic weaknesses (like weak Diffie-Hellman groups and deprecated protocols) appear at the top.

#### 🗣️ What to say to the Judge:
> *"When managing a fleet of hundreds of gateways, administrators suffer from alert fatigue. Our prioritization engine ranks findings so network engineers know exactly which parameter to fix first for maximum risk reduction."*

---

### STEP 6: Cryptographic Seal & The "Tamper Detection" Demo (THE SHOWSTOPPER)

This is the most impressive part of the demo: proving mathematically that audit findings cannot be secretly altered or forged.

#### Part A: Verify Untouched Data (VALID)
```bash
python -m tunneltwin.cli.main verify 24
```
**Output:**  
`[+] VALID -- Cryptographic Merkle Seal & Ed25519 Signature Verified`  
`Integrity Status: VALID` (Exit code: 0)

#### Part B: Tamper with One Byte in the Database
Simulate an attacker or rogue insider altering the audit database:
```powershell
python -c "import sqlite3; con = sqlite3.connect('tunneltwin.db'); con.execute('UPDATE finding SET detail = detail || \'!\' WHERE id = 4'); con.commit(); con.close()"
```

#### Part C: Re-run Verify (TAMPERED)
```bash
python -m tunneltwin.cli.main verify 24
```
**Output:**  
`[!] TAMPERED -- Cryptographic Integrity Verification Failed`  
`TAMPER DETECTED: Recomputed Merkle root does not match stored seal root.`  
*(Notice the command exits with code 1)*

#### Part D: Restore the Database and Verify Again (VALID)
```powershell
python -c "import sqlite3; con = sqlite3.connect('tunneltwin.db'); con.execute('UPDATE finding SET detail = SUBSTR(detail, 1, LENGTH(detail)-1) WHERE id = 4'); con.commit(); con.close()"
python -m tunneltwin.cli.main verify 24
```
**Output:**  
`[+] VALID -- Cryptographic Merkle Seal & Ed25519 Signature Verified`

#### 🗣️ What to say to the Judge:
> *"In compliance auditing, integrity is everything. A corrupt administrator or attacker might tamper with database records to falsely claim compliance.  
> In TunnelTwin, every finding and remediation is hashed into a binary SHA-256 Merkle tree and signed with an Ed25519 private key.  
> As you just saw live: when the data was untouched, verification reported VALID. We then modified a single character in the database, and `tunneltwin verify` instantly detected the tamper and failed. When restored, it immediately passed again. This provides mathematical non-repudiation."*

---

### STEP 7: Signed Compliance Attestation Certificate

#### 💻 Command to Run:
```bash
python -m tunneltwin.cli.main attest 24
```
*(Open [`reports/attestation_run_24.md`](file:///c:/Users/piyus/OneDrive/Desktop/project/Shield/reports/attestation_run_24.md) to inspect the document).*

#### ❓ Why use it?
Provides an official, deterministically generated certificate ready for submission to regulatory bodies (NTRO, CERT-In, NIST auditors).

#### ⚙️ What happens under the hood?
1. Aggregates the gateway identity, evaluated criteria, findings, and remediation diff.
2. Formats a formal Markdown certificate citing authoritative frameworks (**NIST SP 800-77 Rev 1** and **NSA CNSA Suite 2.0**).
3. Appends the SHA-256 Merkle root, the operator's Ed25519 public key, and the 64-byte Ed25519 digital signature.
4. Includes the exact independent verification command: `tunneltwin verify 24`.

#### 🗣️ What to say to the Judge:
> *"Finally, TunnelTwin outputs a Signed Compliance Attestation Certificate. This document is deterministic—there are no hallucinations or LLMs involved. At the bottom is the cryptographic seal and public key. Anyone with this certificate can run `tunneltwin verify 24` to independently confirm that this audit was certified by an authorized operator."*

---

### STEP 8: Large-Scale Fleet Simulation

#### 💻 Command to Run:
```bash
python -m tunneltwin.cli.main emulator simulate -n 50
```

#### ❓ Why use it?
Shows that TunnelTwin is not just a single-tunnel tool; it is a fleet-wide management system capable of analyzing enterprise networks.

#### ⚙️ What happens under the hood?
Asynchronously simulates 50 IPsec gateways across multiple IP subnets with realistic network latency, varying vendor daemons (Cisco, strongSwan, Fortinet), NAT traversal, and security postures, ingesting all findings and sealing the batch with a Merkle root in under 1 second.

#### 🗣️ What to say to the Judge:
> *"In large organizations, security teams oversee hundreds or thousands of VPN endpoints. Our asynchronous engine can simulate and audit 50 enterprise nodes in less than a second, scaling smoothly across entire subnets."*

### STEP 9: Full-Stack Integration (FastAPI Backend + React Frontend)

#### 💻 1. Start the FastAPI Backend:
Open Terminal 1:
```bash
python -m uvicorn tunneltwin.api.app:app --host 127.0.0.1 --port 8000 --reload
```
- **Backend URL:** `http://127.0.0.1:8000`
- **Interactive Swagger Docs:** `http://127.0.0.1:8000/docs` (Judges can test any API live in the browser)

#### 💻 2. Start the Frontend Dashboard:
Open Terminal 2:
```bash
cd frontend
npm run dev
```
- **Frontend URL:** `http://localhost:5173`

#### ❓ What to show the Judges:
1. **Interactive Probe Execution:**
   - In the frontend, navigate to **Live probe** (`/probe`).
   - Enter target: `10.0.1.2`, port: `500`, profile: `IKE negotiation discovery`.
   - Click **Run live probe**.
   - Notice that the **backend terminal immediately logs**:
     ```text
     INFO: 127.0.0.1:... - "POST /api/probe HTTP/1.1" 200 OK
     ```
   - The frontend updates live with:
     - State: `COMPLETED`
     - Discovered: `IKEv1`
     - Identified Vendor: `cisco_asa`
     - Security Findings: `12 Flagged`
     - Accepted Transforms: `3DES-CBC`, `HMAC-SHA1`, `MODP-1024`
2. **Fleet Inventory:**
   - Navigate to **VPN fleet** (`/fleet`).
   - The table automatically populates with all 113+ gateways from the SQLite database.
3. **PCAP Analysis:**
   - Navigate to **PCAP analysis** (`/analysis`).
   - Select any sample PCAP file from `lab/captures/` and click **Start analysis**.
   - The backend ingests the capture, extracts ESP statistics, and outputs RFC 4303 candidate ciphers with **94.2% confidence**.

---

## 🏆 Summary Checklist for Your Presentation

- [ ] Mention the problem: Legacy, unhardened IPsec tunnels silently running in critical infrastructure.
- [ ] Show **132 automated passing tests** (`pytest`).
- [ ] Show the **Terminal & HTML Audit Reports** (`report 24`).
- [ ] Show the **Automated Remediation Diff** (`fix 24`).
- [ ] Perform the **Live Tamper Demonstration** (`verify 24` -> tamper 1 byte -> verify fail).
- [ ] Present the **Signed Attestation Certificate** (`attest 24`).
- [ ] Demonstrate **Fleet Scalability** (`emulator simulate -n 50`).
- [ ] Showcase the **Live Backend & React Console** (`uvicorn` on `:8000` + `npm run dev` on `:5173`).

*TunnelTwin / Valence-IPsec — Engineered for SIH 2026 / NTRO PS 26160.*

