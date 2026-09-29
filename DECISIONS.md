# TunnelTwin — Architecture Decision Records (DECISIONS.md)

> **Purpose**: This record captures every meaningful architectural and technical decision made across the TunnelTwin codebase, documenting the context, alternatives considered, chosen path, and the engineering rationale.

---

## ADR-0001: Lab Substrate Using Native Linux Network Namespaces (`ip netns`)

- **Status**: Accepted
- **Context**: Phase 0 requires an isolated testbed that can simulate real IPsec VPN gateways establishing tunnels with varied cryptographic suites. Docker and Containerlab were explicitly excluded by project constraints.
- **Decision**: Use native Linux network namespaces (`ip netns add ns-left`, `ip netns add ns-right`), linked via a Linux virtual ethernet pair (`veth-left` <-> `veth-right`) with dedicated `/30` IP subnets (`10.0.1.1/30` and `10.0.1.2/30`).
- **Rationale**:
  - Zero container daemon overhead.
  - Precise Linux kernel XFRM state/policy isolation per namespace.
  - Direct execution of strongSwan `charon` instances within namespaces using distinct configuration environments and runtime socket paths.
  - Reproducible on any modern Linux system or WSL2 kernel with network namespace support.

---

## ADR-0002: Four-Tier Provenance Tracking as a First-Class Model Citizen

- **Status**: Accepted
- **Context**: In security auditing, attributing whether a finding came from a scanned active port, a static text configuration, an AI inference, or is completely unknown is vital for defensibility and zero false-positive trust.
- **Decision**: Every parameter, attribute, and evaluated fact throughout the TunnelTwin core model carries an explicit provenance tag:
  1. `observed`: Directly extracted from active network probes (e.g. IKE responder packets, SA payloads).
  2. `parsed`: Extracted from static configuration files (Cisco IOS, strongSwan, FortiOS).
  3. `inferred`: Predicted by the ML heuristic engine, accompanied by a mandatory confidence score $\in [0.0, 1.0]$ and inference reason.
  4. `unknown`: Missing, redacted, or unreachable information.
- **Strict Compliance Constraint**: Any compliance or security rule requiring an `unknown` fact MUST emit `"cannot assess"`, NEVER a pass or fail.

---

## ADR-0003: Safety-First, Consent-Gated Active Probing Model

- **Status**: Accepted
- **Context**: Active probing of cryptographic protocols can trigger IDS/IPS or violate organizational boundaries if misdirected or intrusive.
- **Decision**: The active scanning engine (`tunneltwin.probe`) will implement a double-barrier enforcement check:
  1. Target IP/FQDN must exist within a cryptographically signed or explicitly declared local allowlist (`TargetAllowlist`).
  2. The target profile must have `consent_verified: True` explicitly asserted.
  3. Probes are strictly restricted to standard SA proposal discovery (sending non-intrusive IKE_SA_INIT / Phase 1 proposals).
  4. Aggressive mode credential harvesting, brute-force PSK capture, and fuzzing payloads are architecturally excluded.
- **Rationale**: Complies with NTRO/SIH ethical scanning mandates and ensures zero disruption to production infrastructures.

---

## ADR-0004: Multi-Daemon strongSwan Isolation Architecture

- **Status**: Accepted
- **Context**: strongSwan's `charon` daemon by default uses global `/etc/strongswan.conf`, `/var/run/charon.vici`, and global pidfiles. Running two instances across namespaces can collide if paths are shared.
- **Decision**: Create completely self-contained directory trees per namespace:
  - `/tmp/tunneltwin/ns-left/` and `/tmp/tunneltwin/ns-right/`
  - Per-namespace `strongswan.conf` pointing `charon.plugins.vici.socket` to local runtime paths (`/tmp/tunneltwin/<ns>/charon.vici`).
  - Explicit execution with `ip netns exec <ns> unshare -m ...` and invocation of `swanctl` with `--uri unix:///tmp/tunneltwin/<ns>/charon.vici`.
- **Rationale**: Complete isolation of the management plane and data plane between the two synthetic VPN peers.

---

## ADR-0005: 100% Original Code & Cleanroom Implementation Policy

- **Status**: Accepted
- **Context**: Competitive context includes public tools (CipherLens, IPsec Sentinel, Alchemist, CipherGuard, ipsec-Detector, SIH-160, vpnguard, VPN-Prots, IPsecAnalyzer, TunnelScope).
- **Decision**: Zero lines of code or proprietary schemas will be adapted or copied from any public repository. All protocol parsers, state machines, rule definitions, and diff generators are built cleanroom from RFC specifications (RFC 7296, RFC 4301, RFC 2409, RFC 9395) and official vendor documentation (NIST SP 800-77 Rev 1, ANSSI IPsec guidelines).

---

## ADR-0006: Core Technology Stack & Module Boundaries

- **Status**: Accepted
- **Decision**:
  - **Core Logic & Engine**: Python 3.10+ with strict typing (`dataclasses`, `typing`, `pydantic` models).
  - **Networking / Lab Automation**: Shell & Python scripts utilizing Linux `ip netns`, `veth`, and `swanctl`.
  - **API Engine**: FastAPI / ASGI for microsecond response times and OpenAPI automatic documentation.
  - **UI / Frontend**: Premium dark-mode dashboard built with Semantic HTML5, Vanilla Modern CSS (glassmorphism, vibrant cyan/indigo cyber aesthetic, responsive grid), and vanilla JavaScript (zero heavy dependency bloat).

---

## ADR-0007: Private Mount Namespace Isolation for Multi-Instance `charon.pid`

- **Status**: Accepted
- **Context**: strongSwan's `charon` binary checks `/var/run/charon.pid` on startup to prevent concurrent daemons. In Linux network namespaces, `/var/run` is shared from the host root filesystem unless isolated. Spawning the second charon in `ns-right` failed with `charon already running ('/var/run/charon.pid' exists)`.
- **Decision**: Wrap the charon execution within a private Linux mount namespace using `unshare -m`:
  `ip netns exec <ns> unshare -m sh -c "mount -t tmpfs tmpfs /var/run && exec env STRONGSWAN_CONF=... /usr/lib/ipsec/charon >/dev/null 2>&1"`
  VICI sockets are placed in `/tmp/tunneltwin/<ns>/charon.vici` (outside the private tmpfs mount), enabling external `swanctl` instances to connect directly.
- **Rationale**: Clean, kernel-native isolation without requiring root filesystem modification or Docker overhead.

---

## ADR-0008: Strict Labeling Invariant for Non-Lab-Verified Configurations (Cisco ASA)

- **Status**: Accepted
- **Context**: Phase 3 requires generating vendor remediation configurations for Cisco ASA as well as strongSwan. While strongSwan is verified natively in the Linux netns testbed, physical Cisco ASA hardware is absent from the automated lab environment. Providing generated security configs without explicit disclaimers risks operational misuse.
- **Decision**: All Cisco ASA configurations generated by `tunneltwin.fix` MUST include the exact string `"generated, not lab-verified"` across all representation layers:
  1. Prominently in the header comments and metadata of the generated CLI block.
  2. In the `RemediationConfig.verification_status` attribute.
  3. In `__str__` and `__repr__` implementations of the configuration model.
  4. In UI/CLI formatted presentation banners.
- **Rationale**: Zero false assurances. Operators and auditors are unambiguously warned that the generated commands require testing in a lab before production deployment.

---

## ADR-0009: Empirical Twin-Check Protocol via In-Lab Re-Scan and Data-Plane Validation

- **Status**: Accepted
- **Context**: Automated configuration remediation cannot be declared successful based solely on static diff generation or mocked tests. The system must prove both compliance remediation and operational viability.
- **Decision**: The Twin Check protocol requires a 4-step live execution in the network namespace lab:
  1. Apply baseline insecure config $\implies$ assert baseline tunnel establishes $\implies$ reproduce compliance findings (`NIST-001`, `NIST-004`).
  2. Generate and apply hardened remediated config (`aes256gcm-baseline`) $\implies$ confirm new tunnel establishes on both peers (`ESTABLISHED` on both `ns-left` and `ns-right`) $\implies$ verify bidirectional data-plane traffic via ICMP ping.
  3. Execute active probe re-scan against the remediated responder $\implies$ confirm baseline findings are completely cleared and compliance score improves.
  4. Re-establish the tunnel to prove continuous operational readiness.
- **Rationale**: Demonstrates end-to-end defensibility: remediation fixes the security weakness without breaking network connectivity.

---

## ADR-0010: Side-by-Side Coexistence of strongSwan and Libreswan in Linux Namespaces

- **Status**: Accepted
- **Context**: On Debian/Ubuntu distributions, standard package manager (`apt install libreswan`) marks `strongswan-libcharon` and `strongswan-starter` as mutually exclusive, attempting to uninstall strongSwan when installing Libreswan. Phase 4 mandates testing Libreswan alongside strongSwan concurrently in namespaces.
- **Decision**: Install Libreswan by extracting runtime binaries and helper utilities into `/opt/libreswan` while installing shared dependencies (`libnss3`, `bind9-libs`, `libevent`) via package management without conflicts. Symlink `/usr/libexec/ipsec` and `/usr/local/sbin/ipsec` to allow `pluto` helper scripts to locate required utilities. Provide per-namespace isolated NSS databases (`sql:/tmp/tunneltwin/<ns>/nss`), private runtime directories, and whack control sockets.
- **Rationale**: Enables concurrent testing of both major Linux IPsec implementations on a single host without container virtualization overhead.

---

## ADR-0011: Behavioral Daemon Fingerprinting via Observable Protocol Quirks over Static Assumptions

- **Status**: Accepted
- **Context**: Phase 4 requires confirming which daemon type the scanner is communicating with. Relying on user assumptions, IP address mappings, or port numbers violates the core principle of empirical defensibility.
- **Decision**: Implement behavioral daemon fingerprinting based on observable protocol packet quirks and notification signatures:
  1. Libreswan quirk: Pluto emits unsolicited `NAT_DETECTION_SOURCE_IP` (16388) and `NAT_DETECTION_DESTINATION_IP` (16389) in `IKE_SA_INIT` responses even when client probes omit NAT-D payloads, includes notify 16418, and omits strongSwan's signature hash notify $\implies$ classified as `LIBRESWAN` with 0.95 confidence.
  2. strongSwan quirk: Charon responds with RFC 7427 `SIGNATURE_HASH_ALGORITHMS` (16404) and omits unsolicited NAT-D notifications $\implies$ classified as `STRONGSWAN` with 0.95 confidence.
  3. Cisco ASA quirk: Private vendor IDs (`12f5f28c...`) or private notify codes (16400-16402) $\implies$ classified as `CISCO_ASA` with 0.90-1.0 confidence.
  4. Explicit Vendor IDs: Overrides heuristics with 1.0 confidence when present.
- **Rationale**: Grounded in empirical protocol observation with transparent confidence scoring and explicit evidence tracking.

