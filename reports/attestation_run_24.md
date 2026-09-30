# CRYPTOGRAPHIC COMPLIANCE ATTESTATION CERTIFICATE
**Valence-IPsec / TunnelTwin Security Assessment Framework**
**Attestation ID:** TT-CERT-RUN-000024  
**Issued Timestamp:** 2026-09-30 07:24:57 UTC  
**Integrity Seal Status:** VERIFIED (AUTHENTIC)  

---

## 1. Gateway Identification & Scope of Assessment

- **Target Endpoint:** `10.0.1.2:500`
- **Discovered Daemon / Vendor:** `cisco_asa`
- **Detected IKE Protocol:** `IKEv1`
- **Scan Run Reference:** ScanRun #24
- **Operator Identity:** `tunneltwin-operator`

## 2. Cited Standards & Rule Packs

- **NIST Special Publication 800-77 Rev 1**: *Guide to IPsec VPNs* (Authoritative)
- **NSA Commercial National Security Algorithm (CNSA) Suite 2.0**: *Quantum-Resistant Cryptography Requirements* (Authoritative)
- **CERT-In Technical Advisory**: *Pending confirmation of official primary publication; recorded as informational advisory only.*

## 3. Executive Posture Summary

- **Total Evaluated Criteria:** 17
- **Critical Vulnerabilities:** 5
- **High-Risk Non-Compliances:** 4
- **Conforming Rules (PASS):** 5

## 4. Evaluated Findings & Technical Evidence

| Rule ID | Standard / Framework | Severity | Outcome | Parameter | Assessment Narrative |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `CNSA-001` | NSA CNSA Suite | **CRITICAL** | `FAIL` | `protocol_version` | CNSA Suite requires IKEv2 (RFC 7296). IKEv1 does not support the required cryptographic agility and is excluded from CNSA compliance. |
| `CNSA-002` | NSA CNSA Suite | **CRITICAL** | `FAIL` | `key_exchange` | CNSA Suite mandates ECDH with NIST P-384 (ECP-384) as the minimum DH group. MODP groups and ECP-256 do not meet the CNSA security strength floor of 192 bits. |
| `CNSA-003` | NSA CNSA Suite | **CRITICAL** | `FAIL` | `encryption` | CNSA Suite requires AES with a 256-bit key. AES-128 and all legacy ciphers (DES, 3DES) are insufficient for CNSA compliance. |
| `NIST-002` | NIST SP 800-77 Rev 1 | **CRITICAL** | `FAIL` | `key_exchange` | DH groups with fewer than 2048 bits (MODP-768, MODP-1024, MODP-1536) are vulnerable to precomputation attacks and MUST NOT be used. NIST SP 800-77r1 §5.3 requires a minimum of 2048-bit MODP or 256-bit ECP for key exchange. |
| `NIST-004` | NIST SP 800-77 Rev 1 | **CRITICAL** | `FAIL` | `encryption` | DES (56-bit) and Triple DES (168-bit effective, 112-bit security) are prohibited for protecting federal information. AES-128 or AES-256 MUST be used per NIST SP 800-77r1 §6.2. |
| `CERTIN-002` | CERT-In Advisory (Pending Confirmation) | **HIGH** | `FAIL` | `key_exchange` | DH groups below 2048 bits are considered inadequate for protecting sensitive government communications. Minimum MODP-2048 or ECP-256 is required. |
| `CERTIN-003` | CERT-In Advisory (Pending Confirmation) | **HIGH** | `FAIL` | `encryption` | DES and 3DES are prohibited for government data protection. AES-128 or AES-256 in approved modes (CBC, GCM, CTR) must be used for all VPN tunnels. |
| `CNSA-004` | NSA CNSA Suite | **HIGH** | `FAIL` | `integrity` | CNSA Suite requires SHA-384 as the minimum hash algorithm for integrity protection. SHA-256, SHA-1, and MD5 do not meet the 192-bit security strength requirement. |
| `NIST-001` | NIST SP 800-77 Rev 1 | **HIGH** | `FAIL` | `protocol_version` | IKEv1 (RFC 2409) is deprecated. NIST SP 800-77r1 §5.1 mandates IKEv2 (RFC 7296) for new deployments due to improved security, simplified exchange, and resistance to denial-of-service attacks. |
| `CERTIN-001` | CERT-In Advisory (Pending Confirmation) | **MEDIUM** | `FAIL` | `protocol_version` | IKEv1 lacks modern security features including cookie-based DoS protection and EAP authentication. Migration to IKEv2 is recommended for all government and critical infrastructure deployments. |
| `CERTIN-004` | CERT-In Advisory (Pending Confirmation) | **INFO** | `PASS` | `integrity` | MD5 Integrity Prohibited |
| `NIST-003` | NIST SP 800-77 Rev 1 | **INFO** | `PASS` | `key_exchange` | MODP-2048 Acceptable but ECP Preferred |
| `NIST-005` | NIST SP 800-77 Rev 1 | **INFO** | `PASS` | `encryption` | AES-GCM Preferred over AES-CBC |
| `NIST-006` | NIST SP 800-77 Rev 1 | **INFO** | `PASS` | `integrity` | MD5 Integrity Prohibited |
| `NIST-007` | NIST SP 800-77 Rev 1 | **MEDIUM** | `FAIL` | `integrity` | SHA-1 has known theoretical weaknesses and practical collision attacks (SHAttered, 2017). NIST SP 800-131A Rev 2 disallows SHA-1 for digital signatures after 2030. SHA-256 or higher is recommended. |
| `NIST-008` | NIST SP 800-77 Rev 1 | **INFO** | `PASS` | `encryption` | AES-256 Recommended Over AES-128 |
| `NIST-009` | NIST SP 800-77 Rev 1 | **LOW** | `FAIL` | `exposure` | NIST SP 800-77 Rev 1 Section 4.3 recommends that IKEv2 responders enforce cookie mechanisms (RFC 7296 Section 2.6) to mitigate half-open state exhaustion and asymmetric CPU denial-of-service attacks before performing Diffie-Hellman exponentiation. |

## 5. Verified Remediation & Re-Scan State

### Proposed Patch: strongswan [PROPOSED]
```diff
--- a/swanctl-left.conf (insecure)
+++ b/swanctl-left.conf (remediated)
@@ -1 +1,39 @@
-# Baseline unhardened
+# ─────────────────────────────────────────────────────────────────────────────
+#  TunnelTwin Remediated Configuration — strongSwan swanctl
+#  Profile   : AES-256-GCM Baseline Profile (aes256gcm-baseline)
+#  Role      : LEFT (10.0.1.1 -> 10.0.1.2)
+#  Standards : NIST SP 800-77 Rev 1 / RFC 7296 (IKEv2) / RFC 5282 (AEAD)
+# ─────────────────────────────────────────────────────────────────────────────
+
+connections {
+    remediated-conn {
+        version = 2
+        local_addrs = 10.0.1.1
+        remote_addrs = 10.0.1.2
+        proposals = aes256gcm16-prfsha384-ecp384,aes256gcm16-prfsha256-ecp256,aes256-sha384-ecp384
+
+        local {
+            auth = psk
+        }
+
+        remote {
+            auth = psk
+        }
+
+        children {
+            remediated-child {
+                esp_proposals = aes256gcm16-ecp384,aes256gcm16
+                mode = tunnel
+                local_ts = 10.0.1.0/30
+                remote_ts = 10.0.1.0/30
+                start_action = none
+            }
+        }
+    }
+}
+
+secrets {
+    ike-remediated-conn {
+        secret = "vPn-sEcReT-2026"
+    }
+}
```

---

## 6. Cryptographic Trust Anchor & Verification Signature

This document is cryptographically bound to the underlying factual observations and rule findings.
Any alteration to a single byte of stored finding or remediation records invalidates the Merkle root.

- **SHA-256 Merkle Root:** `dee02dc46929c089a5cb0c6ceacf36654f80ec13f95404782e16361baa6dfcf4`
- **Ed25519 Signer Public Key:** `b0b11d0f1becc2b0ab650586e3642000a9e01ea975c1cb1170921963ae5c196c`
- **Ed25519 Digital Signature:**
  ```text
  6b89d14fa5dc26921ed563fe72064248e6faaebed9b6b664e6f969798ab7a0e122fd66630bf52622c13eb1f24cb350edd5789a2cd05e7f86cd2a9c2f139b370b
  ```

### Verification Command
To independently recompute the Merkle tree and verify this certificate against the fleet store:
```bash
tunneltwin verify 24
```

---
*Generated deterministically by TunnelTwin Trust Layer v0.1.0 on 2026-09-30 07:24:57 UTC.*
