"""
TunnelTwin Probe Engine — Behavioral Daemon Fingerprinting.

Classifies IPsec/IKE responder implementations (strongSwan, Libreswan, Cisco ASA)
via observable protocol behaviors, notification payload combinations, and RFC quirks
rather than static assumptions or manual declarations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tunneltwin.ike.codec import ParsedIKEMessage

# Known Vendor ID hash prefixes
CISCO_VENDOR_ID_PREFIXES = (
    b"\x12\xf5\xf2\x8c",  # Cisco Unity / ASA
    b"\x09\x00\x26\x89",  # Cisco Concentrator
    b"\x40\x48\xb7\xd5",  # Cisco Altiga
)

STRONGSWAN_VENDOR_ID_SNIPPETS = (
    b"strongSwan",
    b"\x88\x2f\x0a\x3c",  # strongSwan hash snippet
)

LIBRESWAN_VENDOR_ID_SNIPPETS = (
    b"OE-Libreswan",
    b"Libreswan",
    b"Openswan",
    b"\x4f\x45\x2d\x4c",  # OE-L
)


class DaemonType(str, Enum):
    """Supported IPsec VPN daemon implementations."""

    STRONGSWAN = "strongswan"
    LIBRESWAN = "libreswan"
    CISCO_ASA = "cisco_asa"
    UNKNOWN = "unknown"


@dataclass
class DaemonFingerprint:
    """Outcome of behavioral daemon fingerprinting against an active responder."""

    daemon: DaemonType
    confidence: float  # In [0.0, 1.0]
    evidence: list[str] = field(default_factory=list)
    rtt_ms: float = 0.0
    details: dict[str, str] = field(default_factory=dict)

    @property
    def is_identified(self) -> bool:
        """True if a specific daemon type was classified with >= 0.70 confidence."""
        return self.daemon != DaemonType.UNKNOWN and self.confidence >= 0.70

    def summary(self) -> str:
        """Formatted human-readable summary of the fingerprint."""
        conf_pct = f"{self.confidence * 100:.1f}%"
        ev_str = "; ".join(self.evidence) if self.evidence else "No decisive behavioral markers"
        return f"{self.daemon.value.upper()} (Confidence: {conf_pct}) — Evidence: {ev_str}"


def classify_daemon(
    msg: ParsedIKEMessage | None,
    rtt_ms: float = 0.0,
) -> DaemonFingerprint:
    """
    Classify the responder implementation based on packet quirks and payload evidence.

    Behavioral Decision Tree:
      1. Explicit Vendor IDs:
         - Libreswan / Openswan VIDs -> LIBRESWAN (1.00)
         - strongSwan VIDs -> STRONGSWAN (1.00)
         - Cisco ASA / Unity VIDs -> CISCO_ASA (1.00)
      2. IKEv2 SA_INIT Notification Payload Quirks:
         - Libreswan unconditionally sends NAT_DETECTION_SOURCE_IP (16388) and
           NAT_DETECTION_DESTINATION_IP (16389) without client request, and omits
           strongSwan's signature hash algorithm notify (16404). -> LIBRESWAN (0.95)
         - strongSwan responds with RFC 7427 SIGNATURE_HASH_ALGORITHMS (16404)
           and omits unsolicited NAT-D notifications. -> STRONGSWAN (0.95)
         - Cisco ASA returns Cisco private notify codes (16400/16401) or specific
           NAT-D ordering with zero padding quirks. -> CISCO_ASA (0.90)
      3. Fallback: UNKNOWN (0.00)
    """
    if msg is None:
        return DaemonFingerprint(
            daemon=DaemonType.UNKNOWN,
            confidence=0.0,
            evidence=["No response packet received"],
            rtt_ms=rtt_ms,
        )

    evidence: list[str] = []

    # ── Check 1: Vendor ID Analysis ──────────────────────────────────
    for vid in msg.vendor_ids:
        for l_snip in LIBRESWAN_VENDOR_ID_SNIPPETS:
            if l_snip in vid:
                evidence.append(f"Explicit Libreswan Vendor ID match: {l_snip.decode('ascii', errors='ignore')}")
                return DaemonFingerprint(
                    daemon=DaemonType.LIBRESWAN,
                    confidence=1.0,
                    evidence=evidence,
                    rtt_ms=rtt_ms,
                    details={"matched_vid": vid.hex()},
                )

        for s_snip in STRONGSWAN_VENDOR_ID_SNIPPETS:
            if s_snip in vid:
                evidence.append(f"Explicit strongSwan Vendor ID match: {s_snip.decode('ascii', errors='ignore')}")
                return DaemonFingerprint(
                    daemon=DaemonType.STRONGSWAN,
                    confidence=1.0,
                    evidence=evidence,
                    rtt_ms=rtt_ms,
                    details={"matched_vid": vid.hex()},
                )

        for c_prefix in CISCO_VENDOR_ID_PREFIXES:
            if vid.startswith(c_prefix):
                evidence.append(f"Cisco Vendor ID header match: {c_prefix.hex()}")
                return DaemonFingerprint(
                    daemon=DaemonType.CISCO_ASA,
                    confidence=1.0,
                    evidence=evidence,
                    rtt_ms=rtt_ms,
                    details={"matched_vid": vid.hex()},
                )

    # ── Check 2: IKEv2 Notification Payload Behavioral Quirks ────────
    notify_types = {n.notify_type for n in msg.notifies}

    # Quirk A: strongSwan RFC 7427 signature hash algorithms notification
    # strongSwan includes notify 16404 in standard IKE_SA_INIT responses.
    has_strongswan_sig_hash = 16404 in notify_types

    # Quirk B: Libreswan unsolicited NAT-D
    # Libreswan pluto sends both 16388 (NAT_DETECTION_SOURCE_IP) and
    # 16389 (NAT_DETECTION_DESTINATION_IP) in IKE_SA_INIT response even if
    # the client initiator probe did not include NAT-D payloads.
    has_unsolicited_natd = 16388 in notify_types and 16389 in notify_types

    # Quirk C: Cisco ASA private notifies
    has_cisco_private = any(nt in notify_types for nt in (16400, 16401, 16402))

    if has_cisco_private:
        evidence.append("Cisco-specific private notify payload observed (16400-16402)")
        return DaemonFingerprint(
            daemon=DaemonType.CISCO_ASA,
            confidence=0.90,
            evidence=evidence,
            rtt_ms=rtt_ms,
            details={"notifies": str(sorted(list(notify_types)))},
        )

    if has_strongswan_sig_hash and not has_unsolicited_natd:
        evidence.append(
            "strongSwan signature: RFC 7427 SIGNATURE_HASH_ALGORITHMS (16404) present; unsolicited NAT-D omitted"
        )
        if 16418 in notify_types:
            evidence.append("Notify 16418 (REDIRECT_SUPPORTED) present")
        return DaemonFingerprint(
            daemon=DaemonType.STRONGSWAN,
            confidence=0.95,
            evidence=evidence,
            rtt_ms=rtt_ms,
            details={"notifies": str(sorted(list(notify_types)))},
        )

    if has_unsolicited_natd and not has_strongswan_sig_hash:
        evidence.append(
            "Libreswan signature: Unsolicited NAT_DETECTION (16388/16389) emitted; SIGNATURE_HASH (16404) absent"
        )
        if 16418 in notify_types:
            evidence.append("Notify 16418 (REDIRECT_SUPPORTED / CHILDLESS_IKE_SA_SUPPORTED) present")
        return DaemonFingerprint(
            daemon=DaemonType.LIBRESWAN,
            confidence=0.95,
            evidence=evidence,
            rtt_ms=rtt_ms,
            details={"notifies": str(sorted(list(notify_types)))},
        )

    if has_unsolicited_natd and has_strongswan_sig_hash:
        # Both present (e.g. initiator requested NAT-D): strongSwan was given NAT-D
        evidence.append("RFC 7427 SIGNATURE_HASH (16404) present along with negotiated NAT-D")
        return DaemonFingerprint(
            daemon=DaemonType.STRONGSWAN,
            confidence=0.85,
            evidence=evidence,
            rtt_ms=rtt_ms,
            details={"notifies": str(sorted(list(notify_types)))},
        )

    # ── Check 3: Generic / Unknown ───────────────────────────────────
    evidence.append(f"Unmatched notify profile: {sorted(list(notify_types))}")
    return DaemonFingerprint(
        daemon=DaemonType.UNKNOWN,
        confidence=0.20 if notify_types else 0.0,
        evidence=evidence,
        rtt_ms=rtt_ms,
        details={"notifies": str(sorted(list(notify_types)))},
    )
