"""
Probe Scan Result Data Models.

All findings from the active prober carry ProvenanceTag.OBSERVED — they were
directly observed from real network responses, not inferred or parsed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum

from tunneltwin.core.models import ProvenancedFact
from tunneltwin.ike.constants import (
    DH_GROUP_NAMES,
    ENCRYPTION_NAMES,
    INTEGRITY_NAMES,
    PRF_NAMES,
)
from tunneltwin.probe.fingerprint import DaemonFingerprint


class ScanStatus(str, Enum):
    """Overall status of a gateway scan."""

    SUCCESS = "success"
    TIMEOUT = "timeout"
    REFUSED = "refused"
    ERROR = "error"
    CONSENT_DENIED = "consent_denied"


@dataclass
class AcceptedTransform:
    """A single accepted transform from a successful negotiation."""

    transform_type: int  # TransformType enum value
    transform_id: int  # Algorithm ID
    key_length: int | None = None

    @property
    def human_name(self) -> str:
        from tunneltwin.ike.constants import TransformType

        if self.transform_type == TransformType.ENCR:
            name = ENCRYPTION_NAMES.get(self.transform_id, f"ENCR-{self.transform_id}")
            if self.key_length:
                return f"{name}-{self.key_length}"
            return name
        elif self.transform_type == TransformType.PRF:
            return PRF_NAMES.get(self.transform_id, f"PRF-{self.transform_id}")
        elif self.transform_type == TransformType.INTEG:
            return INTEGRITY_NAMES.get(self.transform_id, f"INTEG-{self.transform_id}")
        elif self.transform_type == TransformType.DH:
            return DH_GROUP_NAMES.get(self.transform_id, f"DH-{self.transform_id}")
        return f"TYPE-{self.transform_type}:{self.transform_id}"


@dataclass
class IKEv1AcceptedTransform:
    """Accepted IKEv1 transform attributes."""

    encryption: int
    hash_alg: int
    auth_method: int
    dh_group: int
    key_length: int | None = None

    @property
    def encryption_name(self) -> str:
        from tunneltwin.ike.constants import IKEv1EncryptionType

        _v1_encr_names: dict[int, str] = {
            IKEv1EncryptionType.DES_CBC: "DES-CBC",
            IKEv1EncryptionType.THREE_DES_CBC: "3DES-CBC",
            IKEv1EncryptionType.AES_CBC: "AES-CBC",
            IKEv1EncryptionType.BLOWFISH_CBC: "BLOWFISH-CBC",
        }
        name = _v1_encr_names.get(self.encryption, f"ENCR-{self.encryption}")
        if self.key_length:
            return f"{name}-{self.key_length}"
        return name

    @property
    def hash_name(self) -> str:
        from tunneltwin.ike.constants import IKEv1HashType

        _v1_hash_names: dict[int, str] = {
            IKEv1HashType.MD5: "MD5",
            IKEv1HashType.SHA1: "SHA1",
            IKEv1HashType.SHA2_256: "SHA2-256",
            IKEv1HashType.SHA2_384: "SHA2-384",
            IKEv1HashType.SHA2_512: "SHA2-512",
        }
        return _v1_hash_names.get(self.hash_alg, f"HASH-{self.hash_alg}")

    @property
    def dh_group_name(self) -> str:
        return DH_GROUP_NAMES.get(self.dh_group, f"DH-{self.dh_group}")


@dataclass
class GatewayScanResult:
    """
    Complete scan result for a single IKE gateway.

    All accepted/rejected facts carry OBSERVED provenance.
    """

    target_ip: str
    target_port: int
    scan_status: ScanStatus
    ike_version_detected: ProvenancedFact[str] = field(default_factory=ProvenancedFact.unknown)

    # IKEv2 results
    accepted_dh_groups: list[ProvenancedFact[str]] = field(default_factory=list)
    rejected_dh_groups: list[ProvenancedFact[str]] = field(default_factory=list)
    accepted_transforms: list[AcceptedTransform] = field(default_factory=list)

    # IKEv1 results
    ikev1_accepted: list[IKEv1AcceptedTransform] = field(default_factory=list)

    # Cookie handling
    cookie_required: ProvenancedFact[bool] = field(default_factory=ProvenancedFact.unknown)

    # Timing
    scan_start_time: float = 0.0
    scan_end_time: float = 0.0
    probe_count: int = 0
    error_message: str = ""

    # Responder SPI (for correlation)
    responder_spi: bytes = b""

    # Behavioral Daemon Fingerprinting (Phase 4)
    fingerprint: DaemonFingerprint | None = None

    @property
    def detected_daemon(self) -> str:
        if self.fingerprint and self.fingerprint.is_identified:
            return self.fingerprint.daemon.value
        return "unknown"

    @property
    def scan_duration_ms(self) -> float:
        return (self.scan_end_time - self.scan_start_time) * 1000

    def mark_observed_ike_version(self, version: str) -> None:
        self.ike_version_detected = ProvenancedFact.observed(
            version,
            source_ref=f"probe:{self.target_ip}:{self.target_port}",
            notes="Detected from IKE header version field in response",
        )

    def add_accepted_dh_group(self, group_name: str) -> None:
        self.accepted_dh_groups.append(
            ProvenancedFact.observed(
                group_name,
                source_ref=f"probe:{self.target_ip}:{self.target_port}",
                notes="DH group accepted by responder (SA response received)",
            )
        )

    def add_rejected_dh_group(self, group_name: str, reason: str = "") -> None:
        self.rejected_dh_groups.append(
            ProvenancedFact.observed(
                group_name,
                source_ref=f"probe:{self.target_ip}:{self.target_port}",
                notes=f"DH group rejected: {reason}" if reason else "DH group rejected by responder",
            )
        )

    def mark_cookie_required(self, required: bool) -> None:
        self.cookie_required = ProvenancedFact.observed(
            required,
            source_ref=f"probe:{self.target_ip}:{self.target_port}",
            notes="COOKIE notify observed in IKE_SA_INIT response" if required else "No COOKIE required",
        )

    def start_timer(self) -> None:
        self.scan_start_time = time.monotonic()

    def stop_timer(self) -> None:
        self.scan_end_time = time.monotonic()

    def summary(self) -> str:
        """Human-readable scan summary."""
        lines = [
            f"═══ Scan Result: {self.target_ip}:{self.target_port} ═══",
            f"  Status        : {self.scan_status.value}",
            f"  Duration      : {self.scan_duration_ms:.1f} ms",
            f"  Probes Sent   : {self.probe_count}",
        ]

        if self.ike_version_detected.is_known():
            lines.append(f"  IKE Version   : {self.ike_version_detected.value}")

        if self.fingerprint and self.fingerprint.is_identified:
            lines.append(f"  Daemon Type   : {self.fingerprint.summary()}")

        if self.cookie_required.is_known():
            lines.append(f"  Cookie Needed : {self.cookie_required.value}")

        if self.accepted_dh_groups:
            names = [f.value for f in self.accepted_dh_groups if f.value]
            lines.append(f"  Accepted DH   : {', '.join(names)}")

        if self.rejected_dh_groups:
            names = [f.value for f in self.rejected_dh_groups if f.value]
            lines.append(f"  Rejected DH   : {', '.join(names)}")

        if self.accepted_transforms:
            for t in self.accepted_transforms:
                lines.append(f"  Accepted      : {t.human_name}")

        if self.ikev1_accepted:
            for v1t in self.ikev1_accepted:
                lines.append(f"  IKEv1 Accept  : {v1t.encryption_name} / {v1t.hash_name} / {v1t.dh_group_name}")

        if self.error_message:
            lines.append(f"  Error         : {self.error_message}")

        return "\n".join(lines)
