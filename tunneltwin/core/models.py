"""
TunnelTwin Core Data Models and Provenance Tracking System.

Every fact reported by TunnelTwin carries an explicit provenance tag:
- OBSERVED: Directly obtained from an active network probe.
- PARSED: Extracted from a static configuration file.
- INFERRED: Deduced by the ML heuristic engine (with mandatory confidence score [0.0, 1.0]).
- UNKNOWN: Missing, unreachable, or redacted.

Compliance Rule Guarantee:
Any security/compliance rule requiring an UNKNOWN fact MUST emit AssessmentStatus.CANNOT_ASSESS,
never a false PASS or unverified FAIL.
"""

from __future__ import annotations

from enum import Enum
from typing import Generic, TypeVar

from pydantic import BaseModel, Field, model_validator


class ProvenanceTag(str, Enum):
    """
    Taxonomy of knowledge origin for all facts and protocol attributes.
    """

    OBSERVED = "observed"
    PARSED = "parsed"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class AssessmentStatus(str, Enum):
    """
    Evaluation outcomes for security and compliance rules.
    """

    PASS = "PASS"  # nosec B105  # noqa: S105
    FAIL = "FAIL"
    CANNOT_ASSESS = "CANNOT ASSESS"


T = TypeVar("T")


class ProvenancedFact(BaseModel, Generic[T]):
    """
    Atomic datum wrapper binding a value to its origin and integrity attributes.
    """

    value: T | None = None
    tag: ProvenanceTag = ProvenanceTag.UNKNOWN
    confidence: float | None = Field(
        default=None, description="Confidence score in [0.0, 1.0]. Mandatory when tag == INFERRED."
    )
    source_ref: str = Field(default="", description="Line number, packet index, probe ID, or config section reference.")
    notes: str | None = None

    @model_validator(mode="after")
    def validate_confidence(self) -> ProvenancedFact[T]:
        # Validate that inferred facts strictly carry a valid confidence score
        if self.tag == ProvenanceTag.INFERRED:
            if self.confidence is None or not (0.0 <= self.confidence <= 1.0):
                raise ValueError("INFERRED facts must specify confidence in range [0.0, 1.0]")
        elif self.tag == ProvenanceTag.UNKNOWN:
            self.value = None
        return self

    @classmethod
    def observed(cls, value: T, source_ref: str = "", notes: str | None = None) -> ProvenancedFact[T]:
        return cls(value=value, tag=ProvenanceTag.OBSERVED, confidence=1.0, source_ref=source_ref, notes=notes)

    @classmethod
    def parsed(cls, value: T, source_ref: str = "", notes: str | None = None) -> ProvenancedFact[T]:
        return cls(value=value, tag=ProvenanceTag.PARSED, confidence=1.0, source_ref=source_ref, notes=notes)

    @classmethod
    def inferred(
        cls, value: T, confidence: float, source_ref: str = "", notes: str | None = None
    ) -> ProvenancedFact[T]:
        return cls(value=value, tag=ProvenanceTag.INFERRED, confidence=confidence, source_ref=source_ref, notes=notes)

    @classmethod
    def unknown(cls, source_ref: str = "", notes: str | None = None) -> ProvenancedFact[T]:
        return cls(value=None, tag=ProvenanceTag.UNKNOWN, confidence=None, source_ref=source_ref, notes=notes)

    def is_known(self) -> bool:
        return self.tag != ProvenanceTag.UNKNOWN and self.value is not None


class IKEVersion(str, Enum):
    IKEV1 = "IKEv1"
    IKEV2 = "IKEv2"
    UNKNOWN = "UNKNOWN"


class DiffieHellmanGroup(str, Enum):
    MODP_768 = "modp768"  # DH Group 1 (Insecure)
    MODP_1024 = "modp1024"  # DH Group 2 (Insecure / Deprecated)
    MODP_1536 = "modp1536"  # DH Group 5 (Deprecated)
    MODP_2048 = "modp2048"  # DH Group 14 (Minimum acceptable legacy)
    MODP_3072 = "modp3072"  # DH Group 15 (Acceptable)
    MODP_4096 = "modp4096"  # DH Group 16 (High security)
    ECP_256 = "ecp256"  # DH Group 19 (NIST P-256)
    ECP_384 = "ecp384"  # DH Group 20 (NIST P-384 / CNSA)
    ECP_521 = "ecp521"  # DH Group 21 (NIST P-521)
    CURVE25519 = "curve25519"  # DH Group 31 (RFC 8031)
    UNKNOWN = "UNKNOWN"


class CipherAlgorithm(str, Enum):
    DES_56 = "des"
    TRIPLE_DES_168 = "3des"
    AES_128_CBC = "aes128"
    AES_256_CBC = "aes256"
    AES_128_GCM = "aes128gcm"
    AES_256_GCM = "aes256gcm"
    CHACHA20_POLY1305 = "chacha20poly1305"
    UNKNOWN = "UNKNOWN"


class IntegrityAlgorithm(str, Enum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    NONE = "none"  # For AEAD ciphers like AES-GCM
    UNKNOWN = "UNKNOWN"


class NormalizedProposal(BaseModel):
    """
    Representation of an individual crypto proposal (Phase 1 or Phase 2).
    """

    cipher: ProvenancedFact[str] = Field(default_factory=ProvenancedFact.unknown)
    integrity: ProvenancedFact[str] = Field(default_factory=ProvenancedFact.unknown)
    dh_group: ProvenancedFact[str] = Field(default_factory=ProvenancedFact.unknown)
    prf: ProvenancedFact[str] = Field(default_factory=ProvenancedFact.unknown)
    key_length: ProvenancedFact[int] = Field(default_factory=ProvenancedFact.unknown)


class NormalizedConnection(BaseModel):
    """
    Vendor-agnostic canonical representation of an IPsec VPN peer/tunnel.
    Every attribute is wrapped in a ProvenancedFact.
    """

    connection_name: ProvenancedFact[str] = Field(default_factory=ProvenancedFact.unknown)
    ike_version: ProvenancedFact[str] = Field(default_factory=ProvenancedFact.unknown)
    local_endpoint: ProvenancedFact[str] = Field(default_factory=ProvenancedFact.unknown)
    remote_endpoint: ProvenancedFact[str] = Field(default_factory=ProvenancedFact.unknown)
    auth_method: ProvenancedFact[str] = Field(default_factory=ProvenancedFact.unknown)
    phase1_proposals: list[NormalizedProposal] = Field(default_factory=list)
    phase2_proposals: list[NormalizedProposal] = Field(default_factory=list)
    pfs_group: ProvenancedFact[str] = Field(default_factory=ProvenancedFact.unknown)
    phase1_lifetime: ProvenancedFact[int] = Field(default_factory=ProvenancedFact.unknown)
    phase2_lifetime: ProvenancedFact[int] = Field(default_factory=ProvenancedFact.unknown)
    vendor_type: ProvenancedFact[str] = Field(default_factory=ProvenancedFact.unknown)
    source_format: str = "unknown"
