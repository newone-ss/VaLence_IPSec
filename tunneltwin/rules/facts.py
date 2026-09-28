"""
Fact Model and Fact Store for the TunnelTwin Rule Engine.

A Fact is the atomic unit of evidence: a single observation about a gateway
(e.g. "gateway X uses IKEv1" or "gateway X accepts MODP-1024").

Facts carry provenance (OBSERVED, PARSED, INFERRED, UNKNOWN), a confidence
score, and a source pointer tracing them back to the exact probe, config
line, or inference step that produced them.

The FactStore indexes facts by (subject, key) for fast rule evaluation.
The bridge function converts Phase 1 GatewayScanResult objects into facts.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from tunneltwin.core.models import ProvenanceTag

if TYPE_CHECKING:
    from tunneltwin.probe.result import GatewayScanResult


class FactCategory(str, Enum):
    """Categories used for scoring weight distribution."""

    KEY_EXCHANGE = "key_exchange"
    ENCRYPTION = "encryption"
    INTEGRITY = "integrity"
    PROTOCOL_VERSION = "protocol_version"
    EXPOSURE = "exposure"


@dataclass(frozen=True)
class Fact:
    """
    Atomic evidence datum about a specific gateway.

    Attributes:
        subject: Identifier for the entity (e.g. "10.0.1.2:500").
        key: The attribute being described (e.g. "ike_version", "cipher").
        value: The observed/parsed/inferred value.
        provenance: How this fact was obtained.
        confidence: Float in [0.0, 1.0]. Always 1.0 for OBSERVED/PARSED.
        source_pointer: Traceability back to origin (probe ID, config line, etc.).
    """

    subject: str
    key: str
    value: str
    provenance: ProvenanceTag
    confidence: float = 1.0
    source_pointer: str = ""

    def __post_init__(self) -> None:
        if self.provenance == ProvenanceTag.INFERRED and not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"INFERRED fact confidence must be in [0.0, 1.0], got {self.confidence}")

    @property
    def is_known(self) -> bool:
        """A fact is known if its provenance is not UNKNOWN."""
        return self.provenance != ProvenanceTag.UNKNOWN


class FactStore:
    """
    Indexed collection of facts for a single assessment session.

    Facts are indexed by (subject, key) for O(1) lookup during rule evaluation.
    Multiple facts can exist for the same (subject, key) — e.g. multiple
    accepted DH groups.
    """

    def __init__(self) -> None:
        self._facts: dict[str, list[Fact]] = {}
        self._subjects: set[str] = set()

    def add(self, fact: Fact) -> None:
        """Add a fact to the store."""
        compound_key = f"{fact.subject}::{fact.key}"
        if compound_key not in self._facts:
            self._facts[compound_key] = []
        self._facts[compound_key].append(fact)
        self._subjects.add(fact.subject)

    def get(self, subject: str, key: str) -> list[Fact]:
        """Retrieve all facts for a (subject, key) pair."""
        compound_key = f"{subject}::{key}"
        return self._facts.get(compound_key, [])

    def get_first(self, subject: str, key: str) -> Fact | None:
        """Retrieve the first (primary) fact for a (subject, key) pair."""
        facts = self.get(subject, key)
        return facts[0] if facts else None

    def get_value(self, subject: str, key: str) -> str | None:
        """Shorthand: get the value of the first fact, or None if missing."""
        fact = self.get_first(subject, key)
        return fact.value if fact and fact.is_known else None

    def get_values(self, subject: str, key: str) -> list[str]:
        """Get all values for a (subject, key) pair."""
        return [f.value for f in self.get(subject, key) if f.is_known]

    def has_fact(self, subject: str, key: str) -> bool:
        """Check if at least one known fact exists for (subject, key)."""
        facts = self.get(subject, key)
        return any(f.is_known for f in facts)

    @property
    def subjects(self) -> set[str]:
        """All subjects with at least one fact."""
        return self._subjects.copy()

    def all_facts_for(self, subject: str) -> list[Fact]:
        """Return all facts for a given subject."""
        result: list[Fact] = []
        for compound_key, facts in self._facts.items():
            if compound_key.startswith(f"{subject}::"):
                result.extend(facts)
        return result

    def fact_count(self, subject: str | None = None) -> int:
        """Count facts, optionally filtered by subject."""
        if subject is None:
            return sum(len(v) for v in self._facts.values())
        return len(self.all_facts_for(subject))


# ═══════════════════════════════════════════════════════════════════════
#  Bridge: GatewayScanResult → FactStore
# ═══════════════════════════════════════════════════════════════════════


def scan_result_to_facts(
    scan_result: GatewayScanResult,
) -> FactStore:
    """
    Convert a Phase 1 GatewayScanResult into a FactStore.

    Every fact is tagged with OBSERVED provenance and traces back to the
    scan probe that produced it.
    """
    from tunneltwin.ike.constants import TransformType
    from tunneltwin.probe.result import ScanStatus

    store = FactStore()
    result = scan_result
    subject = f"{result.target_ip}:{result.target_port}"
    source = f"probe:{subject}"

    # Skip non-successful scans
    if result.scan_status != ScanStatus.SUCCESS:
        return store

    # IKE version
    if result.ike_version_detected.is_known():
        store.add(
            Fact(
                subject=subject,
                key="ike_version",
                value=str(result.ike_version_detected.value),
                provenance=ProvenanceTag.OBSERVED,
                confidence=1.0,
                source_pointer=source,
            )
        )

    # Cookie requirement
    if result.cookie_required.is_known():
        store.add(
            Fact(
                subject=subject,
                key="cookie_required",
                value=str(result.cookie_required.value),
                provenance=ProvenanceTag.OBSERVED,
                confidence=1.0,
                source_pointer=source,
            )
        )

    # Accepted DH groups
    for dh_fact in result.accepted_dh_groups:
        if dh_fact.is_known():
            store.add(
                Fact(
                    subject=subject,
                    key="accepted_dh_group",
                    value=str(dh_fact.value),
                    provenance=ProvenanceTag.OBSERVED,
                    confidence=1.0,
                    source_pointer=source,
                )
            )

    # Rejected DH groups
    for dh_fact in result.rejected_dh_groups:
        if dh_fact.is_known():
            store.add(
                Fact(
                    subject=subject,
                    key="rejected_dh_group",
                    value=str(dh_fact.value),
                    provenance=ProvenanceTag.OBSERVED,
                    confidence=1.0,
                    source_pointer=source,
                )
            )

    # IKEv2 accepted transforms
    for transform in result.accepted_transforms:
        if transform.transform_type == TransformType.ENCR:
            store.add(
                Fact(
                    subject=subject,
                    key="cipher",
                    value=transform.human_name,
                    provenance=ProvenanceTag.OBSERVED,
                    confidence=1.0,
                    source_pointer=source,
                )
            )
        elif transform.transform_type == TransformType.INTEG:
            store.add(
                Fact(
                    subject=subject,
                    key="integrity",
                    value=transform.human_name,
                    provenance=ProvenanceTag.OBSERVED,
                    confidence=1.0,
                    source_pointer=source,
                )
            )
        elif transform.transform_type == TransformType.PRF:
            store.add(
                Fact(
                    subject=subject,
                    key="prf",
                    value=transform.human_name,
                    provenance=ProvenanceTag.OBSERVED,
                    confidence=1.0,
                    source_pointer=source,
                )
            )
        elif transform.transform_type == TransformType.DH:
            # DH group already captured via accepted_dh_groups
            pass

    # IKEv1 accepted transforms
    for v1t in result.ikev1_accepted:
        store.add(
            Fact(
                subject=subject,
                key="cipher",
                value=v1t.encryption_name,
                provenance=ProvenanceTag.OBSERVED,
                confidence=1.0,
                source_pointer=source,
            )
        )
        store.add(
            Fact(
                subject=subject,
                key="integrity",
                value=v1t.hash_name,
                provenance=ProvenanceTag.OBSERVED,
                confidence=1.0,
                source_pointer=source,
            )
        )
        store.add(
            Fact(
                subject=subject,
                key="accepted_dh_group",
                value=v1t.dh_group_name,
                provenance=ProvenanceTag.OBSERVED,
                confidence=1.0,
                source_pointer=source,
            )
        )

    # Scan metadata
    store.add(
        Fact(
            subject=subject,
            key="scan_duration_ms",
            value=f"{result.scan_duration_ms:.1f}",
            provenance=ProvenanceTag.OBSERVED,
            confidence=1.0,
            source_pointer=source,
        )
    )
    store.add(
        Fact(
            subject=subject,
            key="probe_count",
            value=str(result.probe_count),
            provenance=ProvenanceTag.OBSERVED,
            confidence=1.0,
            source_pointer=source,
        )
    )

    # Behavioral daemon fingerprint
    if result.fingerprint and result.fingerprint.is_identified:
        store.add(
            Fact(
                subject=subject,
                key="daemon_type",
                value=result.fingerprint.daemon.value,
                provenance=ProvenanceTag.OBSERVED,
                confidence=result.fingerprint.confidence,
                source_pointer=source,
            )
        )

    return store
