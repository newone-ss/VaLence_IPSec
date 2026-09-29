"""
tunneltwin.core.db — SQLite persistence layer.

Engine is configured with:
  - WAL journal mode for concurrent read access during active scans.
  - check_same_thread=False to allow cross-thread session use inside FastAPI.

Tables
------
Target         — Authorized scan target (consent-gated).
ScanRun        — A discrete probe / parse / capture session.
Gateway        — Observed or parsed IKE endpoint.
Fact           — Atomic provenance-tagged datum (OBSERVED/PARSED/INFERRED/UNKNOWN).
Finding        — Compliance rule result bound to a ScanRun.
Remediation    — Vendor-specific config diff attached to a Finding.
Capture        — PCAP file or live-capture record linked to a ScanRun.
Model          — ML inference artifact (weights path + metadata).
Seal           — Merkle audit-trail entry chaining assessment integrity receipts.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import event, text
from sqlmodel import Field, Relationship, Session, SQLModel, create_engine

# ---------------------------------------------------------------------------
# Database path & engine
# ---------------------------------------------------------------------------

_DB_PATH: Path = Path(__file__).resolve().parents[2] / "tunneltwin.db"
_DB_URL: str = f"sqlite:///{_DB_PATH}"

engine = create_engine(
    _DB_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)


@event.listens_for(engine, "connect")
def _set_wal_mode(dbapi_conn, _connection_record) -> None:  # type: ignore[type-arg]
    """Enable WAL journal mode immediately after every new SQLite connection."""
    dbapi_conn.execute("PRAGMA journal_mode=WAL;")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ProvenanceEnum(str, enum.Enum):
    """
    Four-tier fact provenance taxonomy.

    OBSERVED  — Verified directly via active packet exchange or wire capture.
    PARSED    — Extracted from a static configuration file.
    INFERRED  — Predicted by the ML heuristic engine; accompanied by confidence in [0.0, 1.0].
    UNKNOWN   — Unobserved/missing; triggers CANNOT_ASSESS in compliance rules.
    """

    OBSERVED = "OBSERVED"
    PARSED = "PARSED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class FindingStatus(str, enum.Enum):
    PASS = "PASS"  # noqa: S105
    FAIL = "FAIL"
    CANNOT_ASSESS = "CANNOT_ASSESS"


class RemediationStatus(str, enum.Enum):
    PROPOSED = "PROPOSED"
    APPLIED = "APPLIED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


class SealType(str, enum.Enum):
    SCAN = "SCAN"
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    CAPTURE = "CAPTURE"
    ATTEST = "ATTEST"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class Target(SQLModel, table=True):
    """
    Authorized scan target.

    Double-barrier consent: a target is only probeable when
    consent_verified=True AND the IP/subnet is registered here.
    """

    __tablename__ = "target"

    id: Optional[int] = Field(default=None, primary_key=True)
    ip_or_cidr: str = Field(index=True, description="Target IP address or CIDR subnet.")
    owner: str = Field(default="", description="Organizational owner of the target.")
    description: str = Field(default="")
    consent_verified: bool = Field(default=False, description="Explicit written consent flag.")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Relationships
    scan_runs: list["ScanRun"] = Relationship(back_populates="target")
    gateways: list["Gateway"] = Relationship(back_populates="target")


class ScanRun(SQLModel, table=True):
    """
    A discrete scan session (probe, parse, or capture) against a Target.
    """

    __tablename__ = "scan_run"

    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: Optional[int] = Field(default=None, foreign_key="target.id", index=True)
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    scan_type: str = Field(default="probe", description="'probe' | 'parse' | 'capture' | 'full'")
    started_at: Optional[datetime] = Field(default=None)
    finished_at: Optional[datetime] = Field(default=None)
    error_message: Optional[str] = Field(default=None)
    operator: str = Field(default="", description="Operator identifier initiating the scan.")
    notes: str = Field(default="")

    # Relationships
    target: Optional[Target] = Relationship(back_populates="scan_runs")
    gateways: list["Gateway"] = Relationship(back_populates="scan_run")
    facts: list["Fact"] = Relationship(back_populates="scan_run")
    findings: list["Finding"] = Relationship(back_populates="scan_run")
    captures: list["Capture"] = Relationship(back_populates="scan_run")
    seals: list["Seal"] = Relationship(back_populates="scan_run")


class Gateway(SQLModel, table=True):
    """
    Observed or parsed IKE gateway endpoint discovered during a ScanRun.
    """

    __tablename__ = "gateway"

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_run_id: Optional[int] = Field(default=None, foreign_key="scan_run.id", index=True)
    target_id: Optional[int] = Field(default=None, foreign_key="target.id", index=True)
    ip_address: str = Field(index=True)
    port: int = Field(default=500)
    ike_version: str = Field(default="UNKNOWN", description="'IKEv1' | 'IKEv2' | 'UNKNOWN'")
    vendor_type: str = Field(default="UNKNOWN", description="Cisco IOS | strongSwan | FortiOS | UNKNOWN")
    provenance: ProvenanceEnum = Field(default=ProvenanceEnum.UNKNOWN)
    responded: bool = Field(default=False, description="True if the gateway responded to IKE SA_INIT.")
    nat_traversal: bool = Field(default=False)
    raw_fingerprint: Optional[str] = Field(default=None, description="Vendor ID or banner string.")
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Relationships
    scan_run: Optional[ScanRun] = Relationship(back_populates="gateways")
    target: Optional[Target] = Relationship(back_populates="gateways")
    facts: list["Fact"] = Relationship(back_populates="gateway")


class Fact(SQLModel, table=True):
    """
    Atomic provenance-tagged datum.

    Every IPsec parameter (cipher, DH group, lifetime, auth method, etc.)
    is stored as a Fact with an explicit ProvenanceEnum tag and an optional
    confidence score (mandatory when provenance == INFERRED).
    """

    __tablename__ = "fact"

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_run_id: Optional[int] = Field(default=None, foreign_key="scan_run.id", index=True)
    gateway_id: Optional[int] = Field(default=None, foreign_key="gateway.id", index=True)
    parameter: str = Field(index=True, description="Parameter name, e.g. 'cipher', 'dh_group', 'ike_version'.")
    raw_value: Optional[str] = Field(default=None, description="Serialised string representation of the value.")
    provenance: ProvenanceEnum = Field(default=ProvenanceEnum.UNKNOWN, index=True)
    confidence: Optional[float] = Field(
        default=None,
        description="Confidence score in [0.0, 1.0]. Required when provenance == INFERRED.",
    )
    source_ref: str = Field(default="", description="Line number, packet index, probe ID, or config section ref.")
    notes: Optional[str] = Field(default=None)
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Relationships
    scan_run: Optional[ScanRun] = Relationship(back_populates="facts")
    gateway: Optional[Gateway] = Relationship(back_populates="facts")


class Finding(SQLModel, table=True):
    """
    Compliance rule evaluation result for a single parameter or connection within a ScanRun.

    Status CANNOT_ASSESS is emitted when required facts carry ProvenanceEnum.UNKNOWN,
    ensuring zero-false-pass guarantee.
    """

    __tablename__ = "finding"

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_run_id: Optional[int] = Field(default=None, foreign_key="scan_run.id", index=True)
    rule_id: str = Field(index=True, description="Compliance rule identifier, e.g. 'NIST-SP800-77r1-4.1'.")
    rule_framework: str = Field(
        default="", description="Framework name, e.g. 'NIST SP 800-77r1', 'ANSSI', 'RFC 9395'."
    )
    parameter: str = Field(default="", description="Parameter under assessment.")
    status: FindingStatus = Field(default=FindingStatus.CANNOT_ASSESS, index=True)
    severity: str = Field(default="INFO", description="'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'")
    detail: str = Field(default="", description="Human-readable rule evaluation narrative.")
    evidence_refs: str = Field(default="", description="Comma-separated Fact IDs used as evidence.")
    assessed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Relationships
    scan_run: Optional[ScanRun] = Relationship(back_populates="findings")
    remediations: list["Remediation"] = Relationship(back_populates="finding")


class Remediation(SQLModel, table=True):
    """
    Vendor-specific configuration diff / patch proposed or applied for a Finding.
    """

    __tablename__ = "remediation"

    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: Optional[int] = Field(default=None, foreign_key="finding.id", index=True)
    vendor: str = Field(default="", description="Target vendor: 'cisco_ios' | 'strongswan' | 'fortios' | 'generic'")
    diff_text: str = Field(default="", description="Unified diff or structured patch text.")
    status: RemediationStatus = Field(default=RemediationStatus.PROPOSED)
    verified_by: Optional[str] = Field(default=None, description="Operator who verified application.")
    verification_seal_id: Optional[int] = Field(default=None, foreign_key="seal.id")
    proposed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    applied_at: Optional[datetime] = Field(default=None)

    # Relationships
    finding: Optional[Finding] = Relationship(back_populates="remediations")
    verification_seal: Optional["Seal"] = Relationship()


class Capture(SQLModel, table=True):
    """
    PCAP file or live-capture session record linked to a ScanRun.
    """

    __tablename__ = "capture"

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_run_id: Optional[int] = Field(default=None, foreign_key="scan_run.id", index=True)
    file_path: Optional[str] = Field(default=None, description="Absolute path to the PCAP file on disk.")
    interface: Optional[str] = Field(default=None, description="Network interface name for live capture.")
    packet_count: int = Field(default=0)
    is_live: bool = Field(default=False, description="True for live tcpdump/scapy capture; False for file import.")
    bpf_filter: str = Field(default="udp port 500 or udp port 4500", description="BPF filter expression.")
    started_at: Optional[datetime] = Field(default=None)
    finished_at: Optional[datetime] = Field(default=None)
    notes: str = Field(default="")

    # Relationships
    scan_run: Optional[ScanRun] = Relationship(back_populates="captures")


class Model(SQLModel, table=True):
    """
    ML inference model artifact record (parameter inference engine).
    """

    __tablename__ = "model"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, description="Human-readable model name.")
    version: str = Field(default="0.0.0")
    model_type: str = Field(default="", description="Model family, e.g. 'random_forest', 'gradient_boost'.")
    weights_path: Optional[str] = Field(default=None, description="Absolute path to serialised weights file.")
    feature_schema: Optional[str] = Field(default=None, description="JSON-encoded feature column schema.")
    target_parameter: str = Field(default="", description="IPsec parameter this model predicts.")
    accuracy: Optional[float] = Field(default=None, description="Held-out validation accuracy in [0.0, 1.0].")
    trained_at: Optional[datetime] = Field(default=None)
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = Field(default=False, description="Whether this model is the current production model.")
    notes: str = Field(default="")


class Seal(SQLModel, table=True):
    """
    Merkle audit-trail entry.

    Each significant action (scan, finding, remediation, capture) generates
    a Seal whose sha256_hash is chained to the previous_hash, forming a
    tamper-evident SHA-256 Merkle tree of all assessment events.
    """

    __tablename__ = "seal"

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_run_id: Optional[int] = Field(default=None, foreign_key="scan_run.id", index=True)
    seal_type: SealType = Field(default=SealType.SCAN, index=True)
    entity_type: str = Field(default="", description="Table name of the sealed entity, e.g. 'finding'.")
    entity_id: Optional[int] = Field(default=None, description="Primary key of the sealed entity row.")
    sha256_hash: str = Field(index=True, description="SHA-256 digest of the serialised entity payload.")
    previous_hash: Optional[str] = Field(default=None, description="SHA-256 of the preceding Seal — chain root.")
    merkle_root: Optional[str] = Field(default=None, description="Running Merkle root after including this Seal.")
    signature: Optional[str] = Field(default=None, description="Optional Ed25519/RSA signature over sha256_hash.")
    signed_by: Optional[str] = Field(default=None, description="Key identifier or operator name.")
    sealed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str = Field(default="")

    # Relationships
    scan_run: Optional[ScanRun] = Relationship(back_populates="seals")


# ---------------------------------------------------------------------------
# Schema bootstrap
# ---------------------------------------------------------------------------


def init_db() -> None:
    """
    Create all tables and verify WAL mode is active.

    Call once at application startup (FastAPI lifespan, CLI --init-db, or tests).
    """
    SQLModel.metadata.create_all(engine)
    with engine.connect() as conn:
        result = conn.execute(text("PRAGMA journal_mode;")).scalar()
        if result != "wal":
            conn.execute(text("PRAGMA journal_mode=WAL;"))
            conn.commit()


def get_session() -> Session:
    """
    Return a new SQLModel Session bound to the shared engine.

    Intended for use as a FastAPI dependency via Depends(get_session).

    Example::

        @app.get("/scan-runs")
        def list_scan_runs(session: Session = Depends(get_session)):
            return session.exec(select(ScanRun)).all()
    """
    return Session(engine)
