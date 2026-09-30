"""
tunneltwin.seal.engine -- Cryptographic Audit Trail & Verification Engine.

Orchestrates canonical hashing of scan artifacts, binary Merkle tree construction,
Ed25519 digital signature generation, database seal persistence, and tamper verification.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from tunneltwin.core.db import (
    Finding,
    Remediation,
    ScanRun,
    Seal,
    SealType,
    engine,
)
from tunneltwin.seal.merkle import (
    compute_merkle_root,
    hash_leaf,
    serialize_finding,
    serialize_remediation,
)
from tunneltwin.seal.signer import (
    DEFAULT_KEY_DIR,
    PUBLIC_KEY_FILENAME,
    get_or_create_keypair,
    sign_merkle_root,
    verify_signature,
)

REPORTS_DIR = Path("reports")


@dataclass
class SealReceipt:
    """Cryptographic audit receipt for a sealed ScanRun."""

    scan_run_id: int
    merkle_root: str
    signature: str
    public_key: str
    signed_by: str
    leaf_count: int
    findings_count: int
    remediations_count: int
    sealed_at: str
    receipt_file: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_run_id": self.scan_run_id,
            "merkle_root": self.merkle_root,
            "signature": self.signature,
            "public_key": self.public_key,
            "signed_by": self.signed_by,
            "leaf_count": self.leaf_count,
            "findings_count": self.findings_count,
            "remediations_count": self.remediations_count,
            "sealed_at": self.sealed_at,
        }


@dataclass
class VerificationReport:
    """Result of recomputing and cryptographically verifying a ScanRun seal."""

    scan_run_id: int
    is_valid: bool
    status: str  # "VALID" | "TAMPERED" | "INVALID_SIGNATURE" | "UNSEALED"
    stored_merkle_root: str | None
    recomputed_merkle_root: str | None
    signature_valid: bool
    leaf_count: int
    details: str
    public_key: str | None = None


def seal_scan_run(
    scan_run_id: int,
    operator: str = "tunneltwin-trust-engine",
    key_dir: Path | None = None,
    db_session: Session | None = None,
) -> SealReceipt:
    """
    Compute binary Merkle tree over findings and remediations of a ScanRun,
    digitally sign the root with Ed25519, and commit a Seal record to the database.
    """

    def _execute(session: Session) -> SealReceipt:
        scan_run = session.get(ScanRun, scan_run_id)
        if not scan_run:
            raise ValueError(f"ScanRun #{scan_run_id} not found in fleet store.")

        # 1. Fetch and sort findings
        raw_findings = session.exec(select(Finding).where(Finding.scan_run_id == scan_run_id)).all()
        findings = sorted(raw_findings, key=lambda f: (f.rule_id, f.id or 0))

        # 2. Fetch and sort remediations for these findings
        finding_id_set = {f.id for f in findings if f.id is not None}
        all_rems = session.exec(select(Remediation)).all()
        remediations = sorted(
            [r for r in all_rems if r.finding_id in finding_id_set],
            key=lambda r: (r.finding_id or 0, r.id or 0),
        )

        # 3. Canonical leaf hashing
        leaf_hashes: list[str] = []
        for f in findings:
            leaf_hashes.append(hash_leaf(serialize_finding(f)))
        for r in remediations:
            leaf_hashes.append(hash_leaf(serialize_remediation(r)))

        # 4. Construct Merkle tree root
        merkle_root = compute_merkle_root(leaf_hashes)

        # 5. Load/generate Ed25519 keypair and sign root
        priv_key, pub_hex = get_or_create_keypair(key_dir)
        signature_hex = sign_merkle_root(priv_key, merkle_root)

        # 6. Persist Seal record
        notes_str = (
            f"public_key={pub_hex};leaves={len(leaf_hashes)};findings={len(findings)};remediations={len(remediations)}"
        )

        seal_record = Seal(
            scan_run_id=scan_run_id,
            seal_type=SealType.SCAN,
            entity_type="scan_run",
            entity_id=scan_run_id,
            sha256_hash=merkle_root,
            merkle_root=merkle_root,
            signature=signature_hex,
            signed_by=operator,
            notes=notes_str,
            sealed_at=datetime.now(timezone.utc),
        )
        session.add(seal_record)
        session.commit()
        session.refresh(seal_record)

        # 7. Write sidecar JSON receipt
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        receipt_path = REPORTS_DIR / f"seal_run_{scan_run_id}.json"
        receipt = SealReceipt(
            scan_run_id=scan_run_id,
            merkle_root=merkle_root,
            signature=signature_hex,
            public_key=pub_hex,
            signed_by=operator,
            leaf_count=len(leaf_hashes),
            findings_count=len(findings),
            remediations_count=len(remediations),
            sealed_at=seal_record.sealed_at.isoformat(),
            receipt_file=str(receipt_path),
        )
        receipt_path.write_text(json.dumps(receipt.to_dict(), indent=2), encoding="utf-8")

        return receipt

    if db_session:
        return _execute(db_session)
    with Session(engine) as session:
        return _execute(session)


def verify_scan_run(
    scan_run_id: int,
    key_dir: Path | None = None,
    db_session: Session | None = None,
) -> VerificationReport:
    """
    Verify the cryptographic integrity of a ScanRun by recomputing its Merkle root
    from database records and validating its Ed25519 digital signature.
    """

    def _execute(session: Session) -> VerificationReport:
        scan_run = session.get(ScanRun, scan_run_id)
        if not scan_run:
            return VerificationReport(
                scan_run_id=scan_run_id,
                is_valid=False,
                status="UNSEALED",
                stored_merkle_root=None,
                recomputed_merkle_root=None,
                signature_valid=False,
                leaf_count=0,
                details=f"ScanRun #{scan_run_id} not found in fleet store.",
            )

        seals = session.exec(
            select(Seal).where(Seal.scan_run_id == scan_run_id).order_by(Seal.id.desc())  # type: ignore[union-attr]
        ).all()
        if not seals:
            return VerificationReport(
                scan_run_id=scan_run_id,
                is_valid=False,
                status="UNSEALED",
                stored_merkle_root=None,
                recomputed_merkle_root=None,
                signature_valid=False,
                leaf_count=0,
                details=f"ScanRun #{scan_run_id} has no cryptographic seals recorded.",
            )

        latest_seal = seals[0]
        stored_root = latest_seal.merkle_root or latest_seal.sha256_hash

        # Extract public key from seal notes, key dir, or sidecar
        pub_hex = ""
        if latest_seal.notes and "public_key=" in latest_seal.notes:
            for part in latest_seal.notes.split(";"):
                if part.startswith("public_key="):
                    pub_hex = part.split("=", 1)[1].strip()
                    break

        if not pub_hex:
            target_key_dir = key_dir or DEFAULT_KEY_DIR
            pub_file = target_key_dir / PUBLIC_KEY_FILENAME
            if pub_file.exists():
                pub_hex = pub_file.read_text(encoding="utf-8").strip()

        # Re-fetch findings and remediations from current DB state
        raw_findings = session.exec(select(Finding).where(Finding.scan_run_id == scan_run_id)).all()
        findings = sorted(raw_findings, key=lambda f: (f.rule_id, f.id or 0))

        finding_id_set = {f.id for f in findings if f.id is not None}
        all_rems = session.exec(select(Remediation)).all()
        remediations = sorted(
            [r for r in all_rems if r.finding_id in finding_id_set],
            key=lambda r: (r.finding_id or 0, r.id or 0),
        )

        # Recompute leaf digests
        recomputed_leaves: list[str] = []
        for f in findings:
            recomputed_leaves.append(hash_leaf(serialize_finding(f)))
        for r in remediations:
            recomputed_leaves.append(hash_leaf(serialize_remediation(r)))

        recomputed_root = compute_merkle_root(recomputed_leaves)

        # 1. Compare recomputed root against stored root
        root_matches = recomputed_root.lower() == stored_root.lower()
        if not root_matches:
            return VerificationReport(
                scan_run_id=scan_run_id,
                is_valid=False,
                status="TAMPERED",
                stored_merkle_root=stored_root,
                recomputed_merkle_root=recomputed_root,
                signature_valid=False,
                leaf_count=len(recomputed_leaves),
                details=(
                    f"TAMPER DETECTED: Recomputed Merkle root ({recomputed_root}) does not match "
                    f"the stored seal root ({stored_root}). One or more findings or remediations have been altered."
                ),
                public_key=pub_hex or None,
            )

        # 2. Check Ed25519 signature
        sig_valid = False
        if latest_seal.signature and pub_hex:
            sig_valid = verify_signature(pub_hex, recomputed_root, latest_seal.signature)

        if not sig_valid and latest_seal.signature:
            return VerificationReport(
                scan_run_id=scan_run_id,
                is_valid=False,
                status="INVALID_SIGNATURE",
                stored_merkle_root=stored_root,
                recomputed_merkle_root=recomputed_root,
                signature_valid=False,
                leaf_count=len(recomputed_leaves),
                details="INVALID SIGNATURE: Merkle root matches, but Ed25519 digital signature verification failed.",
                public_key=pub_hex or None,
            )

        return VerificationReport(
            scan_run_id=scan_run_id,
            is_valid=True,
            status="VALID",
            stored_merkle_root=stored_root,
            recomputed_merkle_root=recomputed_root,
            signature_valid=sig_valid,
            leaf_count=len(recomputed_leaves),
            details=(
                f"INTEGRITY VERIFIED: All {len(recomputed_leaves)} artifacts verified against Merkle root. "
                f"Ed25519 signature is cryptographically valid."
            ),
            public_key=pub_hex or None,
        )

    if db_session:
        return _execute(db_session)
    with Session(engine) as session:
        return _execute(session)
