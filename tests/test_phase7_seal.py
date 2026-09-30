"""
tests.test_phase7_seal -- Comprehensive Tests for Phase 7 Trust Layer & Signed Attestation.

Validates:
  1. Deterministic canonical leaf serialization and SHA-256 Merkle tree construction.
  2. Ed25519 digital signing, public key serialization, and signature verification.
  3. End-to-end ScanRun sealing into SQLite fleet store.
  4. Byte-level tamper detection (single byte alteration in DB immediately invalidates root).
  5. Deterministic compliance attestation certificate generation and formatting.
  6. CLI commands (`verify`, `attest`) execution.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from sqlmodel import Session, SQLModel, create_engine
from typer.testing import CliRunner

from tunneltwin.cli.main import app
from tunneltwin.core.db import (
    Finding,
    FindingStatus,
    Gateway,
    ProvenanceEnum,
    Remediation,
    RemediationStatus,
    ScanRun,
    ScanStatus,
    Target,
)
from tunneltwin.seal.attestation import generate_attestation_certificate
from tunneltwin.seal.engine import seal_scan_run, verify_scan_run
from tunneltwin.seal.merkle import (
    compute_merkle_root,
    hash_leaf,
    serialize_finding,
    serialize_remediation,
)
from tunneltwin.seal.signer import (
    get_or_create_keypair,
    sign_merkle_root,
    verify_signature,
)

runner = CliRunner()


@pytest.fixture
def temp_db_and_keys():
    """Create an isolated SQLite database and key directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_trust.db"
        key_dir = Path(tmpdir) / "keys"
        engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
        SQLModel.metadata.create_all(engine)
        yield engine, key_dir
        engine.dispose()


def test_merkle_tree_deterministic():
    """Verify Merkle tree computation is strictly deterministic and detects single-bit changes."""
    leaves_a = ["a" * 64, "b" * 64, "c" * 64]
    leaves_b = ["a" * 64, "b" * 64, "c" * 64]

    root_a = compute_merkle_root(leaves_a)
    root_b = compute_merkle_root(leaves_b)
    assert root_a == root_b
    assert len(root_a) == 64

    # Single-byte change in third leaf
    leaves_tampered = ["a" * 64, "b" * 64, "c" * 63 + "d"]
    root_tampered = compute_merkle_root(leaves_tampered)
    assert root_a != root_tampered

    # Empty tree handling
    empty_root = compute_merkle_root([])
    assert len(empty_root) == 64

    # Single leaf
    single_root = compute_merkle_root(["e" * 64])
    assert single_root == "e" * 64


def test_ed25519_signing_and_verification(temp_db_and_keys):
    """Verify Ed25519 key generation, digital signing, and signature verification."""
    _, key_dir = temp_db_and_keys

    priv_key, pub_hex = get_or_create_keypair(key_dir)
    assert len(pub_hex) == 64  # 32 bytes in hex = 64 chars

    data = "test_merkle_root_hash_value_12345"
    sig_hex = sign_merkle_root(priv_key, data)
    assert len(sig_hex) == 128  # 64-byte Ed25519 signature = 128 chars

    # Authentic signature verifies
    assert verify_signature(pub_hex, data, sig_hex) is True

    # Tampered data fails
    assert verify_signature(pub_hex, data + "!", sig_hex) is False

    # Corrupted signature fails
    corrupted_sig = ("0" if sig_hex[0] != "0" else "1") + sig_hex[1:]
    assert verify_signature(pub_hex, data, corrupted_sig) is False


def test_canonical_leaf_hashing():
    """Verify canonical serialization handles findings and remediations consistently."""
    f1 = Finding(
        id=1,
        scan_run_id=1,
        rule_id="NIST-001",
        rule_framework="NIST SP 800-77r1",
        parameter="ike_version",
        status=FindingStatus.FAIL,
        severity="HIGH",
        detail="IKEv1 deprecated",
        evidence_refs="fact-1",
    )
    leaf1 = hash_leaf(serialize_finding(f1))

    f2 = Finding(
        id=1,
        scan_run_id=1,
        rule_id="NIST-001",
        rule_framework="NIST SP 800-77r1",
        parameter="ike_version",
        status=FindingStatus.FAIL,
        severity="HIGH",
        detail="IKEv1 deprecated",
        evidence_refs="fact-1",
    )
    leaf2 = hash_leaf(serialize_finding(f2))
    assert leaf1 == leaf2

    # Detail alteration changes leaf hash
    f2.detail = "IKEv1 deprecated."
    assert hash_leaf(serialize_finding(f2)) != leaf1

    rem = Remediation(
        id=1,
        finding_id=1,
        vendor="strongswan",
        diff_text="--- a\n+++ b",
        status=RemediationStatus.PROPOSED,
    )
    rem_leaf = hash_leaf(serialize_remediation(rem))
    assert len(rem_leaf) == 64


def test_seal_and_verify_cycle_valid(temp_db_and_keys):
    """End-to-end: seed database, compute Merkle seal, verify returns VALID."""
    engine, key_dir = temp_db_and_keys

    with Session(engine) as session:
        target = Target(ip_or_cidr="10.0.1.2", consent_verified=True)
        session.add(target)
        session.flush()

        run = ScanRun(target_id=target.id, status=ScanStatus.COMPLETED, scan_type="probe")
        session.add(run)
        session.flush()

        f1 = Finding(
            scan_run_id=run.id,
            rule_id="NIST-001",
            rule_framework="NIST SP 800-77r1",
            parameter="protocol_version",
            status=FindingStatus.FAIL,
            severity="HIGH",
            detail="IKEv1 is deprecated.",
            evidence_refs="1",
        )
        f2 = Finding(
            scan_run_id=run.id,
            rule_id="CNSA-001",
            rule_framework="NSA CNSA Suite",
            parameter="encryption",
            status=FindingStatus.FAIL,
            severity="CRITICAL",
            detail="3DES is insecure.",
            evidence_refs="2",
        )
        session.add_all([f1, f2])
        session.flush()

        rem = Remediation(
            finding_id=f1.id,
            vendor="strongswan",
            diff_text="--- a/swanctl.conf\n+++ b/swanctl.conf",
            status=RemediationStatus.PROPOSED,
        )
        session.add(rem)
        session.commit()
        run_id = run.id

    assert run_id is not None
    with Session(engine) as session:
        receipt = seal_scan_run(scan_run_id=run_id, key_dir=key_dir, db_session=session)
    assert receipt.leaf_count == 3  # 2 findings + 1 remediation
    assert len(receipt.merkle_root) == 64
    assert len(receipt.signature) == 128

    # Verify unmodified data
    with Session(engine) as session:
        report = verify_scan_run(scan_run_id=run_id, key_dir=key_dir, db_session=session)
    assert report.is_valid is True
    assert report.status == "VALID"
    assert report.signature_valid is True
    assert report.recomputed_merkle_root == receipt.merkle_root


def test_tamper_detection_invalidates_seal(temp_db_and_keys):
    """Prove that changing a single byte of a finding record causes verify to report TAMPERED."""
    engine, key_dir = temp_db_and_keys

    with Session(engine) as session:
        target = Target(ip_or_cidr="10.0.1.2", consent_verified=True)
        session.add(target)
        session.flush()

        run = ScanRun(target_id=target.id, status=ScanStatus.COMPLETED, scan_type="probe")
        session.add(run)
        session.flush()

        f1 = Finding(
            scan_run_id=run.id,
            rule_id="NIST-001",
            rule_framework="NIST SP 800-77 Rev 1",
            parameter="protocol_version",
            status=FindingStatus.FAIL,
            severity="HIGH",
            detail="IKEv1 is deprecated.",
            evidence_refs="1",
        )
        session.add(f1)
        session.commit()
        run_id = run.id
        finding_id = f1.id

    assert run_id is not None
    with Session(engine) as session:
        receipt = seal_scan_run(scan_run_id=run_id, key_dir=key_dir, db_session=session)
    assert receipt.leaf_count == 1

    # Before tampering: verify reports VALID
    with Session(engine) as session:
        report_before = verify_scan_run(scan_run_id=run_id, key_dir=key_dir, db_session=session)
    assert report_before.is_valid is True
    assert report_before.status == "VALID"

    # DELIBERATE 1-BYTE TAMPER in database: alter finding detail
    with Session(engine) as session:
        f = session.get(Finding, finding_id)
        assert f is not None
        f.detail = f.detail + "X"  # Alter 1 byte
        session.add(f)
        session.commit()

    # After tampering: verify MUST report TAMPERED / INVALID
    with Session(engine) as session:
        report_after = verify_scan_run(scan_run_id=run_id, key_dir=key_dir, db_session=session)
    assert report_after.is_valid is False
    assert report_after.status == "TAMPERED"
    assert report_after.recomputed_merkle_root != receipt.merkle_root
    assert "TAMPER DETECTED" in report_after.details


def test_attestation_certificate_formatting(temp_db_and_keys):
    """Verify deterministic Markdown compliance attestation certificate format and fields."""
    engine, key_dir = temp_db_and_keys

    with Session(engine) as session:
        target = Target(ip_or_cidr="10.0.1.2", consent_verified=True)
        session.add(target)
        session.flush()

        run = ScanRun(target_id=target.id, status=ScanStatus.COMPLETED, scan_type="probe")
        session.add(run)
        session.flush()

        gw = Gateway(
            scan_run_id=run.id,
            target_id=target.id,
            ip_address="10.0.1.2",
            port=500,
            ike_version="IKEv1",
            vendor_type="strongswan",
            provenance=ProvenanceEnum.OBSERVED,
        )
        session.add(gw)

        f1 = Finding(
            scan_run_id=run.id,
            rule_id="NIST-002",
            rule_framework="NIST SP 800-77 Rev 1",
            parameter="key_exchange",
            status=FindingStatus.FAIL,
            severity="CRITICAL",
            detail="DH group MODP-1024 is vulnerable.",
            evidence_refs="fact-1",
        )
        session.add(f1)
        session.commit()
        run_id = run.id

    assert run_id is not None
    with Session(engine) as session:
        seal_scan_run(scan_run_id=run_id, key_dir=key_dir, db_session=session)
        cert = generate_attestation_certificate(scan_run_id=run_id, db_session=session)

    assert "# CRYPTOGRAPHIC COMPLIANCE ATTESTATION CERTIFICATE" in cert
    assert "10.0.1.2:500" in cert
    assert "NIST-002" in cert
    assert "NIST Special Publication 800-77 Rev 1" in cert
    assert "NSA Commercial National Security Algorithm (CNSA) Suite 2.0" in cert
    assert "SHA-256 Merkle Root" in cert
    assert "Ed25519 Signer Public Key" in cert
    assert "Ed25519 Digital Signature" in cert
    assert f"tunneltwin verify {run_id}" in cert


def test_cli_verify_and_attest_smoke():
    """Verify that CLI verify and attest commands execute properly."""
    res_help_verify = runner.invoke(app, ["verify", "--help"])
    assert res_help_verify.exit_code == 0
    assert "Recompute Merkle tree" in res_help_verify.output

    res_help_attest = runner.invoke(app, ["attest", "--help"])
    assert res_help_attest.exit_code == 0
    assert "Seal the ScanRun" in res_help_attest.output
