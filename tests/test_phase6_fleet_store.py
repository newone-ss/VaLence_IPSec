"""
tests/test_phase6_fleet_store.py - Unit test suite for Phase 6 SQLite fleet store,
ingestion bridge, HTML report generator, emulator, and Typer CLI.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from sqlmodel import Session, create_engine, select
from typer.testing import CliRunner

from tunneltwin.cli.main import app
from tunneltwin.core.db import (
    Fact,
    Finding,
    FindingStatus,
    Gateway,
    ProvenanceEnum,
    Remediation,
    RemediationStatus,
    ScanRun,
    ScanStatus,
    Seal,
    SealType,
    Target,
)
from tunneltwin.core.ingest import ingest_scan_run
from tunneltwin.core.models import AssessmentStatus, ProvenancedFact
from tunneltwin.probe.emulator import _SimNode, run_emulator
from tunneltwin.probe.result import (
    AcceptedTransform,
    GatewayScanResult,
    IKEv1AcceptedTransform,
)
from tunneltwin.probe.result import (
    ScanStatus as ProbeScanStatus,
)
from tunneltwin.reports.html import generate_html_report
from tunneltwin.rules.engine import RuleResult


@pytest.fixture
def temp_db():
    """Create an isolated SQLite database in a temporary directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_fleet.db"
        engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
        from sqlmodel import SQLModel

        SQLModel.metadata.create_all(engine)
        yield engine
        engine.dispose()


def test_db_schema_and_crud(temp_db):
    """Verify Target, ScanRun, Gateway, Fact, Finding, Remediation, and Seal models."""
    with Session(temp_db) as session:
        # 1. Target
        target = Target(
            ip_or_cidr="10.0.1.2/32",
            owner="Lab-Admin",
            description="Phase-0 strongSwan Gateway",
            consent_verified=True,
        )
        session.add(target)
        session.commit()
        session.refresh(target)
        assert target.id is not None
        assert target.consent_verified is True

        # 2. ScanRun
        run = ScanRun(
            target_id=target.id,
            status=ScanStatus.COMPLETED,
            scan_type="probe",
            operator="tester",
            notes="Active scan test",
        )
        session.add(run)
        session.commit()
        session.refresh(run)
        assert run.id is not None
        assert run.status == ScanStatus.COMPLETED

        # 3. Gateway
        gw = Gateway(
            scan_run_id=run.id,
            target_id=target.id,
            ip_address="10.0.1.2",
            port=500,
            ike_version="IKEv2",
            vendor_type="strongswan",
            provenance=ProvenanceEnum.OBSERVED,
            responded=True,
        )
        session.add(gw)
        session.commit()
        session.refresh(gw)
        assert gw.id is not None
        assert gw.provenance == ProvenanceEnum.OBSERVED

        # 4. Fact
        fact = Fact(
            scan_run_id=run.id,
            gateway_id=gw.id,
            parameter="cipher",
            raw_value="aes256gcm",
            provenance=ProvenanceEnum.OBSERVED,
            confidence=1.0,
            source_ref="probe:sa_init",
        )
        session.add(fact)
        session.commit()
        session.refresh(fact)
        assert fact.parameter == "cipher"
        assert fact.raw_value == "aes256gcm"

        # 5. Finding
        finding = Finding(
            scan_run_id=run.id,
            rule_id="NIST-SP800-77r1-4.1",
            rule_framework="NIST SP 800-77r1",
            parameter="cipher",
            status=FindingStatus.PASS,
            severity="INFO",
            detail="AES-256-GCM compliant with NIST SP 800-77r1.",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        assert finding.status == FindingStatus.PASS

        # 6. Remediation
        remediation = Remediation(
            finding_id=finding.id,
            vendor="strongswan",
            diff_text="+ esp = aes256gcm16-ecp384!",
            status=RemediationStatus.PROPOSED,
        )
        session.add(remediation)
        session.commit()
        session.refresh(remediation)
        assert remediation.status == RemediationStatus.PROPOSED

        # 7. Seal
        seal = Seal(
            scan_run_id=run.id,
            seal_type=SealType.SCAN,
            entity_type="scan_run",
            entity_id=run.id,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            merkle_root="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        session.add(seal)
        session.commit()
        session.refresh(seal)
        assert seal.sha256_hash is not None

        # Verify query retrieval
        runs = session.exec(select(ScanRun).where(ScanRun.target_id == target.id)).all()
        assert len(runs) == 1
        assert runs[0].operator == "tester"


def test_ingest_scan_and_html_generation(temp_db):
    """Verify ingestion of live-format GatewayScanResult and HTML report rendering."""
    # Build simulated live scan result
    scan_res = GatewayScanResult(
        target_ip="10.0.1.2",
        target_port=500,
        scan_status=ProbeScanStatus.SUCCESS,
        ike_version_detected=ProvenancedFact.observed("IKEv1"),
        accepted_transforms=[AcceptedTransform(transform_type=1, transform_id=20, key_length=256)],
        ikev1_accepted=[IKEv1AcceptedTransform(encryption=5, hash_alg=1, auth_method=1, dh_group=2, key_length=None)],
        scan_start_time=1727670000.0,
        scan_end_time=1727670001.2,
        probe_count=14,
    )

    rule_results = [
        RuleResult(
            rule_id="NIST-SP800-77r1-IKEV1",
            rule_name="IKEv1 Deprecation",
            pack="NIST SP 800-77r1",
            category="protocol_version",
            status=AssessmentStatus.FAIL,
            severity=10,
            citation="NIST SP 800-77r1 §4.1",
            message="IKEv1 is deprecated due to aggressive/main mode vulnerabilities.",
        ),
        RuleResult(
            rule_id="NIST-SP800-77r1-3DES",
            rule_name="3DES Deprecation",
            pack="NIST SP 800-77r1",
            category="encryption",
            status=AssessmentStatus.FAIL,
            severity=9,
            citation="NIST SP 800-77r1 §4.2",
            message="3DES Sweet32 vulnerability.",
        ),
    ]

    remediations = [
        {
            "rule_id": "NIST-SP800-77r1-IKEV1",
            "vendor": "strongswan",
            "diff_text": "- version = 1\n+ version = 2\n+ esp = aes256gcm16!",
            "verified": True,
        }
    ]

    with Session(temp_db) as session:
        run_id = ingest_scan_run(
            scan_result=scan_res,
            rule_results=rule_results,
            remediations=remediations,
            profile_name="weak",
            operator="test-operator",
            db_session=session,
        )
        assert run_id > 0

        # Verify HTML generation
        html = generate_html_report(run_id, db_session=session)
        assert "<!DOCTYPE html>" in html
        assert "TunnelTwin — IPsec Assessment Report" in html
        assert "10.0.1.2:500" in html
        assert "CRITICAL NON-COMPLIANT" in html
        assert "NIST-SP800-77r1-IKEV1" in html
        assert "OBSERVED" in html
        assert "- version = 1" in html
        assert "VERIFIED (Twin Check Passed)" in html
        assert "SHA-256:" in html

        # Verify saving to disk
        with tempfile.TemporaryDirectory() as tmp_report_dir:
            out_file = Path(tmp_report_dir) / "test_report.html"
            content = generate_html_report(run_id, db_session=session)
            out_file.write_text(content, encoding="utf-8")
            assert out_file.exists()
            assert out_file.stat().st_size > 1000


def test_sim_node_generator():
    """Verify simulated node generator attributes."""
    node = _SimNode.generate(1)
    assert node.index == 1
    assert node.profile in ("weak", "strong", "legacy")
    assert node.port in (500, 4500)
    assert 10.0 <= node.latency_ms <= 500.0
    assert 0.55 <= node.inferred_confidence <= 0.99


@pytest.mark.asyncio
async def test_emulator_small_fleet():
    """Verify run_emulator executes concurrently and returns valid metrics."""
    result = await run_emulator(node_count=5)
    assert result["count"] == 5
    assert result["weak"] + result["strong"] + result["legacy"] == 5
    assert isinstance(result["merkle_root"], str)
    assert len(result["merkle_root"]) == 64  # SHA-256 hex string


def test_cli_help_and_commands():
    """Verify Typer CLI entrypoint and registered commands."""
    runner = CliRunner()

    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    assert "Valence-IPsec" in res.stdout or "tunneltwin" in res.stdout

    for cmd in ["scan", "analyze", "fix", "report", "emulator"]:
        res_cmd = runner.invoke(app, [cmd, "--help"])
        assert res_cmd.exit_code == 0, f"Command '{cmd} --help' failed: {res_cmd.output}"


def test_cli_report_and_save():
    """Verify CLI report command outputs text, json, and html."""
    runner = CliRunner()

    # Ingest a real run into the default DB
    scan_res = GatewayScanResult(
        target_ip="10.0.1.2",
        target_port=500,
        scan_status=ProbeScanStatus.SUCCESS,
        ike_version_detected=ProvenancedFact.observed("IKEv2"),
        scan_start_time=1727670000.0,
        scan_end_time=1727670001.0,
        probe_count=5,
    )
    rule_results = [
        RuleResult(
            rule_id="NIST-TEST",
            rule_name="Test Rule",
            pack="NIST SP 800-77r1",
            category="encryption",
            status=AssessmentStatus.PASS,
            severity=1,
            citation="Clause 4.1",
            message="Test rule passed",
        )
    ]
    run_id = ingest_scan_run(scan_result=scan_res, rule_results=rule_results, profile_name="strong")

    # Text report
    res_text = runner.invoke(app, ["report", str(run_id)])
    assert res_text.exit_code == 0
    assert "10.0.1.2:500" in res_text.stdout
    assert "NIST-TEST" in res_text.stdout
    assert "PASS" in res_text.stdout

    # JSON report
    res_json = runner.invoke(app, ["report", str(run_id), "--format", "json"])
    assert res_json.exit_code == 0
    assert '"scan_run_id":' in res_json.stdout
    assert '"NIST-TEST"' in res_json.stdout

    # HTML report
    res_html = runner.invoke(app, ["report", str(run_id), "--format", "html"])
    assert res_html.exit_code == 0
    assert "report_run_" in res_html.stdout or "HTML" in res_html.stdout
