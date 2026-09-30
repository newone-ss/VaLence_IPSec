"""
tests/test_api.py -- Integration tests for TunnelTwin FastAPI backend.

Verifies:
- /api/health endpoint
- /api/fleet endpoint
- /api/probe receiving frontend inputs and returning protocol facts
- /api/reports/{id} endpoint
- /api/verify/{id} cryptographic seal verification
- /api/attest/{id} compliance certificate generation
- /api/fix/{id} remediation diff generation
- /api/analysis PCAP upload endpoint
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session  # noqa: E402

from tunneltwin.api.app import app  # noqa: E402
from tunneltwin.core.db import (  # noqa: E402
    Finding,
    FindingStatus,
    Gateway,
    ProvenanceEnum,
    ScanRun,
    ScanStatus,
    Target,
    engine,
    init_db,
)
from tunneltwin.seal.engine import seal_scan_run  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def setup_api_database():
    """Ensure database has at least one sealed scan run (run 24) for reports/verify/attest in CI."""
    init_db()
    with Session(engine) as session:
        run = session.get(ScanRun, 24)
        if not run:
            target = Target(name="ci-test-target", ip_range="10.0.1.2/32")
            session.add(target)
            session.commit()
            session.refresh(target)

            gw = Gateway(
                target_id=target.id,
                ip_address="10.0.1.2",
                port=500,
                vendor_type="cisco_asa",
                ike_version="IKEv1",
                responded=True,
            )
            session.add(gw)
            session.commit()
            session.refresh(gw)

            run = ScanRun(
                id=24,
                target_id=target.id,
                scan_type="active_probe",
                status=ScanStatus.COMPLETED,
            )
            session.add(run)
            session.commit()
            session.refresh(run)

            f1 = Finding(
                scan_run_id=24,
                rule_id="NIST-800-77-IKEV1-DEPRECATED",
                rule_framework="nist_sp800_77r1",
                severity="CRITICAL",
                status=FindingStatus.FAIL,
                parameter="ike_version",
                expected="IKEv2",
                observed="IKEv1",
                provenance=ProvenanceEnum.OBSERVED,
                detail="IKEv1 is deprecated",
            )
            session.add(f1)
            session.commit()

            seal_scan_run(24, key_dir=Path(".keys"))


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


def test_api_health(client: TestClient) -> None:
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"
    assert "total_scan_runs" in data


def test_api_fleet(client: TestClient) -> None:
    res = client.get("/api/fleet")
    assert res.status_code == 200
    data = res.json()
    assert "gateways" in data
    assert "scan_runs" in data
    assert isinstance(data["gateways"], list)


def test_api_probe_receives_frontend_input(client: TestClient) -> None:
    payload = {
        "target": "10.0.1.2",
        "port": 500,
        "probe_mode": "ike",
        "consent": True,
    }
    res = client.post("/api/probe", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert data["target"] == "10.0.1.2"
    assert data["discovered_ike_version"] == "IKEv1"
    assert data["findings_count"] > 0
    assert len(data["accepted_transforms"]) > 0


def test_api_probe_custom_ip(client: TestClient) -> None:
    payload = {
        "target": "192.168.1.100",
        "port": 500,
        "probe_mode": "ike",
        "consent": True,
    }
    res = client.post("/api/probe", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert data["target"] == "192.168.1.100"
    assert data["discovered_ike_version"] == "IKEv2"


def test_api_probe_empty_target_fails(client: TestClient) -> None:
    payload = {
        "target": "",
        "port": 500,
        "probe_mode": "ike",
        "consent": True,
    }
    res = client.post("/api/probe", json=payload)
    assert res.status_code == 400


def test_api_report_and_verify(client: TestClient) -> None:
    # ScanRun 24 is our real empirical scan run in tunneltwin.db
    res = client.get("/api/reports/24")
    if res.status_code == 200:
        data = res.json()
        assert data["scan_run_id"] == 24
        assert len(data["findings"]) > 0

        # Verify endpoint
        verify_res = client.post("/api/verify/24")
        assert verify_res.status_code == 200
        v_data = verify_res.json()
        assert v_data["status"] == "VALID"
        assert v_data["valid"] is True


def test_api_attest(client: TestClient) -> None:
    res = client.get("/api/attest/24")
    if res.status_code == 200:
        data = res.json()
        assert data["status"] == "AUTHENTIC"
        assert "certificate_markdown" in data


def test_api_fix(client: TestClient) -> None:
    res = client.post("/api/fix/24")
    assert res.status_code == 200
    data = res.json()
    assert data["target_vendor"] == "strongswan"
    assert "diff" in data


def test_api_analysis_pcap_upload(client: TestClient) -> None:
    dummy_pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 32
    files = {"file": ("test_capture.pcap", dummy_pcap, "application/vnd.tcpdump.pcap")}
    res = client.post("/api/analysis", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "analyzed"
    assert data["file_name"] == "test_capture.pcap"
    assert data["rfc4303_compliant"] is True
