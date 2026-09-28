"""
Tests for TunnelTwin Behavioral Daemon Fingerprinting.

Verifies:
  - Vendor ID classification for Libreswan, strongSwan, and Cisco.
  - Behavioral notify payload quirk classification:
    * Libreswan unsolicited NAT-D (16388, 16389) without client request.
    * strongSwan RFC 7427 SIGNATURE_HASH_ALGORITHMS (16404).
    * Cisco ASA private notify codes (16400-16402).
  - Fact store integration: daemon_type fact with OBSERVED provenance.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from tunneltwin.core.models import ProvenanceTag
from tunneltwin.ike.codec import ParsedIKEMessage, ParsedNotify
from tunneltwin.probe.fingerprint import (
    DaemonFingerprint,
    DaemonType,
    classify_daemon,
)
from tunneltwin.probe.result import GatewayScanResult, ScanStatus
from tunneltwin.rules.facts import scan_result_to_facts


def test_classify_none_message() -> None:
    fp = classify_daemon(None)
    assert fp.daemon == DaemonType.UNKNOWN
    assert fp.confidence == 0.0
    assert not fp.is_identified


def test_classify_explicit_libreswan_vid() -> None:
    msg = MagicMock(spec=ParsedIKEMessage)
    msg.vendor_ids = [b"Something", b"OE-Libreswan-5.2", b"Other"]
    msg.notifies = []

    fp = classify_daemon(msg)
    assert fp.daemon == DaemonType.LIBRESWAN
    assert fp.confidence == 1.0
    assert fp.is_identified
    assert any("Libreswan" in e for e in fp.evidence)


def test_classify_explicit_strongswan_vid() -> None:
    msg = MagicMock(spec=ParsedIKEMessage)
    msg.vendor_ids = [b"\x88\x2f\x0a\x3c_strongSwan_5.9.13"]
    msg.notifies = []

    fp = classify_daemon(msg)
    assert fp.daemon == DaemonType.STRONGSWAN
    assert fp.confidence == 1.0
    assert fp.is_identified


def test_classify_explicit_cisco_vid() -> None:
    msg = MagicMock(spec=ParsedIKEMessage)
    msg.vendor_ids = [b"\x12\xf5\xf2\x8c_Cisco_ASA_9_14"]
    msg.notifies = []

    fp = classify_daemon(msg)
    assert fp.daemon == DaemonType.CISCO_ASA
    assert fp.confidence == 1.0
    assert fp.is_identified


def test_classify_libreswan_behavioral_quirk() -> None:
    """Libreswan emits unsolicited NAT-D (16388 & 16389) and omits 16404."""
    msg = MagicMock(spec=ParsedIKEMessage)
    msg.vendor_ids = []

    n1 = MagicMock(spec=ParsedNotify)
    n1.notify_type = 16388  # NAT_DETECTION_SOURCE_IP
    n2 = MagicMock(spec=ParsedNotify)
    n2.notify_type = 16389  # NAT_DETECTION_DESTINATION_IP
    n3 = MagicMock(spec=ParsedNotify)
    n3.notify_type = 16418  # REDIRECT_SUPPORTED / CHILDLESS

    msg.notifies = [n1, n2, n3]

    fp = classify_daemon(msg, rtt_ms=4.2)
    assert fp.daemon == DaemonType.LIBRESWAN
    assert fp.confidence >= 0.90
    assert fp.is_identified
    assert fp.rtt_ms == 4.2
    assert any("NAT_DETECTION" in e for e in fp.evidence)


def test_classify_strongswan_behavioral_quirk() -> None:
    """strongSwan emits RFC 7427 signature hash notify (16404) and omits unsolicited NAT-D."""
    msg = MagicMock(spec=ParsedIKEMessage)
    msg.vendor_ids = []

    n1 = MagicMock(spec=ParsedNotify)
    n1.notify_type = 16404  # SIGNATURE_HASH_ALGORITHMS
    n2 = MagicMock(spec=ParsedNotify)
    n2.notify_type = 16418  # REDIRECT_SUPPORTED

    msg.notifies = [n1, n2]

    fp = classify_daemon(msg, rtt_ms=3.5)
    assert fp.daemon == DaemonType.STRONGSWAN
    assert fp.confidence >= 0.90
    assert fp.is_identified
    assert any("SIGNATURE_HASH_ALGORITHMS" in e for e in fp.evidence)


def test_classify_cisco_private_notify() -> None:
    msg = MagicMock(spec=ParsedIKEMessage)
    msg.vendor_ids = []

    n1 = MagicMock(spec=ParsedNotify)
    n1.notify_type = 16400  # Cisco private

    msg.notifies = [n1]

    fp = classify_daemon(msg)
    assert fp.daemon == DaemonType.CISCO_ASA
    assert fp.confidence >= 0.90
    assert fp.is_identified


def test_classify_unknown_profile() -> None:
    msg = MagicMock(spec=ParsedIKEMessage)
    msg.vendor_ids = []
    msg.notifies = []

    fp = classify_daemon(msg)
    assert fp.daemon == DaemonType.UNKNOWN
    assert not fp.is_identified


def test_gateway_scan_result_detected_daemon() -> None:
    res = GatewayScanResult(
        target_ip="10.0.1.2",
        target_port=500,
        scan_status=ScanStatus.SUCCESS,
    )
    assert res.detected_daemon == "unknown"

    res.fingerprint = DaemonFingerprint(
        daemon=DaemonType.LIBRESWAN,
        confidence=0.95,
        evidence=["NAT-D unsolicited quirk"],
    )
    assert res.detected_daemon == "libreswan"
    assert "LIBRESWAN" in res.summary()


def test_scan_result_to_facts_records_daemon_type() -> None:
    res = GatewayScanResult(
        target_ip="10.0.1.2",
        target_port=500,
        scan_status=ScanStatus.SUCCESS,
    )
    res.fingerprint = DaemonFingerprint(
        daemon=DaemonType.LIBRESWAN,
        confidence=0.95,
        evidence=["NAT-D unsolicited quirk"],
    )

    facts = scan_result_to_facts(res)
    daemon_fact = facts.get_first("10.0.1.2:500", "daemon_type")
    assert daemon_fact is not None
    assert daemon_fact.value == "libreswan"
    assert daemon_fact.provenance == ProvenanceTag.OBSERVED
    assert daemon_fact.confidence == 0.95
