"""
Unit and integration tests for the async IKE probe scanner.

Unit tests (always run):
  - Consent denied stops scan immediately
  - Scan result provenance tagging
  - Result summary formatting

Integration tests (marked, require WSL2 netns testbed):
  - Scan the 4 Phase-0 namespace gateways
  - Verify accepted/rejected proposals match expected profiles
  - Cookie handling against a cookie-enabled endpoint
"""

import asyncio

from tunneltwin.probe.allowlist import TargetAllowlist
from tunneltwin.probe.result import GatewayScanResult, ScanStatus
from tunneltwin.probe.scanner import ScanConfig, scan_gateway

# ─── Unit Tests (always run, no network required) ────────────────


class TestConsentDenied:
    def test_scan_refuses_without_consent(self):
        """Scan must refuse immediately if target not in allowlist."""
        al = TargetAllowlist()

        result = asyncio.run(scan_gateway("10.0.1.1", al))
        assert result.scan_status == ScanStatus.CONSENT_DENIED
        assert "not in the scan allowlist" in result.error_message

    def test_scan_refuses_without_consent_flag(self):
        """Scan must refuse if consent_verified is False."""
        al = TargetAllowlist()
        al.add("10.0.1.1", consent_verified=False)

        result = asyncio.run(scan_gateway("10.0.1.1", al))
        assert result.scan_status == ScanStatus.CONSENT_DENIED
        assert "consent_verified is False" in result.error_message

    def test_scan_refuses_unapproved_ip(self):
        """Scan must refuse IPs not in the allowlist even if others are."""
        al = TargetAllowlist()
        al.add("10.0.1.1", consent_verified=True)

        result = asyncio.run(scan_gateway("192.168.1.1", al))
        assert result.scan_status == ScanStatus.CONSENT_DENIED


class TestScanResultProvenance:
    def test_observed_ike_version(self):
        """IKE version finding must carry OBSERVED provenance."""
        from tunneltwin.core.models import ProvenanceTag

        result = GatewayScanResult(
            target_ip="10.0.1.1",
            target_port=500,
            scan_status=ScanStatus.SUCCESS,
        )
        result.mark_observed_ike_version("IKEv2")
        assert result.ike_version_detected.tag == ProvenanceTag.OBSERVED
        assert result.ike_version_detected.value == "IKEv2"
        assert result.ike_version_detected.is_known()

    def test_observed_dh_group_accepted(self):
        from tunneltwin.core.models import ProvenanceTag

        result = GatewayScanResult(
            target_ip="10.0.1.1",
            target_port=500,
            scan_status=ScanStatus.SUCCESS,
        )
        result.add_accepted_dh_group("MODP-2048")
        assert len(result.accepted_dh_groups) == 1
        assert result.accepted_dh_groups[0].tag == ProvenanceTag.OBSERVED
        assert result.accepted_dh_groups[0].value == "MODP-2048"

    def test_observed_dh_group_rejected(self):
        from tunneltwin.core.models import ProvenanceTag

        result = GatewayScanResult(
            target_ip="10.0.1.1",
            target_port=500,
            scan_status=ScanStatus.SUCCESS,
        )
        result.add_rejected_dh_group("MODP-768", "NO_PROPOSAL_CHOSEN")
        assert len(result.rejected_dh_groups) == 1
        assert result.rejected_dh_groups[0].tag == ProvenanceTag.OBSERVED

    def test_cookie_provenance(self):
        from tunneltwin.core.models import ProvenanceTag

        result = GatewayScanResult(
            target_ip="10.0.1.1",
            target_port=500,
            scan_status=ScanStatus.SUCCESS,
        )
        result.mark_cookie_required(True)
        assert result.cookie_required.tag == ProvenanceTag.OBSERVED
        assert result.cookie_required.value is True


class TestScanResultSummary:
    def test_summary_format(self):
        result = GatewayScanResult(
            target_ip="10.0.1.1",
            target_port=500,
            scan_status=ScanStatus.SUCCESS,
            scan_start_time=1000.0,
            scan_end_time=1001.5,
            probe_count=12,
        )
        result.mark_observed_ike_version("IKEv2")
        result.add_accepted_dh_group("MODP-2048")

        summary = result.summary()
        assert "10.0.1.1:500" in summary
        assert "success" in summary
        assert "IKEv2" in summary
        assert "MODP-2048" in summary


class TestScanTimerAndConfig:
    def test_scan_duration_tracking(self):
        import time

        result = GatewayScanResult(
            target_ip="10.0.1.1",
            target_port=500,
            scan_status=ScanStatus.SUCCESS,
        )
        result.start_timer()
        time.sleep(0.05)  # 50ms — sufficient for Windows monotonic clock resolution
        result.stop_timer()
        assert result.scan_duration_ms >= 1.0  # At least 1ms elapsed

    def test_default_config(self):
        config = ScanConfig()
        assert config.initial_timeout_ms == 300
        assert config.max_retries == 3
        assert config.try_ikev1 is True
