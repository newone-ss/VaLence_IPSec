"""
Unit tests for the consent-gated target allowlist (ADR-0003 double-barrier).

Tests:
  - Target in allowlist with consent → allowed
  - Target in allowlist without consent → denied
  - Target not in allowlist → denied
  - CIDR network matching
  - Multiple entries
"""

import pytest

from tunneltwin.probe.allowlist import (
    ConsentDeniedError,
    TargetAllowlist,
)


class TestAllowlistBasic:
    def test_authorized_target(self):
        """Target in list with consent_verified=True → passes."""
        al = TargetAllowlist()
        al.add("10.0.1.1", consent_verified=True, owner="lab")
        entry = al.verify("10.0.1.1")
        assert entry.consent_verified is True
        assert al.is_authorized("10.0.1.1") is True

    def test_no_consent_raises(self):
        """Target in list but consent_verified=False → denied."""
        al = TargetAllowlist()
        al.add("10.0.1.1", consent_verified=False, owner="lab")
        with pytest.raises(ConsentDeniedError, match="consent_verified is False"):
            al.verify("10.0.1.1")
        assert al.is_authorized("10.0.1.1") is False

    def test_unknown_target_raises(self):
        """Target not in list → denied."""
        al = TargetAllowlist()
        al.add("10.0.1.1", consent_verified=True)
        with pytest.raises(ConsentDeniedError, match="not in the scan allowlist"):
            al.verify("192.168.1.1")
        assert al.is_authorized("192.168.1.1") is False

    def test_empty_allowlist_denies(self):
        """Empty allowlist denies all targets."""
        al = TargetAllowlist()
        with pytest.raises(ConsentDeniedError):
            al.verify("10.0.1.1")


class TestCIDRMatching:
    def test_cidr_match(self):
        """Target within CIDR range → allowed."""
        al = TargetAllowlist()
        al.add("10.0.1.0/30", consent_verified=True, owner="lab")
        assert al.is_authorized("10.0.1.1") is True
        assert al.is_authorized("10.0.1.2") is True

    def test_cidr_outside_range(self):
        """Target outside CIDR range → denied."""
        al = TargetAllowlist()
        al.add("10.0.1.0/30", consent_verified=True)
        assert al.is_authorized("10.0.2.1") is False

    def test_cidr_no_consent(self):
        """Target within CIDR but consent=False → denied."""
        al = TargetAllowlist()
        al.add("10.0.1.0/24", consent_verified=False)
        with pytest.raises(ConsentDeniedError, match="consent_verified is False"):
            al.verify("10.0.1.5")


class TestMultipleEntries:
    def test_multiple_authorized_targets(self):
        al = TargetAllowlist()
        al.add("10.0.1.1", consent_verified=True, owner="left")
        al.add("10.0.1.2", consent_verified=True, owner="right")
        al.add("192.168.0.1", consent_verified=False, owner="prod")
        assert al.is_authorized("10.0.1.1") is True
        assert al.is_authorized("10.0.1.2") is True
        assert al.is_authorized("192.168.0.1") is False
        assert al.is_authorized("172.16.0.1") is False

    def test_overlapping_cidr_and_host(self):
        """Host entry takes effect even with overlapping CIDR."""
        al = TargetAllowlist()
        al.add("10.0.1.0/30", consent_verified=True)
        assert al.is_authorized("10.0.1.1") is True
        assert al.is_authorized("10.0.1.2") is True


class TestEdgeCases:
    def test_invalid_ip_format(self):
        """Non-IP strings not matching any entry → denied."""
        al = TargetAllowlist()
        al.add("10.0.1.1", consent_verified=True)
        assert al.is_authorized("not-an-ip") is False

    def test_entry_metadata(self):
        """Verify entry metadata fields are preserved."""
        al = TargetAllowlist()
        al.add("10.0.1.1", consent_verified=True, owner="lab-team", notes="Phase 0 test target")
        entry = al.verify("10.0.1.1")
        assert entry.owner == "lab-team"
        assert entry.notes == "Phase 0 test target"
