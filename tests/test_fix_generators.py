"""
Phase 3 — Unit Tests for Remediation Generators and Twin Check.

Verifies:
  1. Security profile definitions (aes256gcm-baseline, nist-sp800-77r1, cnsa-suite).
  2. strongSwan swanctl.conf generator and unified diff generation.
  3. Cisco ASA generator — strictly verifies "generated, not lab-verified" label
     is present in content, metadata, string output, and display formats.
  4. TwinVerifier workflow comparing baseline vs remediated states.
"""

from __future__ import annotations

from tunneltwin.fix import (
    AES256GCM_BASELINE,
    CISCO_ASA_VERIFICATION_LABEL,
    NIST_SP800_77R1,
    NSA_CNSA_SUITE,
    TwinVerifier,
    build_remediation_artifacts,
    generate_cisco_asa_config,
    generate_swanctl_conf,
    generate_swanctl_pair,
    get_profile,
)
from tunneltwin.ike.constants import (
    EncryptionAlgorithm,
    PRFAlgorithm,
    TransformType,
)
from tunneltwin.probe.result import (
    AcceptedTransform,
    GatewayScanResult,
    IKEv1AcceptedTransform,
    ScanStatus,
)


class TestSecurityProfiles:
    """Tests for cryptographic profile registry."""

    def test_default_profile_is_aes256gcm(self) -> None:
        prof = get_profile()
        assert prof.id == "aes256gcm-baseline"
        assert prof.ike_version == 2
        assert any("aes256gcm" in p for p in prof.ike_proposals)

    def test_get_profile_by_id(self) -> None:
        nist = get_profile("nist-sp800-77r1")
        assert nist == NIST_SP800_77R1
        cnsa = get_profile("cnsa-suite")
        assert cnsa == NSA_CNSA_SUITE

    def test_unknown_profile_raises(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="Unknown security profile"):
            get_profile("des-weak-unknown")


class TestSwanctlGenerator:
    """Tests for strongSwan swanctl.conf generator."""

    def test_swanctl_generation_content(self) -> None:
        cfg = generate_swanctl_conf(
            profile=AES256GCM_BASELINE,
            conn_name="test-conn",
            child_name="test-child",
            local_addrs="10.0.1.1",
            remote_addrs="10.0.1.2",
            role="left",
        )
        assert cfg.target_device == "swanctl"
        assert cfg.verification_status == "lab-verified"
        assert "connections {" in cfg.content
        assert "test-conn {" in cfg.content
        assert "version = 2" in cfg.content
        expected = "proposals = aes256gcm16-prfsha384-ecp384,aes256gcm16-prfsha256-ecp256,aes256-sha384-ecp384"
        assert expected in cfg.content
        assert "esp_proposals = aes256gcm16-ecp384,aes256gcm16" in cfg.content
        assert "secrets {" in cfg.content

    def test_swanctl_pair_generation(self) -> None:
        left, right = generate_swanctl_pair(
            profile="nist-sp800-77r1",
            conn_name="peer-conn",
            child_name="peer-child",
        )
        assert "local_addrs = 10.0.1.1" in left.content
        assert "remote_addrs = 10.0.1.2" in left.content
        assert "local_addrs = 10.0.1.2" in right.content
        assert "remote_addrs = 10.0.1.1" in right.content

    def test_swanctl_diff_generation(self) -> None:
        old_conf = "connections {\n  weak-conn {\n    version = 1\n    proposals = 3des-sha1-modp1024\n  }\n}\n"
        cfg = generate_swanctl_conf(
            profile=AES256GCM_BASELINE,
            conn_name="weak-conn",
            child_name="weak-child",
            old_config_content=old_conf,
        )
        assert cfg.diff != ""
        assert "--- a/swanctl-left.conf (insecure)" in cfg.diff
        assert "+++ b/swanctl-left.conf (remediated)" in cfg.diff
        assert "-    version = 1" in cfg.diff
        assert "+        version = 2" in cfg.diff


class TestCiscoASAGenerator:
    """
    Tests for Cisco ASA generator.

    MANDATORY REQUIREMENT:
      Verify that 'generated, not lab-verified' is displayed in:
        1. config.verification_status
        2. config.content
        3. str(config)
        4. repr(config)
        5. config.display()
    """

    def test_cisco_asa_mandatory_label_enforcement(self) -> None:
        cfg = generate_cisco_asa_config(
            profile="aes256gcm-baseline",
            peer_ip="192.168.100.1",
        )

        # 1. Verification status attribute
        assert cfg.verification_status == CISCO_ASA_VERIFICATION_LABEL
        assert "generated, not lab-verified" in cfg.verification_status

        # 2. In content itself
        assert CISCO_ASA_VERIFICATION_LABEL in cfg.content
        assert f"STATUS    : {CISCO_ASA_VERIFICATION_LABEL}" in cfg.content
        assert f"! [VERIFICATION NOTICE: {CISCO_ASA_VERIFICATION_LABEL}]" in cfg.content

        # 3. In __str__ representation
        string_repr = str(cfg)
        assert CISCO_ASA_VERIFICATION_LABEL in string_repr

        # 4. In __repr__ representation
        obj_repr = repr(cfg)
        assert CISCO_ASA_VERIFICATION_LABEL in obj_repr

        # 5. In display() output
        display_output = cfg.display()
        assert CISCO_ASA_VERIFICATION_LABEL in display_output
        assert "GENERATED, NOT LAB-VERIFIED" in display_output

    def test_cisco_asa_syntax_components(self) -> None:
        cfg = generate_cisco_asa_config(
            profile="aes256gcm-baseline",
            peer_ip="10.0.1.2",
            local_interface="outside",
        )
        # Policy
        assert "crypto ikev2 policy 10" in cfg.content
        assert "encryption aes-gcm-256" in cfg.content
        assert "integrity null" in cfg.content
        assert "group 20 19" in cfg.content
        assert "prf sha384 sha256" in cfg.content
        # Enable interface
        assert "crypto ikev2 enable outside" in cfg.content
        # IPsec proposal
        assert "crypto ipsec ikev2 ipsec-proposal" in cfg.content
        # Crypto map
        assert "crypto map VPN_MAP" in cfg.content
        assert "set peer 10.0.1.2" in cfg.content
        # Tunnel group
        assert "tunnel-group 10.0.1.2 type ipsec-l2l" in cfg.content
        assert "ikev2 remote-authentication pre-shared-key" in cfg.content


class TestTwinVerifierLogic:
    """Tests for TwinVerifier comparing simulated baseline vs remediated scans."""

    def _make_weak_scan(self) -> GatewayScanResult:
        result = GatewayScanResult(
            target_ip="10.0.1.2",
            target_port=500,
            scan_status=ScanStatus.SUCCESS,
        )
        result.mark_observed_ike_version("IKEv1")
        result.mark_cookie_required(False)
        result.ikev1_accepted.append(
            IKEv1AcceptedTransform(
                encryption=5,  # THREE_DES_CBC
                hash_alg=2,  # SHA1
                auth_method=1,  # PSK
                dh_group=2,  # MODP_1024
            )
        )
        return result

    def _make_remediated_scan(self) -> GatewayScanResult:
        result = GatewayScanResult(
            target_ip="10.0.1.2",
            target_port=500,
            scan_status=ScanStatus.SUCCESS,
        )
        result.mark_observed_ike_version("IKEv2")
        result.mark_cookie_required(True)  # DoS protection active
        result.add_accepted_dh_group("ECP-384")
        result.accepted_transforms.extend(
            [
                AcceptedTransform(
                    transform_type=TransformType.ENCR,
                    transform_id=EncryptionAlgorithm.ENCR_AES_GCM_16,
                    key_length=256,
                ),
                AcceptedTransform(
                    transform_type=TransformType.PRF,
                    transform_id=PRFAlgorithm.PRF_HMAC_SHA2_384,
                ),
            ]
        )
        return result

    def test_twin_transition_clears_findings(self) -> None:
        verifier = TwinVerifier()
        weak_scan = self._make_weak_scan()
        remediated_scan = self._make_remediated_scan()

        remediated_cfg = generate_swanctl_conf(profile="aes256gcm-baseline")

        twin_result = verifier.verify_twin_transition(
            baseline_scan=weak_scan,
            remediated_scan=remediated_scan,
            remediated_config=remediated_cfg,
            baseline_tunnel_ok=True,
            remediated_tunnel_ok=True,
            ping_verified=True,
        )

        assert twin_result.passed is True
        assert twin_result.old_score < 40
        assert twin_result.new_score > 90
        assert len(twin_result.cleared_findings) > 0
        # NIST-001 (IKEv1) and NIST-004 (3DES) must be in cleared findings
        cleared_text = " ".join(twin_result.cleared_findings)
        assert "NIST-001" in cleared_text
        assert "NIST-004" in cleared_text

        # Verify summary format
        summary = twin_result.summary()
        assert "PASSED" in summary
        assert "STEP 1: Baseline Scan" in summary
        assert "STEP 3: Re-Scan Verification" in summary
        assert "CLEARED: NIST-001" in summary

    def test_build_remediation_artifacts_helper(self) -> None:
        old_left = "connections { weak-conn { version = 1 } }"
        old_right = "connections { weak-conn { version = 1 } }"
        left_cfg, right_cfg = build_remediation_artifacts(
            old_profile_name="weak",
            old_left_content=old_left,
            old_right_content=old_right,
        )
        assert "weak-conn" in left_cfg.content
        assert "weak-child" in left_cfg.content
        assert left_cfg.diff != ""
        assert right_cfg.diff != ""
