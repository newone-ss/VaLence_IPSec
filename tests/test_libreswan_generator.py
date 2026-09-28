"""
Tests for Libreswan Remediation Configuration Generator.

Verifies:
  - Generation of compliant Libreswan ipsec.conf for all standard profiles.
  - Secret file content generation.
  - Verification status labeling ('lab-verified').
  - Diff generation against original configuration.
"""

from __future__ import annotations

from tunneltwin.fix import (
    AES256GCM_BASELINE,
    LIBRESWAN_VERIFIED_LABEL,
    NIST_SP800_77R1,
    NSA_CNSA_SUITE,
    generate_libreswan_config,
    generate_libreswan_secrets,
)


def test_generate_libreswan_baseline_config() -> None:
    config = generate_libreswan_config(
        profile=AES256GCM_BASELINE,
        conn_name="swan-baseline",
        left="10.0.1.1",
        right="10.0.1.2",
    )
    assert config.target_device == "libreswan"
    assert config.verification_status == LIBRESWAN_VERIFIED_LABEL
    assert "conn swan-baseline" in config.content
    assert "left=10.0.1.1" in config.content
    assert "right=10.0.1.2" in config.content
    assert "ikev2=insist" in config.content
    assert "ike=aes_gcm256-sha2_384;dh20,aes_gcm256-sha2_256;dh19" in config.content
    assert "esp=aes_gcm256" in config.content
    assert "authby=secret" in config.content


def test_generate_libreswan_nist_profile() -> None:
    config = generate_libreswan_config(
        profile=NIST_SP800_77R1,
        conn_name="swan-nist",
    )
    assert "conn swan-nist" in config.content
    assert "ike=aes_gcm256-sha2_384;dh20,aes256-sha2_256;dh14" in config.content
    assert "esp=aes_gcm256,aes256-sha2_256" in config.content


def test_generate_libreswan_cnsa_profile() -> None:
    config = generate_libreswan_config(
        profile=NSA_CNSA_SUITE,
        conn_name="swan-cnsa",
    )
    assert "conn swan-cnsa" in config.content
    assert "ike=aes_gcm256-sha2_384;dh20" in config.content
    assert "esp=aes_gcm256" in config.content


def test_generate_libreswan_secrets() -> None:
    secrets = generate_libreswan_secrets("10.0.1.1", "10.0.1.2", "SuperSecretKey!")
    assert secrets == '10.0.1.1 10.0.1.2 : PSK "SuperSecretKey!"\n'


def test_generate_libreswan_diff() -> None:
    old_conf = """conn swan-old
    ike=3des-sha1;modp1024
    esp=3des-sha1
    authby=secret
"""
    config = generate_libreswan_config(
        profile=AES256GCM_BASELINE,
        conn_name="swan-old",
        old_config_content=old_conf,
    )
    assert config.diff != ""
    assert "a/ipsec.conf" in config.diff
    assert "b/ipsec.conf" in config.diff
    assert "+    ike=aes_gcm256" in config.diff
