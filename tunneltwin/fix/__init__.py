"""
tunneltwin.fix — Automated configuration hardening and twin-check verification.

Modules:
  - models: SecurityProfile, RemediationConfig, TwinCheckResult, CISCO_ASA_VERIFICATION_LABEL.
  - profiles: Standard profiles (aes256gcm-baseline, nist-sp800-77r1, cnsa-suite).
  - swanctl_generator: strongSwan swanctl.conf generator and unified diff creator.
  - cisco_generator: Cisco ASA config generator (labeled 'generated, not lab-verified').
  - twin: TwinVerifier workflow confirming finding reproduction, clearance, and re-scan.
"""

from tunneltwin.fix.cisco_generator import generate_cisco_asa_config
from tunneltwin.fix.models import (
    CISCO_ASA_VERIFICATION_LABEL,
    SWANCTL_VERIFIED_LABEL,
    RemediationConfig,
    SecurityProfile,
    TwinCheckResult,
    generate_unified_diff,
)
from tunneltwin.fix.profiles import (
    AES256GCM_BASELINE,
    NIST_SP800_77R1,
    NSA_CNSA_SUITE,
    STANDARD_PROFILES,
    get_profile,
)
from tunneltwin.fix.swanctl_generator import generate_swanctl_conf, generate_swanctl_pair
from tunneltwin.fix.twin import TwinVerifier, build_remediation_artifacts

__all__ = [
    "AES256GCM_BASELINE",
    "CISCO_ASA_VERIFICATION_LABEL",
    "NIST_SP800_77R1",
    "NSA_CNSA_SUITE",
    "RemediationConfig",
    "SWANCTL_VERIFIED_LABEL",
    "SecurityProfile",
    "STANDARD_PROFILES",
    "TwinCheckResult",
    "TwinVerifier",
    "build_remediation_artifacts",
    "generate_cisco_asa_config",
    "generate_swanctl_conf",
    "generate_swanctl_pair",
    "generate_unified_diff",
    "get_profile",
]
