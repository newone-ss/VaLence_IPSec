"""
TunnelTwin Fix Engine — Standard Cryptographic Security Profiles.

Contains pre-configured profiles adhering to modern security standards:
  - aes256gcm-baseline: Modern AEAD baseline (AES-256-GCM, ECP-384/256, PRF-SHA384/256).
  - nist-sp800-77r1: Strictly compliant with NIST SP 800-77 Rev 1 guidelines.
  - cnsa-suite: Strictly compliant with NSA CNSA 2.0 192-bit security floor.
"""

from __future__ import annotations

from tunneltwin.fix.models import SecurityProfile

# 1. aes256gcm-baseline: Recommended modern standard for IPsec VPNs
AES256GCM_BASELINE = SecurityProfile(
    id="aes256gcm-baseline",
    name="AES-256-GCM Baseline Profile",
    description="Modern high-assurance AEAD suite utilizing AES-256-GCM with ECP-384/ECP-256 key exchange.",
    ike_version=2,
    ike_proposals=[
        "aes256gcm16-prfsha384-ecp384",
        "aes256gcm16-prfsha256-ecp256",
        "aes256-sha384-ecp384",
    ],
    esp_proposals=[
        "aes256gcm16-ecp384",
        "aes256gcm16",
    ],
    cisco_ike_encryption="aes-gcm-256",
    cisco_ike_integrity="null",
    cisco_ike_groups=[20, 19],  # Group 20 = NIST P-384 (ECP-384), Group 19 = NIST P-256 (ECP-256)
    cisco_ike_prfs=["sha384", "sha256"],
    cisco_esp_encryption="aes-gcm-256",
    cisco_esp_integrity="null",
    libreswan_ike=["aes_gcm256-sha2_384;dh20", "aes_gcm256-sha2_256;dh19"],
    libreswan_esp=["aes_gcm256"],
    ike_lifetime_seconds=86400,
    esp_lifetime_seconds=28800,
    dos_cookie_threshold=10,
)

# 2. nist-sp800-77r1: NIST SP 800-77 Rev 1 compliance profile
NIST_SP800_77R1 = SecurityProfile(
    id="nist-sp800-77r1",
    name="NIST SP 800-77 Rev 1 Compliance Profile",
    description="Federal compliance profile implementing NIST SP 800-77 Rev 1 & SP 800-131A recommendations.",
    ike_version=2,
    ike_proposals=[
        "aes256gcm16-prfsha384-ecp384",
        "aes256-sha256-modp2048",
    ],
    esp_proposals=[
        "aes256gcm16",
        "aes256-sha256",
    ],
    cisco_ike_encryption="aes-gcm-256",
    cisco_ike_integrity="null",
    cisco_ike_groups=[20, 14],  # Group 20 (ECP-384), Group 14 (MODP-2048)
    cisco_ike_prfs=["sha384", "sha256"],
    cisco_esp_encryption="aes-gcm-256",
    cisco_esp_integrity="null",
    libreswan_ike=["aes_gcm256-sha2_384;dh20", "aes256-sha2_256;dh14"],
    libreswan_esp=["aes_gcm256", "aes256-sha2_256"],
    ike_lifetime_seconds=86400,
    esp_lifetime_seconds=28800,
    dos_cookie_threshold=10,
)

# 3. cnsa-suite: NSA Commercial National Security Algorithm Suite 2.0
NSA_CNSA_SUITE = SecurityProfile(
    id="cnsa-suite",
    name="NSA CNSA 2.0 National Security Profile",
    description=(
        "Rigid 192-bit minimum security floor for National Security Systems (IKEv2, ECP-384, AES-256, SHA-384)."
    ),
    ike_version=2,
    ike_proposals=[
        "aes256gcm16-prfsha384-ecp384",
    ],
    esp_proposals=[
        "aes256gcm16-ecp384",
    ],
    cisco_ike_encryption="aes-gcm-256",
    cisco_ike_integrity="null",
    cisco_ike_groups=[20],  # Group 20 (ECP-384) only
    cisco_ike_prfs=["sha384"],
    cisco_esp_encryption="aes-gcm-256",
    cisco_esp_integrity="null",
    libreswan_ike=["aes_gcm256-sha2_384;dh20"],
    libreswan_esp=["aes_gcm256"],
    ike_lifetime_seconds=86400,
    esp_lifetime_seconds=28800,
    dos_cookie_threshold=1,
)

STANDARD_PROFILES: dict[str, SecurityProfile] = {
    "aes256gcm-baseline": AES256GCM_BASELINE,
    "nist-sp800-77r1": NIST_SP800_77R1,
    "cnsa-suite": NSA_CNSA_SUITE,
}


def get_profile(name_or_id: str | None = None) -> SecurityProfile:
    """Retrieve a security profile by ID or name (defaults to aes256gcm-baseline)."""
    if not name_or_id:
        return AES256GCM_BASELINE

    key = name_or_id.lower().strip()
    if key in STANDARD_PROFILES:
        return STANDARD_PROFILES[key]

    # Flexible matching
    for pid, prof in STANDARD_PROFILES.items():
        if key in pid or key in prof.name.lower():
            return prof

    raise ValueError(
        f"Unknown security profile '{name_or_id}'. Available profiles: {', '.join(STANDARD_PROFILES.keys())}"
    )
