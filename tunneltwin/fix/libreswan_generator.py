"""
TunnelTwin Fix Engine — Libreswan ipsec.conf Generator.

Synthesizes hardened, modern Libreswan (pluto) configuration files and secrets
adhering to specified compliance profiles (e.g. aes256gcm-baseline, NIST SP 800-77r1, CNSA 2.0).
"""

from __future__ import annotations

from tunneltwin.fix.models import LIBRESWAN_VERIFIED_LABEL, RemediationConfig, generate_unified_diff
from tunneltwin.fix.profiles import AES256GCM_BASELINE, SecurityProfile, get_profile

# Default pre-shared key used by lab/testbed remediation outputs.
DEFAULT_LIBRESWAN_PSK = "TunnelTwinSuperSecretKeyPhase42026!"


def generate_libreswan_secrets(
    left: str = "10.0.1.1",
    right: str = "10.0.1.2",
    secret: str = DEFAULT_LIBRESWAN_PSK,
) -> str:
    """Generate ipsec.secrets format content for PSK authentication."""
    return f'{left} {right} : PSK "{secret}"\n'


def generate_libreswan_config(
    profile: SecurityProfile | str = AES256GCM_BASELINE,
    conn_name: str = "remediated-conn",
    left: str = "10.0.1.1",
    leftid: str | None = None,
    leftsubnet: str = "10.0.1.0/30",
    right: str = "10.0.1.2",
    rightid: str | None = None,
    rightsubnet: str = "10.0.1.0/30",
    secret: str = DEFAULT_LIBRESWAN_PSK,
    auto: str = "add",
    ikev2: str = "insist",
    old_config_content: str | None = None,
) -> RemediationConfig:
    """
    Generate a hardened Libreswan ipsec.conf connection configuration.

    Args:
        profile: Target SecurityProfile or profile ID string.
        conn_name: Name of the conn section.
        left: Local / left IP address.
        leftid: Local identity (defaults to left IP).
        leftsubnet: Local traffic selector subnet.
        right: Remote / right IP address.
        rightid: Remote identity (defaults to right IP).
        rightsubnet: Remote traffic selector subnet.
        secret: Pre-shared key for authentication.
        auto: Startup mode ("add", "start", "ignore", "route").
        ikev2: IKEv2 negotiation mode ("insist", "permit", "propose").
        old_config_content: Optional original config for diff generation.

    Returns:
        RemediationConfig object carrying content, metadata, secrets, and optional diff.
    """
    prof = get_profile(profile) if isinstance(profile, str) else profile

    l_id = leftid or left
    r_id = rightid or right

    ike_str = ",".join(prof.libreswan_ike) if prof.libreswan_ike else "aes_gcm256-sha2_384;dh20"
    esp_str = ",".join(prof.libreswan_esp) if prof.libreswan_esp else "aes_gcm256;dh20"

    secrets_content = generate_libreswan_secrets(left=left, right=right, secret=secret)

    lines = [
        "# ─────────────────────────────────────────────────────────────────────────────",
        "#  TunnelTwin Remediated Configuration — Libreswan (pluto)",
        f"#  Profile   : {prof.name} ({prof.id})",
        f"#  Peers     : {left} <-> {right}",
        "#  Standards : NIST SP 800-77 Rev 1 / RFC 7296 (IKEv2) / RFC 5282 (AEAD)",
        "# ─────────────────────────────────────────────────────────────────────────────",
        "",
        f"conn {conn_name}",
        f"    left={left}",
        f"    leftid={l_id}",
        f"    leftsubnet={leftsubnet}",
        f"    right={right}",
        f"    rightid={r_id}",
        f"    rightsubnet={rightsubnet}",
        f"    ikev2={ikev2}",
        f"    ike={ike_str}",
        f"    esp={esp_str}",
        "    authby=secret",
        f"    auto={auto}",
        f"    ikelifetime={prof.ike_lifetime_seconds}s",
        f"    salifetime={prof.esp_lifetime_seconds}s",
        "",
    ]

    content = "\n".join(lines)

    diff = ""
    if old_config_content is not None:
        diff = generate_unified_diff(
            old_content=old_config_content,
            new_content=content,
            filename="ipsec.conf",
        )

    metadata: dict[str, str] = {
        "conn_name": conn_name,
        "ike": ike_str,
        "esp": esp_str,
        "ike_lifetime": str(prof.ike_lifetime_seconds),
        "esp_lifetime": str(prof.esp_lifetime_seconds),
        "secrets": secrets_content,
        "auto": auto,
        "ikev2": ikev2,
    }

    return RemediationConfig(
        target_device="libreswan",
        profile_name=prof.name,
        content=content,
        verification_status=LIBRESWAN_VERIFIED_LABEL,
        diff=diff,
        metadata=metadata,
    )
