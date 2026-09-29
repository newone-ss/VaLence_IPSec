"""
TunnelTwin Fix Engine — strongSwan swanctl.conf Generator.

Synthesizes hardened, modern swanctl configuration files adhering to
specified compliance profiles (e.g. aes256gcm-baseline, NIST SP 800-77r1).
"""

from __future__ import annotations

from tunneltwin.fix.models import SWANCTL_VERIFIED_LABEL, RemediationConfig, generate_unified_diff
from tunneltwin.fix.profiles import AES256GCM_BASELINE, SecurityProfile, get_profile

# Default pre-shared key used by lab/testbed remediation outputs.
DEFAULT_LAB_PSK = "vPn-sEcReT-2026"


def generate_swanctl_conf(
    profile: SecurityProfile | str = AES256GCM_BASELINE,
    conn_name: str = "remediated-conn",
    child_name: str = "remediated-child",
    local_addrs: str = "10.0.1.1",
    remote_addrs: str = "10.0.1.2",
    local_ts: str = "10.0.1.0/30",
    remote_ts: str = "10.0.1.0/30",
    secret: str = DEFAULT_LAB_PSK,
    role: str = "left",  # "left" (initiator) or "right" (responder)
    old_config_content: str | None = None,
) -> RemediationConfig:
    """
    Generate a hardened strongSwan swanctl.conf configuration.

    Args:
        profile: Target SecurityProfile or profile ID string.
        conn_name: Name of the IKE connection section.
        child_name: Name of the child SA section.
        local_addrs: Local IP address or %any.
        remote_addrs: Remote IP address or %any.
        local_ts: Local traffic selector subnet.
        remote_ts: Remote traffic selector subnet.
        secret: Pre-shared key for authentication.
        role: "left" for initiator, "right" for responder.
        old_config_content: Optional original config for diff generation.

    Returns:
        RemediationConfig object carrying content, metadata, and optional diff.
    """
    prof = get_profile(profile) if isinstance(profile, str) else profile

    proposals_str = ",".join(prof.ike_proposals)
    esp_proposals_str = ",".join(prof.esp_proposals)

    # Determine peer naming for secret section
    secret_id = f"ike-{conn_name}"

    lines = [
        "# ─────────────────────────────────────────────────────────────────────────────",
        "#  TunnelTwin Remediated Configuration — strongSwan swanctl",
        f"#  Profile   : {prof.name} ({prof.id})",
        f"#  Role      : {role.upper()} ({local_addrs} -> {remote_addrs})",
        "#  Standards : NIST SP 800-77 Rev 1 / RFC 7296 (IKEv2) / RFC 5282 (AEAD)",
        "# ─────────────────────────────────────────────────────────────────────────────",
        "",
        "connections {",
        f"    {conn_name} {{",
        f"        version = {prof.ike_version}",
        f"        local_addrs = {local_addrs}",
        f"        remote_addrs = {remote_addrs}",
        f"        proposals = {proposals_str}",
        "",
        "        local {",
        "            auth = psk",
        "        }",
        "",
        "        remote {",
        "            auth = psk",
        "        }",
        "",
        "        children {",
        f"            {child_name} {{",
        f"                esp_proposals = {esp_proposals_str}",
        "                mode = tunnel",
        f"                local_ts = {local_ts}",
        f"                remote_ts = {remote_ts}",
        "                start_action = none",
        "            }",
        "        }",
        "    }",
        "}",
        "",
        "secrets {",
        f"    {secret_id} {{",
        f'        secret = "{secret}"',
        "    }",
        "}",
        "",
    ]

    content = "\n".join(lines)

    diff = ""
    if old_config_content:
        diff = generate_unified_diff(old_config_content, content, filename=f"swanctl-{role}.conf")

    return RemediationConfig(
        target_device="swanctl",
        profile_name=prof.id,
        content=content,
        verification_status=SWANCTL_VERIFIED_LABEL,
        diff=diff,
        metadata={
            "role": role,
            "conn_name": conn_name,
            "child_name": child_name,
            "ike_version": str(prof.ike_version),
            "proposals": proposals_str,
            "esp_proposals": esp_proposals_str,
        },
    )


def generate_swanctl_pair(
    profile: SecurityProfile | str = AES256GCM_BASELINE,
    conn_name: str = "remediated-conn",
    child_name: str = "remediated-child",
    left_ip: str = "10.0.1.1",
    right_ip: str = "10.0.1.2",
    subnet: str = "10.0.1.0/30",
    secret: str = DEFAULT_LAB_PSK,
    old_left_content: str | None = None,
    old_right_content: str | None = None,
    left_ts: str | None = None,
    right_ts: str | None = None,
) -> tuple[RemediationConfig, RemediationConfig]:
    """
    Generate matching pair of swanctl configurations for initiator (left)
    and responder (right) peers.

    Args:
        left_ts: Traffic selector for the left peer (defaults to subnet).
        right_ts: Traffic selector for the right peer (defaults to subnet).
    """
    left_cfg = generate_swanctl_conf(
        profile=profile,
        conn_name=conn_name,
        child_name=child_name,
        local_addrs=left_ip,
        remote_addrs=right_ip,
        local_ts=left_ts or subnet,
        remote_ts=right_ts or subnet,
        secret=secret,
        role="left",
        old_config_content=old_left_content,
    )

    right_cfg = generate_swanctl_conf(
        profile=profile,
        conn_name=conn_name,
        child_name=child_name,
        local_addrs=right_ip,
        remote_addrs=left_ip,
        local_ts=right_ts or subnet,
        remote_ts=left_ts or subnet,
        secret=secret,
        role="right",
        old_config_content=old_right_content,
    )

    return left_cfg, right_cfg
