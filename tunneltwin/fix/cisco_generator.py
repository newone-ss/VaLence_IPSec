"""
TunnelTwin Fix Engine — Cisco ASA Configuration Generator.

Synthesizes Cisco Adaptive Security Appliance (ASA) IKEv2 site-to-site VPN
configurations adhering to target cryptographic compliance profiles.

CRITICAL COMPLIANCE REQUIREMENT:
  The output of this generator MUST be labeled:
  "generated, not lab-verified"
  everywhere it is displayed, formatted, or serialized.
"""

from __future__ import annotations

from tunneltwin.fix.models import CISCO_ASA_VERIFICATION_LABEL, RemediationConfig, generate_unified_diff
from tunneltwin.fix.profiles import AES256GCM_BASELINE, SecurityProfile, get_profile


def generate_cisco_asa_config(
    profile: SecurityProfile | str = AES256GCM_BASELINE,
    peer_ip: str = "10.0.1.2",
    local_interface: str = "outside",
    tunnel_group_name: str | None = None,
    crypto_map_name: str = "VPN_MAP",
    crypto_map_seq: int = 10,
    policy_id: int = 10,
    proposal_name: str = "TUNNELTWIN-IKEV2-PROPOSAL",
    acl_name: str = "VPN_TRAFFIC_ACL",
    local_subnet: str = "10.0.1.0 255.255.255.252",
    remote_subnet: str = "10.0.1.0 255.255.255.252",
    preshared_key: str = "vPn-sEcReT-2026",
    old_config_content: str | None = None,
) -> RemediationConfig:
    """
    Generate Cisco ASA IKEv2 / IPsec site-to-site configuration.

    ALL OUTPUT FROM THIS FUNCTION IS STRICTLY LABELED:
    "generated, not lab-verified"

    Args:
        profile: Target SecurityProfile or profile ID string.
        peer_ip: Remote gateway IP address.
        local_interface: Outside interface name (default: "outside").
        tunnel_group_name: Tunnel group identifier (defaults to peer_ip).
        crypto_map_name: Crypto map tag name.
        crypto_map_seq: Sequence number for crypto map entry.
        policy_id: IKEv2 policy priority number.
        proposal_name: IPsec IKEv2 proposal name.
        acl_name: Access-list name for interesting traffic.
        local_subnet: Local network and netmask.
        remote_subnet: Remote network and netmask.
        preshared_key: IKEv2 pre-shared key.
        old_config_content: Optional original config for diff generation.

    Returns:
        RemediationConfig with verification_status='generated, not lab-verified'.
    """
    prof = get_profile(profile) if isinstance(profile, str) else profile

    tg_name = tunnel_group_name or peer_ip
    groups_str = " ".join(str(g) for g in prof.cisco_ike_groups)
    prfs_str = " ".join(prof.cisco_ike_prfs)

    lines = [
        "! " + "=" * 76,
        "! TunnelTwin Automated Remediation — Cisco ASA Configuration",
        f"! STATUS    : {CISCO_ASA_VERIFICATION_LABEL}",
        f"! NOTICE    : {CISCO_ASA_VERIFICATION_LABEL.upper()}",
        f"! Profile   : {prof.name} ({prof.id})",
        "! Target    : Cisco Adaptive Security Appliance (ASA) Software 9.x+",
        "! " + "=" * 76,
        f"! [VERIFICATION NOTICE: {CISCO_ASA_VERIFICATION_LABEL}]",
        "! This configuration was synthesized based on Cisco ASA syntax standards.",
        "! It has NOT been executed or verified against a live physical or virtual",
        f"! Cisco testbed. Status is strictly: {CISCO_ASA_VERIFICATION_LABEL}.",
        "! " + "=" * 76,
        "",
        f"! ── Step 1: Interesting Traffic Access List [{CISCO_ASA_VERIFICATION_LABEL}] ──",
        f"access-list {acl_name} extended permit ip {local_subnet} {remote_subnet}",
        "",
        f"! ── Step 2: IKEv2 Policy Configuration [{CISCO_ASA_VERIFICATION_LABEL}] ──",
        f"crypto ikev2 policy {policy_id}",
        f" encryption {prof.cisco_ike_encryption}",
        f" integrity {prof.cisco_ike_integrity}",
        f" group {groups_str}",
        f" prf {prfs_str}",
        f" lifetime seconds {prof.ike_lifetime_seconds}",
        "",
        f"! ── Step 3: Enable IKEv2 on Interface [{CISCO_ASA_VERIFICATION_LABEL}] ──",
        f"crypto ikev2 enable {local_interface}",
        "",
        f"! ── Step 4: IPsec IKEv2 Proposal [{CISCO_ASA_VERIFICATION_LABEL}] ──",
        f"crypto ipsec ikev2 ipsec-proposal {proposal_name}",
        f" protocol esp encryption {prof.cisco_esp_encryption}",
        f" protocol esp integrity {prof.cisco_esp_integrity}",
        "",
        f"! ── Step 5: Crypto Map Definition [{CISCO_ASA_VERIFICATION_LABEL}] ──",
        f"crypto map {crypto_map_name} {crypto_map_seq} match address {acl_name}",
        f"crypto map {crypto_map_name} {crypto_map_seq} set peer {peer_ip}",
        f"crypto map {crypto_map_name} {crypto_map_seq} set ikev2 ipsec-proposal {proposal_name}",
        f"crypto map {crypto_map_name} {crypto_map_seq} "
        f"set security-association lifetime seconds {prof.esp_lifetime_seconds}",
        f"crypto map {crypto_map_name} interface {local_interface}",
        "",
        f"! ── Step 6: Tunnel Group & Authentication [{CISCO_ASA_VERIFICATION_LABEL}] ──",
        f"tunnel-group {tg_name} type ipsec-l2l",
        f"tunnel-group {tg_name} ipsec-attributes",
        f" ikev2 remote-authentication pre-shared-key {preshared_key}",
        f" ikev2 local-authentication pre-shared-key {preshared_key}",
        "",
        "! " + "=" * 76,
        f"! END OF CONFIGURATION [{CISCO_ASA_VERIFICATION_LABEL}]",
        "! " + "=" * 76,
        "",
    ]

    content = "\n".join(lines)

    diff = ""
    if old_config_content:
        diff = generate_unified_diff(old_config_content, content, filename="cisco-asa.cfg")

    return RemediationConfig(
        target_device="cisco_asa",
        profile_name=prof.id,
        content=content,
        verification_status=CISCO_ASA_VERIFICATION_LABEL,
        diff=diff,
        metadata={
            "verification_status": CISCO_ASA_VERIFICATION_LABEL,
            "peer_ip": peer_ip,
            "interface": local_interface,
            "profile_id": prof.id,
            "policy_id": str(policy_id),
            "proposal_name": proposal_name,
        },
    )
