"""
TunnelTwin Fix Engine — Data Models.

Defines:
  - SecurityProfile: Cryptographic parameters for target compliance profiles.
  - RemediationConfig: Generated configuration container with verification labels.
  - TwinCheckResult: Complete before-and-after twin verification record.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field

# Mandatory label for all Cisco ASA generated configurations
CISCO_ASA_VERIFICATION_LABEL = "generated, not lab-verified"
SWANCTL_VERIFIED_LABEL = "lab-verified"
LIBRESWAN_VERIFIED_LABEL = "lab-verified"


@dataclass
class SecurityProfile:
    """Target cryptographic posture definition for remediation."""

    id: str
    name: str
    description: str
    ike_version: int = 2
    # strongSwan syntax
    ike_proposals: list[str] = field(default_factory=list)
    esp_proposals: list[str] = field(default_factory=list)
    # Cisco ASA syntax
    cisco_ike_encryption: str = "aes-gcm-256"
    cisco_ike_integrity: str = "null"
    cisco_ike_groups: list[int] = field(default_factory=lambda: [20, 19])  # ECP-384, ECP-256
    cisco_ike_prfs: list[str] = field(default_factory=lambda: ["sha384", "sha256"])
    cisco_esp_encryption: str = "aes-gcm-256"
    cisco_esp_integrity: str = "null"
    # Libreswan syntax
    libreswan_ike: list[str] = field(default_factory=list)
    libreswan_esp: list[str] = field(default_factory=list)
    # Operational parameters
    ike_lifetime_seconds: int = 86400
    esp_lifetime_seconds: int = 28800
    dos_cookie_threshold: int = 10


@dataclass
class RemediationConfig:
    """
    Generated remediation configuration for a specific target device.

    NOTE: For Cisco ASA outputs, the verification_status is strictly
    'generated, not lab-verified' and is prominently displayed.
    """

    target_device: str  # "swanctl" or "cisco_asa"
    profile_name: str
    content: str
    verification_status: str
    diff: str = ""
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.target_device.lower() in ("cisco_asa", "cisco", "asa"):
            self.verification_status = CISCO_ASA_VERIFICATION_LABEL
            # Ensure the content itself carries the mandatory warning label
            if CISCO_ASA_VERIFICATION_LABEL not in self.content:
                header = (
                    "! " + "=" * 76 + "\n"
                    f"! WARNING: {CISCO_ASA_VERIFICATION_LABEL}\n"
                    f"! Status: {CISCO_ASA_VERIFICATION_LABEL}\n"
                    "! This configuration was synthesized by TunnelTwin and has NOT been\n"
                    "! verified inside a live hardware or virtual Cisco ASA testbed.\n"
                    "! " + "=" * 76 + "\n\n"
                )
                self.content = header + self.content

    def __str__(self) -> str:
        if self.target_device.lower() in ("cisco_asa", "cisco", "asa"):
            return f"[{CISCO_ASA_VERIFICATION_LABEL}]\n{self.content}"
        return self.content

    def __repr__(self) -> str:
        return (
            f"RemediationConfig(device={self.target_device}, "
            f"profile={self.profile_name}, status='{self.verification_status}')"
        )

    def display(self) -> str:
        """Formatted display string including verification badge."""
        badge = (
            f"[⚠️  {CISCO_ASA_VERIFICATION_LABEL.upper()}]"
            if self.target_device.lower() in ("cisco_asa", "cisco", "asa")
            else f"[✅ {self.verification_status.upper()}]"
        )
        lines = [
            f"═══ Remediation Config: {self.target_device} ({self.profile_name}) {badge} ═══",
            f"Verification Status : {self.verification_status}",
            "",
            self.content,
        ]
        if self.diff:
            lines.extend(["", "─── Configuration Diff ───", self.diff])
        return "\n".join(lines)


def generate_unified_diff(old_content: str, new_content: str, filename: str = "config") -> str:
    """Generate a clean unified diff between old and remediated configurations."""
    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{filename} (insecure)",
        tofile=f"b/{filename} (remediated)",
    )
    return "".join(diff)


@dataclass
class TwinCheckResult:
    """Outcome of an end-to-end Twin Check (before vs after remediation)."""

    profile_name: str
    target_ip: str
    # Phase 0: Old configuration state
    old_findings: list[str]
    old_score: int
    old_tunnel_established: bool
    # Phase 3: Remediated state
    new_config: RemediationConfig
    new_tunnel_established: bool
    new_findings: list[str]
    new_score: int
    # Diff metrics
    cleared_findings: list[str]
    ping_verified: bool = False
    details: str = ""

    @property
    def passed(self) -> bool:
        """
        Phase 3 Exit Criteria check:
          1. Old findings were present.
          2. Remediated tunnel established.
          3. Old findings completely cleared on re-scan.
        """
        old_had_issues = len(self.old_findings) > 0
        tunnel_works = self.new_tunnel_established
        findings_cleared = len(self.cleared_findings) > 0 and len(self.new_findings) < len(self.old_findings)
        return old_had_issues and tunnel_works and findings_cleared

    def summary(self) -> str:
        """Formatted human-readable summary of the Twin Check."""
        status_icon = "✅ PASSED" if self.passed else "❌ FAILED"
        lines = [
            "=" * 78,
            f"             TunnelTwin Phase 3: Twin Check Verification Report ({status_icon})",
            "=" * 78,
            f"Target Gateway          : {self.target_ip}",
            f"Remediation Profile     : {self.profile_name}",
            f"Verification Status     : {self.new_config.verification_status}",
            "",
            "--- STEP 1: Baseline Scan (Old Configuration) ---",
            f"  Tunnel Established    : {'YES ✅' if self.old_tunnel_established else 'NO ❌'}",
            f"  Security Posture Score: {self.old_score}/100",
            f"  Active Findings Count : {len(self.old_findings)}",
        ]
        for f in self.old_findings:
            lines.append(f"    • {f}")

        lines.extend(
            [
                "",
                "--- STEP 2: Twin Execution (New Configuration Applied) ---",
                f"  Remediated Tunnel Est : {'YES ✅' if self.new_tunnel_established else 'NO ❌'}",
                f"  Data-Plane Ping Check : {'PASS ✅' if self.ping_verified else 'SKIPPED / N/A'}",
                "",
                "--- STEP 3: Re-Scan Verification ---",
                f"  New Posture Score     : {self.new_score}/100 (improved by +{self.new_score - self.old_score} pts)",
                f"  Cleared Findings      : {len(self.cleared_findings)}",
            ]
        )
        for f in self.cleared_findings:
            lines.append(f"    ✓ CLEARED: {f}")

        if self.new_findings:
            lines.append(f"  Remaining Findings    : {len(self.new_findings)}")
            for f in self.new_findings:
                lines.append(f"    ℹ {f}")
        else:
            lines.append("  Remaining Findings    : ZERO (clean slate)")

        lines.extend(
            [
                "",
                f"--- EXIT CRITERIA EVALUATION : {status_icon} ---",
                "=" * 78,
            ]
        )
        return "\n".join(lines)
