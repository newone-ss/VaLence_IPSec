"""
Consent-Gated Target Allowlist — Safety-First Active Probing.

Enforces the double-barrier safety model (ADR-0003):
  1. Target IP/FQDN must exist in the allowlist.
  2. The target entry must have consent_verified == True.

If either gate fails, the prober MUST refuse to scan.
No exceptions, no overrides, no "force" flags.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network


class ConsentDeniedError(Exception):
    """Raised when a scan target fails the consent-gated allowlist check."""


@dataclass(frozen=True)
class AllowlistEntry:
    """A single allowed scan target with explicit consent flag."""

    target: str  # IP address, CIDR network, or FQDN
    consent_verified: bool = False
    owner: str = ""
    notes: str = ""


@dataclass
class TargetAllowlist:
    """
    Consent-gated allowlist for active scanning targets.

    All scan operations must pass through verify() before any packet is sent.
    """

    entries: list[AllowlistEntry] = field(default_factory=list)

    def add(
        self,
        target: str,
        consent_verified: bool = False,
        owner: str = "",
        notes: str = "",
    ) -> None:
        """Add a target to the allowlist."""
        self.entries.append(
            AllowlistEntry(
                target=target,
                consent_verified=consent_verified,
                owner=owner,
                notes=notes,
            )
        )

    def _find_entry(self, target_ip: str) -> AllowlistEntry | None:
        """Find the allowlist entry matching a target IP address."""
        try:
            addr = ip_address(target_ip)
        except ValueError:
            return None

        for entry in self.entries:
            try:
                # Check if entry is an exact IP match
                entry_addr = ip_address(entry.target)
                if addr == entry_addr:
                    return entry
            except ValueError:
                pass

            try:
                # Check if entry is a CIDR network containing the target
                network = ip_network(entry.target, strict=False)
                if addr in network:
                    return entry
            except ValueError:
                pass

            # Check FQDN match (exact string match)
            if entry.target == target_ip:
                return entry

        return None

    def verify(self, target_ip: str) -> AllowlistEntry:
        """
        Verify a target against the allowlist.  Both gates must pass:
          1. Target must be in the allowlist.
          2. Entry must have consent_verified == True.

        Returns the matching AllowlistEntry on success.
        Raises ConsentDeniedError on failure.
        """
        entry = self._find_entry(target_ip)

        if entry is None:
            raise ConsentDeniedError(
                f"Target {target_ip} is not in the scan allowlist. "
                "Active scanning is only permitted against explicitly authorized targets."
            )

        if not entry.consent_verified:
            raise ConsentDeniedError(
                f"Target {target_ip} is in the allowlist but consent_verified is False. "
                "Explicit consent must be granted before active scanning."
            )

        return entry

    def is_authorized(self, target_ip: str) -> bool:
        """Non-throwing check: returns True only if both gates pass."""
        try:
            self.verify(target_ip)
            return True
        except ConsentDeniedError:
            return False
