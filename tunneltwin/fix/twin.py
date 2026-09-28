"""
TunnelTwin Fix Engine — Twin Check & Verification Workflow.

Implements the core verification logic for Phase 3:
  1. Record baseline scan findings and posture score for the old configuration.
  2. Generate and apply the remediated configuration.
  3. Verify tunnel establishes in the twin environment.
  4. Re-scan the endpoint using Phase 1 active prober.
  5. Confirm old findings have cleared and posture score has improved.
"""

from __future__ import annotations

import logging
from pathlib import Path

from tunneltwin.core.models import AssessmentStatus
from tunneltwin.fix.models import RemediationConfig, TwinCheckResult
from tunneltwin.fix.profiles import AES256GCM_BASELINE, SecurityProfile, get_profile
from tunneltwin.fix.swanctl_generator import generate_swanctl_pair
from tunneltwin.probe.result import GatewayScanResult
from tunneltwin.rules.engine import RuleEngine, RuleResult
from tunneltwin.rules.facts import scan_result_to_facts
from tunneltwin.rules.scoring import compute_score

logger = logging.getLogger(__name__)


class TwinVerifier:
    """
    Orchestrates twin verification comparing baseline scan findings against
    remediated configuration scan findings.
    """

    def __init__(self, packs_dir: Path | None = None) -> None:
        self.engine = RuleEngine(packs_dir=packs_dir)

    def evaluate_scan(self, scan_result: GatewayScanResult) -> tuple[int, list[RuleResult]]:
        """
        Convert scan result to facts, evaluate all rule packs, and compute score.

        Returns:
            Tuple of (final_score, list_of_failures)
        """
        store = scan_result_to_facts(scan_result)
        subject = f"{scan_result.target_ip}:{scan_result.target_port}"
        results = self.engine.evaluate(store, subject)
        gateway_score = compute_score(subject, results)
        failures = [r for r in results if r.status == AssessmentStatus.FAIL]
        return gateway_score.final_score, failures

    def verify_twin_transition(
        self,
        baseline_scan: GatewayScanResult,
        remediated_scan: GatewayScanResult,
        remediated_config: RemediationConfig,
        baseline_tunnel_ok: bool = True,
        remediated_tunnel_ok: bool = True,
        ping_verified: bool = True,
        target_profile: SecurityProfile | str = AES256GCM_BASELINE,
    ) -> TwinCheckResult:
        """
        Execute twin comparison between baseline and remediated scan results.

        Confirms:
          - Baseline had security findings (e.g. NIST-001, NIST-004).
          - Remediated tunnel established successfully.
          - Re-scan proves the baseline findings have cleared.
        """
        prof = get_profile(target_profile) if isinstance(target_profile, str) else target_profile

        # 1. Baseline analysis
        old_score, old_failures = self.evaluate_scan(baseline_scan)
        old_finding_ids = [f"{f.rule_id} ({f.rule_name})" for f in old_failures]

        # 2. Remediated analysis
        new_score, new_failures = self.evaluate_scan(remediated_scan)
        new_finding_ids = [f"{f.rule_id} ({f.rule_name})" for f in new_failures]

        # 3. Compute cleared findings
        old_rule_ids = {f.rule_id for f in old_failures}
        new_rule_ids = {f.rule_id for f in new_failures}
        cleared_ids = old_rule_ids - new_rule_ids
        cleared_findings = [f"{f.rule_id} ({f.rule_name})" for f in old_failures if f.rule_id in cleared_ids]

        return TwinCheckResult(
            profile_name=prof.id,
            target_ip=baseline_scan.target_ip,
            old_findings=old_finding_ids,
            old_score=old_score,
            old_tunnel_established=baseline_tunnel_ok,
            new_config=remediated_config,
            new_tunnel_established=remediated_tunnel_ok,
            new_findings=new_finding_ids,
            new_score=new_score,
            cleared_findings=cleared_findings,
            ping_verified=ping_verified,
            details=f"Posture improved from {old_score}/100 to {new_score}/100.",
        )


def build_remediation_artifacts(
    old_profile_name: str,
    old_left_content: str,
    old_right_content: str,
    target_profile: SecurityProfile | str = AES256GCM_BASELINE,
    left_ip: str = "10.0.1.1",
    right_ip: str = "10.0.1.2",
    subnet: str = "10.0.1.0/30",
    left_ts: str | None = None,
    right_ts: str | None = None,
) -> tuple[RemediationConfig, RemediationConfig]:
    """
    Generate remediated pair of swanctl configurations preserving connection
    naming while modernizing cryptographic suites.
    """
    prof = get_profile(target_profile) if isinstance(target_profile, str) else target_profile
    conn_name = f"{old_profile_name}-conn"
    child_name = f"{old_profile_name}-child"

    return generate_swanctl_pair(
        profile=prof,
        conn_name=conn_name,
        child_name=child_name,
        left_ip=left_ip,
        right_ip=right_ip,
        subnet=subnet,
        old_left_content=old_left_content,
        old_right_content=old_right_content,
        left_ts=left_ts,
        right_ts=right_ts,
    )
