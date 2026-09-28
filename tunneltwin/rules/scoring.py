"""
TunnelTwin Scoring Engine.

Computes a security posture score for a gateway based on rule evaluation results.

Algorithm:
  - Start at 100 points.
  - Subtract severity-weighted penalties for each FAIL result, grouped by category.
  - Floor at 0.
  - Track assessed-coverage percentage: (PASS + FAIL) / total applicable rules.

Categories and their penalty multipliers:
  - protocol_version: 2.0x (using deprecated IKE versions is critical)
  - key_exchange:     1.5x (weak DH groups expose key exchange)
  - encryption:       1.5x (weak ciphers risk confidentiality)
  - integrity:        1.2x (weak integrity risks authentication)
  - exposure:         1.0x (operational exposure findings)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tunneltwin.core.models import AssessmentStatus
from tunneltwin.rules.engine import RuleResult

# Category severity multipliers
CATEGORY_MULTIPLIERS: dict[str, float] = {
    "protocol_version": 2.0,
    "key_exchange": 1.5,
    "encryption": 1.5,
    "integrity": 1.2,
    "exposure": 1.0,
}

DEFAULT_MULTIPLIER = 1.0


@dataclass
class CategoryScore:
    """Score breakdown for a single category."""

    category: str
    total_rules: int = 0
    passed: int = 0
    failed: int = 0
    cannot_assess: int = 0
    penalty_points: float = 0.0

    @property
    def assessed_count(self) -> int:
        return self.passed + self.failed

    @property
    def coverage_pct(self) -> float:
        if self.total_rules == 0:
            return 0.0
        return (self.assessed_count / self.total_rules) * 100.0


@dataclass
class GatewayScore:
    """Complete scoring result for a single gateway."""

    subject: str
    raw_score: float = 100.0
    final_score: int = 100
    total_rules: int = 0
    rules_passed: int = 0
    rules_failed: int = 0
    rules_cannot_assess: int = 0
    category_scores: dict[str, CategoryScore] = field(default_factory=dict)
    findings: list[RuleResult] = field(default_factory=list)

    @property
    def assessed_coverage_pct(self) -> float:
        """Percentage of rules that returned PASS or FAIL (not CANNOT_ASSESS)."""
        assessed = self.rules_passed + self.rules_failed
        if self.total_rules == 0:
            return 0.0
        return (assessed / self.total_rules) * 100.0

    def summary(self) -> str:
        """Human-readable scoring summary."""
        lines = [
            f"═══ Security Score: {self.subject} ═══",
            f"  Score           : {self.final_score}/100",
            f"  Coverage        : {self.assessed_coverage_pct:.1f}%",
            f"  Rules Passed    : {self.rules_passed}",
            f"  Rules Failed    : {self.rules_failed}",
            f"  Cannot Assess   : {self.rules_cannot_assess}",
            "",
            "  Category Breakdown:",
        ]

        for cat_name in sorted(self.category_scores.keys()):
            cat = self.category_scores[cat_name]
            lines.append(
                f"    {cat_name:<20s} : "
                f"P={cat.passed} F={cat.failed} N/A={cat.cannot_assess} "
                f"(-{cat.penalty_points:.1f}pts)"
            )

        if self.findings:
            lines.append("")
            lines.append("  Findings:")
            for finding in self.findings:
                lines.append(f"    [{finding.rule_id}] {finding.rule_name}")
                lines.append(f"      Citation: {finding.citation}")
                if finding.message:
                    lines.append(f"      Detail:   {finding.message}")

        return "\n".join(lines)


def compute_score(subject: str, results: list[RuleResult]) -> GatewayScore:
    """
    Compute a gateway security posture score from rule evaluation results.

    Algorithm:
      1. Start at 100.
      2. For each FAIL: penalty = severity × category_multiplier.
      3. Subtract all penalties, floor at 0.
      4. Track per-category stats and overall assessed coverage.
    """
    score = GatewayScore(subject=subject)
    score.total_rules = len(results)

    total_penalty = 0.0

    for result in results:
        category = result.category

        # Ensure category entry exists
        if category not in score.category_scores:
            score.category_scores[category] = CategoryScore(category=category)
        cat_score = score.category_scores[category]
        cat_score.total_rules += 1

        if result.status == AssessmentStatus.PASS:
            score.rules_passed += 1
            cat_score.passed += 1

        elif result.status == AssessmentStatus.FAIL:
            score.rules_failed += 1
            cat_score.failed += 1
            score.findings.append(result)

            # Calculate penalty
            multiplier = CATEGORY_MULTIPLIERS.get(category, DEFAULT_MULTIPLIER)
            penalty = result.severity * multiplier
            total_penalty += penalty
            cat_score.penalty_points += penalty

        elif result.status == AssessmentStatus.CANNOT_ASSESS:
            score.rules_cannot_assess += 1
            cat_score.cannot_assess += 1

    score.raw_score = max(0.0, 100.0 - total_penalty)
    score.final_score = max(0, int(score.raw_score))

    return score


class ScoringEngine:
    """Engine for computing gateway security posture scores."""

    @staticmethod
    def score(subject: str, results: list[RuleResult]) -> GatewayScore:
        """Compute gateway score from rule evaluation results."""
        return compute_score(subject, results)
