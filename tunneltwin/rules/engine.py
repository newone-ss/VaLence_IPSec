"""
TunnelTwin Rule Engine — YAML Rule Pack Loader & Evaluator.

Rules are loaded from YAML packs that cite specific standards
(NIST SP 800-77 Rev 1, NSA CNSA Suite, CERT-In).

Each rule declares:
  - required_facts: list of fact keys that must be present
  - condition: a declarative check (operator + operands)
  - severity: 1-10 penalty weight
  - category: scoring category (key_exchange, encryption, etc.)
  - citation: exact document clause
  - remediation_template_id: links to fix guidance

If any required fact is UNKNOWN or missing, the rule emits CANNOT_ASSESS.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml  # type: ignore[import-untyped]

from tunneltwin.core.models import AssessmentStatus
from tunneltwin.rules.facts import Fact, FactStore

logger = logging.getLogger(__name__)

# Directory containing YAML rule packs
PACKS_DIR = Path(__file__).parent / "packs"

# ═══════════════════════════════════════════════════════════════════════
#  Rule Data Model
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class Rule:
    """A single compliance/security rule loaded from a YAML pack."""

    id: str
    name: str
    pack: str
    category: str
    description: str
    required_facts: list[str]
    condition_type: str  # "not_in", "in", "equals", "not_equals", "version_min"
    condition_field: str  # fact key to evaluate
    condition_values: list[str]  # operand values
    severity: int  # 1-10
    citation: str
    remediation_template_id: str = ""


@dataclass
class RuleResult:
    """Outcome of evaluating a single rule against a gateway."""

    rule_id: str
    rule_name: str
    pack: str
    category: str
    status: AssessmentStatus
    severity: int
    citation: str
    matched_facts: list[Fact] = field(default_factory=list)
    message: str = ""
    remediation_template_id: str = ""


# ═══════════════════════════════════════════════════════════════════════
#  Rule Loading
# ═══════════════════════════════════════════════════════════════════════


def load_rules_from_yaml(yaml_path: Path) -> list[Rule]:
    """Load rules from a single YAML rule pack file."""
    with open(yaml_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data or "rules" not in data:
        logger.warning("No rules found in %s", yaml_path)
        return []

    pack_name = data.get("pack_name", yaml_path.stem)
    rules: list[Rule] = []

    for rule_data in data["rules"]:
        rule = Rule(
            id=rule_data["id"],
            name=rule_data["name"],
            pack=pack_name,
            category=rule_data["category"],
            description=rule_data.get("description", ""),
            required_facts=rule_data["required_facts"],
            condition_type=rule_data["condition"]["type"],
            condition_field=rule_data["condition"]["field"],
            condition_values=rule_data["condition"]["values"],
            severity=rule_data["severity"],
            citation=rule_data["citation"],
            remediation_template_id=rule_data.get("remediation_template_id", ""),
        )
        rules.append(rule)

    return rules


def load_all_rule_packs(packs_dir: Path | None = None) -> list[Rule]:
    """Load all YAML rule packs from the packs directory."""
    directory = packs_dir or PACKS_DIR
    if not directory.exists():
        logger.warning("Rule packs directory does not exist: %s", directory)
        return []

    all_rules: list[Rule] = []
    for yaml_file in sorted(directory.glob("*.yaml")):
        pack_rules = load_rules_from_yaml(yaml_file)
        all_rules.extend(pack_rules)
        logger.info("Loaded %d rules from %s", len(pack_rules), yaml_file.name)

    return all_rules


# ═══════════════════════════════════════════════════════════════════════
#  Condition Evaluation
# ═══════════════════════════════════════════════════════════════════════


def _evaluate_condition(
    condition_type: str,
    fact_values: list[str],
    condition_values: list[str],
) -> bool:
    """
    Evaluate a condition against fact values.

    Returns True if the gateway PASSES the rule (is compliant).
    Returns False if the gateway FAILS the rule (has a finding).
    """
    if condition_type == "not_in":
        # PASS if none of the fact values appear in the forbidden set
        forbidden = {v.upper() for v in condition_values}
        return not any(fv.upper() in forbidden for fv in fact_values)

    elif condition_type == "in":
        # PASS if all fact values are in the allowed set
        allowed = {v.upper() for v in condition_values}
        return all(fv.upper() in allowed for fv in fact_values)

    elif condition_type == "equals":
        # PASS if the fact value equals one of the expected values
        expected = {v.upper() for v in condition_values}
        return any(fv.upper() in expected for fv in fact_values)

    elif condition_type == "not_equals":
        # PASS if the fact value does NOT equal any of the forbidden values
        forbidden = {v.upper() for v in condition_values}
        return not any(fv.upper() in forbidden for fv in fact_values)

    elif condition_type == "min_key_bits":
        # PASS if the numeric value extracted from fact is >= threshold
        threshold = int(condition_values[0])
        for fv in fact_values:
            # Extract trailing digits (e.g. "AES-CBC-128" → 128)
            digits = "".join(c for c in fv.split("-")[-1] if c.isdigit())
            if digits and int(digits) < threshold:
                return False
        return True

    else:
        logger.warning("Unknown condition type: %s", condition_type)
        return True  # default to pass for unknown conditions


# ═══════════════════════════════════════════════════════════════════════
#  Rule Evaluation Engine
# ═══════════════════════════════════════════════════════════════════════


def evaluate_rule(rule: Rule, store: FactStore, subject: str) -> RuleResult:
    """
    Evaluate a single rule against a subject's facts.

    Missing or UNKNOWN required facts → CANNOT_ASSESS (never a false PASS).
    """
    # Check all required facts are present and known
    missing_facts: list[str] = []
    for req_key in rule.required_facts:
        if not store.has_fact(subject, req_key):
            missing_facts.append(req_key)

    if missing_facts:
        return RuleResult(
            rule_id=rule.id,
            rule_name=rule.name,
            pack=rule.pack,
            category=rule.category,
            status=AssessmentStatus.CANNOT_ASSESS,
            severity=rule.severity,
            citation=rule.citation,
            message=f"Missing required facts: {', '.join(missing_facts)}",
            remediation_template_id=rule.remediation_template_id,
        )

    # Gather fact values for the condition field
    fact_values = store.get_values(subject, rule.condition_field)
    matched_facts = [f for f in store.get(subject, rule.condition_field) if f.is_known]

    if not fact_values:
        # Condition field has no known values
        return RuleResult(
            rule_id=rule.id,
            rule_name=rule.name,
            pack=rule.pack,
            category=rule.category,
            status=AssessmentStatus.CANNOT_ASSESS,
            severity=rule.severity,
            citation=rule.citation,
            message=f"No known values for condition field: {rule.condition_field}",
            remediation_template_id=rule.remediation_template_id,
        )

    # Evaluate the condition
    passed = _evaluate_condition(rule.condition_type, fact_values, rule.condition_values)

    return RuleResult(
        rule_id=rule.id,
        rule_name=rule.name,
        pack=rule.pack,
        category=rule.category,
        status=AssessmentStatus.PASS if passed else AssessmentStatus.FAIL,
        severity=rule.severity,
        citation=rule.citation,
        matched_facts=matched_facts,
        message=rule.description if not passed else "",
        remediation_template_id=rule.remediation_template_id,
    )


def evaluate_all_rules(
    rules: list[Rule],
    store: FactStore,
    subject: str,
) -> list[RuleResult]:
    """Evaluate all rules against a single subject and return results."""
    return [evaluate_rule(rule, store, subject) for rule in rules]


class RuleEngine:
    """
    Top-level engine that loads rule packs and evaluates them against fact stores.
    """

    def __init__(self, packs_dir: Path | None = None) -> None:
        self.rules = load_all_rule_packs(packs_dir)

    def evaluate(self, store: FactStore, subject: str) -> list[RuleResult]:
        """Evaluate all loaded rules against a subject."""
        return evaluate_all_rules(self.rules, store, subject)

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    @property
    def pack_names(self) -> list[str]:
        return sorted({r.pack for r in self.rules})
