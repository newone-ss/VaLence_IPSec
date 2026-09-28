"""
Phase 2 — Rule Engine & Evidence Model Tests.

Verifies:
  1. Fact model creation and indexing.
  2. GatewayScanResult → FactStore bridge.
  3. YAML rule pack loading and validation.
  4. Rule evaluation against 4 Phase-0 profiles produces distinct, correct scores.
  5. At least one finding per profile with exact rule/clause cited.
  6. CANNOT_ASSESS on missing facts.
  7. Score floor at 0.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tunneltwin.core.models import AssessmentStatus, ProvenanceTag
from tunneltwin.ike.constants import (
    EncryptionAlgorithm,
    IntegrityAlgorithmID,
    PRFAlgorithm,
    TransformType,
)
from tunneltwin.probe.result import (
    AcceptedTransform,
    GatewayScanResult,
    IKEv1AcceptedTransform,
    ScanStatus,
)
from tunneltwin.rules.engine import (
    Rule,
    RuleEngine,
    evaluate_rule,
    load_all_rule_packs,
)
from tunneltwin.rules.facts import (
    Fact,
    FactStore,
    scan_result_to_facts,
)
from tunneltwin.rules.scoring import compute_score

# ═══════════════════════════════════════════════════════════════════════
#  Fixtures: Simulated Phase-0 Gateway Scan Results
# ═══════════════════════════════════════════════════════════════════════

PACKS_DIR = Path(__file__).parent.parent / "tunneltwin" / "rules" / "packs"


def _make_weak_result() -> GatewayScanResult:
    """weak: IKEv1, 3DES-CBC, SHA1, MODP-1024."""
    result = GatewayScanResult(
        target_ip="10.0.1.2",
        target_port=500,
        scan_status=ScanStatus.SUCCESS,
    )
    result.mark_observed_ike_version("IKEv1")
    result.mark_cookie_required(False)
    result.ikev1_accepted.append(
        IKEv1AcceptedTransform(
            encryption=5,  # THREE_DES_CBC
            hash_alg=2,  # SHA1
            auth_method=1,  # PSK
            dh_group=2,  # MODP_1024
        )
    )
    result.scan_start_time = 1000.0
    result.scan_end_time = 1000.35
    result.probe_count = 12
    return result


def _make_mixed_result() -> GatewayScanResult:
    """mixed: IKEv2, AES-CBC-256, SHA2-256, MODP-1024."""
    result = GatewayScanResult(
        target_ip="10.0.1.2",
        target_port=500,
        scan_status=ScanStatus.SUCCESS,
    )
    result.mark_observed_ike_version("IKEv2")
    result.mark_cookie_required(False)
    result.add_accepted_dh_group("MODP-1024")
    result.accepted_transforms.extend(
        [
            AcceptedTransform(
                transform_type=TransformType.ENCR,
                transform_id=EncryptionAlgorithm.ENCR_AES_CBC,
                key_length=256,
            ),
            AcceptedTransform(
                transform_type=TransformType.INTEG,
                transform_id=IntegrityAlgorithmID.AUTH_HMAC_SHA2_256_128,
            ),
            AcceptedTransform(
                transform_type=TransformType.PRF,
                transform_id=PRFAlgorithm.PRF_HMAC_SHA2_256,
            ),
        ]
    )
    result.scan_start_time = 1000.0
    result.scan_end_time = 1000.29
    result.probe_count = 8
    return result


def _make_strong_result() -> GatewayScanResult:
    """strong: IKEv2, AES-GCM-16-256, SHA2-384, ECP-384."""
    result = GatewayScanResult(
        target_ip="10.0.1.2",
        target_port=500,
        scan_status=ScanStatus.SUCCESS,
    )
    result.mark_observed_ike_version("IKEv2")
    result.mark_cookie_required(False)
    result.add_accepted_dh_group("ECP-384")
    result.accepted_transforms.extend(
        [
            AcceptedTransform(
                transform_type=TransformType.ENCR,
                transform_id=EncryptionAlgorithm.ENCR_AES_GCM_16,
                key_length=256,
            ),
            AcceptedTransform(
                transform_type=TransformType.PRF,
                transform_id=PRFAlgorithm.PRF_HMAC_SHA2_384,
            ),
        ]
    )
    result.scan_start_time = 1000.0
    result.scan_end_time = 1000.33
    result.probe_count = 6
    return result


def _make_legacy_cbc_result() -> GatewayScanResult:
    """legacy-cbc: IKEv2, AES-CBC-128, SHA1, MODP-2048."""
    result = GatewayScanResult(
        target_ip="10.0.1.2",
        target_port=500,
        scan_status=ScanStatus.SUCCESS,
    )
    result.mark_observed_ike_version("IKEv2")
    result.mark_cookie_required(False)
    result.add_accepted_dh_group("MODP-2048")
    result.accepted_transforms.extend(
        [
            AcceptedTransform(
                transform_type=TransformType.ENCR,
                transform_id=EncryptionAlgorithm.ENCR_AES_CBC,
                key_length=128,
            ),
            AcceptedTransform(
                transform_type=TransformType.INTEG,
                transform_id=IntegrityAlgorithmID.AUTH_HMAC_SHA1_96,
            ),
            AcceptedTransform(
                transform_type=TransformType.PRF,
                transform_id=PRFAlgorithm.PRF_HMAC_SHA1,
            ),
        ]
    )
    result.scan_start_time = 1000.0
    result.scan_end_time = 1000.30
    result.probe_count = 7
    return result


# ═══════════════════════════════════════════════════════════════════════
#  Test Group 1: Fact Model
# ═══════════════════════════════════════════════════════════════════════


class TestFactModel:
    """Tests for the Fact dataclass and FactStore."""

    def test_fact_creation(self) -> None:
        fact = Fact(
            subject="10.0.1.2:500",
            key="ike_version",
            value="IKEv2",
            provenance=ProvenanceTag.OBSERVED,
            confidence=1.0,
            source_pointer="probe:10.0.1.2:500",
        )
        assert fact.subject == "10.0.1.2:500"
        assert fact.key == "ike_version"
        assert fact.value == "IKEv2"
        assert fact.provenance == ProvenanceTag.OBSERVED
        assert fact.is_known is True

    def test_unknown_fact_not_known(self) -> None:
        fact = Fact(
            subject="10.0.1.2:500",
            key="cipher",
            value="",
            provenance=ProvenanceTag.UNKNOWN,
        )
        assert fact.is_known is False

    def test_inferred_fact_validates_confidence(self) -> None:
        with pytest.raises(ValueError, match="INFERRED fact confidence"):
            Fact(
                subject="10.0.1.2:500",
                key="cipher",
                value="AES-256",
                provenance=ProvenanceTag.INFERRED,
                confidence=1.5,
            )

    def test_fact_store_add_and_get(self) -> None:
        store = FactStore()
        fact = Fact(
            subject="gw1",
            key="ike_version",
            value="IKEv2",
            provenance=ProvenanceTag.OBSERVED,
        )
        store.add(fact)
        assert store.has_fact("gw1", "ike_version")
        assert store.get_value("gw1", "ike_version") == "IKEv2"

    def test_fact_store_multiple_values(self) -> None:
        store = FactStore()
        store.add(Fact(subject="gw1", key="accepted_dh_group", value="MODP-1024", provenance=ProvenanceTag.OBSERVED))
        store.add(Fact(subject="gw1", key="accepted_dh_group", value="MODP-2048", provenance=ProvenanceTag.OBSERVED))
        values = store.get_values("gw1", "accepted_dh_group")
        assert len(values) == 2
        assert "MODP-1024" in values
        assert "MODP-2048" in values

    def test_fact_store_missing_returns_none(self) -> None:
        store = FactStore()
        assert store.get_value("gw1", "nonexistent") is None
        assert store.has_fact("gw1", "nonexistent") is False

    def test_fact_store_subjects(self) -> None:
        store = FactStore()
        store.add(Fact(subject="gw1", key="ike_version", value="IKEv2", provenance=ProvenanceTag.OBSERVED))
        store.add(Fact(subject="gw2", key="ike_version", value="IKEv1", provenance=ProvenanceTag.OBSERVED))
        assert store.subjects == {"gw1", "gw2"}


# ═══════════════════════════════════════════════════════════════════════
#  Test Group 2: Scan Result → FactStore Bridge
# ═══════════════════════════════════════════════════════════════════════


class TestBridge:
    """Tests for GatewayScanResult → FactStore conversion."""

    def test_weak_profile_bridge(self) -> None:
        result = _make_weak_result()
        store = scan_result_to_facts(result)
        subject = "10.0.1.2:500"

        assert store.get_value(subject, "ike_version") == "IKEv1"
        assert store.has_fact(subject, "cipher")
        assert store.has_fact(subject, "integrity")
        assert store.has_fact(subject, "accepted_dh_group")
        # IKEv1 carries cipher/integrity/dh from ikev1_accepted
        assert "3DES-CBC" in store.get_values(subject, "cipher")
        assert "SHA1" in store.get_values(subject, "integrity")
        assert "MODP-1024" in store.get_values(subject, "accepted_dh_group")

    def test_strong_profile_bridge(self) -> None:
        result = _make_strong_result()
        store = scan_result_to_facts(result)
        subject = "10.0.1.2:500"

        assert store.get_value(subject, "ike_version") == "IKEv2"
        assert "ECP-384" in store.get_values(subject, "accepted_dh_group")
        assert "AES-GCM-16-256" in store.get_values(subject, "cipher")

    def test_failed_scan_produces_empty_store(self) -> None:
        result = GatewayScanResult(
            target_ip="10.0.1.2",
            target_port=500,
            scan_status=ScanStatus.TIMEOUT,
        )
        store = scan_result_to_facts(result)
        assert store.fact_count() == 0


# ═══════════════════════════════════════════════════════════════════════
#  Test Group 3: YAML Rule Pack Loading
# ═══════════════════════════════════════════════════════════════════════


class TestRulePacks:
    """Tests for YAML rule pack loading and validation."""

    def test_all_packs_load(self) -> None:
        rules = load_all_rule_packs(PACKS_DIR)
        assert len(rules) > 0, "No rules loaded from packs directory"

    def test_nist_pack_has_rules(self) -> None:
        rules = load_all_rule_packs(PACKS_DIR)
        nist_rules = [r for r in rules if "NIST" in r.id]
        assert len(nist_rules) >= 7, f"Expected >= 7 NIST rules, got {len(nist_rules)}"

    def test_cnsa_pack_has_rules(self) -> None:
        rules = load_all_rule_packs(PACKS_DIR)
        cnsa_rules = [r for r in rules if "CNSA" in r.id]
        assert len(cnsa_rules) >= 4, f"Expected >= 4 CNSA rules, got {len(cnsa_rules)}"

    def test_certin_pack_has_pending_citation(self) -> None:
        rules = load_all_rule_packs(PACKS_DIR)
        certin_rules = [r for r in rules if "CERTIN" in r.id]
        assert len(certin_rules) >= 4, f"Expected >= 4 CERT-In rules, got {len(certin_rules)}"
        for rule in certin_rules:
            assert "pending" in rule.citation.lower(), (
                f"CERT-In rule {rule.id} should have 'pending' in citation, got: {rule.citation}"
            )

    def test_every_rule_has_required_fields(self) -> None:
        rules = load_all_rule_packs(PACKS_DIR)
        for rule in rules:
            assert rule.id, f"Rule missing ID: {rule}"
            assert rule.name, f"Rule {rule.id} missing name"
            assert rule.category, f"Rule {rule.id} missing category"
            assert rule.required_facts, f"Rule {rule.id} has no required_facts"
            assert rule.condition_type, f"Rule {rule.id} missing condition type"
            assert rule.condition_field, f"Rule {rule.id} missing condition field"
            assert rule.condition_values, f"Rule {rule.id} has no condition values"
            assert 1 <= rule.severity <= 10, f"Rule {rule.id} severity {rule.severity} out of range"
            assert rule.citation, f"Rule {rule.id} missing citation"


# ═══════════════════════════════════════════════════════════════════════
#  Test Group 4: Rule Evaluation — Profile-Specific Assertions
# ═══════════════════════════════════════════════════════════════════════


class TestRuleEvaluation:
    """Tests for rule evaluation against the 4 Phase-0 profiles."""

    @pytest.fixture(autouse=True)
    def _load_engine(self) -> None:
        self.engine = RuleEngine(packs_dir=PACKS_DIR)
        assert self.engine.rule_count > 0

    def test_weak_profile_has_findings(self) -> None:
        """weak: IKEv1, 3DES, SHA1, MODP-1024 → many findings."""
        store = scan_result_to_facts(_make_weak_result())
        subject = "10.0.1.2:500"
        results = self.engine.evaluate(store, subject)

        failures = [r for r in results if r.status == AssessmentStatus.FAIL]
        assert len(failures) >= 1, "weak profile must have at least 1 finding"

        # Specifically: IKEv1 deprecated (NIST-001 or CNSA-001)
        ikev1_findings = [r for r in failures if "IKEv1" in r.rule_name or "IKEv2 Required" in r.rule_name]
        assert len(ikev1_findings) >= 1, "weak profile must flag IKEv1"

        # Specifically: 3DES prohibited (NIST-004)
        encr_findings = [r for r in failures if r.category == "encryption"]
        assert len(encr_findings) >= 1, "weak profile must flag 3DES"

        # Verify citation is present
        for finding in failures:
            assert finding.citation, f"Finding {finding.rule_id} missing citation"

    def test_mixed_profile_has_dh_finding(self) -> None:
        """mixed: IKEv2, AES-CBC-256, SHA2-256, MODP-1024 → DH group finding."""
        store = scan_result_to_facts(_make_mixed_result())
        subject = "10.0.1.2:500"
        results = self.engine.evaluate(store, subject)

        failures = [r for r in results if r.status == AssessmentStatus.FAIL]
        assert len(failures) >= 1, "mixed profile must have at least 1 finding"

        # MODP-1024 should trigger DH group findings
        dh_findings = [r for r in failures if r.category == "key_exchange"]
        assert len(dh_findings) >= 1, "mixed profile must flag MODP-1024"

    def test_strong_profile_minimal_findings(self) -> None:
        """strong: IKEv2, AES-GCM-256, ECP-384 → passes core crypto, flags DoS cookie exposure."""
        store = scan_result_to_facts(_make_strong_result())
        subject = "10.0.1.2:500"
        results = self.engine.evaluate(store, subject)

        failures = [r for r in results if r.status == AssessmentStatus.FAIL]
        assert len(failures) >= 1, "strong profile must have at least 1 finding (exit criteria)"
        for finding in failures:
            assert finding.citation, f"finding {finding.rule_id} must have a citation"

        passes = [r for r in results if r.status == AssessmentStatus.PASS]
        assert len(passes) >= 3, "strong profile must pass core cryptographic rules"

    def test_legacy_cbc_has_integrity_finding(self) -> None:
        """legacy-cbc: IKEv2, AES-CBC-128, SHA1, MODP-2048 → SHA1 finding."""
        store = scan_result_to_facts(_make_legacy_cbc_result())
        subject = "10.0.1.2:500"
        results = self.engine.evaluate(store, subject)

        failures = [r for r in results if r.status == AssessmentStatus.FAIL]
        assert len(failures) >= 1, "legacy-cbc profile must have at least 1 finding"

        # SHA1 should trigger integrity findings
        integ_findings = [r for r in failures if r.category == "integrity"]
        assert len(integ_findings) >= 1, "legacy-cbc profile must flag SHA1"


# ═══════════════════════════════════════════════════════════════════════
#  Test Group 5: Scoring Engine
# ═══════════════════════════════════════════════════════════════════════


class TestScoring:
    """Tests for the security posture scoring engine."""

    @pytest.fixture(autouse=True)
    def _load_engine(self) -> None:
        self.engine = RuleEngine(packs_dir=PACKS_DIR)

    def test_distinct_scores_per_profile(self) -> None:
        """All 4 profiles must produce distinct, correct scores."""
        profiles = {
            "weak": _make_weak_result(),
            "mixed": _make_mixed_result(),
            "strong": _make_strong_result(),
            "legacy-cbc": _make_legacy_cbc_result(),
        }

        scores: dict[str, int] = {}
        for name, scan_result in profiles.items():
            store = scan_result_to_facts(scan_result)
            subject = "10.0.1.2:500"
            results = self.engine.evaluate(store, subject)
            gateway_score = compute_score(subject, results)
            scores[name] = gateway_score.final_score

        # Verify ordering: strong > legacy-cbc/mixed > weak
        assert scores["strong"] > scores["weak"], (
            f"strong ({scores['strong']}) should score higher than weak ({scores['weak']})"
        )
        assert scores["strong"] > scores["mixed"], (
            f"strong ({scores['strong']}) should score higher than mixed ({scores['mixed']})"
        )
        assert scores["mixed"] > scores["weak"], (
            f"mixed ({scores['mixed']}) should score higher than weak ({scores['weak']})"
        )

        # All scores must be distinct
        score_values = list(scores.values())
        assert len(set(score_values)) == len(score_values), f"Scores must be distinct: {scores}"

    def test_weak_score_lowest(self) -> None:
        """weak profile must have the lowest score."""
        store = scan_result_to_facts(_make_weak_result())
        subject = "10.0.1.2:500"
        results = self.engine.evaluate(store, subject)
        gateway_score = compute_score(subject, results)

        assert gateway_score.final_score < 50, f"weak profile score should be < 50, got {gateway_score.final_score}"
        assert gateway_score.rules_failed > 0

    def test_strong_score_highest(self) -> None:
        """strong profile must have the highest score."""
        store = scan_result_to_facts(_make_strong_result())
        subject = "10.0.1.2:500"
        results = self.engine.evaluate(store, subject)
        gateway_score = compute_score(subject, results)

        assert gateway_score.final_score >= 60, f"strong profile score should be >= 60, got {gateway_score.final_score}"

    def test_score_floor_at_zero(self) -> None:
        """Score can never go below 0."""
        from tunneltwin.rules.engine import RuleResult

        # Create extreme penalty results
        extreme_results = [
            RuleResult(
                rule_id=f"TEST-{i}",
                rule_name=f"Critical Failure {i}",
                pack="test",
                category="encryption",
                status=AssessmentStatus.FAIL,
                severity=10,
                citation="test",
            )
            for i in range(20)
        ]
        gateway_score = compute_score("test-gw", extreme_results)
        assert gateway_score.final_score == 0
        assert gateway_score.raw_score == 0.0

    def test_coverage_percentage(self) -> None:
        """Assessed coverage percentage is correctly calculated."""
        store = scan_result_to_facts(_make_strong_result())
        subject = "10.0.1.2:500"
        results = self.engine.evaluate(store, subject)
        gateway_score = compute_score(subject, results)

        # Coverage should be > 0 (some rules assessed) and <= 100
        assert 0 < gateway_score.assessed_coverage_pct <= 100.0

    def test_findings_carry_citations(self) -> None:
        """Every finding must carry an exact rule/clause citation."""
        store = scan_result_to_facts(_make_weak_result())
        subject = "10.0.1.2:500"
        results = self.engine.evaluate(store, subject)
        gateway_score = compute_score(subject, results)

        for finding in gateway_score.findings:
            assert finding.citation, f"Finding {finding.rule_id} has no citation"
            assert len(finding.citation) > 10, f"Finding {finding.rule_id} citation too short: {finding.citation}"


# ═══════════════════════════════════════════════════════════════════════
#  Test Group 6: CANNOT_ASSESS Semantics
# ═══════════════════════════════════════════════════════════════════════


class TestCannotAssess:
    """Tests for the CANNOT_ASSESS guarantee on missing facts."""

    def test_missing_facts_produce_cannot_assess(self) -> None:
        """A rule requiring facts that don't exist MUST return CANNOT_ASSESS."""
        rule = Rule(
            id="TEST-001",
            name="Test Rule",
            pack="test",
            category="encryption",
            description="Test rule requiring cipher fact",
            required_facts=["cipher"],
            condition_type="not_in",
            condition_field="cipher",
            condition_values=["DES"],
            severity=5,
            citation="Test Citation §1",
        )
        empty_store = FactStore()
        result = evaluate_rule(rule, empty_store, "gw1")
        assert result.status == AssessmentStatus.CANNOT_ASSESS
        assert "cipher" in result.message

    def test_cannot_assess_never_pass_or_fail(self) -> None:
        """UNKNOWN facts must never produce PASS or FAIL."""
        rules = load_all_rule_packs(PACKS_DIR)
        empty_store = FactStore()

        for rule in rules:
            result = evaluate_rule(rule, empty_store, "empty-gw")
            assert result.status == AssessmentStatus.CANNOT_ASSESS, (
                f"Rule {rule.id} with no facts should be CANNOT_ASSESS, got {result.status}"
            )

    def test_partial_facts_cannot_assess(self) -> None:
        """If some required facts exist but others don't, result is CANNOT_ASSESS."""
        rule = Rule(
            id="TEST-002",
            name="Multi-fact Rule",
            pack="test",
            category="key_exchange",
            description="Requires both ike_version and accepted_dh_group",
            required_facts=["ike_version", "accepted_dh_group"],
            condition_type="not_in",
            condition_field="accepted_dh_group",
            condition_values=["MODP-768"],
            severity=5,
            citation="Test Citation §2",
        )
        store = FactStore()
        store.add(
            Fact(
                subject="gw1",
                key="ike_version",
                value="IKEv2",
                provenance=ProvenanceTag.OBSERVED,
            )
        )
        # Deliberately not adding accepted_dh_group
        result = evaluate_rule(rule, store, "gw1")
        assert result.status == AssessmentStatus.CANNOT_ASSESS
        assert "accepted_dh_group" in result.message
