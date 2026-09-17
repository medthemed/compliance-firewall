"""Tests for the evaluator: Action + Rules -> DecisionResult."""

from __future__ import annotations

import pytest

from compliance_firewall.evaluate import evaluate
from compliance_firewall.models import (
    Action,
    ActionType,
    Decision,
    MatchCondition,
    Rule,
    Severity,
)


def _make_rule(
    id: str = "TEST-001",
    decision: Decision = Decision.BLOCK,
    priority: int = 0,
    contains_pii: bool | None = True,
    destination_regions: tuple[str, ...] | None = ("US",),
    action_types: tuple[str, ...] | None = None,
    data_categories: tuple[str, ...] | None = None,
    purposes: tuple[str, ...] | None = None,
    remediation: str = "",
) -> Rule:
    return Rule(
        id=id,
        jurisdiction="EU",
        description=f"Test rule {id}",
        match=MatchCondition(
            contains_pii=contains_pii,
            destination_regions=destination_regions,
            action_types=action_types,
            data_categories=data_categories,
            purposes=purposes,
        ),
        decision=decision,
        severity=Severity.CRITICAL,
        citation="TEST-CITE",
        remediation=remediation,
        priority=priority,
    )


class TestBlockPIIToForbiddenRegion:
    """Block PII transferred to a forbidden region."""

    def test_block_pii_to_us(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            contains_pii=True,
            data_categories=["email"],
            payload={"email": "user@example.com"},
        )
        rules = [_make_rule(decision=Decision.BLOCK)]
        result = evaluate(action, rules)
        assert result.is_blocked
        assert result.decision == Decision.BLOCK
        assert len(result.matched_rules) == 1

    def test_block_multiple_forbidden_regions(self):
        for region in ["US", "CN", "RU", "IN"]:
            action = Action(
                action_type=ActionType.HTTP_REQUEST,
                destination_region=region,
                contains_pii=True,
            )
            rules = [_make_rule(destination_regions=("US", "CN", "RU", "IN"))]
            result = evaluate(action, rules)
            assert result.is_blocked, f"Expected block for region {region}"


class TestAllowCleanAction:
    """Allow actions with no matching rules."""

    def test_allow_no_pii_no_rules(self):
        action = Action(
            action_type=ActionType.HTTP_REQUEST,
            destination_region="EU",
            contains_pii=False,
        )
        result = evaluate(action, [])
        assert result.decision == Decision.ALLOW
        assert not result.is_blocked
        assert len(result.matched_rules) == 0

    def test_allow_when_no_rules_match(self):
        action = Action(
            action_type=ActionType.HTTP_REQUEST,
            destination_region="EU",
            contains_pii=False,
        )
        rules = [_make_rule(contains_pii=True)]  # requires PII
        result = evaluate(action, rules)
        assert result.decision == Decision.ALLOW

    def test_allow_to_adequate_region(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="EU",
            contains_pii=True,
            data_categories=["email"],
        )
        rules = [_make_rule(destination_regions=("US",))]  # only blocks US
        result = evaluate(action, rules)
        assert result.decision == Decision.ALLOW


class TestRedactPath:
    """Redact decisions produce scrubbed payloads."""

    def test_redact_strips_fields(self):
        action = Action(
            action_type=ActionType.TOOL_CALL,
            destination_region="EU",
            contains_pii=True,
            data_categories=["phone"],
            payload={"tool": "lookup", "phone": "+49-123", "id": 42},
        )
        rules = [_make_rule(decision=Decision.REDACT, destination_regions=None)]
        result = evaluate(action, rules)
        assert result.is_redacted
        assert result.redacted_action is not None
        assert result.redacted_action.payload["phone"] == "[REDACTED]"
        assert result.redacted_action.payload["tool"] == "lookup"
        assert result.redacted_action.payload["id"] == 42
        assert result.redacted_action.contains_pii is False

    def test_redact_preserves_original_action(self):
        original_payload = {"phone": "+1-555"}
        action = Action(
            action_type=ActionType.TOOL_CALL,
            contains_pii=True,
            data_categories=["phone"],
            payload=original_payload,
        )
        rules = [_make_rule(decision=Decision.REDACT, destination_regions=None)]
        result = evaluate(action, rules)
        # Original action untouched
        assert action.payload["phone"] == "+1-555"
        # Redacted copy has placeholder
        assert result.redacted_action.payload["phone"] == "[REDACTED]"


class TestRulePriority:
    """Higher-priority rules take precedence in decision resolution."""

    def test_block_wins_over_allow(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            contains_pii=True,
        )
        block_rule = _make_rule(id="BLOCK-R", decision=Decision.BLOCK, priority=10)
        allow_rule = _make_rule(
            id="ALLOW-R",
            decision=Decision.ALLOW,
            priority=0,
            contains_pii=True,
            destination_regions=("US",),
        )
        result = evaluate(action, [allow_rule, block_rule])
        assert result.decision == Decision.BLOCK

    def test_block_wins_over_redact(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            contains_pii=True,
        )
        block_rule = _make_rule(id="B", decision=Decision.BLOCK, priority=100)
        redact_rule = _make_rule(id="R", decision=Decision.REDACT, priority=1)
        result = evaluate(action, [redact_rule, block_rule])
        assert result.decision == Decision.BLOCK

    def test_require_consent_wins_over_redact(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            contains_pii=True,
        )
        consent_rule = _make_rule(id="C", decision=Decision.REQUIRE_CONSENT, priority=50)
        redact_rule = _make_rule(id="R", decision=Decision.REDACT, priority=10)
        result = evaluate(action, [redact_rule, consent_rule])
        assert result.decision == Decision.REQUIRE_CONSENT
        assert result.requires_consent

    def test_matched_rules_sorted_by_priority(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            contains_pii=True,
        )
        low = _make_rule(id="LOW", decision=Decision.ALLOW, priority=1)
        high = _make_rule(id="HIGH", decision=Decision.BLOCK, priority=100)
        mid = _make_rule(id="MID", decision=Decision.REDACT, priority=50)
        result = evaluate(action, [low, mid, high])
        assert [r.id for r in result.matched_rules] == ["HIGH", "MID", "LOW"]


class TestRequireConsent:
    """Require-consent decision is surfaced correctly."""

    def test_require_consent_decision(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="EU",
            contains_pii=True,
            data_categories=["email"],
            purpose="marketing",
        )
        rules = [
            _make_rule(
                decision=Decision.REQUIRE_CONSENT,
                destination_regions=("EU",),
                purposes=("marketing",),
            )
        ]
        result = evaluate(action, rules)
        assert result.requires_consent
        assert result.decision == Decision.REQUIRE_CONSENT
        assert result.redacted_action is None


class TestRemediationHints:
    """Remediation hints are collected from matched rules."""

    def test_hints_collected(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            contains_pii=True,
        )
        rules = [
            _make_rule(id="A", remediation="Hint A", priority=10),
            _make_rule(id="B", remediation="Hint B", priority=5),
        ]
        result = evaluate(action, rules)
        assert "Hint A" in result.remediation_hints
        assert "Hint B" in result.remediation_hints


class TestActionTypeMatching:
    """Rules can filter by action type."""

    def test_action_type_filter(self):
        action = Action(
            action_type=ActionType.HTTP_REQUEST,
            destination_region="US",
            contains_pii=True,
        )
        rules = [_make_rule(action_types=("db_query",))]
        result = evaluate(action, rules)
        assert result.decision == Decision.ALLOW  # no match

    def test_action_type_match(self):
        action = Action(
            action_type=ActionType.DB_QUERY,
            destination_region="US",
            contains_pii=True,
        )
        rules = [_make_rule(action_types=("db_query", "data_export"))]
        result = evaluate(action, rules)
        assert result.is_blocked


class TestSourceRegionMatching:
    """Origin-based jurisdiction matching via source_regions."""

    def _pipl_rule(self) -> Rule:
        return Rule(
            id="CHINA-PIPL-LOCALIZE",
            jurisdiction="CN",
            description="PII collected in China must not leave without assessment",
            match=MatchCondition(
                source_regions=("CN",),
                destination_regions=("US",),
                contains_pii=True,
            ),
            decision=Decision.BLOCK,
            severity=Severity.CRITICAL,
            citation="PIPL Art. 38",
            remediation="Complete a CAC security assessment.",
            priority=90,
        )

    def test_pipl_blocks_china_origin_pii_to_us(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            source_region="CN",
            contains_pii=True,
            data_categories=["email"],
        )
        result = evaluate(action, [self._pipl_rule()])
        assert result.is_blocked
        assert result.matched_rules[0].id == "CHINA-PIPL-LOCALIZE"

    def test_pipl_allows_non_china_origin_pii_to_us(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            source_region="EU",
            contains_pii=True,
            data_categories=["email"],
        )
        result = evaluate(action, [self._pipl_rule()])
        assert result.decision == Decision.ALLOW
        assert len(result.matched_rules) == 0

    def test_pipl_allows_unspecified_source(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            contains_pii=True,
            data_categories=["email"],
        )
        result = evaluate(action, [self._pipl_rule()])
        assert result.decision == Decision.ALLOW

    def test_pipl_allows_china_origin_to_adequate_region(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="EU",
            source_region="CN",
            contains_pii=True,
            data_categories=["email"],
        )
        result = evaluate(action, [self._pipl_rule()])
        assert result.decision == Decision.ALLOW

    def test_gdpr_and_pipl_both_match_china_origin(self):
        gdpr = _make_rule(
            id="GDPR-ART44",
            decision=Decision.BLOCK,
            destination_regions=("US", "CN", "RU", "IN"),
            contains_pii=True,
        )
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            source_region="CN",
            contains_pii=True,
        )
        result = evaluate(action, [gdpr, self._pipl_rule()])
        assert result.is_blocked
        matched_ids = [r.id for r in result.matched_rules]
        assert "GDPR-ART44" in matched_ids
        assert "CHINA-PIPL-LOCALIZE" in matched_ids

    def test_redact_preserves_source_region(self):
        action = Action(
            action_type=ActionType.TOOL_CALL,
            source_region="CN",
            contains_pii=True,
            data_categories=["phone"],
            payload={"phone": "+86-138-0000"},
        )
        rules = [
            Rule(
                id="REDACT-PHONE",
                jurisdiction="GLOBAL",
                description="Redact phone",
                match=MatchCondition(data_categories=("phone",)),
                decision=Decision.REDACT,
                severity=Severity.MEDIUM,
                citation="POL-003",
                remediation="Strip phone",
                priority=10,
            )
        ]
        result = evaluate(action, rules)
        assert result.is_redacted
        assert result.redacted_action is not None
        assert result.redacted_action.source_region == "CN"


class TestDecisionExplanation:
    """deciding_rule, overridden_rules, and explain() (issue #3)."""

    def _action(self, **kwargs) -> Action:
        defaults = {
            "action_type": ActionType.DATA_EXPORT,
            "destination_region": "US",
            "contains_pii": True,
            "data_categories": ["email"],
            "purpose": "marketing",
        }
        defaults.update(kwargs)
        return Action(**defaults)

    def test_no_match_means_no_deciding_rule(self):
        result = evaluate(self._action(), [])
        assert result.deciding_rule is None
        assert result.overridden_rules == ()
        assert result.explain() == "No rules matched; action allowed."

    def test_single_rule_is_deciding(self):
        rule = _make_rule(id="ONLY", decision=Decision.BLOCK, priority=10)
        result = evaluate(self._action(), [rule])
        assert result.deciding_rule is not None
        assert result.deciding_rule.id == "ONLY"
        assert result.overridden_rules == ()
        assert result.explain() == "block by ONLY (critical)."

    def test_same_decision_multi_rule_picks_highest_priority(self):
        low = _make_rule(id="LOW", decision=Decision.BLOCK, priority=1)
        high = _make_rule(id="HIGH", decision=Decision.BLOCK, priority=100)
        result = evaluate(self._action(), [low, high])
        assert result.deciding_rule.id == "HIGH"
        # Same decision → nothing overridden
        assert result.overridden_rules == ()
        assert "overridden" not in result.explain()

    def test_mixed_decisions_block_overrides_soft_matches(self):
        block = _make_rule(id="BLOCK-R", decision=Decision.BLOCK, priority=100)
        consent = _make_rule(
            id="CONSENT-R",
            decision=Decision.REQUIRE_CONSENT,
            priority=50,
            purposes=("marketing",),
        )
        redact = _make_rule(
            id="REDACT-R",
            decision=Decision.REDACT,
            priority=10,
            destination_regions=None,
        )
        result = evaluate(self._action(), [redact, consent, block])
        assert result.decision == Decision.BLOCK
        assert result.deciding_rule.id == "BLOCK-R"
        overridden_ids = [r.id for r in result.overridden_rules]
        assert "CONSENT-R" in overridden_ids
        assert "REDACT-R" in overridden_ids
        assert "BLOCK-R" not in overridden_ids
        explanation = result.explain()
        assert explanation.startswith("block by BLOCK-R (critical)")
        assert "overridden:" in explanation
        assert "CONSENT-R (require_consent)" in explanation
        assert "REDACT-R (redact)" in explanation

    def test_consent_overrides_redact(self):
        consent = _make_rule(
            id="C", decision=Decision.REQUIRE_CONSENT, priority=50
        )
        redact = _make_rule(
            id="R",
            decision=Decision.REDACT,
            priority=10,
            destination_regions=None,
        )
        result = evaluate(self._action(), [redact, consent])
        assert result.deciding_rule.id == "C"
        assert [r.id for r in result.overridden_rules] == ["R"]
        assert result.explain() == (
            "require_consent by C (critical); overridden: R (redact)."
        )
