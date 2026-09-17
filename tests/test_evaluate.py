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
