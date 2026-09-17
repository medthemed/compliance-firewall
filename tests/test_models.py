"""Tests for the models module."""

from __future__ import annotations

from compliance_firewall.models import Action, ActionType, Decision, Severity


class TestActionSerialization:
    """Action.to_dict / from_dict round-trip."""

    def test_roundtrip(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            contains_pii=True,
            purpose="analytics",
            data_categories=["email", "phone"],
            payload={"email": "a@b.c"},
            actor="agent-1",
        )
        d = action.to_dict()
        restored = Action.from_dict(d)
        assert restored.action_type == ActionType.DATA_EXPORT
        assert restored.destination_region == "US"
        assert restored.contains_pii is True
        assert restored.purpose == "analytics"
        assert restored.data_categories == ["email", "phone"]
        assert restored.payload == {"email": "a@b.c"}
        assert restored.actor == "agent-1"

    def test_from_dict_defaults(self):
        action = Action.from_dict({"action_type": "http_request"})
        assert action.action_type == ActionType.HTTP_REQUEST
        assert action.destination_region == ""
        assert action.contains_pii is False
        assert action.data_categories == []
        assert action.payload == {}
        assert action.actor == ""


class TestEnums:
    """Enum value correctness."""

    def test_action_types(self):
        assert ActionType.HTTP_REQUEST.value == "http_request"
        assert ActionType.DB_QUERY.value == "db_query"
        assert ActionType.DATA_EXPORT.value == "data_export"
        assert ActionType.TOOL_CALL.value == "tool_call"

    def test_decisions(self):
        assert Decision.ALLOW.value == "allow"
        assert Decision.BLOCK.value == "block"
        assert Decision.REDACT.value == "redact"
        assert Decision.REQUIRE_CONSENT.value == "require_consent"

    def test_severities(self):
        assert Severity.LOW.value == "low"
        assert Severity.CRITICAL.value == "critical"
