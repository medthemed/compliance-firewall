"""Tests for the models module."""

from __future__ import annotations

from compliance_firewall.models import Action, ActionType, Decision, MatchCondition, Severity


class TestActionSerialization:
    """Action.to_dict / from_dict round-trip."""

    def test_roundtrip(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            source_region="CN",
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
        assert restored.source_region == "CN"
        assert restored.contains_pii is True
        assert restored.purpose == "analytics"
        assert restored.data_categories == ["email", "phone"]
        assert restored.payload == {"email": "a@b.c"}
        assert restored.actor == "agent-1"

    def test_from_dict_defaults(self):
        action = Action.from_dict({"action_type": "http_request"})
        assert action.action_type == ActionType.HTTP_REQUEST
        assert action.destination_region == ""
        assert action.source_region == ""
        assert action.contains_pii is False
        assert action.data_categories == []
        assert action.payload == {}
        assert action.actor == ""

    def test_from_dict_source_region(self):
        action = Action.from_dict(
            {"action_type": "data_export", "source_region": "EU"}
        )
        assert action.source_region == "EU"

    def test_to_dict_includes_source_region(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            source_region="CN",
        )
        assert action.to_dict()["source_region"] == "CN"


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


class TestSourceRegionMatching:
    """MatchCondition.source_regions semantics."""

    def test_source_regions_match(self):
        cond = MatchCondition(source_regions=("CN",))
        action = Action(action_type=ActionType.DATA_EXPORT, source_region="CN")
        assert cond.matches(action)

    def test_source_regions_no_match(self):
        cond = MatchCondition(source_regions=("CN",))
        action = Action(action_type=ActionType.DATA_EXPORT, source_region="EU")
        assert not cond.matches(action)

    def test_source_regions_empty_action_does_not_match(self):
        # An action with no source_region must not match a rule that requires one
        cond = MatchCondition(source_regions=("CN",))
        action = Action(action_type=ActionType.DATA_EXPORT, source_region="")
        assert not cond.matches(action)

    def test_source_regions_unset_is_wildcard(self):
        cond = MatchCondition(contains_pii=True)
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            source_region="CN",
            contains_pii=True,
        )
        assert cond.matches(action)

    def test_source_regions_multiple_values(self):
        cond = MatchCondition(source_regions=("CN", "RU", "IN"))
        for region in ("CN", "RU", "IN"):
            action = Action(action_type=ActionType.DATA_EXPORT, source_region=region)
            assert cond.matches(action), f"expected match for {region}"
        other = Action(action_type=ActionType.DATA_EXPORT, source_region="US")
        assert not cond.matches(other)

    def test_source_and_destination_combined(self):
        cond = MatchCondition(
            source_regions=("CN",),
            destination_regions=("US",),
            contains_pii=True,
        )
        matching = Action(
            action_type=ActionType.DATA_EXPORT,
            source_region="CN",
            destination_region="US",
            contains_pii=True,
        )
        assert cond.matches(matching)

        wrong_source = Action(
            action_type=ActionType.DATA_EXPORT,
            source_region="EU",
            destination_region="US",
            contains_pii=True,
        )
        assert not cond.matches(wrong_source)

        wrong_dest = Action(
            action_type=ActionType.DATA_EXPORT,
            source_region="CN",
            destination_region="EU",
            contains_pii=True,
        )
        assert not cond.matches(wrong_dest)
