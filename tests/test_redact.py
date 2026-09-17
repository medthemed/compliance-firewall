"""Tests for redaction utilities."""

from __future__ import annotations

from compliance_firewall.models import Action, ActionType
from compliance_firewall.redact import (
    REDACTED_PLACEHOLDER,
    redact_action,
    redact_payload,
)


class TestRedactPayload:
    """Field-level redaction of payload dicts."""

    def test_strips_email_field(self):
        payload = {"email": "user@example.com", "name": "Alice"}
        result = redact_payload(payload, ["email"])
        assert result["email"] == REDACTED_PLACEHOLDER
        assert result["name"] == "Alice"

    def test_strips_multiple_categories(self):
        payload = {"email": "a@b.c", "phone": "+1-555", "note": "hello"}
        result = redact_payload(payload, ["email", "phone"])
        assert result["email"] == REDACTED_PLACEHOLDER
        assert result["phone"] == REDACTED_PLACEHOLDER
        assert result["note"] == "hello"

    def test_always_redacts_secrets(self):
        payload = {"password": "hunter2", "data": "public"}
        result = redact_payload(payload, [])
        assert result["password"] == REDACTED_PLACEHOLDER
        assert result["data"] == "public"

    def test_always_redacts_api_key(self):
        payload = {"api_key": "sk-123", "count": 5}
        result = redact_payload(payload, [])
        assert result["api_key"] == REDACTED_PLACEHOLDER

    def test_nested_dict_redaction(self):
        payload = {
            "user": {"email": "a@b.c", "id": 42},
            "meta": {"source": "web"},
        }
        result = redact_payload(payload, ["email"])
        assert result["user"]["email"] == REDACTED_PLACEHOLDER
        assert result["user"]["id"] == 42
        assert result["meta"]["source"] == "web"

    def test_list_redaction(self):
        payload = {"items": [{"email": "a@b.c"}, {"email": "d@e.f"}]}
        result = redact_payload(payload, ["email"])
        assert result["items"][0]["email"] == REDACTED_PLACEHOLDER
        assert result["items"][1]["email"] == REDACTED_PLACEHOLDER

    def test_does_not_mutate_original(self):
        payload = {"email": "a@b.c"}
        redact_payload(payload, ["email"])
        assert payload["email"] == "a@b.c"

    def test_empty_categories_still_redacts_secrets(self):
        payload = {"token": "abc", "name": "Alice"}
        result = redact_payload(payload, [])
        assert result["token"] == REDACTED_PLACEHOLDER
        assert result["name"] == "Alice"

    def test_unknown_category_maps_to_key_name(self):
        payload = {"custom_field": "sensitive", "other": "ok"}
        result = redact_payload(payload, ["custom_field"])
        assert result["custom_field"] == REDACTED_PLACEHOLDER
        assert result["other"] == "ok"


class TestRedactAction:
    """Full-action redaction."""

    def test_redact_action_scrubs_payload(self):
        action = Action(
            action_type=ActionType.TOOL_CALL,
            destination_region="EU",
            contains_pii=True,
            purpose="support",
            data_categories=["phone", "email"],
            payload={"phone": "+1-555", "email": "a@b.c", "ticket": "T1"},
            actor="agent-1",
        )
        redacted = redact_action(action)
        assert redacted.payload["phone"] == REDACTED_PLACEHOLDER
        assert redacted.payload["email"] == REDACTED_PLACEHOLDER
        assert redacted.payload["ticket"] == "T1"
        assert redacted.contains_pii is False
        assert redacted.data_categories == []

    def test_redact_action_preserves_metadata(self):
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            source_region="CN",
            contains_pii=True,
            purpose="analytics",
            data_categories=["email"],
            payload={"email": "a@b.c"},
            actor="agent-2",
        )
        redacted = redact_action(action)
        assert redacted.action_type == ActionType.DATA_EXPORT
        assert redacted.destination_region == "US"
        assert redacted.source_region == "CN"
        assert redacted.purpose == "analytics"
        assert redacted.actor == "agent-2"

    def test_redact_action_does_not_mutate_original(self):
        action = Action(
            action_type=ActionType.TOOL_CALL,
            contains_pii=True,
            data_categories=["phone"],
            payload={"phone": "+1-555"},
        )
        redact_action(action)
        assert action.payload["phone"] == "+1-555"
        assert action.contains_pii is True
