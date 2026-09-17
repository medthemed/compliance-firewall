"""Tests for the proxy middleware."""

from __future__ import annotations

import pytest

from compliance_firewall.models import (
    Action,
    ActionType,
    Decision,
    MatchCondition,
    Rule,
    Severity,
)
from compliance_firewall.proxy import (
    ActionBlockedError,
    ComplianceError,
    ComplianceProxy,
    ConsentRequiredError,
)


def _block_rule() -> Rule:
    return Rule(
        id="BLOCK-ALL-PII-US",
        jurisdiction="EU",
        description="Block PII to US",
        match=MatchCondition(contains_pii=True, destination_regions=("US",)),
        decision=Decision.BLOCK,
        severity=Severity.CRITICAL,
        citation="GDPR Art. 44",
        remediation="Use EU processor",
        priority=100,
    )


def _redact_rule() -> Rule:
    return Rule(
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


def _consent_rule() -> Rule:
    return Rule(
        id="CONSENT-MKT",
        jurisdiction="US-CA",
        description="Marketing needs consent",
        match=MatchCondition(
            data_categories=("email",),
            purposes=("marketing",),
        ),
        decision=Decision.REQUIRE_CONSENT,
        severity=Severity.HIGH,
        citation="CCPA",
        remediation="Get opt-in",
        priority=50,
    )


class TestProxyBlocks:
    """Blocked actions never reach the executor."""

    def test_blocked_action_raises_and_never_calls_executor(self):
        calls: list[Action] = []

        def executor(action: Action) -> str:
            calls.append(action)
            return "should-not-happen"

        proxy = ComplianceProxy(rules=[_block_rule()], executor=executor)

        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            contains_pii=True,
            data_categories=["email"],
        )

        with pytest.raises(ActionBlockedError) as exc_info:
            proxy.execute(action)

        assert len(calls) == 0, "Executor must NOT be called for blocked actions"
        assert exc_info.value.result.is_blocked

    def test_on_block_callback_fired(self):
        blocked_actions: list[Action] = []

        def executor(action: Action) -> None:
            pass

        proxy = ComplianceProxy(
            rules=[_block_rule()],
            executor=executor,
            on_block=lambda a, r: blocked_actions.append(a),
        )

        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            contains_pii=True,
        )

        with pytest.raises(ActionBlockedError):
            proxy.execute(action)

        assert len(blocked_actions) == 1

    def test_audit_log_records_block(self):
        proxy = ComplianceProxy(rules=[_block_rule()], executor=lambda a: None)
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            contains_pii=True,
        )
        with pytest.raises(ActionBlockedError):
            proxy.execute(action)

        log = proxy.get_audit_log()
        assert len(log) == 1
        assert log[0][1].is_blocked


class TestProxyAllows:
    """Allowed actions are passed through to the executor."""

    def test_allowed_action_calls_executor(self):
        calls: list[Action] = []

        def executor(action: Action) -> dict:
            calls.append(action)
            return {"status": "ok"}

        proxy = ComplianceProxy(rules=[_block_rule()], executor=executor)

        action = Action(
            action_type=ActionType.HTTP_REQUEST,
            destination_region="EU",
            contains_pii=False,
        )

        result = proxy.execute(action)
        assert result == {"status": "ok"}
        assert len(calls) == 1
        assert calls[0] is action

    def test_executor_receives_original_action_when_allowed(self):
        received: list[Action] = []

        def executor(action: Action) -> None:
            received.append(action)

        proxy = ComplianceProxy(rules=[], executor=executor)
        action = Action(action_type=ActionType.TOOL_CALL, payload={"x": 1})
        proxy.execute(action)
        assert received[0].payload == {"x": 1}


class TestProxyRedacts:
    """Redacted actions run with scrubbed payload."""

    def test_redacted_action_runs_with_scrubbed_payload(self):
        received: list[Action] = []

        def executor(action: Action) -> dict:
            received.append(action)
            return {"executed": True, "payload": action.payload}

        proxy = ComplianceProxy(rules=[_redact_rule()], executor=executor)

        action = Action(
            action_type=ActionType.TOOL_CALL,
            contains_pii=True,
            data_categories=["phone"],
            payload={"tool": "lookup", "phone": "+1-555-0100", "ticket": "T1"},
        )

        result = proxy.execute(action)
        assert result["executed"] is True
        assert len(received) == 1
        # Executor received the REDACTED action
        assert received[0].payload["phone"] == "[REDACTED]"
        assert received[0].payload["tool"] == "lookup"
        assert received[0].payload["ticket"] == "T1"
        assert received[0].contains_pii is False

    def test_on_redact_callback_fired(self):
        redacted_actions: list[Action] = []

        proxy = ComplianceProxy(
            rules=[_redact_rule()],
            executor=lambda a: None,
            on_redact=lambda a, r: redacted_actions.append(a),
        )

        action = Action(
            action_type=ActionType.TOOL_CALL,
            contains_pii=True,
            data_categories=["phone"],
            payload={"phone": "+1"},
        )

        proxy.execute(action)
        assert len(redacted_actions) == 1


class TestProxyConsent:
    """Consent-required actions raise before executor."""

    def test_consent_required_raises(self):
        calls: list[Action] = []

        def executor(action: Action) -> None:
            calls.append(action)

        proxy = ComplianceProxy(rules=[_consent_rule()], executor=executor)

        action = Action(
            action_type=ActionType.DATA_EXPORT,
            contains_pii=True,
            data_categories=["email"],
            purpose="marketing",
        )

        with pytest.raises(ConsentRequiredError):
            proxy.execute(action)

        assert len(calls) == 0


class TestProxyCheck:
    """check() evaluates without executing."""

    def test_check_does_not_execute(self):
        calls: list[Action] = []
        proxy = ComplianceProxy(
            rules=[_block_rule()],
            executor=lambda a: calls.append(a),
        )
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            contains_pii=True,
        )
        result = proxy.check(action)
        assert result.is_blocked
        assert len(calls) == 0


class TestComplianceErrorBase:
    """ComplianceError is a shared base for block and consent failures."""

    def test_blocked_is_compliance_error(self):
        proxy = ComplianceProxy(rules=[_block_rule()], executor=lambda a: None)
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            contains_pii=True,
        )
        with pytest.raises(ComplianceError) as exc_info:
            proxy.execute(action)
        assert isinstance(exc_info.value, ActionBlockedError)
        assert exc_info.value.result is not None

    def test_consent_is_compliance_error(self):
        proxy = ComplianceProxy(rules=[_consent_rule()], executor=lambda a: None)
        action = Action(
            action_type=ActionType.DATA_EXPORT,
            contains_pii=True,
            data_categories=["email"],
            purpose="marketing",
        )
        with pytest.raises(ComplianceError) as exc_info:
            proxy.execute(action)
        assert isinstance(exc_info.value, ConsentRequiredError)

    def test_except_compliance_error_catches_both(self):
        caught: list[str] = []
        proxy = ComplianceProxy(
            rules=[_block_rule(), _consent_rule()],
            executor=lambda a: None,
        )
        block_action = Action(
            action_type=ActionType.DATA_EXPORT,
            destination_region="US",
            contains_pii=True,
        )
        consent_action = Action(
            action_type=ActionType.DATA_EXPORT,
            contains_pii=True,
            data_categories=["email"],
            purpose="marketing",
        )
        for action in (block_action, consent_action):
            try:
                proxy.execute(action)
            except ComplianceError as exc:
                caught.append(exc.result.decision.value)
        assert caught == ["block", "require_consent"]
