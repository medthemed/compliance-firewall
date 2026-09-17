"""Proxy middleware: wraps an executor with compliance evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .evaluate import evaluate
from .models import Action, Decision, DecisionResult, Rule


class ActionBlockedError(Exception):
    """Raised when a blocked action is attempted through the proxy."""

    def __init__(self, result: DecisionResult):
        self.result = result
        rules_str = ", ".join(r.id for r in result.matched_rules)
        hints = "; ".join(result.remediation_hints) if result.remediation_hints else ""
        msg = f"Action blocked by compliance rules: {rules_str}"
        if hints:
            msg += f". Remediation: {hints}"
        super().__init__(msg)


class ConsentRequiredError(Exception):
    """Raised when an action requires explicit consent."""

    def __init__(self, result: DecisionResult):
        self.result = result
        rules_str = ", ".join(r.id for r in result.matched_rules)
        super().__init__(
            f"Action requires consent (matched rules: {rules_str}). "
            "Obtain user consent before retrying."
        )


@dataclass
class ComplianceProxy:
    """Wraps an executor function with compliance evaluation.

    The executor is only called if the action is allowed or successfully redacted.
    Blocked actions raise ActionBlockedError and never reach the executor.
    Consent-required actions raise ConsentRequiredError.

    Attributes:
        rules: List of compliance rules to enforce.
        executor: Callable that receives an Action and returns Any.
        on_block: Optional callback invoked when an action is blocked.
        on_redact: Optional callback invoked when an action is redacted.
        audit_log: List of (action, result) tuples for all evaluated actions.
    """

    rules: list[Rule]
    executor: Callable[[Action], Any]
    on_block: Callable[[Action, DecisionResult], None] | None = None
    on_redact: Callable[[Action, DecisionResult], None] | None = None
    audit_log: list[tuple[Action, DecisionResult]] = field(default_factory=list)

    def check(self, action: Action) -> DecisionResult:
        """Evaluate an action without executing it."""
        return evaluate(action, self.rules)

    def execute(self, action: Action) -> Any:
        """Evaluate and conditionally execute an action.

        Args:
            action: The intended action.

        Returns:
            Result of the executor, or None if the action was blocked
            (blocked actions raise ActionBlockedError).

        Raises:
            ActionBlockedError: If the action is blocked.
            ConsentRequiredError: If the action requires consent.
        """
        result = evaluate(action, self.rules)
        self.audit_log.append((action, result))

        if result.decision == Decision.BLOCK:
            if self.on_block:
                self.on_block(action, result)
            raise ActionBlockedError(result)

        if result.decision == Decision.REQUIRE_CONSENT:
            raise ConsentRequiredError(result)

        if result.decision == Decision.REDACT:
            if self.on_redact:
                self.on_redact(action, result)
            # Execute with the redacted action
            assert result.redacted_action is not None
            return self.executor(result.redacted_action)

        # ALLOW
        return self.executor(action)

    def get_audit_log(self) -> list[tuple[Action, DecisionResult]]:
        """Return a copy of the audit log."""
        return list(self.audit_log)
