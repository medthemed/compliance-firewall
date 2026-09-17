"""Pure-function evaluator: Action + Rules -> DecisionResult."""

from __future__ import annotations

from .models import Action, Decision, DecisionResult, Rule
from .redact import redact_action

# Decision priority: lower value = more restrictive = wins
_DECISION_PRIORITY: dict[Decision, int] = {
    Decision.BLOCK: 0,
    Decision.REQUIRE_CONSENT: 1,
    Decision.REDACT: 2,
    Decision.ALLOW: 3,
}


def _resolve_deciding_rule(
    matched_sorted: list[Rule], final_decision: Decision
) -> Rule | None:
    """Pick the highest-priority matched rule that proposed the final decision.

    ``matched_sorted`` must already be ordered by priority (descending).
    """
    for rule in matched_sorted:
        if rule.decision == final_decision:
            return rule
    return None


def evaluate(action: Action, rules: list[Rule]) -> DecisionResult:
    """Evaluate an action against a set of compliance rules.

    This is a pure function: same inputs always produce the same output.

    Args:
        action: The agent's intended action.
        rules: List of compliance rules to check against.

    Returns:
        DecisionResult with the final decision, matched rules, deciding rule,
        overridden rules, and remediation hints.
    """
    matched = [r for r in rules if r.applies_to(action)]

    if not matched:
        return DecisionResult(
            decision=Decision.ALLOW,
            matched_rules=(),
            remediation_hints=(),
            action=action,
        )

    # Sort matched rules by priority desc, then by severity implicitly via decision priority
    matched_sorted = sorted(matched, key=lambda r: r.priority, reverse=True)

    # Most restrictive decision wins
    final_decision = min(
        (r.decision for r in matched_sorted),
        key=lambda d: _DECISION_PRIORITY[d],
    )

    deciding = _resolve_deciding_rule(matched_sorted, final_decision)
    overridden = tuple(
        r
        for r in matched_sorted
        if deciding is not None
        and r is not deciding
        and _DECISION_PRIORITY[r.decision] > _DECISION_PRIORITY[final_decision]
    )

    hints = tuple(
        r.remediation for r in matched_sorted if r.remediation
    )

    redacted = None
    if final_decision == Decision.REDACT:
        redacted = redact_action(action)

    return DecisionResult(
        decision=final_decision,
        matched_rules=tuple(matched_sorted),
        remediation_hints=hints,
        action=action,
        redacted_action=redacted,
        deciding_rule=deciding,
        overridden_rules=overridden,
    )
