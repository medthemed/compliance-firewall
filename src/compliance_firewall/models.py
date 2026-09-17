"""Core data models for compliance-firewall."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ActionType(str, Enum):
    """Types of agent actions that can be intercepted."""

    HTTP_REQUEST = "http_request"
    DB_QUERY = "db_query"
    DATA_EXPORT = "data_export"
    TOOL_CALL = "tool_call"


class Decision(str, Enum):
    """Possible outcomes of compliance evaluation."""

    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    REQUIRE_CONSENT = "require_consent"


class Severity(str, Enum):
    """Severity levels for compliance rules."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Action:
    """An agent intended action with payload metadata.

    Attributes:
        action_type: The kind of action being performed.
        destination_region: ISO region code of the data destination (e.g. "US", "EU", "CN").
        contains_pii: Whether the payload contains personally identifiable information.
        purpose: Declared purpose of the action (e.g. "analytics", "marketing", "support").
        data_categories: List of data categories involved (e.g. ["email", "phone", "health"]).
        payload: Arbitrary payload dict; keys marked for redaction are scrubbed.
        actor: Optional identifier of the agent or user performing the action.
    """

    action_type: ActionType
    destination_region: str = ""
    contains_pii: bool = False
    purpose: str = ""
    data_categories: list[str] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)
    actor: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        return {
            "action_type": self.action_type.value,
            "destination_region": self.destination_region,
            "contains_pii": self.contains_pii,
            "purpose": self.purpose,
            "data_categories": list(self.data_categories),
            "payload": dict(self.payload),
            "actor": self.actor,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Action:
        """Construct an Action from a plain dict."""
        return cls(
            action_type=ActionType(data["action_type"]),
            destination_region=data.get("destination_region", ""),
            contains_pii=bool(data.get("contains_pii", False)),
            purpose=data.get("purpose", ""),
            data_categories=list(data.get("data_categories", [])),
            payload=dict(data.get("payload", {})),
            actor=data.get("actor", ""),
        )


@dataclass(frozen=True)
class MatchCondition:
    """Conditions under which a rule applies to an action.

    All specified conditions must match (AND semantics). Unset fields are
    treated as wildcards.
    """

    action_types: tuple[str, ...] | None = None
    destination_regions: tuple[str, ...] | None = None
    contains_pii: bool | None = None
    purposes: tuple[str, ...] | None = None
    data_categories: tuple[str, ...] | None = None
    min_severity: Severity | None = None

    def matches(self, action: Action) -> bool:
        """Return True if this condition matches the given action."""
        if self.action_types is not None:
            if action.action_type.value not in self.action_types:
                return False

        if self.destination_regions is not None:
            if action.destination_region not in self.destination_regions:
                return False

        if self.contains_pii is not None:
            if action.contains_pii != self.contains_pii:
                return False

        if self.purposes is not None:
            if action.purpose not in self.purposes:
                return False

        if self.data_categories is not None:
            # Match if any of the condition's categories appear in the action
            if not set(self.data_categories) & set(action.data_categories):
                return False

        return True


@dataclass(frozen=True)
class Rule:
    """A single compliance rule.

    Attributes:
        id: Unique rule identifier.
        jurisdiction: Legal jurisdiction (e.g. "EU", "US-CA", "GLOBAL").
        description: Human-readable description of the rule.
        match: Match conditions determining when the rule fires.
        decision: The decision to apply when the rule matches.
        severity: How serious a violation of this rule is.
        citation: Legal citation or reference (e.g. "GDPR Art. 44").
        remediation: Optional hint text for how to resolve a violation.
        priority: Higher priority rules take precedence (default 0).
    """

    id: str
    jurisdiction: str
    description: str
    match: MatchCondition
    decision: Decision
    severity: Severity
    citation: str
    remediation: str = ""
    priority: int = 0

    def applies_to(self, action: Action) -> bool:
        """Return True if this rule's match conditions match the action."""
        return self.match.matches(action)


@dataclass(frozen=True)
class DecisionResult:
    """The outcome of evaluating an action against a rule set.

    Attributes:
        decision: The final decision (most restrictive wins).
        matched_rules: Rules that matched the action, sorted by priority desc.
        remediation_hints: Aggregated remediation guidance from matched rules.
        action: The original action that was evaluated.
        redacted_action: Present only when decision is REDACT; contains scrubbed payload.
    """

    decision: Decision
    matched_rules: tuple[Rule, ...]
    remediation_hints: tuple[str, ...]
    action: Action
    redacted_action: Action | None = None

    @property
    def is_blocked(self) -> bool:
        """True if the action is blocked."""
        return self.decision == Decision.BLOCK

    @property
    def is_redacted(self) -> bool:
        """True if the action should run with scrubbed payload."""
        return self.decision == Decision.REDACT

    @property
    def requires_consent(self) -> bool:
        """True if the action requires explicit consent before proceeding."""
        return self.decision == Decision.REQUIRE_CONSENT
