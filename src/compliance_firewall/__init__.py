"""compliance-firewall: intercept agent actions against compliance rules."""

from .evaluate import evaluate
from .models import (
    Action,
    ActionType,
    Decision,
    DecisionResult,
    MatchCondition,
    Rule,
    Severity,
)
from .proxy import (
    ActionBlockedError,
    ComplianceError,
    ComplianceProxy,
    ConsentRequiredError,
)
from .redact import REDACTED_PLACEHOLDER, redact_action, redact_payload
from .rules import load_rules, load_rules_from_dict

__version__ = "0.1.1"

__all__ = [
    "Action",
    "ActionBlockedError",
    "ActionType",
    "ComplianceError",
    "ComplianceProxy",
    "ConsentRequiredError",
    "Decision",
    "DecisionResult",
    "MatchCondition",
    "REDACTED_PLACEHOLDER",
    "Rule",
    "Severity",
    "evaluate",
    "load_rules",
    "load_rules_from_dict",
    "redact_action",
    "redact_payload",
]
