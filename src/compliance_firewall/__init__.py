"""compliance-firewall: intercept agent actions against compliance rules."""

from .config import (
    Config,
    ConfigError,
    filter_rules_by_severity,
    load_config,
    load_config_file,
    parse_severity,
)
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

__version__ = "0.3.0"

__all__ = [
    "Action",
    "ActionBlockedError",
    "ActionType",
    "ComplianceError",
    "ComplianceProxy",
    "Config",
    "ConfigError",
    "ConsentRequiredError",
    "Decision",
    "DecisionResult",
    "MatchCondition",
    "REDACTED_PLACEHOLDER",
    "Rule",
    "Severity",
    "evaluate",
    "filter_rules_by_severity",
    "load_config",
    "load_config_file",
    "load_rules",
    "load_rules_from_dict",
    "parse_severity",
    "redact_action",
    "redact_payload",
]
