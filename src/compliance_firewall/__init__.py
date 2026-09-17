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
    decision_result_to_dict,
    rule_to_dict,
)
from .proxy import (
    ActionBlockedError,
    ComplianceError,
    ComplianceProxy,
    ConsentRequiredError,
)
from .redact import REDACTED_PLACEHOLDER, redact_action, redact_payload
from .rules import load_rules, load_rules_from_dict
from .schemas import (
    ACTION_SCHEMA,
    RULES_SCHEMA,
    schema_path,
    validate_action_data,
    validate_rules_data,
)

__version__ = "0.5.0"

__all__ = [
    "ACTION_SCHEMA",
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
    "RULES_SCHEMA",
    "Rule",
    "Severity",
    "decision_result_to_dict",
    "evaluate",
    "filter_rules_by_severity",
    "load_config",
    "load_config_file",
    "load_rules",
    "load_rules_from_dict",
    "parse_severity",
    "redact_action",
    "redact_payload",
    "rule_to_dict",
    "schema_path",
    "validate_action_data",
    "validate_rules_data",
]
