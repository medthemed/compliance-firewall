"""JSON Schema documents and lightweight validation for action/rule files.

Schemas are draft-07 JSON Schema documents shipped as package data:

* ``schema_files/action.schema.json``
* ``schema_files/rules.schema.json``

This module exposes them as plain dicts for external validators and provides
a small stdlib-only structural validator so examples can be checked without
installing ``jsonschema``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

__all__ = [
    "ACTION_SCHEMA",
    "RULES_SCHEMA",
    "SCHEMA_FILES_DIR",
    "schema_path",
    "validate_action_data",
    "validate_rules_data",
]

SCHEMA_FILES_DIR = Path(__file__).resolve().parent / "schema_files"

_ACTION_ENUMS = {
    "action_type": frozenset(
        {"http_request", "db_query", "data_export", "tool_call"}
    ),
}

_ACTION_STRING_FIELDS = frozenset(
    {
        "destination_region",
        "source_region",
        "purpose",
        "actor",
    }
)

_ACTION_BOOL_FIELDS = frozenset({"contains_pii"})

_RULE_ENUMS = {
    "decision": frozenset({"allow", "block", "redact", "require_consent"}),
    "severity": frozenset({"low", "medium", "high", "critical"}),
    "min_severity": frozenset({"low", "medium", "high", "critical"}),
}

_RULE_STRING_FIELDS = frozenset(
    {"id", "jurisdiction", "description", "citation", "remediation"}
)

_MATCH_STRING_LIST_FIELDS = frozenset(
    {
        "action_types",
        "destination_regions",
        "source_regions",
        "purposes",
        "data_categories",
    }
)

_MATCH_KNOWN_FIELDS = _MATCH_STRING_LIST_FIELDS | {"contains_pii", "min_severity"}


def schema_path(name: str) -> Path:
    """Return the filesystem path of a shipped schema file.

    Args:
        name: ``action`` or ``rules`` (with or without ``.schema.json``).

    Returns:
        Path to the schema JSON file.

    Raises:
        FileNotFoundError: When the named schema does not exist.
    """
    filename = name if name.endswith(".json") else f"{name}.schema.json"
    path = SCHEMA_FILES_DIR / filename
    if not path.is_file():
        raise FileNotFoundError(f"Unknown schema: {name!r} (looked in {SCHEMA_FILES_DIR})")
    return path


def _load_schema(name: str) -> dict[str, Any]:
    return json.loads(schema_path(name).read_text(encoding="utf-8"))


ACTION_SCHEMA: dict[str, Any] = _load_schema("action")
RULES_SCHEMA: dict[str, Any] = _load_schema("rules")


def validate_action_data(data: Any) -> list[str]:
    """Structurally validate an action document against the action schema.

    This is a focused stdlib validator covering required fields, enums, and
    basic types — not a full JSON Schema implementation.

    Args:
        data: Parsed action document.

    Returns:
        A list of human-readable error strings; empty when valid.
    """
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["action must be a JSON object"]

    if "action_type" not in data:
        errors.append("missing required field: action_type")
    else:
        action_type = data["action_type"]
        if action_type not in _ACTION_ENUMS["action_type"]:
            allowed = ", ".join(sorted(_ACTION_ENUMS["action_type"]))
            errors.append(
                f"action_type must be one of: {allowed} (got {action_type!r})"
            )

    for field in _ACTION_STRING_FIELDS:
        if field in data and data[field] is not None and not isinstance(data[field], str):
            errors.append(f"{field} must be a string")

    for field in _ACTION_BOOL_FIELDS:
        if field in data and data[field] is not None and not isinstance(data[field], bool):
            errors.append(f"{field} must be a boolean")

    if "data_categories" in data and data["data_categories"] is not None:
        categories = data["data_categories"]
        if not isinstance(categories, list) or not all(
            isinstance(c, str) for c in categories
        ):
            errors.append("data_categories must be a list of strings")

    if "payload" in data and data["payload"] is not None:
        if not isinstance(data["payload"], dict):
            errors.append("payload must be an object")

    return errors


def validate_rules_data(data: Any) -> list[str]:
    """Structurally validate a rule-database document.

    Args:
        data: Parsed rules document (must contain a ``rules`` list).

    Returns:
        A list of human-readable error strings; empty when valid.
    """
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["rules document must be a JSON object"]

    if "rules" not in data:
        return ["missing required field: rules"]

    rules = data["rules"]
    if not isinstance(rules, list):
        return ["rules must be a list"]

    for index, rule in enumerate(rules):
        prefix = f"rules[{index}]"
        if not isinstance(rule, dict):
            errors.append(f"{prefix}: rule must be an object")
            continue

        for required in ("id", "jurisdiction", "decision", "severity"):
            if required not in rule:
                errors.append(f"{prefix}: missing required field: {required}")

        for field, allowed in _RULE_ENUMS.items():
            if field in rule and rule[field] is not None and rule[field] not in allowed:
                allowed_list = ", ".join(sorted(allowed))
                errors.append(
                    f"{prefix}.{field} must be one of: {allowed_list} "
                    f"(got {rule[field]!r})"
                )

        for field in _RULE_STRING_FIELDS:
            if field in rule and rule[field] is not None and not isinstance(rule[field], str):
                errors.append(f"{prefix}.{field} must be a string")

        if "priority" in rule and rule["priority"] is not None:
            if not isinstance(rule["priority"], int) or isinstance(rule["priority"], bool):
                errors.append(f"{prefix}.priority must be an integer")

        match = rule.get("match")
        if match is not None:
            if not isinstance(match, dict):
                errors.append(f"{prefix}.match must be an object")
            else:
                errors.extend(_validate_match(match, prefix))

    return errors


def _validate_match(match: dict[str, Any], prefix: str) -> list[str]:
    errors: list[str] = []
    for field, value in match.items():
        if field not in _MATCH_KNOWN_FIELDS:
            # Tolerate unknown match keys for forward compatibility.
            continue
        if field in _MATCH_STRING_LIST_FIELDS:
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                errors.append(f"{prefix}.match.{field} must be a list of strings")
        elif field == "contains_pii":
            if not isinstance(value, bool):
                errors.append(f"{prefix}.match.contains_pii must be a boolean")
        elif field == "min_severity":
            if value not in _RULE_ENUMS["min_severity"]:
                errors.append(
                    f"{prefix}.match.min_severity must be one of: "
                    f"{', '.join(sorted(_RULE_ENUMS['min_severity']))}"
                )
    return errors
