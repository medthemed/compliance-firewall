"""Rule loading and management for compliance-firewall."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Decision, MatchCondition, Rule, Severity


def _parse_match(data: dict[str, Any]) -> MatchCondition:
    """Parse a match condition dict into a MatchCondition."""
    min_sev = data.get("min_severity")
    return MatchCondition(
        action_types=tuple(data["action_types"]) if "action_types" in data else None,
        destination_regions=(
            tuple(data["destination_regions"]) if "destination_regions" in data else None
        ),
        source_regions=(
            tuple(data["source_regions"]) if "source_regions" in data else None
        ),
        contains_pii=data.get("contains_pii"),
        purposes=tuple(data["purposes"]) if "purposes" in data else None,
        data_categories=(
            tuple(data["data_categories"]) if "data_categories" in data else None
        ),
        min_severity=Severity(min_sev) if min_sev else None,
    )


def _parse_rule(data: dict[str, Any]) -> Rule:
    """Parse a single rule dict into a Rule."""
    return Rule(
        id=data["id"],
        jurisdiction=data["jurisdiction"],
        description=data.get("description", ""),
        match=_parse_match(data.get("match", {})),
        decision=Decision(data["decision"]),
        severity=Severity(data["severity"]),
        citation=data.get("citation", ""),
        remediation=data.get("remediation", ""),
        priority=int(data.get("priority", 0)),
    )


def load_rules_from_dict(data: dict[str, Any]) -> list[Rule]:
    """Load rules from a dict with a 'rules' key.

    Args:
        data: Dict with a "rules" list of rule dicts.

    Returns:
        List of Rule objects sorted by priority (descending).
    """
    raw_rules = data.get("rules", [])
    rules = [_parse_rule(r) for r in raw_rules]
    rules.sort(key=lambda r: r.priority, reverse=True)
    return rules


def load_rules(path: str | Path) -> list[Rule]:
    """Load rules from a YAML or JSON file.

    YAML is loaded with a minimal parser (stdlib-only). JSON is loaded with json.

    Args:
        path: Path to a .yaml, .yml, or .json rules file.

    Returns:
        List of Rule objects sorted by priority (descending).
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")

    if path.suffix in (".yaml", ".yml"):
        data = _parse_yaml(text)
    elif path.suffix == ".json":
        data = json.loads(text)
    else:
        # Try JSON first, then YAML
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = _parse_yaml(text)

    return load_rules_from_dict(data)


def _parse_yaml(text: str) -> dict[str, Any]:
    """Minimal YAML parser for the rule file format used by this project.

    Supports: top-level 'rules:' list, nested dicts, strings, ints, bools,
    and lists of strings. Not a full YAML implementation — sufficient for
    the compliance-firewall rule schema.
    """
    try:
        import yaml  # type: ignore[import-untyped]

        return yaml.safe_load(text)
    except ImportError:
        pass

    # Fallback: attempt JSON (some YAML files are valid JSON)
    text_stripped = text.strip()
    if text_stripped.startswith("{"):
        return json.loads(text_stripped)

    # Minimal line-based parser for our rule format
    return _minimal_yaml(text)


def _minimal_yaml(text: str) -> dict[str, Any]:
    """Parse a constrained YAML subset used by compliance-firewall rules."""
    lines = text.splitlines()
    rules: list[dict[str, Any]] = []

    # Find rules: section
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line == "rules:" or line.startswith("rules:"):
            i += 1
            break
        i += 1

    # Parse rule items
    current_rule: dict[str, Any] | None = None
    current_match: dict[str, Any] | None = None

    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        indent = len(raw) - len(raw.lstrip())

        # New rule item at indent 2
        if stripped.startswith("- ") and indent == 2:
            # Flush previous rule
            if current_rule is not None:
                if current_match is not None:
                    current_rule["match"] = current_match
                rules.append(current_rule)

            current_rule = {}
            current_match = None

            rest = stripped[2:].strip()
            if ":" in rest:
                k, _, v = rest.partition(":")
                k = k.strip()
                v = v.strip()
                if k == "match":
                    current_match = {}
                elif v:
                    current_rule[k] = _yaml_scalar(v)
            i += 1
            continue

        if current_rule is None:
            i += 1
            continue

        # Key at indent 4 (rule-level fields)
        if indent == 4 and ":" in stripped and not stripped.startswith("- "):
            k, _, v = stripped.partition(":")
            k = k.strip()
            v = v.strip()

            if k == "match":
                current_match = {}
            elif v:
                current_rule[k] = _yaml_scalar(v)
            i += 1
            continue

        # Key at indent 6 (match-level fields)
        if indent == 6 and ":" in stripped and not stripped.startswith("- "):
            if current_match is not None:
                k, _, v = stripped.partition(":")
                k = k.strip()
                v = v.strip()
                if v:
                    current_match[k] = _yaml_scalar(v)
                else:
                    # List follows
                    current_match[k] = []
            i += 1
            continue

        # List item at indent 8 (values for match lists)
        if indent == 8 and stripped.startswith("- ") and current_match is not None:
            # Find which key this list belongs to (last key with empty list)
            val = stripped[2:].strip()
            for mk in reversed(list(current_match.keys())):
                if isinstance(current_match[mk], list) and not current_match[mk]:
                    current_match[mk].append(_yaml_scalar(val))
                    break
                if isinstance(current_match[mk], list):
                    current_match[mk].append(_yaml_scalar(val))
                    break
            i += 1
            continue

        i += 1

    # Flush last rule
    if current_rule is not None:
        if current_match is not None:
            current_rule["match"] = current_match
        rules.append(current_rule)

    return {"rules": rules}


def _yaml_scalar(value: str) -> Any:
    """Convert a YAML scalar string to a Python value."""
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    if value.lower() in ("true", "yes"):
        return True
    if value.lower() in ("false", "no"):
        return False
    if value.lower() in ("null", "~", ""):
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value
