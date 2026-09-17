"""Tests for rule loading from YAML/JSON."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from compliance_firewall.models import Decision, Severity
from compliance_firewall.rules import load_rules, load_rules_from_dict


class TestLoadFromDict:
    """Load rules from a Python dict."""

    def test_basic_rule(self):
        data = {
            "rules": [
                {
                    "id": "R1",
                    "jurisdiction": "EU",
                    "description": "Test",
                    "match": {"contains_pii": True},
                    "decision": "block",
                    "severity": "critical",
                    "citation": "GDPR Art. 44",
                    "remediation": "Do X",
                    "priority": 10,
                }
            ]
        }
        rules = load_rules_from_dict(data)
        assert len(rules) == 1
        assert rules[0].id == "R1"
        assert rules[0].decision == Decision.BLOCK
        assert rules[0].severity == Severity.CRITICAL
        assert rules[0].priority == 10
        assert rules[0].match.contains_pii is True

    def test_sorted_by_priority_desc(self):
        data = {
            "rules": [
                {"id": "LOW", "jurisdiction": "EU", "description": "",
                 "match": {}, "decision": "allow", "severity": "low",
                 "citation": "", "priority": 1},
                {"id": "HIGH", "jurisdiction": "EU", "description": "",
                 "match": {}, "decision": "block", "severity": "critical",
                 "citation": "", "priority": 100},
                {"id": "MID", "jurisdiction": "EU", "description": "",
                 "match": {}, "decision": "redact", "severity": "medium",
                 "citation": "", "priority": 50},
            ]
        }
        rules = load_rules_from_dict(data)
        assert [r.id for r in rules] == ["HIGH", "MID", "LOW"]

    def test_match_with_lists(self):
        data = {
            "rules": [
                {
                    "id": "R1",
                    "jurisdiction": "EU",
                    "description": "",
                    "match": {
                        "action_types": ["http_request", "db_query"],
                        "destination_regions": ["US", "CN"],
                        "data_categories": ["email", "phone"],
                        "purposes": ["marketing"],
                    },
                    "decision": "block",
                    "severity": "high",
                    "citation": "",
                }
            ]
        }
        rules = load_rules_from_dict(data)
        assert rules[0].match.action_types == ("http_request", "db_query")
        assert rules[0].match.destination_regions == ("US", "CN")
        assert rules[0].match.data_categories == ("email", "phone")
        assert rules[0].match.purposes == ("marketing",)

    def test_empty_rules(self):
        rules = load_rules_from_dict({"rules": []})
        assert rules == []


class TestLoadFromFile:
    """Load rules from YAML or JSON files."""

    def test_load_json(self, tmp_path: Path):
        data = {
            "rules": [
                {
                    "id": "J1",
                    "jurisdiction": "EU",
                    "description": "JSON rule",
                    "match": {"contains_pii": True},
                    "decision": "block",
                    "severity": "critical",
                    "citation": "GDPR",
                }
            ]
        }
        path = tmp_path / "rules.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        rules = load_rules(path)
        assert len(rules) == 1
        assert rules[0].id == "J1"

    def test_load_yaml(self, tmp_path: Path):
        yaml_text = """
rules:
  - id: Y1
    jurisdiction: EU
    description: "YAML rule"
    match:
      contains_pii: true
      destination_regions:
        - US
        - CN
    decision: block
    severity: critical
    citation: "GDPR Art. 44"
    remediation: "Use EU processor"
    priority: 100
"""
        path = tmp_path / "rules.yaml"
        path.write_text(yaml_text, encoding="utf-8")
        rules = load_rules(path)
        assert len(rules) == 1
        assert rules[0].id == "Y1"
        assert rules[0].decision == Decision.BLOCK
        assert rules[0].match.contains_pii is True
        assert rules[0].match.destination_regions == ("US", "CN")

    def test_load_examples_rules_yaml(self):
        examples_path = Path(__file__).parent.parent / "examples" / "rules.yaml"
        if not examples_path.exists():
            pytest.skip("examples/rules.yaml not found")
        rules = load_rules(examples_path)
        assert len(rules) > 0
        # Should be sorted by priority desc
        priorities = [r.priority for r in rules]
        assert priorities == sorted(priorities, reverse=True)


class TestMatchCondition:
    """MatchCondition.matches logic."""

    def test_empty_condition_matches_everything(self):
        from compliance_firewall.models import Action, ActionType, MatchCondition

        cond = MatchCondition()
        action = Action(action_type=ActionType.HTTP_REQUEST)
        assert cond.matches(action)

    def test_contains_pii_mismatch(self):
        from compliance_firewall.models import Action, ActionType, MatchCondition

        cond = MatchCondition(contains_pii=True)
        action = Action(action_type=ActionType.HTTP_REQUEST, contains_pii=False)
        assert not cond.matches(action)

    def test_data_categories_any_match(self):
        from compliance_firewall.models import Action, ActionType, MatchCondition

        cond = MatchCondition(data_categories=("email", "phone"))
        action = Action(
            action_type=ActionType.TOOL_CALL,
            data_categories=["phone"],
        )
        assert cond.matches(action)

    def test_data_categories_no_overlap(self):
        from compliance_firewall.models import Action, ActionType, MatchCondition

        cond = MatchCondition(data_categories=("email",))
        action = Action(
            action_type=ActionType.TOOL_CALL,
            data_categories=["health"],
        )
        assert not cond.matches(action)
