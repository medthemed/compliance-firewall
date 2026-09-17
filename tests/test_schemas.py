"""Tests for JSON Schema documents and structural validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from compliance_firewall import load_rules, load_rules_from_dict
from compliance_firewall.schemas import (
    ACTION_SCHEMA,
    RULES_SCHEMA,
    SCHEMA_FILES_DIR,
    schema_path,
    validate_action_data,
    validate_rules_data,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples"


class TestSchemaLoading:
    def test_action_schema_is_draft07(self):
        assert ACTION_SCHEMA["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert ACTION_SCHEMA["title"] == "compliance-firewall Action"
        assert "action_type" in ACTION_SCHEMA["required"]

    def test_rules_schema_is_draft07(self):
        assert RULES_SCHEMA["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert RULES_SCHEMA["title"] == "compliance-firewall Rule Database"
        assert "rules" in RULES_SCHEMA["required"]

    def test_schema_path_action(self):
        path = schema_path("action")
        assert path.name == "action.schema.json"
        assert path.is_file()

    def test_schema_path_rules_with_suffix(self):
        path = schema_path("rules.schema.json")
        assert path.name == "rules.schema.json"
        assert path.is_file()

    def test_schema_path_unknown_raises(self):
        with pytest.raises(FileNotFoundError):
            schema_path("nope")

    def test_schema_files_dir_contains_both(self):
        names = {p.name for p in SCHEMA_FILES_DIR.glob("*.json")}
        assert names == {"action.schema.json", "rules.schema.json"}

    def test_repo_root_schemas_match_package(self):
        root_schemas = REPO_ROOT / "schemas"
        assert root_schemas.is_dir()
        for name in ("action.schema.json", "rules.schema.json"):
            packaged = json.loads((SCHEMA_FILES_DIR / name).read_text(encoding="utf-8"))
            published = json.loads((root_schemas / name).read_text(encoding="utf-8"))
            assert packaged == published


class TestValidateActionData:
    def test_valid_minimal(self):
        assert validate_action_data({"action_type": "http_request"}) == []

    def test_valid_full(self):
        data = {
            "action_type": "data_export",
            "destination_region": "US",
            "source_region": "CN",
            "contains_pii": True,
            "purpose": "analytics",
            "data_categories": ["email", "phone"],
            "payload": {"email": "a@example.com"},
            "actor": "agent-1",
        }
        assert validate_action_data(data) == []

    def test_missing_action_type(self):
        errors = validate_action_data({"destination_region": "US"})
        assert any("action_type" in e for e in errors)

    def test_invalid_action_type(self):
        errors = validate_action_data({"action_type": "teleport"})
        assert any("action_type" in e for e in errors)

    def test_wrong_types(self):
        data = {
            "action_type": "http_request",
            "contains_pii": "yes",
            "data_categories": "email",
            "payload": [],
        }
        errors = validate_action_data(data)
        assert any("contains_pii" in e for e in errors)
        assert any("data_categories" in e for e in errors)
        assert any("payload" in e for e in errors)

    def test_not_an_object(self):
        assert validate_action_data(["nope"]) != []

    def test_all_example_actions_validate(self):
        actions_dir = EXAMPLES / "actions"
        files = sorted(actions_dir.glob("*.json"))
        assert files, "expected example action files"
        for path in files:
            data = json.loads(path.read_text(encoding="utf-8"))
            assert validate_action_data(data) == [], f"{path.name} failed validation"


class TestValidateRulesData:
    def test_valid_rules(self):
        data = {
            "rules": [
                {
                    "id": "R1",
                    "jurisdiction": "EU",
                    "description": "d",
                    "match": {
                        "contains_pii": True,
                        "destination_regions": ["US"],
                    },
                    "decision": "block",
                    "severity": "critical",
                    "citation": "GDPR",
                    "remediation": "fix it",
                    "priority": 10,
                }
            ]
        }
        assert validate_rules_data(data) == []

    def test_missing_rules_key(self):
        errors = validate_rules_data({})
        assert any("rules" in e for e in errors)

    def test_missing_required_rule_fields(self):
        errors = validate_rules_data({"rules": [{"description": "incomplete"}]})
        assert any("id" in e for e in errors)
        assert any("decision" in e for e in errors)

    def test_invalid_enums(self):
        data = {
            "rules": [
                {
                    "id": "R1",
                    "jurisdiction": "EU",
                    "decision": "destroy",
                    "severity": "apocalyptic",
                }
            ]
        }
        errors = validate_rules_data(data)
        assert any("decision" in e for e in errors)
        assert any("severity" in e for e in errors)

    def test_invalid_match_types(self):
        data = {
            "rules": [
                {
                    "id": "R1",
                    "jurisdiction": "EU",
                    "decision": "block",
                    "severity": "high",
                    "match": {"data_categories": "email", "contains_pii": "yes"},
                }
            ]
        }
        errors = validate_rules_data(data)
        assert any("data_categories" in e for e in errors)
        assert any("contains_pii" in e for e in errors)

    def test_priority_must_be_integer(self):
        data = {
            "rules": [
                {
                    "id": "R1",
                    "jurisdiction": "EU",
                    "decision": "block",
                    "severity": "high",
                    "priority": "high",
                }
            ]
        }
        errors = validate_rules_data(data)
        assert any("priority" in e for e in errors)

    def test_example_rules_yaml_validates(self):
        rules = load_rules(EXAMPLES / "rules.yaml")
        # Reconstruct a schema-valid dict from loaded rules
        data = {
            "rules": [
                {
                    "id": r.id,
                    "jurisdiction": r.jurisdiction,
                    "description": r.description,
                    "decision": r.decision.value,
                    "severity": r.severity.value,
                    "citation": r.citation,
                    "remediation": r.remediation,
                    "priority": r.priority,
                }
                for r in rules
            ]
        }
        assert validate_rules_data(data) == []

    def test_raw_example_rules_dict_validates(self):
        # Parse the YAML example via the loader's dict path
        from compliance_firewall.rules import _parse_yaml

        text = (EXAMPLES / "rules.yaml").read_text(encoding="utf-8")
        data = _parse_yaml(text)
        assert validate_rules_data(data) == []

    def test_empty_rules_list_is_valid(self):
        assert validate_rules_data({"rules": []}) == []

    def test_rules_from_dict_roundtrip(self):
        data = {
            "rules": [
                {
                    "id": "R1",
                    "jurisdiction": "GLOBAL",
                    "decision": "allow",
                    "severity": "low",
                }
            ]
        }
        rules = load_rules_from_dict(data)
        assert len(rules) == 1
        assert validate_rules_data(data) == []
