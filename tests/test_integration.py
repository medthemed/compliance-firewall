"""End-to-end integration tests: rules file → load_rules → proxy/CLI → outcome."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from compliance_firewall import (
    Action,
    ActionBlockedError,
    ComplianceError,
    ComplianceProxy,
    ConsentRequiredError,
    load_rules,
)
from compliance_firewall.cli import main


RULES_DATA = {
    "rules": [
        {
            "id": "GDPR-ART44",
            "jurisdiction": "EU",
            "description": "No PII transfer to non-adequate third countries",
            "match": {
                "contains_pii": True,
                "destination_regions": ["US", "CN", "RU", "IN"],
            },
            "decision": "block",
            "severity": "critical",
            "citation": "GDPR Art. 44",
            "remediation": "Use an EU-based processor.",
            "priority": 100,
        },
        {
            "id": "CCPA-OPTEVENT",
            "jurisdiction": "US-CA",
            "description": "Email cannot be used for marketing without opt-in",
            "match": {
                "data_categories": ["email"],
                "purposes": ["marketing"],
            },
            "decision": "require_consent",
            "severity": "high",
            "citation": "CCPA §1798.120",
            "remediation": "Record explicit opt-in.",
            "priority": 50,
        },
        {
            "id": "BASIC-REDACT",
            "jurisdiction": "GLOBAL",
            "description": "Redact phone numbers from tool payloads",
            "match": {
                "action_types": ["tool_call"],
                "data_categories": ["phone"],
            },
            "decision": "redact",
            "severity": "medium",
            "citation": "Internal policy POL-003",
            "remediation": "Strip phone fields.",
            "priority": 10,
        },
        {
            "id": "ALLOW-STATUS",
            "jurisdiction": "GLOBAL",
            "description": "Status checks to EU are always fine",
            "match": {
                "action_types": ["http_request"],
                "destination_regions": ["EU"],
                "contains_pii": False,
            },
            "decision": "allow",
            "severity": "low",
            "citation": "Internal policy POL-001",
            "priority": 1,
        },
    ]
}


@pytest.fixture
def rules_file(tmp_path: Path) -> Path:
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(RULES_DATA), encoding="utf-8")
    return path


@pytest.fixture
def rules_file_yaml(tmp_path: Path) -> Path:
    # Reuse the same data via the JSON-capable YAML path (json is valid YAML subset
    # for our loader when the file starts with '{'). Also write a real .json sibling
    # so both suffixes are exercised.
    path = tmp_path / "rules.yaml"
    # The minimal YAML parser expects a 'rules:' document; write JSON to a .yaml
    # only if we force the JSON branch — instead emit a tiny hand-rolled YAML file.
    path.write_text(
        """
rules:
  - id: GDPR-ART44
    jurisdiction: EU
    description: "No PII to US"
    match:
      contains_pii: true
      destination_regions:
        - US
    decision: block
    severity: critical
    citation: "GDPR Art. 44"
    remediation: "Use an EU processor"
    priority: 100
  - id: BASIC-REDACT
    jurisdiction: GLOBAL
    description: "Redact phone"
    match:
      action_types:
        - tool_call
      data_categories:
        - phone
    decision: redact
    severity: medium
    citation: "POL-003"
    remediation: "Strip phone"
    priority: 10
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def recording_executor():
    calls: list[Action] = []

    def executor(action: Action) -> dict:
        calls.append(action)
        return {"status": "ok", "payload": action.payload}

    return executor, calls


class TestProxyEndToEnd:
    """Full path: load_rules(file) → ComplianceProxy → outcome."""

    def test_allow_end_to_end(self, rules_file, recording_executor):
        executor, calls = recording_executor
        rules = load_rules(rules_file)
        proxy = ComplianceProxy(rules=rules, executor=executor)

        action = Action.from_dict(
            {
                "action_type": "http_request",
                "destination_region": "EU",
                "contains_pii": False,
                "purpose": "status",
                "payload": {"url": "https://api.example.eu/status"},
            }
        )
        result = proxy.execute(action)

        assert result == {"status": "ok", "payload": {"url": "https://api.example.eu/status"}}
        assert len(calls) == 1
        assert calls[0] is action
        assert proxy.get_audit_log()[0][1].decision.value == "allow"

    def test_block_end_to_end(self, rules_file, recording_executor):
        executor, calls = recording_executor
        rules = load_rules(rules_file)
        proxy = ComplianceProxy(rules=rules, executor=executor)

        action = Action.from_dict(
            {
                "action_type": "data_export",
                "destination_region": "US",
                "contains_pii": True,
                "purpose": "analytics",
                "data_categories": ["email", "name"],
                "payload": {"email": "user@example.com", "name": "Alice"},
            }
        )

        with pytest.raises(ActionBlockedError) as exc_info:
            proxy.execute(action)

        assert len(calls) == 0
        assert exc_info.value.result.is_blocked
        assert exc_info.value.result.deciding_rule.id == "GDPR-ART44"
        assert isinstance(exc_info.value, ComplianceError)

    def test_redact_end_to_end(self, rules_file, recording_executor):
        executor, calls = recording_executor
        rules = load_rules(rules_file)
        proxy = ComplianceProxy(rules=rules, executor=executor)

        action = Action.from_dict(
            {
                "action_type": "tool_call",
                "destination_region": "EU",
                "contains_pii": True,
                "purpose": "support",
                "data_categories": ["phone"],
                "payload": {"tool": "crm_lookup", "phone": "+1-555-0100", "ticket": "T-9"},
            }
        )
        result = proxy.execute(action)

        assert result["status"] == "ok"
        assert len(calls) == 1
        assert calls[0].payload["phone"] == "[REDACTED]"
        assert calls[0].payload["tool"] == "crm_lookup"
        assert calls[0].contains_pii is False

    def test_require_consent_end_to_end(self, rules_file, recording_executor):
        executor, calls = recording_executor
        rules = load_rules(rules_file)
        proxy = ComplianceProxy(rules=rules, executor=executor)

        action = Action.from_dict(
            {
                "action_type": "data_export",
                "destination_region": "EU",
                "contains_pii": True,
                "purpose": "marketing",
                "data_categories": ["email"],
                "payload": {"email": "user@example.com"},
            }
        )

        with pytest.raises(ConsentRequiredError) as exc_info:
            proxy.execute(action)

        assert len(calls) == 0
        assert exc_info.value.result.requires_consent
        assert isinstance(exc_info.value, ComplianceError)

    def test_yaml_rules_file_loads(self, rules_file_yaml, recording_executor):
        executor, calls = recording_executor
        rules = load_rules(rules_file_yaml)
        assert {r.id for r in rules} == {"GDPR-ART44", "BASIC-REDACT"}

        proxy = ComplianceProxy(rules=rules, executor=executor)
        action = Action.from_dict(
            {
                "action_type": "data_export",
                "destination_region": "US",
                "contains_pii": True,
                "data_categories": ["email"],
                "payload": {"email": "a@example.com"},
            }
        )
        with pytest.raises(ActionBlockedError):
            proxy.execute(action)
        assert len(calls) == 0

    def test_audit_log_captures_all_decisions(self, rules_file, recording_executor):
        executor, calls = recording_executor
        rules = load_rules(rules_file)
        proxy = ComplianceProxy(rules=rules, executor=executor)

        actions = [
            Action.from_dict(
                {
                    "action_type": "http_request",
                    "destination_region": "EU",
                    "contains_pii": False,
                    "payload": {"url": "https://ok.example.eu"},
                }
            ),
            Action.from_dict(
                {
                    "action_type": "data_export",
                    "destination_region": "US",
                    "contains_pii": True,
                    "data_categories": ["email"],
                    "payload": {"email": "x@example.com"},
                }
            ),
            Action.from_dict(
                {
                    "action_type": "tool_call",
                    "contains_pii": True,
                    "data_categories": ["phone"],
                    "payload": {"phone": "+1"},
                }
            ),
        ]

        outcomes = []
        for action in actions:
            try:
                proxy.execute(action)
            except ComplianceError as exc:
                outcomes.append(exc.result.decision.value)

        log = proxy.get_audit_log()
        assert len(log) == 3
        assert [r.decision.value for _, r in log] == ["allow", "block", "redact"]
        assert outcomes == ["block"]
        # Executor ran for allow + redact only
        assert len(calls) == 2
        # Redacted action had phone scrubbed
        assert calls[1].payload["phone"] == "[REDACTED]"


class TestCliEndToEnd:
    """cf check against real temp files."""

    def test_cli_block_exit_code_and_output(self, rules_file, tmp_path, capsys):
        action_path = tmp_path / "block.json"
        action_path.write_text(
            json.dumps(
                {
                    "action_type": "data_export",
                    "destination_region": "US",
                    "contains_pii": True,
                    "data_categories": ["email"],
                    "payload": {"email": "user@example.com"},
                }
            ),
            encoding="utf-8",
        )
        code = main(["check", str(action_path), "--rules", str(rules_file)])
        out = capsys.readouterr().out
        assert code == 1
        assert "BLOCK" in out
        assert "GDPR-ART44" in out

    def test_cli_allow_exit_code(self, rules_file, tmp_path, capsys):
        action_path = tmp_path / "allow.json"
        action_path.write_text(
            json.dumps(
                {
                    "action_type": "http_request",
                    "destination_region": "EU",
                    "contains_pii": False,
                    "payload": {"url": "https://ok.example.eu"},
                }
            ),
            encoding="utf-8",
        )
        code = main(["check", str(action_path), "--rules", str(rules_file)])
        out = capsys.readouterr().out
        assert code == 0
        assert "ALLOW" in out

    def test_cli_redact_exit_code(self, rules_file, tmp_path, capsys):
        action_path = tmp_path / "redact.json"
        action_path.write_text(
            json.dumps(
                {
                    "action_type": "tool_call",
                    "contains_pii": True,
                    "data_categories": ["phone"],
                    "payload": {"phone": "+1-555", "tool": "lookup"},
                }
            ),
            encoding="utf-8",
        )
        code = main(["check", str(action_path), "--rules", str(rules_file)])
        out = capsys.readouterr().out
        assert code == 3
        assert "REDACT" in out.upper()
        assert "[REDACTED]" in out

    def test_cli_consent_exit_code(self, rules_file, tmp_path, capsys):
        action_path = tmp_path / "consent.json"
        action_path.write_text(
            json.dumps(
                {
                    "action_type": "data_export",
                    "contains_pii": True,
                    "data_categories": ["email"],
                    "purpose": "marketing",
                    "payload": {"email": "m@example.com"},
                }
            ),
            encoding="utf-8",
        )
        code = main(["check", str(action_path), "--rules", str(rules_file)])
        out = capsys.readouterr().out
        assert code == 1
        assert "CONSENT" in out.upper()

    def test_cli_verbose_shows_deciding_rule(self, rules_file, tmp_path, capsys):
        action_path = tmp_path / "block.json"
        action_path.write_text(
            json.dumps(
                {
                    "action_type": "data_export",
                    "destination_region": "US",
                    "contains_pii": True,
                    "data_categories": ["email"],
                    "purpose": "marketing",
                    "payload": {"email": "user@example.com"},
                }
            ),
            encoding="utf-8",
        )
        code = main(
            ["check", str(action_path), "--rules", str(rules_file), "--verbose"]
        )
        out = capsys.readouterr().out
        assert code == 1
        assert "Explanation:" in out
        assert "Deciding rule: GDPR-ART44" in out
        assert "Overridden rules:" in out
        assert "CCPA-OPTEVENT" in out
        # Deciding rule is starred in the matched list
        assert "* [critical] GDPR-ART44" in out
