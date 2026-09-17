"""Tests for stable --format json CLI output."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from compliance_firewall.cli import SCHEMA_VERSION, main


@pytest.fixture
def rules_file(tmp_path: Path) -> Path:
    data = {
        "rules": [
            {
                "id": "GDPR-ART44",
                "jurisdiction": "EU",
                "description": "No PII to US",
                "match": {"contains_pii": True, "destination_regions": ["US"]},
                "decision": "block",
                "severity": "critical",
                "citation": "GDPR Art. 44",
                "remediation": "Use EU processor",
                "priority": 100,
            },
            {
                "id": "BASIC-REDACT-PHONE",
                "jurisdiction": "GLOBAL",
                "description": "Redact phone from tool calls",
                "match": {
                    "action_types": ["tool_call"],
                    "data_categories": ["phone"],
                },
                "decision": "redact",
                "severity": "medium",
                "citation": "POL-003",
                "priority": 10,
            },
        ]
    }
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _write_action(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


BLOCK_ACTION = {
    "action_type": "data_export",
    "destination_region": "US",
    "contains_pii": True,
    "purpose": "analytics",
    "data_categories": ["email"],
    "payload": {"email": "user@example.com"},
}

ALLOW_ACTION = {
    "action_type": "http_request",
    "destination_region": "EU",
    "contains_pii": False,
    "purpose": "api_call",
    "data_categories": [],
    "payload": {"url": "https://example.eu"},
}

REDACT_ACTION = {
    "action_type": "tool_call",
    "destination_region": "EU",
    "contains_pii": True,
    "purpose": "support",
    "data_categories": ["phone"],
    "payload": {"tool": "crm", "phone": "+1-555-0100"},
}


class TestCheckJsonFormat:
    def test_blocked_emits_stable_envelope(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        action_path = _write_action(tmp_path / "action.json", BLOCK_ACTION)
        code = main(
            [
                "check",
                str(action_path),
                "--rules",
                str(rules_file),
                "--format",
                "json",
            ]
        )
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert code == 1
        assert payload["schema_version"] == SCHEMA_VERSION
        assert payload["command"] == "check"
        assert payload["exit_code"] == 1
        assert payload["decision"] == "block"
        assert payload["action_file"] == str(action_path)
        assert payload["action"]["action_type"] == "data_export"
        result = payload["result"]
        assert result["decision"] == "block"
        assert result["deciding_rule"] == "GDPR-ART44"
        assert result["overridden_rules"] == []
        assert result["matched_rules"][0]["id"] == "GDPR-ART44"
        assert result["matched_rules"][0]["severity"] == "critical"
        assert result["redacted_payload"] is None
        assert any("EU processor" in hint for hint in result["remediation_hints"])

    def test_allow_emits_json(self, rules_file: Path, tmp_path: Path, capsys):
        action_path = _write_action(tmp_path / "action.json", ALLOW_ACTION)
        code = main(
            [
                "check",
                str(action_path),
                "--rules",
                str(rules_file),
                "--format",
                "json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 0
        assert payload["decision"] == "allow"
        assert payload["result"]["deciding_rule"] is None
        assert payload["result"]["matched_rules"] == []

    def test_redact_includes_payload(self, rules_file: Path, tmp_path: Path, capsys):
        action_path = _write_action(tmp_path / "action.json", REDACT_ACTION)
        code = main(
            [
                "check",
                str(action_path),
                "--rules",
                str(rules_file),
                "--format",
                "json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 3
        assert payload["decision"] == "redact"
        redacted = payload["result"]["redacted_payload"]
        assert redacted is not None
        assert redacted["phone"] == "[REDACTED]"

    def test_default_format_is_text(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        action_path = _write_action(tmp_path / "action.json", BLOCK_ACTION)
        code = main(["check", str(action_path), "--rules", str(rules_file)])
        captured = capsys.readouterr()
        assert code == 1
        assert "BLOCK" in captured.out
        # Not JSON
        with pytest.raises(json.JSONDecodeError):
            json.loads(captured.out)

    def test_missing_action_json_error(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        code = main(
            [
                "check",
                str(tmp_path / "missing.json"),
                "--rules",
                str(rules_file),
                "--format",
                "json",
            ]
        )
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert code == 2
        assert payload["exit_code"] == 2
        assert "not found" in payload["error"].lower()

    def test_parse_error_json(self, rules_file: Path, tmp_path: Path, capsys):
        bad = tmp_path / "bad.json"
        bad.write_text("{nope", encoding="utf-8")
        code = main(
            ["check", str(bad), "--rules", str(rules_file), "--format", "json"]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 2
        assert "failed to parse" in payload["error"]

    def test_missing_rules_json_error(self, tmp_path: Path, capsys):
        action_path = _write_action(tmp_path / "action.json", ALLOW_ACTION)
        code = main(
            [
                "check",
                str(action_path),
                "--rules",
                "missing.yaml",
                "--format",
                "json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 2
        assert "rules file not found" in payload["error"]


class TestCheckBatchJsonFormat:
    def test_mixed_batch_json(self, rules_file: Path, tmp_path: Path, capsys):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        _write_action(actions_dir / "clean.json", ALLOW_ACTION)
        _write_action(actions_dir / "blocked.json", BLOCK_ACTION)
        _write_action(actions_dir / "phone.json", REDACT_ACTION)

        code = main(
            [
                "check-batch",
                str(actions_dir),
                "--rules",
                str(rules_file),
                "--format",
                "json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 1
        assert payload["schema_version"] == SCHEMA_VERSION
        assert payload["command"] == "check-batch"
        assert payload["exit_code"] == 1
        summary = payload["summary"]
        assert summary["total"] == 3
        assert summary["allow"] == 1
        assert summary["block"] == 1
        assert summary["redact"] == 1
        assert summary["require_consent"] == 0
        assert summary["errors"] == 0
        assert len(payload["results"]) == 3
        by_file = {r["action_file"]: r for r in payload["results"]}
        assert by_file["blocked.json"]["decision"] == "block"
        assert by_file["blocked.json"]["exit_code"] == 1
        assert by_file["clean.json"]["decision"] == "allow"
        assert by_file["clean.json"]["exit_code"] == 0
        assert by_file["phone.json"]["decision"] == "redact"
        assert by_file["phone.json"]["exit_code"] == 3
        assert by_file["blocked.json"]["result"]["deciding_rule"] == "GDPR-ART44"

    def test_batch_parse_error_included(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        _write_action(actions_dir / "clean.json", ALLOW_ACTION)
        (actions_dir / "bad.json").write_text("{", encoding="utf-8")

        code = main(
            [
                "check-batch",
                str(actions_dir),
                "--rules",
                str(rules_file),
                "--format",
                "json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 2
        assert payload["summary"]["errors"] == 1
        assert payload["summary"]["allow"] == 1
        by_file = {r["action_file"]: r for r in payload["results"]}
        assert "error" in by_file["bad.json"]
        assert by_file["bad.json"]["exit_code"] == 2
        assert by_file["clean.json"]["decision"] == "allow"

    def test_batch_missing_directory_json(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        code = main(
            [
                "check-batch",
                str(tmp_path / "nope"),
                "--rules",
                str(rules_file),
                "--format",
                "json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 2
        assert "not found" in payload["error"].lower()

    def test_batch_empty_directory_json(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        code = main(
            [
                "check-batch",
                str(actions_dir),
                "--rules",
                str(rules_file),
                "--format",
                "json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 2
        assert "no *.json" in payload["error"].lower()

    def test_batch_all_allow_json(self, rules_file: Path, tmp_path: Path, capsys):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        _write_action(actions_dir / "clean.json", ALLOW_ACTION)
        code = main(
            [
                "check-batch",
                str(actions_dir),
                "--rules",
                str(rules_file),
                "--format",
                "json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 0
        assert payload["summary"]["allow"] == 1
        assert payload["summary"]["errors"] == 0
