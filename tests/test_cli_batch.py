"""Tests for the cf check-batch subcommand."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from compliance_firewall.cli import main


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
            {
                "id": "CCPA-OPTEVENT",
                "jurisdiction": "US-CA",
                "description": "Marketing email needs consent",
                "match": {
                    "data_categories": ["email"],
                    "purposes": ["marketing"],
                },
                "decision": "require_consent",
                "severity": "high",
                "citation": "CCPA §1798.120",
                "priority": 50,
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

CONSENT_ACTION = {
    "action_type": "data_export",
    "destination_region": "EU",
    "contains_pii": True,
    "purpose": "marketing",
    "data_categories": ["email"],
    "payload": {"email": "m@example.com"},
}


class TestCheckBatch:
    """cf check-batch directory evaluation and exit codes."""

    def test_all_allow_returns_0(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        _write_action(actions_dir / "a.json", ALLOW_ACTION)
        _write_action(actions_dir / "b.json", ALLOW_ACTION)

        code = main(["check-batch", str(actions_dir), "--rules", str(rules_file)])
        captured = capsys.readouterr()
        assert code == 0
        assert "Batch summary" in captured.out
        assert "allow: 2" in captured.out

    def test_mixed_with_block_returns_1(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        _write_action(actions_dir / "clean.json", ALLOW_ACTION)
        _write_action(actions_dir / "blocked.json", BLOCK_ACTION)
        _write_action(actions_dir / "phone.json", REDACT_ACTION)
        _write_action(actions_dir / "marketing.json", CONSENT_ACTION)

        code = main(["check-batch", str(actions_dir), "--rules", str(rules_file)])
        captured = capsys.readouterr()
        assert code == 1
        assert "block: 1" in captured.out
        assert "require_consent: 1" in captured.out
        assert "redact: 1" in captured.out
        assert "allow: 1" in captured.out

    def test_redact_only_returns_3(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        _write_action(actions_dir / "phone.json", REDACT_ACTION)
        _write_action(actions_dir / "clean.json", ALLOW_ACTION)

        code = main(["check-batch", str(actions_dir), "--rules", str(rules_file)])
        captured = capsys.readouterr()
        assert code == 3
        assert "redact: 1" in captured.out
        assert "allow: 1" in captured.out

    def test_consent_only_returns_1(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        _write_action(actions_dir / "marketing.json", CONSENT_ACTION)

        code = main(["check-batch", str(actions_dir), "--rules", str(rules_file)])
        captured = capsys.readouterr()
        assert code == 1
        assert "require_consent: 1" in captured.out

    def test_parse_error_returns_2_and_continues(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        _write_action(actions_dir / "clean.json", ALLOW_ACTION)
        _write_action(actions_dir / "blocked.json", BLOCK_ACTION)
        (actions_dir / "bad.json").write_text("{not valid json", encoding="utf-8")

        code = main(["check-batch", str(actions_dir), "--rules", str(rules_file)])
        captured = capsys.readouterr()
        assert code == 2
        # Batch continues past the parse failure
        assert "clean.json" in captured.out
        assert "blocked.json" in captured.out
        assert "bad.json" in captured.out
        assert "failed to parse" in captured.out
        assert "errors: 1" in captured.out
        assert "allow: 1" in captured.out
        assert "block: 1" in captured.out

    def test_invalid_action_schema_returns_2(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        (actions_dir / "broken.json").write_text(
            json.dumps({"foo": "bar"}), encoding="utf-8"
        )

        code = main(["check-batch", str(actions_dir), "--rules", str(rules_file)])
        assert code == 2

    def test_missing_directory_exits_2(self, rules_file: Path, tmp_path: Path, capsys):
        code = main(
            ["check-batch", str(tmp_path / "nope"), "--rules", str(rules_file)]
        )
        captured = capsys.readouterr()
        assert code == 2
        assert "not found" in captured.err.lower()

    def test_empty_directory_exits_2(self, rules_file: Path, tmp_path: Path, capsys):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        code = main(["check-batch", str(actions_dir), "--rules", str(rules_file)])
        captured = capsys.readouterr()
        assert code == 2
        assert "no *.json" in captured.err.lower()

    def test_file_instead_of_directory_exits_2(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        file_path = tmp_path / "not_a_dir.json"
        file_path.write_text("{}", encoding="utf-8")
        code = main(["check-batch", str(file_path), "--rules", str(rules_file)])
        captured = capsys.readouterr()
        assert code == 2
        assert "not a directory" in captured.err.lower()

    def test_missing_rules_exits_2(self, tmp_path: Path, capsys):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        _write_action(actions_dir / "clean.json", ALLOW_ACTION)
        code = main(["check-batch", str(actions_dir), "--rules", "missing.yaml"])
        captured = capsys.readouterr()
        assert code == 2
        assert "not found" in captured.err.lower()

    def test_files_processed_in_sorted_order(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        _write_action(actions_dir / "c_last.json", ALLOW_ACTION)
        _write_action(actions_dir / "a_first.json", ALLOW_ACTION)
        _write_action(actions_dir / "b_mid.json", ALLOW_ACTION)

        main(["check-batch", str(actions_dir), "--rules", str(rules_file)])
        captured = capsys.readouterr()
        out = captured.out
        assert (
            out.index("--- a_first.json ---")
            < out.index("--- b_mid.json ---")
            < out.index("--- c_last.json ---")
        )

    def test_ignores_non_json_files(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        _write_action(actions_dir / "clean.json", ALLOW_ACTION)
        (actions_dir / "notes.txt").write_text("ignore me", encoding="utf-8")
        (actions_dir / "rules.yaml").write_text("rules: []\n", encoding="utf-8")

        code = main(["check-batch", str(actions_dir), "--rules", str(rules_file)])
        captured = capsys.readouterr()
        assert code == 0
        assert "Total files: 1" in captured.out

    def test_verbose_shows_explanations(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        _write_action(actions_dir / "blocked.json", BLOCK_ACTION)

        code = main(
            [
                "check-batch",
                str(actions_dir),
                "--rules",
                str(rules_file),
                "--verbose",
            ]
        )
        captured = capsys.readouterr()
        assert code == 1
        assert "Explanation:" in captured.out
        assert "Deciding rule: GDPR-ART44" in captured.out

    def test_config_supplies_rules_path(
        self, rules_file: Path, tmp_path: Path, capsys, monkeypatch
    ):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        _write_action(actions_dir / "blocked.json", BLOCK_ACTION)
        (tmp_path / "cf.toml").write_text(
            f'rules_path = "{rules_file.as_posix()}"\n', encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)

        code = main(["check-batch", "actions"])
        assert code == 1

    def test_severity_threshold_applies(
        self, rules_file: Path, tmp_path: Path, capsys
    ):
        actions_dir = tmp_path / "actions"
        actions_dir.mkdir()
        # Would be redacted by the medium phone rule; high threshold drops it
        _write_action(actions_dir / "phone.json", REDACT_ACTION)

        code = main(
            [
                "check-batch",
                str(actions_dir),
                "--rules",
                str(rules_file),
                "--severity-threshold",
                "high",
            ]
        )
        captured = capsys.readouterr()
        assert code == 0
        assert "allow: 1" in captured.out
        assert "redact: 0" in captured.out
