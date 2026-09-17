"""Tests for the CLI."""

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
            }
        ]
    }
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def block_action_file(tmp_path: Path) -> Path:
    data = {
        "action_type": "data_export",
        "destination_region": "US",
        "contains_pii": True,
        "purpose": "analytics",
        "data_categories": ["email"],
        "payload": {"email": "user@example.com"},
    }
    path = tmp_path / "action_block.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def allow_action_file(tmp_path: Path) -> Path:
    data = {
        "action_type": "http_request",
        "destination_region": "EU",
        "contains_pii": False,
        "purpose": "api_call",
        "data_categories": [],
        "payload": {"url": "https://example.eu"},
    }
    path = tmp_path / "action_allow.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class TestCliCheck:
    """cf check subcommand."""

    def test_check_blocked_returns_1(
        self, rules_file: Path, block_action_file: Path, capsys
    ):
        exit_code = main(["check", str(block_action_file), "--rules", str(rules_file)])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "BLOCK" in captured.out.upper()

    def test_check_allowed_returns_0(
        self, rules_file: Path, allow_action_file: Path, capsys
    ):
        exit_code = main(["check", str(allow_action_file), "--rules", str(rules_file)])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "ALLOW" in captured.out.upper()

    def test_check_missing_action_file(self, rules_file: Path, capsys):
        exit_code = main(["check", "nonexistent.json", "--rules", str(rules_file)])
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower()

    def test_check_missing_rules_file(self, block_action_file: Path, capsys):
        exit_code = main(["check", str(block_action_file), "--rules", "nonexistent.yaml"])
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower()


class TestCliDemo:
    """cf serve-demo subcommand."""

    def test_demo_runs_successfully(self, capsys):
        exit_code = main(["serve-demo"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "compliance-firewall demo" in captured.out
        assert "BLOCKED" in captured.out or "blocked" in captured.out.lower()
        assert "ALLOW" in captured.out or "Executor returned" in captured.out


class TestCliNoArgs:
    """cf with no args prints help."""

    def test_no_args_prints_help(self, capsys):
        exit_code = main([])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "check" in captured.out.lower() or "usage" in captured.out.lower()
