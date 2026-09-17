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

    def test_check_shows_source_region(self, tmp_path: Path, capsys):
        rules = {
            "rules": [
                {
                    "id": "PIPL-38",
                    "jurisdiction": "CN",
                    "description": "PII collected in China must not leave",
                    "match": {
                        "source_regions": ["CN"],
                        "destination_regions": ["US"],
                        "contains_pii": True,
                    },
                    "decision": "block",
                    "severity": "critical",
                    "citation": "PIPL Art. 38",
                    "priority": 90,
                }
            ]
        }
        rules_path = tmp_path / "rules.json"
        rules_path.write_text(json.dumps(rules), encoding="utf-8")

        action = {
            "action_type": "data_export",
            "destination_region": "US",
            "source_region": "CN",
            "contains_pii": True,
            "data_categories": ["email"],
            "payload": {"email": "a@example.cn"},
        }
        action_path = tmp_path / "action.json"
        action_path.write_text(json.dumps(action), encoding="utf-8")

        exit_code = main(["check", str(action_path), "--rules", str(rules_path)])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Source: CN" in captured.out
        assert "PIPL-38" in captured.out

    def test_check_eu_origin_not_matched_by_pipl(self, tmp_path: Path, capsys):
        rules = {
            "rules": [
                {
                    "id": "PIPL-38",
                    "jurisdiction": "CN",
                    "description": "PII collected in China must not leave",
                    "match": {
                        "source_regions": ["CN"],
                        "destination_regions": ["US"],
                        "contains_pii": True,
                    },
                    "decision": "block",
                    "severity": "critical",
                    "citation": "PIPL Art. 38",
                    "priority": 90,
                }
            ]
        }
        rules_path = tmp_path / "rules.json"
        rules_path.write_text(json.dumps(rules), encoding="utf-8")

        action = {
            "action_type": "data_export",
            "destination_region": "US",
            "source_region": "EU",
            "contains_pii": True,
            "data_categories": ["email"],
            "payload": {"email": "b@example.de"},
        }
        action_path = tmp_path / "action.json"
        action_path.write_text(json.dumps(action), encoding="utf-8")

        exit_code = main(["check", str(action_path), "--rules", str(rules_path)])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "ALLOW" in captured.out.upper()
        assert "PIPL-38" not in captured.out


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


class TestCliVerboseExplanations:
    """--verbose surfaces deciding rule and overridden matches."""

    def test_verbose_marks_deciding_rule(self, tmp_path: Path, capsys):
        rules = {
            "rules": [
                {
                    "id": "BLOCK-R",
                    "jurisdiction": "EU",
                    "description": "Block PII to US",
                    "match": {"contains_pii": True, "destination_regions": ["US"]},
                    "decision": "block",
                    "severity": "critical",
                    "citation": "GDPR Art. 44",
                    "priority": 100,
                },
                {
                    "id": "REDACT-R",
                    "jurisdiction": "GLOBAL",
                    "description": "Would redact email",
                    "match": {"data_categories": ["email"]},
                    "decision": "redact",
                    "severity": "medium",
                    "citation": "POL-003",
                    "priority": 10,
                },
            ]
        }
        rules_path = tmp_path / "rules.json"
        rules_path.write_text(json.dumps(rules), encoding="utf-8")
        action_path = tmp_path / "action.json"
        action_path.write_text(
            json.dumps(
                {
                    "action_type": "data_export",
                    "destination_region": "US",
                    "contains_pii": True,
                    "data_categories": ["email"],
                    "payload": {"email": "a@example.com"},
                }
            ),
            encoding="utf-8",
        )

        code = main(["check", str(action_path), "--rules", str(rules_path), "--verbose"])
        captured = capsys.readouterr()
        assert code == 1
        assert "Explanation:" in captured.out
        assert "Deciding rule: BLOCK-R" in captured.out
        assert "Overridden rules:" in captured.out
        assert "REDACT-R proposed redact" in captured.out

    def test_non_verbose_omits_explanation_block(self, tmp_path: Path, capsys):
        rules = {
            "rules": [
                {
                    "id": "BLOCK-R",
                    "jurisdiction": "EU",
                    "description": "Block",
                    "match": {"contains_pii": True},
                    "decision": "block",
                    "severity": "critical",
                    "citation": "X",
                    "priority": 100,
                }
            ]
        }
        rules_path = tmp_path / "rules.json"
        rules_path.write_text(json.dumps(rules), encoding="utf-8")
        action_path = tmp_path / "action.json"
        action_path.write_text(
            json.dumps(
                {
                    "action_type": "data_export",
                    "contains_pii": True,
                    "payload": {},
                }
            ),
            encoding="utf-8",
        )
        code = main(["check", str(action_path), "--rules", str(rules_path)])
        captured = capsys.readouterr()
        assert code == 1
        assert "Explanation:" not in captured.out
        assert "Deciding rule:" not in captured.out


class TestCliConfig:
    """cf check --config / env / auto-discovery and severity threshold."""

    def _write_rules(self, path: Path) -> Path:
        data = {
            "rules": [
                {
                    "id": "CRIT-BLOCK",
                    "jurisdiction": "EU",
                    "description": "Critical block",
                    "match": {"contains_pii": True},
                    "decision": "block",
                    "severity": "critical",
                    "citation": "GDPR",
                    "priority": 100,
                },
                {
                    "id": "LOW-REDACT",
                    "jurisdiction": "GLOBAL",
                    "description": "Low severity redact",
                    "match": {"data_categories": ["phone"]},
                    "decision": "redact",
                    "severity": "low",
                    "citation": "POL",
                    "priority": 1,
                },
            ]
        }
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def _write_action(self, path: Path) -> Path:
        path.write_text(
            json.dumps(
                {
                    "action_type": "data_export",
                    "contains_pii": True,
                    "data_categories": ["phone"],
                    "payload": {"phone": "+1"},
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_config_supplies_rules_path(self, tmp_path: Path, capsys):
        rules_path = self._write_rules(tmp_path / "rules.json")
        action_path = self._write_action(tmp_path / "action.json")
        config_path = tmp_path / "cf.toml"
        config_path.write_text(
            f'rules_path = "{rules_path.as_posix()}"\n', encoding="utf-8"
        )

        code = main(["check", str(action_path), "--config", str(config_path)])
        captured = capsys.readouterr()
        # Without threshold, both rules apply; block wins
        assert code == 1
        assert "CRIT-BLOCK" in captured.out

    def test_cli_rules_overrides_config(self, tmp_path: Path, capsys):
        rules_a = self._write_rules(tmp_path / "a.json")
        # Rules B only has the low redact rule
        rules_b = tmp_path / "b.json"
        rules_b.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "ONLY-REDACT",
                            "jurisdiction": "GLOBAL",
                            "description": "Redact phone",
                            "match": {"data_categories": ["phone"]},
                            "decision": "redact",
                            "severity": "low",
                            "citation": "POL",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        action_path = self._write_action(tmp_path / "action.json")
        config_path = tmp_path / "cf.toml"
        config_path.write_text(
            f'rules_path = "{rules_a.as_posix()}"\n', encoding="utf-8"
        )

        code = main(
            [
                "check",
                str(action_path),
                "--config",
                str(config_path),
                "--rules",
                str(rules_b),
            ]
        )
        captured = capsys.readouterr()
        assert code == 3  # redact from B, not block from A
        assert "ONLY-REDACT" in captured.out
        assert "CRIT-BLOCK" not in captured.out

    def test_env_rules_path(self, tmp_path: Path, capsys, monkeypatch):
        rules_path = self._write_rules(tmp_path / "rules.json")
        action_path = self._write_action(tmp_path / "action.json")
        monkeypatch.setenv("CF_RULES_PATH", str(rules_path))
        # Avoid picking up a stray cf.toml
        monkeypatch.chdir(tmp_path)

        code = main(["check", str(action_path)])
        captured = capsys.readouterr()
        assert code == 1
        assert "CRIT-BLOCK" in captured.out

    def test_autodiscovery_cf_toml(self, tmp_path: Path, capsys, monkeypatch):
        rules_path = self._write_rules(tmp_path / "rules.json")
        action_path = self._write_action(tmp_path / "action.json")
        (tmp_path / "cf.toml").write_text(
            f'rules_path = "{rules_path.as_posix()}"\n', encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)

        code = main(["check", str(action_path)])
        captured = capsys.readouterr()
        assert code == 1
        assert "CRIT-BLOCK" in captured.out

    def test_severity_threshold_filters_low_rule(
        self, tmp_path: Path, capsys
    ):
        rules_path = self._write_rules(tmp_path / "rules.json")
        action_path = self._write_action(tmp_path / "action.json")

        # High threshold: low-severity redact rule is dropped; critical block remains
        code = main(
            [
                "check",
                str(action_path),
                "--rules",
                str(rules_path),
                "--severity-threshold",
                "high",
                "--verbose",
            ]
        )
        captured = capsys.readouterr()
        assert code == 1
        assert "Severity threshold: high" in captured.out
        assert "CRIT-BLOCK" in captured.out
        assert "LOW-REDACT" not in captured.out

    def test_severity_threshold_from_config(
        self, tmp_path: Path, capsys, monkeypatch
    ):
        rules_path = self._write_rules(tmp_path / "rules.json")
        action_path = self._write_action(tmp_path / "action.json")
        (tmp_path / "cf.toml").write_text(
            f'rules_path = "{rules_path.as_posix()}"\n'
            'severity_threshold = "critical"\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        code = main(["check", str(action_path), "--verbose"])
        captured = capsys.readouterr()
        assert code == 1
        assert "Severity threshold: critical" in captured.out
        assert "LOW-REDACT" not in captured.out

    def test_cli_threshold_overrides_config(
        self, tmp_path: Path, capsys
    ):
        rules_path = self._write_rules(tmp_path / "rules.json")
        action_path = self._write_action(tmp_path / "action.json")
        config_path = tmp_path / "cf.toml"
        config_path.write_text(
            f'rules_path = "{rules_path.as_posix()}"\n'
            'severity_threshold = "critical"\n',
            encoding="utf-8",
        )

        # CLI asks for low threshold → nothing filtered
        code = main(
            [
                "check",
                str(action_path),
                "--config",
                str(config_path),
                "--severity-threshold",
                "low",
                "--verbose",
            ]
        )
        captured = capsys.readouterr()
        assert code == 1
        assert "Severity threshold: low" in captured.out
        assert "LOW-REDACT" in captured.out

    def test_missing_config_file_exits_2(self, tmp_path: Path, capsys):
        action_path = self._write_action(tmp_path / "action.json")
        code = main(
            ["check", str(action_path), "--config", str(tmp_path / "missing.toml")]
        )
        captured = capsys.readouterr()
        assert code == 2
        assert "not found" in captured.err.lower()

    def test_no_rules_anywhere_exits_2(self, tmp_path: Path, capsys, monkeypatch):
        action_path = self._write_action(tmp_path / "action.json")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("CF_RULES_PATH", raising=False)
        monkeypatch.delenv("CF_CONFIG", raising=False)
        code = main(["check", str(action_path)])
        captured = capsys.readouterr()
        assert code == 2
        assert "no rules file" in captured.err.lower()
