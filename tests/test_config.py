"""Tests for configuration loading and severity filtering."""

from __future__ import annotations

from pathlib import Path

import pytest

from compliance_firewall.config import (
    Config,
    ConfigError,
    discover_config_file,
    filter_rules_by_severity,
    load_config,
    load_config_file,
    parse_severity,
)
from compliance_firewall.models import (
    Action,
    ActionType,
    Decision,
    MatchCondition,
    Rule,
    Severity,
)


def _rule(id: str, severity: Severity, priority: int = 0) -> Rule:
    return Rule(
        id=id,
        jurisdiction="GLOBAL",
        description=f"Rule {id}",
        match=MatchCondition(),
        decision=Decision.BLOCK,
        severity=severity,
        citation="TEST",
        priority=priority,
    )


class TestParseSeverity:
    def test_parses_all_levels(self):
        assert parse_severity("low") == Severity.LOW
        assert parse_severity("MEDIUM") == Severity.MEDIUM
        assert parse_severity("High") == Severity.HIGH
        assert parse_severity("critical") == Severity.CRITICAL

    def test_unknown_raises(self):
        with pytest.raises(ConfigError) as exc_info:
            parse_severity("urgent")
        assert "urgent" in str(exc_info.value)


class TestLoadConfigFile:
    def test_loads_rules_path_and_threshold(self, tmp_path: Path):
        path = tmp_path / "cf.toml"
        path.write_text(
            'rules_path = "examples/rules.yaml"\nseverity_threshold = "high"\n',
            encoding="utf-8",
        )
        cfg = load_config_file(path)
        assert cfg.rules_path == Path("examples/rules.yaml")
        assert cfg.severity_threshold == Severity.HIGH

    def test_partial_file(self, tmp_path: Path):
        path = tmp_path / "cf.toml"
        path.write_text('severity_threshold = "medium"\n', encoding="utf-8")
        cfg = load_config_file(path)
        assert cfg.rules_path is None
        assert cfg.severity_threshold == Severity.MEDIUM

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(ConfigError) as exc_info:
            load_config_file(tmp_path / "nope.toml")
        assert "not found" in str(exc_info.value).lower()

    def test_invalid_toml_raises(self, tmp_path: Path):
        path = tmp_path / "cf.toml"
        path.write_text("rules_path = [unterminated\n", encoding="utf-8")
        with pytest.raises(ConfigError) as exc_info:
            load_config_file(path)
        assert "Invalid TOML" in str(exc_info.value)

    def test_bad_rules_path_type_raises(self, tmp_path: Path):
        path = tmp_path / "cf.toml"
        path.write_text("rules_path = 42\n", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config_file(path)

    def test_bad_severity_raises(self, tmp_path: Path):
        path = tmp_path / "cf.toml"
        path.write_text('severity_threshold = "urgent"\n', encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config_file(path)

    def test_unknown_keys_tolerated(self, tmp_path: Path):
        path = tmp_path / "cf.toml"
        path.write_text(
            'rules_path = "r.yaml"\nfuture_flag = true\n',
            encoding="utf-8",
        )
        cfg = load_config_file(path)
        assert cfg.rules_path == Path("r.yaml")


class TestDiscoverConfigFile:
    def test_finds_cf_toml(self, tmp_path: Path):
        (tmp_path / "cf.toml").write_text('rules_path = "a.yaml"\n', encoding="utf-8")
        found = discover_config_file(tmp_path)
        assert found is not None
        assert found.name == "cf.toml"

    def test_finds_dotfile_fallback(self, tmp_path: Path):
        (tmp_path / ".cf.toml").write_text("rules_path = 'b.yaml'\n", encoding="utf-8")
        found = discover_config_file(tmp_path)
        assert found is not None
        assert found.name == ".cf.toml"

    def test_returns_none_when_absent(self, tmp_path: Path):
        assert discover_config_file(tmp_path) is None


class TestLoadConfig:
    def test_explicit_path(self, tmp_path: Path):
        path = tmp_path / "my.toml"
        path.write_text('rules_path = "rules.yaml"\n', encoding="utf-8")
        cfg = load_config(path, use_env=False, discover=False)
        assert cfg.rules_path == Path("rules.yaml")

    def test_explicit_missing_path_raises(self, tmp_path: Path):
        with pytest.raises(ConfigError):
            load_config(tmp_path / "missing.toml", use_env=False, discover=False)

    def test_empty_config(self, tmp_path: Path):
        cfg = load_config(None, use_env=False, discover=False, cwd=tmp_path)
        assert cfg.rules_path is None
        assert cfg.severity_threshold is None

    def test_env_overrides_file(self, tmp_path: Path, monkeypatch):
        path = tmp_path / "cf.toml"
        path.write_text(
            'rules_path = "from_file.yaml"\nseverity_threshold = "low"\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("CF_RULES_PATH", "from_env.yaml")
        monkeypatch.setenv("CF_SEVERITY_THRESHOLD", "critical")
        cfg = load_config(path, use_env=True, discover=False)
        assert cfg.rules_path == Path("from_env.yaml")
        assert cfg.severity_threshold == Severity.CRITICAL

    def test_env_config_path_selected(self, tmp_path: Path, monkeypatch):
        path = tmp_path / "via-env.toml"
        path.write_text('rules_path = "env_selected.yaml"\n', encoding="utf-8")
        monkeypatch.setenv("CF_CONFIG", str(path))
        cfg = load_config(None, use_env=True, discover=False)
        assert cfg.rules_path == Path("env_selected.yaml")

    def test_autodiscovery_from_cwd(self, tmp_path: Path):
        (tmp_path / "cf.toml").write_text(
            'rules_path = "auto.yaml"\n', encoding="utf-8"
        )
        cfg = load_config(None, use_env=False, discover=True, cwd=tmp_path)
        assert cfg.rules_path == Path("auto.yaml")


class TestConfigMergedWith:
    def test_cli_overrides_file(self, tmp_path: Path):
        path = tmp_path / "cf.toml"
        path.write_text(
            'rules_path = "file.yaml"\nseverity_threshold = "low"\n',
            encoding="utf-8",
        )
        base = load_config(path, use_env=False, discover=False)
        merged = base.merged_with(
            rules_path="cli.yaml", severity_threshold="high", source="cli"
        )
        assert merged.rules_path == Path("cli.yaml")
        assert merged.severity_threshold == Severity.HIGH

    def test_none_does_not_clear(self, tmp_path: Path):
        path = tmp_path / "cf.toml"
        path.write_text('rules_path = "keep.yaml"\n', encoding="utf-8")
        base = load_config(path, use_env=False, discover=False)
        merged = base.merged_with(rules_path=None, severity_threshold=None)
        assert merged.rules_path == Path("keep.yaml")

    def test_accepts_severity_enum(self):
        cfg = Config().merged_with(severity_threshold=Severity.MEDIUM)
        assert cfg.severity_threshold == Severity.MEDIUM


class TestFilterRulesBySeverity:
    def test_none_threshold_keeps_all(self):
        rules = [_rule("a", Severity.LOW), _rule("b", Severity.CRITICAL)]
        assert filter_rules_by_severity(rules, None) == rules

    def test_high_threshold_drops_low_and_medium(self):
        rules = [
            _rule("low", Severity.LOW),
            _rule("med", Severity.MEDIUM),
            _rule("high", Severity.HIGH),
            _rule("crit", Severity.CRITICAL),
        ]
        kept = filter_rules_by_severity(rules, Severity.HIGH)
        assert [r.id for r in kept] == ["high", "crit"]

    def test_critical_threshold(self):
        rules = [_rule("high", Severity.HIGH), _rule("crit", Severity.CRITICAL)]
        kept = filter_rules_by_severity(rules, Severity.CRITICAL)
        assert [r.id for r in kept] == ["crit"]

    def test_low_threshold_keeps_everything(self):
        rules = [_rule("low", Severity.LOW), _rule("high", Severity.HIGH)]
        kept = filter_rules_by_severity(rules, Severity.LOW)
        assert len(kept) == 2
