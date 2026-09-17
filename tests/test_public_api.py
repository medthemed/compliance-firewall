"""Tests for the public package surface."""

from __future__ import annotations

import compliance_firewall as cf


EXPECTED_EXPORTS = {
    "Action",
    "ActionBlockedError",
    "ActionType",
    "ComplianceError",
    "ComplianceProxy",
    "Config",
    "ConfigError",
    "ConsentRequiredError",
    "Decision",
    "DecisionResult",
    "MatchCondition",
    "REDACTED_PLACEHOLDER",
    "Rule",
    "Severity",
    "evaluate",
    "filter_rules_by_severity",
    "load_config",
    "load_config_file",
    "load_rules",
    "load_rules_from_dict",
    "parse_severity",
    "redact_action",
    "redact_payload",
}


class TestPublicExports:
    def test_all_lists_expected_names(self):
        assert set(cf.__all__) == EXPECTED_EXPORTS

    def test_all_names_are_importable(self):
        for name in cf.__all__:
            assert hasattr(cf, name), f"missing public name: {name}"

    def test_compliance_error_is_base(self):
        assert issubclass(cf.ActionBlockedError, cf.ComplianceError)
        assert issubclass(cf.ConsentRequiredError, cf.ComplianceError)

    def test_redacted_placeholder_value(self):
        assert cf.REDACTED_PLACEHOLDER == "[REDACTED]"

    def test_version_is_semver(self):
        parts = cf.__version__.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)
