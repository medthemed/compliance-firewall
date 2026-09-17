# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-09-20

### Added
- Draft-07 JSON Schema documents for actions and rule databases:
  `schemas/action.schema.json` and `schemas/rules.schema.json`, also shipped
  as package data under `compliance_firewall/schema_files/`
- `ACTION_SCHEMA`, `RULES_SCHEMA`, `schema_path`, `validate_action_data`,
  and `validate_rules_data` exported from the package root
- Lightweight stdlib structural validators (no `jsonschema` dependency)
- `cf check --format json` and `cf check-batch --format json` emit a stable
  machine-readable envelope with `schema_version`, decision details, matched
  rules, and (for batch) a summary plus per-file results
- `decision_result_to_dict` and `rule_to_dict` for library integrations

### Changed
- JSON-mode errors are reported as `error` fields on stdout so CI parsers
  always receive a single JSON object; process exit codes are unchanged
- Human-readable `text` output remains the default and is unchanged

## [0.4.0] - 2026-09-19

### Added
- `cf check-batch <actions-dir>` evaluates every `*.json` action file in a
  directory (non-recursive, sorted by filename)
- Per-file result blocks plus a batch summary grouped by decision
- Documented batch exit codes: 0 all allow, 1 any block/require_consent,
  3 any redact without block/consent, 2 config/rules error, empty or
  missing directory, or any parse failure
- Individual parse failures are reported and the rest of the batch continues;
  the process still exits 2 when any file fails to parse
- Shared config/rules resolution helper used by both `cf check` and
  `cf check-batch` (same `--rules`, `--config`, and `--severity-threshold`
  behavior)

## [0.3.0] - 2026-09-18

### Added
- `cf.toml` / `.cf.toml` / `compliance-firewall.toml` project config with
  `rules_path` and `severity_threshold`
- Environment variables `CF_RULES_PATH`, `CF_SEVERITY_THRESHOLD`, and `CF_CONFIG`
- `cf check --config` for an explicit config file; auto-discovers `cf.toml` in cwd
- `cf check --severity-threshold` to drop rules below a named severity
- `load_config`, `load_config_file`, `parse_severity`, and
  `filter_rules_by_severity` exported from the package root
- `ConfigError` for configuration failures
- Example config at `examples/cf.toml` and README configuration section

### Changed
- `cf check --rules` is now optional when a config file or `CF_RULES_PATH`
  supplies a default path

## [0.2.0] - 2026-09-18

### Added
- `DecisionResult.deciding_rule` and `DecisionResult.overridden_rules` identify
  which matched rule produced the final decision and which softer matches lost
- `DecisionResult.explain()` returns a one-line operator-facing explanation
- `ComplianceError` base exception; `ActionBlockedError` and
  `ConsentRequiredError` now subclass it (existing handlers still work)
- `REDACTED_PLACEHOLDER` re-exported from the package root
- CLI `--verbose` prints the explanation, deciding rule, and overridden matches
- End-to-end integration tests covering allow / block / redact / require_consent
  through both `ComplianceProxy` and `cf check` against a real rules file

### Changed
- Matched-rules CLI output marks the deciding rule with `*`

## [0.1.1] - 2026-09-17

### Added
- `Action.source_region` field and `MatchCondition.source_regions` match condition
  for origin-based jurisdiction rules (e.g. PIPL scoped to data collected in China)
- Example action `pii_export_us_eu_origin.json` showing a non-China origin export
- CLI now prints the source region when present
- `docs/RULE_AUTHORING.md` — field-by-field guide to writing compliance rules
- CI, license, and Python version badges in the README

### Changed
- `CHINA-PIPL-LOCALIZE` example rule now matches on `source_regions: [CN]` so it
  only fires for personal information collected in China

## [0.1.0] - 2026-09-16

### Added
- Core action model: `http_request`, `db_query`, `data_export`, `tool_call`
- YAML/JSON rule database with jurisdiction, match conditions, decisions, severity, and citations
- Pure-function evaluator producing `DecisionResult` with matched rules and remediation hints
- Proxy middleware that blocks, redacts, or passes actions before executor invocation
- Field-level redaction for PII categories (email, phone, national_id, etc.)
- CLI: `cf check` and `cf serve-demo`
- Example rules and action files for GDPR / CCPA scenarios
- Full pytest suite covering evaluation, proxy, redaction, and priority
