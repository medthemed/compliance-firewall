# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
