# Architecture

## Overview

compliance-firewall is a compliance proxy that sits between an autonomous agent and its executors. Every intended action is evaluated against a rule database before execution. Actions may be allowed, blocked, redacted (PII stripped), or held pending explicit consent.

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│   Agent     │────▶│ ComplianceProxy  │────▶│  Executor   │
│ (intended   │     │                  │     │ (HTTP, DB,  │
│  action)    │     │  evaluate()      │     │  tool, ...) │
└─────────────┘     │  redact()        │     └─────────────┘
                    │  audit_log       │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │   Rule Database  │
                    │  (YAML / JSON)   │
                    └──────────────────┘
```

## Module Layout

```
src/compliance_firewall/
├── __init__.py      # Public API re-exports
├── models.py        # Action, Rule, MatchCondition, DecisionResult, enums
├── rules.py         # Load rules from YAML/JSON files
├── evaluate.py      # Pure function: Action + Rules → DecisionResult
├── redact.py        # Field-level PII scrubbing
├── proxy.py         # ComplianceProxy middleware wrapping an executor
└── cli.py           # `cf check` and `cf serve-demo` commands
```

## Data Flow

1. **Agent** constructs an `Action` with metadata (type, region, PII flag, categories, payload).
2. **ComplianceProxy.execute(action)** calls `evaluate(action, rules)`.
3. **Evaluator** runs each rule's `MatchCondition.matches(action)`. Matched rules are collected.
4. **Decision resolution**: the most restrictive decision wins:
   `BLOCK > REQUIRE_CONSENT > REDACT > ALLOW`
5. **Proxy behavior**:
   - `BLOCK` → raises `ActionBlockedError`; executor never called.
   - `REQUIRE_CONSENT` → raises `ConsentRequiredError`; executor never called.
   - `REDACT` → calls `redact_action(action)`, then executes the scrubbed action.
   - `ALLOW` → executes the original action.
6. Every evaluation is appended to `proxy.audit_log`.

## Rule Schema

```yaml
rules:
  - id: GDPR-ART44
    jurisdiction: EU
    description: "No PII transfer to non-adequate third countries"
    match:
      contains_pii: true
      destination_regions: [US, CN, RU, IN]
      # All optional; unspecified fields are wildcards
      # action_types: [http_request, db_query]
      # data_categories: [email, phone]
      # purposes: [marketing]
    decision: block          # allow | block | redact | require_consent
    severity: critical       # low | medium | high | critical
    citation: "GDPR Art. 44"
    remediation: "Use an EU-based processor."
    priority: 100            # higher = evaluated first
```

### Match Semantics

- All specified conditions use AND logic (every condition must match).
- `data_categories` uses OR logic within itself (any category match suffices).
- Unspecified fields are wildcards (match anything).

## Decision Priority

| Decision | Wins over |
|---|---|
| `block` | everything |
| `require_consent` | `redact`, `allow` |
| `redact` | `allow` |
| `allow` | (nothing) |

## Redaction

`redact.py` maps data categories to known payload keys:

| Category | Keys redacted |
|---|---|
| `email` | `email`, `user_email`, `contact_email`, `email_address` |
| `phone` | `phone`, `phone_number`, `tel`, `mobile` |
| `national_id` | `national_id`, `ssn`, `sin`, `nino`, `passport`, `id_number` |
| `name` | `name`, `full_name`, `first_name`, `last_name`, `display_name` |
| `address` | `address`, `street`, `city`, `postal_code`, `zip`, `home_address` |
| `health` | `health_data`, `medical_record`, `diagnosis`, `treatment` |
| `financial` | `bank_account`, `credit_card`, `iban`, `card_number` |
| `biometric` | `fingerprint`, `face_id`, `iris_scan`, `biometric_data` |

Secrets (`password`, `api_key`, `token`, `secret`, `private_key`, etc.) are always redacted regardless of category.

Nested dicts and lists are traversed recursively.

## Extending: Remote Rule Feed

The current MVP loads rules from local files. A remote feed plugs in cleanly:

```python
from compliance_firewall.rules import load_rules_from_dict
from compliance_firewall.proxy import ComplianceProxy
import urllib.request, json

def fetch_remote_rules(url: str) -> list:
    with urllib.request.urlopen(url, timeout=5) as resp:
        data = json.loads(resp.read())
    return load_rules_from_dict(data)

# Periodically refresh rules
rules = fetch_remote_rules("https://rules.example.com/api/v1/rules")
proxy = ComplianceProxy(rules=rules, executor=my_executor)
```

The `load_rules_from_dict` function is the extension point: any source that produces the same dict schema works (HTTP API, S3 bucket, database query, etc.).

## Design Decisions

- **Pure evaluator**: `evaluate()` has no side effects, making it trivially testable and cacheable.
- **Frozen dataclasses**: Actions and Rules are immutable, preventing accidental mutation in the proxy chain.
- **Stdlib-only runtime**: No runtime dependencies beyond Python 3.11+. PyYAML is optional; a minimal built-in parser handles the rule schema.
- **Audit log**: Every evaluation (including allowed ones) is recorded for compliance evidence.
- **Exit codes**: CLI returns 0 (allow), 1 (block/consent), 3 (redacted), 2 (error) for scripting.
