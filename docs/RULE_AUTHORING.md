# Rule Authoring Guide

This guide is for people who write, review, or maintain compliance rules for
compliance-firewall. It assumes you have read the
[README](../README.md) and know what the four decisions mean.

## Rule anatomy

Every rule is a single entry under the top-level `rules:` list. Here is a
fully-annotated example:

```yaml
rules:
  - id: GDPR-ART44                 # Required. Unique, stable, UPPER-KEBAB recommended
    jurisdiction: EU               # Required. ISO-style code: EU, US-CA, CN, GLOBAL
    description: "No PII transfer to non-adequate third countries"
    match:                         # Required. Conditions; see below
      contains_pii: true
      destination_regions: [US, CN, RU, IN]
    decision: block                # Required. allow | block | redact | require_consent
    severity: critical             # Required. low | medium | high | critical
    citation: "GDPR Art. 44"       # Required. Legal or policy reference
    remediation: "Use an EU-based processor."  # Optional. Operator guidance
    priority: 100                  # Optional. Default 0. Higher is evaluated first
```

### Field reference

| Field | Required | Notes |
|---|---|---|
| `id` | yes | Unique across the rule set. Use a stable name — it appears in audit logs and error messages. |
| `jurisdiction` | yes | Human-facing label. Does not affect matching; matching is controlled by `match`. |
| `description` | no | One sentence an operator can act on. |
| `match` | yes | See [Match conditions](#match-conditions). An empty `match: {}` matches every action. |
| `decision` | yes | The outcome this rule proposes. The evaluator still resolves conflicts. |
| `severity` | yes | Informational. Does not change which decision wins. |
| `citation` | yes | Statute, regulation, or internal policy ID. Never leave this blank on a real rule. |
| `remediation` | no | What the operator should do next. Aggregated across matched rules. |
| `priority` | no | Tie-breaker and evaluation order. Default `0`. |

## Match conditions

All specified fields use **AND** logic: every field you set must match, or the
rule does not fire. Unset fields are wildcards.

| Field | Type | Matches on |
|---|---|---|
| `action_types` | list | `http_request`, `db_query`, `data_export`, `tool_call` |
| `destination_regions` | list | Action's `destination_region` (where data is going) |
| `source_regions` | list | Action's `source_region` (where data was collected) |
| `contains_pii` | bool | Action's `contains_pii` flag |
| `purposes` | list | Action's `purpose` (exact string match) |
| `data_categories` | list | **OR** within the list — any category present in the action matches |

### Source vs destination

- Use `destination_regions` when the law cares about where data is *sent*
  (GDPR Art. 44 transfers, adequacy decisions).
- Use `source_regions` when the law cares about where data was *collected*
  (PIPL applies to personal information collected in China).
- Combine both for cross-border rules that are origin-scoped.

An action with an empty `source_region` is treated as unspecified and will
**not** match a rule that lists `source_regions`. If you omit `source_regions`
from a rule, origin is ignored.

### data_categories OR semantics

```yaml
match:
  data_categories: [email, phone]
```

This matches an action whose categories include `email` **or** `phone` (or
both). It is the only list field that uses OR internally.

## Choosing a decision

| Use | When |
|---|---|
| `block` | The transfer or processing is unlawful without a path forward the agent can take. Raise an error; never execute. |
| `require_consent` | The action is lawful *with* user consent that has not yet been recorded. Raise so the caller can obtain it. |
| `redact` | The action is fine if sensitive fields are stripped. The proxy scrubs and re-executes. |
| `allow` | Rare. Use only when you need an explicit allow that still participates in matched-rule reporting. |

When multiple rules match, the most restrictive decision wins:

```
block > require_consent > redact > allow
```

So a `block` rule always overrides a `redact` rule, regardless of priority.
Priority only affects ordering of matched rules and which rule is listed first.

## Priority and severity

They answer different questions:

- **Severity** — how bad is a violation of this rule? (`critical` for unlawful
  transfers, `medium` for internal hygiene.)
- **Priority** — when several rules match, which one is listed first? Higher
  numbers win. Does *not* override decision restrictiveness.

Suggested ranges:

| Range | Use for |
|---|---|
| 90–100 | Hard statutory blocks (GDPR Art. 44, PIPL Art. 38) |
| 50–80 | Consent requirements, high-severity redactions |
| 10–40 | Internal policy, hygiene redactions |
| 0 | Default; fine for most rules |

## Jurisdiction conventions

Use consistent ISO-style codes. The codebase examples use:

| Code | Meaning |
|---|---|
| `EU` | European Union / EEA |
| `US` | United States (federal / unspecified) |
| `US-CA` | California |
| `CN` | China |
| `RU` | Russia |
| `IN` | India |
| `GLOBAL` | Internal policy, no single jurisdiction |

`jurisdiction` is a label for humans and reports. Actual matching is controlled
by `match.destination_regions` and `match.source_regions`. Keep them in sync
when it makes sense, but they are independent.

## Worked examples

### 1. Statutory transfer block (origin-scoped)

```yaml
- id: CHINA-PIPL-LOCALIZE
  jurisdiction: CN
  description: "PII collected in China must not be exported to non-local processors without a security assessment"
  match:
    source_regions: [CN]
    destination_regions: [US]
    contains_pii: true
  decision: block
  severity: critical
  citation: "PIPL Art. 38"
  remediation: "Complete a security assessment before transferring PII to overseas processors."
  priority: 90
```

Only fires for China-origin PII leaving to the US. A US-origin export to the
US, or a China-origin export to an adequate destination, does not match.

### 2. Purpose limitation (consent)

```yaml
- id: CCPA-OPTEVENT
  jurisdiction: US-CA
  description: "Email cannot be used for marketing without prior opt-in"
  match:
    data_categories: [email]
    purposes: [marketing, advertising]
  decision: require_consent
  severity: high
  citation: "CCPA §1798.120"
  remediation: "Record explicit opt-in before sending marketing communications."
  priority: 50
```

Matches any action that touches `email` **and** declares a marketing purpose,
regardless of region.

### 3. Hygiene redaction (internal policy)

```yaml
- id: BASIC-REDACT-PHONE
  jurisdiction: GLOBAL
  description: "Redact phone numbers from tool call payloads"
  match:
    action_types: [tool_call]
    data_categories: [phone]
  decision: redact
  severity: medium
  citation: "Internal policy POL-003"
  remediation: "Strip phone fields before invoking external tools."
  priority: 10
```

Narrow on purpose: only `tool_call` actions, only when a phone category is
present. The proxy strips matching keys and continues.

## Common pitfalls

1. **Over-broad matches.** Omitting `action_types` or `destination_regions`
   makes a rule fire on every action that satisfies the remaining conditions.
   Start narrow, widen deliberately.

2. **Empty `source_region` and origin rules.** An action that does not declare
   `source_region` will not match a rule with `source_regions: [CN]`. If your
   agent does not populate the field, origin-scoped rules will never fire —
   populate it.

3. **Missing citations.** A rule without a citation cannot be defended in an
   audit. Always fill `citation`, even for internal policy (`"Internal policy POL-003"`).

4. **Assuming priority overrides decision.** A priority-100 `redact` rule
   loses to a priority-0 `block` rule. Restrictiveness wins; priority is only
   ordering.

5. **Reusing rule IDs.** IDs appear in `ActionBlockedError` messages and audit
   logs. Renaming an ID breaks external dashboards that key on it. Prefer
   adding a new rule and retiring the old one.

6. **Forgetting remediation.** The evaluator aggregates `remediation` strings
   from every matched rule. An empty remediation leaves the operator with a
   block and no next step.

## Validating a rule set

Load your file and check a known action before deploying:

```python
from compliance_firewall import Action, evaluate, load_rules

rules = load_rules("my_rules.yaml")
action = Action.from_dict({
    "action_type": "data_export",
    "destination_region": "US",
    "source_region": "CN",
    "contains_pii": True,
    "data_categories": ["email"],
})
result = evaluate(action, rules)
print(result.decision, [r.id for r in result.matched_rules])
```

Or from the CLI:

```bash
cf check examples/actions/pii_export_us.json --rules my_rules.yaml
```

Exit codes: `0` allow, `1` block or require-consent, `3` redacted, `2` error.

## Related

- [ARCHITECTURE.md](ARCHITECTURE.md) — how evaluation and the proxy work
- [examples/rules.yaml](../examples/rules.yaml) — the reference rule set
