"""Command-line interface for compliance-firewall."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import ConfigError, filter_rules_by_severity, load_config
from .evaluate import evaluate
from .models import Action, Decision
from .rules import load_rules


def _format_result(action: Action, result, *, verbose: bool = False) -> str:
    """Format a DecisionResult for terminal output."""
    lines: list[str] = []

    decision_icon = {
        Decision.ALLOW: "✓",
        Decision.BLOCK: "✗",
        Decision.REDACT: "⚠",
        Decision.REQUIRE_CONSENT: "⚠",
    }
    icon = decision_icon.get(result.decision, "?")

    lines.append(f"{icon} Decision: {result.decision.value.upper()}")
    lines.append(f"  Action: {action.action_type.value}")
    if action.source_region:
        lines.append(f"  Source: {action.source_region}")
    if action.destination_region:
        lines.append(f"  Destination: {action.destination_region}")
    if action.purpose:
        lines.append(f"  Purpose: {action.purpose}")
    if action.contains_pii:
        lines.append(f"  PII: yes ({', '.join(action.data_categories) or 'unspecified'})")

    if result.matched_rules:
        lines.append(f"  Matched rules ({len(result.matched_rules)}):")
        for rule in result.matched_rules:
            marker = "*" if result.deciding_rule is not None and rule.id == result.deciding_rule.id else "-"
            lines.append(
                f"    {marker} [{rule.severity.value}] {rule.id} "
                f"({rule.jurisdiction}): {rule.description}"
            )
            if rule.citation:
                lines.append(f"        Citation: {rule.citation}")
    else:
        lines.append("  Matched rules: none")

    if verbose:
        lines.append(f"  Explanation: {result.explain()}")
        if result.deciding_rule is not None:
            lines.append(
                f"  Deciding rule: {result.deciding_rule.id} "
                f"→ {result.decision.value} "
                f"({result.deciding_rule.severity.value})"
            )
        if result.overridden_rules:
            lines.append("  Overridden rules:")
            for rule in result.overridden_rules:
                lines.append(
                    f"    - {rule.id} proposed {rule.decision.value} "
                    f"({rule.severity.value})"
                )

    if result.remediation_hints:
        lines.append("  Remediation:")
        for hint in result.remediation_hints:
            lines.append(f"    → {hint}")

    if result.is_redacted and result.redacted_action:
        lines.append("  Redacted payload:")
        lines.append(
            "    " + json.dumps(result.redacted_action.payload, indent=2).replace("\n", "\n    ")
        )

    return "\n".join(lines)


def _resolve_rules(args: argparse.Namespace):
    """Resolve config, rules path, and filtered rule list for a check command.

    Returns:
        ``(rules, error_exit_code)``. On failure, ``rules`` is None and the
        second element is the process exit code (always 2).
    """
    try:
        config = load_config(getattr(args, "config", None))
    except ConfigError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return None, 2

    config = config.merged_with(
        rules_path=args.rules,
        severity_threshold=getattr(args, "severity_threshold", None),
        source="cli",
    )

    rules_path = config.rules_path
    if rules_path is None:
        print(
            "Error: no rules file specified. Pass --rules, set CF_RULES_PATH, "
            "or provide rules_path in cf.toml.",
            file=sys.stderr,
        )
        return None, 2

    if not rules_path.exists():
        print(f"Error: rules file not found: {rules_path}", file=sys.stderr)
        return None, 2

    try:
        rules = load_rules(rules_path)
    except Exception as exc:
        print(f"Error: failed to load rules: {exc}", file=sys.stderr)
        return None, 2

    threshold = config.severity_threshold
    if threshold is not None:
        before = len(rules)
        rules = filter_rules_by_severity(rules, threshold)
        if getattr(args, "verbose", False):
            print(
                f"  Severity threshold: {threshold.value} "
                f"({before - len(rules)} rule(s) filtered out)"
            )

    return rules, 0


def _exit_code_for_decision(result) -> int:
    """Map a DecisionResult to the process exit code for a single check."""
    # Exit code: 0 = allow, 1 = blocked/consent, 3 = redacted
    if result.is_blocked or result.requires_consent:
        return 1
    if result.is_redacted:
        return 3
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Handle the `cf check` subcommand."""
    action_path = Path(args.action)

    rules, err = _resolve_rules(args)
    if rules is None:
        return err

    if not action_path.exists():
        print(f"Error: action file not found: {action_path}", file=sys.stderr)
        return 2

    try:
        action_data = json.loads(action_path.read_text(encoding="utf-8"))
        action = Action.from_dict(action_data)
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"Error: failed to parse action file: {exc}", file=sys.stderr)
        return 2

    result = evaluate(action, rules)
    print(_format_result(action, result, verbose=args.verbose))

    return _exit_code_for_decision(result)


# Decision order used when summarizing a batch (most restrictive first).
_BATCH_DECISION_ORDER = (
    Decision.BLOCK,
    Decision.REQUIRE_CONSENT,
    Decision.REDACT,
    Decision.ALLOW,
)


def _discover_action_files(directory: Path) -> list[Path]:
    """Return sorted non-recursive ``*.json`` files in ``directory``."""
    return sorted(
        p for p in directory.iterdir() if p.is_file() and p.suffix == ".json"
    )


def _format_batch_summary(
    counts: dict[Decision, int], errors: int, total: int
) -> str:
    """Format the end-of-batch decision summary block."""
    lines: list[str] = []
    lines.append("=" * 40)
    lines.append("  Batch summary")
    lines.append("=" * 40)
    lines.append(f"  Total files: {total}")
    for decision in _BATCH_DECISION_ORDER:
        lines.append(f"  {decision.value}: {counts.get(decision, 0)}")
    if errors:
        lines.append(f"  errors: {errors}")
    return "\n".join(lines)


def cmd_check_batch(args: argparse.Namespace) -> int:
    """Handle the ``cf check-batch`` subcommand.

    Evaluates every ``*.json`` action file in a directory and prints a
    per-file result plus a summary grouped by decision.

    Exit codes:

    * 0 — every action evaluated to ``allow``
    * 1 — at least one action is ``block`` or ``require_consent``
    * 3 — at least one action is ``redact``, and none are block/consent
    * 2 — config/rules error, empty/missing directory, or any parse failure
    """
    directory = Path(args.directory)

    if not directory.exists():
        print(f"Error: directory not found: {directory}", file=sys.stderr)
        return 2
    if not directory.is_dir():
        print(f"Error: not a directory: {directory}", file=sys.stderr)
        return 2

    rules, err = _resolve_rules(args)
    if rules is None:
        return err

    action_files = _discover_action_files(directory)
    if not action_files:
        print(
            f"Error: no *.json action files found in {directory}",
            file=sys.stderr,
        )
        return 2

    counts: dict[Decision, int] = {d: 0 for d in Decision}
    errors = 0
    had_block_or_consent = False
    had_redact = False

    for action_path in action_files:
        print(f"--- {action_path.name} ---")
        try:
            action_data = json.loads(action_path.read_text(encoding="utf-8"))
            action = Action.from_dict(action_data)
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            errors += 1
            print(f"  Error: failed to parse action file: {exc}")
            print()
            continue

        result = evaluate(action, rules)
        print(_format_result(action, result, verbose=args.verbose))
        print()

        counts[result.decision] += 1
        if result.is_blocked or result.requires_consent:
            had_block_or_consent = True
        elif result.is_redacted:
            had_redact = True

    print(_format_batch_summary(counts, errors, len(action_files)))

    # Parse failures mean the batch is incomplete — that outranks decision codes.
    if errors:
        return 2
    if had_block_or_consent:
        return 1
    if had_redact:
        return 3
    return 0


def cmd_serve_demo(args: argparse.Namespace) -> int:
    """Handle the `cf serve-demo` subcommand: run a local demo without network."""
    from .proxy import ActionBlockedError, ComplianceProxy, ConsentRequiredError

    print("=" * 60)
    print("  compliance-firewall demo")
    print("=" * 60)
    print()

    # Built-in demo rules
    demo_rules_data = {
        "rules": [
            {
                "id": "GDPR-ART44",
                "jurisdiction": "EU",
                "description": "No PII transfer to non-adequate third countries",
                "match": {
                    "contains_pii": True,
                    "destination_regions": ["US", "CN", "RU", "IN"],
                },
                "decision": "block",
                "severity": "critical",
                "citation": "GDPR Art. 44",
                "remediation": "Use an EU-based processor or obtain explicit consent under Art. 49.",
                "priority": 100,
            },
            {
                "id": "CCPA-OPTEVENT",
                "jurisdiction": "US-CA",
                "description": "Email cannot be used for marketing without opt-in",
                "match": {
                    "data_categories": ["email"],
                    "purposes": ["marketing"],
                },
                "decision": "require_consent",
                "severity": "high",
                "citation": "CCPA §1798.120",
                "remediation": "Record explicit opt-in before sending marketing emails.",
                "priority": 50,
            },
            {
                "id": "BASIC-REDACT",
                "jurisdiction": "GLOBAL",
                "description": "Redact phone numbers from tool call payloads",
                "match": {
                    "action_types": ["tool_call"],
                    "data_categories": ["phone"],
                },
                "decision": "redact",
                "severity": "medium",
                "citation": "Internal policy POL-003",
                "remediation": "Strip phone fields before invoking external tools.",
                "priority": 10,
            },
        ]
    }

    from .rules import load_rules_from_dict

    rules = load_rules_from_dict(demo_rules_data)

    def fake_executor(action: Action) -> dict:
        """Simulated executor that records what it received."""
        return {
            "status": "ok",
            "executed_action": action.action_type.value,
            "destination": action.destination_region,
            "payload_keys": sorted(action.payload.keys()),
        }

    proxy = ComplianceProxy(
        rules=rules,
        executor=fake_executor,
        on_block=lambda a, r: print(f"  🛑 BLOCKED: {a.action_type.value} → {a.destination_region}"),
        on_redact=lambda a, r: print(f"  ✂  REDACTED: {a.action_type.value}"),
    )

    # Demo scenario 1: PII export to US (should block)
    print("Scenario 1: Export PII to US (expect BLOCK)")
    print("-" * 40)
    action1 = Action.from_dict(
        {
            "action_type": "data_export",
            "destination_region": "US",
            "contains_pii": True,
            "purpose": "analytics",
            "data_categories": ["email", "name"],
            "payload": {"email": "user@example.com", "name": "Alice"},
        }
    )
    try:
        result1 = proxy.execute(action1)
        print(f"  Result: {result1}")
    except ActionBlockedError as exc:
        print(f"  ActionBlockedError: {exc}")
    print()

    # Demo scenario 2: Clean action (should allow)
    print("Scenario 2: Clean HTTP request to EU (expect ALLOW)")
    print("-" * 40)
    action2 = Action.from_dict(
        {
            "action_type": "http_request",
            "destination_region": "EU",
            "contains_pii": False,
            "purpose": "api_call",
            "data_categories": [],
            "payload": {"url": "https://api.example.eu/status", "method": "GET"},
        }
    )
    try:
        result2 = proxy.execute(action2)
        print(f"  Executor returned: {json.dumps(result2, indent=2)}")
    except (ActionBlockedError, ConsentRequiredError) as exc:
        print(f"  Error: {exc}")
    print()

    # Demo scenario 3: Tool call with phone (should redact)
    print("Scenario 3: Tool call with phone data (expect REDACT)")
    print("-" * 40)
    action3 = Action.from_dict(
        {
            "action_type": "tool_call",
            "destination_region": "EU",
            "contains_pii": True,
            "purpose": "support",
            "data_categories": ["phone"],
            "payload": {"tool": "crm_lookup", "phone": "+1-555-0100", "ticket_id": "T-42"},
        }
    )
    try:
        result3 = proxy.execute(action3)
        print(f"  Executor returned: {json.dumps(result3, indent=2)}")
    except (ActionBlockedError, ConsentRequiredError) as exc:
        print(f"  Error: {exc}")
    print()

    print("=" * 60)
    print(f"  Audit log entries: {len(proxy.get_audit_log())}")
    print("=" * 60)

    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point for the cf CLI."""
    parser = argparse.ArgumentParser(
        prog="cf",
        description="compliance-firewall: evaluate agent actions against compliance rules.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # check subcommand
    check_parser = subparsers.add_parser(
        "check",
        help="Check an action file against a rules file.",
    )
    check_parser.add_argument("action", help="Path to action JSON file.")
    check_parser.add_argument(
        "--rules",
        default=None,
        help="Path to rules YAML/JSON file. Falls back to cf.toml / CF_RULES_PATH.",
    )
    check_parser.add_argument(
        "--config",
        default=None,
        help="Path to a cf.toml config file. Auto-discovers cf.toml in cwd when omitted.",
    )
    check_parser.add_argument(
        "--severity-threshold",
        default=None,
        choices=["low", "medium", "high", "critical"],
        help="Ignore rules below this severity (overrides config).",
    )
    check_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed output.",
    )
    check_parser.set_defaults(func=cmd_check)

    # check-batch subcommand
    batch_parser = subparsers.add_parser(
        "check-batch",
        help="Check a directory of action JSON files against a rules file.",
    )
    batch_parser.add_argument(
        "directory",
        help="Directory containing action JSON files (non-recursive *.json).",
    )
    batch_parser.add_argument(
        "--rules",
        default=None,
        help="Path to rules YAML/JSON file. Falls back to cf.toml / CF_RULES_PATH.",
    )
    batch_parser.add_argument(
        "--config",
        default=None,
        help="Path to a cf.toml config file. Auto-discovers cf.toml in cwd when omitted.",
    )
    batch_parser.add_argument(
        "--severity-threshold",
        default=None,
        choices=["low", "medium", "high", "critical"],
        help="Ignore rules below this severity (overrides config).",
    )
    batch_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed output per action.",
    )
    batch_parser.set_defaults(func=cmd_check_batch)

    # serve-demo subcommand
    demo_parser = subparsers.add_parser(
        "serve-demo",
        help="Run a local demo with built-in scenarios (no network).",
    )
    demo_parser.set_defaults(func=cmd_serve_demo)

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
