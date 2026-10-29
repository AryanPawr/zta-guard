"""
cli/main.py
─────────────────────────────────────────────────────────────────────────────
ZTA Guard — CLI Entry Point

Design decisions
    • argparse subparsers (not positional choices)
      Each command gets its own add_parser() call, its own help text, and its
      own argument set.  The nested partner command family remains separate
      from deployment scanning and metrics arguments.

    • build_parser() is extracted from main() so it can be imported and
      tested in isolation (useful for argparse unit tests).

    • run_scan() returns the issue list.  export-metrics calls run_scan first,
      then passes the result straight to export_metrics() — no state stored,
      no redundant scan.

Usage examples
    zta scan --path ./my-service
    zta scan https://api.example.com
    zta scan --path . --target-url http://localhost:3000
    zta scan --output json --ci
    zta scan --path . --target-url https://api.example.com
    zta export-metrics --path .
    zta export-metrics --path . --target-url https://api.example.com
    zta partner evaluate --input examples/partner_access.json --as-of 2026-10-21
    zta partner audit --input examples/partner_access.json --as-of 2026-10-21 --output json
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import argparse
import json
import sys

from core.orchestrator import export_metrics, run_scan
from core.partner_access import (
    PartnerInputError,
    audit_partner_accounts,
    evaluate_partner_requests,
    load_partner_dataset,
    parse_as_of,
    render_partner_audit,
    render_partner_evaluation,
)


# ─────────────────────────────────────────────────────────────────────────────
# PARSER FACTORY
# ─────────────────────────────────────────────────────────────────────────────

class ZTAGuardArgumentParser(argparse.ArgumentParser):
    """ArgumentParser with ZTA Guard-specific cross-argument validation."""

    def parse_args(self, args=None, namespace=None):
        parsed = super().parse_args(args, namespace)

        positional_url = getattr(parsed, "target_url_positional", None)
        option_url = getattr(parsed, "target_url", None)

        if positional_url and option_url:
            self.error("provide target URL either positionally or with --target-url, not both")

        if positional_url:
            parsed.target_url = positional_url

        if hasattr(parsed, "target_url_positional"):
            delattr(parsed, "target_url_positional")

        target_url = getattr(parsed, "target_url", None)
        if target_url and not (
            target_url.startswith("http://") or target_url.startswith("https://")
        ):
            self.error("--target-url must start with http:// or https://")

        return parsed


def build_parser() -> argparse.ArgumentParser:
    """
    Construct and return the top-level argument parser.

    Subcommands
        scan            Run static + optional dynamic ZTA audit.
        export-metrics  Same scan, then emit Prometheus-format metrics.
        partner         Evaluate or audit synthetic partner-access records.

    Each subcommand registers its own --path and --target-url arguments
    independently.  This makes each command fully self-documented in --help
    and allows future commands to diverge in their argument sets without
    patching shared code.
    """
    parser = ZTAGuardArgumentParser(
        prog="zta",
        description="ZTA Guard — Zero Trust Architecture Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  zta scan --path ./my-service\n"
            "  zta scan https://api.example.com\n"
            "  zta scan --path . --target-url http://localhost:3000\n"
            "  zta scan --output json --ci\n"
            "  zta export-metrics --path .\n"
            "  zta export-metrics --path . --target-url https://api.example.com\n"
            "  zta partner evaluate --input examples/partner_access.json --as-of 2026-10-21\n"
            "  zta partner audit --input examples/partner_access.json --as-of 2026-10-21 --output json\n"
        ),
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True   # print help + exit if no subcommand given

    # ── scan ──────────────────────────────────────────────────────────────────
    scan_p = subparsers.add_parser(
        "scan",
        help="Run a ZTA audit against IaC files and/or a live endpoint",
        description="Audit Dockerfile(s) and optionally probe a live HTTP endpoint.",
    )
    _add_common_args(scan_p)

    # ── export-metrics ────────────────────────────────────────────────────────
    metrics_p = subparsers.add_parser(
        "export-metrics",
        help="Run a ZTA audit and emit results in Prometheus exposition format",
        description=(
            "Performs the same audit as 'scan', then outputs metrics in "
            "Prometheus text exposition format (suitable for /metrics scraping)."
        ),
    )
    _add_common_args(metrics_p)

    # ── partner ───────────────────────────────────────────────────────────────
    partner_p = subparsers.add_parser(
        "partner",
        help="Evaluate and audit synthetic contractor/delivery-partner access",
        description=(
            "Run the limited, read-only partner-access policy prototype against "
            "synthetic JSON data."
        ),
    )
    partner_commands = partner_p.add_subparsers(dest="partner_command", metavar="ACTION")
    partner_commands.required = True

    evaluate_p = partner_commands.add_parser(
        "evaluate",
        help="Evaluate synthetic access requests",
    )
    _add_partner_args(evaluate_p)

    audit_p = partner_commands.add_parser(
        "audit",
        help="Audit synthetic accounts for lifecycle and grant problems",
    )
    _add_partner_args(audit_p)

    return parser


def _add_common_args(subparser: argparse.ArgumentParser) -> None:
    """
    Register arguments that are shared across multiple subcommands.

    Centralising this avoids duplicating argument definitions and ensures
    that --path and --target-url have identical help text and defaults
    everywhere they appear.
    """
    subparser.add_argument(
        "target_url_positional",
        nargs="?",
        metavar="URL",
        help="Live endpoint URL to probe for dynamic analysis (optional)",
    )
    subparser.add_argument(
        "--path",
        default=".",
        metavar="PATH",
        help="Directory containing infrastructure files (default: current directory)",
    )
    subparser.add_argument(
        "--target-url",
        default=None,
        metavar="URL",
        dest="target_url",       # normalise hyphen → underscore for args.target_url
        help="Live endpoint URL to probe for dynamic analysis (optional)",
    )
    subparser.add_argument(
        "--output",
        choices=("table", "json"),
        default="table",
        help="Output format for scan results (default: table)",
    )
    subparser.add_argument(
        "--ci",
        action="store_true",
        help="Exit with status 1 when HIGH severity issues are found",
    )


def _add_partner_args(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--input",
        required=True,
        metavar="FILE",
        help="Synthetic partner policy, account, and request JSON file",
    )
    subparser.add_argument(
        "--as-of",
        required=True,
        metavar="YYYY-MM-DD",
        dest="as_of",
        help="Explicit evaluation date for reproducible results",
    )
    subparser.add_argument(
        "--output",
        choices=("table", "json"),
        default="table",
        help="Output format (default: table)",
    )


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Parse CLI arguments and dispatch to the appropriate handler.

    The dispatch table pattern used here (if/elif on args.command) is
    intentionally simple for Phase 1.  In Phase 2+, when the command count
    grows, this can be replaced with a dict-based dispatcher:

        HANDLERS = {"scan": cmd_scan, "export-metrics": cmd_export_metrics}
        HANDLERS[args.command](args)
    """
    parser = build_parser()
    args   = parser.parse_args()

    if args.command == "scan":
        render = args.output != "json"
        result = run_scan(
            path=args.path,
            target_url=args.target_url,
            render=render,
            output_format=args.output,
        )

        if args.output == "json":
            issues, report = result
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            issues = result

        if args.ci:
            has_high = any(issue.get("type") == "HIGH" for issue in issues)
            sys.exit(1 if has_high else 0)

    elif args.command == "export-metrics":
        # run_scan returns the full issue list — hand it directly to
        # export_metrics so no data is lost and no second scan is needed.
        issues = run_scan(path=args.path, target_url=args.target_url, render=False)
        export_metrics(issues)

    elif args.command == "partner":
        try:
            dataset = load_partner_dataset(args.input)
            as_of = parse_as_of(args.as_of)
            if args.partner_command == "evaluate":
                report = evaluate_partner_requests(dataset, as_of)
                renderer = render_partner_evaluation
            else:
                report = audit_partner_accounts(dataset, as_of)
                renderer = render_partner_audit
        except PartnerInputError as exc:
            parser.error(str(exc))

        if args.output == "json":
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            renderer(report)


if __name__ == "__main__":
    main()
