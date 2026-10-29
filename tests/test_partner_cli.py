import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cli.main import build_parser, main


EXAMPLE = Path(__file__).parents[1] / "examples" / "partner_access.json"


class PartnerCliTests(unittest.TestCase):
    def test_partner_parser_requires_explicit_input_and_as_of(self):
        args = build_parser().parse_args([
            "partner",
            "evaluate",
            "--input",
            str(EXAMPLE),
            "--as-of",
            "2026-10-21",
            "--output",
            "json",
        ])

        self.assertEqual(args.command, "partner")
        self.assertEqual(args.partner_command, "evaluate")
        self.assertEqual(args.as_of, "2026-10-21")

    def test_evaluate_json_cli_runs_example_scenarios(self):
        argv = [
            "zta",
            "partner",
            "evaluate",
            "--input",
            str(EXAMPLE),
            "--as-of",
            "2026-10-21",
            "--output",
            "json",
        ]
        with patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()) as stdout:
            main()

        report = json.loads(stdout.getvalue())
        self.assertEqual(report["summary"]["total_requests"], 18)
        self.assertEqual(report["summary"]["expected_matches"], 18)
        self.assertEqual(report["summary"]["allowed"], 2)
        self.assertEqual(report["summary"]["conditional"], 1)
        self.assertEqual(report["summary"]["denied"], 15)

    def test_audit_json_cli_reports_stale_and_invalid_accounts(self):
        argv = [
            "zta",
            "partner",
            "audit",
            "--input",
            str(EXAMPLE),
            "--as-of",
            "2026-10-21",
            "--output",
            "json",
        ]
        with patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()) as stdout:
            main()

        report = json.loads(stdout.getvalue())
        self.assertEqual(report["summary"]["accounts_checked"], 10)
        self.assertEqual(report["summary"]["finding_count"], 8)
        self.assertEqual(
            report["summary"]["priority_breakdown"],
            {"P1": 7, "P2": 1, "P3": 0},
        )
        self.assertTrue(all("matched_policy" in item for item in report["findings"]))
