import io
import json
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from cli.main import build_parser, main


class CliTests(unittest.TestCase):
    def test_scan_accepts_positional_target_url(self):
        args = build_parser().parse_args(["scan", "https://example.com"])

        self.assertEqual(args.command, "scan")
        self.assertEqual(args.target_url, "https://example.com")

    def test_scan_rejects_conflicting_url_forms(self):
        parser = build_parser()

        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(["scan", "https://example.com", "--target-url", "https://other.com"])

    @patch("cli.main.run_scan", return_value=[])
    def test_export_metrics_runs_non_rendered_scan_once(self, mock_run_scan):
        with patch("cli.main.export_metrics") as mock_export:
            with patch("sys.argv", ["zta", "export-metrics", "--path", "."]):
                main()

        mock_run_scan.assert_called_once_with(path=".", target_url=None, render=False)
        mock_export.assert_called_once_with([])

    def test_scan_accepts_json_output_and_ci_flags(self):
        args = build_parser().parse_args(["scan", "--output", "json", "--ci"])

        self.assertEqual(args.output, "json")
        self.assertTrue(args.ci)

    @patch("cli.main.run_scan")
    def test_scan_json_prints_json_report(self, mock_run_scan):
        mock_run_scan.return_value = ([], {"overall_score": 100, "issues": []})

        with patch("sys.argv", ["zta", "scan", "--output", "json"]):
            with patch("sys.stdout", new_callable=io.StringIO) as stdout:
                main()

        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["overall_score"], 100)
        mock_run_scan.assert_called_once_with(
            path=".",
            target_url=None,
            render=False,
            output_format="json",
        )

    @patch("cli.main.run_scan")
    def test_ci_mode_exits_one_when_high_issue_exists(self, mock_run_scan):
        mock_run_scan.return_value = [{"type": "HIGH", "category": "identity"}]

        with patch("sys.argv", ["zta", "scan", "--ci"]):
            with self.assertRaises(SystemExit) as ctx:
                main()

        self.assertEqual(ctx.exception.code, 1)

    @patch("cli.main.run_scan")
    def test_ci_mode_exits_zero_without_high_issue(self, mock_run_scan):
        mock_run_scan.return_value = [{"type": "MEDIUM", "category": "network"}]

        with patch("sys.argv", ["zta", "scan", "--ci"]):
            with self.assertRaises(SystemExit) as ctx:
                main()

        self.assertEqual(ctx.exception.code, 0)

    @patch("cli.main.run_scan")
    def test_ci_mode_works_with_json_output(self, mock_run_scan):
        mock_run_scan.return_value = (
            [{"type": "HIGH", "category": "identity"}],
            {"overall_score": 50, "issues": [{"type": "HIGH"}]},
        )

        with patch("sys.argv", ["zta", "scan", "--output", "json", "--ci"]):
            with patch("sys.stdout", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as ctx:
                    main()

        self.assertEqual(ctx.exception.code, 1)
