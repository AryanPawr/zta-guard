import io
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
