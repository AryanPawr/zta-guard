import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

from core.orchestrator import _calculate_score, _probe_endpoint, export_metrics, run_scan


class ScoringTests(unittest.TestCase):
    def test_score_examples_are_weighted_and_clamped(self):
        self.assertEqual(_calculate_score([]), 100)
        self.assertEqual(_calculate_score([{"type": "HIGH", "category": "identity"}]), 78)
        self.assertEqual(_calculate_score([{"type": "MEDIUM", "category": "supply_chain"}]), 92)
        self.assertEqual(
            _calculate_score([{"type": "HIGH", "category": "identity"} for _ in range(10)]),
            0,
        )


class ProbeTests(unittest.TestCase):
    @patch("core.orchestrator.requests.get")
    def test_probe_endpoint_returns_original_and_final_url(self, mock_get):
        mock_get.return_value = Mock(
            url="https://example.com",
            status_code=200,
            headers={"Strict-Transport-Security": "max-age=31536000"},
        )

        result = _probe_endpoint("http://example.com", render=False)

        self.assertEqual(result["original_url"], "http://example.com")
        self.assertEqual(result["final_url"], "https://example.com")
        mock_get.assert_called_once()


class MetricsTests(unittest.TestCase):
    def test_export_metrics_is_plain_prometheus_text(self):
        issues = [
            {"type": "HIGH", "category": "identity", "message": "root"},
            {"type": "LOW", "category": "information_disclosure", "message": "server"},
        ]
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            export_metrics(issues)

        output = stdout.getvalue()
        self.assertIn("# HELP zta_score", output)
        self.assertIn("zta_issues_total 2", output)
        self.assertIn('zta_issues_by_category{category="identity"} 1', output)
        self.assertNotIn("╭", output)
        self.assertNotIn("Metrics Export", output)

    @patch("core.orchestrator._render_executive_summary")
    @patch("core.orchestrator._render_issues_table")
    @patch("core.orchestrator.console")
    @patch("core.orchestrator.parse_dockerfile", return_value=None)
    def test_run_scan_can_skip_human_rendering_for_metrics(
        self,
        mock_parse,
        mock_console,
        mock_render_table,
        mock_summary,
    ):
        issues = run_scan(".", render=False)

        self.assertEqual(issues, [])
        mock_console.print.assert_not_called()
        mock_render_table.assert_not_called()
        mock_summary.assert_not_called()
