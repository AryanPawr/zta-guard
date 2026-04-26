import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

from core.orchestrator import (
    _calculate_score,
    _category_counts,
    _category_scores,
    _prioritized_fixes,
    _probe_endpoint,
    build_scan_report,
    export_metrics,
    run_scan,
)


class ScoringTests(unittest.TestCase):
    def test_score_examples_are_weighted_and_clamped(self):
        self.assertEqual(_calculate_score([]), 100)
        self.assertEqual(_calculate_score([{"type": "HIGH", "category": "identity"}]), 78)
        self.assertEqual(_calculate_score([{"type": "MEDIUM", "category": "supply_chain"}]), 92)
        self.assertEqual(
            _calculate_score([{"type": "HIGH", "category": "identity"} for _ in range(10)]),
            0,
        )

    def test_exposure_adjusts_score_deterministically(self):
        public_issue = {"type": "MEDIUM", "category": "network", "exposure": "public"}
        internal_issue = {"type": "MEDIUM", "category": "network", "exposure": "internal"}

        self.assertLess(_calculate_score([public_issue]), _calculate_score([internal_issue]))

    def test_category_scores_include_required_categories(self):
        issues = [
            {"type": "HIGH", "category": "identity"},
            {"type": "MEDIUM", "category": "application_security"},
        ]

        scores = _category_scores(issues)

        for category in (
            "identity",
            "network",
            "transport",
            "access_control",
            "supply_chain",
            "application_security",
        ):
            self.assertIn(category, scores)
        self.assertLess(scores["identity"], 100)
        self.assertLess(scores["application_security"], 100)

    def test_prioritized_fixes_sort_by_severity_exposure_category_and_rule_id(self):
        issues = [
            {
                "rule_id": "ZTA-HTTP-010",
                "title": "Medium",
                "type": "MEDIUM",
                "category": "network",
                "recommendation": "medium",
                "exposure": "public",
            },
            {
                "rule_id": "ZTA-COMPOSE-001",
                "title": "High Internal",
                "type": "HIGH",
                "category": "identity",
                "recommendation": "high internal",
                "exposure": "internal",
            },
            {
                "rule_id": "ZTA-COMPOSE-003",
                "title": "High Public",
                "type": "HIGH",
                "category": "network",
                "recommendation": "high public",
                "exposure": "public",
            },
        ]

        fixes = _prioritized_fixes(issues)

        self.assertEqual([fix["rule_id"] for fix in fixes], ["ZTA-COMPOSE-003", "ZTA-COMPOSE-001", "ZTA-HTTP-010"])


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

    @patch("core.orchestrator.requests.get")
    def test_probe_endpoint_preserves_multiple_set_cookie_headers(self, mock_get):
        raw_headers = Mock()
        raw_headers.get_all.return_value = [
            "sid=abc; Path=/",
            "pref=light; Secure; HttpOnly; SameSite=Lax",
        ]
        mock_get.return_value = Mock(
            url="https://example.com",
            status_code=200,
            headers={"Set-Cookie": "sid=abc; Path=/"},
            raw=Mock(headers=raw_headers),
        )

        result = _probe_endpoint("https://example.com", render=False)

        self.assertEqual(
            result["headers"]["Set-Cookie"],
            [
                "sid=abc; Path=/",
                "pref=light; Secure; HttpOnly; SameSite=Lax",
            ],
        )


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


class ReportTests(unittest.TestCase):
    def test_build_scan_report_has_required_json_fields(self):
        issues = [
            {
                "rule_id": "ZTA-DOCKER-001",
                "title": "Root",
                "severity": "HIGH",
                "type": "HIGH",
                "category": "identity",
                "message": "root",
                "description": "root",
                "recommendation": "use non-root",
                "source": "Dockerfile",
                "exposure": "internal",
            }
        ]

        report = build_scan_report(issues, ["Dockerfile @ ."])
        encoded = json.dumps(report)
        decoded = json.loads(encoded)

        for key in (
            "scanned_targets",
            "overall_score",
            "risk_label",
            "issue_count",
            "severity_breakdown",
            "category_breakdown",
            "score_breakdown_by_category",
            "prioritized_fixes",
            "issues",
        ):
            self.assertIn(key, decoded)
        self.assertEqual(decoded["issue_count"], 1)
        self.assertEqual(decoded["severity_breakdown"]["HIGH"], 1)
        self.assertEqual(decoded["category_breakdown"]["identity"], 1)
        self.assertEqual(decoded["prioritized_fixes"][0]["rule_id"], "ZTA-DOCKER-001")

    @patch("core.orchestrator.parse_compose_file")
    @patch("core.orchestrator.parse_dockerfile", return_value=None)
    def test_run_scan_integrates_compose_rules(self, mock_docker, mock_compose):
        mock_compose.return_value = {
            "_path": "/tmp/docker-compose.yml",
            "_parsed": True,
            "services": {
                "api": {
                    "privileged": True,
                    "network_mode": None,
                    "networks": ["backend"],
                    "ports": [],
                    "expose": [],
                    "volumes": [],
                    "environment": {},
                }
            },
            "networks": {"backend": {}},
            "errors": [],
        }

        issues, report = run_scan(".", render=False, output_format="json")

        self.assertEqual(issues[0]["rule_id"], "ZTA-COMPOSE-001")
        self.assertIn("Compose @ /tmp/docker-compose.yml", report["scanned_targets"])
