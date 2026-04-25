import unittest

from core.rules import (
    check_hsts,
    check_https_enforcement,
    check_latest_tag,
    check_root_user,
    check_sensitive_headers,
)


class StaticRuleTests(unittest.TestCase):
    def test_root_user_rule_flags_missing_and_explicit_root_users(self):
        for user in (None, "root", "0", "0:0"):
            with self.subTest(user=user):
                issues = check_root_user({"user": user})
                self.assertEqual(len(issues), 1)
                self.assertEqual(issues[0]["type"], "HIGH")
                self.assertEqual(issues[0]["category"], "identity")

    def test_root_user_rule_allows_non_root_users(self):
        self.assertEqual(check_root_user({"user": "node"}), [])
        self.assertEqual(check_root_user({"user": "1001"}), [])
        self.assertEqual(check_root_user({"user": "1001:1001"}), [])

    def test_latest_tag_rule_handles_registry_ports_and_digests(self):
        cases = [
            ("python", True),
            ("python:latest", True),
            ("localhost:5000/team/app", True),
            ("localhost:5000/team/app:1.2.3", False),
            ("registry.example.com:5000/app@sha256:abcdef", False),
        ]

        for image, should_flag in cases:
            with self.subTest(image=image):
                issues = check_latest_tag({"base_images": [image]})
                self.assertEqual(bool(issues), should_flag)

    def test_latest_tag_rule_checks_all_stages(self):
        issues = check_latest_tag({"base_images": ["python:3.12-slim", "node:latest"]})

        self.assertEqual(len(issues), 1)
        self.assertIn("node:latest", issues[0]["message"])


class DynamicRuleTests(unittest.TestCase):
    def test_https_enforcement_uses_final_url_after_redirects(self):
        self.assertEqual(
            check_https_enforcement(
                "http://example.com",
                {},
                200,
                final_url="https://example.com",
            ),
            [],
        )

    def test_https_enforcement_flags_plaintext_final_url(self):
        issues = check_https_enforcement(
            "http://example.com",
            {},
            200,
            final_url="http://example.com",
        )

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "HIGH")

    def test_missing_hsts_is_high_transport_issue(self):
        issues = check_hsts("https://example.com", {}, 200)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "HIGH")
        self.assertEqual(issues[0]["category"], "transport")
        self.assertIn("Add 'max-age=31536000", issues[0]["message"])

    def test_sensitive_headers_report_each_leak(self):
        issues = check_sensitive_headers(
            "https://example.com",
            {"Server": "nginx", "X-Powered-By": "Express"},
            200,
        )

        self.assertEqual(len(issues), 2)
        self.assertTrue(all(issue["type"] == "LOW" for issue in issues))
