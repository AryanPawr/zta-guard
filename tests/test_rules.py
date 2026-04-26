import unittest

from core.rules import (
    check_compose_host_network,
    check_compose_privileged,
    check_compose_public_bindings,
    check_compose_sensitive_ports,
    check_compose_weak_isolation,
    check_content_security_policy,
    check_hsts,
    check_https_enforcement,
    check_latest_tag,
    check_root_user,
    check_set_cookie_flags,
    check_x_content_type_options,
    check_x_frame_options,
    run_compose_rules,
    run_dynamic_rules,
    run_static_rules,
    check_sensitive_headers,
)


class StaticRuleTests(unittest.TestCase):
    def assert_issue_metadata(self, issue, rule_id_prefix):
        for key in (
            "rule_id",
            "title",
            "severity",
            "type",
            "category",
            "message",
            "description",
            "recommendation",
            "source",
        ):
            self.assertIn(key, issue)
        self.assertTrue(issue["rule_id"].startswith(rule_id_prefix))
        self.assertEqual(issue["severity"], issue["type"])

    def test_root_user_rule_flags_missing_and_explicit_root_users(self):
        for user in (None, "root", "0", "0:0"):
            with self.subTest(user=user):
                issues = check_root_user({"user": user})
                self.assertEqual(len(issues), 1)
                self.assertEqual(issues[0]["type"], "HIGH")
                self.assertEqual(issues[0]["category"], "identity")
                self.assert_issue_metadata(issues[0], "ZTA-DOCKER-")

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

    def test_static_rules_return_metadata_rich_issues(self):
        issues = run_static_rules({
            "user": None,
            "base_images": ["python:latest"],
            "exposed_ports": ["6379"],
            "_path": "Dockerfile",
        })

        self.assertGreaterEqual(len(issues), 3)
        for issue in issues:
            self.assert_issue_metadata(issue, "ZTA-DOCKER-")


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
        self.assertTrue(issues[0]["rule_id"].startswith("ZTA-HTTP-"))

    def test_sensitive_headers_report_each_leak(self):
        issues = check_sensitive_headers(
            "https://example.com",
            {"Server": "nginx", "X-Powered-By": "Express"},
            200,
        )

        self.assertEqual(len(issues), 2)
        self.assertTrue(all(issue["type"] == "LOW" for issue in issues))

    def test_dynamic_rules_return_metadata_rich_issues(self):
        issues = run_dynamic_rules(
            "http://example.com",
            {
                "Access-Control-Allow-Origin": "*",
                "Server": "nginx",
                "Set-Cookie": "sid=abc",
            },
            200,
            final_url="http://example.com",
        )

        self.assertGreaterEqual(len(issues), 6)
        for issue in issues:
            for key in (
                "rule_id",
                "title",
                "severity",
                "type",
                "category",
                "message",
                "description",
                "recommendation",
                "source",
            ):
                self.assertIn(key, issue)

    def test_missing_application_security_headers_are_reported(self):
        headers = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}

        csp = check_content_security_policy("https://example.com", headers, 200)
        xfo = check_x_frame_options("https://example.com", headers, 200)
        xcto = check_x_content_type_options("https://example.com", headers, 200)

        self.assertEqual(csp[0]["rule_id"], "ZTA-HTTP-005")
        self.assertEqual(csp[0]["category"], "application_security")
        self.assertEqual(xfo[0]["rule_id"], "ZTA-HTTP-006")
        self.assertEqual(xcto[0]["rule_id"], "ZTA-HTTP-007")

    def test_secure_application_security_headers_are_not_reported(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        }

        self.assertEqual(check_content_security_policy("https://example.com", headers, 200), [])
        self.assertEqual(check_x_frame_options("https://example.com", headers, 200), [])
        self.assertEqual(check_x_content_type_options("https://example.com", headers, 200), [])

    def test_insecure_set_cookie_flags_are_reported_per_cookie(self):
        headers = {
            "Set-Cookie": [
                "sid=abc; Path=/",
                "pref=light; Secure; HttpOnly; SameSite=Lax",
            ]
        }

        issues = check_set_cookie_flags("https://example.com", headers, 200)

        self.assertEqual([issue["rule_id"] for issue in issues], ["ZTA-HTTP-008"] * 3)
        self.assertEqual(
            sorted(issue["title"] for issue in issues),
            [
                "Cookie Missing HttpOnly Flag",
                "Cookie Missing SameSite Flag",
                "Cookie Missing Secure Flag",
            ],
        )


class ComposeRuleTests(unittest.TestCase):
    def _compose_data(self):
        return {
            "_path": "/tmp/docker-compose.yml",
            "_parsed": True,
            "services": {
                "api": {
                    "privileged": True,
                    "network_mode": "host",
                    "networks": [],
                    "ports": [
                        {
                            "raw": "0.0.0.0:6379:6379",
                            "host_ip": "0.0.0.0",
                            "published": "6379",
                            "target": "6379",
                            "protocol": "tcp",
                            "exposure": "public",
                        }
                    ],
                    "expose": ["3306"],
                    "volumes": [],
                    "environment": {},
                }
            },
            "networks": {},
            "errors": [],
        }

    def test_compose_privileged_detected(self):
        issues = check_compose_privileged(self._compose_data())

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["rule_id"], "ZTA-COMPOSE-001")
        self.assertEqual(issues[0]["type"], "HIGH")

    def test_compose_host_network_detected(self):
        issues = check_compose_host_network(self._compose_data())

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["rule_id"], "ZTA-COMPOSE-002")

    def test_compose_public_binding_detected(self):
        issues = check_compose_public_bindings(self._compose_data())

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["rule_id"], "ZTA-COMPOSE-003")
        self.assertEqual(issues[0]["exposure"], "public")

    def test_compose_sensitive_ports_detected_with_exposure_awareness(self):
        issues = check_compose_sensitive_ports(self._compose_data())

        self.assertEqual([issue["rule_id"] for issue in issues], ["ZTA-COMPOSE-004", "ZTA-COMPOSE-004"])
        self.assertEqual(issues[0]["type"], "HIGH")
        self.assertEqual(issues[0]["exposure"], "public")
        self.assertEqual(issues[1]["type"], "MEDIUM")
        self.assertEqual(issues[1]["exposure"], "internal")

    def test_compose_weak_isolation_detected(self):
        issues = check_compose_weak_isolation(self._compose_data())

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["rule_id"], "ZTA-COMPOSE-005")

    def test_run_compose_rules_uses_registry(self):
        issues = run_compose_rules(self._compose_data())

        self.assertGreaterEqual(len(issues), 5)
        self.assertTrue(all(issue["rule_id"].startswith("ZTA-COMPOSE-") for issue in issues))
