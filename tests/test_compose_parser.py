import tempfile
import unittest
from pathlib import Path

from core.docker_parser import parse_compose_file


class ComposeParserTests(unittest.TestCase):
    def test_missing_compose_file_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(parse_compose_file(tmp))

    def test_empty_compose_file_returns_unparsed_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "docker-compose.yml").write_text("", encoding="utf-8")

            result = parse_compose_file(tmp)

        self.assertFalse(result["_parsed"])
        self.assertEqual(result["services"], {})
        self.assertTrue(result["errors"])

    def test_malformed_yaml_returns_error_without_raising(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "compose.yaml").write_text("services:\n  api: [", encoding="utf-8")

            result = parse_compose_file(tmp)

        self.assertFalse(result["_parsed"])
        self.assertIn("errors", result)

    def test_valid_compose_file_normalizes_services(self):
        content = """
        services:
          api:
            image: example/api:1.0
            privileged: true
            network_mode: host
            ports:
              - "0.0.0.0:8080:80"
              - "127.0.0.1:5432:5432"
              - target: 6379
                published: 6379
                host_ip: 0.0.0.0
            expose:
              - "3306"
            networks:
              - backend
            volumes:
              - "./data:/data:ro"
            environment:
              DEBUG: "false"
              TOKEN: abc
          worker:
            image: example/worker:1.0
            ports:
              - 9000
            environment:
              - MODE=worker
              - EMPTY_VALUE
        networks:
          backend:
            driver: bridge
        """
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "docker-compose.yml").write_text(content, encoding="utf-8")

            result = parse_compose_file(tmp)

        self.assertTrue(result["_parsed"])
        self.assertEqual(set(result["services"]), {"api", "worker"})
        api = result["services"]["api"]
        self.assertTrue(api["privileged"])
        self.assertEqual(api["network_mode"], "host")
        self.assertEqual(api["networks"], ["backend"])
        self.assertEqual(api["environment"], {"DEBUG": "false", "TOKEN": "abc"})
        self.assertEqual(api["expose"], ["3306"])
        self.assertEqual(api["ports"][0]["host_ip"], "0.0.0.0")
        self.assertEqual(api["ports"][0]["published"], "8080")
        self.assertEqual(api["ports"][0]["target"], "80")
        self.assertEqual(api["ports"][0]["exposure"], "public")
        self.assertEqual(api["ports"][1]["exposure"], "internal")
        self.assertEqual(api["ports"][2]["host_ip"], "0.0.0.0")
        self.assertEqual(result["services"]["worker"]["environment"], {"MODE": "worker"})
