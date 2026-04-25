import tempfile
import unittest
from pathlib import Path

from core.docker_parser import parse_dockerfile


class DockerParserTests(unittest.TestCase):
    def _parse(self, content: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "Dockerfile").write_text(content, encoding="utf-8")
            parsed = parse_dockerfile(tmp)
        self.assertIsNotNone(parsed)
        return parsed

    def test_final_stage_user_and_ports_drive_runtime_metadata(self):
        data = self._parse(
            """
            FROM python:3.12 AS builder
            USER app
            EXPOSE 6379

            FROM python:3.12-slim
            EXPOSE 8080
            """
        )

        self.assertEqual(data["base_image"], "python:3.12-slim")
        self.assertEqual(data["base_images"], ["python:3.12", "python:3.12-slim"])
        self.assertIsNone(data["user"])
        self.assertEqual(data["exposed_ports"], ["8080"])

    def test_final_stage_user_overrides_builder_stage_user(self):
        data = self._parse(
            """
            FROM node:20 AS builder
            USER root

            FROM node:20-alpine
            USER node
            EXPOSE 3000
            """
        )

        self.assertEqual(data["user"], "node")
        self.assertEqual(data["exposed_ports"], ["3000"])

    def test_lowercase_dockerfile_name_is_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "dockerfile").write_text("FROM alpine:3.20\nUSER app\n", encoding="utf-8")
            parsed = parse_dockerfile(tmp)

        self.assertEqual(parsed["base_image"], "alpine:3.20")
        self.assertEqual(parsed["user"], "app")

    def test_missing_dockerfile_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(parse_dockerfile(tmp))
