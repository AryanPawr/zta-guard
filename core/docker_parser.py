"""
core/docker_parser.py
─────────────────────────────────────────────────────────────────────────────
ZTA Guard — Infrastructure File Parser

Responsibilities
    • Locate and parse a Dockerfile inside a given directory
    • Return a normalised data dict for the rule engine
    • Locate and parse a Docker Compose file inside a given directory

Robustness goals
    • Case-insensitive instruction matching  (from / FROM / From all valid)
    • Comment and blank-line stripping
    • Inconsistent whitespace handling via regex split
    • Multi-port EXPOSE lines  (EXPOSE 80 443 8080)
    • Multi-stage FROM  (FROM python:3.12 AS builder → captures 'python:3.12')
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import os
import re
from typing import Optional

import yaml


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _clean_lines(raw_lines: list) -> list[str]:
    """
    Strip whitespace and drop comment / blank lines.

    A Dockerfile comment starts with '#' (after optional leading spaces).
    Inline comments are rare but not valid Dockerfile syntax, so no special
    handling is needed beyond stripping each line first.
    """
    cleaned = []
    for line in raw_lines:
        line = line.strip()
        if line and not line.startswith("#"):
            cleaned.append(line)
    return cleaned


def _split_instruction(line: str) -> tuple[str, str]:
    """
    Split a Dockerfile line into (INSTRUCTION, value).

    Uses a maxsplit=1 regex split on one-or-more whitespace characters so
    that instructions with inconsistent spacing (e.g. 'EXPOSE  80') parse
    correctly.  The instruction token is uppercased for uniform comparison.

    Returns ("", "") for malformed lines.
    """
    parts = re.split(r"\s+", line.strip(), maxsplit=1)
    if len(parts) == 2:
        return parts[0].upper(), parts[1].strip()
    if len(parts) == 1:
        return parts[0].upper(), ""
    return "", ""


# ─────────────────────────────────────────────────────────────────────────────
# DOCKERFILE
# ─────────────────────────────────────────────────────────────────────────────

def find_dockerfile(path: str) -> Optional[str]:
    """
    Locate a Dockerfile inside *path* using a case-insensitive filename check.

    A case-insensitive scan handles edge cases like 'dockerfile' on Linux.
    Returns the full file path, or None if not found.
    """
    try:
        for fname in os.listdir(path):
            if fname.lower() == "dockerfile":
                return os.path.join(path, fname)
    except (FileNotFoundError, NotADirectoryError):
        pass
    return None


def parse_dockerfile(path: str) -> Optional[dict]:
    """
    Parse a Dockerfile and return ZTA-relevant metadata.

    Return structure:
        {
            "base_image":     str | None   — final runtime FROM image reference
            "base_images":    list[str]    — all FROM image references
            "user":           str | None   — final-stage USER value (None → root)
            "exposed_ports":  list[str]    — final-stage EXPOSE values
            "_compose_ready": bool         — stub flag for Phase 2
        }

    Returns None when no Dockerfile exists at *path*.

    Notes:
        • Multi-stage builds reset runtime USER / EXPOSE metadata on each FROM.
          Only the final stage represents the shipped image runtime posture.
        • All FROM values are preserved in base_images so supply-chain rules
          can check every stage.
    """
    dockerfile_path = find_dockerfile(path)
    if not dockerfile_path:
        return None

    with open(dockerfile_path, "r", encoding="utf-8") as fh:
        raw_lines = fh.readlines()

    lines = _clean_lines(raw_lines)

    data: dict = {
        "base_image": None,
        "base_images": [],
        "user": None,
        "exposed_ports": [],
        "_compose_ready": False,   # Phase 2 placeholder
    }

    for line in lines:
        instruction, value = _split_instruction(line)

        if instruction == "FROM":
            # Multi-stage: "FROM python:3.12-slim AS builder"
            # Only the image token (before optional AS clause) is relevant.
            image = value.split()[0] if value else None
            data["base_image"] = image
            if image:
                data["base_images"].append(image)

            # A new stage starts from that image's default user and exposes no
            # ports unless this stage declares them.
            data["user"] = None
            data["exposed_ports"] = []

        elif instruction == "USER":
            # Keep the last USER directive — Docker uses the final value.
            data["user"] = value.split()[0] if value else None

        elif instruction == "EXPOSE":
            # "EXPOSE 80 443 8080/tcp" — capture every token.
            ports = value.split()
            data["exposed_ports"].extend(ports)

    return data


# ─────────────────────────────────────────────────────────────────────────────
# DOCKER COMPOSE
# ─────────────────────────────────────────────────────────────────────────────

def find_compose_file(path: str) -> Optional[str]:
    """
    Locate a docker-compose / Compose file under *path*.

    Checks canonical filenames in order of preference.
    Returns the first matching filename, or None if not found.
    """
    candidates = [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ]
    for fname in candidates:
        candidate = os.path.join(path, fname)
        if os.path.exists(candidate):
            return candidate
    return None


def parse_compose_file(path: str) -> Optional[dict]:
    """Parse a Docker Compose file into rule-engine-friendly metadata."""
    compose_path = find_compose_file(path)
    if not compose_path:
        return None

    result = {
        "_path": compose_path,
        "_parsed": False,
        "services": {},
        "networks": {},
        "errors": [],
    }

    try:
        with open(compose_path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        result["errors"].append(f"Malformed Compose YAML: {exc}")
        return result
    except OSError as exc:
        result["errors"].append(f"Unable to read Compose file: {exc}")
        return result

    if not raw:
        result["errors"].append("Compose file is empty.")
        return result

    if not isinstance(raw, dict):
        result["errors"].append("Compose file root must be a mapping.")
        return result

    services = raw.get("services")
    if not isinstance(services, dict) or not services:
        result["errors"].append("Compose file does not define services.")
        return result

    result["_parsed"] = True
    result["networks"] = raw.get("networks") if isinstance(raw.get("networks"), dict) else {}

    for service_name, service_data in services.items():
        if not isinstance(service_data, dict):
            service_data = {}

        result["services"][str(service_name)] = {
            "privileged": bool(service_data.get("privileged", False)),
            "network_mode": _string_or_none(service_data.get("network_mode")),
            "networks": _normalize_string_list(service_data.get("networks")),
            "ports": [_normalize_port(port) for port in _as_list(service_data.get("ports"))],
            "expose": [str(port) for port in _as_list(service_data.get("expose"))],
            "volumes": [str(volume) for volume in _as_list(service_data.get("volumes"))],
            "environment": _normalize_environment(service_data.get("environment")),
        }

    return result


def _string_or_none(value) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_string_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [str(key) for key in value.keys()]
    return [str(item) for item in _as_list(value)]


def _normalize_environment(value) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return {str(key): str(val) for key, val in value.items() if val is not None}

    env: dict[str, str] = {}
    for item in _as_list(value):
        text = str(item)
        if "=" in text:
            key, val = text.split("=", maxsplit=1)
            env[key] = val
    return env


def _normalize_port(value) -> dict:
    raw = str(value)
    port = {
        "raw": raw,
        "host_ip": None,
        "published": None,
        "target": None,
        "protocol": "tcp",
        "exposure": "internal",
    }

    if isinstance(value, dict):
        host_ip = value.get("host_ip") or value.get("host-ip")
        published = value.get("published")
        target = value.get("target")
        protocol = value.get("protocol", "tcp")
        port.update({
            "host_ip": str(host_ip) if host_ip is not None else None,
            "published": str(published) if published is not None else None,
            "target": _strip_protocol(str(target)) if target is not None else None,
            "protocol": str(protocol),
        })
        port["exposure"] = _port_exposure(port["host_ip"], port["published"])
        return port

    text = raw.strip().strip("'\"")
    text, protocol = _split_protocol(text)
    port["protocol"] = protocol
    pieces = text.split(":")

    if len(pieces) == 1:
        port["target"] = pieces[0]
    elif len(pieces) == 2:
        port["published"], port["target"] = pieces
    else:
        port["host_ip"] = ":".join(pieces[:-2])
        port["published"] = pieces[-2]
        port["target"] = pieces[-1]

    port["target"] = _strip_protocol(port["target"]) if port["target"] else None
    port["exposure"] = _port_exposure(port["host_ip"], port["published"])
    return port


def _split_protocol(value: str) -> tuple[str, str]:
    if "/" not in value:
        return value, "tcp"
    port_part, protocol = value.rsplit("/", maxsplit=1)
    return port_part, protocol


def _strip_protocol(value: str) -> str:
    return value.split("/", maxsplit=1)[0]


def _port_exposure(host_ip: Optional[str], published: Optional[str]) -> str:
    if not published:
        return "internal"
    if host_ip in {"127.0.0.1", "localhost", "::1"}:
        return "internal"
    return "public"
