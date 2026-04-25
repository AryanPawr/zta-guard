"""
core/rules.py
─────────────────────────────────────────────────────────────────────────────
ZTA Guard — Rule Engine

All rules return a list of Issue dicts:
    {
        "type":     "HIGH" | "MEDIUM" | "LOW",
        "message":  str,
        "category": str
    }

Category vocabulary (underscore-separated — matches CATEGORY_WEIGHT keys):
    identity              user / privilege rules
    network               port exposure, segmentation
    transport             TLS, HSTS, encryption-in-transit
    access_control        CORS, authorisation headers
    supply_chain          base-image provenance, unpinned tags
    information_disclosure header leakage, verbose errors

Rules are grouped into two registries:
    STATIC_RULES  — applied to parsed Dockerfile / IaC data
    DYNAMIC_RULES — applied to a live HTTP probe result

Every dynamic rule shares the same signature:
    fn(url: str, headers: dict, status_code: int, final_url: str | None) -> list[Issue]
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional

# ── Type aliases ─────────────────────────────────────────────────────────────

Issue       = Dict[str, str]
StaticRule  = Callable[[dict], List[Issue]]
DynamicRule = Callable[[str, dict, int, Optional[str]], List[Issue]]

# ─────────────────────────────────────────────────────────────────────────────
# STATIC RULES  (Dockerfile / IaC)
# ─────────────────────────────────────────────────────────────────────────────

def check_root_user(docker_data: dict) -> List[Issue]:
    """
    HIGH / identity

    No USER directive, or an explicit root user, means the container process
    runs as UID 0 (root).
    A compromised root container can escape to the host via volume mounts,
    kernel exploits, or misconfigured runtimes.
    ZTA principle: least-privilege identity for every workload.
    """
    user = docker_data.get("user")
    user_value = "" if user is None else str(user).strip().lower()
    user_principal = user_value.split(":", maxsplit=1)[0]

    if not user_value or user_principal in {"root", "0"}:
        return [{
            "type":     "HIGH",
            "message":  "Container runs as root (UID 0). Use a non-root USER directive.",
            "category": "identity",
        }]
    return []


def check_exposed_ports(docker_data: dict) -> List[Issue]:
    """
    MEDIUM / network

    Well-known service ports exposed in the image surface unnecessary
    attack vectors. Under ZTA every open port is an implicit trust boundary.

    Flagged ports:
        22    SSH          — remote shell, brute-force target
        3306  MySQL        — cleartext auth, credential theft
        5432  PostgreSQL   — database dump risk
        6379  Redis        — no-auth-by-default, RCE via config rewrite
        27017 MongoDB      — unauthenticated access in default config
        9200  Elasticsearch— full cluster dump via REST API
    """
    SENSITIVE_PORTS: Dict[str, str] = {
        "22":    "SSH",
        "3306":  "MySQL",
        "5432":  "PostgreSQL",
        "6379":  "Redis",
        "27017": "MongoDB",
        "9200":  "Elasticsearch",
    }
    issues: List[Issue] = []

    for port in docker_data.get("exposed_ports", []):
        raw = port.split("/")[0]
        if raw in SENSITIVE_PORTS:
            service = SENSITIVE_PORTS[raw]
            issues.append({
                "type":     "MEDIUM",
                "message":  (
                    f"Sensitive port {raw} ({service}) exposed in image. "
                    "Restrict to internal networks or remove if not required."
                ),
                "category": "network",
            })
    return issues


def check_latest_tag(docker_data: dict) -> List[Issue]:
    """
    MEDIUM / supply_chain

    Unpinned base image (:latest or no tag) breaks supply-chain
    reproducibility. A compromised upstream image silently replaces the build
    without a digest change, violating ZTA's continuous-verification principle.
    """
    images = docker_data.get("base_images") or []
    if not images and docker_data.get("base_image"):
        images = [docker_data["base_image"]]

    issues: List[Issue] = []
    for image in images:
        if _is_unpinned_image(str(image)):
            issues.append({
                "type":     "MEDIUM",
                "message":  (
                    f"Base image '{image}' uses an unpinned or 'latest' tag. "
                    "Pin to a specific version or digest (sha256:...) for supply-chain integrity."
                ),
                "category": "supply_chain",
            })
    return issues


def _is_unpinned_image(image: str) -> bool:
    """
    Return True when an image reference has no explicit version tag or uses latest.

    Docker image references may include registry ports, so only a colon after the
    final slash denotes a tag. Digest-pinned references are considered pinned.
    """
    if not image:
        return False
    if "@" in image:
        return False

    last_component = image.rsplit("/", maxsplit=1)[-1]
    if ":" not in last_component:
        return True

    tag = last_component.rsplit(":", maxsplit=1)[-1]
    return tag == "latest"


# ─────────────────────────────────────────────────────────────────────────────
# DYNAMIC RULES  (HTTP endpoint probing)
# Uniform signature: (url, headers, status_code, final_url) -> List[Issue]
# ─────────────────────────────────────────────────────────────────────────────

def check_https_enforcement(
    url: str,
    headers: dict,
    status_code: int,
    final_url: Optional[str] = None,
) -> List[Issue]:
    """
    HIGH / transport

    Plain HTTP transmits credentials, tokens, and session cookies in
    cleartext. ZTA mandates TLS for every connection — internal or external.
    """
    effective_url = final_url or url
    if effective_url.startswith("http://"):
        return [{
            "type":     "HIGH",
            "message":  (
                "Endpoint is served over plaintext HTTP. "
                "All Zero Trust traffic must use TLS (HTTPS)."
            ),
            "category": "transport",
        }]
    return []


def check_hsts(
    url: str,
    headers: dict,
    status_code: int,
    final_url: Optional[str] = None,
) -> List[Issue]:
    """
    Three-tier HSTS validation — transport

    Tier 1 (HIGH)   — Header absent entirely.
        Without HSTS, a browser will happily send the first request over HTTP,
        exposing the session token to SSL stripping attacks.

    Tier 2 (MEDIUM) — max-age below 1 year (31_536_000 s).
        Short max-age windows let an attacker who captures a session still
        reach the user via HTTP once the directive expires.

    Tier 3 (LOW)    — Missing includeSubDomains.
        Sub-domain cookies can be stolen by injecting a rogue sub-domain if
        the policy does not extend across all sub-domains.

    Only the most severe Tier 1 finding is returned if the header is absent
    (Tiers 2 and 3 are implied). Tiers 2 and 3 can co-exist when the header
    is present but misconfigured.
    """
    RECOMMENDED_MAX_AGE = 31_536_000    # 1 year in seconds

    lower_headers = {k.lower(): v for k, v in headers.items()}
    hsts_value    = lower_headers.get("strict-transport-security")

    # ── Tier 1: header absent ────────────────────────────────────────────────
    if not hsts_value:
        return [{
            "type":     "HIGH",
            "message":  (
                "Strict-Transport-Security (HSTS) header is not detected. "
                "This may depend on endpoint, CDN, or request context. "
                f"Add 'max-age={RECOMMENDED_MAX_AGE}; includeSubDomains' "
                "to prevent SSL stripping."
            ),
            "category": "transport",
        }]

    issues: List[Issue] = []

    # ── Tier 2: max-age present but too short ─────────────────────────────────
    match = re.search(r"max-age\s*=\s*(\d+)", hsts_value, re.IGNORECASE)
    if match:
        max_age = int(match.group(1))
        if max_age < RECOMMENDED_MAX_AGE:
            issues.append({
                "type":     "MEDIUM",
                "message":  (
                    f"HSTS max-age={max_age} is below the recommended "
                    f"{RECOMMENDED_MAX_AGE} s (1 year). "
                    "Short directives expire before long-lived sessions do."
                ),
                "category": "transport",
            })

    # ── Tier 3: includeSubDomains absent ─────────────────────────────────────
    if "includesubdomains" not in hsts_value.lower():
        issues.append({
            "type":     "LOW",
            "message":  (
                "HSTS policy is missing 'includeSubDomains'. "
                "Sub-domain cookies can be stolen via a rogue sub-domain."
            ),
            "category": "transport",
        })

    return issues


def check_cors(
    url: str,
    headers: dict,
    status_code: int,
    final_url: Optional[str] = None,
) -> List[Issue]:
    """
    HIGH / access_control

    Access-Control-Allow-Origin: * permits any origin to read authenticated
    API responses via cross-site requests, bypassing same-origin isolation.
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    acao = lower_headers.get("access-control-allow-origin", "")

    if acao.strip() == "*":
        return [{
            "type":     "HIGH",
            "message":  (
                "Access-Control-Allow-Origin: * — wildcard CORS is set. "
                "Any origin can read authenticated responses. "
                "Restrict to an explicit allowlist of trusted domains."
            ),
            "category": "access_control",
        }]
    return []


def check_sensitive_headers(
    url: str,
    headers: dict,
    status_code: int,
    final_url: Optional[str] = None,
) -> List[Issue]:
    """
    LOW / information_disclosure

    'Server' and 'X-Powered-By' disclose exact software versions, enabling
    targeted CVE matching. Removal is zero-cost and has no functional impact.
    """
    issues: List[Issue] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    if "server" in lower_headers:
        issues.append({
            "type":     "LOW",
            "message":  (
                f"'Server' header leaks software version: "
                f"'{lower_headers['server']}'. "
                "Remove or redact via reverse-proxy config."
            ),
            "category": "information_disclosure",
        })

    if "x-powered-by" in lower_headers:
        issues.append({
            "type":     "LOW",
            "message":  (
                f"'X-Powered-By' leaks technology stack: "
                f"'{lower_headers['x-powered-by']}'. "
                "Remove via framework config (e.g. app.disable('x-powered-by') in Express)."
            ),
            "category": "information_disclosure",
        })

    return issues


# ─────────────────────────────────────────────────────────────────────────────
# RULE REGISTRIES
# ─────────────────────────────────────────────────────────────────────────────

STATIC_RULES: List[StaticRule] = [
    check_root_user,
    check_exposed_ports,
    check_latest_tag,
]

DYNAMIC_RULES: List[DynamicRule] = [
    check_https_enforcement,
    check_hsts,
    check_cors,
    check_sensitive_headers,
]


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC DISPATCH  (called by orchestrator — do not rename)
# ─────────────────────────────────────────────────────────────────────────────

def run_static_rules(docker_data: dict) -> List[Issue]:
    """Run every registered static rule against parsed Dockerfile data."""
    issues: List[Issue] = []
    for rule_fn in STATIC_RULES:
        issues.extend(rule_fn(docker_data))
    return issues


def run_dynamic_rules(
    url: str,
    headers: dict,
    status_code: int,
    final_url: Optional[str] = None,
) -> List[Issue]:
    """Run every registered dynamic rule against a live HTTP probe result."""
    issues: List[Issue] = []
    for rule_fn in DYNAMIC_RULES:
        issues.extend(rule_fn(url, headers, status_code, final_url))
    return issues
