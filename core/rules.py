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

Issue       = Dict[str, object]
StaticRule  = Callable[[dict], List[Issue]]
ComposeRule = Callable[[dict], List[Issue]]
DynamicRule = Callable[[str, dict, int, Optional[str]], List[Issue]]

SENSITIVE_PORTS: Dict[str, str] = {
    "22":    "SSH",
    "3306":  "MySQL",
    "5432":  "PostgreSQL",
    "6379":  "Redis",
    "27017": "MongoDB",
    "9200":  "Elasticsearch",
}


def _issue(
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    recommendation: str,
    source: str,
    exposure: str = "unknown",
) -> Issue:
    """Create a metadata-rich issue while preserving Phase 1 keys."""
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "type": severity,
        "category": category,
        "message": description,
        "description": description,
        "recommendation": recommendation,
        "source": source,
        "exposure": exposure,
    }

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
        return [_issue(
            rule_id="ZTA-DOCKER-001",
            title="Container Runs As Root",
            severity="HIGH",
            category="identity",
            description="Container runs as root (UID 0). Use a non-root USER directive.",
            recommendation="Set USER to a non-root user or numeric UID in the final Dockerfile stage.",
            source=str(docker_data.get("_path", "Dockerfile")),
            exposure="internal",
        )]
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
    issues: List[Issue] = []

    for port in docker_data.get("exposed_ports", []):
        raw = port.split("/")[0]
        if raw in SENSITIVE_PORTS:
            service = SENSITIVE_PORTS[raw]
            description = (
                f"Sensitive port {raw} ({service}) exposed in image. "
                "Restrict to internal networks or remove if not required."
            )
            issues.append(_issue(
                rule_id="ZTA-DOCKER-002",
                title="Sensitive Port Exposed",
                severity="MEDIUM",
                category="network",
                description=description,
                recommendation="Remove the EXPOSE directive or restrict the service to an internal network.",
                source=str(docker_data.get("_path", "Dockerfile")),
                exposure="internal",
            ))
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
            description = (
                f"Base image '{image}' uses an unpinned or 'latest' tag. "
                "Pin to a specific version or digest (sha256:...) for supply-chain integrity."
            )
            issues.append(_issue(
                rule_id="ZTA-DOCKER-003",
                title="Unpinned Base Image",
                severity="MEDIUM",
                category="supply_chain",
                description=description,
                recommendation="Pin the base image to an immutable digest or a specific version tag.",
                source=str(docker_data.get("_path", "Dockerfile")),
                exposure="internal",
            ))
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
        return [_issue(
            rule_id="ZTA-HTTP-001",
            title="Plaintext HTTP Endpoint",
            severity="HIGH",
            category="transport",
            description=(
                "Endpoint is served over plaintext HTTP. "
                "All Zero Trust traffic must use TLS (HTTPS)."
            ),
            recommendation="Serve the endpoint over HTTPS and redirect HTTP to HTTPS.",
            source=effective_url,
            exposure="public",
        )]
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
        return [_issue(
            rule_id="ZTA-HTTP-002",
            title="Missing HSTS Header",
            severity="HIGH",
            category="transport",
            description=(
                "Strict-Transport-Security (HSTS) header is not detected. "
                "This may depend on endpoint, CDN, or request context. "
                f"Add 'max-age={RECOMMENDED_MAX_AGE}; includeSubDomains' "
                "to prevent SSL stripping."
            ),
            recommendation=f"Add Strict-Transport-Security: max-age={RECOMMENDED_MAX_AGE}; includeSubDomains.",
            source=final_url or url,
            exposure="public",
        )]

    issues: List[Issue] = []

    # ── Tier 2: max-age present but too short ─────────────────────────────────
    match = re.search(r"max-age\s*=\s*(\d+)", hsts_value, re.IGNORECASE)
    if match:
        max_age = int(match.group(1))
        if max_age < RECOMMENDED_MAX_AGE:
            issues.append(_issue(
                rule_id="ZTA-HTTP-003",
                title="Weak HSTS Max Age",
                severity="MEDIUM",
                category="transport",
                description=(
                    f"HSTS max-age={max_age} is below the recommended "
                    f"{RECOMMENDED_MAX_AGE} s (1 year). "
                    "Short directives expire before long-lived sessions do."
                ),
                recommendation=f"Set HSTS max-age to at least {RECOMMENDED_MAX_AGE} seconds.",
                source=final_url or url,
                exposure="public",
            ))

    # ── Tier 3: includeSubDomains absent ─────────────────────────────────────
    if "includesubdomains" not in hsts_value.lower():
        issues.append(_issue(
            rule_id="ZTA-HTTP-004",
            title="HSTS Missing includeSubDomains",
            severity="LOW",
            category="transport",
            description=(
                "HSTS policy is missing 'includeSubDomains'. "
                "Sub-domain cookies can be stolen via a rogue sub-domain."
            ),
            recommendation="Add includeSubDomains to the Strict-Transport-Security header.",
            source=final_url or url,
            exposure="public",
        ))

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
        return [_issue(
            rule_id="ZTA-HTTP-009",
            title="Wildcard CORS Policy",
            severity="HIGH",
            category="access_control",
            description=(
                "Access-Control-Allow-Origin: * — wildcard CORS is set. "
                "Any origin can read authenticated responses. "
                "Restrict to an explicit allowlist of trusted domains."
            ),
            recommendation="Replace wildcard CORS with an explicit allowlist of trusted origins.",
            source=final_url or url,
            exposure="public",
        )]
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
        issues.append(_issue(
            rule_id="ZTA-HTTP-010",
            title="Server Header Exposed",
            severity="LOW",
            category="information_disclosure",
            description=(
                f"'Server' header leaks software version: "
                f"'{lower_headers['server']}'. "
                "Remove or redact via reverse-proxy config."
            ),
            recommendation="Remove or redact the Server header at the application or reverse proxy layer.",
            source=final_url or url,
            exposure="public",
        ))

    if "x-powered-by" in lower_headers:
        issues.append(_issue(
            rule_id="ZTA-HTTP-011",
            title="X-Powered-By Header Exposed",
            severity="LOW",
            category="information_disclosure",
            description=(
                f"'X-Powered-By' leaks technology stack: "
                f"'{lower_headers['x-powered-by']}'. "
                "Remove via framework config (e.g. app.disable('x-powered-by') in Express)."
            ),
            recommendation="Disable framework technology headers such as X-Powered-By.",
            source=final_url or url,
            exposure="public",
        ))

    return issues


def check_content_security_policy(
    url: str,
    headers: dict,
    status_code: int,
    final_url: Optional[str] = None,
) -> List[Issue]:
    lower_headers = {k.lower(): v for k, v in headers.items()}
    if "content-security-policy" in lower_headers:
        return []
    return [_issue(
        rule_id="ZTA-HTTP-005",
        title="Missing Content-Security-Policy",
        severity="MEDIUM",
        category="application_security",
        description="Content-Security-Policy header is missing.",
        recommendation="Add a restrictive Content-Security-Policy such as default-src 'self'.",
        source=final_url or url,
        exposure="public",
    )]


def check_x_frame_options(
    url: str,
    headers: dict,
    status_code: int,
    final_url: Optional[str] = None,
) -> List[Issue]:
    lower_headers = {k.lower(): v for k, v in headers.items()}
    if lower_headers.get("x-frame-options", "").lower() in {"deny", "sameorigin"}:
        return []
    return [_issue(
        rule_id="ZTA-HTTP-006",
        title="Missing X-Frame-Options",
        severity="MEDIUM",
        category="application_security",
        description="X-Frame-Options header is missing or not set to DENY/SAMEORIGIN.",
        recommendation="Set X-Frame-Options to DENY or SAMEORIGIN to reduce clickjacking risk.",
        source=final_url or url,
        exposure="public",
    )]


def check_x_content_type_options(
    url: str,
    headers: dict,
    status_code: int,
    final_url: Optional[str] = None,
) -> List[Issue]:
    lower_headers = {k.lower(): v for k, v in headers.items()}
    if lower_headers.get("x-content-type-options", "").lower() == "nosniff":
        return []
    return [_issue(
        rule_id="ZTA-HTTP-007",
        title="Missing X-Content-Type-Options",
        severity="LOW",
        category="application_security",
        description="X-Content-Type-Options: nosniff header is missing.",
        recommendation="Set X-Content-Type-Options to nosniff.",
        source=final_url or url,
        exposure="public",
    )]


def check_set_cookie_flags(
    url: str,
    headers: dict,
    status_code: int,
    final_url: Optional[str] = None,
) -> List[Issue]:
    cookies = _get_header_values(headers, "set-cookie")
    issues: List[Issue] = []
    for cookie in cookies:
        lower_cookie = cookie.lower()
        cookie_name = cookie.split("=", maxsplit=1)[0]
        missing = []
        if "secure" not in lower_cookie:
            missing.append(("Cookie Missing Secure Flag", "Secure"))
        if "httponly" not in lower_cookie:
            missing.append(("Cookie Missing HttpOnly Flag", "HttpOnly"))
        if "samesite" not in lower_cookie:
            missing.append(("Cookie Missing SameSite Flag", "SameSite"))

        for title, flag in missing:
            issues.append(_issue(
                rule_id="ZTA-HTTP-008",
                title=title,
                severity="MEDIUM",
                category="application_security",
                description=f"Set-Cookie value for '{cookie_name}' is missing the {flag} attribute.",
                recommendation=f"Add {flag} to the Set-Cookie directive for '{cookie_name}'.",
                source=final_url or url,
                exposure="public",
            ))
    return issues


def _get_header_values(headers: dict, header_name: str) -> List[str]:
    for key, value in headers.items():
        if key.lower() == header_name:
            if isinstance(value, list):
                return [str(item) for item in value]
            return [str(value)]
    return []


# ─────────────────────────────────────────────────────────────────────────────
# COMPOSE RULES
# ─────────────────────────────────────────────────────────────────────────────

def check_compose_privileged(compose_data: dict) -> List[Issue]:
    issues: List[Issue] = []
    for service, data in compose_data.get("services", {}).items():
        if data.get("privileged") is True:
            issues.append(_issue(
                rule_id="ZTA-COMPOSE-001",
                title="Privileged Compose Service",
                severity="HIGH",
                category="identity",
                description=f"Compose service '{service}' runs with privileged: true.",
                recommendation="Remove privileged: true and grant only the specific capabilities required.",
                source=f"{compose_data.get('_path', 'compose')}:{service}",
                exposure="internal",
            ))
    return issues


def check_compose_host_network(compose_data: dict) -> List[Issue]:
    issues: List[Issue] = []
    for service, data in compose_data.get("services", {}).items():
        if str(data.get("network_mode", "")).lower() == "host":
            issues.append(_issue(
                rule_id="ZTA-COMPOSE-002",
                title="Host Network Mode",
                severity="HIGH",
                category="network",
                description=f"Compose service '{service}' uses network_mode: host.",
                recommendation="Use explicit Compose networks instead of host networking.",
                source=f"{compose_data.get('_path', 'compose')}:{service}",
                exposure="public",
            ))
    return issues


def check_compose_public_bindings(compose_data: dict) -> List[Issue]:
    issues: List[Issue] = []
    for service, data in compose_data.get("services", {}).items():
        for port in data.get("ports", []):
            if port.get("exposure") == "public" and port.get("published"):
                issues.append(_issue(
                    rule_id="ZTA-COMPOSE-003",
                    title="Public Compose Port Binding",
                    severity="MEDIUM",
                    category="network",
                    description=(
                        f"Compose service '{service}' publishes port {port.get('published')} "
                        "on a public interface."
                    ),
                    recommendation="Bind the port to 127.0.0.1 or place it behind a controlled ingress.",
                    source=f"{compose_data.get('_path', 'compose')}:{service}",
                    exposure="public",
                ))
    return issues


def check_compose_sensitive_ports(compose_data: dict) -> List[Issue]:
    issues: List[Issue] = []
    for service, data in compose_data.get("services", {}).items():
        for port in data.get("ports", []):
            target = str(port.get("target") or "").split("/")[0]
            if target in SENSITIVE_PORTS:
                exposure = str(port.get("exposure", "internal"))
                severity = "HIGH" if exposure == "public" else "MEDIUM"
                issues.append(_sensitive_compose_issue(compose_data, service, target, exposure, severity))
        for exposed in data.get("expose", []):
            target = str(exposed).split("/")[0]
            if target in SENSITIVE_PORTS:
                issues.append(_sensitive_compose_issue(compose_data, service, target, "internal", "MEDIUM"))
    return issues


def _sensitive_compose_issue(
    compose_data: dict,
    service: str,
    port: str,
    exposure: str,
    severity: str,
) -> Issue:
    service_name = SENSITIVE_PORTS[port]
    return _issue(
        rule_id="ZTA-COMPOSE-004",
        title="Sensitive Compose Port Exposed",
        severity=severity,
        category="network",
        description=f"Compose service '{service}' exposes sensitive port {port} ({service_name}).",
        recommendation="Remove the port binding or restrict it to a private network.",
        source=f"{compose_data.get('_path', 'compose')}:{service}",
        exposure=exposure,
    )


def check_compose_weak_isolation(compose_data: dict) -> List[Issue]:
    issues: List[Issue] = []
    for service, data in compose_data.get("services", {}).items():
        if not data.get("networks") or str(data.get("network_mode", "")).lower() == "host":
            issues.append(_issue(
                rule_id="ZTA-COMPOSE-005",
                title="Weak Compose Network Isolation",
                severity="MEDIUM",
                category="network",
                description=f"Compose service '{service}' does not use explicit isolated networks.",
                recommendation="Assign the service to an explicit least-privilege Compose network.",
                source=f"{compose_data.get('_path', 'compose')}:{service}",
                exposure="internal",
            ))
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
    check_content_security_policy,
    check_x_frame_options,
    check_x_content_type_options,
    check_set_cookie_flags,
]

COMPOSE_RULES: List[ComposeRule] = [
    check_compose_privileged,
    check_compose_host_network,
    check_compose_public_bindings,
    check_compose_sensitive_ports,
    check_compose_weak_isolation,
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


def run_compose_rules(compose_data: dict) -> List[Issue]:
    """Run every registered Compose rule against parsed Compose data."""
    if not compose_data or not compose_data.get("_parsed"):
        return []

    issues: List[Issue] = []
    for rule_fn in COMPOSE_RULES:
        issues.extend(rule_fn(compose_data))
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
