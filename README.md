# ZTA Guard - Zero Trust Architecture Auditor

## Overview

ZTA Guard is a Python CLI for lightweight Zero Trust Architecture checks. Phase 2 focuses on deployment-aware and application-aware checks across:

- Dockerfile static analysis
- Docker Compose static analysis
- Optional HTTP/HTTPS endpoint probing

The tool reports metadata-rich findings by severity and ZTA category, calculates an exposure-aware weighted score, renders a Rich terminal summary for humans, can emit JSON for CI/CD, and can export Prometheus-compatible metrics for automation.

## Install

```bash
pip install -e .
```

Runtime dependencies are intentionally small:

- `requests`
- `rich`
- `PyYAML`

## Usage

Run a Dockerfile scan in the current directory:

```bash
zta scan
```

Scan a different directory:

```bash
zta scan --path ./my-service
```

Scan a live endpoint using either supported URL form:

```bash
zta scan https://example.com
zta scan --target-url https://example.com
zta scan --path . --target-url http://localhost:3000
```

Emit JSON instead of Rich terminal output:

```bash
zta scan --output json
zta scan --path . --target-url https://example.com --output json
```

Fail CI when HIGH severity findings exist:

```bash
zta scan --ci
zta scan --output json --ci
```

Export machine-readable metrics:

```bash
zta export-metrics --path .
zta export-metrics --path . --target-url https://example.com
```

`export-metrics` prints plain Prometheus text exposition output without Rich tables or panels.

## Current Phase 2 Checks

### Dockerfile Static Analysis

- Missing `USER` directive
- Explicit root runtime user: `USER root`, `USER 0`, `USER 0:0`
- Sensitive exposed runtime ports: SSH, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch
- Unpinned or `latest` base image tags
- Multi-stage Dockerfiles, using the final stage for runtime user and ports
- All `FROM` stages for base-image pinning checks

### Docker Compose Static Analysis

Supported Compose filenames:

- `docker-compose.yml`
- `docker-compose.yaml`
- `compose.yml`
- `compose.yaml`

Parsed service fields:

- `ports`
- `expose`
- `privileged`
- `network_mode`
- `networks`
- simple `volumes`
- simple `environment`

Rules:

- `privileged: true`
- `network_mode: host`
- public port bindings such as `0.0.0.0:8080:80`
- sensitive exposed ports
- weak or missing network isolation

### Endpoint Dynamic Analysis

- Plain HTTP after redirects
- Missing or weak HSTS
- Missing `includeSubDomains` in HSTS
- Wildcard CORS via `Access-Control-Allow-Origin: *`
- Sensitive response headers: `Server`, `X-Powered-By`
- Missing `Content-Security-Policy`
- Missing or weak `X-Frame-Options`
- Missing `X-Content-Type-Options: nosniff`
- Insecure `Set-Cookie` flags: missing `Secure`, `HttpOnly`, or `SameSite`

## Issue Metadata

Every issue includes both Phase 1-compatible fields and Phase 2 metadata:

```json
{
  "rule_id": "ZTA-HTTP-005",
  "title": "Missing Content-Security-Policy",
  "severity": "MEDIUM",
  "type": "MEDIUM",
  "category": "application_security",
  "message": "Content-Security-Policy header is missing.",
  "description": "Content-Security-Policy header is missing.",
  "recommendation": "Add a restrictive Content-Security-Policy such as default-src 'self'.",
  "source": "https://example.com",
  "exposure": "public"
}
```

## Scoring

Each issue produces a penalty:

```text
penalty = severity weight * category weight * exposure weight
score = 100 - total penalty, clamped to 0..100
```

JSON output also includes:

- scanned targets
- overall score
- risk label
- issue count
- severity breakdown
- category breakdown
- category score breakdown
- prioritized fixes
- full issue list

Risk levels:

- `80-100`: LOW RISK
- `50-79`: MEDIUM RISK
- `0-49`: HIGH RISK

## Project Structure

```text
zta-guard/
├── cli/
│   ├── __init__.py
│   └── main.py
├── core/
│   ├── __init__.py
│   ├── docker_parser.py
│   ├── orchestrator.py
│   └── rules.py
├── tests/
│   ├── test_cli.py
│   ├── test_compose_parser.py
│   ├── test_docker_parser.py
│   ├── test_orchestrator.py
│   └── test_rules.py
├── Dockerfile
├── README.md
├── requirements.txt
└── setup.py
```

## Development

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

Useful local smoke checks:

```bash
zta --help
zta scan --path .
zta scan --output json
zta scan --ci
zta export-metrics --path .
```

## Phase Boundaries

Phase 2 is limited to Dockerfile, Docker Compose, endpoint security headers, JSON output, and CI/CD exit behavior.

Kubernetes, dashboards, APIs, AI explanations, cloud integrations, SaaS features, and advanced remediation automation remain out of scope.

## Disclaimer

ZTA Guard provides best-effort security insights based on static Dockerfile content and observable HTTP response behavior. Results can vary depending on deployment, CDN behavior, redirects, and request context.

## Author

Aryan Pawar
