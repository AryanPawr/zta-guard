# ZTA Guard - Zero Trust Architecture Auditor

## Overview

ZTA Guard is a Python CLI for lightweight Zero Trust Architecture checks. Phase 1 focuses on two inputs:

- Dockerfile static analysis
- Optional HTTP/HTTPS endpoint probing

The tool reports findings by severity and ZTA category, calculates a weighted score, renders a Rich terminal summary for humans, and can export Prometheus-compatible metrics for automation.

## Install

```bash
pip install -e .
```

Runtime dependencies are intentionally small:

- `requests`
- `rich`

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

Export machine-readable metrics:

```bash
zta export-metrics --path .
zta export-metrics --path . --target-url https://example.com
```

`export-metrics` prints plain Prometheus text exposition output without Rich tables or panels.

## Current Phase 1 Checks

### Dockerfile Static Analysis

- Missing `USER` directive
- Explicit root runtime user: `USER root`, `USER 0`, `USER 0:0`
- Sensitive exposed runtime ports: SSH, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch
- Unpinned or `latest` base image tags
- Multi-stage Dockerfiles, using the final stage for runtime user and ports
- All `FROM` stages for base-image pinning checks

### Endpoint Dynamic Analysis

- Plain HTTP after redirects
- Missing or weak HSTS
- Missing `includeSubDomains` in HSTS
- Wildcard CORS via `Access-Control-Allow-Origin: *`
- Sensitive response headers: `Server`, `X-Powered-By`

## Scoring

Each issue produces a penalty:

```text
penalty = severity weight * category weight
score = 100 - total penalty, clamped to 0..100
```

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
zta export-metrics --path .
```

## Phase Boundaries

Phase 1 is limited to Dockerfile and endpoint scanning.

Docker Compose, Kubernetes, dashboards, APIs, AI explanations, and advanced remediation guidance are intentionally out of scope for Phase 1 and belong to later phases.

## Disclaimer

ZTA Guard provides best-effort security insights based on static Dockerfile content and observable HTTP response behavior. Results can vary depending on deployment, CDN behavior, redirects, and request context.

## Author

Aryan Pawar
