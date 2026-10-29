# ZTA Guard - Zero Trust Architecture Auditor

## Overview

ZTA Guard is a Python CLI for lightweight Zero Trust Architecture checks. Its existing Phase 2 checks cover:

- Dockerfile static analysis
- Docker Compose static analysis
- Optional HTTP/HTTPS endpoint probing

It also includes a limited, synthetic contractor and delivery-partner access prototype. This focused extension demonstrates the project's D3 policy/access model, D4 prototype, and D5 scenario evaluation in response to the Week 6 lifecycle-control priority. It is evidence for the wider 10-week architecture project; it does not replace the current-state assessment, target architecture, implementation priorities, roadmap, report, or presentation.

Explore the results visually in the [ZTA Guard Partner Access Lab](https://aryanpawr.github.io/zta-guard/). The dashboard is a static, read-only companion to the Python CLI: it explains the included sample and can visualize locally selected CLI JSON reports without uploading them to a server.

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

### Contractor and delivery-partner prototype

Evaluate the included synthetic access scenarios using an explicit date:

```bash
zta partner evaluate --input examples/partner_access.json --as-of 2026-10-21
```

Emit the same decisions as JSON:

```bash
zta partner evaluate --input examples/partner_access.json --as-of 2026-10-21 --output json
```

Audit synthetic account records for lifecycle and least-privilege problems:

```bash
zta partner audit --input examples/partner_access.json --as-of 2026-10-21
zta partner audit --input examples/partner_access.json --as-of 2026-10-21 --output json
```

`--as-of` is required so demonstrations and tests do not depend on the computer's current date.

For setup instructions, the complete input schema, policy logic, expected scenarios, audit priorities, assumptions, limitations, and production-integration considerations, see [Contractor and Delivery-Partner Access Prototype](docs/partner-access-prototype.md).

## Partner Policy Prototype (D3/D4/D5)

The input document declares `synthetic: true` and contains a vendor-neutral policy; contractor/delivery-partner account and engagement records; explicit grants; and request context for MFA, device posture, source zone, and synthetic telemetry evidence.

The evaluator applies ten explainable checks with stable IDs:

| Checks | Category | Proposal traceability |
| --- | --- | --- |
| 001 lifecycle validity, 004 account state, 007 MFA | identity | Scope PDF p.5 (printed p.4); D4 PDF p.11 (printed p.10) |
| 008 device posture | device posture | Scope p.5; D4 p.11 |
| 009 allowed source-to-resource zone path | network segmentation | Scope p.5; D4 p.11 |
| 002 active engagement, 003 engagement dates, 005 role eligibility, 006 explicit grant | partner access / least privilege | Scope p.5; D3-D4 p.11; Week 6 client priority |
| 010 required identity/device/access/network telemetry assertions | monitoring | Scope p.5; D4 p.11 |

D3's allow/limited/deny model is represented as `ALLOW`, `CONDITIONAL`, and `DENY`. `DENY` takes precedence. Missing, malformed, inconsistent, or ambiguous required evidence fails closed. A resource must pass both role eligibility and the explicit per-account grant check. The sample's environment names, mappings, conditional posture, severities, and remediation are synthetic assumptions that Southern Logistics must validate.

The audit reports:

- Enabled accounts whose engagement is pending, suspended, ended, inactive, or expired.
- Enabled accounts with invalid lifecycle data.
- Ambiguous duplicate identities and invalid account/grant records.
- Explicit grants outside the D3 role-to-resource model.

Human and JSON reports include decisions/findings, reasons, priority, matched policy identifiers, and recommended actions. Failed/conditional checks and audit findings share fields for finding/check ID, title, severity, category, outcome, explanation, evidence, source, and remediation. Priorities use `P1` for immediate lifecycle/fail-closed action, `P2` for prompt access-model remediation, and `P3` for lower-priority observations. Successful decisions use `NONE`.

The example provides 18 D5-style scenarios. They exercise all ten checks and cover two valid requests, lifecycle states (active, pending, suspended, inactive, ended, expired, future, malformed), disabled/unknown identities, role eligibility and explicit grants, MFA/device failures, a conditional device, a prohibited segmentation path, and missing telemetry. At `2026-10-21`, expected results are 2 `ALLOW`, 1 `CONDITIONAL`, 15 `DENY`, and 18/18 expected matches. The audit checks 10 accounts and returns 8 findings (7 P1, 1 P2).

The complete requirements traceability matrix, per-check severity/remediation details, full schema and sample, all scenario mappings, client-validation assumptions, limitations, and production integration decisions are in [Contractor and Delivery-Partner Access Prototype](docs/partner-access-prototype.md).

### Minimal input shape

```json
{
  "dataset_name": "Synthetic partner scenarios",
  "synthetic": true,
  "policy": {
    "policy_id": "D3-PARTNER-ACCESS-V1",
    "role_eligible_resources": {
      "contractor": ["inventory-read"],
      "delivery_partner": ["delivery-portal"]
    },
    "context_requirements": {
      "mfa_verified": true,
      "allowed_device_postures": ["compliant", "managed"],
      "conditional_device_postures": ["managed"]
    },
    "segmentation_requirements": {
      "resource_zones": {
        "inventory-read": "warehouse",
        "delivery-portal": "third-party-partner"
      },
      "allowed_paths": [
        {"partner_type": "contractor", "network_zone": "partner", "resource_zone": "warehouse"},
        {"partner_type": "delivery_partner", "network_zone": "partner", "resource_zone": "third-party-partner"}
      ]
    },
    "monitoring_requirements": {
      "required_events": ["identity", "device", "access", "network"]
    }
  },
  "accounts": [
    {
      "identity_id": "ctr-example",
      "partner_type": "contractor",
      "engagement": {
        "status": "active",
        "start_date": "2026-10-01",
        "end_date": "2026-10-31"
      },
      "account_state": "enabled",
      "granted_resources": ["inventory-read"]
    }
  ],
  "requests": [
    {
      "request_id": "scenario-01",
      "identity_id": "ctr-example",
      "resource": "inventory-read",
      "context": {
        "mfa_verified": true,
        "device_posture": "compliant",
        "network_zone": "partner",
        "telemetry": {"identity": true, "device": true, "access": true, "network": true}
      },
      "expected_decision": "ALLOW"
    }
  ]
}
```

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
│   ├── partner_access.py
│   └── rules.py
├── examples/
│   └── partner_access.json
├── docs/
│   └── partner-access-prototype.md
├── tests/
│   ├── test_cli.py
│   ├── test_compose_parser.py
│   ├── test_docker_parser.py
│   ├── test_orchestrator.py
│   ├── test_partner_access.py
│   ├── test_partner_cli.py
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
zta partner evaluate --input examples/partner_access.json --as-of 2026-10-21
zta partner audit --input examples/partner_access.json --as-of 2026-10-21 --output json
```

## Phase Boundaries

The deployment scanner remains limited to Dockerfile, Docker Compose, endpoint security headers, JSON output, and CI/CD exit behavior. The partner feature is a separate, limited policy-assessment demonstration using local synthetic JSON only.

The partner prototype does not connect to real IAM, HR, device-management, logistics, partner, or production systems. It does not collect credentials or real partner data, provision accounts, revoke access, disable accounts, or perform remediation. Kubernetes, dashboards, APIs, AI explanations, cloud integrations, SaaS features, and advanced remediation automation also remain out of scope.

## Disclaimer

ZTA Guard provides best-effort security insights based on static Dockerfile content, observable HTTP response behavior, and explicitly supplied synthetic partner scenarios. Partner decisions are a transparent policy demonstration, not a production authorisation decision or substitute for the broader Zero Trust architecture and governance deliverables.

## Author

Aryan Pawar
