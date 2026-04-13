# ZTA Guard — Zero Trust Architecture Auditor

## Overview

ZTA Guard is a Python-based CLI tool designed to evaluate applications against **Zero Trust Architecture (ZTA)** principles. It combines static and dynamic analysis to identify security misconfigurations early in the development lifecycle and on live systems.

---

## Key Features

### Static Analysis (Infrastructure & Container Security)

* Dockerfile parsing
* Detection of:

  * Containers running as root (least privilege violation)
  * Use of `latest` tags (supply chain risk)
  * Exposure of sensitive ports (e.g., SSH, Redis, MySQL)
* Graceful handling of missing Dockerfile with contextual insights

---

### Dynamic Analysis (Live Endpoint Scanning)

* HTTP/HTTPS enforcement checks
* HSTS validation (context-aware)
* CORS misconfiguration detection
* Sensitive header exposure detection (`Server`, `X-Powered-By`)
* Redirect-aware probing for accurate results

---

### Risk Scoring System

* Weighted scoring model:

  * Severity-based (HIGH, MEDIUM, LOW)
  * Category-based (transport, identity, network, etc.)
* Outputs:

  * ZTA Score (0–100)
  * Risk Level classification

---

### CLI Interface

* Built using `rich` for professional terminal output
* Structured sections:

  * Static Analysis
  * Dynamic Analysis
  * Executive Summary

---

## Installation

### Local Development

```bash
pip install -e .
```

### Usage

```bash
zta scan
zta scan https://example.com
zta scan --target-url http://localhost:3000
```

---

## Project Structure

```
zta-guard/
├── cli/
│   └── main.py
├── core/
│   ├── orchestrator.py
│   ├── docker_parser.py
│   ├── rules.py
│   └── ai_engine.py (future)
├── tests/
├── setup.py
├── README.md
```

---

## Use Cases

### 1. Local Development (Primary)

* Scan applications before deployment
* Identify misconfigurations early
* Integrate into CI/CD pipelines

### 2. Live System Analysis

* Evaluate deployed applications
* Detect header and transport issues
* Perform lightweight security auditing

---

## Current Status

### Phase 1 — Advanced MVP (Completed)

* Static + Dynamic analysis implemented
* Scoring system integrated
* CLI tool functional and installable

---

## Roadmap

### Phase 1.5 — Refinement

* Improve scoring normalization
* Reduce redundant checks
* Enhance contextual reporting

### Phase 2 — AI Integration

* AI-generated explanations
* Fix recommendations
* Risk prioritization

### Phase 3 — Distribution

* Dockerization
* PyPI publishing
* Optional API layer

---

## Disclaimer

This tool provides **best-effort security insights** based on observable data. Results may vary depending on environment, CDN behavior, and request context.

---

## Author

Aryan Pawar
