"""
core/orchestrator.py
─────────────────────────────────────────────────────────────────────────────
ZTA Guard — Scan Orchestrator

Audit pipeline (three phases):
    Phase 1 — Static Analysis   parse Dockerfile/Compose → run static rules → render
    Phase 2 — Dynamic Analysis  probe endpoint   → run dynamic rules → render
    Phase 3 — Executive Summary aggregate issues → compute score → render panel

Scoring model:
    penalty(issue) = SEVERITY_WEIGHT[type] × CATEGORY_WEIGHT[category]
    score          = max(0, min(100, 100 − Σ penalty_i))

    SEVERITY_WEIGHT encodes how bad the class of vulnerability is in absolute
    terms.  CATEGORY_WEIGHT encodes how critical that ZTA pillar is relative
    to the others.  The product gives a risk-calibrated deduction per finding.

Public API:
    run_scan(path, target_url, render, output_format)  → List[Issue] | (List[Issue], report)
    export_metrics(issues)                             → None
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import warnings
from typing import Dict, List, Optional, Tuple

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.docker_parser import parse_compose_file, parse_dockerfile
from core.rules import Issue, run_compose_rules, run_dynamic_rules, run_static_rules

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# SCORING TABLES
# ─────────────────────────────────────────────────────────────────────────────

# Base penalty points per severity level.
# HIGH is set to 15 (not 20) so that the score reaches exactly 0 only when
# several high-impact issues co-exist, keeping the scale meaningful.
SEVERITY_WEIGHT: dict[str, float] = {
    "HIGH":   15.0,
    "MEDIUM":  8.0,
    "LOW":     3.0,
}

# Multipliers per ZTA pillar.
# Keys use underscores to match category strings emitted by rules.py.
#
# Rationale:
#   identity (×1.5)             — root containers threaten host integrity
#   transport (×1.4)            — broken TLS is the widest-open front door
#   network (×1.3)              — exposed ports multiply lateral-movement risk
#   access_control (×1.2)       — broken CORS enables cross-origin data theft
#   supply_chain (×1.0)         — baseline; risk is probabilistic, not immediate
#   general (×1.0)              — fallback for unlabelled issues
#   information_disclosure (×0.7) — low immediate exploitability; aids recon
CATEGORY_WEIGHT: dict[str, float] = {
    "identity":              1.5,
    "transport":             1.4,
    "network":               1.3,
    "access_control":        1.2,
    "application_security":   1.1,
    "supply_chain":          1.0,
    "general":               1.0,
    "information_disclosure": 0.7,
}

REQUIRED_SCORE_CATEGORIES: tuple[str, ...] = (
    "identity",
    "network",
    "transport",
    "access_control",
    "supply_chain",
    "application_security",
)

EXPOSURE_WEIGHT: dict[str, float] = {
    "public": 1.2,
    "unknown": 1.0,
    "internal": 0.8,
}

SEVERITY_COLOR: dict[str, str] = {
    "HIGH":   "bold red",
    "MEDIUM": "bold yellow",
    "LOW":    "bold cyan",
}


# ─────────────────────────────────────────────────────────────────────────────
# SCORING HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _score_issue(issue: Issue) -> float:
    """
    Compute the penalty for a single issue.

    Formula:
        penalty = SEVERITY_WEIGHT[type] × CATEGORY_WEIGHT[category]

    If the category is not in the weight table (e.g. a future rule uses a
    new category name not yet registered) it falls back to 1.0 so the
    severity weight still applies correctly rather than silently zeroing out.

    Examples (with current tables):
        HIGH   / identity              → 15.0 × 1.5 = 22.5
        HIGH   / transport             → 15.0 × 1.4 = 21.0
        MEDIUM / network               → 8.0  × 1.3 = 10.4
        MEDIUM / supply_chain          → 8.0  × 1.0 =  8.0
        LOW    / information_disclosure → 3.0  × 0.7 =  2.1
    """
    severity_pts = SEVERITY_WEIGHT.get(str(issue.get("severity", issue.get("type", "LOW"))), 3.0)
    category_mul = CATEGORY_WEIGHT.get(issue.get("category", "general"), 1.0)
    exposure_mul = EXPOSURE_WEIGHT.get(str(issue.get("exposure", "unknown")), 1.0)
    return severity_pts * category_mul * exposure_mul


def _calculate_score(issues: List[Issue]) -> int:
    """
    Compute the normalised ZTA score (0–100) for a set of issues.

    Mathematical model:
        total_penalty = Σ _score_issue(i)   for i in issues
        score         = max(0, min(100, 100 − total_penalty))

    The score is rounded to the nearest integer for display.

    Score bands (enforced by _risk_label):
        80–100  LOW RISK    — isolated minor findings
        50–79   MEDIUM RISK — meaningful gaps, remediation recommended
        0–49    HIGH RISK   — critical violations, do not deploy

    Why not normalise against a theoretical maximum?
    Dividing by a fixed maximum would let one HIGH finding look acceptable
    when 10 rules exist.  Subtracting absolute penalty points means every
    unfixed finding always reduces the score regardless of total rule count.
    """
    total_penalty = sum(_score_issue(i) for i in issues)
    return max(0, min(100, round(100 - total_penalty)))


def _risk_label(score: int) -> Tuple[str, str]:
    """Return a (label, rich_colour) pair for the given ZTA score."""
    if score >= 80:
        return "LOW RISK",    "green"
    elif score >= 50:
        return "MEDIUM RISK", "yellow"
    else:
        return "HIGH RISK",   "red"


def _severity_counts(issues: List[Issue]) -> Tuple[int, int, int]:
    """Return (high, medium, low) counts from an issue list."""
    high   = sum(1 for i in issues if i.get("type") == "HIGH")
    medium = sum(1 for i in issues if i.get("type") == "MEDIUM")
    low    = sum(1 for i in issues if i.get("type") == "LOW")
    return high, medium, low


def _category_counts(issues: List[Issue]) -> Dict[str, int]:
    counts: Dict[str, int] = {category: 0 for category in REQUIRED_SCORE_CATEGORIES}
    for issue in issues:
        category = str(issue.get("category", "general"))
        counts[category] = counts.get(category, 0) + 1
    return counts


def _category_scores(issues: List[Issue]) -> Dict[str, int]:
    scores: Dict[str, int] = {}
    categories = set(REQUIRED_SCORE_CATEGORIES)
    categories.update(str(issue.get("category", "general")) for issue in issues)
    for category in sorted(categories):
        penalty = sum(_score_issue(issue) for issue in issues if issue.get("category") == category)
        scores[category] = max(0, min(100, round(100 - penalty)))
    return scores


def _prioritized_fixes(issues: List[Issue]) -> List[dict]:
    severity_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    exposure_rank = {"public": 3, "unknown": 2, "internal": 1}

    sorted_issues = sorted(
        issues,
        key=lambda issue: (
            -severity_rank.get(str(issue.get("type", "LOW")), 0),
            -exposure_rank.get(str(issue.get("exposure", "unknown")), 0),
            -CATEGORY_WEIGHT.get(str(issue.get("category", "general")), 1.0),
            str(issue.get("rule_id", "")),
        ),
    )

    return [
        {
            "rule_id": issue.get("rule_id", ""),
            "title": issue.get("title", ""),
            "severity": issue.get("severity", issue.get("type", "")),
            "category": issue.get("category", "general"),
            "exposure": issue.get("exposure", "unknown"),
            "recommendation": issue.get("recommendation", ""),
            "source": issue.get("source", ""),
        }
        for issue in sorted_issues
    ]


def build_scan_report(issues: List[Issue], targets: List[str]) -> dict:
    score = _calculate_score(issues)
    label, _ = _risk_label(score)
    high, medium, low = _severity_counts(issues)
    return {
        "scanned_targets": targets,
        "overall_score": score,
        "risk_label": label,
        "issue_count": len(issues),
        "severity_breakdown": {
            "HIGH": high,
            "MEDIUM": medium,
            "LOW": low,
        },
        "category_breakdown": _category_counts(issues),
        "score_breakdown_by_category": _category_scores(issues),
        "prioritized_fixes": _prioritized_fixes(issues),
        "issues": issues,
    }


# ─────────────────────────────────────────────────────────────────────────────
# RENDERING
# ─────────────────────────────────────────────────────────────────────────────

def _render_issues_table(issues: List[Issue], title: str) -> None:
    """
    Render a Rich table of security findings.

    Columns:  Severity | Category | Finding

    When issues is empty a single green confirmation line is shown so the
    operator always gets explicit feedback for every phase.
    """
    if not issues:
        console.print(f"  [green]✓ No issues detected — {title}[/green]\n")
        return

    table = Table(
        title=f"[bold]{title}[/bold]",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold white on dark_blue",
        title_style="bold white",
        border_style="blue",
        expand=False,
    )
    table.add_column("Severity",  style="bold",    width=10, no_wrap=True)
    table.add_column("Category",  style="dim",     width=22, no_wrap=True)
    table.add_column("Finding",   style="default", width=64)

    for issue in issues:
        color = SEVERITY_COLOR.get(issue["type"], "white")
        table.add_row(
            f"[{color}]{issue['type']}[/{color}]",
            issue.get("category", "general"),
            str(issue["message"]),
        )

    console.print(table)
    console.print()


def _render_executive_summary(issues: List[Issue], targets: List[str]) -> None:
    """
    Render a consulting-grade executive summary panel.

    Shows: ZTA Score, Risk Level, what was audited, and per-severity counts.
    The score is colour-coded by risk band for at-a-glance assessment.
    """
    score               = _calculate_score(issues)
    label, risk_color   = _risk_label(score)
    high, medium, low   = _severity_counts(issues)

    target_str = ", ".join(targets) if targets else "none"

    body = (
        f"[bold]ZTA Score  :[/bold]  [{risk_color}]{score} / 100[/{risk_color}]\n"
        f"[bold]Risk Level :[/bold]  [{risk_color}]{label}[/{risk_color}]\n"
        f"[bold]Audited    :[/bold]  {target_str}\n\n"
        f"  [bold red]■ HIGH[/bold red] {high}   "
        f"[bold yellow]■ MEDIUM[/bold yellow] {medium}   "
        f"[bold cyan]■ LOW[/bold cyan] {low}   "
        f"[dim]│ Total: {len(issues)}[/dim]"
    )

    console.print(Panel(
        body,
        title="[bold]Executive Summary[/bold]",
        border_style="blue",
        padding=(1, 4),
    ))


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINT PROBING
# ─────────────────────────────────────────────────────────────────────────────

def _probe_endpoint(url: str, render: bool = True) -> Optional[dict]:
    """
    Issue an HTTP GET to url and return response metadata.

    verify=False is intentional: we want to reach HTTP targets and also
    surface TLS misconfiguration via rules rather than letting a cert error
    abort the probe silently.

    allow_redirects=True captures the final URL after any HTTP→HTTPS redirect
    so the HTTPS and HSTS rules evaluate the actual served response, not the
    redirect headers.
    """
    try:
        if render:
            console.print(f"  [dim]→ Probing {url} …[/dim]")

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

        resp = requests.get(url, timeout=8, allow_redirects=True, verify=False, headers=headers)
        response_headers = dict(resp.headers)
        raw_headers = getattr(getattr(resp, "raw", None), "headers", None)
        get_all = getattr(raw_headers, "get_all", None)
        if callable(get_all):
            set_cookie_values = get_all("Set-Cookie")
            if isinstance(set_cookie_values, (list, tuple)) and set_cookie_values:
                response_headers["Set-Cookie"] = list(set_cookie_values)

        return {
            "original_url": url,
            "final_url":         str(resp.url),
            "status_code": resp.status_code,
            "headers":     response_headers,
        }
    except requests.exceptions.ConnectionError:
        if render:
            console.print(f"  [red]✗ Connection refused or unreachable: {url}[/red]")
    except requests.exceptions.Timeout:
        if render:
            console.print(f"  [red]✗ Request timed out after 8 s: {url}[/red]")
    except requests.exceptions.RequestException as exc:
        if render:
            console.print(f"  [red]✗ Probe error: {exc}[/red]")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC SCAN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(
    path: str,
    target_url: Optional[str] = None,
    render: bool = True,
    output_format: str = "table",
):
    """
    Execute the full ZTA audit pipeline and return all discovered issues.

    Pipeline:
        1. Banner
        2. Static analysis  (Dockerfile @ path)
        3. Dynamic analysis (HTTP endpoint) — only if target_url provided
        4. Executive summary

    Returns the aggregated issue list so callers (e.g. export-metrics) can
    consume the result without re-running the scan.
    """
    if render:
        console.print(Panel(
            "[bold blue]ZTA Guard[/bold blue]  —  Zero Trust Architecture Auditor",
            padding=(0, 2),
            border_style="blue",
        ))

    all_issues:   List[Issue] = []
    scan_targets: List[str]   = []

    # ── Phase 1 — Static Analysis ─────────────────────────────────────────────
    if render:
        console.rule("[bold]Phase 1 — Static Analysis[/bold]", style="blue")

    docker_data = parse_dockerfile(path)
    if docker_data:
        scan_targets.append(f"Dockerfile @ {path}")
        static_issues = run_static_rules(docker_data)
        all_issues.extend(static_issues)
        if render:
            _render_issues_table(static_issues, "Dockerfile — ZTA Findings")
    else:
        if render:
            console.print(f"  [yellow]⚠  No Dockerfile found at path: {path}[/yellow]\n")

    compose_data = parse_compose_file(path)
    if compose_data:
        scan_targets.append(f"Compose @ {compose_data['_path']}")
        compose_issues = run_compose_rules(compose_data)
        all_issues.extend(compose_issues)
        if render:
            _render_issues_table(compose_issues, "Docker Compose — ZTA Findings")

    # ── Phase 2 — Dynamic Analysis ────────────────────────────────────────────
    if target_url:
        if render:
            console.rule("[bold]Phase 2 — Dynamic Analysis[/bold]", style="blue")
        scan_targets.append(target_url)

        probe = _probe_endpoint(target_url, render=render)
        if probe:
            dynamic_issues = run_dynamic_rules(
                url=probe["original_url"],
                headers=probe["headers"],
                status_code=probe["status_code"],
                final_url=probe["final_url"],
            )
            all_issues.extend(dynamic_issues)
            if render:
                _render_issues_table(dynamic_issues, f"Endpoint — {target_url}")

    # ── Phase 3 — Executive Summary ───────────────────────────────────────────
    if render:
        console.rule("[bold]Executive Summary[/bold]", style="blue")
        _render_executive_summary(all_issues, scan_targets)

    if output_format == "json":
        return all_issues, build_scan_report(all_issues, scan_targets)

    return all_issues


# ─────────────────────────────────────────────────────────────────────────────
# METRICS EXPORT
# ─────────────────────────────────────────────────────────────────────────────

def export_metrics(issues: List[Issue]) -> None:
    """
    Render scan results in Prometheus exposition format.

    Metrics emitted:
        zta_score                — overall audit score (gauge, 0–100)
        zta_issues_total         — total issue count (gauge)
        zta_issues_by_severity   — per-severity counts with label (gauge)
        zta_issues_by_category   — per-category counts with label (gauge)

    The category breakdown is new here: it lets a Prometheus alert rule target
    a specific ZTA pillar (e.g. alert if zta_issues_by_category{category="identity"} > 0).
    """
    score          = _calculate_score(issues)
    high, med, low = _severity_counts(issues)
    total          = len(issues)

    # Build per-category counts
    cat_counts: dict[str, int] = {}
    for issue in issues:
        cat = issue.get("category", "general")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    lines = [
        "# HELP zta_score Zero Trust Architecture audit score (0-100)",
        "# TYPE zta_score gauge",
        f"zta_score {score}",
        "",
        "# HELP zta_issues_total Total number of ZTA policy violations found",
        "# TYPE zta_issues_total gauge",
        f"zta_issues_total {total}",
        "",
        "# HELP zta_issues_by_severity Issues grouped by severity level",
        "# TYPE zta_issues_by_severity gauge",
        f'zta_issues_by_severity{{severity="HIGH"}} {high}',
        f'zta_issues_by_severity{{severity="MEDIUM"}} {med}',
        f'zta_issues_by_severity{{severity="LOW"}} {low}',
        "",
        "# HELP zta_issues_by_category Issues grouped by ZTA pillar",
        "# TYPE zta_issues_by_category gauge",
    ]
    for cat, count in sorted(cat_counts.items()):
        lines.append(f'zta_issues_by_category{{category="{cat}"}} {count}')

    print("\n".join(lines))
