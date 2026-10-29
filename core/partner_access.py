"""Synthetic contractor and delivery-partner policy evaluation.

This module is intentionally a local, read-only demonstration.  It evaluates
JSON records in memory and never connects to an identity provider, provisions
accounts, revokes access, or handles credentials.
"""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from typing import Any, Iterable

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


PARTNER_TYPES = ("contractor", "delivery_partner")
ENGAGEMENT_STATUSES = ("active", "pending", "suspended", "inactive", "ended")
ACCOUNT_STATES = ("enabled", "disabled")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")

POLICY_LIFECYCLE_VALID = "D3-PARTNER-001-LIFECYCLE-DATA-VALID"
POLICY_ENGAGEMENT_ACTIVE = "D3-PARTNER-002-ENGAGEMENT-ACTIVE"
POLICY_TIME_BOUND = "D3-PARTNER-003-WITHIN-ENGAGEMENT-DATES"
POLICY_ACCOUNT_ENABLED = "D3-PARTNER-004-ACCOUNT-ENABLED"
POLICY_ROLE_ELIGIBLE = "D3-PARTNER-005-ROLE-ELIGIBLE-RESOURCE"
POLICY_EXPLICIT_GRANT = "D3-PARTNER-006-EXPLICIT-ACCOUNT-GRANT"
POLICY_MFA = "D3-PARTNER-007-MFA-VERIFIED"
POLICY_DEVICE = "D3-PARTNER-008-DEVICE-POSTURE"
POLICY_SEGMENTATION = "D3-PARTNER-009-SEGMENTATION-PATH"
POLICY_MONITORING = "D3-PARTNER-010-MONITORING-EVIDENCE"

EVALUATION_POLICIES = (
    POLICY_LIFECYCLE_VALID,
    POLICY_ENGAGEMENT_ACTIVE,
    POLICY_TIME_BOUND,
    POLICY_ACCOUNT_ENABLED,
    POLICY_ROLE_ELIGIBLE,
    POLICY_EXPLICIT_GRANT,
    POLICY_MFA,
    POLICY_DEVICE,
    POLICY_SEGMENTATION,
    POLICY_MONITORING,
)

CHECK_DEFINITIONS: dict[str, dict[str, str]] = {
    POLICY_LIFECYCLE_VALID: {
        "title": "Identity and lifecycle evidence is valid",
        "category": "identity",
        "severity": "HIGH",
        "source": "synthetic account identity and engagement record",
    },
    POLICY_ENGAGEMENT_ACTIVE: {
        "title": "Partner engagement is active",
        "category": "partner_access",
        "severity": "HIGH",
        "source": "synthetic account engagement status",
    },
    POLICY_TIME_BOUND: {
        "title": "Request is within engagement dates",
        "category": "partner_access",
        "severity": "HIGH",
        "source": "synthetic engagement dates and explicit as-of date",
    },
    POLICY_ACCOUNT_ENABLED: {
        "title": "Account state permits access",
        "category": "identity",
        "severity": "MEDIUM",
        "source": "synthetic account state",
    },
    POLICY_ROLE_ELIGIBLE: {
        "title": "Resource is eligible for the partner role",
        "category": "partner_access",
        "severity": "HIGH",
        "source": "synthetic role-to-resource policy",
    },
    POLICY_EXPLICIT_GRANT: {
        "title": "Account has an explicit resource grant",
        "category": "partner_access",
        "severity": "MEDIUM",
        "source": "synthetic account grant record",
    },
    POLICY_MFA: {
        "title": "MFA evidence is verified",
        "category": "identity",
        "severity": "HIGH",
        "source": "synthetic request MFA context",
    },
    POLICY_DEVICE: {
        "title": "Device posture satisfies policy",
        "category": "device_posture",
        "severity": "HIGH",
        "source": "synthetic request device context",
    },
    POLICY_SEGMENTATION: {
        "title": "Network segmentation path is allowed",
        "category": "network_segmentation",
        "severity": "HIGH",
        "source": "synthetic network zone and segmentation policy",
    },
    POLICY_MONITORING: {
        "title": "Required monitoring evidence is present",
        "category": "monitoring",
        "severity": "MEDIUM",
        "source": "synthetic request telemetry assertions",
    },
}

AUDIT_CHECK_DEFINITIONS: dict[str, dict[str, str]] = {
    "D3-PARTNER-AUDIT-001-NO-ACCESS-AFTER-END": {
        "title": "Ended engagement has no enabled account",
        "category": "partner_access",
        "severity": "HIGH",
        "source": "synthetic account and engagement record",
    },
    "D3-PARTNER-AUDIT-002-NO-ACCESS-AFTER-EXPIRY": {
        "title": "Expired engagement has no enabled account",
        "category": "partner_access",
        "severity": "HIGH",
        "source": "synthetic account and engagement record",
    },
    "D3-PARTNER-AUDIT-003-ENABLED-REQUIRES-VALID-LIFECYCLE": {
        "title": "Enabled account has valid lifecycle data",
        "category": "identity",
        "severity": "HIGH",
        "source": "synthetic account and engagement record",
    },
    "D3-PARTNER-AUDIT-004-ACCOUNT-DATA-VALID": {
        "title": "Account identity and state data is valid",
        "category": "identity",
        "severity": "HIGH",
        "source": "synthetic account record",
    },
    "D3-PARTNER-AUDIT-005-GRANTS-VALID": {
        "title": "Explicit grant data is valid",
        "category": "partner_access",
        "severity": "HIGH",
        "source": "synthetic account grant record",
    },
    "D3-PARTNER-AUDIT-006-LEAST-PRIVILEGE-GRANTS": {
        "title": "Explicit grants remain role eligible",
        "category": "partner_access",
        "severity": "MEDIUM",
        "source": "synthetic account grants and role-to-resource policy",
    },
    "D3-PARTNER-AUDIT-007-NONACTIVE-ACCOUNT-DISABLED": {
        "title": "Non-active engagement has no enabled account",
        "category": "partner_access",
        "severity": "HIGH",
        "source": "synthetic account and engagement record",
    },
}

console = Console()


class PartnerInputError(ValueError):
    """Raised when the input document itself cannot be evaluated safely."""


def parse_as_of(value: str) -> date:
    """Parse an explicit, canonical ISO date used for reproducible results."""
    parsed, error = _parse_date(value, "--as-of")
    if error:
        raise PartnerInputError(error)
    assert parsed is not None
    return parsed


def load_partner_dataset(path: str) -> dict:
    """Load and validate the outer structure of a synthetic JSON dataset."""
    source = Path(path)
    try:
        with source.open("r", encoding="utf-8") as stream:
            data = json.load(stream)
    except OSError as exc:
        raise PartnerInputError(f"unable to read partner input '{path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PartnerInputError(
            f"partner input is not valid JSON at line {exc.lineno}, column {exc.colno}"
        ) from exc

    if not isinstance(data, dict):
        raise PartnerInputError("partner input root must be a JSON object")
    if data.get("synthetic") is not True:
        raise PartnerInputError(
            "partner input must declare synthetic: true; real partner data is out of scope"
        )
    if not isinstance(data.get("accounts"), list):
        raise PartnerInputError("partner input must contain an accounts array")
    if "requests" not in data:
        data["requests"] = []
    elif not isinstance(data.get("requests"), list):
        raise PartnerInputError("partner input requests must be an array when supplied")

    _validated_policy(data.get("policy"))
    return data


def evaluate_partner_requests(dataset: dict, as_of: date) -> dict:
    """Evaluate every synthetic request and return a JSON-serialisable report."""
    policy = _validated_policy(dataset.get("policy"))
    accounts = dataset.get("accounts", [])
    requests = dataset.get("requests", [])
    account_index: dict[str, list[dict]] = {}

    for account in accounts:
        if not isinstance(account, dict):
            continue
        identity_id = account.get("identity_id")
        if isinstance(identity_id, str) and identity_id.strip():
            account_index.setdefault(identity_id, []).append(account)

    decisions = [
        _evaluate_request(request, position, account_index, policy, as_of)
        for position, request in enumerate(requests, 1)
    ]
    allowed = sum(item["decision"] == "ALLOW" for item in decisions)
    conditional = sum(item["decision"] == "CONDITIONAL" for item in decisions)
    expected = [item for item in decisions if item["expected_decision"] is not None]

    return {
        "command": "partner evaluate",
        "dataset_name": dataset.get("dataset_name", "unnamed synthetic dataset"),
        "synthetic": True,
        "as_of": as_of.isoformat(),
        "policy": {
            "policy_id": policy["policy_id"],
            "role_eligible_resources": policy["role_eligible_resources"],
            "context_requirements": policy["context_requirements"],
            "segmentation_requirements": policy["segmentation_requirements"],
            "monitoring_requirements": policy["monitoring_requirements"],
        },
        "check_catalog": _check_catalog(),
        "summary": {
            "total_requests": len(decisions),
            "allowed": allowed,
            "conditional": conditional,
            "denied": len(decisions) - allowed - conditional,
            "expected_results": len(expected),
            "expected_matches": sum(item["expectation_met"] is True for item in expected),
        },
        "decisions": decisions,
        "limitations": _limitations(),
    }


def audit_partner_accounts(dataset: dict, as_of: date) -> dict:
    """Find enabled stale/invalid accounts and least-privilege grant drift."""
    policy = _validated_policy(dataset.get("policy"))
    accounts = dataset.get("accounts", [])
    findings: list[dict] = []
    identity_counts: dict[str, int] = {}

    for account in accounts:
        if isinstance(account, dict):
            identity_id = account.get("identity_id")
            if isinstance(identity_id, str) and identity_id.strip():
                identity_counts[identity_id] = identity_counts.get(identity_id, 0) + 1

    for position, account in enumerate(accounts, 1):
        if not isinstance(account, dict):
            findings.append(_finding(
                finding_id=f"account-{position}:invalid-record",
                identity_id=f"account-{position}",
                partner_type="unknown",
                title="Malformed account record",
                priority="P1",
                severity="HIGH",
                matched_policy="D3-PARTNER-AUDIT-004-ACCOUNT-DATA-VALID",
                reasons=["Account entry is not a JSON object."],
                action="Disable or quarantine the record until an owner supplies valid account data.",
            ))
            continue

        identity_id = _display_value(account.get("identity_id"), f"account-{position}")
        partner_type = _display_value(account.get("partner_type"), "unknown")
        account_state = account.get("account_state")
        lifecycle = _analyse_lifecycle(account, as_of)

        if not isinstance(account.get("identity_id"), str) or not account["identity_id"].strip():
            findings.append(_finding(
                finding_id=f"account-{position}:invalid-identity",
                identity_id=identity_id,
                partner_type=partner_type,
                title="Invalid account identity",
                priority="P1",
                severity="HIGH",
                matched_policy="D3-PARTNER-AUDIT-004-ACCOUNT-DATA-VALID",
                reasons=["identity_id must be a non-empty string."],
                action="Fail closed and reconcile the record with an authoritative identity owner.",
            ))

        if account.get("partner_type") not in PARTNER_TYPES:
            findings.append(_finding(
                finding_id=f"{identity_id}:invalid-partner-type",
                identity_id=identity_id,
                partner_type=partner_type,
                title="Invalid partner type",
                priority="P1",
                severity="HIGH",
                matched_policy="D3-PARTNER-AUDIT-004-ACCOUNT-DATA-VALID",
                reasons=["partner_type must be contractor or delivery_partner."],
                action="Fail closed and classify the account before assigning access.",
            ))

        if identity_counts.get(identity_id, 0) > 1:
            findings.append(_finding(
                finding_id=f"{identity_id}:ambiguous-identity",
                identity_id=identity_id,
                partner_type=partner_type,
                title="Ambiguous duplicate identity",
                priority="P1",
                severity="HIGH",
                matched_policy="D3-PARTNER-AUDIT-004-ACCOUNT-DATA-VALID",
                reasons=["More than one account record uses this identity_id."],
                action="Disable duplicate records and reconcile the authoritative account owner.",
            ))

        if account_state not in ACCOUNT_STATES:
            findings.append(_finding(
                finding_id=f"{identity_id}:invalid-account-state",
                identity_id=identity_id,
                partner_type=partner_type,
                title="Invalid account state",
                priority="P1",
                severity="HIGH",
                matched_policy="D3-PARTNER-AUDIT-004-ACCOUNT-DATA-VALID",
                reasons=["account_state must be exactly 'enabled' or 'disabled'."],
                action="Fail closed and correct the account state in the authoritative lifecycle record.",
            ))

        if account_state == "enabled":
            lifecycle_finding = _enabled_lifecycle_finding(
                identity_id, partner_type, lifecycle, as_of
            )
            if lifecycle_finding:
                findings.append(lifecycle_finding)

        grant_finding = _grant_audit_finding(account, identity_id, partner_type, policy)
        if grant_finding:
            findings.append(grant_finding)

    findings = _dedupe_findings(findings)
    findings.sort(key=lambda item: (item["priority"], item["identity_id"], item["finding_id"]))
    priority_counts = {
        priority: sum(item["priority"] == priority for item in findings)
        for priority in ("P1", "P2", "P3")
    }

    return {
        "command": "partner audit",
        "dataset_name": dataset.get("dataset_name", "unnamed synthetic dataset"),
        "synthetic": True,
        "as_of": as_of.isoformat(),
        "policy_id": policy["policy_id"],
        "check_catalog": _audit_check_catalog(),
        "summary": {
            "accounts_checked": len(accounts),
            "finding_count": len(findings),
            "priority_breakdown": priority_counts,
        },
        "findings": findings,
        "limitations": _limitations(),
    }


def render_partner_evaluation(report: dict) -> None:
    """Render an evaluation report for a human at the terminal."""
    summary = report["summary"]
    console.print(Panel(
        f"[bold]As of:[/bold] {report['as_of']}\n"
        f"[bold]Requests:[/bold] {summary['total_requests']}  "
        f"[green]ALLOW {summary['allowed']}[/green]  "
        f"[yellow]CONDITIONAL {summary['conditional']}[/yellow]  "
        f"[red]DENY {summary['denied']}[/red]\n"
        f"[bold]Expected scenario matches:[/bold] "
        f"{summary['expected_matches']}/{summary['expected_results']}",
        title="Synthetic Partner Access Evaluation",
        border_style="cyan",
    ))
    table = Table(box=box.SIMPLE_HEAVY, show_lines=True)
    table.add_column("Request")
    table.add_column("Identity / resource")
    table.add_column("Decision")
    table.add_column("Priority")
    table.add_column("Category / severity")
    table.add_column("Reason")
    table.add_column("Matched policy")
    table.add_column("Recommended action")
    for item in report["decisions"]:
        colour = {
            "ALLOW": "green",
            "CONDITIONAL": "yellow",
            "DENY": "red",
        }[item["decision"]]
        finding_labels = _unique(
            f"{finding['category']} / {finding['severity']}"
            for finding in item["findings"]
        )
        table.add_row(
            item["request_id"],
            f"{item['identity_id']}\n{item['resource']}",
            f"[{colour}]{item['decision']}[/{colour}]\nExpected: "
            f"{item['expected_decision'] or '-'}",
            item["priority"],
            "\n".join(finding_labels) if finding_labels else "-",
            "\n".join(reason["message"] for reason in item["reasons"]),
            "\n".join(item["matched_policies"]),
            "\n".join(item["recommended_actions"]),
        )
    console.print(table)
    console.print("[dim]Synthetic, read-only demonstration only; no real systems or accounts are changed.[/dim]")


def render_partner_audit(report: dict) -> None:
    """Render an account-audit report for a human at the terminal."""
    summary = report["summary"]
    counts = summary["priority_breakdown"]
    console.print(Panel(
        f"[bold]As of:[/bold] {report['as_of']}\n"
        f"[bold]Accounts checked:[/bold] {summary['accounts_checked']}  "
        f"[bold]Findings:[/bold] {summary['finding_count']}  "
        f"[red]P1 {counts['P1']}[/red]  [yellow]P2 {counts['P2']}[/yellow]  P3 {counts['P3']}",
        title="Synthetic Partner Account Audit",
        border_style="cyan",
    ))
    table = Table(box=box.SIMPLE_HEAVY, show_lines=True)
    table.add_column("Priority")
    table.add_column("Identity")
    table.add_column("Finding")
    table.add_column("Category / severity")
    table.add_column("Reason")
    table.add_column("Matched policy")
    table.add_column("Recommended action")
    for item in report["findings"]:
        table.add_row(
            item["priority"],
            item["identity_id"],
            item["title"],
            f"{item['category']} / {item['severity']}",
            "\n".join(item["reasons"]),
            item["matched_policy"],
            item["recommended_action"],
        )
    console.print(table)
    if not report["findings"]:
        console.print("[green]No audit findings matched the configured policies.[/green]")
    console.print("[dim]Synthetic, read-only demonstration only; no real systems or accounts are changed.[/dim]")


def _evaluate_request(
    request: Any,
    position: int,
    account_index: dict[str, list[dict]],
    policy: dict,
    as_of: date,
) -> dict:
    request_id = f"request-{position}"
    identity_id = "unknown"
    resource = "unknown"
    partner_type = "unknown"
    expected_decision = None
    failures: list[dict] = []

    if not isinstance(request, dict):
        failures.append(_failure(
            "REQUEST_DATA_INVALID",
            "Request entry is not a JSON object.",
            POLICY_LIFECYCLE_VALID,
            "Correct the synthetic request record before retrying.",
            "P1",
        ))
    else:
        request_id = _display_value(request.get("request_id"), request_id)
        identity_id = _display_value(request.get("identity_id"), "unknown")
        resource = _display_value(request.get("resource"), "unknown")
        if request.get("expected_decision") in ("ALLOW", "CONDITIONAL", "DENY"):
            expected_decision = request["expected_decision"]
        elif "expected_decision" in request:
            failures.append(_failure(
                "EXPECTED_DECISION_INVALID",
                "expected_decision must be ALLOW, CONDITIONAL, or DENY when supplied.",
                POLICY_LIFECYCLE_VALID,
                "Correct the scenario expectation.",
                "P2",
            ))

        matching_accounts = account_index.get(identity_id, [])
        if not matching_accounts:
            failures.append(_failure(
                "IDENTITY_NOT_FOUND",
                "No account record matches the request identity.",
                POLICY_LIFECYCLE_VALID,
                "Deny access and reconcile the identity with the authoritative lifecycle source.",
                "P1",
            ))
        elif len(matching_accounts) > 1:
            failures.append(_failure(
                "IDENTITY_AMBIGUOUS",
                "Multiple account records match the request identity.",
                POLICY_LIFECYCLE_VALID,
                "Deny access and reconcile duplicate account records.",
                "P1",
            ))
        else:
            account = matching_accounts[0]
            partner_type = _display_value(account.get("partner_type"), "unknown")
            failures.extend(_account_failures(account, request, policy, as_of))

    decision = (
        "DENY"
        if any(item["outcome"] == "DENY" for item in failures)
        else "CONDITIONAL"
        if failures
        else "ALLOW"
    )
    if failures:
        reasons = _unique_dicts(
            [{"code": item["code"], "message": item["message"]} for item in failures],
            ("code", "message"),
        )
        matched_policies = _unique(item["policy"] for item in failures)
        actions = _unique(item["action"] for item in failures)
        priority = min(item["priority"] for item in failures)
        findings = [
            _decision_finding(request_id, identity_id, item)
            for item in failures
        ]
    else:
        reasons = [{
            "code": "ACCESS_ALLOWED",
            "message": (
                "Identity, lifecycle, least privilege, MFA, device posture, segmentation, "
                "and monitoring checks passed."
            ),
        }]
        matched_policies = list(EVALUATION_POLICIES)
        actions = ["Continue time-bound access and re-evaluate on each request."]
        priority = "NONE"
        findings = []

    return {
        "request_id": request_id,
        "identity_id": identity_id,
        "partner_type": partner_type,
        "resource": resource,
        "decision": decision,
        "priority": priority,
        "reasons": reasons,
        "matched_policies": matched_policies,
        "recommended_actions": actions,
        "findings": findings,
        "expected_decision": expected_decision,
        "expectation_met": None if expected_decision is None else expected_decision == decision,
    }


def _account_failures(account: dict, request: dict, policy: dict, as_of: date) -> list[dict]:
    failures: list[dict] = []
    lifecycle = _analyse_lifecycle(account, as_of)

    for message in lifecycle["validation_errors"]:
        failures.append(_failure(
            "LIFECYCLE_DATA_INVALID",
            message,
            POLICY_LIFECYCLE_VALID,
            "Deny access, correct the lifecycle record, and confirm it with the engagement owner.",
            "P1",
        ))

    status = lifecycle["status"]
    if status == "inactive":
        failures.append(_failure(
            "ENGAGEMENT_INACTIVE",
            "Engagement status is inactive.",
            POLICY_ENGAGEMENT_ACTIVE,
            "Keep the account disabled until a new engagement is approved.",
            "P1",
        ))
    elif status == "ended":
        failures.append(_failure(
            "ENGAGEMENT_ENDED",
            "Engagement status is ended.",
            POLICY_ENGAGEMENT_ACTIVE,
            "Disable the account, remove grants, and review access since the engagement ended.",
            "P1",
        ))
    elif status == "pending":
        failures.append(_failure(
            "ENGAGEMENT_PENDING",
            "Engagement status is pending and access is not yet authorised.",
            POLICY_ENGAGEMENT_ACTIVE,
            "Keep the account disabled until the engagement is approved and active.",
            "P1",
        ))
    elif status == "suspended":
        failures.append(_failure(
            "ENGAGEMENT_SUSPENDED",
            "Engagement status is suspended.",
            POLICY_ENGAGEMENT_ACTIVE,
            "Keep the account disabled and require owner review before reinstatement.",
            "P1",
        ))

    start_date = lifecycle["start_date"]
    end_date = lifecycle["end_date"]
    if start_date and as_of < start_date:
        failures.append(_failure(
            "ENGAGEMENT_NOT_STARTED",
            f"Engagement starts on {start_date.isoformat()}, after the as-of date.",
            POLICY_TIME_BOUND,
            "Keep the account disabled until the approved start date.",
            "P1",
        ))
    if end_date and as_of > end_date:
        failures.append(_failure(
            "ENGAGEMENT_EXPIRED",
            f"Engagement ended on {end_date.isoformat()}, before the as-of date.",
            POLICY_TIME_BOUND,
            "Disable the account, remove grants, and review post-engagement access.",
            "P1",
        ))

    account_state = account.get("account_state")
    if account_state not in ACCOUNT_STATES:
        failures.append(_failure(
            "ACCOUNT_STATE_INVALID",
            "account_state must be exactly 'enabled' or 'disabled'.",
            POLICY_ACCOUNT_ENABLED,
            "Fail closed and correct the account state.",
            "P1",
        ))
    elif account_state != "enabled":
        failures.append(_failure(
            "ACCOUNT_DISABLED",
            "Account state is disabled.",
            POLICY_ACCOUNT_ENABLED,
            "Keep access denied unless the engagement owner approves reactivation.",
            "P2",
        ))

    partner_type = account.get("partner_type")
    if partner_type not in PARTNER_TYPES:
        failures.append(_failure(
            "PARTNER_TYPE_INVALID",
            "partner_type must be contractor or delivery_partner.",
            POLICY_ROLE_ELIGIBLE,
            "Classify the partner before assigning resources.",
            "P1",
        ))

    resource = request.get("resource")
    if not isinstance(resource, str) or not resource.strip():
        failures.append(_failure(
            "RESOURCE_INVALID",
            "Requested resource must be a non-empty string.",
            POLICY_ROLE_ELIGIBLE,
            "Correct the request and identify the target resource.",
            "P1",
        ))
    elif partner_type in PARTNER_TYPES:
        eligible = policy["role_eligible_resources"][partner_type]
        if resource not in eligible:
            failures.append(_failure(
                "RESOURCE_NOT_ROLE_ELIGIBLE",
                f"Resource '{resource}' is not eligible for partner type '{partner_type}'.",
                POLICY_ROLE_ELIGIBLE,
                "Remove the request or update the reviewed D3 role-to-resource model.",
                "P1",
            ))

    grants = account.get("granted_resources")
    if not _valid_string_list(grants):
        failures.append(_failure(
            "GRANTS_INVALID",
            "granted_resources must be an array of unique, non-empty strings.",
            POLICY_EXPLICIT_GRANT,
            "Fail closed and correct the account grant record.",
            "P1",
        ))
    elif isinstance(resource, str) and resource not in grants:
        failures.append(_failure(
            "RESOURCE_NOT_EXPLICITLY_GRANTED",
            f"Resource '{resource}' is not explicitly granted to this account.",
            POLICY_EXPLICIT_GRANT,
            "Request an owner-approved, time-bound grant if access is required.",
            "P2",
        ))

    context = request.get("context")
    if not isinstance(context, dict):
        context = {}
        failures.append(_failure(
            "REQUEST_CONTEXT_INVALID",
            "Request context is missing or malformed.",
            POLICY_MFA,
            "Deny access and collect verified MFA and device posture context.",
            "P1",
        ))

    required_mfa = policy["context_requirements"]["mfa_verified"]
    if context.get("mfa_verified") is not required_mfa:
        failures.append(_failure(
            "MFA_NOT_VERIFIED",
            "MFA verification is missing, false, or malformed.",
            POLICY_MFA,
            "Require successful MFA before re-evaluating the request.",
            "P1",
        ))

    posture = context.get("device_posture")
    allowed_postures = policy["context_requirements"]["allowed_device_postures"]
    if not isinstance(posture, str) or posture not in allowed_postures:
        failures.append(_failure(
            "DEVICE_POSTURE_NOT_ALLOWED",
            f"Device posture must be one of: {', '.join(allowed_postures)}.",
            POLICY_DEVICE,
            "Use a device with an allowed posture or remediate it before access.",
            "P1",
        ))
    elif posture in policy["context_requirements"]["conditional_device_postures"]:
        failures.append(_failure(
            "DEVICE_POSTURE_CONDITIONAL",
            f"Device posture '{posture}' permits limited or stepped-up access only.",
            POLICY_DEVICE,
            "Restrict the session and require a compliant device for full access.",
            "P2",
            outcome="CONDITIONAL",
            severity="MEDIUM",
        ))

    network_zone = context.get("network_zone")
    resource_zone = policy["segmentation_requirements"]["resource_zones"].get(resource)
    allowed_paths = policy["segmentation_requirements"]["allowed_paths"]
    if not isinstance(network_zone, str) or not network_zone.strip():
        failures.append(_failure(
            "NETWORK_ZONE_EVIDENCE_MISSING",
            "Request network_zone is missing or malformed.",
            POLICY_SEGMENTATION,
            "Fail closed and supply an asserted source zone before re-evaluating access.",
            "P1",
        ))
    elif not resource_zone:
        failures.append(_failure(
            "RESOURCE_ZONE_UNMAPPED",
            f"Resource '{resource}' has no synthetic destination-zone mapping.",
            POLICY_SEGMENTATION,
            "Define and review the resource zone before permitting access.",
            "P1",
        ))
    elif partner_type in PARTNER_TYPES and {
        "partner_type": partner_type,
        "network_zone": network_zone,
        "resource_zone": resource_zone,
    } not in allowed_paths:
        failures.append(_failure(
            "SEGMENTATION_PATH_NOT_ALLOWED",
            (
                f"Network path '{network_zone}' to '{resource_zone}' is not allowed "
                f"for partner type '{partner_type}'."
            ),
            POLICY_SEGMENTATION,
            "Use an approved partner access zone and enforcement path.",
            "P1",
        ))

    telemetry = context.get("telemetry")
    required_events = policy["monitoring_requirements"]["required_events"]
    if not isinstance(telemetry, dict):
        missing_events = list(required_events)
    else:
        missing_events = [event for event in required_events if telemetry.get(event) is not True]
    if missing_events:
        failures.append(_failure(
            "MONITORING_EVIDENCE_MISSING",
            f"Required telemetry is missing or unverified: {', '.join(missing_events)}.",
            POLICY_MONITORING,
            "Fail closed and restore the required synthetic identity, device, access, and network evidence.",
            "P1",
        ))

    return failures


def _analyse_lifecycle(account: dict, as_of: date) -> dict:
    errors: list[str] = []
    engagement = account.get("engagement")
    if not isinstance(engagement, dict):
        return {
            "status": None,
            "start_date": None,
            "end_date": None,
            "validation_errors": ["engagement must be an object with status, start_date, and end_date."],
        }

    status = engagement.get("status")
    if status not in ENGAGEMENT_STATUSES:
        errors.append(
            "engagement.status is missing or ambiguous; use active, pending, "
            "suspended, inactive, or ended."
        )

    start_date, start_error = _parse_date(engagement.get("start_date"), "engagement.start_date")
    end_date, end_error = _parse_date(engagement.get("end_date"), "engagement.end_date")
    if start_error:
        errors.append(start_error)
    if end_error:
        errors.append(end_error)
    if start_date and end_date and start_date > end_date:
        errors.append("engagement.start_date is after engagement.end_date.")
    if status == "active" and start_date and as_of < start_date:
        errors.append("engagement.status is active before the engagement start date.")
    if status == "active" and end_date and as_of > end_date:
        errors.append("engagement.status is active after the engagement end date.")
    if status == "ended" and end_date and as_of <= end_date:
        errors.append("engagement.status is ended but the end date is not before the as-of date.")

    return {
        "status": status,
        "start_date": start_date,
        "end_date": end_date,
        "validation_errors": _unique(errors),
    }


def _enabled_lifecycle_finding(
    identity_id: str,
    partner_type: str,
    lifecycle: dict,
    as_of: date,
) -> dict | None:
    status = lifecycle["status"]
    end_date = lifecycle["end_date"]
    validation_errors = lifecycle["validation_errors"]

    if status == "ended":
        reasons = ["Account is enabled although engagement.status is ended."] + validation_errors
        return _finding(
            f"{identity_id}:ended-enabled", identity_id, partner_type,
            "Enabled account after ended engagement", "P1", "HIGH",
            "D3-PARTNER-AUDIT-001-NO-ACCESS-AFTER-END", reasons,
            "Disable the account, remove grants, and review access since the engagement ended.",
        )
    if end_date and as_of > end_date:
        reasons = [
            f"Account is enabled after the engagement expired on {end_date.isoformat()}."
        ] + validation_errors
        return _finding(
            f"{identity_id}:expired-enabled", identity_id, partner_type,
            "Enabled account after expired engagement", "P1", "HIGH",
            "D3-PARTNER-AUDIT-002-NO-ACCESS-AFTER-EXPIRY", reasons,
            "Disable the account, remove grants, and review post-expiry access immediately.",
        )
    if status == "inactive":
        return _finding(
            f"{identity_id}:inactive-enabled", identity_id, partner_type,
            "Enabled account for inactive engagement", "P1", "HIGH",
            "D3-PARTNER-AUDIT-007-NONACTIVE-ACCOUNT-DISABLED",
            ["Account is enabled although engagement.status is inactive."],
            "Disable the account and retain no access until a new engagement is approved.",
        )
    if status == "pending":
        return _finding(
            f"{identity_id}:pending-enabled", identity_id, partner_type,
            "Enabled account for pending engagement", "P1", "HIGH",
            "D3-PARTNER-AUDIT-007-NONACTIVE-ACCOUNT-DISABLED",
            ["Account is enabled although engagement.status is pending."],
            "Disable the account until the engagement is approved and active.",
        )
    if status == "suspended":
        return _finding(
            f"{identity_id}:suspended-enabled", identity_id, partner_type,
            "Enabled account for suspended engagement", "P1", "HIGH",
            "D3-PARTNER-AUDIT-007-NONACTIVE-ACCOUNT-DISABLED",
            ["Account is enabled although engagement.status is suspended."],
            "Disable the account and require owner review before reinstatement.",
        )
    if validation_errors:
        return _finding(
            f"{identity_id}:invalid-lifecycle", identity_id, partner_type,
            "Enabled account with invalid lifecycle data", "P1", "HIGH",
            "D3-PARTNER-AUDIT-003-ENABLED-REQUIRES-VALID-LIFECYCLE",
            validation_errors,
            "Fail closed: disable the account, correct lifecycle data, and confirm it with the owner.",
        )
    return None


def _grant_audit_finding(account: dict, identity_id: str, partner_type: str, policy: dict) -> dict | None:
    grants = account.get("granted_resources")
    if not _valid_string_list(grants):
        return _finding(
            f"{identity_id}:invalid-grants", identity_id, partner_type,
            "Invalid explicit grant data", "P1", "HIGH",
            "D3-PARTNER-AUDIT-005-GRANTS-VALID",
            ["granted_resources must be an array of unique, non-empty strings."],
            "Fail closed and reconcile grants with the approved access record.",
        )
    if partner_type not in PARTNER_TYPES:
        return None
    eligible = policy["role_eligible_resources"][partner_type]
    excess = sorted(set(grants) - set(eligible))
    if not excess:
        return None
    return _finding(
        f"{identity_id}:ineligible-grants", identity_id, partner_type,
        "Explicit grants exceed role eligibility", "P2", "MEDIUM",
        "D3-PARTNER-AUDIT-006-LEAST-PRIVILEGE-GRANTS",
        [f"Ineligible grant: {resource}" for resource in excess],
        "Remove ineligible grants or update the reviewed D3 role-to-resource model.",
    )


def _validated_policy(value: Any) -> dict:
    if not isinstance(value, dict):
        raise PartnerInputError("partner input must contain a policy object")
    policy_id = value.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise PartnerInputError("policy.policy_id must be a non-empty string")

    eligible = value.get("role_eligible_resources")
    if not isinstance(eligible, dict):
        raise PartnerInputError("policy.role_eligible_resources must be an object")
    normalised_eligible: dict[str, list[str]] = {}
    for partner_type in PARTNER_TYPES:
        resources = eligible.get(partner_type)
        if not _valid_string_list(resources):
            raise PartnerInputError(
                f"policy.role_eligible_resources.{partner_type} must be an array "
                "of unique, non-empty strings"
            )
        normalised_eligible[partner_type] = list(resources)

    context = value.get("context_requirements")
    if not isinstance(context, dict):
        raise PartnerInputError("policy.context_requirements must be an object")
    if context.get("mfa_verified") is not True:
        raise PartnerInputError("policy.context_requirements.mfa_verified must be true")
    postures = context.get("allowed_device_postures")
    if not _valid_string_list(postures) or not postures:
        raise PartnerInputError(
            "policy.context_requirements.allowed_device_postures must be a non-empty "
            "array of unique strings"
        )

    conditional_postures = context.get("conditional_device_postures", [])
    if not _valid_string_list(conditional_postures):
        raise PartnerInputError(
            "policy.context_requirements.conditional_device_postures must be an array "
            "of unique, non-empty strings"
        )
    if set(conditional_postures) - set(postures):
        raise PartnerInputError(
            "policy.context_requirements.conditional_device_postures must be a subset "
            "of allowed_device_postures"
        )

    segmentation = value.get("segmentation_requirements")
    if not isinstance(segmentation, dict):
        raise PartnerInputError("policy.segmentation_requirements must be an object")
    resource_zones = segmentation.get("resource_zones")
    if not isinstance(resource_zones, dict):
        raise PartnerInputError(
            "policy.segmentation_requirements.resource_zones must be an object"
        )
    normalised_zones: dict[str, str] = {}
    resources = _unique(
        resource
        for eligible_resources in normalised_eligible.values()
        for resource in eligible_resources
    )
    for resource in resources:
        zone = resource_zones.get(resource)
        if not isinstance(zone, str) or not zone.strip():
            raise PartnerInputError(
                "policy.segmentation_requirements.resource_zones must map every "
                f"role-eligible resource; missing valid zone for '{resource}'"
            )
        normalised_zones[resource] = zone

    allowed_paths = segmentation.get("allowed_paths")
    if not isinstance(allowed_paths, list) or not allowed_paths:
        raise PartnerInputError(
            "policy.segmentation_requirements.allowed_paths must be a non-empty array"
        )
    normalised_paths: list[dict[str, str]] = []
    path_markers: set[tuple[str, str, str]] = set()
    for position, path in enumerate(allowed_paths, 1):
        if not isinstance(path, dict):
            raise PartnerInputError(
                f"policy.segmentation_requirements.allowed_paths[{position}] must be an object"
            )
        partner_type = path.get("partner_type")
        network_zone = path.get("network_zone")
        resource_zone = path.get("resource_zone")
        if partner_type not in PARTNER_TYPES:
            raise PartnerInputError(
                f"policy.segmentation_requirements.allowed_paths[{position}].partner_type "
                "must be contractor or delivery_partner"
            )
        if not isinstance(network_zone, str) or not network_zone.strip():
            raise PartnerInputError(
                f"policy.segmentation_requirements.allowed_paths[{position}].network_zone "
                "must be a non-empty string"
            )
        if not isinstance(resource_zone, str) or not resource_zone.strip():
            raise PartnerInputError(
                f"policy.segmentation_requirements.allowed_paths[{position}].resource_zone "
                "must be a non-empty string"
            )
        marker = (partner_type, network_zone, resource_zone)
        if marker in path_markers:
            raise PartnerInputError(
                "policy.segmentation_requirements.allowed_paths must not contain duplicates"
            )
        path_markers.add(marker)
        normalised_paths.append({
            "partner_type": partner_type,
            "network_zone": network_zone,
            "resource_zone": resource_zone,
        })

    if any(
        not any(path["partner_type"] == partner_type for path in normalised_paths)
        for partner_type in PARTNER_TYPES
    ):
        raise PartnerInputError(
            "policy.segmentation_requirements.allowed_paths must include each partner type"
        )

    monitoring = value.get("monitoring_requirements")
    if not isinstance(monitoring, dict):
        raise PartnerInputError("policy.monitoring_requirements must be an object")
    required_events = monitoring.get("required_events")
    if not _valid_string_list(required_events) or not required_events:
        raise PartnerInputError(
            "policy.monitoring_requirements.required_events must be a non-empty array "
            "of unique strings"
        )
    if not {"identity", "device", "access", "network"}.issubset(required_events):
        raise PartnerInputError(
            "policy.monitoring_requirements.required_events must include identity, "
            "device, access, and network"
        )

    return {
        "policy_id": policy_id,
        "role_eligible_resources": normalised_eligible,
        "context_requirements": {
            "mfa_verified": True,
            "allowed_device_postures": list(postures),
            "conditional_device_postures": list(conditional_postures),
        },
        "segmentation_requirements": {
            "resource_zones": normalised_zones,
            "allowed_paths": normalised_paths,
        },
        "monitoring_requirements": {
            "required_events": list(required_events),
        },
    }


def _parse_date(value: Any, field: str) -> tuple[date | None, str | None]:
    if not isinstance(value, str) or not DATE_PATTERN.fullmatch(value):
        return None, f"{field} must be a valid YYYY-MM-DD date."
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        return None, f"{field} must be a valid YYYY-MM-DD date."
    return parsed, None


def _valid_string_list(value: Any) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) and item.strip() for item in value)
        and len(value) == len(set(value))
    )


def _failure(
    code: str,
    message: str,
    policy: str,
    action: str,
    priority: str,
    *,
    outcome: str = "DENY",
    severity: str | None = None,
) -> dict:
    definition = CHECK_DEFINITIONS[policy]
    return {
        "code": code,
        "message": message,
        "policy": policy,
        "action": action,
        "priority": priority,
        "outcome": outcome,
        "title": definition["title"],
        "category": definition["category"],
        "severity": severity or definition["severity"],
        "source": definition["source"],
        "evidence": {"observed": message},
    }


def _decision_finding(request_id: str, identity_id: str, failure: dict) -> dict:
    """Return the stable D4 finding schema for a request check that did not pass."""
    return {
        "finding_id": f"{request_id}:{failure['code']}",
        "check_id": failure["policy"],
        "title": failure["title"],
        "severity": failure["severity"],
        "category": failure["category"],
        "outcome": failure["outcome"],
        "explanation": failure["message"],
        "evidence": failure["evidence"],
        "source": failure["source"],
        "remediation": failure["action"],
        "request_id": request_id,
        "identity_id": identity_id,
    }


def _check_catalog() -> list[dict]:
    return [
        {
            "check_id": check_id,
            "title": CHECK_DEFINITIONS[check_id]["title"],
            "category": CHECK_DEFINITIONS[check_id]["category"],
            "default_severity": CHECK_DEFINITIONS[check_id]["severity"],
            "source": CHECK_DEFINITIONS[check_id]["source"],
        }
        for check_id in EVALUATION_POLICIES
    ]


def _audit_check_catalog() -> list[dict]:
    return [
        {
            "check_id": check_id,
            "title": definition["title"],
            "category": definition["category"],
            "default_severity": definition["severity"],
            "source": definition["source"],
        }
        for check_id, definition in AUDIT_CHECK_DEFINITIONS.items()
    ]


def _finding(
    finding_id: str,
    identity_id: str,
    partner_type: str,
    title: str,
    priority: str,
    severity: str,
    matched_policy: str,
    reasons: list[str],
    action: str,
) -> dict:
    definition = AUDIT_CHECK_DEFINITIONS[matched_policy]
    unique_reasons = _unique(reasons)
    return {
        "finding_id": finding_id,
        "check_id": matched_policy,
        "identity_id": identity_id,
        "partner_type": partner_type,
        "title": title,
        "priority": priority,
        "severity": severity,
        "category": definition["category"],
        "outcome": "FINDING",
        "explanation": "; ".join(unique_reasons),
        "evidence": {"observed": unique_reasons},
        "source": definition["source"],
        "remediation": action,
        "reasons": unique_reasons,
        "matched_policy": matched_policy,
        "recommended_action": action,
    }
def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen: set[str] = set()
    result = []
    for finding in findings:
        key = finding["finding_id"]
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _unique_dicts(values: list[dict], keys: tuple[str, ...]) -> list[dict]:
    seen = set()
    result = []
    for value in values:
        marker = tuple(value[key] for key in keys)
        if marker not in seen:
            seen.add(marker)
            result.append(value)
    return result


def _display_value(value: Any, fallback: str) -> str:
    return value if isinstance(value, str) and value.strip() else fallback


def _limitations() -> list[str]:
    return [
        "Uses synthetic JSON data only.",
        "Does not connect to identity, HR, partner, device, or production systems.",
        "Does not provision, disable, revoke, or otherwise change accounts.",
        "Demonstrates a limited D3/D4/D5 policy slice and does not replace other project deliverables.",
    ]
