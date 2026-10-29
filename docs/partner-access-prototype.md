# Contractor and Delivery-Partner Access Prototype

## Purpose and boundary

This is a small, read-only demonstration of vendor-neutral Zero Trust policy decisions for contractor and delivery-partner access. It supplies focused evidence for the proposal's D3 policy/access model, D4 limited prototype, and D5 scenario evaluation. The Week 6 client email made third-party lifecycle control the immediate prototype priority after an ended contractor account remained active.

The prototype does **not** claim that deliverables D1-D8, the ten-week project, or a complete Zero Trust Architecture are finished. The current-state assessment, target architecture, implementation priorities, roadmap, evaluation, report, and presentation remain separate project work.

Only local data explicitly marked `"synthetic": true` is accepted. The code evaluates JSON in memory. It never connects to Southern Logistics or any identity, HR, partner, device, network, logistics, monitoring, or production system. It cannot provision, disable, revoke, or otherwise change an account or session.

The policy values in the sample are design hypotheses for demonstration. They are not confirmed Southern Logistics requirements.

## Proposal and scope-change traceability

Page references below use the PDF page number, followed by the printed page number where different.

| Source requirement | Source | Prototype evidence | Status and boundary |
| --- | --- | --- | --- |
| Vendor-neutral ZTA spanning identity, device posture, least privilege, segmentation, monitoring, and partner access | Executive summary, PDF p.3 (printed p.2); Scope, PDF p.5 (printed p.4) | Ten stable checks cover all five prototype categories without vendor SDKs | Demonstrated with synthetic assertions; not an enterprise architecture implementation |
| Explicit, continuous verification and context-aware decisions | Goals, PDF p.4 (printed p.3) | Every request re-evaluates identity/lifecycle, grants, MFA, posture, path, and telemetry for an explicit `--as-of` date | Point-in-time simulation only; no continuous production enforcement |
| D3 decisions may be allow, limited/conditional, or deny, with constrained external access and rationale | D3, PDF p.11 (printed p.10) | `ALLOW`, `CONDITIONAL`, and `DENY`; reasons, matched check IDs, priorities, evidence, and remediation | Policy values require client approval |
| D4 should contain roughly seven or more checks across identity, device, segmentation, partner access, and monitoring | D4, PDF p.11 (printed p.10) | Ten checks in the check catalog; stable finding schema in table and JSON output | Limited CLI proof of concept |
| D4 findings should be consistent, prioritised, and remediable | D4, PDF p.11 (printed p.10) | Finding fields include ID, title, severity, category, explanation, evidence, source, and remediation; priorities are P1/P2/P3/NONE | Recommended actions are text only |
| D5 should compare inputs, expected and observed outcomes, and rationale for at least eight scenarios | D5, PDF p.11 (printed p.10) | Eighteen scenarios include `expected_decision`, `expectation_met`, observed decision, reasons, and policies | Scenario coverage is illustrative, not production acceptance testing |
| High-risk cases should be denied, restricted, or stepped up | D5, PDF p.11 (printed p.10) | Invalid or missing evidence fails closed; an accepted but restricted device posture produces `CONDITIONAL` | Step-up is represented, not performed |
| Synthetic configuration, rules, tests, and reporting within an MVP | Implementation approach, PDF p.12 (printed p.11) | `examples/partner_access.json`, `core/partner_access.py`, CLI commands, and unit/CLI tests | Complete for this limited slice only |
| No production change, real credentials/PII, purchase, penetration test, or operational rollout | Exclusions and assumptions, PDF p.6 (printed p.5) | Explicit synthetic marker; local read-only execution; limitations emitted in reports | Enforced by input validation and project boundary |
| Prioritise partner grant, time limits, cutoff at engagement end, and a quick stale-account audit without dropping wider architecture work | Week 6 client email screenshot | Lifecycle evaluation, expiry/end denial, explicit grants, and account audit; documentation preserves the broader-project boundary | Automatic cutoff is a recommended future integration, not implemented |

## Components

1. `examples/partner_access.json` contains the synthetic policy, accounts, and D5 requests.
2. `core/partner_access.py` validates input, evaluates requests, audits accounts, and builds table/JSON reports.
3. `cli/main.py` provides `zta partner evaluate` and `zta partner audit` without changing the existing scanner commands.
4. `tests/test_partner_access.py` tests policy logic and schema; `tests/test_partner_cli.py` tests the command integration and sample totals.

`evaluate` asks whether each request should be allowed, conditionally restricted, or denied. `audit` asks which account records show lifecycle or least-privilege drift.

## Quick start

Open this repository root in Codex or a terminal:

```text
/Users/aryanpawar/Documents/Codex/2026-10-21/implement-the-contractor-and-delivery-partner/zta-guard
```

It is the directory containing `README.md`, `setup.py`, `core/`, `cli/`, `examples/`, and `tests/`.

Create a virtual environment and install the command:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Run all four documented demonstrations:

```bash
zta partner evaluate --input examples/partner_access.json --as-of 2026-10-21
zta partner evaluate --input examples/partner_access.json --as-of 2026-10-21 --output json
zta partner audit --input examples/partner_access.json --as-of 2026-10-21
zta partner audit --input examples/partner_access.json --as-of 2026-10-21 --output json
```

`table` is the default, so `--output table` is optional. `--as-of` is required and must be a real date in exact `YYYY-MM-DD` form. This makes demonstrations reproducible rather than dependent on today's date.

To use another synthetic file or date, replace the two values:

```bash
zta partner evaluate --input path/to/other-synthetic.json --as-of 2026-11-15
zta partner audit --input path/to/other-synthetic.json --as-of 2026-11-15 --output json
```

## Input JSON structure

### Root

| Field | Type | Description |
| --- | --- | --- |
| `dataset_name` | string | Optional report label |
| `synthetic` | boolean | Must be exactly `true`; otherwise loading stops |
| `policy` | object | Required policy and evidence requirements |
| `accounts` | array | Required synthetic partner account records |
| `requests` | array | Synthetic requests; optional for `audit` |

### Policy

| Field | Description |
| --- | --- |
| `policy_id` | Non-empty policy version/identifier |
| `role_eligible_resources.contractor` | Unique resources that a contractor may be considered for |
| `role_eligible_resources.delivery_partner` | Unique resources that a delivery partner may be considered for |
| `context_requirements.mfa_verified` | Must be `true` in this prototype |
| `context_requirements.allowed_device_postures` | Unique postures accepted for full or conditional access |
| `context_requirements.conditional_device_postures` | Optional subset of allowed postures that yields `CONDITIONAL` when no deny check fails |
| `segmentation_requirements.resource_zones` | Destination zone for every role-eligible resource |
| `segmentation_requirements.allowed_paths` | Allowed partner type, source `network_zone`, and destination `resource_zone` triples |
| `monitoring_requirements.required_events` | Unique telemetry assertions; must include identity, device, access, and network |

### Accounts

| Field | Description |
| --- | --- |
| `identity_id` | Non-empty synthetic identity; must match uniquely |
| `partner_type` | `contractor` or `delivery_partner` |
| `engagement.status` | `active`, `pending`, `suspended`, `inactive`, or `ended` |
| `engagement.start_date` / `end_date` | Valid `YYYY-MM-DD` dates; start cannot follow end |
| `account_state` | `enabled` or `disabled` |
| `granted_resources` | Unique resources explicitly granted to this account |

### Requests

| Field | Description |
| --- | --- |
| `request_id` | Scenario identifier |
| `identity_id` | Account to evaluate |
| `resource` | Requested resource |
| `context.mfa_verified` | Must be the boolean `true` |
| `context.device_posture` | Must be allowed; may be designated conditional |
| `context.network_zone` | Synthetic source zone used for path evaluation |
| `context.telemetry` | Object whose required event keys must each be exactly `true` |
| `expected_decision` | Optional `ALLOW`, `CONDITIONAL`, or `DENY` D5 expectation |

Arrays used for resources, postures, events, and grants must contain unique, non-empty strings. Policy structure is validated before any request is evaluated.

### Small complete example

```json
{
  "dataset_name": "Synthetic partner example",
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

## Checks and decision logic

| Check ID | Category / default severity | Pass condition | Typical remediation when it fails |
| --- | --- | --- | --- |
| `D3-PARTNER-001-LIFECYCLE-DATA-VALID` | identity / HIGH | Identity and engagement data are present, valid, consistent, and uniquely matched | Reconcile with the authoritative identity/lifecycle owner |
| `D3-PARTNER-002-ENGAGEMENT-ACTIVE` | partner_access / HIGH | Status is `active`; pending, suspended, inactive, and ended are denied | Keep disabled until an approved active engagement exists |
| `D3-PARTNER-003-WITHIN-ENGAGEMENT-DATES` | partner_access / HIGH | As-of date falls within the inclusive start/end dates | Wait for start or disable/remove access after expiry |
| `D3-PARTNER-004-ACCOUNT-ENABLED` | identity / MEDIUM | Account state is `enabled` | Confirm ownership before reactivation |
| `D3-PARTNER-005-ROLE-ELIGIBLE-RESOURCE` | partner_access / HIGH | Resource appears in the partner type's eligible set | Reject it or review the D3 role model |
| `D3-PARTNER-006-EXPLICIT-ACCOUNT-GRANT` | partner_access / MEDIUM | Resource is also explicitly granted to the account | Obtain an owner-approved, time-bound grant |
| `D3-PARTNER-007-MFA-VERIFIED` | identity / HIGH | MFA evidence is exactly `true` | Require verified MFA |
| `D3-PARTNER-008-DEVICE-POSTURE` | device_posture / HIGH | Posture is allowed; sample `managed` is conditional | Restrict/step up or use a compliant device |
| `D3-PARTNER-009-SEGMENTATION-PATH` | network_segmentation / HIGH | Partner type, source zone, and resource zone match an allowed path | Use an approved partner enforcement path |
| `D3-PARTNER-010-MONITORING-EVIDENCE` | monitoring / MEDIUM | Every required synthetic telemetry assertion is exactly `true` | Restore evidence collection before re-evaluation |

Role eligibility and an explicit account grant are both required; neither overrides the other. Dates are inclusive. `DENY` takes precedence over `CONDITIONAL`. A request is `CONDITIONAL` only if no deny check failed and at least one check requires restriction or step-up. Otherwise all checks must pass for `ALLOW`.

### Fail closed

The evaluator denies when required evidence is missing, malformed, inconsistent, or ambiguous. Examples include an unknown/duplicate identity, missing or invalid dates, start after end, active status outside the date range, unknown status/type/state, missing MFA or device evidence, an unmapped/disallowed network path, or absent/unverified telemetry. Malformed top-level policy structures stop the command rather than silently weakening the policy.

## Stable finding schema

Failed or conditional request checks and all audit findings expose these common fields:

| Field | Meaning |
| --- | --- |
| `finding_id` | Stable scenario/account plus condition identifier |
| `check_id` | Stable policy or audit check ID |
| `title` | Human-readable check/finding name |
| `severity` | `HIGH`, `MEDIUM`, or another explicitly modelled severity |
| `category` | `identity`, `device_posture`, `network_segmentation`, `partner_access`, or `monitoring` |
| `outcome` | `DENY`, `CONDITIONAL`, or `FINDING` |
| `explanation` | Why this result was produced |
| `evidence` | Synthetic observed values/messages supporting the result |
| `source` | Synthetic input source used by the check |
| `remediation` | Recommended follow-up text; no action is executed |

Evaluation decisions retain convenient `reasons`, `matched_policies`, and `recommended_actions` fields. Audit findings retain `priority`, `reasons`, `matched_policy`, and `recommended_action` aliases.

## D5 scenarios and expected outcomes

The included file has eighteen scenarios for `--as-of 2026-10-21`.

| Scenario | Primary check(s) exercised | Expected |
| --- | --- | --- |
| `scenario-01-legitimate-contractor` | All ten checks pass | `ALLOW` |
| `scenario-02-ineligible-resource` | 005 role eligibility | `DENY` |
| `scenario-03-ended-engagement` | 002 engagement status | `DENY` |
| `scenario-04-not-yet-started` | 001 lifecycle consistency; 003 dates | `DENY` |
| `scenario-05-legitimate-delivery-partner` | All ten checks pass | `ALLOW` |
| `scenario-06-mfa-failure` | 007 MFA | `DENY` |
| `scenario-07-unmanaged-device` | 008 device posture | `DENY` |
| `scenario-08-disabled-account` | 004 account state | `DENY` |
| `scenario-09-missing-lifecycle-date` | 001 lifecycle data | `DENY` |
| `scenario-10-not-explicitly-granted` | 006 explicit grant | `DENY` |
| `scenario-11-expired-active-record` | 001 lifecycle consistency; 003 expiry | `DENY` |
| `scenario-12-inactive-engagement` | 002 engagement status | `DENY` |
| `scenario-13-segmentation-path-denied` | 009 segmentation | `DENY` |
| `scenario-14-monitoring-evidence-missing` | 010 monitoring | `DENY` |
| `scenario-15-conditional-device` | 008 restricted device | `CONDITIONAL` |
| `scenario-16-pending-engagement` | 002 engagement status; 003 future start | `DENY` |
| `scenario-17-suspended-engagement` | 002 engagement status | `DENY` |
| `scenario-18-unknown-identity` | 001 identity matching | `DENY` |

Expected summary:

```text
Requests: 18  ALLOW 2  CONDITIONAL 1  DENY 15
Expected scenario matches: 18/18
```

In JSON, `summary.expected_matches` should equal `summary.expected_results`. That confirms that observed outcomes matched the declared synthetic expectations; it does not prove production suitability.

## Audit findings and priorities

The audit independently detects enabled access after ended, expired, inactive, pending, or suspended engagements; enabled records with invalid lifecycle data; duplicate/invalid identities and account fields; invalid grant data; and grants outside role eligibility.

| Audit check ID | Category / severity | Meaning |
| --- | --- | --- |
| `D3-PARTNER-AUDIT-001-NO-ACCESS-AFTER-END` | partner_access / HIGH | An ended engagement must not retain an enabled account |
| `D3-PARTNER-AUDIT-002-NO-ACCESS-AFTER-EXPIRY` | partner_access / HIGH | An account must not remain enabled after its end date |
| `D3-PARTNER-AUDIT-003-ENABLED-REQUIRES-VALID-LIFECYCLE` | identity / HIGH | Enabled accounts require complete, consistent lifecycle evidence |
| `D3-PARTNER-AUDIT-004-ACCOUNT-DATA-VALID` | identity / HIGH | Identity, type, uniqueness, and state data must be valid |
| `D3-PARTNER-AUDIT-005-GRANTS-VALID` | partner_access / HIGH | Explicit grant data must be a valid unique string list |
| `D3-PARTNER-AUDIT-006-LEAST-PRIVILEGE-GRANTS` | partner_access / MEDIUM | Explicit grants must remain within role eligibility |
| `D3-PARTNER-AUDIT-007-NONACTIVE-ACCOUNT-DISABLED` | partner_access / HIGH | Pending, suspended, or inactive engagements must not retain enabled accounts |

| Priority | Prototype meaning |
| --- | --- |
| `P1` | Immediate review/fail-closed action because access may persist without a valid engagement or trusted data |
| `P2` | Prompt least-privilege or conditional-access remediation |
| `P3` | Reserved for lower-priority observations; unused in the sample |
| `NONE` | Evaluation passed and no remediation is needed |

For the included file at `2026-10-21`, audit checks 10 accounts and reports 8 findings: 7 P1, 1 P2, and 0 P3. These priorities and actions are prototype choices that require business ownership, response targets, and escalation approval.

## Reading the output

- `ALLOW` means all ten checks passed.
- `CONDITIONAL` means no deny condition occurred, but the sample policy requires a restricted or stepped-up session.
- `DENY` means one or more deny checks failed or required evidence could not be trusted.
- A successful process exit means the file loaded and the report was produced. It does not mean all requests were allowed or that the audit was clear.
- In table mode, compare the totals and `Expected scenario matches`. In JSON mode, inspect `summary`, then each decision's `findings` or the audit's `findings`.

## Assumptions Southern Logistics must confirm

- Authoritative partner types and lifecycle vocabulary, including pending, suspended, inactive, ended, extensions, and overlapping engagements.
- Which system owns identity, engagement dates, account state, resource grants, network zone, device posture, and monitoring evidence.
- Whether dates are inclusive, whether day precision is adequate, and whether cutoff has no grace period.
- Actual role-to-resource and resource-to-zone mappings, including warehouse, corporate, critical, guest, and third-party zones.
- Whether individual identities are mandatory and shared/service accounts are prohibited or handled separately.
- MFA strength, device trust definitions, approved source paths, and when limited/conditional access is acceptable.
- Which identity, device, access, and network events must be present, trusted, correlated, retained, and reviewed.
- Severity, priority, response-time, owner, notification, and escalation rules.
- Exception, emergency/break-glass, legal-hold, safety, suspension, dispute, and after-hours processes.
- Whether audit `account_state: enabled` is an adequate indication of potential access in each real target system.

## Limitations

- Synthetic evaluation only; no production source is queried and no account or session is provisioned or revoked.
- Point-in-time date logic, not continuous enforcement; no time of day/time-zone/session-duration modelling.
- Telemetry and network posture are caller-supplied synthetic assertions, not independently verified logs or controls.
- No credentials, tokens, real identities, PII, production logs, risk feeds, approvals, or service accounts are processed.
- No downstream entitlement discovery, token invalidation, retries, rollback, exception workflow, or proof of revocation.
- Recommended actions are explanatory text only.
- Passing tests and scenarios validates implemented code paths, not the full architecture, every threat, or D1-D8 completion.

## What real automatic revocation would require

A production design would need approved integrations with authoritative HR/contractor/procurement/vendor lifecycle sources; an IdP/IGA platform; supported SCIM or application entitlement APIs; MFA, MDM/EDR, gateways and policy enforcement points; session/token revocation; SIEM/log pipelines; workflow/retry/dead-letter processing; and ticketing/notification systems.

Operational owners must decide the authoritative event and revocation service level, disable/suspend/delete sequence, entitlement and session removal order, exception approvals, failure retry/escalation, after-hours ownership, notification recipients, evidence retention/privacy, reconciliation cadence, staged rollout, monitoring, rollback, and periodic access review. Integrations would need approved service identities, least privilege, change control, testing, and auditable error handling.

## Run the tests

From the repository root with the virtual environment active:

```bash
python -m unittest discover -s tests -v
```

A passing run ends in `OK`. The suite covers the original scanner plus active/pending/suspended/inactive/ended/expired/future lifecycle cases; date boundaries; malformed and duplicate data; grants and role eligibility; MFA and device pass/fail/conditional behaviour; segmentation; monitoring evidence; stable schemas; account audit; explicit as-of dates; sample totals; and CLI integration.
