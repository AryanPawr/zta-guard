import copy
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from core.partner_access import (
    PartnerInputError,
    audit_partner_accounts,
    evaluate_partner_requests,
    load_partner_dataset,
    parse_as_of,
)


def base_dataset():
    return {
        "dataset_name": "test scenarios",
        "synthetic": True,
        "policy": {
            "policy_id": "D3-PARTNER-ACCESS-V1",
            "role_eligible_resources": {
                "contractor": ["inventory-read", "work-order-update"],
                "delivery_partner": ["delivery-portal", "shipment-status"],
            },
            "context_requirements": {
                "mfa_verified": True,
                "allowed_device_postures": ["compliant", "managed"],
                "conditional_device_postures": [],
            },
            "segmentation_requirements": {
                "resource_zones": {
                    "inventory-read": "warehouse",
                    "work-order-update": "warehouse",
                    "delivery-portal": "third-party-partner",
                    "shipment-status": "third-party-partner",
                },
                "allowed_paths": [
                    {
                        "partner_type": "contractor",
                        "network_zone": "third-party-partner",
                        "resource_zone": "warehouse",
                    },
                    {
                        "partner_type": "delivery_partner",
                        "network_zone": "third-party-partner",
                        "resource_zone": "third-party-partner",
                    },
                ],
            },
            "monitoring_requirements": {
                "required_events": ["identity", "device", "access", "network"],
            },
        },
        "accounts": [
            {
                "identity_id": "ctr-1",
                "partner_type": "contractor",
                "engagement": {
                    "status": "active",
                    "start_date": "2026-10-01",
                    "end_date": "2026-10-31",
                },
                "account_state": "enabled",
                "granted_resources": ["inventory-read"],
            }
        ],
        "requests": [
            {
                "request_id": "req-1",
                "identity_id": "ctr-1",
                "resource": "inventory-read",
                "context": {
                    "mfa_verified": True,
                    "device_posture": "compliant",
                    "network_zone": "third-party-partner",
                    "telemetry": {
                        "identity": True,
                        "device": True,
                        "access": True,
                        "network": True,
                    },
                },
                "expected_decision": "ALLOW",
            }
        ],
    }


class PartnerInputTests(unittest.TestCase):
    def test_as_of_requires_canonical_valid_date(self):
        self.assertEqual(parse_as_of("2026-10-21"), date(2026, 10, 21))
        for value in ("21-10-2026", "2026-02-30", "2026-1-01"):
            with self.subTest(value=value):
                with self.assertRaises(PartnerInputError):
                    parse_as_of(value)

    def test_loader_requires_explicit_synthetic_marker(self):
        data = base_dataset()
        data["synthetic"] = False
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "input.json")
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(PartnerInputError, "real partner data is out of scope"):
                load_partner_dataset(str(path))


class PartnerEvaluationTests(unittest.TestCase):
    as_of = date(2026, 10, 21)

    def _decision(self, dataset):
        return evaluate_partner_requests(dataset, self.as_of)["decisions"][0]

    def _codes(self, decision):
        return {reason["code"] for reason in decision["reasons"]}

    def test_valid_time_bound_least_privilege_request_is_allowed(self):
        report = evaluate_partner_requests(base_dataset(), self.as_of)
        decision = report["decisions"][0]

        self.assertEqual(decision["decision"], "ALLOW")
        self.assertTrue(decision["expectation_met"])
        self.assertEqual(decision["priority"], "NONE")
        self.assertEqual(len(decision["matched_policies"]), 10)
        self.assertEqual(len(report["check_catalog"]), 10)
        self.assertTrue(all(item["check_id"].startswith("D3-PARTNER-0") for item in report["check_catalog"]))

    def test_start_and_end_dates_are_inclusive(self):
        for as_of in (date(2026, 10, 1), date(2026, 10, 31)):
            with self.subTest(as_of=as_of):
                report = evaluate_partner_requests(base_dataset(), as_of)
                self.assertEqual(report["decisions"][0]["decision"], "ALLOW")

    def test_nonactive_not_started_and_expired_engagements_are_denied(self):
        cases = (
            ("inactive", "2026-10-01", "2026-10-31", "ENGAGEMENT_INACTIVE"),
            ("ended", "2026-08-01", "2026-08-31", "ENGAGEMENT_ENDED"),
            ("pending", "2026-11-01", "2026-12-01", "ENGAGEMENT_PENDING"),
            ("suspended", "2026-10-01", "2026-12-01", "ENGAGEMENT_SUSPENDED"),
            ("active", "2026-11-01", "2026-12-01", "ENGAGEMENT_NOT_STARTED"),
            ("active", "2026-08-01", "2026-08-31", "ENGAGEMENT_EXPIRED"),
        )
        for status, start, end, code in cases:
            with self.subTest(status=status, start=start, end=end):
                data = base_dataset()
                data["accounts"][0]["engagement"] = {
                    "status": status,
                    "start_date": start,
                    "end_date": end,
                }
                decision = self._decision(data)
                self.assertEqual(decision["decision"], "DENY")
                self.assertIn(code, self._codes(decision))

    def test_missing_malformed_inconsistent_and_ambiguous_lifecycle_fail_closed(self):
        cases = (
            {"status": "active", "start_date": "2026-10-01"},
            {"status": "active", "start_date": "yesterday", "end_date": "2026-10-31"},
            {"status": "active", "start_date": "2026-11-01", "end_date": "2026-10-01"},
            {"status": "maybe", "start_date": "2026-10-01", "end_date": "2026-10-31"},
        )
        for engagement in cases:
            with self.subTest(engagement=engagement):
                data = base_dataset()
                data["accounts"][0]["engagement"] = engagement
                decision = self._decision(data)
                self.assertEqual(decision["decision"], "DENY")
                self.assertIn("LIFECYCLE_DATA_INVALID", self._codes(decision))

    def test_role_eligibility_and_explicit_grant_are_both_required(self):
        ineligible = base_dataset()
        ineligible["accounts"][0]["granted_resources"].append("finance-admin")
        ineligible["requests"][0]["resource"] = "finance-admin"
        denied = self._decision(ineligible)
        self.assertIn("RESOURCE_NOT_ROLE_ELIGIBLE", self._codes(denied))

        ungranted = base_dataset()
        ungranted["requests"][0]["resource"] = "work-order-update"
        denied = self._decision(ungranted)
        self.assertIn("RESOURCE_NOT_EXPLICITLY_GRANTED", self._codes(denied))

    def test_mfa_and_device_posture_are_both_required(self):
        data = base_dataset()
        data["requests"][0]["context"].update({
            "mfa_verified": False,
            "device_posture": "unmanaged",
        })
        decision = self._decision(data)

        self.assertEqual(decision["decision"], "DENY")
        self.assertIn("MFA_NOT_VERIFIED", self._codes(decision))
        self.assertIn("DEVICE_POSTURE_NOT_ALLOWED", self._codes(decision))

    def test_allowed_conditional_device_posture_requires_restriction(self):
        data = base_dataset()
        data["policy"]["context_requirements"]["conditional_device_postures"] = ["managed"]
        data["requests"][0]["context"]["device_posture"] = "managed"
        data["requests"][0]["expected_decision"] = "CONDITIONAL"

        decision = self._decision(data)

        self.assertEqual(decision["decision"], "CONDITIONAL")
        self.assertTrue(decision["expectation_met"])
        self.assertIn("DEVICE_POSTURE_CONDITIONAL", self._codes(decision))

    def test_network_segmentation_path_passes_and_missing_or_disallowed_path_denies(self):
        self.assertEqual(self._decision(base_dataset())["decision"], "ALLOW")

        for value, code in ((None, "NETWORK_ZONE_EVIDENCE_MISSING"),
                            ("corporate", "SEGMENTATION_PATH_NOT_ALLOWED")):
            with self.subTest(network_zone=value):
                data = base_dataset()
                if value is None:
                    data["requests"][0]["context"].pop("network_zone")
                else:
                    data["requests"][0]["context"]["network_zone"] = value
                decision = self._decision(data)
                self.assertEqual(decision["decision"], "DENY")
                self.assertIn(code, self._codes(decision))

    def test_monitoring_evidence_passes_and_missing_or_malformed_evidence_denies(self):
        self.assertEqual(self._decision(base_dataset())["decision"], "ALLOW")

        for telemetry in (None, {"identity": True}, "present"):
            with self.subTest(telemetry=telemetry):
                data = base_dataset()
                if telemetry is None:
                    data["requests"][0]["context"].pop("telemetry")
                else:
                    data["requests"][0]["context"]["telemetry"] = telemetry
                decision = self._decision(data)
                self.assertEqual(decision["decision"], "DENY")
                self.assertIn("MONITORING_EVIDENCE_MISSING", self._codes(decision))

    def test_decision_findings_use_stable_schema(self):
        data = base_dataset()
        data["requests"][0]["context"]["mfa_verified"] = False
        decision = self._decision(data)
        required = {
            "finding_id", "check_id", "title", "severity", "category", "outcome",
            "explanation", "evidence", "source", "remediation",
        }

        self.assertTrue(decision["findings"])
        self.assertTrue(required.issubset(decision["findings"][0]))
        self.assertEqual(decision["findings"][0]["check_id"], "D3-PARTNER-007-MFA-VERIFIED")

    def test_malformed_policy_extensions_fail_closed_at_load_time(self):
        cases = (
            ("segmentation_requirements", None),
            ("monitoring_requirements", {"required_events": ["access"]}),
        )
        for field, value in cases:
            with self.subTest(field=field):
                data = base_dataset()
                data["policy"][field] = value
                with self.assertRaises(PartnerInputError):
                    evaluate_partner_requests(data, self.as_of)

    def test_unknown_and_duplicate_identities_fail_closed(self):
        unknown = base_dataset()
        unknown["requests"][0]["identity_id"] = "missing"
        self.assertIn("IDENTITY_NOT_FOUND", self._codes(self._decision(unknown)))

        duplicate = base_dataset()
        duplicate["accounts"].append(copy.deepcopy(duplicate["accounts"][0]))
        self.assertIn("IDENTITY_AMBIGUOUS", self._codes(self._decision(duplicate)))


class PartnerAuditTests(unittest.TestCase):
    def test_audit_accepts_accounts_only_input_and_flags_invalid_identity_and_type(self):
        data = base_dataset()
        data.pop("requests")
        data["accounts"][0]["identity_id"] = ""
        data["accounts"][0]["partner_type"] = "vendor"

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "audit.json")
            path.write_text(json.dumps(data), encoding="utf-8")
            loaded = load_partner_dataset(str(path))

        report = audit_partner_accounts(loaded, date(2026, 10, 21))
        titles = {finding["title"] for finding in report["findings"]}
        self.assertIn("Invalid account identity", titles)
        self.assertIn("Invalid partner type", titles)

    def test_audit_finds_ended_expired_invalid_and_overprivileged_accounts(self):
        data = base_dataset()
        data["accounts"] = [
            {
                "identity_id": "ended",
                "partner_type": "contractor",
                "engagement": {
                    "status": "ended",
                    "start_date": "2026-01-01",
                    "end_date": "2026-08-31",
                },
                "account_state": "enabled",
                "granted_resources": ["inventory-read"],
            },
            {
                "identity_id": "expired",
                "partner_type": "delivery_partner",
                "engagement": {
                    "status": "active",
                    "start_date": "2026-01-01",
                    "end_date": "2026-09-30",
                },
                "account_state": "enabled",
                "granted_resources": ["delivery-portal"],
            },
            {
                "identity_id": "invalid",
                "partner_type": "contractor",
                "engagement": {"status": "active", "start_date": "2026-01-01"},
                "account_state": "enabled",
                "granted_resources": ["inventory-read"],
            },
            {
                "identity_id": "overprivileged",
                "partner_type": "contractor",
                "engagement": {
                    "status": "active",
                    "start_date": "2026-01-01",
                    "end_date": "2026-12-31",
                },
                "account_state": "enabled",
                "granted_resources": ["inventory-read", "finance-admin"],
            },
        ]

        report = audit_partner_accounts(data, date(2026, 10, 21))
        titles = {finding["title"] for finding in report["findings"]}

        self.assertIn("Enabled account after ended engagement", titles)
        self.assertIn("Enabled account after expired engagement", titles)
        self.assertIn("Enabled account with invalid lifecycle data", titles)
        self.assertIn("Explicit grants exceed role eligibility", titles)
        self.assertEqual(report["summary"]["priority_breakdown"], {"P1": 3, "P2": 1, "P3": 0})
        required = {
            "finding_id", "check_id", "title", "severity", "category", "outcome",
            "explanation", "evidence", "source", "remediation",
        }
        self.assertTrue(all(required.issubset(finding) for finding in report["findings"]))
        self.assertEqual(len(report["check_catalog"]), 7)
        self.assertTrue(
            all(item["check_id"].startswith("D3-PARTNER-AUDIT-") for item in report["check_catalog"])
        )
        json.dumps(report)

    def test_disabled_expired_account_is_not_active_access_finding(self):
        data = base_dataset()
        account = data["accounts"][0]
        account["account_state"] = "disabled"
        account["engagement"]["end_date"] = "2026-09-30"

        report = audit_partner_accounts(data, date(2026, 10, 21))

        self.assertEqual(report["findings"], [])
