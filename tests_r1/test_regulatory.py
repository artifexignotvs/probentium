"""Experimenta fines et incerta servant."""

from copy import deepcopy
import unittest

from probentium.contracts import ProbentiumError, object_digest
from probentium.regulatory import (compare_filings, evaluate_control,
                                   evaluate_deadlines, prepare_filing, profiles)

NOW = "2026-10-18T10:00:00Z"


def track(profile="dora", **anchors):
    return {"id": "track-a", "profile": profile, "anchors": anchors}


def stage(result, name):
    return next(row for row in result["deadlines"] if row["stage"] == name)


def mfa():
    return {"id": "control-a", "title": "Declared MFA test", "kind": "mfa", "population": 1,
            "observations": [{"id": "o1", "subject": "account-a/path-a",
                              "evidence_refs": ["record-a"], "configured": True, "enforced": True}]}


class ControlTests(unittest.TestCase):
    def test_supplied_scope_is_not_independent_verification(self):
        result = evaluate_control(mfa())
        self.assertEqual(result["status"], "effective_in_scope")
        self.assertEqual(result["coverage"], {"population": 1, "assessed": 1, "passed": 1,
                                              "failed": 0, "unknown": 0, "missing": 0})
        self.assertEqual(result["evidence"]["verification"], "references_only")
        self.assertEqual(result["evidence"]["observation_basis"], "supplied_declarations")
        self.assertFalse(result["legally_verified"])

    def test_known_population_not_fully_observed(self):
        value = mfa()
        value["population"] = 100
        result = evaluate_control(value)
        self.assertEqual(result["status"], "partially_demonstrated")
        self.assertEqual(result["coverage"]["missing"], 99)

    def test_unknown_population_never_completes(self):
        value = mfa()
        value["population"] = None
        result = evaluate_control(value)
        self.assertEqual(result["status"], "partially_demonstrated")
        self.assertIsNone(result["coverage"]["missing"])

    def test_document_alone_not_effectiveness(self):
        result = evaluate_control({"id": "c", "kind": "mfa", "population": 12,
                                   "evidence_refs": ["policy.pdf"], "observations": []})
        self.assertEqual(result["status"], "not_demonstrated")
        self.assertEqual(result["coverage"]["assessed"], 0)

    def test_missing_refs_or_unknown_enforcement_do_not_pass(self):
        for changes in ({"evidence_refs": []}, {"enforced": None}):
            value = mfa()
            value["observations"][0].update(changes)
            result = evaluate_control(value)
            self.assertEqual(result["status"], "not_demonstrated")
            self.assertEqual(result["coverage"]["unknown"], 1)

    def test_failed_enforcement_is_explicit(self):
        value = mfa()
        value["observations"][0]["enforced"] = False
        self.assertEqual(evaluate_control(value)["status"], "failed_in_scope")

    def test_zero_population_not_vacuous_success(self):
        value = mfa()
        value.update(population=0, observations=[])
        self.assertEqual(evaluate_control(value)["status"], "not_demonstrated")

    def test_duplicates_cannot_inflate_coverage(self):
        value = mfa()
        value["population"] = 2
        duplicate = deepcopy(value["observations"][0])
        duplicate["id"] = "o2"
        value["observations"].append(duplicate)
        with self.assertRaisesRegex(ProbentiumError, "duplicate_control_observation"):
            evaluate_control(value)

    def test_restore_exact_targets_and_missing_functional_check(self):
        value = {"id": "r", "kind": "restore", "population": 1, "rto_seconds": 60, "rpo_seconds": 30,
                 "observations": [{"id": "r1", "subject": "service-a", "evidence_refs": ["restore-test"],
                                   "restored": True, "functional_check": True,
                                   "elapsed_seconds": 60, "data_age_seconds": 30}]}
        self.assertEqual(evaluate_control(value)["status"], "effective_in_scope")
        value["observations"][0]["elapsed_seconds"] = 61
        self.assertEqual(evaluate_control(value)["status"], "failed_in_scope")
        value["observations"][0].update(elapsed_seconds=60, functional_check=None)
        self.assertEqual(evaluate_control(value)["status"], "not_demonstrated")

    def test_unknown_restore_target_not_invented(self):
        value = {"id": "r", "kind": "restore", "population": 1,
                 "observations": [{"id": "r1", "subject": "service-a", "evidence_refs": ["r"],
                                   "restored": True, "functional_check": True,
                                   "elapsed_seconds": 5, "data_age_seconds": 5}]}
        self.assertEqual(evaluate_control(value)["status"], "not_demonstrated")

    def test_remediation_requires_applicability_and_retest(self):
        value = {"id": "r", "kind": "remediation", "population": 1,
                 "observations": [{"id": "o", "subject": "asset/finding/version", "evidence_refs": ["test"],
                                   "applicable": True, "remediated": True, "retest_passed": True}]}
        self.assertEqual(evaluate_control(value)["status"], "effective_in_scope")
        value["observations"][0]["retest_passed"] = False
        self.assertEqual(evaluate_control(value)["status"], "failed_in_scope")
        value["observations"][0]["applicable"] = False
        self.assertEqual(evaluate_control(value)["status"], "not_demonstrated")

    def test_boolean_not_population_integer(self):
        value = mfa()
        value["population"] = True
        with self.assertRaises(ProbentiumError):
            evaluate_control(value)


class DeadlineTests(unittest.TestCase):
    def test_profiles_independent_unverified_drafts(self):
        available = profiles()
        available["dora"]["status"] = "active"
        self.assertEqual(profiles()["dora"]["status"], "draft")
        for profile in profiles():
            result = evaluate_deadlines(track(profile), NOW)
            self.assertFalse(result["legally_verified"])
            self.assertEqual(result["legal_currentness"], "unverified")
            self.assertTrue(all(row["legal_deadline"] is None for row in result["deadlines"]))

    def test_dora_earlier_limit_and_late_classification_boundary(self):
        cases = [("2026-10-19T09:00:00Z", "2026-10-19T10:00:00Z"),
                 ("2026-10-19T10:00:00Z", "2026-10-19T10:00:00Z"),
                 ("2026-10-19T10:00:01Z", "2026-10-19T14:00:01Z")]
        for classification, expected in cases:
            value = track(awareness=NOW, classification=classification)
            self.assertEqual(stage(evaluate_deadlines(value, NOW), "initial")["operational_target"], expected)

    def test_dora_classification_before_awareness_rejected(self):
        with self.assertRaisesRegex(ProbentiumError, "classification_precedes_awareness"):
            evaluate_deadlines(track(awareness=NOW, classification="2026-10-18T09:00:00Z"), NOW)

    def test_dora_actual_submission_latest_intermediate(self):
        value = track(awareness=NOW, classification=NOW, submitted="2026-10-18T12:00:00Z",
                      intermediate="2026-10-20T12:00:00Z", latest_intermediate="2026-10-31T12:00:00Z")
        result = evaluate_deadlines(value, NOW)
        self.assertEqual(stage(result, "intermediate")["operational_target"], "2026-10-21T12:00:00Z")
        self.assertEqual(stage(result, "final")["operational_target"], "2026-11-30T12:00:00Z")
        self.assertIn("report_required_even_if_unchanged", stage(result, "intermediate")["reasons"])

    def test_unknown_latest_update_does_not_fall_back(self):
        value = track(intermediate=NOW, latest_intermediate={"status": "time_unknown"})
        result = stage(evaluate_deadlines(value, NOW), "final")
        self.assertEqual(result["status"], "trigger_time_unknown")
        self.assertIsNone(result["operational_target"])

    def test_updated_intermediate_cannot_precede_original(self):
        with self.assertRaisesRegex(ProbentiumError, "updated_intermediate_precedes_intermediate"):
            evaluate_deadlines(track(intermediate=NOW, latest_intermediate="2026-10-17T10:00:00Z"), NOW)

    def test_month_clamps_leap_day_without_using_30_days(self):
        value = track(intermediate="2028-01-31T10:00:00Z")
        self.assertEqual(stage(evaluate_deadlines(value, NOW), "final")["operational_target"], "2028-02-29T10:00:00Z")

    def test_cra_vulnerability_measure_anchor(self):
        value = track("cra-vulnerability", awareness=NOW, measure_available="2026-11-01T10:00:00Z")
        result = evaluate_deadlines(value, NOW)
        self.assertEqual(stage(result, "final")["operational_target"], "2026-11-15T10:00:00Z")
        self.assertEqual(stage(result, "final")["anchor"], "measure_available")

    def test_cra_incident_notification_anchor(self):
        value = track("cra-incident", awareness=NOW, submitted="2026-10-20T10:00:00Z", measure_available=NOW)
        self.assertEqual(stage(evaluate_deadlines(value, NOW), "final")["operational_target"], "2026-11-20T10:00:00Z")

    def test_waiting_unknown_time_and_unknown_occurrence_distinct(self):
        cases = [(None, "trigger_status_unknown"), ({"status": "time_unknown"}, "trigger_time_unknown"),
                 ({"status": "waiting"}, "waiting_for_trigger")]
        for anchor, expected in cases:
            row = stage(evaluate_deadlines(track("cra-vulnerability", measure_available=anchor), NOW), "final")
            self.assertEqual(row["status"], expected)
            self.assertIsNone(row["operational_target"])

    def test_interval_preserves_bounds_and_openness(self):
        value = track("gdpr-controller", awareness={"status": "interval", "earliest": NOW,
                                                    "latest": "2026-10-18T11:00:00Z", "earliest_inclusive": False})
        result = stage(evaluate_deadlines(value, "2026-10-21T10:30:00Z"), "supervisory_notification")
        self.assertIsNone(result["operational_target"])
        self.assertEqual(result["operational_target_range"], {"earliest": "2026-10-21T10:00:00Z",
                                                              "latest": "2026-10-21T11:00:00Z",
                                                              "earliest_inclusive": False, "latest_inclusive": True})
        self.assertEqual(result["operational_status"], "possibly_past_operational_target")

    def test_unbounded_interval_does_not_gain_false_precision(self):
        value = track("gdpr-controller", awareness={"status": "interval", "earliest": None, "latest": NOW})
        row = stage(evaluate_deadlines(value, NOW), "supervisory_notification")
        self.assertIsNone(row["operational_target_range"]["earliest"])
        self.assertFalse(row["operational_target_range"]["earliest_inclusive"])

    def test_dora_crossing_late_branch_stays_interval(self):
        value = track(awareness=NOW, classification={"status": "interval", "earliest": "2026-10-19T09:00:00Z",
                                                    "latest": "2026-10-19T11:00:00Z"})
        row = stage(evaluate_deadlines(value, NOW), "initial")
        self.assertEqual(row["status"], "interval")
        self.assertIsNone(row["operational_target"])
        self.assertIn("late_classification_branch_uncertain_conservative_envelope", row["reasons"])

    def test_czech_30_days_ongoing_and_trust_branch(self):
        value = track("cz-nis2-higher", awareness=NOW, submitted="2026-10-31T10:00:00Z",
                      resolved={"status": "waiting"})
        value.update(ongoing=True, trust_service=True)
        result = evaluate_deadlines(value, NOW)
        self.assertEqual(stage(result, "notification")["operational_target"], "2026-10-19T10:00:00Z")
        self.assertEqual(stage(result, "progress_if_ongoing")["operational_target"], "2026-11-30T10:00:00Z")
        self.assertEqual(stage(result, "final_after_resolution")["status"], "waiting_for_trigger")

    def test_gdpr_processor_people_no_72_hour_allowance(self):
        for profile in ["gdpr-processor", "gdpr-communication"]:
            result = evaluate_deadlines(track(profile, awareness=NOW), NOW)["deadlines"][0]
            self.assertIsNone(result["operational_target"])
            self.assertEqual(result["operational_status"], "human_action_review_required")

    def test_stale_profile_never_verified(self):
        value = track("gdpr-controller", awareness=NOW)
        value["profile_review_due"] = "2026-10-17T10:00:00Z"
        result = evaluate_deadlines(value, NOW)
        self.assertEqual(result["legal_currentness"], "stale_unverified")
        self.assertFalse(result["legally_verified"])

    def test_cannot_inject_profile_verification(self):
        value = track()
        value["legally_verified"] = True
        with self.assertRaises(ProbentiumError):
            evaluate_deadlines(value, NOW)

    def test_offset_normalized_boundary_status(self):
        value = track("gdpr-controller", awareness="2026-10-18T12:00:00+02:00")
        row = evaluate_deadlines(value, "2026-10-21T10:00:00Z")["deadlines"][0]
        self.assertEqual(row["operational_target"], "2026-10-21T10:00:00Z")
        self.assertEqual(row["operational_status"], "at_operational_target")


class FilingTests(unittest.TestCase):
    def filing(self, fields=None, tr=None):
        return prepare_filing(tr or track(awareness=NOW), fields if fields is not None else [{"id": "accounts"}], 7, NOW)

    def test_missing_fact_not_zero_prepared_not_submitted(self):
        result = self.filing()
        self.assertIsNone(result["fields"][0]["value"])
        self.assertEqual(result["unknown_fields"], ["accounts"])
        self.assertEqual(result["state"], "prepared")
        self.assertEqual(result["submission_status"], "not_submitted")
        self.assertNotIn("approval", result)
        self.assertNotIn("receipt", result)

    def test_digest_covers_snapshot_without_circular_identity(self):
        result = self.filing()
        expected = object_digest({k: v for k, v in result.items() if k not in {"id", "digest"}}, domain="PROBENTIUM-FILING-V1")
        self.assertEqual(result["id"], expected)
        self.assertEqual(result["digest"], expected)

    def test_inputs_not_mutated_or_shared(self):
        fields, tr = [{"id": "scope", "basis": "source_backed", "value": ["a"], "refs": ["r1"]}], track(awareness=NOW)
        original = deepcopy((fields, tr))
        result = self.filing(fields, tr)
        self.assertEqual((fields, tr), original)
        fields[0]["value"].append("b")
        tr["anchors"]["awareness"] = "2026-01-01T00:00:00Z"
        self.assertEqual(result["fields"][0]["value"], ["a"])
        self.assertEqual(result["track"]["anchors"]["awareness"], NOW)

    def test_fields_and_refs_canonicalized(self):
        first = [{"id": "z", "basis": "source_backed", "value": "a", "refs": ["r2", "r1"]}, {"id": "a"}]
        second = [first[1], {**first[0], "refs": ["r1", "r2"]}]
        self.assertEqual(self.filing(first)["digest"], self.filing(second)["digest"])

    def test_derived_requires_version_and_declared_inputs(self):
        field = {"id": "event_count", "value": 2, "basis": "derived", "refs": ["r1", "r2"],
                 "calculation": {"id": "count-events", "version": "1", "input_refs": ["r1", "r2"]}}
        self.assertEqual(self.filing([field])["fields"][0]["value"], 2)
        field["calculation"]["input_refs"] = ["r3"]
        with self.assertRaisesRegex(ProbentiumError, "derived_field_requires_calculation_inputs"):
            self.filing([field])

    def test_attested_requires_reason(self):
        field = {"id": "affected", "value": 0, "basis": "human_attested", "reason": "Analyst declaration; no independent count."}
        self.assertEqual(self.filing([field])["fields"][0]["basis"], "human_attested")
        del field["reason"]
        with self.assertRaisesRegex(ProbentiumError, "field_basis_requires_reason"):
            self.filing([field])

    def test_unknown_cannot_assert_zero(self):
        with self.assertRaisesRegex(ProbentiumError, "unknown_field_cannot_assert_value"):
            self.filing([{"id": "affected", "basis": "unknown", "value": 0}])

    def test_source_backed_requires_reference(self):
        with self.assertRaisesRegex(ProbentiumError, "field_basis_requires_refs"):
            self.filing([{"id": "affected", "basis": "source_backed", "value": 2}])

    def test_diff_changed_reference_without_changed_value(self):
        first = {"id": "scope", "value": "same", "basis": "source_backed", "refs": ["r1"]}
        result = compare_filings(self.filing([first]), self.filing([{**first, "refs": ["r2"]}]))
        self.assertEqual(result["changes"][0]["reason"], "evidence_basis_changed")
        self.assertTrue(result["correction_impact"]["review_required"])
        self.assertEqual(result["correction_impact"]["legal_correction_required"], "undetermined")
        self.assertFalse(result["correction_impact"]["submission_changed"])

    def test_diff_added_removed_changed_facts(self):
        old = self.filing([{"id": "gone"}, {"id": "count"}])
        new = self.filing([{"id": "new"}, {"id": "count", "value": 3, "basis": "source_backed", "refs": ["r"]}])
        changes = {row["field"]: row["reason"] for row in compare_filings(old, new)["changes"]}
        self.assertEqual(changes, {"gone": "field_removed", "new": "field_added", "count": "value_changed"})

    def test_no_change_no_correction(self):
        result = self.filing()
        self.assertFalse(compare_filings(result, result)["correction_impact"]["review_required"])

    def test_tampered_snapshot_rejected(self):
        first, second = self.filing(), self.filing()
        second["fields"][0]["reason"] = "altered after creation"
        with self.assertRaisesRegex(ProbentiumError, "filing_snapshot_integrity_failed"):
            compare_filings(first, second)

    def test_boolean_and_integer_values_are_distinct_facts(self):
        first = {"id": "fact", "value": 1, "basis": "source_backed", "refs": ["r"]}
        result = compare_filings(self.filing([first]), self.filing([{**first, "value": True}]))
        self.assertEqual(len(result["changes"]), 1)
        self.assertEqual(result["changes"][0]["reason"], "value_changed")

    def test_false_verification_flag_cannot_be_replaced_by_zero(self):
        result = self.filing()
        result["legally_verified"] = 0
        with self.assertRaisesRegex(ProbentiumError, "filing_snapshot_integrity_failed"):
            compare_filings(result, self.filing())

    def test_cross_track_diff_rejected(self):
        other = track(awareness=NOW)
        other["id"] = "track-b"
        with self.assertRaisesRegex(ProbentiumError, "filing_tracks_differ"):
            compare_filings(self.filing(), self.filing(tr=other))

    def test_approval_receipt_cannot_enter_snapshot(self):
        result = self.filing()
        result["approval"] = True
        with self.assertRaises(ProbentiumError):
            compare_filings(result, self.filing())

    def test_injection_float_duplicate_limits_rejected(self):
        bad = [[{"id": "a\x1b[31m"}], [{"id": "a", "basis": "source_backed", "value": 1.2, "refs": ["r"]}],
               [{"id": "a"}, {"id": "a"}], [{"id": "x"}] * 501,
               [{"id": "a", "value": "x" * 65537, "basis": "human_attested", "reason": "test"}]]
        for fields in bad:
            with self.assertRaises(ProbentiumError):
                self.filing(fields)


if __name__ == "__main__":
    unittest.main()
