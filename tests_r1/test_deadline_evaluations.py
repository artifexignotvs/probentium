"""Calendaria, exceptiones et historia contra falsa certamina probantur."""
from copy import deepcopy
import base64
from datetime import datetime, timezone
import struct
import unittest

from probentium import governance as g, reporting as r, legalpacks as lp
from probentium.deadlines import evaluate_rule, validate_calendar
from probentium.deadline_records import validate_stored
from probentium.contracts import ProbentiumError
from tests_r1.test_governance import Fixture, T0, T1, T2, T3, pack_fixture


def calendar(**changes):
    return {"schema": "probentium.calendar-policy.v1", "id": "synthetic-calendar", "version": "1",
            "timezone": "UTC", "timezone_data": None, "source_ids": ["procedure"], "status": "unverified",
            "hour_rule": "elapsed_hours", "day_rule": "elapsed_days", "month_rule": "same_local_time_clamp",
            "nonworking_rule": "none", "weekend_days": [5, 6], "holidays": [],
            "holiday_coverage": {"start": "2026-01-01", "end": "2027-12-31"}, **changes}


def rule(operator="hours_after", amount=24, anchor="awareness", **changes):
    return {"id": "initial", "version": "1", "stage": "initial", "source_id": "procedure", "provision": "Synthetic 1",
            "title": "Synthetic rule", "origin": "internal", "condition": "Synthetic only", "evidence": [],
            "operator": operator, "parameters": {} if operator in ("manual_review", "dora_initial") else {"anchor": anchor, "amount": amount},
            "without_undue_delay": True, **changes}


def track(anchor="2026-01-31T10:00:00Z", **changes):
    return {"id": "synthetic", "profile": "dora", "anchors": {"awareness": anchor}, **changes}


def exception(**changes):
    return {"kind": "dora_nonworking", "stage": "initial", "entity_class": "other", "nis2_essential_or_important": False,
            "authority_exclusion": False, "actor": "synthetic-reviewer", "at": "2026-01-01T00:00:00Z",
            "rationale": "Synthetic eligibility declaration, not a legal review.", "basis_refs": ["a" * 64], **changes}


def timezone_fixture():
    # Duae transitiones fictae; tabula systematis non requiritur.
    transitions = [int(datetime(2026, month, day, 1, tzinfo=timezone.utc).timestamp()) for month, day in ((3, 29), (10, 25))]
    header = b"TZif\0" + b"\0" * 15 + struct.pack(">6I", 0, 0, 0, 2, 2, 8)
    data = struct.pack(">2i", *transitions) + bytes([1, 0])
    data += struct.pack(">iBBiBB", 3600, 0, 0, 7200, 1, 4) + b"CET\0CEST"
    return base64.b64encode(header + data).decode()


class CalendarTests(unittest.TestCase):
    def test_month_is_not_thirty_days_and_rule_versions_are_bound(self):
        value = evaluate_rule(track(), rule("months_after", 1), calendar(), T0)
        self.assertEqual(value["operational_target"], "2026-02-28T10:00:00Z")
        self.assertIsNone(value["legal_deadline"])
        self.assertFalse(value["legally_verified"])
        self.assertFalse(value["legal_countdown_enabled"])
        self.assertFalse(value["reference_vectors_reviewed"])
        other = evaluate_rule(track(), rule("months_after", 1, version="2"), calendar(), T0)
        self.assertNotEqual(other["rule_digest"], value["rule_digest"])
        self.assertTrue(other["without_undue_delay"])

    def test_unknown_and_waiting_remain_distinct_and_open_bounds_survive(self):
        for supplied, expected in ((None, "trigger_status_unknown"), ({"status": "waiting"}, "waiting_for_trigger"), ({"status": "time_unknown"}, "trigger_time_unknown")):
            result = evaluate_rule(track(supplied), rule(), calendar(), T0)
            self.assertEqual(result["status"], expected)
            self.assertIsNone(result["operational_target"])
        value = {"status": "interval", "earliest": "2026-01-01T00:00:00Z", "latest": "2026-01-02T00:00:00Z", "earliest_inclusive": False, "latest_inclusive": True}
        result = evaluate_rule(track(value), rule(), calendar(), T0)
        self.assertFalse(result["operational_target_range"]["earliest_inclusive"])
        self.assertTrue(result["operational_target_range"]["latest_inclusive"])

    def test_dora_late_classification_and_final_anchor_do_not_use_detection(self):
        tr = track("2026-01-01T00:00:00Z")
        tr["anchors"].update(classification="2026-01-02T01:00:00Z", submitted="2026-01-02T02:00:00Z",
                             intermediate="2026-01-04T10:00:00Z", latest_intermediate="2026-01-05T11:00:00Z")
        initial = evaluate_rule(tr, rule("dora_initial"), calendar(), T0)
        self.assertEqual(initial["operational_target"], "2026-01-02T05:00:00Z")
        final = evaluate_rule(tr, rule("months_after", 1, "latest_intermediate", stage="final"), calendar(), T0)
        self.assertEqual(final["operational_target"], "2026-02-05T11:00:00Z")

    def test_cra_tracks_use_separate_awareness_and_available_measure_anchors(self):
        anchors = {"awareness": "2026-01-01T10:00:00Z", "measure_available": "2026-01-05T10:00:00Z"}
        vulnerability = {"id": "synthetic-vulnerability", "profile": "cra-vulnerability", "anchors": anchors}
        incident = {"id": "synthetic-incident", "profile": "cra-incident", "anchors": anchors}
        vuln = evaluate_rule(vulnerability, rule("days_after", 14, "measure_available", stage="final"), calendar(), T0)
        final = evaluate_rule(incident, rule("months_after", 1, "awareness", stage="final"), calendar(), T0)
        self.assertEqual(vuln["operational_target"], "2026-01-19T10:00:00Z")
        self.assertEqual(final["operational_target"], "2026-02-01T10:00:00Z")
        vulnerability["anchors"] = {"awareness": anchors["awareness"], "measure_available": {"status": "waiting"}}
        self.assertEqual(evaluate_rule(vulnerability, rule("days_after", 14, "measure_available"), calendar(), T0)["status"], "waiting_for_trigger")

    def test_exception_needs_explicit_policy_and_known_eligible_role(self):
        tr = track("2026-01-02T10:00:00Z")
        policy = calendar(nonworking_rule="dora_next_working_day_noon", holidays=["2026-01-05"])
        no = evaluate_rule(tr, rule(), policy, T0)
        self.assertEqual(no["operational_target"], "2026-01-03T10:00:00Z")
        self.assertEqual(no["exception_status"], "explicit_eligibility_required")
        eligible = evaluate_rule(tr, rule(), policy, T0, exception())
        self.assertEqual(eligible["operational_target"], "2026-01-06T12:00:00Z")
        for ex in (exception(entity_class="credit_institution"), exception(authority_exclusion=True), exception(nis2_essential_or_important=True), exception(authority_exclusion=None)):
            value = evaluate_rule(tr, rule(), policy, T0, ex)
            self.assertEqual(value["operational_target"], no["operational_target"])
        final = evaluate_rule(tr, rule(stage="final"), policy, T0, exception(stage="final", entity_class="credit_institution"))
        self.assertEqual(final["operational_target"], "2026-01-06T12:00:00Z")
        with self.assertRaises(ProbentiumError):
            evaluate_rule(tr, rule(), calendar(), T0, exception())

    def test_calendar_coverage_and_timezone_ambiguity_do_not_invent_target(self):
        policy = calendar(nonworking_rule="next_working_day_end", holiday_coverage={"start": "2026-01-01", "end": "2026-01-03"})
        result = evaluate_rule(track("2026-01-02T10:00:00Z"), rule(), policy, T0)
        self.assertEqual(result["status"], "calendar_unknown")
        self.assertIsNone(result["operational_target"])
        policy = calendar(timezone="Synthetic/Central", timezone_data=timezone_fixture())
        result = evaluate_rule(track("2026-02-28T01:30:00Z"), rule("months_after", 1), policy, T0)
        self.assertEqual(result["operational_target"], "2026-03-28T01:30:00Z")
        result = evaluate_rule(track("2026-01-29T01:30:00Z"), rule("months_after", 2), policy, T0)
        self.assertEqual(result["status"], "calendar_unknown")
        self.assertIn("calendar_local_time_unresolved", result["reasons"])

    def test_exclusive_interval_end_and_conservative_calendar_mapping(self):
        bounds = {"status": "interval", "earliest": "2026-01-01T00:00:00Z", "latest": "2026-01-02T00:00:00Z", "earliest_inclusive": False, "latest_inclusive": False}
        value = evaluate_rule(track(bounds), rule(), calendar(), "2026-01-03T00:00:00Z")
        self.assertEqual(value["operational_status"], "past_all_possible_operational_targets")
        value = evaluate_rule(track(bounds), rule("months_after", 1), calendar(), T0)
        self.assertTrue(value["operational_target_range"]["latest_inclusive"])
        self.assertIn("calendar_mapping_conservative_closed_enclosure", value["reasons"])

    def test_explicit_start_hour_and_day_policies_do_not_change_defaults(self):
        tr = track("2026-01-02T10:15:30Z")
        self.assertEqual(evaluate_rule(tr, rule("hours_after", 2), calendar(), T0)["operational_target"], "2026-01-02T12:15:30Z")
        self.assertEqual(evaluate_rule(tr, rule("hours_after", 2), calendar(hour_rule="exclude_started_hour"), T0)["operational_target"], "2026-01-02T13:00:00Z")
        self.assertEqual(evaluate_rule(tr, rule("days_after", 2), calendar(day_rule="exclude_start_day_end_of_day"), T0)["operational_target"], "2026-01-04T23:59:59.999999Z")

    def test_closed_calendar_schema_rejects_certification_code_and_wrong_types(self):
        for changes in ({"status": "verified"}, {"python": "run"}, {"weekend_days": [True]}, {"holidays": ["2026-02-30"]}, {"timezone": "Europe/Prague", "timezone_data": "VFpJZg=="}):
            with self.subTest(changes=changes), self.assertRaises(ProbentiumError):
                validate_calendar(calendar(**changes))

    def test_timezone_and_calendar_overflow_is_a_stable_domain_error(self):
        for policy in (calendar(), calendar(timezone="Synthetic/Central", timezone_data=timezone_fixture())):
            with self.assertRaises(ProbentiumError) as caught:
                evaluate_rule(track("9999-12-31T23:59:59Z"), rule(), policy, T0)
            self.assertEqual(caught.exception.code, "operational_date_out_of_range")


class DeadlineRecordTests(Fixture, unittest.TestCase):
    def make_track(self):
        pack = pack_fixture(self.source, "calendar-v1")
        pack["rules"] = [rule()]; pack["calendars"] = [calendar()]
        self.pack = lp.import_pack(self.case, pack)
        data = {"id": "deadline-demo", "title": "Synthetic deadline", "profile": "dora", "incident_id": "synthetic",
                "service_refs": [self.service["id"]], "recipient": "synthetic authority", "role": "operator",
                "qualification": {"status": "unknown", "basis_refs": [], "reason": "Synthetic only", "reviewer": "operator"},
                "pack_ref": self.pack["id"], "template_id": "incident", "awareness_refs": {}, "supersedes": None,
                "actor": "synthetic-operator", "recorded_at": T1, "rationale": "Synthetic only"}
        original = r.create_track(self.case, data)
        self.awareness_input = {**self.common("awareness"), "track_ref": original["id"], "event_type": "awareness", "anchor": T0,
                                "actor_role": "incident analyst", "review_decision": "confirmed"}
        self.awareness = g.put_record(self.case, "awareness", self.awareness_input)
        return r.create_track(self.case, {**data, "supersedes": original["id"], "awareness_refs": {"awareness": self.awareness["id"]}})

    def evaluation(self, tr):
        return r.evaluate_deadline(self.case, tr["id"], rule_id="initial", calendar_id="synthetic-calendar", as_of=T2)

    def test_saved_evaluation_is_replayable_immutable_and_revision_bound(self):
        tr = self.make_track(); revision = self.case.revision
        obj = self.evaluation(tr); before = deepcopy(obj)
        self.assertEqual(obj["data"]["case_revision"], revision)
        self.assertEqual(r.replay_deadline(self.case, obj["id"])["status"], "replayed")
        self.assertEqual(r.deadline_status(self.case, obj["id"], T2)["state"], "current_for_recorded_inputs")
        g.put_record(self.case, "service", self.service_input("unrelated"))
        self.assertEqual(self.case.get_object(obj["id"]), before)
        self.assertEqual(r.deadline_status(self.case, obj["id"], T3)["state"], "current_for_recorded_inputs")
        self.assertTrue(r.deadline_status(self.case, obj["id"], T3)["operational_status_requires_new_evaluation"])
        self.assertCode("revision_conflict", r.evaluate_deadline, self.case, tr["id"], rule_id="initial", calendar_id="synthetic-calendar", as_of=T2, expected_revision=revision)

    def test_awareness_correction_stales_old_evaluation_without_rewriting_it(self):
        tr = self.make_track(); obj = self.evaluation(tr)
        g.put_record(self.case, "awareness", {**self.awareness_input, "supersedes": self.awareness["id"], "recorded_at": T3, "anchor": "2026-10-17T00:00:00Z"})
        self.assertEqual(r.deadline_status(self.case, obj["id"], T3)["state"], "stale")
        self.assertEqual(r.replay_deadline(self.case, obj["id"])["status"], "replayed")
        self.assertEqual(self.case.get_object(obj["id"])["data"]["result"]["operational_target"], "2026-10-19T10:00:00Z")

    def test_prepared_filing_is_not_submission_and_later_state_stales(self):
        tr = self.make_track(); before = self.evaluation(tr)
        filing = r.prepare(self.case, tr["id"], [], T2)
        self.assertIn("filing_state_changed", r.deadline_status(self.case, before["id"], T3)["reasons"])
        after = self.evaluation(tr)
        self.assertEqual(after["data"]["filing_states"][0]["state"], "prepared")
        self.assertEqual(after["data"]["filing_states"][0]["submission_refs"], [])
        self.assertEqual(r.replay_deadline(self.case, before["id"])["status"], "replayed")
        self.assertEqual(after["data"]["filing_states"][0]["filing_ref"], filing["id"])

    def test_tampered_result_or_reference_is_rejected(self):
        obj = self.evaluation(self.make_track())
        for mutation in (lambda d: d["result"].update(legally_verified=True), lambda d: d.update(input_digest="0" * 64), lambda d: d.update(dependency_refs=[])):
            data = deepcopy(obj["data"]); mutation(data)
            with self.assertRaises(ProbentiumError):
                validate_stored(data)

    def test_local_review_attestations_never_enable_legal_countdown(self):
        from tests_r1.test_legalpacks import LegalPackTests
        tr = self.make_track(); before = self.evaluation(tr)
        legal = lp.review_pack(self.case, self.pack["id"], LegalPackTests.review(self, "legal"))
        technical = lp.review_pack(self.case, self.pack["id"], LegalPackTests.review(self, "technical"))
        lp.activate_pack(self.case, self.pack["id"], LegalPackTests.activation(self, mode="review_attested", review_refs=[legal["id"], technical["id"]]))
        after = self.evaluation(tr)
        self.assertEqual(after["data"]["pack_state"]["currentness"], "review_attested_current")
        self.assertFalse(after["data"]["result"]["reference_vectors_reviewed"])
        self.assertFalse(after["data"]["result"]["legal_countdown_enabled"])
        self.assertIsNone(after["data"]["result"]["legal_deadline"])
        self.assertEqual(r.deadline_status(self.case, before["id"], T3)["state"], "stale")
        self.assertEqual(r.replay_deadline(self.case, before["id"])["status"], "replayed")
        self.assertIn("pack_review_or_activation_changed", r.deadline_status(self.case, after["id"], "2026-10-18T13:00:01Z")["reasons"])

    def test_legacy_calendar_is_not_silently_executable(self):
        tr = self.make_track()
        legacy = deepcopy(self.pack["data"]); legacy["version"] = "legacy-calendar"
        for key in ("schema", "timezone_data", "holiday_coverage", "weekend_days"):
            del legacy["calendars"][0][key]
        imported = lp.import_pack(self.case, legacy)
        changed = {key: value for key, value in tr["data"].items() if key not in {"schema", "kind"}}
        changed.update(pack_ref=imported["id"], supersedes=tr["id"])
        newer = r.create_track(self.case, changed)
        self.assertCode("invalid_regulatory_fields", self.evaluation, newer)

    def test_replay_refuses_corrupt_source_and_future_snapshot_revision(self):
        obj = self.evaluation(self.make_track())
        forged = deepcopy(obj["data"]); forged["case_revision"] = self.case.revision + 10
        invalid = self.case.put_object("eu.deadline_evaluation", forged)
        self.assertCode("deadline_snapshot_revision_invalid", r.replay_deadline, self.case, invalid["id"])
        blob = self.root / "case" / "blobs" / (self.source + ".bin")
        blob.write_bytes(b"synthetic corruption")
        self.assertCode("deadline_case_integrity_failed", r.replay_deadline, self.case, obj["id"])

    def test_authorized_unavailable_evidence_is_partial_not_full_replay(self):
        from probentium import retention
        obj = self.evaluation(self.make_track())
        plan = retention.plan(self.case, [self.source], "synthetic-owner", "Synthetic deletion test", T0)
        approval = retention.approve(self.case, plan["id"], "synthetic-reviewer", "Synthetic approval")
        retention.execute(self.case, plan["id"], approval["id"], as_of=T3)
        replay = r.replay_deadline(self.case, obj["id"])
        self.assertEqual(replay["status"], "partial")
        self.assertEqual(replay["exit_code"], 3)
        self.assertEqual(replay["computation_status"], "replayed")
        self.assertEqual(r.deadline_status(self.case, obj["id"], T3)["exit_code"], 3)

    def test_demonstration_contains_saved_operational_deadline_and_two_prepared_filings(self):
        demo = r.build_demonstration(self.case, acknowledged_synthetic=True)
        obj = self.case.get_object(demo["deadline_evaluation_ref"])
        self.assertEqual(obj["kind"], "eu.deadline_evaluation")
        self.assertEqual(obj["data"]["result"]["operational_target"], "2026-10-19T10:00:00Z")
        self.assertIsNone(obj["data"]["result"]["legal_deadline"])
        self.assertEqual(len(obj["data"]["filing_states"]), 2)
        self.assertTrue(all(f["state"] == "prepared" for f in obj["data"]["filing_states"]))
        self.assertEqual(r.replay_deadline(self.case, obj["id"])["status"], "replayed")
