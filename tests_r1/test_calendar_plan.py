"""Ordines finiti et dies operativi ex exemplis fictis probantur."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from probentium import legalpacks as lp, reporting as rep
from probentium.calendar_plan import validate_plan
from probentium.contracts import ProbentiumError
from probentium.deadlines import evaluate_rule
from tests_r1.test_deadline_evaluations import calendar, rule, track, exception, timezone_fixture
from tests_r1.test_governance import Fixture, T0, T1, T2


def plan(nodes, output=None):
    return {"schema": "probentium.deadline-plan.v1", "nodes": nodes, "output": output or nodes[-1]["id"]}


def minimum_two():
    return plan([
        {"id": "start", "op": "anchor", "anchor": "awareness"},
        {"id": "nominal", "op": "shift", "input": "start", "unit": "days", "amount": 2},
        {"id": "working", "op": "working_days", "input": "start", "count": 2, "include_start_day": False, "completion": "local_end_of_day"},
        {"id": "minimum_days", "op": "combine", "inputs": ["nominal", "working"], "mode": "maximum"},
        {"id": "adjusted", "op": "nonworking_adjust", "input": "minimum_days", "mode": "next_working_day_end"},
    ])


def declared_rule(parameters, **changes):
    return rule("calendar_plan", parameters=parameters, **changes)


class CalendarPlanTests(unittest.TestCase):
    def calculate(self, parameters, instant="2026-01-02T10:00:00Z", policy=None, **kw):
        return evaluate_rule(track(instant), declared_rule(parameters), policy or calendar(), T0, **kw)

    def test_explicit_minimum_two_working_days_skips_weekend_and_supplied_holiday(self):
        result = self.calculate(minimum_two(), policy=calendar(holidays=["2026-01-05"]))
        self.assertEqual(result["operational_target"], "2026-01-07T23:59:59.999999Z")
        self.assertEqual(result["plan_trace"][1]["operational_target"], "2026-01-04T10:00:00Z")
        self.assertFalse(result["legally_verified"])
        self.assertFalse(result["reference_vectors_reviewed"])
        self.assertIsNone(result["legal_deadline"])
        self.assertEqual(len(result["plan_trace"]), 5)

    def test_start_day_and_completion_are_explicit_inputs(self):
        nodes = [{"id": "start", "op": "anchor", "anchor": "awareness"},
                 {"id": "working", "op": "working_days", "input": "start", "count": 2, "include_start_day": True, "completion": "same_local_time"}]
        result = self.calculate(plan(nodes))
        self.assertEqual(result["operational_target"], "2026-01-05T10:00:00Z")
        nodes[-1]["include_start_day"] = False
        self.assertEqual(self.calculate(plan(nodes))["operational_target"], "2026-01-06T10:00:00Z")

    def test_larger_nominal_period_is_not_shortened_by_working_day_floor(self):
        value = minimum_two(); value["nodes"][1]["amount"] = 10
        result = self.calculate(value)
        self.assertEqual(result["operational_target"], "2026-01-12T10:00:00Z")

    def test_missing_holiday_coverage_propagates_unknown_not_shorter_alternative(self):
        result = self.calculate(minimum_two(), policy=calendar(holiday_coverage={"start": "2026-01-01", "end": "2026-01-04"}))
        self.assertEqual(result["status"], "calendar_unknown")
        self.assertIsNone(result["operational_target"])
        self.assertIn("calendar_holiday_coverage_unknown", result["plan_trace"][2]["reasons"])

    def test_month_end_and_daylight_saving_are_bound_to_frozen_timezone(self):
        p = plan([{"id": "start", "op": "anchor", "anchor": "awareness"}, {"id": "month", "op": "shift", "input": "start", "unit": "months", "amount": 1}])
        self.assertEqual(self.calculate(p, "2026-01-31T10:00:00Z")["operational_target"], "2026-02-28T10:00:00Z")
        p["nodes"][-1]["amount"] = 2
        zone = calendar(timezone="Synthetic/Central", timezone_data=timezone_fixture())
        self.assertEqual(self.calculate(p, "2026-01-29T01:30:00Z", zone)["status"], "calendar_unknown")
        p = minimum_two()
        self.assertEqual(self.calculate(p, "2026-03-27T12:00:00Z", zone)["operational_target"], "2026-03-31T21:59:59.999999Z")

    def test_special_precedence_does_not_apply_general_rule_after_selection(self):
        p = plan([{"id": "start", "op": "anchor", "anchor": "awareness"},
                  {"id": "base", "op": "shift", "input": "start", "unit": "hours", "amount": 24},
                  {"id": "general", "op": "nonworking_adjust", "input": "base", "mode": "next_working_day_end"},
                  {"id": "special", "op": "nonworking_adjust", "input": "base", "mode": "dora_next_working_day_noon"},
                  {"id": "selected", "op": "precedence", "candidates": [{"input": "special", "applies": True}, {"input": "general", "applies": True}]}])
        result = self.calculate(p, exception=exception())
        self.assertEqual(result["operational_target"], "2026-01-05T12:00:00Z")
        self.assertEqual(result["plan_trace"][-1]["selection"], "special")
        self.assertEqual(result["plan_trace"][2]["operational_target"], "2026-01-05T23:59:59.999999Z")
        p["nodes"][-1]["candidates"][0]["applies"] = None
        unknown = self.calculate(p, exception=exception())
        self.assertEqual(unknown["status"], "trigger_status_unknown")
        self.assertIsNone(unknown["operational_target"])
        p["nodes"][-1]["candidates"][0]["applies"] = False
        self.assertEqual(self.calculate(p, exception=exception())["operational_target"], "2026-01-05T23:59:59.999999Z")

    def test_predecessor_unknown_and_waiting_are_not_replaced_by_awareness(self):
        p = plan([{"id": "updated", "op": "anchor", "anchor": "latest_intermediate"},
                  {"id": "original", "op": "anchor", "anchor": "intermediate"},
                  {"id": "selected", "op": "precedence", "candidates": [{"input": "updated", "applies": True}, {"input": "original", "applies": True}]},
                  {"id": "final", "op": "shift", "input": "selected", "unit": "months", "amount": 1}])
        tr = track(); tr["anchors"].update(intermediate="2026-01-01T00:00:00Z", latest_intermediate={"status": "time_unknown"})
        result = evaluate_rule(tr, declared_rule(p), calendar(), T0)
        self.assertEqual(result["status"], "trigger_time_unknown")
        tr["anchors"]["latest_intermediate"] = {"status": "waiting"}
        self.assertEqual(evaluate_rule(tr, declared_rule(p), calendar(), T0)["status"], "waiting_for_trigger")
        p["nodes"][2]["candidates"][0]["applies"] = False
        self.assertEqual(evaluate_rule(tr, declared_rule(p), calendar(), T0)["operational_target"], "2026-02-01T00:00:00Z")

    def test_named_dora_late_branch_can_precede_explicit_calendar_adjustment(self):
        p = plan([{"id": "aware", "op": "anchor", "anchor": "awareness"},
                  {"id": "classified", "op": "anchor", "anchor": "classification"},
                  {"id": "initial", "op": "dora_initial", "awareness": "aware", "classification": "classified"},
                  {"id": "adjusted", "op": "nonworking_adjust", "input": "initial", "mode": "dora_next_working_day_noon"}])
        tr = track("2026-01-01T00:00:00Z"); tr["anchors"]["classification"] = "2026-01-03T01:00:00Z"
        result = evaluate_rule(tr, declared_rule(p), calendar(), T0, exception())
        self.assertEqual(result["plan_trace"][2]["operational_target"], "2026-01-03T05:00:00Z")
        self.assertEqual(result["operational_target"], "2026-01-05T12:00:00Z")
        result = evaluate_rule(tr, declared_rule(p), calendar(), T0, exception(entity_class="credit_institution"))
        self.assertEqual(result["operational_target"], "2026-01-03T05:00:00Z")
        swapped = deepcopy(p)
        swapped["nodes"][2].update(awareness="classified", classification="aware")
        with self.assertRaises(ProbentiumError):
            validate_plan(swapped)
        tr["profile"] = "gdpr-controller"
        with self.assertRaises(ProbentiumError):
            evaluate_rule(tr, declared_rule(p), calendar(), T0)

    def test_minimum_maximum_interval_bounds_are_conservative_and_trace_preserves_input(self):
        interval = {"status": "interval", "earliest": "2026-01-01T00:00:00Z", "latest": "2026-01-02T00:00:00Z", "earliest_inclusive": False, "latest_inclusive": True}
        p = plan([{"id": "a", "op": "anchor", "anchor": "awareness"}, {"id": "b", "op": "anchor", "anchor": "classification"},
                  {"id": "earlier", "op": "combine", "inputs": ["a", "b"], "mode": "minimum"}])
        tr = track(interval); tr["anchors"]["classification"] = "2026-01-03T00:00:00Z"
        result = evaluate_rule(tr, declared_rule(p), calendar(), T0)
        self.assertFalse(result["plan_trace"][0]["operational_target_range"]["earliest_inclusive"])
        self.assertEqual(result["operational_target_range"]["latest"], "2026-01-02T00:00:00Z")
        self.assertTrue(result["operational_target_range"]["earliest_inclusive"])
        tr["anchors"]["classification"] = None
        self.assertEqual(evaluate_rule(tr, declared_rule(p), calendar(), T0)["status"], "trigger_status_unknown")

    def test_closed_ordered_plan_rejects_cycles_forward_refs_disconnected_nodes_and_types(self):
        original = minimum_two()
        mutations = [lambda d: d["nodes"][1].update(input="later"), lambda d: d["nodes"][1].update(input="nominal"),
                     lambda d: d["nodes"][1].update(id="start"), lambda d: d.update(output="start"),
                     lambda d: d["nodes"][2].update(count=True), lambda d: d["nodes"][2].update(count=367),
                     lambda d: d["nodes"][2].update(include_start_day="yes"), lambda d: d["nodes"][2].update(python="exec"),
                     lambda d: d["nodes"].insert(0, {"id": "unreachable", "op": "anchor", "anchor": "submitted"}),
                     lambda d: d["nodes"][3].update(inputs=["nominal", "nominal"]),
                     lambda d: d["nodes"][0].update(anchor="automatic_detected")]
        for mutate in mutations:
            value = deepcopy(original); mutate(value)
            with self.assertRaises(ProbentiumError):
                validate_plan(value)
        with patch("probentium.calendar_plan.MAX_NODES", 4), self.assertRaises(ProbentiumError) as caught:
            validate_plan(original)
        self.assertEqual(caught.exception.exit_code, 6)
        with patch("probentium.calendar_plan.MAX_DAY_STEPS", 1), self.assertRaises(ProbentiumError) as caught:
            self.calculate(original)
        self.assertEqual(caught.exception.exit_code, 6)


class StoredCalendarPlanTests(Fixture, unittest.TestCase):
    def test_stored_plan_policy_and_trace_replay_and_tamper_detection(self):
        from tests_r1.test_deadline_evaluations import DeadlineRecordTests
        tr = DeadlineRecordTests.make_track(self)
        supplied = deepcopy(self.pack["data"]); supplied["version"] = "plan-version-1"
        supplied["rules"] = [declared_rule(minimum_two())]
        pack = lp.import_pack(self.case, supplied)
        track_data = {key: value for key, value in tr["data"].items() if key not in {"schema", "kind"}}
        track_data.update(pack_ref=pack["id"], supersedes=tr["id"])
        selected = rep.create_track(self.case, track_data)
        evaluation = rep.evaluate_deadline(self.case, selected["id"], rule_id="initial", calendar_id="synthetic-calendar", as_of=T2)
        self.assertEqual(rep.replay_deadline(self.case, evaluation["id"])["status"], "replayed")
        self.assertIn("plan_trace", evaluation["data"]["result"])
        self.assertFalse(evaluation["data"]["result"]["reference_vectors_reviewed"])
        changed = deepcopy(evaluation["data"])
        changed["inputs"]["rule"]["parameters"]["nodes"][2]["count"] = 1
        with self.assertRaises(ProbentiumError):
            rep.validate_stored("eu.deadline_evaluation", changed)
        changed = deepcopy(evaluation["data"]); changed["result"]["plan_trace"][0]["selection"] = "invented"
        with self.assertRaises(ProbentiumError):
            rep.validate_stored("eu.deadline_evaluation", changed)


if __name__ == "__main__":
    unittest.main()
