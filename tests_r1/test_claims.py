"""Numerus observationum a possibilitate coniuncta distinguitur."""
from copy import deepcopy
import unittest
import random

from probentium import claims
from probentium import time_model as tm
from probentium.contracts import ProbentiumError, object_digest
from test_time_model import clock


def eid(n):
    return format(n, "064x")


def data(count=2, complete=True):
    return {"schema": "testifex.analysis-data.v1", "revision": 1, "integrity": "verified",
            "sources": [{"artifact_id": eid(100), "parse_run_id": eid(101), "complete": complete, "family_id": None, "coverage_digest": eid(102), "reasons": []}],
            "events": [{"id": eid(n+1), "artifact_id": eid(100), "parse_run_id": eid(101), "fields": {"kind": "auth.failure", "host": "host", "actor": "operator"},
                        "recorded_time": tm.interval(n, n), "clock_model": clock(), "entity_assertion_ids": []} for n in range(count)],
            "duplicate_groups": [], "identity_assertions": [], "limitations": []}


def claim(predicate="record_observed", operands=None, selector=None):
    return {"schema": "testifex.claim.v1", "id": "claim-one", "predicate": predicate, "scope": {"all_at_revision": 1},
            "selector": selector or [], "operands": operands or {}, "assumptions": []}


class ClaimTests(unittest.TestCase):
    def test_observed_witness_and_absence_in_partial_stream(self):
        source = data(1, False)
        self.assertEqual(claims.evaluate_claim(claim(), source)["verdict"], "entailed")
        self.assertEqual(claims.evaluate_claim(claim("absent_in_stream"), source)["verdict"], "ruled_out")
        source["events"] = []
        self.assertEqual(claims.evaluate_claim(claim("absent_in_stream"), source)["verdict"], "unknown")
        source["sources"][0]["complete"] = True
        result = claims.evaluate_claim(claim("absent_in_stream"), source)
        self.assertEqual(result["verdict"], "entailed")
        self.assertIn("not_observed_in_the_supplied_stream", result["limitations"])

    def test_unknown_matching_field_prevents_false_absence(self):
        source = data(1)
        del source["events"][0]["fields"]["actor"]
        selected = [{"field": "actor", "op": "eq", "value": "operator"}]
        self.assertEqual(claims.evaluate_claim(claim("absent_in_stream", selector=selected), source)["verdict"], "unknown")
        source["events"][0]["fields"]["actor"] = None
        self.assertEqual(claims.evaluate_claim(claim(selector=[{"field": "actor", "op": "is_null"}]), source)["verdict"], "entailed")

    def test_closed_empty_scope_means_no_sources_not_all(self):
        value = claim("absent_in_stream")
        value["scope"] = {"artifact_ids": [], "active_parse_runs": [], "event_kinds": [], "time_filter": None}
        self.assertEqual(claims.evaluate_claim(value, data())["verdict"], "entailed")

    def test_unknown_time_blocks_time_bounded_absence(self):
        source = data(1)
        source["events"][0]["recorded_time"] = None
        value = claim("absent_in_stream")
        value["scope"] = claims.resolve_scope(value["scope"], source)
        value["scope"]["time_filter"] = {"after_us": "0", "before_us": "10", "basis": "recorded", "mode": "overlap"}
        self.assertEqual(claims.evaluate_claim(value, source)["verdict"], "unknown")

    def test_counts_distinct_observations_and_disjoint_duplicate_groups(self):
        source = data(3)
        source["duplicate_groups"] = [{"id": "copies", "event_ids": [eid(1), eid(2)]}]
        value = claim("count_at_least", {"threshold": 3, "unit": "normalized_observation"})
        self.assertEqual(claims.evaluate_claim(value, source)["verdict"], "entailed")
        value["operands"]["unit"] = "explicit_duplicate_group"
        result = claims.evaluate_claim(value, source)
        self.assertEqual(result["verdict"], "ruled_out")
        self.assertEqual((result["count"]["lower"], result["count"]["upper"]), (2, 2))
        self.assertEqual(len(result["witness_set"]), 2)
        source["duplicate_groups"].append({"id": "bad", "event_ids": [eid(2)]})
        with self.assertRaises(ProbentiumError):
            claims.evaluate_claim(value, source)

    def test_partial_count_upper_bound_is_null(self):
        source = data(1, False)
        value = claim("count_at_least", {"threshold": 2, "unit": "normalized_observation"})
        result = claims.evaluate_claim(value, source)
        self.assertEqual(result["verdict"], "unknown")
        self.assertIsNone(result["count"]["upper"])
        value["operands"]["threshold"] = 1
        self.assertEqual(claims.evaluate_claim(value, source)["verdict"], "entailed")

    def test_possible_memberships_do_not_assert_joint_feasibility(self):
        source = data(3)
        for index, coefficient in enumerate((-1, 1)):
            source["events"][index]["recorded_time"] = tm.interval(0, 0)
            source["events"][index]["clock_model"] = clock(shared=[{"id": "x", "coefficient": coefficient, "interval": tm.interval(-1, 1)}])
        source["events"][2]["recorded_time"] = tm.interval(0, 0)
        source["events"][2]["fields"]["kind"] = "auth.success"
        value = claim("count_at_least", {"threshold": 2, "unit": "normalized_observation", "anchor_event": eid(3), "window_us": "1"}, [{"field": "kind", "op": "eq", "value": "auth.failure"}])
        result = claims.evaluate_claim(value, source)
        self.assertEqual((result["verdict"], result["count"]["lower"], result["count"]["upper"]), ("unresolved", 0, 2))
        self.assertIn("joint_feasibility_not_evaluated", result["reasons"])
        for x in (-1, 0, 1):
            self.assertLess(sum(0 < -coefficient*x <= 1 for coefficient in (-1, 1)), 2)

    def test_missing_anchor_never_refutes_count(self):
        value = claim("count_at_least", {"threshold": 5, "unit": "normalized_observation", "anchor_event": eid(999), "window_us": "10"})
        self.assertEqual(claims.evaluate_claim(value, data())["verdict"], "unknown")
        value["operands"]["anchor_event"] = eid(1)
        source = data()
        source["events"][0]["clock_model"] = None
        self.assertEqual(claims.evaluate_claim(value, source)["verdict"], "unknown")

    def test_field_equality_null_and_namespaces(self):
        value = claim("field_equal", {"left": {"event_id": eid(1), "field": "actor"}, "right": {"event_id": eid(2), "field": "actor"}})
        source = data()
        self.assertEqual(claims.evaluate_claim(value, source)["verdict"], "entailed")
        source["events"][0]["fields"]["actor"] = None
        source["events"][1]["fields"]["actor"] = None
        self.assertEqual(claims.evaluate_claim(value, source)["verdict"], "unknown")
        value["operands"]["right"]["field"] = "host"
        with self.assertRaises(ProbentiumError):
            claims.evaluate_claim(value, source)

    def test_conflicting_identity_blocks_dependent_claim(self):
        source = data()
        source["identity_assertions"] = [{"id": eid(999), "status": "conflicting", "event_ids": [eid(1)], "source_family_ids": []}]
        source["events"][0]["entity_assertion_ids"] = [eid(999)]
        self.assertEqual(claims.evaluate_claim(claim(), source)["verdict"], "unknown")

    def test_incompatible_active_identity_bindings_are_detected(self):
        source = data()
        source["identity_assertions"] = [{"id": eid(900 + index), "status": "active", "event_ids": [eid(1)], "source_family_ids": [],
                                           "namespace": "actor", "canonical_value": label, "rationale": "Synthetic declaration"} for index, label in enumerate(("one", "two"))]
        source["events"][0]["entity_assertion_ids"] = [eid(900), eid(901)]
        result = claims.evaluate_claim(claim(), source)
        self.assertEqual(result["verdict"], "unknown")
        self.assertIn("identity_assumption_unavailable_or_conflicting", result["reasons"])

    def test_immutable_input_and_semantic_label_independence(self):
        source, value = data(), claim()
        snapshot = deepcopy(source)
        before = claims.analyze([value], source)
        value["human_label"] = "An unrelated display label"
        self.assertEqual(before, claims.analyze([value], source))
        self.assertEqual(source, snapshot)
        self.assertEqual(claims.compare_results(before, before)["changed"], [])

    def test_integrity_invalid_and_malformed_inputs_are_not_claim_refutations(self):
        source = data()
        source["integrity"] = "failed"
        self.assertEqual(claims.evaluate_claim(claim(), source)["verdict"], "invalid")
        for patch in ({"predicate": []}, {"selector": [{"field": "host", "op": "regex", "value": ".*"}]}, {"assumptions": [False]}):
            value = {**claim(), **patch}
            with self.assertRaises(ProbentiumError):
                claims.evaluate_claim(value, data())
        limited = claims.analyze([claim()], data(), max_memberships=1)
        self.assertEqual(limited["execution_state"], "aborted_limit")
        self.assertEqual(limited["evaluations"][0]["verdict"], "not_evaluated")
        malformed = {"schema": "testifex.analysis-result.v1", "engine_version": "1", "evaluations": [{}]}
        malformed["digest"] = object_digest(malformed, "TESTIFEX-ANALYSIS-RESULT-V1")
        with self.assertRaises(ProbentiumError):
            claims.compare_results(malformed, malformed)

    def test_exact_unicode_case_and_selector_limits(self):
        source = data(1)
        source["events"][0]["fields"]["actor"] = "Operator"
        self.assertEqual(claims.evaluate_claim(claim(selector=[{"field": "actor", "op": "eq", "value": "operator"}]), source)["verdict"], "ruled_out")
        with self.assertRaises(ProbentiumError):
            claims.validate_selector([{"field": "actor", "op": "is_null"}] * 33)
        with self.assertRaises(ProbentiumError):
            claims.validate_selector([{"field": "payload.pid", "op": "eq", "value": True}])
        for field, value in (("payload.remote_port", 65536), ("payload.pid", 2147483648), ("payload.uid", -1)):
            with self.assertRaises(ProbentiumError):
                claims.validate_selector([{"field": field, "op": "eq", "value": value}])

    def test_seeded_partial_count_bounds_match_independent_sets(self):
        rng = random.Random(49120)
        for _ in range(100):
            size = rng.randint(0, 25)
            source = data(size, complete=rng.choice((True, False)))
            labels = [rng.choice(("yes", "no", None)) for _ in range(size)]
            for event, label in zip(source["events"], labels):
                event["fields"]["actor"] = label
            threshold = rng.randint(1, 30)
            value = claim("count_at_least", {"threshold": threshold, "unit": "normalized_observation"}, [{"field": "actor", "op": "eq", "value": "yes"}])
            result = claims.evaluate_claim(value, source)
            lower = sum(label == "yes" for label in labels)
            upper = sum(label != "no" for label in labels) if source["sources"][0]["complete"] else None
            verdict = "entailed" if lower >= threshold else "unknown" if upper is None else "ruled_out" if upper < threshold else "unresolved"
            self.assertEqual((result["count"]["lower"], result["count"]["upper"], result["verdict"]), (lower, upper, verdict))

    def test_seeded_hostile_claims_never_escape_as_python_errors(self):
        rng = random.Random(2891)
        invalid = [None, True, 1.5, [], {}, "", "\x1b[2J", "\ud800"]
        for _ in range(250):
            value = claim()
            value[rng.choice(list(value))] = deepcopy(rng.choice(invalid))
            try:
                claims.evaluate_claim(value, data(1))
            except ProbentiumError:
                pass

    def test_large_witnesses_are_explicitly_bounded_without_changing_count(self):
        result = claims.evaluate_claim(claim("count_at_least", {"threshold": 500, "unit": "normalized_observation"}), data(500))
        self.assertEqual(result["verdict"], "entailed")
        self.assertEqual(result["count"]["lower"], 500)
        self.assertEqual(result["witness_count"], 500)
        self.assertEqual(len(result["witness_set"]), 256)
        self.assertFalse(result["witness_set_complete"])
        self.assertEqual(result["witness_set_digest"], object_digest([eid(n+1) for n in range(500)]))

    def test_diff_does_not_mislabel_new_events_as_clock_changes(self):
        source, value = data(), claim()
        value["scope"] = claims.resolve_scope(value["scope"], source)
        before = claims.analyze([value], source)
        source["events"][0]["id"] = eid(42)
        after = claims.analyze([value], source)
        self.assertEqual(claims.compare_results(before, after)["changed"][0]["reason_class"], "unknown")
        source["sources"][0]["parse_run_id"] = eid(999)
        for event in source["events"]:
            event["parse_run_id"] = eid(999)
        changed = claims.analyze([value], source)
        self.assertEqual(claims.compare_results(before, changed)["changed"][0]["reason_class"], "parser")


class DependencyProjectionTests(unittest.TestCase):
    def fixture(self):
        source = data(6)
        first = source["sources"][0]
        source["sources"] = [{**deepcopy(first), "artifact_id": eid(100 + 2*n), "parse_run_id": eid(101 + 2*n)} for n in range(3)]
        for n, event in enumerate(source["events"]):
            event["artifact_id"] = source["sources"][n//2]["artifact_id"]
            event["parse_run_id"] = source["sources"][n//2]["parse_run_id"]
        value = claim("count_at_least", {"threshold": 1, "unit": "normalized_observation"})
        value["scope"] = {"artifact_ids": [eid(100)], "active_parse_runs": [{"artifact_id": eid(100), "parse_run_id": eid(101)}],
                          "event_kinds": sorted(claims.KINDS), "time_filter": None}
        return value, source

    def assert_current_means_identical_analysis(self, value, before, after, expected_current):
        first, second = [claims.dependency_snapshot(value, data) for data in (before, after)]
        same = first["binding"] == second["binding"]
        self.assertEqual(same, expected_current)
        a, b = [claims.analyze([item["claim"]], item["data"]) for item in (first, second)]
        if same:
            self.assertEqual(a, b)
        else:
            self.assertNotEqual(a, b)

    def test_seeded_unrelated_updates_leave_exact_projected_analysis_identical(self):
        rng = random.Random(23029)
        for seed in range(40):
            value, before = self.fixture()
            after = deepcopy(before)
            after["revision"] += 1
            outside = after["events"][rng.randrange(2, 6)]
            outside["fields"]["actor"] = "outside-" + str(rng.randrange(10000))
            outside["clock_model"]["segments"][0]["local_error"] = tm.interval(-seed, seed)
            outside["entity_assertion_ids"] = [eid(800+seed)]
            after["identity_assertions"] = [{"id": eid(800+seed), "status": "conflicting", "event_ids": [outside["id"]], "source_family_ids": []}]
            after["sources"][2]["family_id"] = "unrelated-family"
            after["duplicate_groups"] = [{"id": "outside-duplicates", "event_ids": [eid(3), eid(4)]}]
            with self.subTest(seed=seed):
                self.assert_current_means_identical_analysis(value, before, after, True)

    def test_seeded_relevant_event_and_query_coverage_changes_invalidate(self):
        rng = random.Random(23030)
        for seed in range(30):
            value, before = self.fixture()
            after = deepcopy(before)
            if seed % 3 == 0:
                after["events"][0]["fields"]["actor"] = "relevant-" + str(rng.randrange(10000))
            elif seed % 3 == 1:
                after["sources"][0]["coverage_digest"] = eid(500 + seed)
            else:
                row = deepcopy(after["events"][0])
                row["id"] = eid(500 + seed)
                after["events"].append(row)
            with self.subTest(seed=seed):
                self.assert_current_means_identical_analysis(value, before, after, False)

    def test_transitive_identity_bridge_preserves_all_connected_premises(self):
        value, before = self.fixture()
        before["identity_assertions"] = [
            {"id": eid(800), "status": "active", "event_ids": [eid(1), eid(3)], "source_family_ids": []},
            {"id": eid(801), "status": "active", "event_ids": [eid(3), eid(5)], "source_family_ids": []}]
        before["events"][0]["entity_assertion_ids"] = [eid(800)]
        before["events"][2]["entity_assertion_ids"] = [eid(800), eid(801)]
        before["events"][4]["entity_assertion_ids"] = [eid(801)]
        selected = claims.dependency_snapshot(value, before)
        self.assertEqual({row["id"] for row in selected["data"]["events"]}, {eid(1), eid(2), eid(3), eid(5)})
        after = deepcopy(before)
        after["identity_assertions"][1]["status"] = "withdrawn"
        self.assert_current_means_identical_analysis(value, before, after, False)
        after = deepcopy(before)
        after["events"][4]["fields"]["actor"] = "changed-transitive-premise"
        self.assert_current_means_identical_analysis(value, before, after, False)

    def test_new_identity_bridge_is_detected_without_a_previous_edge(self):
        value, before = self.fixture()
        after = deepcopy(before)
        after["identity_assertions"] = [{"id": eid(800), "status": "active", "event_ids": [eid(1), eid(3)], "source_family_ids": []}]
        after["events"][0]["entity_assertion_ids"] = [eid(800)]
        after["events"][2]["entity_assertion_ids"] = [eid(800)]
        self.assert_current_means_identical_analysis(value, before, after, False)

    def test_duplicate_and_family_membership_cross_scope_expansion_invalidate(self):
        value, before = self.fixture()
        before["duplicate_groups"] = [{"id": "linked", "event_ids": [eid(1), eid(3)]}]
        after = deepcopy(before)
        after["duplicate_groups"][0]["event_ids"].append(eid(5))
        self.assert_current_means_identical_analysis(value, before, after, False)
        value, before = self.fixture()
        before["sources"][0]["family_id"] = "declared-family"
        after = deepcopy(before)
        after["sources"][2]["family_id"] = "declared-family"
        self.assert_current_means_identical_analysis(value, before, after, False)

    def test_same_clock_name_outside_scope_is_not_a_global_clock_binding(self):
        value, before = self.fixture()
        after = deepcopy(before)
        after["events"][4]["clock_model"]["segments"][0]["local_error"] = tm.interval(-500, 500)
        self.assert_current_means_identical_analysis(value, before, after, True)
        before["events"][0]["clock_model"]["basis_refs"] = [eid(5)]
        after = deepcopy(before)
        after["events"][4]["fields"]["actor"] = "changed-clock-basis"
        self.assert_current_means_identical_analysis(value, before, after, False)

    def test_scoped_absence_detects_new_matching_event_and_retains_unknown_candidates(self):
        value, before = self.fixture()
        value["predicate"], value["operands"] = "absent_in_stream", {}
        value["selector"] = [{"field": "actor", "op": "eq", "value": "target"}]
        after = deepcopy(before)
        after["events"][1]["fields"].pop("actor")
        self.assert_current_means_identical_analysis(value, before, after, False)
        after = deepcopy(before)
        row = deepcopy(after["events"][0])
        row["id"], row["fields"]["actor"] = eid(500), "target"
        after["events"].append(row)
        self.assert_current_means_identical_analysis(value, before, after, False)
        selected = claims.dependency_snapshot(value, after)
        self.assertEqual(claims.analyze([value], selected["data"])["evaluations"][0]["verdict"], "ruled_out")

    def test_explicit_assumption_outside_scope_and_global_integrity_remain_dependencies(self):
        value, before = self.fixture()
        before["identity_assertions"] = [{"id": eid(800), "status": "active", "event_ids": [eid(5)], "source_family_ids": []}]
        before["events"][4]["entity_assertion_ids"] = [eid(800)]
        value["assumptions"] = [eid(800)]
        after = deepcopy(before)
        after["identity_assertions"][0]["status"] = "withdrawn"
        self.assert_current_means_identical_analysis(value, before, after, False)
        after = deepcopy(before)
        after["integrity"] = "unavailable"
        self.assert_current_means_identical_analysis(value, before, after, False)

    def test_projection_is_idempotent_and_does_not_mutate_input(self):
        value, before = self.fixture()
        saved = deepcopy(before)
        selected = claims.dependency_snapshot(value, before)
        repeated = claims.dependency_snapshot(selected["claim"], selected["data"])
        self.assertEqual(selected, repeated)
        self.assertEqual(before, saved)

    def test_family_basis_closes_across_sources_and_rejects_malformed_premises(self):
        value, before = self.fixture()
        premises = {eid(100): {"binding_id": eid(900), "basis_refs": [eid(5)]}}
        selected = claims.dependency_snapshot(value, before, family_premises=premises)
        self.assertIn(eid(5), [row["id"] for row in selected["data"]["events"]])
        after = deepcopy(before)
        after["events"][4]["fields"]["actor"] = "changed family basis"
        changed = claims.dependency_snapshot(value, after, family_premises=premises)
        self.assertNotEqual(selected["binding"], changed["binding"])
        for bad in ([], {eid(100): {"binding_id": True, "basis_refs": []}},
                    {eid(100): {"binding_id": eid(900), "basis_refs": ["not-an-identity"]}}):
            with self.subTest(premises=bad):
                with self.assertRaises(ProbentiumError):
                    claims.dependency_snapshot(value, before, family_premises=bad)

    def test_compare_accepts_strict_scoped_extension_and_exposes_dependency_only_change(self):
        value, source = self.fixture()
        selected = claims.dependency_snapshot(value, source)
        before = claims.analyze([selected["claim"]], selected["data"])
        before["dependency_fingerprint"] = selected["binding"]["fingerprint"]
        before["digest"] = object_digest({key: item for key, item in before.items() if key != "digest"}, "TESTIFEX-ANALYSIS-RESULT-V1")
        same = claims.compare_results(before, before)
        self.assertEqual(same["changed"], [])
        self.assertFalse(same["dependencies"]["changed"])
        after = deepcopy(before)
        after["dependency_fingerprint"] = eid(888)
        after["digest"] = object_digest({key: item for key, item in after.items() if key != "digest"}, "TESTIFEX-ANALYSIS-RESULT-V1")
        compared = claims.compare_results(before, after)
        self.assertTrue(compared["dependencies"]["changed"])
        self.assertEqual(compared["changed"], [{"claim_id": value["id"], "before": "entailed", "after": "entailed", "reason_class": "dependency"}])

    def test_compare_scoped_and_legacy_contracts_are_explicitly_incomparable(self):
        value, source = self.fixture()
        selected = claims.dependency_snapshot(value, source)
        legacy = claims.analyze([selected["claim"]], selected["data"])
        scoped = deepcopy(legacy)
        scoped["dependency_fingerprint"] = selected["binding"]["fingerprint"]
        scoped["digest"] = object_digest({key: item for key, item in scoped.items() if key != "digest"}, "TESTIFEX-ANALYSIS-RESULT-V1")
        for before, after in ((legacy, scoped), (scoped, legacy)):
            self.assertEqual(claims.compare_results(before, after), {"status": "incomparable", "reason": "dependency_contract_changed", "added": [], "removed": [], "changed": []})
        self.assertEqual(claims.compare_results(legacy, legacy)["status"], "comparable")

    def test_compare_rejects_unknown_fields_bad_fingerprint_and_unsupported_scoped_batch(self):
        value, source = self.fixture()
        selected = claims.dependency_snapshot(value, source)
        result = claims.analyze([selected["claim"]], selected["data"])
        for patch in ({"dependency_fingerprint": None}, {"dependency_fingerprint": "A" * 64},
                      {"dependency_fingerprint": eid(880), "future_extension": 1}, {"unexpected": True}):
            bad = {**deepcopy(result), **patch}
            bad["digest"] = object_digest({key: item for key, item in bad.items() if key != "digest"}, "TESTIFEX-ANALYSIS-RESULT-V1")
            with self.subTest(patch=patch):
                with self.assertRaises(ProbentiumError):
                    claims.compare_results(bad, bad)
        other = {**deepcopy(selected["claim"]), "id": "another-claim"}
        batch = claims.analyze([selected["claim"], other], selected["data"])
        batch["dependency_fingerprint"] = eid(880)
        batch["digest"] = object_digest({key: item for key, item in batch.items() if key != "digest"}, "TESTIFEX-ANALYSIS-RESULT-V1")
        with self.assertRaises(ProbentiumError) as caught:
            claims.compare_results(batch, batch)
        self.assertEqual(caught.exception.code, "invalid_scoped_analysis_result")


class AnalysisResourceTests(unittest.TestCase):
    def test_chunked_semantic_digest_equals_materialized_contract(self):
        source = data(1025)
        shared = clock()
        for i, event in enumerate(source["events"]):
            event["clock_model"] = None if i % 7 == 0 else shared
            event["fields"]["actor"] = "operator-\u017e-\U0001f642" if i % 11 else 'quote"slash\\'
        original = deepcopy(source)
        for domain in ("PROBENTIUM-OBJECT-V1", "TESTIFEX-CASE-ANALYSIS-INPUT-V1"):
            self.assertEqual(claims.semantic_digest(source, domain), object_digest(claims.semantic_data(source), domain))
        self.assertEqual(source, original)
        source["events"] = []
        self.assertEqual(claims.semantic_digest(source), object_digest(claims.semantic_data(source)))

    def test_expression_cache_is_bounded_without_changing_results(self):
        source = data(1100)
        cache = {}
        first = claims._reference(source["events"][0], cache)
        for row in source["events"]:
            claims._reference(row, cache)
        self.assertLessEqual(len(cache["expressions"]), 1024)
        self.assertNotIn(source["events"][0]["id"], cache["expressions"])
        self.assertEqual(claims._reference(source["events"][0], cache), first)

    def test_reused_memberships_match_individual_evaluations(self):
        source = data(25, False)
        source["events"][-1]["fields"]["kind"] = "auth.success"
        source["events"][3]["fields"]["actor"] = None
        source["events"][5]["recorded_time"] = None
        source["duplicate_groups"] = [{"id": "copy", "event_ids": [eid(1), eid(2)]}]
        values = []
        for index, unit in enumerate(("normalized_observation", "explicit_duplicate_group", "normalized_observation")):
            item = claim("count_at_least", {"threshold": index + 2, "unit": unit, "anchor_event": eid(25), "window_us": "15"},
                         [{"field": "kind", "op": "eq", "value": "auth.failure"}])
            item["id"] = "count-" + str(index)
            values.append(item)
        expected = [claims.evaluate_claim(item, source) for item in values]
        self.assertEqual(claims.analyze(values, source)["evaluations"], expected)

    def test_analysis_limits_are_explicit_validated_and_digest_bound(self):
        old = claims.analyze([claim()], data())
        new = claims.analyze([claim()], data(), analysis_limits={})
        self.assertNotIn("analysis_limits", old["limits"])
        self.assertEqual(new["limits"], new["input"]["limits"])
        self.assertNotEqual(old["input_digest"], new["input_digest"])
        self.assertEqual(claims.compare_results(old, new)["changed"][0]["reason_class"], "resource_budget")
        for invalid in ({"max_events": True}, {"max_claims": 10001}, {"max_time_variables": 33}, {"unknown": 1}):
            with self.subTest(invalid=invalid), self.assertRaises(ProbentiumError):
                claims.analyze([claim()], data(), analysis_limits=invalid)
        altered = deepcopy(new)
        altered["limits"]["analysis_limits"]["unexpected"] = 1
        altered["digest"] = object_digest({k: v for k, v in altered.items() if k != "digest"}, "TESTIFEX-ANALYSIS-RESULT-V1")
        with self.assertRaises(ProbentiumError):
            claims.compare_results(altered, altered)

    def test_relation_support_and_finding_exhaustion_never_return_partial_truth(self):
        source = data(4)
        values = [claim("ordered_within", {"before": eid(1), "after": eid(2), "window_us": "5"}),
                  {**claim(), "id": "other"}]
        for limits, code in (({"max_support_refs": 1}, "analysis_support_limit"), ({"max_findings": 1}, "analysis_finding_limit")):
            with self.subTest(limits=limits):
                result = claims.analyze(values, source, analysis_limits=limits)
                self.assertEqual(result["execution_state"], "aborted_limit")
                self.assertTrue(all(row["verdict"] == "not_evaluated" and row["reasons"] == [code] for row in result["evaluations"]))
        count = claim("count_at_least", {"threshold": 1, "unit": "normalized_observation", "anchor_event": eid(4), "window_us": "5"})
        result = claims.analyze([count], source, analysis_limits={"max_relations": 1})
        self.assertEqual(result["evaluations"][0]["reasons"], ["analysis_relation_limit"])

    def test_time_variable_limit_is_pair_wide_and_preserves_legacy(self):
        source = data(2)
        for index, row in enumerate(source["events"]):
            row["clock_model"] = clock(shared=[{"id": f"v{index}-{n}", "coefficient": 1, "interval": tm.interval(-1, 1)} for n in range(17)])
        item = claim("ordered_within", {"before": eid(1), "after": eid(2), "window_us": "5"})
        self.assertEqual(claims.analyze([item], source)["execution_state"], "complete")
        bounded = claims.analyze([item], source, analysis_limits={})
        self.assertEqual(bounded["evaluations"][0]["reasons"], ["analysis_time_variable_limit"])

    def test_explicit_claim_limit_increase_and_report_limit(self):
        values = [{**claim(), "id": "claim-" + str(i)} for i in range(1001)]
        with self.assertRaises(ProbentiumError):
            claims.analyze(values, data(0))
        result = claims.analyze(values, data(0), analysis_limits={"max_claims": 1001})
        self.assertEqual(len(result["evaluations"]), 1001)
        self.assertEqual(claims.compare_results(result, result)["changed"], [])
        with self.assertRaises(ProbentiumError) as caught:
            claims.analyze([claim()], data(), analysis_limits={"max_report_bytes": 1024})
        self.assertEqual(caught.exception.code, "analysis_report_limit")

    def test_dependency_configuration_is_part_of_currentness(self):
        source = data()
        first = claims.dependency_snapshot(claim(), source, analysis_limits={})
        changed = claims.dependency_snapshot(claim(), source, analysis_limits={"max_relations": 2})
        self.assertNotEqual(first["binding"]["fingerprint"], changed["binding"]["fingerprint"])
        with self.assertRaises(ProbentiumError) as caught:
            claims.dependency_snapshot(claim(), source, analysis_limits={"max_dependency_edges": 1})
        self.assertEqual(caught.exception.code, "dependency_edge_limit")
