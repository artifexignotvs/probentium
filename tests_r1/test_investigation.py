"""Historia, fontes et recensiones sine mutatione priorum probantur."""
from copy import deepcopy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from collections.abc import Mapping, Sequence

from probentium.contracts import ProbentiumError, canonical_bytes, object_digest
from probentium.store import CaseStore
from probentium import investigation as inv
from probentium import time_model as tm
from test_claims import claim, data, eid
from test_time_model import clock


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = CaseStore.create(self.root / "case", "Synthetic investigation")
        self.addCleanup(self.case.close)
        path = self.root / "events.jsonl"
        rows = [{"kind": "auth.failure", "timestamp": "2026-10-18T12:00:00Z", "host": "host", "actor": "operator"},
                {"kind": "auth.success", "timestamp": "2026-10-18T12:00:05Z", "host": "host", "actor": "operator"},
                {"kind": "process.exec", "timestamp": "2026-10-18T12:00:06Z", "host": "host", "actor": "operator", "path": "/usr/bin/true"}]
        path.write_bytes(b"".join(canonical_bytes(row) + b"\n" for row in rows))
        self.source = self.case.ingest(path, "events", "Synthetic source")
        self.events = {row["kind"]: row for row in self.case.query_events(limit=1000)["rows"]}

    def current_claim(self, predicate="record_observed", operands=None):
        value = claim(predicate, operands)
        value["scope"]["all_at_revision"] = self.case.revision
        return value

    def put_clock(self):
        value = clock()
        value["segments"][0]["validity"] = tm.interval(tm.MIN_TIME_US, tm.MAX_TIME_US, True, False)
        return inv.save_clock(self.case, value, [self.source["id"]], expected_revision=self.case.revision)

    def test_load_all_pages_and_absence_of_implicit_alignment(self):
        loaded = inv.load_data(self.case)
        self.assertEqual(len(loaded["events"]), 3)
        self.assertTrue(all(row["clock_model"] is None for row in loaded["events"]))
        self.assertEqual(loaded["integrity"], "verified")
        self.assertTrue(loaded["sources"][0]["complete"])

    def test_claim_freezes_catalog_and_evaluation_does_not_stale_itself(self):
        saved = inv.save_claim(self.case, self.current_claim(), expected_revision=self.case.revision)
        self.assertNotIn("all_at_revision", saved["data"]["claim"]["scope"])
        evaluation = inv.evaluate(self.case, saved["id"], expected_revision=self.case.revision)
        self.assertEqual(evaluation["data"]["result"]["evaluations"][0]["verdict"], "entailed")
        self.assertEqual(inv.stale_status(self.case, evaluation["id"])["status"], "current")
        self.case.put_object("note", {"text": "Decoration does not change semantic inputs"})
        self.assertEqual(inv.stale_status(self.case, evaluation["id"])["status"], "current")

    def test_frozen_all_at_revision_excludes_new_unrelated_artifact(self):
        saved = inv.save_claim(self.case, self.current_claim())
        evaluation = inv.evaluate(self.case, saved["id"])
        previous = deepcopy(evaluation)
        path = self.root / "more.jsonl"
        path.write_bytes(canonical_bytes({"kind": "generic", "timestamp": None, "action": "new observation"}) + b"\n")
        self.case.ingest(path, "events", "Additional source")
        state = inv.stale_status(self.case, evaluation["id"])
        self.assertEqual(state["status"], "current")
        self.assertTrue(state["global_input_changed"])
        self.assertEqual(state["original_dependency_digest"], state["current_dependency_digest"])
        self.assertEqual(self.case.get_object(evaluation["id"]), previous)

    def test_clock_assumption_changes_unknown_order_and_stales_old_result(self):
        value = self.current_claim("ordered_within", {"before": self.events["auth.failure"]["id"], "after": self.events["auth.success"]["id"], "window_us": "10000000"})
        saved = inv.save_claim(self.case, value)
        unknown = inv.evaluate(self.case, saved["id"])
        self.assertEqual(unknown["data"]["result"]["evaluations"][0]["verdict"], "unknown")
        self.put_clock()
        known = inv.evaluate(self.case, saved["id"])
        self.assertEqual(known["data"]["result"]["evaluations"][0]["verdict"], "entailed")
        self.assertEqual(inv.stale_status(self.case, unknown["id"])["status"], "stale")
        self.assertEqual(inv.stale_status(self.case, known["id"])["status"], "current")

    def test_history_requires_latest_predecessor_and_revision_conflicts(self):
        saved = inv.save_claim(self.case, self.current_claim())
        old_revision = self.case.revision
        value = self.current_claim()
        value["human_label"] = "A clarified label"
        with self.assertRaises(ProbentiumError):
            inv.save_claim(self.case, value)
        new = inv.save_claim(self.case, value, previous_id=saved["id"])
        self.assertEqual(new["data"]["previous_id"], saved["id"])
        with self.assertRaises(ProbentiumError):
            inv.evaluate(self.case, new["id"], expected_revision=old_revision)
        with self.assertRaises(ProbentiumError):
            inv.save_claim(self.case, value, previous_id=saved["id"])

    def test_dependency_cycles_missing_refs_and_transitive_staleness(self):
        a, b, c = eid(1), eid(2), eid(3)
        edges = [{"dependency": a, "dependent": b, "type": "supports"}, {"dependency": b, "dependent": c, "type": "uses"}]
        self.assertEqual(inv.stale_descendants([a,b,c], edges, [a]), [b,c])
        with self.assertRaises(ProbentiumError):
            inv.validate_graph([a,b,c], edges + [{"dependency": c, "dependent": a, "type": "cycle"}])
        with self.assertRaises(ProbentiumError):
            inv.validate_graph([a,b], edges)
        before = self.case.revision
        with self.assertRaises(ProbentiumError):
            inv.save_dependency_graph(self.case, [a,b], edges[:1])
        self.assertEqual(self.case.revision, before)

    def test_family_overlay_removes_clock_basis_without_mutating_case(self):
        source = data(3)
        source["sources"][0]["family_id"] = "one"
        source["sources"].append({**deepcopy(source["sources"][0]), "artifact_id": eid(200), "parse_run_id": eid(201), "family_id": "two"})
        source["events"][2].update(artifact_id=eid(200), parse_run_id=eid(201))
        source["events"][2]["clock_model"]["source_family_ids"] = ["one"]
        before = deepcopy(source)
        scenario = {"schema": "testifex.scenario.v1", "id": "remove-one", "remove_families": ["one"], "exclude_duplicate_groups": [], "revoke_identities": [], "widen_clock_errors": []}
        result = inv.apply_scenario(source, scenario)
        self.assertEqual(len(result["events"]), 1)
        self.assertIsNone(result["events"][0]["clock_model"])
        self.assertEqual(source, before)

    def test_scenario_removed_anchor_unknown_and_source_bytes_unchanged(self):
        self.put_clock()
        inv.save_family(self.case, "synthetic-family", [self.source["id"]], [], "Declared single synthetic export")
        value = self.current_claim("ordered_within", {"before": self.events["auth.failure"]["id"], "after": self.events["auth.success"]["id"], "window_us": "10000000"})
        saved = inv.save_claim(self.case, value)
        before = self.case.raw(self.events["auth.success"]["id"])
        scenario = {"schema": "testifex.scenario.v1", "id": "without-source", "remove_families": ["synthetic-family"], "exclude_duplicate_groups": [], "revoke_identities": [], "widen_clock_errors": []}
        result = inv.run_scenario(self.case, [saved["id"]], scenario)
        self.assertEqual(result["data"]["scenario_result"]["evaluations"][0]["verdict"], "unknown")
        self.assertEqual(self.case.raw(self.events["auth.success"]["id"]), before)
        self.assertTrue(self.case.verify()["ok"])

    def test_sensitivity_unknown_families_cannot_claim_complete(self):
        saved = inv.save_claim(self.case, self.current_claim())
        result = inv.sensitivity(self.case, [saved["id"]])
        self.assertFalse(result["plan_complete"])
        self.assertEqual(result["sources_without_family"], 1)
        inv.save_family(self.case, "family", [self.source["id"]], [], "Declared shared source")
        result = inv.sensitivity(self.case, [saved["id"]])
        self.assertTrue(result["plan_complete"])
        self.assertEqual(len(result["results"]), 1)

    def test_correlation_templates_are_conditional_and_unknown_without_clocks(self):
        before = inv.correlate(self.case, "auth_after_failures", window_us="10000000", threshold=1)
        self.assertEqual(before["findings"][0]["verdict"], "unknown")
        self.put_clock()
        after = inv.correlate(self.case, "auth_after_failures", window_us="10000000", threshold=1)
        self.assertEqual(after["findings"][0]["verdict"], "entailed")
        process = inv.correlate(self.case, "post_auth_process", window_us="10000000")
        self.assertEqual(process["findings"][0]["verdict"], "entailed")
        self.assertIn("causality", process["findings"][0]["limitation"])

    def test_snapshot_replay_recomputes_claims_and_detects_changed_result(self):
        saved = inv.save_claim(self.case, self.current_claim())
        inv.evaluate(self.case, saved["id"])
        snapshot = self.case.export_snapshot()
        self.assertEqual(inv.replay_snapshot(snapshot)["analysis_replay"], "passed")
        record = next(row for row in snapshot["objects"] if row["kind"] == "evaluation")
        record["data"]["result"]["evaluations"][0]["verdict"] = "ruled_out"
        self.assertEqual(inv.replay_snapshot(snapshot)["analysis_replay"], "failed")

    def test_review_reference_binding_current_then_historical(self):
        saved = inv.save_claim(self.case, self.current_claim())
        result = inv.evaluate(self.case, saved["id"])
        rationale = "Reviewed the synthetic scoped observation."
        self.case.put_object("review_rationale", {"text": rationale})
        decision = {"claim_id": saved["id"], "claim_revision": saved["revision"], "evaluation_digest": result["data"]["result"]["digest"],
                    "snapshot_digest": result["data"]["data_fingerprint"], "rationale_digest": hashlib.sha256(rationale.encode()).hexdigest(), "previous_decision_id": None}
        self.assertEqual(inv.resolve_review_references(self.case, decision)["status"], "current")
        self.put_clock()
        self.assertEqual(inv.resolve_review_references(self.case, decision)["status"], "historical")
        decision["rationale_digest"] = eid(888)
        self.assertEqual(inv.resolve_review_references(self.case, decision)["status"], "pending_references")

    def test_widening_must_not_narrow_unknown_or_finite_error(self):
        source = data(1)
        source["events"][0]["clock_model"]["segments"][0]["local_error"] = tm.interval(-5, 5)
        scenario = {"schema": "testifex.scenario.v1", "id": "narrow", "remove_families": [], "exclude_duplicate_groups": [], "revoke_identities": [],
                    "widen_clock_errors": [{"clock_id": "clock", "local_error": tm.interval(-1, 1)}]}
        with self.assertRaises(ProbentiumError):
            inv.apply_scenario(source, scenario)

    def test_dense_correlation_is_rejected_before_cartesian_scan(self):
        source = data(1001)
        for event in source["events"]:
            event["fields"]["kind"] = "auth.success"
        with patch.object(inv, "load_data", return_value=source):
            with self.assertRaises(ProbentiumError) as caught:
                inv.correlate(self.case, "post_auth_process", window_us="10")
            self.assertEqual(caught.exception.code, "correlation_scan_limit")
        self.assertTrue(self.case.verify()["ok"])

    def test_snapshot_replay_accepts_bounded_reiterable_tables(self):
        saved = inv.save_claim(self.case, self.current_claim())
        inv.evaluate(self.case, saved["id"])
        snapshot = self.case.export_snapshot()
        class Table(Sequence):
            def __init__(self, rows):
                self.rows = rows
            def __len__(self):
                return len(self.rows)
            def __getitem__(self, key):
                return self.rows[key]
        class View(Mapping):
            def __getitem__(self, key):
                value = snapshot[key]
                return Table(value) if isinstance(value, list) else value
            def __iter__(self):
                return iter(snapshot)
            def __len__(self):
                return len(snapshot)
        self.assertEqual(inv.replay_snapshot(View())["analysis_replay"], "passed")

    def test_graph_edges_across_saved_revisions_cannot_create_cycle(self):
        first = self.case.put_object("note", {"text": "First"})["id"]
        second = self.case.put_object("note", {"text": "Second"})["id"]
        inv.save_dependency_graph(self.case, [first, second], [{"dependency": first, "dependent": second, "type": "supports"}])
        revision = self.case.revision
        with self.assertRaises(ProbentiumError) as caught:
            inv.save_dependency_graph(self.case, [first, second], [{"dependency": second, "dependent": first, "type": "supports"}])
        self.assertEqual(caught.exception.code, "dependency_cycle")
        self.assertEqual(self.case.revision, revision)

    def test_streamed_history_replay_uses_disk_locators_and_rejects_omission(self):
        from probentium.exchange import export_case, open_verified_snapshot
        saved = inv.save_claim(self.case, self.current_claim())
        inv.evaluate(self.case, saved["id"])
        packet = self.root / "history.pbp"
        export_case(self.case, packet)
        with open_verified_snapshot(packet) as (_, snapshot, _):
            with patch.object(inv, "_stream_historical_prefixes", wraps=inv._stream_historical_prefixes) as streamed:
                self.assertEqual(inv.replay_snapshot(snapshot)["analysis_replay"], "passed")
            self.assertEqual(streamed.call_count, 1)
            original = snapshot.iter_run_records
            def omitted(run_id):
                yield from list(original(run_id))[1:]
            with patch.object(snapshot, "iter_run_records", side_effect=omitted):
                self.assertEqual(inv.replay_snapshot(snapshot)["analysis_replay"], "failed")

    def test_unstreamed_large_history_fails_before_materialization_with_unavailable(self):
        saved = inv.save_claim(self.case, self.current_claim())
        inv.evaluate(self.case, saved["id"])
        snapshot = self.case.export_snapshot()
        class LargeRows(Sequence):
            def __len__(self):
                return 250001
            def __getitem__(self, key):
                raise AssertionError("Rows must not be materialized")
        snapshot["records"] = LargeRows()
        result = inv.replay_snapshot(snapshot)
        self.assertEqual(result, {"analysis_replay": "unavailable", "issues": ["analysis_replay_resource_limit"]})

    def test_malformed_stored_claim_currentness_returns_fixed_integrity_error(self):
        self.case.put_object("claim", {"claim": {"id": []}})
        with self.assertRaises(ProbentiumError) as caught:
            inv.stale_status_many(self.case, [])
        self.assertEqual((caught.exception.code, caught.exception.exit_code), ("invalid_investigation_object", 4))

    def test_canonical_payload_fields_are_retained_for_exact_queries(self):
        path = self.root / "canonical.jsonl"
        path.write_bytes(canonical_bytes({"schema": "testifex.events.v2", "kind": "process.start", "recorded_time": None, "origin": None,
                                        "payload": {"pid": 7, "executable": "/usr/bin/true", "command": "true"}}) + b"\n")
        self.case.ingest(path, "events-v2", "Synthetic canonical event")
        loaded = inv.load_data(self.case)
        event = next(row for row in loaded["events"] if row["fields"]["kind"] == "process.start")
        self.assertEqual(event["fields"]["payload.pid"], 7)
        self.assertEqual(event["fields"]["payload.command"], "true")

    def test_analysis_read_budget_aborts_without_mutating_case(self):
        revision = self.case.revision
        with patch.object(inv, "MAX_ANALYSIS_BYTES", 1):
            with self.assertRaises(ProbentiumError) as caught:
                inv.load_data(self.case)
            self.assertEqual(caught.exception.code, "analysis_data_size_limit")
        self.assertEqual(self.case.revision, revision)

    def test_demonstration_requires_synthetic_declaration_and_is_replayable(self):
        with self.assertRaises(ProbentiumError):
            inv.build_demonstration(self.case)
        self.case.put_object("scenario", {"synthetic": True, "artifacts": [self.source["id"]]})
        result = inv.build_demonstration(self.case)
        self.assertEqual((result["unknown_verdict"], result["aligned_verdict"], result["scenario_verdict"]), ("unknown", "entailed", "unresolved"))
        self.assertEqual(inv.replay_snapshot(self.case.export_snapshot())["analysis_replay"], "passed")

    def test_snapshot_replays_partial_coverage_after_resume(self):
        import probentium.store as storage
        path = self.root / "partial.jsonl"
        path.write_bytes(b"".join(canonical_bytes({"kind": "generic", "action": str(n)}) + b"\n" for n in range(4)))
        with patch.object(storage, "MAX_RECORDS", 2):
            source = self.case.ingest(path, "events", "Partial synthetic input")
        saved = inv.save_claim(self.case, self.current_claim("absent_in_stream"))
        inv.evaluate(self.case, saved["id"])
        self.case.resume(source["id"])
        snapshot = self.case.export_snapshot()
        self.assertEqual(inv.replay_snapshot(snapshot)["analysis_replay"], "passed")
        value = next(row for row in snapshot["objects"] if row["kind"] == "evaluation")["data"]
        value["source_catalog"][0]["coverage_snapshot"]["records_total"] += 1
        self.assertEqual(inv.replay_snapshot(snapshot)["analysis_replay"], "failed")

    def test_partial_verification_cannot_claim_verified_observation(self):
        original = self.case.verify()
        with patch.object(self.case, "verify", return_value={**original, "completeness": "partial", "authorized_unavailable": [self.source["id"]]}):
            loaded = inv.load_data(self.case)
        self.assertEqual(loaded["integrity"], "unavailable")

    def test_identity_revisions_have_immutable_interpretation_references(self):
        event = self.events["auth.success"]["id"]
        declaration = {"id": eid(900), "status": "active", "event_ids": [event], "source_family_ids": [],
                       "namespace": "actor", "canonical_value": "operator", "rationale": "Synthetic explicit entity binding"}
        first = inv.save_identity(self.case, declaration)
        old = next(row for row in inv.load_data(self.case)["events"] if row["id"] == event)
        self.assertEqual(old["entity_assertion_ids"], [first["id"]])
        declaration["status"] = "withdrawn"
        second = inv.save_identity(self.case, declaration)
        new = next(row for row in inv.load_data(self.case)["events"] if row["id"] == event)
        self.assertEqual(new["entity_assertion_ids"], [second["id"]])

    def test_batched_correlation_matches_separate_evaluations(self):
        self.put_clock()
        data = inv.load_data(self.case)
        requests = [{"template": name, "window_us": "10000000", "threshold": 1} for name in ("auth_after_failures", "post_auth_process")]
        together = inv.correlate_many_data(data, requests)
        for request, grouped in zip(requests, together["templates"]):
            separate = inv.correlate_data(data, **request)
            self.assertEqual(grouped["findings"], separate["findings"])
        with self.assertRaises(ProbentiumError):
            inv.correlate_many_data(data, requests + requests)

    def test_explain_retains_evidence_lineage_after_new_claim_revision(self):
        saved = inv.save_claim(self.case, self.current_claim())
        evaluation = inv.evaluate(self.case, saved["id"])
        revised = self.current_claim()
        revised["human_label"] = "Revised synthetic description"
        inv.save_claim(self.case, revised, previous_id=saved["id"])
        result = inv.explain(self.case, evaluation["id"])
        self.assertEqual(result["staleness"]["status"], "stale")
        self.assertTrue(any(path[-1] == self.source["id"] for path in result["paths"]))
        self.assertEqual(result["dependency_bindings"]["claim_revision"], saved["id"])

    def test_explanation_graph_has_exact_record_locators_and_interpretations(self):
        saved = inv.save_claim(self.case, self.current_claim())
        result = inv.evaluate(self.case, saved["id"])
        explanation = inv.explain(self.case, result["id"])
        graph = explanation["witness_graph"]
        self.assertTrue(graph["complete"])
        self.assertEqual(graph["count"], graph["shown"])
        identities = {row["id"]: inv.claims.interpretation_id(row) for row in inv.load_data(self.case)["events"]}
        for item in graph["witnesses"]:
            event = next(row for row in self.events.values() if row["id"] == item["event_id"])
            self.assertEqual(item["interpretation_id"], identities[event["id"]])
            self.assertEqual(item["records"][0], {"record_id": event["primary_record_ref"], "artifact_id": event["artifact_id"],
                **{key: event[key] for key in ("ordinal", "offset", "length", "raw_digest")}})
            self.assertEqual(item["raw_verification"], "case_record_bytes_verified")
        self.assertEqual(graph["witness_set_digest"], object_digest(result["data"]["result"]["evaluations"][0]["witness_set"]))
        self.assertIn("stored_evaluation_not_reexecuted_by_explain", graph["limitations"])

    def test_witness_is_base64_only_and_rejects_unrelated_event(self):
        import base64
        value = self.current_claim()
        value["selector"] = [{"field": "kind", "op": "eq", "value": "auth.success"}]
        saved = inv.save_claim(self.case, value)
        result = inv.evaluate(self.case, saved["id"])
        event = self.events["auth.success"]["id"]
        witness = inv.witness(self.case, result["id"], event)
        raw = self.case.raw(event)
        self.assertEqual(base64.b64decode(witness["raw_base64"], validate=True), raw)
        self.assertEqual(witness["raw_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertNotIn("raw_text", witness)
        self.assertNotIn("operator", canonical_bytes(witness).decode())
        with patch.object(self.case, "raw", side_effect=AssertionError("unrelated raw read")):
            with self.assertRaises(ProbentiumError) as caught:
                inv.witness(self.case, result["id"], self.events["process.exec"]["id"])
        self.assertEqual(caught.exception.code, "event_not_in_saved_witness_excerpt")

    def test_historical_witness_retains_old_interpretation_after_clock_revision(self):
        self.put_clock()
        saved = inv.save_claim(self.case, self.current_claim())
        old = inv.evaluate(self.case, saved["id"])
        identity = old["data"]["result"]["evaluations"][0]["witness_set"][0]
        first = inv.witness(self.case, old["id"], identity)
        model = clock(local=tm.interval(-10, 10))
        model["segments"][0]["validity"] = tm.interval(tm.MIN_TIME_US, tm.MAX_TIME_US, True, False)
        inv.save_clock(self.case, model, [self.source["id"]])
        historical = inv.witness(self.case, old["id"], identity)
        new = inv.evaluate(self.case, saved["id"])
        current = inv.witness(self.case, new["id"], identity)
        self.assertEqual(historical["identity"], first["identity"])
        self.assertEqual(historical["history"]["staleness"]["status"], "stale")
        self.assertNotEqual(current["identity"]["interpretation_id"], historical["identity"]["interpretation_id"])
        self.assertEqual(current["raw_base64"], historical["raw_base64"])

    def test_temporal_gaps_separate_unknown_from_derived_bound_condition(self):
        value = self.current_claim("ordered_within", {"before": self.events["auth.failure"]["id"],
            "after": self.events["auth.success"]["id"], "window_us": "5000000"})
        saved = inv.save_claim(self.case, value)
        unknown = inv.evaluate(self.case, saved["id"])
        gaps = inv.explain(self.case, unknown["id"])["gaps"]
        gap = next(row for row in gaps if row["code"] == "clock_alignment_unknown")
        self.assertEqual(gap["discrimination_condition"]["status"], "unquantified")
        self.assertEqual(gap["affected_claim_ids"], [saved["id"]])
        self.assertEqual(gap["evaluation_id"], unknown["id"])
        self.put_clock()
        uncertain = inv.evaluate(self.case, saved["id"])
        gap = next(row for row in inv.explain(self.case, uncertain["id"])["gaps"] if row["code"] == "temporal_boundary_overlap")
        condition = gap["discrimination_condition"]
        self.assertEqual(condition["status"], "derived")
        self.assertEqual(condition["accepted_interval"], tm.interval(0, 5000000, False, True))
        self.assertEqual(condition["observed_difference"], tm.interval(4000000, 6000000, False, False))
        self.assertIn("no_specific_clock_tightening_amount_inferred", condition["limitations"])

    def test_count_gap_uses_units_and_never_invents_joint_assignment(self):
        self.put_clock()
        value = self.current_claim("count_at_least", {"threshold": 1, "unit": "normalized_observation",
            "anchor_event": self.events["auth.success"]["id"], "window_us": "5000000"})
        value["selector"] = [{"field": "kind", "op": "eq", "value": "auth.failure"}]
        saved = inv.save_claim(self.case, value)
        result = inv.evaluate(self.case, saved["id"])
        gap = next(row for row in inv.explain(self.case, result["id"])["gaps"] if row["code"] == "joint_feasibility_not_evaluated")
        condition = gap["discrimination_condition"]
        self.assertEqual((condition["current_lower"], condition["current_upper"]), (0, 1))
        self.assertEqual(condition["additional_definite_units_required"], 1)
        self.assertEqual(condition["refutation_upper_at_most"], 0)
        self.assertEqual(condition["unit"], "normalized_observation")
        self.assertIn("possible_memberships_are_not_a_jointly_feasible_assignment", condition["limitations"])

    def test_explanation_partial_source_gap_preserves_exact_accounting(self):
        path = self.root / "invalid.jsonl"
        path.write_bytes(b"{invalid\n")
        source = self.case.ingest(path, "events", "Synthetic malformed record")
        value = self.current_claim("absent_in_stream")
        value["selector"] = [{"field": "kind", "op": "eq", "value": "file.delete"}]
        saved = inv.save_claim(self.case, value)
        result = inv.evaluate(self.case, saved["id"])
        explanation = inv.explain(self.case, result["id"])
        gap = next(row for row in explanation["gaps"] if row["code"] == "source_coverage_incomplete")
        coverage = next(row for row in gap["discrimination_condition"]["supplied_coverage"] if row["artifact_id"] == source["id"])
        self.assertEqual(coverage["counters"]["malformed"], 1)
        self.assertEqual(gap["discrimination_condition"]["status"], "unquantified")
        self.assertEqual(explanation["witness_graph"]["count"], 0)

    def test_explanation_excerpt_is_bounded_and_outside_excerpt_not_readable(self):
        path = self.root / "many.jsonl"
        path.write_bytes(b"".join(canonical_bytes({"kind": "generic", "timestamp": None, "action": str(n)}) + b"\n" for n in range(260)))
        self.case.ingest(path, "events", "Synthetic witness count")
        saved = inv.save_claim(self.case, self.current_claim("count_at_least", {"threshold": 260, "unit": "normalized_observation"}))
        result = inv.evaluate(self.case, saved["id"])
        explanation = inv.explain(self.case, result["id"])
        graph = explanation["witness_graph"]
        self.assertEqual((graph["count"], graph["shown"], graph["complete"]), (260, 256, False))
        self.assertEqual(len(graph["edges"]), 1024)
        unseen = next(row["id"] for row in self.case.query_events(limit=1000)["rows"] if row["id"] not in {item["event_id"] for item in graph["witnesses"]})
        with self.assertRaises(ProbentiumError) as caught:
            inv.witness(self.case, result["id"], unseen)
        self.assertEqual(caught.exception.code, "event_not_in_saved_witness_excerpt")

    def test_witness_refuses_changed_source_and_invalid_result_binding(self):
        saved = inv.save_claim(self.case, self.current_claim())
        result = inv.evaluate(self.case, saved["id"])
        malformed = deepcopy(result["data"])
        malformed["result"]["evaluations"][0]["verdict"] = "ruled_out"
        forged = self.case.put_object("evaluation", malformed)
        with self.assertRaises(ProbentiumError) as caught:
            inv.explain(self.case, forged["id"])
        self.assertEqual(caught.exception.code, "explanation_result_binding_invalid")
        blob = self.case.path / "blobs" / (self.source["id"] + ".bin")
        raw = blob.read_bytes()
        blob.write_bytes(b"X" + raw[1:])
        event = result["data"]["result"]["evaluations"][0]["witness_set"][0]
        with self.assertRaises(ProbentiumError) as caught:
            inv.witness(self.case, result["id"], event)
        self.assertEqual(caught.exception.code, "explanation_integrity_failed")

    def test_authorized_unavailable_witness_is_marked_and_raw_read_refused(self):
        from probentium import retention
        saved = inv.save_claim(self.case, self.current_claim())
        result = inv.evaluate(self.case, saved["id"])
        plan = retention.plan(self.case, [self.source["id"]], "operator", "Synthetic retention exercise", "2020-01-01T00:00:00Z")
        approval = retention.approve(self.case, plan["id"], "operator", "Synthetic approval")
        retention.execute(self.case, plan["id"], approval["id"])
        explanation = inv.explain(self.case, result["id"])
        self.assertEqual(explanation["witness_graph"]["case_integrity"], "partial")
        self.assertEqual(explanation["witness_graph"]["witnesses"][0]["raw_verification"], "authorized_unavailable")
        self.assertIn("raw_evidence_unavailable", [row["code"] for row in explanation["gaps"]])
        event = result["data"]["result"]["evaluations"][0]["witness_set"][0]
        with self.assertRaises(ProbentiumError) as caught:
            inv.witness(self.case, result["id"], event)
        self.assertEqual(caught.exception.code, "artifact_authorized_unavailable")

    def test_hostile_record_content_is_returned_only_as_base64(self):
        import base64
        path = self.root / "hostile.jsonl"
        raw = canonical_bytes({"schema": "testifex.events.v2", "kind": "process.command", "recorded_time": None,
            "origin": None, "actor": "\u202eoperator", "payload": {"command": "\x1b[31msynthetic"}}) + b"\n"
        path.write_bytes(raw)
        source = self.case.ingest(path, "events-v2", "Synthetic terminal control fixture")
        self.assertEqual(source["events_total"], 1)
        value = self.current_claim()
        value["selector"] = [{"field": "kind", "op": "eq", "value": "process.command"}]
        saved = inv.save_claim(self.case, value)
        result = inv.evaluate(self.case, saved["id"])
        identity = result["data"]["result"]["evaluations"][0]["witness_set"][0]
        view = inv.witness(self.case, result["id"], identity)
        self.assertEqual(base64.b64decode(view["raw_base64"], validate=True), raw)
        serialized = canonical_bytes(view)
        self.assertNotIn(b"\x1b", serialized)
        self.assertNotIn("\u202e".encode(), serialized)
        self.assertNotIn("\u202e".encode(), canonical_bytes(inv.explain(self.case, result["id"])))

    def test_saved_lineage_cannot_substitute_a_different_clock(self):
        saved = inv.save_claim(self.case, self.current_claim())
        result = inv.evaluate(self.case, saved["id"])
        changed = deepcopy(result["data"])
        changed["witness_lineage"][0]["clock_model_digest"] = eid(808)
        forged = self.case.put_object("evaluation", changed)
        with self.assertRaises(ProbentiumError) as caught:
            inv.explain(self.case, forged["id"])
        self.assertEqual(caught.exception.code, "explanation_interpretation_binding_invalid")

    def test_unrelated_clock_identity_and_family_objects_do_not_stale_explicit_scope(self):
        value = self.current_claim()
        value["scope"] = inv.claims.resolve_scope(value["scope"], inv.load_data(self.case))
        saved = inv.save_claim(self.case, value)
        result = inv.evaluate(self.case, saved["id"])
        path = self.root / "outside.jsonl"
        path.write_bytes(canonical_bytes({"kind": "generic", "timestamp": None, "action": "outside"}) + b"\n")
        source = self.case.ingest(path, "events", "Outside frozen scope")
        event = next(row for row in self.case.query_events(limit=1000)["rows"] if row["artifact_id"] == source["id"])
        model = clock()
        model["segments"][0]["validity"] = tm.interval(tm.MIN_TIME_US, tm.MAX_TIME_US, True, False)
        inv.save_clock(self.case, model, [source["id"]])
        inv.save_family(self.case, "outside-family", [source["id"]], [], "Outside declared relationship")
        inv.save_identity(self.case, {"id": eid(905), "status": "conflicting", "event_ids": [event["id"]], "source_family_ids": []})
        status = inv.stale_status(self.case, result["id"])
        self.assertEqual(status["status"], "current")
        self.assertTrue(status["global_input_changed"])
        current = inv.evaluate(self.case, saved["id"], persist=False)
        self.assertEqual(current["result"], result["data"]["result"])
        self.assertEqual(inv.replay_snapshot(self.case.export_snapshot())["analysis_replay"], "passed")

    def test_new_scoped_record_after_resume_stales_absence_and_preserves_history(self):
        import probentium.store as storage
        path = self.root / "partial-valid.jsonl"
        rows = [{"kind": "generic", "timestamp": None, "action": "initial"},
                {"kind": "auth.failure", "timestamp": None, "action": "new matching record"}]
        path.write_bytes(b"".join(canonical_bytes(row) + b"\n" for row in rows))
        with patch.object(storage, "MAX_RECORDS", 1):
            source = self.case.ingest(path, "events", "Synthetic partial stream")
        value = self.current_claim("absent_in_stream")
        value["scope"] = {"artifact_ids": [source["id"]], "active_parse_runs": [{"artifact_id": source["id"], "parse_run_id": source["parse_run_id"]}],
                          "event_kinds": sorted(inv.claims.KINDS), "time_filter": None}
        value["selector"] = [{"field": "kind", "op": "eq", "value": "auth.failure"}]
        saved = inv.save_claim(self.case, value)
        result = inv.evaluate(self.case, saved["id"])
        self.assertEqual(result["data"]["result"]["evaluations"][0]["verdict"], "unknown")
        self.case.resume(source["id"])
        self.assertEqual(inv.stale_status(self.case, result["id"])["status"], "stale")
        current = inv.evaluate(self.case, saved["id"], persist=False)
        self.assertEqual(current["result"]["evaluations"][0]["verdict"], "ruled_out")
        self.assertEqual(inv.replay_snapshot(self.case.export_snapshot())["analysis_replay"], "passed")

    def test_family_provenance_revision_stales_even_without_verdict_change(self):
        inv.save_family(self.case, "synthetic-family", [self.source["id"]], [], "First declared basis")
        saved = inv.save_claim(self.case, self.current_claim())
        result = inv.evaluate(self.case, saved["id"])
        inv.save_family(self.case, "synthetic-family", [self.source["id"]], [self.events["auth.success"]["id"]], "Revised declared basis")
        self.assertEqual(inv.stale_status(self.case, result["id"])["status"], "stale")
        current = inv.evaluate(self.case, saved["id"], persist=False)
        self.assertEqual(result["data"]["result"]["evaluations"][0]["verdict"], current["result"]["evaluations"][0]["verdict"])
        self.assertNotEqual(result["data"]["evaluation_dependencies"]["family_premise_digest"], current["evaluation_dependencies"]["family_premise_digest"])
        self.assertNotEqual(result["data"]["result"]["digest"], current["result"]["digest"])
        self.assertEqual(inv.replay_snapshot(self.case.export_snapshot())["analysis_replay"], "passed")

    def test_legacy_evaluation_replays_but_never_promotes_current_approval(self):
        saved = inv.save_claim(self.case, self.current_claim())
        original = inv.evaluate(self.case, saved["id"], persist=False)
        original.pop("evaluation_dependencies")
        original["result"] = inv.claims.analyze([saved["data"]["claim"]], inv.load_data(self.case))
        legacy = self.case.put_object("evaluation", original)
        modern = inv.evaluate(self.case, saved["id"])
        self.assertNotEqual(modern["data"]["result"]["digest"], original["result"]["digest"])
        status = inv.stale_status(self.case, legacy["id"])
        self.assertEqual(status["status"], "stale")
        self.assertIn("legacy_dependency_binding_unavailable", status["reasons"])
        text = "Historical review only"
        self.case.put_object("review_rationale", {"text": text})
        decision = {"claim_id": saved["id"], "claim_revision": saved["revision"], "evaluation_digest": original["result"]["digest"],
                    "snapshot_digest": original["data_fingerprint"], "rationale_digest": hashlib.sha256(text.encode()).hexdigest(), "previous_decision_id": None}
        self.assertEqual(inv.resolve_review_references(self.case, decision)["status"], "historical")
        self.assertEqual(inv.replay_snapshot(self.case.export_snapshot())["analysis_replay"], "passed")

    def test_dependency_tamper_and_recomputation_limit_fail_closed(self):
        saved = inv.save_claim(self.case, self.current_claim())
        result = inv.evaluate(self.case, saved["id"])
        tampered = deepcopy(result["data"])
        tampered["evaluation_dependencies"]["analysis_data_digest"] = eid(999)
        forged = self.case.put_object("evaluation", tampered)
        with self.assertRaises(ProbentiumError) as caught:
            inv.stale_status(self.case, forged["id"])
        self.assertEqual(caught.exception.code, "evaluation_dependency_binding_invalid")
        with patch.object(inv, "load_data", side_effect=ProbentiumError("analysis_event_limit", 6)):
            status = inv.stale_status(self.case, result["id"])
        self.assertEqual(status["status"], "stale")
        self.assertIn("dependency_recomputation_limit", status["reasons"])
        self.assertIsNone(status["current_dependency_digest"])

    def test_review_resolver_keeps_exact_snapshot_when_scoped_results_repeat(self):
        saved = inv.save_claim(self.case, self.current_claim())
        first = inv.evaluate(self.case, saved["id"])
        path = self.root / "outside-review.jsonl"
        path.write_bytes(canonical_bytes({"kind": "generic", "timestamp": None, "action": "outside review scope"}) + b"\n")
        self.case.ingest(path, "events", "Additional unrelated source")
        second = inv.evaluate(self.case, saved["id"])
        self.assertEqual(first["data"]["result"], second["data"]["result"])
        self.assertNotEqual(first["data"]["data_fingerprint"], second["data"]["data_fingerprint"])
        text = "Review the first exact snapshot."
        self.case.put_object("review_rationale", {"text": text})
        decision = {"claim_id": saved["id"], "claim_revision": saved["revision"], "evaluation_digest": first["data"]["result"]["digest"],
                    "snapshot_digest": first["data"]["data_fingerprint"], "rationale_digest": hashlib.sha256(text.encode()).hexdigest(), "previous_decision_id": None}
        self.assertEqual(inv.resolve_review_references(self.case, decision)["status"], "current")
        decision["snapshot_digest"] = eid(999)
        self.assertEqual(inv.resolve_review_references(self.case, decision)["status"], "pending_references")

    def test_compare_saved_dependency_provenance_change_with_unchanged_verdict(self):
        inv.save_family(self.case, "family", [self.source["id"]], [], "First provenance")
        saved = inv.save_claim(self.case, self.current_claim())
        first = inv.evaluate(self.case, saved["id"])
        inv.save_family(self.case, "family", [self.source["id"]], [], "Revised provenance")
        second = inv.evaluate(self.case, saved["id"])
        compared = inv.claims.compare_results(first["data"]["result"], second["data"]["result"])
        self.assertEqual(compared["status"], "comparable")
        self.assertTrue(compared["dependencies"]["changed"])
        self.assertEqual(compared["changed"][0]["reason_class"], "dependency")
        self.assertEqual(compared["changed"][0]["before"], compared["changed"][0]["after"])


class CompositeWitnessAndBudgetTests(unittest.TestCase):
    def test_composite_witness_preserves_nonadjacent_ranges_and_primary_record(self):
        import base64
        from test_locators import LocatorTests
        with tempfile.TemporaryDirectory() as directory:
            case, lines, first, _ = LocatorTests().fixture(Path(directory))
            with case:
                value = claim(selector=[{"field": "actor", "op": "eq", "value": "first"}])
                value["scope"]["all_at_revision"] = case.revision
                saved = inv.save_claim(case, value)
                evaluated = inv.evaluate(case, saved["id"], analysis_limits={})
                explanation = inv.explain(case, evaluated["id"])
                graph = explanation["witness_graph"]
                self.assertEqual(graph["witnesses"][0]["record_refs"], first["record_refs"])
                for record in first["record_refs"]:
                    self.assertTrue(any(record in path for path in explanation["paths"]))
                result = inv.witness(case, evaluated["id"], first["id"])
                self.assertEqual(result["schema"], "testifex.witness.v2")
                self.assertNotIn("raw_base64", result)
                self.assertEqual([base64.b64decode(row["raw_base64"]) for row in result["raw_segments"]], [lines[0], lines[2]])
                self.assertEqual([row["primary"] for row in result["raw_segments"]], [False, True])
                self.assertEqual(result["raw_bytes"], len(lines[0]) + len(lines[2]))
                self.assertEqual(inv.stale_status(case, evaluated["id"])["status"], "current")
                self.assertEqual(inv.replay_snapshot(case.export_snapshot())["analysis_replay"], "passed")
                segments = case.raw_records(first["id"])
                segments[1]["bytes"] += b"private-canary"
                with patch.object(case, "raw_records", return_value=segments), self.assertRaises(ProbentiumError) as caught:
                    inv.witness(case, evaluated["id"], first["id"])
                self.assertEqual(caught.exception.code, "witness_raw_binding_invalid")

    def test_configured_evaluation_and_legacy_replay_both_survive_history(self):
        with tempfile.TemporaryDirectory() as directory:
            with CaseStore.create(Path(directory) / "case", "Synthetic budget history") as case:
                value = claim("absent_in_stream")
                value["scope"]["all_at_revision"] = case.revision
                saved = inv.save_claim(case, value)
                legacy = inv.evaluate(case, saved["id"])
                bounded = inv.evaluate(case, saved["id"], analysis_limits={"max_relations": 5})
                self.assertNotIn("analysis_limits", legacy["data"]["evaluation_dependencies"])
                self.assertEqual(bounded["data"]["evaluation_dependencies"]["analysis_limits"]["max_relations"], 5)
                self.assertEqual(inv.stale_status(case, legacy["id"])["status"], "current")
                self.assertEqual(inv.stale_status(case, bounded["id"])["status"], "current")
                self.assertEqual(inv.replay_snapshot(case.export_snapshot())["analysis_replay"], "passed")

    def test_small_report_budget_rejects_before_persisting_evaluation(self):
        with tempfile.TemporaryDirectory() as directory:
            with CaseStore.create(Path(directory) / "case", "Synthetic small report") as case:
                value = claim("absent_in_stream")
                value["scope"]["all_at_revision"] = case.revision
                saved = inv.save_claim(case, value)
                before = case.revision
                with self.assertRaises(ProbentiumError) as caught:
                    inv.evaluate(case, saved["id"], analysis_limits={"max_report_bytes": 1024})
                self.assertEqual(caught.exception.code, "analysis_report_limit")
                self.assertEqual(case.revision, before)
                self.assertEqual(case.objects("evaluation"), [])

    def test_batch_currentness_reuses_one_snapshot_and_same_claim_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            with CaseStore.create(Path(directory) / "case", "Synthetic currentness batch") as case:
                value = claim("absent_in_stream")
                value["scope"]["all_at_revision"] = case.revision
                saved = inv.save_claim(case, value)
                first = inv.evaluate(case, saved["id"], analysis_limits={})
                case.put_object("note", {"text": "Independent note"})
                second = inv.evaluate(case, saved["id"], analysis_limits={})
                ids = [first["id"], second["id"]]
                expected = [inv.stale_status(case, identity) for identity in ids]
                with patch.object(inv, "load_data", wraps=inv.load_data) as load, patch.object(inv, "_dependency_snapshot", wraps=inv._dependency_snapshot) as dependency:
                    batch = inv.stale_status_many(case, ids)
                self.assertEqual(load.call_count, 1)
                self.assertEqual(dependency.call_count, 1)
                self.assertEqual(batch["revision"], case.revision)
                self.assertEqual([{key: val for key, val in row.items() if key != "evaluation_id"} for row in batch["statuses"]], expected)
                self.assertEqual(batch["execution_state"], "complete")
                with patch.object(inv, "load_data", side_effect=ProbentiumError("analysis_event_limit", 6)):
                    limited = inv.stale_status_many(case, ids)
                self.assertEqual(limited["execution_state"], "aborted_limit")
                self.assertTrue(all(row["status"] == "stale" and "dependency_recomputation_limit" in row["reasons"] for row in limited["statuses"]))
                with self.assertRaises(ProbentiumError):
                    inv.stale_status_many(case, ids, max_evaluations=1)
