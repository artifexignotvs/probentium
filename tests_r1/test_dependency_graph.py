"""Nexus veri, historia immutata et fines expliciti probantur."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from probentium import dependency_graph as graph
from probentium import investigation as inv
from probentium import reviews, reporting
from probentium.contracts import ProbentiumError, canonical_bytes, object_digest
from probentium.signatures import generate_key
from probentium.store import CaseStore
from test_claims import claim
from test_time_model import clock
from probentium import time_model as tm


class UnifiedGraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = CaseStore.create(self.root / "case")
        self.addCleanup(self.case.close)
        path = self.root / "events.jsonl"
        rows = [{"kind": "auth.failure", "timestamp": "2026-10-18T12:00:00Z", "host": "synthetic-host", "actor": "synthetic-operator"},
                {"kind": "auth.success", "timestamp": "2026-10-18T12:00:05Z", "host": "synthetic-host", "actor": "synthetic-operator"}]
        path.write_bytes(b"".join(canonical_bytes(row) + b"\n" for row in rows))
        self.source = self.case.ingest(path, "events", "Synthetic graph evidence")
        self.events = {row["kind"]: row for row in self.case.query_events(limit=1000)["rows"]}

    def temporal(self):
        value = claim("ordered_within", {"before": self.events["auth.failure"]["id"], "after": self.events["auth.success"]["id"], "window_us": "10000000"})
        value["scope"]["all_at_revision"] = self.case.revision
        saved = inv.save_claim(self.case, value)
        return saved, inv.evaluate(self.case, saved["id"])

    def clock(self):
        value = clock()
        value["segments"][0]["validity"] = tm.interval(tm.MIN_TIME_US, tm.MAX_TIME_US, True, False)
        return inv.save_clock(self.case, value, [self.source["id"]])

    def reachable(self, value, start_ref, end_ref):
        starts = {row["id"] for row in value["nodes"] if row["ref"] == start_ref}
        ends = {row["id"] for row in value["nodes"] if row["ref"] == end_ref}
        edges = {(row["dependency"], row["dependent"], row["type"]) for row in value["edges"]}
        return bool(graph._closure(starts, edges) & ends)

    def test_actual_record_event_parser_lineage_and_no_raw_values(self):
        value = graph.build_case_graph(self.case, persist=False)
        self.assertEqual(value["completeness"], "complete_explicit_schema_references")
        for event in self.events.values():
            self.assertTrue(self.reachable(value, self.source["id"], event["id"]))
            for ref in event["record_refs"]:
                self.assertTrue(self.reachable(value, ref, event["id"]))
        encoded = canonical_bytes(value)
        self.assertNotIn(b"synthetic-operator", encoded)
        self.assertNotIn(str(self.root).encode(), encoded)
        edges = {(row["dependency"], row["dependent"], row["type"]) for row in value["edges"]}
        run = graph._node_id("parse_run", self.source["parse_run_id"])
        self.assertNotIn(run, graph._closure({graph._node_id("active_parse_selection", self.source["id"])}, edges))

    def test_temporal_evaluation_signed_review_and_changed_clock_impact(self):
        saved, evaluated = self.temporal()
        rationale = "Synthetic assessment with unresolved clock alignment."
        self.case.put_object("review_rationale", {"text": rationale})
        key = self.root / "key"
        public = generate_key(key)
        decision = reviews.create_decision(saved["id"], saved["revision"], evaluated["data"]["result"]["digest"], evaluated["data"]["data_fingerprint"],
                                           public["key_id"], "abstain", reviews.rationale_digest(rationale))
        signed = reviews.sign_review(decision, key)
        review = reviews.import_review(self.case, decision, signed, reference_resolver=inv.resolve_review_references)["stored"]
        stored = graph.build_case_graph(self.case)
        original = deepcopy(stored)
        value = graph.load_case_graph(self.case, stored["id"])
        self.assertTrue(self.reachable(value, self.events["auth.failure"]["id"], evaluated["id"]))
        self.assertTrue(self.reachable(value, evaluated["id"], review["id"]))
        self.assertEqual(graph.impact(self.case, stored["id"], [self.source["id"]])["graph_currentness"], "current")
        changed = self.clock()
        impact = graph.impact(self.case, stored["id"], [changed["id"]])
        self.assertEqual(impact["graph_currentness"], "changed")
        self.assertIn(graph._node_id("evaluation", evaluated["id"]), impact["affected"])
        self.assertIn(graph._node_id("review_decision", review["id"]), impact["affected"])
        self.assertEqual(self.case.get_object(stored["id"]), original)
        self.assertEqual(inv.stale_status(self.case, evaluated["id"])["status"], "stale")
        self.assertEqual(reviews.verify_review(decision, signed)["signature_status"], "valid")
        graph.validate_stored("graph_impact", impact)

    def test_service_awareness_filing_calendar_deadline_cross_dependencies(self):
        result = reporting.build_demonstration(self.case, acknowledged_synthetic=True)
        stored = graph.build_case_graph(self.case)
        value = graph.load_case_graph(self.case, stored["id"])
        for ref in [result["awareness_ref"], result["track_ref"], result["deadline_evaluation_ref"], *result["filing_refs"]]:
            self.assertTrue(self.reachable(value, result["service_ref"], ref), ref)
        calendar = next(row for row in value["nodes"] if row["kind"] == "calendar_policy")
        self.assertTrue(self.reachable(value, calendar["ref"], result["deadline_evaluation_ref"]))
        impact = graph.impact(self.case, stored["id"], [result["service_ref"]])
        self.assertIn(graph._node_id("eu.deadline_evaluation", result["deadline_evaluation_ref"]), impact["affected"])
        self.assertEqual(value["completeness"], "incomplete")
        self.assertIn("service_dependencies_declared_unknown", {row["code"] for row in value["gaps"]})

    def test_unknown_schema_and_opaque_source_are_explicit_not_inferred(self):
        unknown = self.case.put_object("custom", {"pretend_ref": self.source["id"], "text": "private-canary"})
        opaque = self.root / "opaque.bin"
        opaque.write_bytes(b"synthetic opaque bytes\n")
        source = self.case.ingest(opaque, "opaque", "Synthetic opaque artifact")
        value = graph.build_case_graph(self.case, persist=False)
        self.assertEqual(value["completeness"], "incomplete")
        self.assertIn("unsupported_object_schema", {row["code"] for row in value["gaps"]})
        self.assertIn("opaque_source_interpretation_unavailable", {row["code"] for row in value["gaps"]})
        self.assertFalse(self.reachable(value, self.source["id"], unknown["id"]))
        self.assertNotIn(b"private-canary", canonical_bytes(value))
        self.assertIn(graph._node_id("artifact", source["id"]), {row["id"] for row in value["nodes"]})

    def test_new_awareness_revision_impacts_old_filing_and_deadline_without_rewriting(self):
        from probentium.governance import put_record
        result = reporting.build_demonstration(self.case, acknowledged_synthetic=True)
        stored = graph.build_case_graph(self.case, object_ids=[result["filing_refs"][0], result["deadline_evaluation_ref"]])
        before = self.case.get_object(result["filing_refs"][0])
        old = self.case.get_object(result["awareness_ref"])
        revised = {key: value for key, value in old["data"].items() if key not in {"schema", "kind", "legal_certification"}}
        revised.update(supersedes=old["id"], recorded_at="2026-10-18T13:00:00Z", anchor={"status": "known", "at": "2026-10-18T10:30:00Z"}, rationale="Corrected synthetic declaration.")
        new = put_record(self.case, "awareness", revised)
        impact = graph.impact(self.case, stored["id"], [new["id"]])
        for kind, ref in (("eu.filing_snapshot", result["filing_refs"][0]), ("eu.deadline_evaluation", result["deadline_evaluation_ref"])):
            self.assertIn(graph._node_id(kind, ref), impact["affected"])
        self.assertEqual(self.case.get_object(before["id"]), before)
        self.assertEqual(impact["graph_currentness"], "changed")

    def test_new_pack_activation_context_reaches_existing_deadline(self):
        from probentium.legalpacks import activate_pack
        result = reporting.build_demonstration(self.case, acknowledged_synthetic=True)
        stored = graph.build_case_graph(self.case)
        activation = activate_pack(self.case, result["pack_ref"], {"actor": "Synthetic operator", "at": "2026-10-18T13:00:00Z",
            "rationale": "Synthetic operational activation only.", "document_refs": [self.source["id"]], "mode": "draft_operational", "review_refs": [], "acknowledged_limits": True})
        impact = graph.impact(self.case, stored["id"], [activation["id"]])
        self.assertIn(graph._node_id("eu.deadline_evaluation", result["deadline_evaluation_ref"]), impact["affected"])
        value = graph.build_case_graph(self.case, persist=False)
        self.assertTrue(self.reachable(value, activation["id"], result["deadline_evaluation_ref"]))

    def test_preflight_nodes_edges_and_revision_fail_without_receipt(self):
        start = self.case.revision
        for target, maximum in (("MAX_NODES", 1), ("MAX_EDGES", 1)):
            with patch.object(graph, target, maximum), self.assertRaises(ProbentiumError) as caught:
                graph.build_case_graph(self.case)
            self.assertEqual(caught.exception.exit_code, 6)
        with self.assertRaises(ProbentiumError) as caught:
            graph.build_case_graph(self.case, expected_revision=start + 1)
        self.assertEqual(caught.exception.exit_code, 5)
        self.assertEqual(self.case.revision, start)
        self.assertEqual(self.case.objects("unified_graph"), [])

    def test_selected_artifact_excludes_unrelated_raw_lineage(self):
        path = self.root / "unrelated.jsonl"
        path.write_bytes(canonical_bytes({"kind": "generic", "timestamp": None}) + b"\n")
        extra = self.case.ingest(path, "events", "Synthetic second source")
        value = graph.build_case_graph(self.case, artifact_ids=[self.source["id"]], persist=False)
        self.assertNotIn(extra["id"], {row["ref"] for row in value["nodes"]})
        self.assertEqual(value["scope"]["mode"], "explicit_reference_closure")
        self.assertEqual(value["completeness"], "complete_explicit_schema_references")
        for args in ({"artifact_ids": []}, {"object_ids": ["f" * 64]}, {"artifact_ids": "private-canary"}, {"persist": 1}):
            with self.subTest(args=args), self.assertRaises(ProbentiumError):
                graph.build_case_graph(self.case, **args)

    def test_unrelated_historical_catalog_does_not_propagate_semantic_review_impact(self):
        path = self.root / "unrelated.jsonl"
        path.write_bytes(canonical_bytes({"kind": "generic", "timestamp": None}) + b"\n")
        extra = self.case.ingest(path, "events", "Synthetic unrelated catalog entry")
        value = claim("record_observed")
        value["scope"] = {"artifact_ids": [self.source["id"]], "active_parse_runs": [{"artifact_id": self.source["id"], "parse_run_id": self.source["parse_run_id"]}],
                          "event_kinds": ["auth.failure"], "time_filter": None}
        saved = inv.save_claim(self.case, value)
        evaluation = inv.evaluate(self.case, saved["id"])
        stored = graph.build_case_graph(self.case)
        impact = graph.impact(self.case, stored["id"], [extra["id"]])
        self.assertNotIn(graph._node_id("evaluation", evaluation["id"]), impact["affected"])
        self.assertEqual(inv.stale_status(self.case, evaluation["id"])["status"], "current")

    def test_small_chunks_roundtrip_cross_reference_validation(self):
        with patch.object(graph, "CHUNK_ROWS", 2):
            stored = graph.build_case_graph(self.case)
            self.assertGreater(len(stored["data"]["storage"]["node_chunks"]), 1)
            value = graph.load_case_graph(self.case, stored["id"])
            self.assertEqual(value["structure_digest"], stored["data"]["structure_digest"])
            snapshot = self.case.export_snapshot()
            self.assertEqual(graph.validate_snapshot_graphs(snapshot)["status"], "consistent")
            missing = deepcopy(snapshot)
            ref = stored["data"]["storage"]["node_chunks"][0]
            missing["objects"] = [obj for obj in missing["objects"] if obj["id"] != ref]
            with self.assertRaises(ProbentiumError):
                graph.validate_snapshot_graphs(missing)
            changed = deepcopy(snapshot)
            chunk = next(obj for obj in changed["objects"] if obj["id"] == ref)
            chunk["data"]["rows"][0]["content_digest"] = "0" * 64
            with self.assertRaises(ProbentiumError):
                graph.validate_snapshot_graphs(changed)

    def test_synthetic_metadata_and_prior_graph_receipts_do_not_self_stale(self):
        marker = {"synthetic": True, "as_of": "2026-10-18T12:00:00Z", "artifacts": [self.source["id"]],
                  "source_digest": object_digest(self.case.sources()), "objects": [], "limits": ["Synthetic exercise."]}
        self.case.put_object("scenario", marker)
        stored = graph.build_case_graph(self.case)
        marker["objects"] = [stored["id"]]
        self.case.put_object("scenario", marker)
        impact = graph.impact(self.case, stored["id"], [])
        self.assertEqual(impact["graph_currentness"], "current")
        self.assertEqual(impact["affected"], [])

    def test_graph_load_rejects_count_digest_and_unexpected_fields(self):
        stored = graph.build_case_graph(self.case)
        for change in (lambda v: v.update(extra=True), lambda v: v.update(structure_digest="0" * 64), lambda v: v["counts"].update(nodes=0)):
            value = deepcopy(stored["data"])
            change(value)
            obj = self.case.put_object("unified_graph", value)
            with self.assertRaises(ProbentiumError):
                graph.load_case_graph(self.case, obj["id"])

    def test_composite_event_keeps_every_record_edge(self):
        from test_locators import LocatorTests
        root = self.root / "composite"
        root.mkdir()
        case, _, event, _ = LocatorTests().fixture(root)
        with case:
            value = graph.build_case_graph(case, persist=False)
            for ref in event["record_refs"]:
                self.assertTrue(self.reachable(value, ref, event["id"]))

    def test_changed_unknown_reference_and_unverified_case_fail_closed(self):
        stored = graph.build_case_graph(self.case)
        with self.assertRaises(ProbentiumError):
            graph.impact(self.case, stored["id"], ["f" * 64])
        with patch.object(self.case, "verify", return_value={"ok": False}), self.assertRaises(ProbentiumError) as caught:
            graph.impact(self.case, stored["id"], [])
        self.assertEqual(caught.exception.exit_code, 4)

    def test_long_impact_paths_are_explicitly_abbreviated_and_predecessors_complete(self):
        value = graph.build_case_graph(self.case, persist=False)
        nodes = [{"id": graph._node_id("synthetic", f"{index:064x}"), "kind": "synthetic", "ref": f"{index:064x}",
                  "content_digest": object_digest(index)} for index in range(300)]
        edges = [{"dependency": a["id"], "dependent": b["id"], "type": "declared_reference"} for a, b in zip(nodes, nodes[1:])]
        value.update(nodes=sorted(nodes, key=lambda row: row["id"]), edges=sorted(edges, key=lambda row: (row["dependency"], row["dependent"], row["type"])), gaps=[],
                     completeness="complete_explicit_schema_references", counts={"nodes": 300, "edges": 299, "gaps": 0})
        value["structure_digest"] = object_digest(graph._structure(value), "PROBENTIUM-GRAPH-STRUCTURE-V1")
        stored = graph._persist(self.case, value, self.case.revision)
        with patch.object(graph, "build_case_graph", return_value=value):
            result = graph.impact(self.case, stored["id"], [nodes[0]["id"]])
        self.assertEqual(len(result["affected"]), 299)
        self.assertEqual(len(result["predecessors"]), 300)
        self.assertFalse(result["path_details_complete"])
        self.assertLessEqual(len(result["paths"]), 256)
        self.assertTrue(all(len(path) <= 256 for path in result["paths"].values()))
        graph.validate_stored("graph_impact", result)
        result["predecessors"][nodes[0]["id"]] = nodes[-1]["id"]
        with self.assertRaises(ProbentiumError):
            graph.validate_stored("graph_impact", result)

    def test_hostile_chunk_manifest_types_fail_without_raw_exception(self):
        stored = graph.build_case_graph(self.case)
        for mutate in (lambda v: v.update(limits=[]), lambda v: v.update(counts=True),
                       lambda v: v["storage"].update(node_chunks={}), lambda v: v.update(completeness="complete"),
                       lambda v: v.update(gaps=[{"node_id": [], "code": "private-canary"}])):
            value = deepcopy(stored["data"]); mutate(value)
            with self.assertRaises(ProbentiumError) as caught:
                graph.validate_stored("unified_graph", value)
            self.assertNotIn("private-canary", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
