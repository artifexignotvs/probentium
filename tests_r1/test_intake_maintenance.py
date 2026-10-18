"""Interruptio, repetitio et absentia adversis exemplis probantur."""
import hashlib
import json
import os
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from probentium.adapters import parse_v2
from probentium.contracts import ProbentiumError, canonical_bytes
from probentium.store import CaseStore
from probentium.worker import ParserWorker
from probentium import intake, maintenance, retention


def raw_event(index=0):
    return canonical_bytes({"kind": "auth.failure", "timestamp": "2026-10-18T12:00:00Z", "actor": "operator-" + str(index)}) + b"\n"


class IntakeMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "input.jsonl"
        self.path.write_bytes(b"".join(raw_event(i) for i in range(5)))

    def tearDown(self):
        self.temp.cleanup()

    def case(self):
        return CaseStore.create(self.root / "case", "Synthetic maintenance case")

    def test_v2_exact_large_timestamp_and_unknown(self):
        base = {"schema": "testifex.events.v2", "kind": "auth.success", "recorded_time": {"value": "9007199254740992", "encoding": "unix_us", "resolution_us": "1000"}, "origin": None, "payload": {"service": "ssh"}}
        result = parse_v2(canonical_bytes(base))
        self.assertEqual(result["time_low_us"], 9007199254740992)
        self.assertEqual(result["time_high_us"] - result["time_low_us"], 999)
        base["recorded_time"] = None
        self.assertIsNone(parse_v2(canonical_bytes(base))["time_low_us"])

    def test_v2_rejects_unknown_keys_and_wrong_integer(self):
        base = {"schema": "testifex.events.v2", "kind": "process.start", "recorded_time": None, "origin": None, "payload": {"pid": True, "executable": None}}
        with self.assertRaises(ProbentiumError):
            parse_v2(canonical_bytes(base))
        base["payload"] = {"arbitrary": "untrusted"}
        with self.assertRaises(ProbentiumError):
            parse_v2(canonical_bytes(base))

    def test_v2_does_not_invent_timezone(self):
        value = {"schema": "testifex.events.v2", "kind": "auth.success", "recorded_time": {"value": "2026-10-18T12:00:00", "encoding": "rfc3339", "resolution_us": "1"}, "origin": None, "payload": {"service": None}}
        with self.assertRaises(ProbentiumError):
            parse_v2(canonical_bytes(value))

    def test_worker_roundtrip_large_frame(self):
        with ParserWorker() as worker:
            result = worker.parse(raw_event(), "events", 1)
            self.assertEqual(result["actor"], "operator-0")
            with self.assertRaises(ProbentiumError):
                worker.parse(b" " * 600000 + b"invalid", "events", 2)

    def test_worker_timeout(self):
        with ParserWorker(wall_seconds=0) as worker:
            with self.assertRaises(ProbentiumError) as caught:
                worker.parse(raw_event(), "events", 1)
            self.assertEqual(caught.exception.exit_code, 6)

    def test_worker_malformed_response_is_not_trusted(self):
        with ParserWorker() as worker, patch.object(worker, "request", return_value={"event": {"kind": "incomplete"}}):
            with self.assertRaises(ProbentiumError) as caught:
                worker.parse(raw_event(), "events", 1)
            self.assertEqual(caught.exception.exit_code, 4)

    def test_inspect_is_explicit_and_sampled(self):
        value = intake.inspect_file(self.path, sample_lines=2)
        self.assertEqual(value["sampled_lines"], 2)
        self.assertTrue(value["sample_only"])
        self.assertTrue(value["format_requires_explicit_selection"])
        self.assertEqual(next(x for x in value["candidates"] if x["format"] == "events")["parsed"], 2)

    def test_batch_source_change_before_apply(self):
        plan = intake.batch_plan([{"path": str(self.path), "format": "events", "label": "Synthetic"}])
        self.path.write_bytes(raw_event(99))
        with self.case() as case:
            with self.assertRaises(ProbentiumError) as caught:
                intake.execute_batch(case, plan)
            self.assertEqual(caught.exception.code, "batch_source_changed")
            self.assertEqual(case.revision, 0)

    def test_batch_fingerprint_checked_during_acquisition(self):
        with self.case() as case:
            with self.assertRaises(ProbentiumError):
                case.ingest(self.path, "events", "Synthetic", expected_sha256="0" * 64)
            self.assertEqual(case.sources(), [])
            self.assertTrue(case.verify()["ok"])

    def test_batch_real_execution(self):
        plan = intake.batch_plan([{"path": str(self.path), "format": "events", "label": "Synthetic"}])
        with self.case() as case:
            result = intake.execute_batch(case, plan, expected_revision=0)
            self.assertEqual(len(result["completed"]), 1)
            self.assertEqual(case.query_events()["total"], 5)

    def test_cursor_is_revision_and_query_bound(self):
        with self.case() as case:
            case.ingest(self.path, "events", "Synthetic")
            first = intake.timeline_page(case, limit=2)
            second = intake.timeline_page(case, limit=2, cursor=first["next_cursor"])
            self.assertEqual(second["offset"], 2)
            with self.assertRaises(ProbentiumError):
                intake.timeline_page(case, query="other", cursor=first["next_cursor"])
            case.put_object("note", {"text": "Revision changed"})
            with self.assertRaises(ProbentiumError) as caught:
                intake.timeline_page(case, cursor=first["next_cursor"])
            self.assertEqual(caught.exception.exit_code, 5)

    def test_interrupted_chunk_is_resumable_without_duplicates(self):
        original = ParserWorker.parse
        def interrupted(worker, raw, name, ordinal):
            if ordinal == 4:
                raise KeyboardInterrupt()
            return original(worker, raw, name, ordinal)
        with self.case() as case, patch("probentium.store.CHECKPOINT_RECORDS", 2):
            with patch.object(ParserWorker, "parse", interrupted), self.assertRaises(KeyboardInterrupt):
                case.ingest(self.path, "events", "Synthetic")
            self.assertTrue(case.verify()["ok"])
            source = case.sources()[0]
            self.assertEqual(source["records_total"], 2)
            self.assertEqual(source["state"], "incomplete")
            case.resume(source["id"])
            self.assertEqual(case.query_events()["total"], 5)
            self.assertTrue(case.verify()["ok"])

    def test_opaque_bytes_never_claim_interpretation_complete(self):
        with self.case() as case:
            source = case.ingest(self.path, "opaque", "Unknown evidence")
            self.assertFalse(source["interpretation_complete"])
            self.assertTrue(case.verify()["ok"])

    def test_snapshot_reconstruction_checks_catalog(self):
        with self.case() as case:
            case.ingest(self.path, "events", "Synthetic")
            case.put_object("note", {"text": "Analyst statement"})
            snapshot = case.export_snapshot()
            sizes = {s["id"]: s["size"] for s in snapshot["artifacts"]}
            receipt = maintenance.restore_snapshot(snapshot, lambda identity: case._blob(identity, sizes[identity]), self.root / "restored")
            self.assertEqual(receipt["integrity"], "passed")
        with CaseStore(self.root / "restored") as restored:
            self.assertTrue(restored.verify()["ok"])
            self.assertEqual(restored.query_events()["total"], 5)
            self.assertEqual(restored.objects("note")[0]["data"]["text"], "Analyst statement")

    def test_recovery_never_removes_referenced_blobs(self):
        with self.case() as case:
            source = case.ingest(self.path, "events", "Synthetic")
            orphan = case.path / "blobs" / ("f" * 64 + ".bin")
            orphan.write_bytes(b"incomplete copy")
            orphan.chmod(0o600)
            plan = maintenance.recovery_plan(case)
            self.assertEqual(len(plan["entries"]), 1)
            maintenance.apply_recovery(case, plan)
            self.assertTrue((case.path / "blobs" / (source["id"] + ".bin")).exists())
            self.assertFalse(orphan.exists())

    def test_schema1_migration_preserves_original_bytes(self):
        from testifex.case import Case
        old_path = self.root / "legacy"
        with Case.create(old_path, "Legacy synthetic") as old:
            old.ingest(self.path, "events", "Synthetic")
        before = {str(p.relative_to(old_path)): hashlib.sha256(p.read_bytes()).hexdigest() for p in old_path.rglob("*") if p.is_file()}
        result = maintenance.migrate_v1(old_path, self.root / "new")
        after = {str(p.relative_to(old_path)): hashlib.sha256(p.read_bytes()).hexdigest() for p in old_path.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertFalse(result["source_modified"])
        with CaseStore(self.root / "new") as case:
            self.assertTrue(case.verify()["ok"])
            self.assertEqual(case.query_events()["total"], 5)

    def test_hold_blocks_retention_and_release_is_attributed(self):
        with self.case() as case:
            source = case.ingest(self.path, "events", "Synthetic")
            saved = retention.hold(case, [source["id"]], "reviewer", "Investigation active")
            with self.assertRaises(ProbentiumError):
                retention.plan(case, [source["id"]], "analyst", "Exercise ended", "2020-01-01T00:00:00Z")
            retention.hold(case, [source["id"]], "reviewer", "Investigation ended", released_hold_id=saved["id"])
            self.assertEqual(retention.active_holds(case), [])

    def test_authorized_purge_is_partial_not_corrupt_and_keeps_disclosed_indices(self):
        with self.case() as case:
            source = case.ingest(self.path, "events", "Synthetic")
            plan = retention.plan(case, [source["id"]], "owner", "Exercise ended", "2020-01-01T00:00:00Z")
            approval = retention.approve(case, plan["id"], "reviewer", "Raw-byte scope accepted")
            result = retention.execute(case, plan["id"], approval["id"])
            self.assertIn("normalized_events", result["retained"])
            check = case.verify()
            self.assertTrue(check["ok"])
            self.assertEqual(check["exit_code"], 3)
            self.assertEqual(case.query_events()["total"], 5)
            with self.assertRaises(ProbentiumError) as caught:
                case.raw(case.query_events()["rows"][0]["id"])
            self.assertEqual(caught.exception.exit_code, 3)

    def test_unexpected_loss_is_integrity_failure(self):
        with self.case() as case:
            source = case.ingest(self.path, "events", "Synthetic")
            (case.path / "blobs" / (source["id"] + ".bin")).unlink()
            check = case.verify()
            self.assertFalse(check["ok"])
            self.assertEqual(check["exit_code"], 4)

    def test_overlapping_retention_plans_cannot_create_conflicting_tombstones(self):
        with self.case() as case:
            source = case.ingest(self.path, "events", "Synthetic")
            first = retention.plan(case, [source["id"]], "owner", "First plan", "2020-01-01T00:00:00Z")
            second = retention.plan(case, [source["id"]], "owner", "Second plan", "2020-01-01T00:00:00Z")
            a = retention.approve(case, first["id"], "reviewer", "First approval")
            b = retention.approve(case, second["id"], "reviewer", "Second approval")
            receipt = retention.execute(case, first["id"], a["id"])
            revision = case.revision
            with self.assertRaisesRegex(ProbentiumError, "retention_already_authorized_by_other_plan"):
                retention.execute(case, second["id"], b["id"])
            self.assertEqual(case.revision, revision)
            self.assertTrue(case.verify()["ok"])
            self.assertEqual(retention.execute(case, first["id"], a["id"])["tombstone_id"], receipt["tombstone_id"])

    def test_new_hold_blocks_an_approved_plan(self):
        with self.case() as case:
            source = case.ingest(self.path, "events", "Synthetic")
            plan = retention.plan(case, [source["id"]], "owner", "Exercise ended", "2020-01-01T00:00:00Z")
            approval = retention.approve(case, plan["id"], "reviewer", "Approved scope")
            retention.hold(case, [source["id"]], "reviewer", "New incident")
            with self.assertRaises(ProbentiumError):
                retention.execute(case, plan["id"], approval["id"])
            self.assertTrue((case.path / "blobs" / (source["id"] + ".bin")).exists())

    def test_killed_writer_recovers_to_copy_without_mutating_original(self):
        with self.case():
            pass
        source = self.root / "case"
        script = """import os,signal,sys
from probentium.store import CaseStore
with CaseStore(sys.argv[1]) as case:
    case._commit_checkpoint=lambda reopen=False: os.kill(os.getpid(), signal.SIGKILL)
    case.ingest(sys.argv[2], 'events', 'Synthetic crash')
"""
        process = subprocess.run([sys.executable, "-c", script, str(source), str(self.path)], capture_output=True, timeout=20)
        self.assertLess(process.returncode, 0)
        before = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source.rglob("*") if p.is_file()}
        result = maintenance.recover_copy(source, self.root / "recovered")
        after = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertFalse(result["source_modified"])
        with CaseStore(self.root / "recovered") as case:
            self.assertTrue(case.verify()["ok"])
            self.assertEqual(case.query_events()["total"], 0)

    def test_directory_publish_never_replaces_existing_destination(self):
        source, target = self.root / "staging", self.root / "existing"
        source.mkdir()
        target.mkdir()
        marker = target / "preserve"
        marker.write_text("original")
        with self.assertRaises(ProbentiumError):
            maintenance._publish_directory(source, target)
        self.assertEqual(marker.read_text(), "original")
        self.assertTrue(source.exists())

    def test_canonical_fast_path_matches_reference_vectors(self):
        import random
        import rfc8785
        rng = random.Random(12345)
        alphabet = ['a', '\x00', '\n', '\t', '"', '\\', '/', '\u2028', '\u2029', '\uffff', '\U0001f642', '\U0010ffff', 'é', '\u0301']
        for _ in range(1000):
            value = {"z": ["".join(rng.choices(alphabet, k=30)), rng.randint(-9007199254740991, 9007199254740991), None, True], "a": {"x": False}}
            self.assertEqual(canonical_bytes(value), rfc8785.dumps(value))
        self.assertEqual(canonical_bytes({'\ue000': 1, '\U0001f600': 2}), rfc8785.dumps({'\ue000': 1, '\U0001f600': 2}))


if __name__ == "__main__":
    unittest.main()
