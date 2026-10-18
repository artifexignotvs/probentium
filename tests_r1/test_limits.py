"""Limites expliciti, receptores et curricula resumpta adversis finibus probantur."""
import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from probentium import exchange, intake, limits, maintenance, store, worker
from probentium.contracts import ProbentiumError, canonical_bytes
from probentium.store import CaseStore


def event(actor="operator"):
    return json.dumps({"kind": "auth.failure", "timestamp": "2026-10-18T12:00:00Z", "actor": actor}).encode() + b"\n"


class ResourcePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.input = self.root / "synthetic.log"
        self.input.write_bytes(event())

    def tearDown(self):
        self.temp.cleanup()

    def assertCode(self, code, function, *args, **kwargs):
        with self.assertRaises(ProbentiumError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def policy(self, **kwargs):
        return limits.configured(**kwargs)

    def test_closed_versioned_fields_hard_caps_and_no_environment_override(self):
        expected = limits.resolve()
        for field, cap in limits.HARD_CAPS.items():
            configured = dict(expected, **{field: cap})
            self.assertEqual(limits.validate(configured)[field], cap)
            self.assertCode("resource_policy_out_of_range", limits.validate, dict(configured, **{field: cap + 1}))
            self.assertCode("resource_policy_out_of_range", limits.validate, dict(configured, **{field: True}))
        for field in limits.FIXED:
            self.assertCode("fixed_resource_limit_changed", limits.validate, dict(expected, **{field: expected[field] + 1}))
        for value in ({}, dict(expected, extra=1), dict(expected, schema="unknown")):
            self.assertCode("invalid_resource_policy", limits.validate, value)
        self.assertCode("resource_policy_inconsistent", self.policy, max_case_bytes=1)
        with patch.dict(os.environ, {"PROBENTIUM_MAX_SOURCE_BYTES": "4294967296"}):
            self.assertEqual(limits.resolve(), expected)
        self.assertEqual(len(limits.digest(expected)), 64)

    def test_invalid_policy_fails_before_filesystem_and_worker(self):
        invalid = dict(limits.resolve(), max_source_bytes=5 * 1024 ** 3)
        target = self.root / "new-case"
        with patch.object(store, "_directory", side_effect=AssertionError("filesystem reached")):
            self.assertCode("resource_policy_out_of_range", CaseStore.create, target, resource_policy=invalid)
        self.assertFalse(target.exists())
        with patch.object(worker.subprocess, "Popen", side_effect=AssertionError("worker reached")):
            self.assertCode("parser_source_size_limit", worker.ParserWorker, 2, resource_policy=self.policy(max_source_bytes=1))
        self.assertCode("resource_policy_out_of_range", intake.batch_plan, [], resource_policy=invalid)

    def test_source_and_case_byte_exact_boundaries_leave_original_intact(self):
        raw = self.input.read_bytes()
        policy = self.policy(max_source_bytes=len(raw), max_case_bytes=2 * len(raw))
        with CaseStore.create(self.root / "case", resource_policy=policy) as case:
            first = case.ingest(self.input, "events", "Synthetic")
            self.assertEqual(first["events_total"], 1)
            self.input.write_bytes(event("operatot"))
            case.ingest(self.input, "events", "Second")
            self.assertEqual(sum(row["size"] for row in case.sources()), policy["max_case_bytes"])
            revision = case.revision
            self.input.write_bytes(event("operatos"))
            self.assertCode("case_evidence_limit", case.ingest, self.input, "events", "Beyond")
            self.assertEqual(case.revision, revision)
            self.assertEqual(len(case.sources()), 2)
            self.assertEqual(self.input.read_bytes(), event("operatos"))
            self.assertEqual(list((case.path / "blobs").glob(".incoming-*")), [])
        self.input.write_bytes(raw + b"x")
        with CaseStore.create(self.root / "small", resource_policy=policy) as case:
            self.assertCode("artifact_size_limit", case.ingest, self.input, "events", "Oversize")
            self.assertEqual(case.revision, 0)
            self.assertEqual(case.sources(), [])

    def test_explicit_config_binds_run_and_resume_frozen_budget(self):
        self.input.write_bytes(event() * 5)
        policy = self.policy(max_import_records=2, max_case_events=8)
        path = self.root / "case"
        with CaseStore.create(path, resource_policy=policy) as case:
            result = case.ingest(self.input, "events", "Bounded")
            run = list(case.iter_snapshot_rows("parse_runs"))[0]
            self.assertEqual(run["config"]["resource_policy"], policy)
            self.assertEqual((result["state"], result["records_total"]), ("incomplete", 2))
            artifact_id, run_id = result["id"], result["parse_run_id"]
        with CaseStore(path, resource_policy=self.policy(max_import_records=3, max_case_events=8)) as case:
            revision = case.revision
            self.assertCode("resume_resource_policy_mismatch", case.resume, artifact_id)
            self.assertEqual(case.revision, revision)
        with CaseStore(path) as case:
            second = case.resume(artifact_id)
            self.assertEqual((second["state"], second["records_total"]), ("incomplete", 4))
            final = case.resume(artifact_id)
            self.assertEqual((final["state"], final["records_total"]), ("complete", 5))
            self.assertEqual(final["parse_run_id"], run_id)
            self.assertTrue(case.verify()["ok"])

    def test_resume_exact_run_id_and_inactive_conflict(self):
        self.input.write_bytes(event() * 5)
        path = self.root / "case"
        with CaseStore.create(path, resource_policy=self.policy(max_import_records=2)) as case:
            old = case.ingest(self.input, "events", "First policy")
        with CaseStore(path, resource_policy=self.policy(max_import_records=3)) as case:
            active = case.ingest(self.input, "events", "Second policy")
            revision = case.revision
            self.assertCode("parse_run_not_active", case.resume, old["parse_run_id"])
            self.assertEqual(case.revision, revision)
            completed = case.resume(active["parse_run_id"])
            self.assertEqual(completed["parse_run_id"], active["parse_run_id"])
            self.assertEqual((completed["records_total"], completed["state"]), (5, "complete"))
            self.assertTrue(case.verify()["ok"])

    def test_legacy_config_shape_unchanged_and_policy_does_not_change_bytes(self):
        with CaseStore.create(self.root / "legacy") as case:
            old = case.ingest(self.input, "events", "Legacy")
            run = list(case.iter_snapshot_rows("parse_runs"))[0]
            self.assertEqual(set(run["config"]), {"format", "max_line_bytes", "max_records"})
        with CaseStore.create(self.root / "explicit", resource_policy=limits.resolve()) as case:
            new = case.ingest(self.input, "events", "Explicit")
            self.assertEqual(old["id"], new["id"])
            self.assertNotEqual(old["parse_run_id"], new["parse_run_id"])
            self.assertEqual(case.raw(case.query_events()["rows"][0]["id"]), self.input.read_bytes())

    def test_event_capacity_and_late_pagination_read_hard_bounds(self):
        self.input.write_bytes(event() * 3)
        with CaseStore.create(self.root / "case", resource_policy=self.policy(max_case_events=3)) as case:
            case.ingest(self.input, "events", "Three")
            with patch.object(store, "MAX_EVENTS", 1), patch.object(store, "MAX_ARTIFACT", 1):
                self.assertEqual(len(case.query_events(offset=2)["rows"]), 1)
                seen, cursor = [], None
                for _ in range(3):
                    page = intake.timeline_page(case, limit=1, cursor=cursor)
                    seen.extend(row["id"] for row in page["rows"])
                    cursor = page["next_cursor"]
                self.assertEqual(len(set(seen)), 3)
                self.assertIsNone(cursor)
                self.assertTrue(case.verify()["ok"])
                self.assertEqual(case.raw(seen[-1]), event())
        with CaseStore.create(self.root / "limited", resource_policy=self.policy(max_case_events=2)) as case:
            self.assertCode("case_event_limit", case.ingest, self.input, "events", "Overflow")
            self.assertEqual(case.query_events()["total"], 0)
            self.assertEqual(case.revision, 0)

    def test_platform_refusal_precedes_acquisition_and_revision(self):
        with CaseStore.create(self.root / "case") as case, patch.object(worker.sys, "platform", "darwin"):
            self.assertCode("strict_resource_mode_unsupported", case.ingest, self.input, "events", "No mutation")
            self.assertEqual(case.revision, 0)
            self.assertEqual(case.sources(), [])
            self.assertEqual(list((case.path / "blobs").iterdir()), [])

    def test_inspect_and_batch_policy_binding(self):
        policy = self.policy(max_source_bytes=len(event()))
        inspected = intake.inspect_file(self.input, format_name="events", resource_policy=policy)
        self.assertEqual(inspected["resource_policy_digest"], limits.digest(policy))
        self.assertEqual(inspected["candidates"][0]["parsed"], 1)
        self.assertCode("artifact_size_limit", intake.inspect_file, self.input, resource_policy=self.policy(max_source_bytes=len(event()) - 1))
        entries = [{"path": str(self.input), "format": "events", "label": "Synthetic"}]
        plan = intake.batch_plan(entries, resource_policy=policy)
        self.assertEqual(plan["resource_policy"], policy)
        with CaseStore.create(self.root / "case") as case:
            self.assertCode("batch_resource_policy_mismatch", intake.execute_batch, case, plan)
            self.assertEqual(case.revision, 0)
        with CaseStore.create(self.root / "explicit", resource_policy=policy) as case:
            result = intake.execute_batch(case, plan)
            self.assertEqual(len(result["completed"]), 1)
            self.assertEqual(result["resource_policy"], policy)

    def test_explicit_packet_cannot_raise_receiver_policy(self):
        packet = self.root / "case.pbp"
        policy = self.policy(max_source_bytes=len(event()), max_packet_bytes=1024 ** 2)
        with CaseStore.create(self.root / "case", resource_policy=policy) as case:
            case.ingest(self.input, "events", "Synthetic")
            result = exchange.export_case(case, packet, resource_policy=policy)
        self.assertEqual(result["resource_policy_digest"], limits.digest(policy))
        report = exchange.verify_packet(packet, resource_policy=self.policy(max_source_bytes=len(event()) - 1))
        self.assertFalse(report["ok"])
        self.assertEqual(report["exit_code"], 6)
        report = exchange.verify_packet(packet, resource_policy=policy)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["packet_resource_policy"], policy)
        with exchange.open_verified_snapshot(packet, resource_policy=policy) as (manifest, snapshot, reader):
            replay = maintenance.replay_packet(manifest, snapshot, reader, resource_policy=policy)
            self.assertEqual(replay["normalization_replay"], "passed", replay)
        restored = maintenance.restore_packet(packet, self.root / "restored", resource_policy=policy)
        self.assertEqual(restored["resource_policy"], policy)
        with CaseStore(self.root / "restored") as case:
            self.assertTrue(case.verify()["ok"])
            self.assertEqual(case.query_events()["total"], 1)

    def test_actual_packet_size_includes_headers_padding_and_member_cap(self):
        packet = self.root / "case.pbp"
        with CaseStore.create(self.root / "case") as case:
            case.ingest(self.input, "events", "Synthetic")
            exchange.export_case(case, packet)
            self.assertCode("packet_size_limit", exchange.export_case, case, self.root / "too-small.pbp", resource_policy=self.policy(max_packet_bytes=1024))
            self.assertFalse((self.root / "too-small.pbp").exists())
        size = packet.stat().st_size
        self.assertTrue(exchange.verify_packet(packet, resource_policy=self.policy(max_packet_bytes=size))["ok"])
        rejected = exchange.verify_packet(packet, resource_policy=self.policy(max_packet_bytes=size - 1))
        self.assertEqual(rejected["exit_code"], 6)
        with exchange.open_verified_snapshot(packet) as (manifest, _, __):
            members = len(manifest["objects"]) + 1
        with patch.object(exchange, "MAX_MEMBERS", members):
            self.assertTrue(exchange.verify_packet(packet)["ok"])
        with patch.object(exchange, "MAX_MEMBERS", members - 1):
            self.assertEqual(exchange.verify_packet(packet)["exit_code"], 6)

    def test_explicit_structural_rows_vs_legacy_default(self):
        self.input.write_bytes(event() * 3)
        policy = self.policy(max_import_records=3, max_case_events=3)
        with CaseStore.create(self.root / "case", resource_policy=policy) as case:
            case.ingest(self.input, "events", "Three")
            with patch.dict(exchange._TABLE_CAPS, {"records": 2, "parse_records": 2}):
                self.assertCode("snapshot_count_limit", exchange.export_case, case, self.root / "legacy.pbp")
                packet = self.root / "explicit.pbp"
                exchange.export_case(case, packet, resource_policy=policy)
                self.assertTrue(exchange.verify_packet(packet, resource_policy=policy)["ok"])
                self.assertFalse(exchange.verify_packet(packet)["ok"])
        self.assertFalse((self.root / "legacy.pbp").exists())

    def test_flat_packet_declared_policy_and_legacy_row_gate(self):
        from tests_r1.test_exchange import members, archive
        class Flat:
            def __init__(self, case):
                self.case = case
            def __getattr__(self, name):
                if name in ("snapshot_header", "iter_snapshot_rows"):
                    raise AttributeError(name)
                return getattr(self.case, name)
        policy = self.policy(max_source_bytes=3 * len(event()))
        self.input.write_bytes(event() * 3)
        packet = self.root / "flat.pbp"
        with CaseStore.create(self.root / "case") as case:
            case.ingest(self.input, "events", "Flat synthetic")
            exchange.export_case(Flat(case), packet, resource_policy=policy)
            legacy = self.root / "flat-legacy.pbp"
            exchange.export_case(Flat(case), legacy)
        self.assertTrue(exchange.verify_packet(packet)["ok"])
        rows = members(packet.read_bytes())
        manifest = json.loads(rows[0][1])
        manifest["resource_policy"]["max_source_bytes"] = 1
        rows[0] = ("manifest.json", canonical_bytes(manifest))
        packet.write_bytes(archive(rows))
        result = exchange.verify_packet(packet)
        self.assertFalse(result["ok"])
        self.assertEqual(result["exit_code"], 6)
        with patch.dict(exchange._TABLE_CAPS, {"records": 2, "parse_records": 2}):
            self.assertFalse(exchange.verify_packet(legacy, resource_policy=policy)["ok"])

    def test_parse_policy_tamper_and_small_recovery(self):
        policy = self.policy(max_source_bytes=len(event()))
        path = self.root / "case"
        with CaseStore.create(path, resource_policy=policy) as case:
            case.ingest(self.input, "events", "Synthetic")
            snapshot = case.export_snapshot()
            changed = copy.deepcopy(snapshot)
            changed["parse_runs"][0]["config"]["resource_policy"]["max_source_bytes"] = 1
            self.assertCode("snapshot_run_resource_policy_mismatch", exchange._snapshot, changed, policy)
        self.assertCode("recovery_size_limit", maintenance.recover_copy, path, self.root / "bad-copy", resource_policy=self.policy(max_source_bytes=1))
        self.assertFalse((self.root / "bad-copy").exists())
        receipt = maintenance.recover_copy(path, self.root / "copy", resource_policy=policy)
        self.assertEqual(receipt["resource_policy_digest"], limits.digest(policy))
        with CaseStore(path) as case:
            self.assertTrue(case.verify()["ok"])
        with CaseStore(self.root / "copy") as case:
            self.assertTrue(case.verify()["ok"])


if __name__ == "__main__":
    unittest.main()
