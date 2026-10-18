"""Historia versionis primae servatur; approbatio nova non fingitur."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from probentium import maintenance
from probentium.contracts import ProbentiumError, canonical_bytes
from probentium.store import CaseStore
from testifex.case import Case
from testifex.cli import build_report
from testifex.model import canonical, digest


def tree(path):
    return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in path.rglob("*") if p.is_file()}


class LegacyMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.legacy = self.root / "legacy"
        self.target = self.root / "target"

    def tearDown(self):
        self.temporary.cleanup()

    def file(self, name, raw):
        path = self.root / name
        path.write_bytes(raw)
        return path

    def migrate(self):
        original = tree(self.legacy)
        result = maintenance.migrate_v1(self.legacy, self.target)
        self.assertFalse(result["source_modified"])
        self.assertEqual(tree(self.legacy), original)
        with CaseStore(self.target) as case:
            self.assertTrue(case.verify()["ok"])
            record = case.get_object(result["migration_id"])["data"]
            self.assertEqual(record["schema"], "probentium.migration.v2")
            self.assertEqual(record["interpretation"], "legacy_v1")
            self.assertEqual(record["legacy_review_status"], "not_carried_forward")
            self.assertFalse(record["new_claims_created"])
            self.assertFalse(case.objects("claim"))
            self.assertFalse(case.objects("review_decision"))
            self.assertFalse(case.objects("clock_model"))
        return record

    def test_historical_formats_clocks_hypotheses_and_snapshot_corpus(self):
        events = b"".join(canonical_bytes({"kind": kind, "timestamp": "2026-10-18T12:00:00Z", "actor": "synthetic"}) + b"\n"
                          for kind in ("auth.failure", "auth.failure", "auth.success"))
        auth = (b"Oct 18 12:00:00 host sshd[10]: Failed password for synthetic from 192.0.2.30 port 22 ssh2\n"
                b"2026-10-18T12:00:00Z host sshd[10]: Accepted password for synthetic from 192.0.2.30 port 22 ssh2\n")
        journal = canonical_bytes({"MESSAGE": "Accepted password for synthetic from 192.0.2.30 port 22 ssh2",
                                   "SYSLOG_IDENTIFIER": "sshd", "__REALTIME_TIMESTAMP": "1792324800000000", "_PID": "10"}) + b"\n"
        with Case.create(self.legacy, "Synthetic historical corpus") as case:
            event_source = case.ingest(self.file("events", events), "events", "Events", {
                "clock_offset_us": 3000000, "clock_error_us": 1000000, "correction_reason": "Synthetic historic premise",
                "declared_start_us": 1792324700000000, "declared_end_us": 1792324900000000})
            case.ingest(self.file("auth", auth), "auth", "Auth")
            case.ingest(self.file("journal", journal), "journal", "Journal")
            selected = list(case.events(event_source["id"]))
            hypothesis = case.add_hypothesis("Synthetic hypothesis", ["Historical assumption"])
            case.link_hypothesis(hypothesis["id"], selected[0]["id"], "supports", "Historical supporting record")
            case.link_hypothesis(hypothesis["id"], selected[-1]["id"], "contradicts", "Historical opposing record")
            case.set_hypothesis_status(hypothesis["id"], "inconclusive")
            report = build_report(case, SimpleNamespace(max_events=100000, window="300", threshold=2))
            snapshot = case.snapshot(report, "Historical result")
            old_events = {event["id"]: event for event in case.events()}
            old_hypotheses = case.hypotheses()
        record = self.migrate()
        self.assertEqual(len(record["mapping"]), 3)
        self.assertEqual(len(record["clock_assertions"]), 3)
        self.assertTrue(all(row["activated"] is False for row in record["clock_assertions"]))
        with CaseStore(self.target) as case:
            histories = case.objects("legacy_history")
            archived = {event["id"]: event for wrapper in histories if wrapper["data"]["section"] == "events"
                        for event in map(json.loads, wrapper["data"]["rows"])}
            self.assertEqual(archived, old_events)
            hypotheses = [json.loads(raw) for wrapper in histories if wrapper["data"]["section"] == "hypotheses" for raw in wrapper["data"]["rows"]]
            links = [json.loads(raw) for wrapper in histories if wrapper["data"]["section"] == "hypothesis_evidence" for raw in wrapper["data"]["rows"]]
            self.assertEqual(hypotheses[0]["status"], old_hypotheses[0]["status"])
            self.assertEqual({row["stance"] for row in links}, {"supports", "contradicts"})
            saved = record["historical_snapshots"][0]
            self.assertEqual(saved["old_snapshot_id"], snapshot["id"])
            self.assertEqual(saved["approval_effect"], "none")
            self.assertEqual(saved["verification"], "historical_report_semantics_replayed")
            copied = self.target / "blobs" / (saved["artifact_id"] + ".bin")
            self.assertEqual(copied.read_bytes(), (self.legacy / "snapshots" / (snapshot["id"] + ".json")).read_bytes())
            mapped = [json.loads(raw) for wrapper in histories if wrapper["data"]["section"] == "event_mapping" for raw in wrapper["data"]["rows"]]
            self.assertEqual({row["old"] for row in mapped}, set(old_events))
            for item in mapped:
                event = case._event(case.db.execute("SELECT * FROM events WHERE id=?", (item["new"],)).fetchone())
                self.assertEqual(event["clock_alignment"], "unknown")
                self.assertEqual(hashlib.sha256(case.raw(event["id"])).hexdigest(), old_events[item["old"]]["raw_sha256"])

    def test_interrupted_prefix_malformed_blank_and_empty_history_are_explicit(self):
        raw = b'{"kind":"generic","timestamp":null}\n\n{broken\n{"kind":"generic","timestamp":null,"actor":"later"}\n'
        with Case.create(self.legacy, "Interrupted history") as case:
            source = case.ingest(self.file("prefix", raw), "events", "Prefix", max_records=1)
            self.assertEqual(source["status"], "interrupted")
        record = self.migrate()
        item = record["mapping"][0]
        self.assertEqual(item["legacy_state"], "interrupted")
        self.assertEqual((item["mapped_events"], item["new_events"], item["new_records_after_legacy_prefix"]), (1, 2, 3))
        with CaseStore(self.target) as case:
            self.assertEqual(case.sources()[0]["counters"]["malformed"], 1)
            self.assertEqual(case.sources()[0]["counters"]["blank"], 1)
        empty, destination = self.root / "empty", self.root / "empty-copy"
        with Case.create(empty):
            pass
        maintenance.migrate_v1(empty, destination)
        with CaseStore(destination) as case:
            self.assertEqual(case.query_events()["total"], 0)

    def test_snapshot_tamper_and_forged_analysis_block_publication(self):
        with Case.create(self.legacy) as case:
            case.ingest(self.file("input", b'{"kind":"generic","timestamp":null}\n'), "events", "Synthetic")
            report = build_report(case, SimpleNamespace(max_events=100000, window="300", threshold=2))
            snapshot = case.snapshot(report, "Historical")
        file = self.legacy / "snapshots" / (snapshot["id"] + ".json")
        file.write_bytes(b"tampered")
        before = tree(self.legacy)
        with self.assertRaisesRegex(ProbentiumError, "legacy_snapshot_digest_mismatch"):
            maintenance.migrate_v1(self.legacy, self.target)
        self.assertFalse(self.target.exists())
        self.assertEqual(tree(self.legacy), before)
        report["analysis"]["invented"] = True
        raw = (canonical(report) + "\n").encode(); identity = hashlib.sha256(raw).hexdigest()
        file.unlink()
        (self.legacy / "snapshots" / (identity + ".json")).write_bytes(raw)
        with sqlite3.connect(self.legacy / "case.sqlite3") as db:
            db.execute("UPDATE snapshots SET id=?,sha256=?", (identity, identity))
        before = tree(self.legacy)
        with self.assertRaisesRegex(ProbentiumError, "legacy_report_replay_failed"):
            maintenance.migrate_v1(self.legacy, self.target)
        self.assertFalse(self.target.exists())
        self.assertEqual(tree(self.legacy), before)

    def test_unknown_schema_parser_and_history_budget_refuse_without_publication(self):
        with Case.create(self.legacy) as case:
            source = case.ingest(self.file("input", b'{"kind":"generic","timestamp":null}\n'), "events", "Synthetic")
        with patch.object(maintenance, "MAX_LEGACY_HISTORY", 1), self.assertRaisesRegex(ProbentiumError, "legacy_history_limit"):
            maintenance.migrate_v1(self.legacy, self.target)
        self.assertFalse(self.target.exists())
        source["parser_version"] = "unsupported-future"
        source["id"] = digest({key: source[key] for key in ("sha256", "format", "parser_version", "options")})
        with sqlite3.connect(self.legacy / "case.sqlite3") as db:
            db.execute("UPDATE sources SET id=?,data=?", (source["id"], canonical(source)))
        with self.assertRaisesRegex(ProbentiumError, "legacy_parser_version_unavailable") as caught:
            maintenance.migrate_v1(self.legacy, self.target)
        self.assertEqual(caught.exception.exit_code, 7)
        self.assertFalse(self.target.exists())
        with sqlite3.connect(self.legacy / "case.sqlite3") as db:
            db.execute("PRAGMA user_version=99")
        with self.assertRaisesRegex(ProbentiumError, "unsupported_legacy_schema"):
            maintenance.migrate_v1(self.legacy, self.target)
        self.assertFalse(self.target.exists())

    def test_clock_out_of_range_history_does_not_hide_new_uncorrected_observation(self):
        with Case.create(self.legacy) as case:
            source = case.ingest(self.file("input", b'{"kind":"generic","timestamp":"0001-01-01T00:00:00Z"}\n'),
                                 "events", "Synthetic", {"clock_offset_us": 2000000, "correction_reason": "Historical boundary"})
            self.assertEqual(source["parsed_count"], 0)
            self.assertEqual(source["error_count"], 1)
        record = self.migrate()
        self.assertEqual(record["mapping"][0]["clock_neutral_new_event_ordinals"], [1])
        self.assertEqual(record["mapping"][0]["new_events"], 1)
        self.assertFalse(record["clock_assertions"][0]["activated"])

    def test_deep_snapshot_and_opaque_historical_document_have_explicit_outcomes(self):
        with Case.create(self.legacy) as case:
            snapshot = case.snapshot({"historical_note": "Unverified supplied statement"}, "Opaque")
        record = self.migrate()
        self.assertEqual(record["historical_snapshots"][0]["verification"], "opaque_historical_json")
        with self.assertRaisesRegex(ProbentiumError, "legacy_snapshot_structure_limit"):
            maintenance._legacy_snapshot_json(b"[" * 33 + b"0" + b"]" * 33)
