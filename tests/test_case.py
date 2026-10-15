import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from contextlib import contextmanager
from unittest.mock import patch

from testifex.case import Case
from testifex.model import CaseError, canonical
from testifex.safeio import bounded_read, read_key, regular_reader, write_new


def record(timestamp="2026-01-01T00:00:00Z", **changes):
    item = {"timestamp": timestamp, "kind": "auth.failure", "actor": "operator", "host": "edge-demo", "src_ip": "192.0.2.30"}
    item.update(changes)
    return (json.dumps(item) + "\n").encode()


class CaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.case = Case.create(self.root / "case", "Synthetic case")
        self.source = self.root / "events.jsonl"

    def tearDown(self):
        self.case.db.close()
        self.tmp.cleanup()

    def ingest(self, data, **kwargs):
        self.source.write_bytes(data)
        return self.case.ingest(self.source, "events", "fixture", **kwargs)

    def test_exact_bytes_locators_and_immutable_original(self):
        data = record() + record("2026-01-01T00:00:01Z", kind="auth.success")
        original_hash = hashlib.sha256(data).hexdigest()
        source = self.ingest(data)
        events = list(self.case.events())
        self.assertEqual(source["sha256"], original_hash)
        self.assertEqual(events[1]["offset"], len(record()))
        self.assertEqual(self.case.raw_event(events[1]["id"]), data[len(record()):])
        self.assertEqual(self.source.read_bytes(), data)
        self.assertTrue(self.case.verify()["ok"])

    def test_duplicate_label_does_not_double_count(self):
        first = self.ingest(record())
        second = self.case.ingest(self.source, "events", "different-label")
        self.assertEqual(first["id"], second["id"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(len(list(self.case.events())), 1)

    def test_conflicting_source_version_rejected_before_case_mutation(self):
        self.ingest(record())
        with self.assertRaisesRegex(CaseError, "separate_case"):
            self.case.ingest(self.source, "events", "shifted", {"clock_error_us": 10, "correction_reason": "Synthetic alternative"})
        self.assertEqual(len(self.case.sources()), 1)
        self.assertTrue(self.case.verify()["ok"])

    def test_errors_are_visible_without_raw_secret(self):
        source = self.ingest(record() + b'{"credential":"sensitive-fixture"}\n' + b'broken-sensitive-fixture\n')
        self.assertEqual(source["status"], "incomplete")
        self.assertEqual(source["error_count"], 2)
        self.assertEqual(source["parsed_count"], 1)
        self.assertNotIn("sensitive-fixture", canonical(list(self.case.issues())))

    def test_record_limit_and_resume_exactly_once(self):
        source = self.ingest(record() * 3, max_records=1)
        self.assertEqual(source["status"], "interrupted")
        self.assertEqual(source["parsed_count"], 1)
        source = self.case.resume(source["id"], max_records=3)
        self.assertEqual(source["status"], "complete")
        self.assertEqual(source["parsed_count"], 3)
        self.assertEqual(sorted(e["ordinal"] for e in self.case.events()), [1, 2, 3])

    def test_changed_copy_cannot_resume(self):
        source = self.ingest(record() * 2, max_records=1)
        (self.case.path / "evidence" / (source["sha256"] + ".bin")).write_bytes(b"changed")
        with self.assertRaisesRegex(CaseError, "digest_mismatch"):
            self.case.resume(source["id"])

    def test_source_path_traversal_rejected_before_raw_read(self):
        source = self.ingest(record())
        event = next(self.case.events())
        source["sha256"] = "../../outside"
        self.case.db.execute("UPDATE sources SET data=? WHERE id=?", (canonical(source), source["id"]))
        self.case.db.commit()
        with self.assertRaisesRegex(CaseError, "source_identity"):
            self.case.raw_event(event["id"])
        self.assertFalse(self.case.verify()["ok"])

    def test_replaced_evidence_after_hash_never_marks_import_complete(self):
        from testifex import case as module
        source = self.ingest(record() * 2, max_records=1)
        original = module.verified_reader
        @contextmanager
        def replaced(path, sha, limit):
            with original(path, sha, limit) as pair:
                replacement = self.root / "replacement"
                replacement.write_bytes(record(actor="attacker") * 2)
                os.replace(replacement, path)
                yield pair
        with patch.object(module, "verified_reader", replaced):
            with self.assertRaisesRegex(CaseError, "changed"):
                self.case.resume(source["id"])
        saved = self.case.source(source["id"])
        self.assertEqual(saved["status"], "interrupted")
        self.assertEqual(saved["parsed_count"], 1)
        self.assertFalse(self.case.verify()["ok"])

    def test_record_tampering_detected_by_reparse(self):
        self.ingest(record())
        event = next(self.case.events())
        event["actor"] = "different-account"
        self.case.db.execute("UPDATE events SET data=? WHERE id=?", (canonical(event), event["id"]))
        self.case.db.commit()
        self.assertFalse(self.case.verify()["ok"])

    def test_deleted_record_is_detected_against_evidence_copy(self):
        self.ingest(record())
        self.case.db.execute("DELETE FROM events"); self.case.db.commit()
        self.assertFalse(self.case.verify()["ok"])

    def test_modified_sort_index_detected(self):
        self.ingest(record())
        self.case.db.execute("UPDATE events SET low_us=1"); self.case.db.commit()
        self.assertFalse(self.case.verify()["ok"])

    def test_removed_error_record_is_detected(self):
        self.ingest(b"invalid\n")
        self.case.db.execute("DELETE FROM issues"); self.case.db.commit()
        self.assertFalse(self.case.verify()["ok"])

    def test_clock_correction_retains_original_interval(self):
        self.ingest(record(), options={"clock_offset_us": 30000000, "clock_error_us": 2000000, "correction_reason": "Synthetic calibrated bound"})
        event = next(self.case.events())
        self.assertEqual(event["original_low_us"] - event["time_low_us"], 32000000)
        self.assertEqual(event["original_high_us"] - event["time_high_us"], 28000000)

    def test_adjustment_without_reason_rejected(self):
        with self.assertRaisesRegex(CaseError, "correction_reason"):
            self.ingest(record(), options={"clock_error_us": 1})

    def test_hypothesis_has_counterevidence_and_idempotent_links(self):
        self.ingest(record())
        event = next(self.case.events())
        h = self.case.add_hypothesis("Was this authorized?", ["Collector identity is correct"])
        self.case.link_hypothesis(h["id"], event["id"], "contradicts", "A failed login is not a successful session")
        self.case.link_hypothesis(h["id"], event["id"], "contradicts", "Updated note")
        self.case.set_hypothesis_status(h["id"], "inconclusive")
        result = self.case.hypotheses()[0]
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(len(result["evidence"]), 1)
        self.assertEqual(result["evidence"][0]["note"], "Updated note")

    def test_oversized_record_is_bounded_and_next_record_is_parsed(self):
        source = self.ingest(b"x" * (1024 * 1024 + 100) + b"\n" + record())
        self.assertEqual(source["parsed_count"], 1)
        self.assertEqual(source["error_count"], 1)
        self.assertEqual(next(self.case.events())["ordinal"], 2)

    def test_keyboard_interrupt_rolls_back_to_checkpoint(self):
        from testifex import parsers
        original = parsers.parse_line
        calls = 0
        def interrupted(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise KeyboardInterrupt
            return original(*args)
        self.source.write_bytes(record() * 3)
        with patch.object(parsers, "parse_line", side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.case.ingest(self.source, "events", "fixture")
        source = self.case.sources()[0]
        self.assertEqual(source["status"], "interrupted")
        self.assertEqual(len(list(self.case.events())), 0)
        self.assertEqual(self.case.resume(source["id"])["parsed_count"], 3)

    def test_unknown_case_version_fails_without_migration(self):
        self.case.db.execute("PRAGMA user_version=999")
        self.case.db.commit()
        with self.assertRaisesRegex(CaseError, "schema"):
            Case(self.case.path)


class SafeIOTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def test_final_and_parent_symlinks_refused(self):
        target = self.root / "target"; target.write_bytes(b"test")
        link = self.root / "link"; link.symlink_to(target)
        with self.assertRaises(CaseError):
            bounded_read(link, 100)
        folder = self.root / "folder"; folder.mkdir(); (folder / "data").write_bytes(b"test")
        alias = self.root / "alias"; alias.symlink_to(folder, target_is_directory=True)
        with self.assertRaises(CaseError):
            bounded_read(alias / "data", 100)

    def test_fifo_rejected_without_waiting_for_writer(self):
        fifo = self.root / "fifo"; os.mkfifo(fifo)
        with self.assertRaisesRegex(CaseError, "regular_file"):
            bounded_read(fifo, 100)

    def test_file_change_during_read_detected(self):
        path = self.root / "data"; path.write_bytes(b"one")
        with self.assertRaisesRegex(CaseError, "changed"):
            with regular_reader(path, 100) as (stream, _):
                stream.read(); path.write_bytes(b"different content")

    def test_output_never_overwrites_existing_file(self):
        path = self.root / "out"; path.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            write_new(path, b"replace")
        self.assertEqual(path.read_bytes(), b"keep")

    def test_private_key_permissions_and_length(self):
        path = self.root / "key"; path.write_bytes(b"x" * 32); path.chmod(0o644)
        with self.assertRaisesRegex(CaseError, "owner_only"):
            read_key(path)
        path.chmod(0o600); self.assertEqual(read_key(path), b"x" * 32)
        path.write_bytes(b"short")
        with self.assertRaisesRegex(CaseError, "length"):
            read_key(path)


if __name__ == "__main__":
    unittest.main()
