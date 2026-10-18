"""Mors scriptoris ante et post terminos transactionis sine iactura probatur."""
import hashlib
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from probentium import maintenance
from probentium.store import CaseStore
from probentium.contracts import ProbentiumError


CRASH_WRITER = r'''
import os, signal, sys
import probentium.store as storage
storage.CHECKPOINT_RECORDS = 2
phase, target = sys.argv[3], int(sys.argv[4])
with storage.CaseStore(sys.argv[1]) as case:
    original = case._commit_checkpoint
    count = [0]
    def checkpoint(reopen=False):
        count[0] += 1
        if phase == 'before' and count[0] == target:
            os.kill(os.getpid(), signal.SIGKILL)
        original(reopen=reopen)
        if phase == 'after' and count[0] == target:
            os.kill(os.getpid(), signal.SIGKILL)
    case._commit_checkpoint = checkpoint
    if phase == 'after_sql_commit':
        underlying = case.db
        class Connection:
            def __getattr__(self, name):
                return getattr(underlying, name)
            def execute(self, statement, *args, **kwargs):
                result = underlying.execute(statement, *args, **kwargs)
                if statement == 'COMMIT' and count[0] == target:
                    os.kill(os.getpid(), signal.SIGKILL)
                return result
        case.db = Connection()
    case.ingest(sys.argv[2], 'events', 'Synthetic crash matrix')
raise SystemExit(92)
'''


@unittest.skipUnless(sys.platform.startswith("linux"), "strict recovery requires Linux")
class CheckpointMatrixTests(unittest.TestCase):
    def test_disk_and_io_faults_at_checkpoint_boundaries_resume_identically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.jsonl"
            lines = [(json.dumps({"kind": "generic", "timestamp": None, "actor": "synthetic-" + str(i)}) + "\n").encode()
                     if i not in (2, 5) else b"\n" if i == 2 else b"{broken\n" for i in range(8)]
            source.write_bytes(b"".join(lines))
            with CaseStore.create(root / "reference") as case:
                expected = case.ingest(source, "events", "Reference")
                expected_ids = sorted(row["id"] for row in case.query_events()["rows"])
            for error in (errno.ENOSPC, errno.EIO):
                for phase in ("before", "after_sql_commit", "after"):
                    for boundary in range(1, 5):
                        with self.subTest(errno=error, phase=phase, boundary=boundary):
                            path = root / (str(error) + phase + str(boundary))
                            with CaseStore.create(path) as case, patch("probentium.store.CHECKPOINT_RECORDS", 2):
                                original = case._commit_checkpoint
                                count = [0]
                                def checkpoint(reopen=False):
                                    count[0] += 1
                                    if phase == "before" and count[0] == boundary:
                                        raise OSError(error, "synthetic storage failure")
                                    original(reopen=reopen)
                                    if phase == "after" and count[0] == boundary:
                                        raise OSError(error, "synthetic storage failure")
                                case._commit_checkpoint = checkpoint
                                if phase == "after_sql_commit":
                                    underlying = case.db
                                    class Connection:
                                        def __getattr__(self, name):
                                            return getattr(underlying, name)
                                        def execute(self, statement, *args, **kwargs):
                                            result = underlying.execute(statement, *args, **kwargs)
                                            if statement == "COMMIT" and count[0] == boundary:
                                                raise OSError(error, "synthetic storage failure")
                                            return result
                                    case.db = Connection()
                                with self.assertRaises((OSError, ProbentiumError)):
                                    case.ingest(source, "events", "Synthetic fault")
                            before = {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in path.rglob("*") if p.is_file()}
                            target = path.with_name(path.name + "-recovered")
                            maintenance.recover_copy(path, target)
                            self.assertEqual(before, {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
                                                     for p in path.rglob("*") if p.is_file()})
                            with CaseStore(target) as recovered:
                                sources = recovered.sources()
                                current = recovered.ingest(source, "events", "Synthetic retry") if not sources else sources[0]
                                if current["state"] == "incomplete":
                                    current = recovered.resume(current["id"])
                                self.assertEqual(current["state"], "complete")
                                self.assertEqual(current["counters"], expected["counters"])
                                self.assertEqual(current["records_total"], 8)
                                self.assertEqual(sorted(row["id"] for row in recovered.query_events()["rows"]), expected_ids)
                                for row in recovered.query_events()["rows"]:
                                    self.assertEqual(recovered.raw(row["id"]), lines[row["ordinal"] - 1])
                                self.assertTrue(recovered.verify()["ok"])

    def test_all_checkpoints_before_commit_after_sql_and_after_fsync_recover_exactly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.jsonl"
            lines = [(json.dumps({"kind": "auth.failure", "timestamp": "2026-10-18T12:00:00Z",
                                  "actor": "synthetic-" + str(index)}) + "\n").encode()
                     if index not in (2, 5, 7) else b"\n" if index == 2 else b"{broken\n"
                     for index in range(8)]
            source.write_bytes(b"".join(lines))
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            with CaseStore.create(root / "reference") as reference:
                expected_source = reference.ingest(source, "events", "Synthetic reference")
                expected_ids = sorted(row["id"] for row in reference.query_events(limit=100)["rows"])
                expected_counters = expected_source["counters"]
                self.assertEqual(len(expected_ids), 5)
            for phase in ("before", "after_sql_commit", "after"):
                for boundary in range(1, 5):
                    with self.subTest(phase=phase, boundary=boundary):
                        origin = root / (phase + "-" + str(boundary))
                        restored = root / (phase + "-" + str(boundary) + "-recovered")
                        with CaseStore.create(origin):
                            pass
                        child = subprocess.run([sys.executable, "-c", CRASH_WRITER, str(origin), str(source),
                                                phase, str(boundary)], capture_output=True, timeout=20)
                        self.assertEqual(child.returncode, -signal.SIGKILL, child.stderr)
                        before = {str(path.relative_to(origin)): hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in origin.rglob("*") if path.is_file()}
                        receipt = maintenance.recover_copy(origin, restored)
                        self.assertFalse(receipt["source_modified"])
                        after = {str(path.relative_to(origin)): hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in origin.rglob("*") if path.is_file()}
                        self.assertEqual(before, after)
                        with CaseStore(restored) as case:
                            self.assertTrue(case.verify()["ok"])
                            current = case.sources()
                            if not current:
                                completed = case.ingest(source, "events", "Synthetic resumed source")
                            elif current[0]["state"] == "incomplete":
                                completed = case.resume(current[0]["id"])
                            else:
                                completed = current[0]
                            self.assertEqual(completed["state"], "complete")
                            self.assertEqual(completed["cursor"], len(b"".join(lines)))
                            self.assertEqual(completed["records_total"], 8)
                            self.assertEqual(completed["events_total"], 5)
                            self.assertEqual(completed["counters"], expected_counters)
                            rows = case.query_events(limit=100)["rows"]
                            self.assertEqual(sorted(row["id"] for row in rows), expected_ids)
                            for row in rows:
                                self.assertEqual(case.raw(row["id"]), lines[row["ordinal"] - 1])
                            self.assertTrue(case.verify()["ok"])
                        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_hash)


if __name__ == "__main__":
    unittest.main()
