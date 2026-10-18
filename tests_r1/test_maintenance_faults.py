"""Defectus repositionis exemplaria integra aut nulla relinquunt."""
import errno
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from probentium import maintenance
from probentium.contracts import ProbentiumError
from probentium.store import CaseStore


def tree(path):
    return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in path.rglob("*") if p.is_file()}


class MaintenanceFaultTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.input = self.root / "input.jsonl"
        self.raw = b'{"kind":"auth.success","timestamp":null,"actor":"synthetic"}\n'
        self.input.write_bytes(self.raw)
        with CaseStore.create(self.source) as case:
            case.ingest(self.input, "events", "Synthetic")
            self.event_id = case.query_events()["rows"][0]["id"]
        self.original = tree(self.source)

    def tearDown(self):
        self.temporary.cleanup()

    def complete_or_absent(self, target):
        if target.exists():
            with CaseStore(target) as case:
                self.assertTrue(case.verify()["ok"])
                self.assertEqual(case.query_events()["total"], 1)
                self.assertEqual(case.raw(self.event_id), self.raw)

    def test_every_recovery_fsync_boundary_refuses_or_leaves_complete_destination(self):
        calls = []
        original = os.fsync
        def observe(fd):
            calls.append(True)
            return original(fd)
        with patch("os.fsync", observe):
            maintenance.recover_copy(self.source, self.root / "baseline")
        self.assertGreaterEqual(len(calls), 8)
        for code in (errno.ENOSPC, errno.EIO):
            for boundary in range(1, len(calls) + 1):
                with self.subTest(errno=code, boundary=boundary):
                    target = self.root / ("fault-" + str(code) + "-" + str(boundary))
                    count = [0]
                    def fail(fd):
                        count[0] += 1
                        if count[0] == boundary:
                            raise OSError(code, "synthetic private canary")
                        return original(fd)
                    with patch("os.fsync", fail), self.assertRaises(ProbentiumError) as caught:
                        maintenance.recover_copy(self.source, target)
                    self.assertNotIn("canary", str(caught.exception))
                    if target.exists():
                        self.assertEqual(caught.exception.code, "directory_published_durability_unknown")
                    self.complete_or_absent(target)
                    self.assertEqual(tree(self.source), self.original)
                    self.assertEqual(list(self.root.glob(".recovery-*")), [])
                    if not target.exists():
                        maintenance.recover_copy(self.source, target)
                        self.complete_or_absent(target)

    def test_rename_failure_never_publishes_and_retry_preserves_source(self):
        for code in (errno.ENOSPC, errno.EIO, errno.EXDEV):
            with self.subTest(errno=code):
                target = self.root / ("rename-" + str(code))
                with patch.object(maintenance, "_rename_noreplace", side_effect=OSError(code, "synthetic private canary")):
                    with self.assertRaises(ProbentiumError) as caught:
                        maintenance.recover_copy(self.source, target)
                self.assertFalse(target.exists())
                self.assertNotIn("canary", str(caught.exception))
                self.assertEqual(tree(self.source), self.original)
                maintenance.recover_copy(self.source, target)
                self.complete_or_absent(target)

    def test_disk_full_during_real_partial_copy_does_not_publish_or_change_original(self):
        original = os.fdopen
        written = []
        class Writer:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                return self
            def __exit__(self, *_):
                self.stream.close()
            def write(self, data):
                written.append(self.stream.write(data[:17]))
                self.stream.flush()
                raise OSError(errno.ENOSPC, "synthetic private canary")
        def wrap(fd, mode="r", *args, **kwargs):
            stream = original(fd, mode, *args, **kwargs)
            return Writer(stream) if mode == "wb" else stream
        target = self.root / "partial-copy"
        with patch("os.fdopen", wrap), self.assertRaises(ProbentiumError) as caught:
            maintenance.recover_copy(self.source, target)
        self.assertEqual(written, [17])
        self.assertNotIn("canary", str(caught.exception))
        self.assertFalse(target.exists())
        self.assertEqual(tree(self.source), self.original)
        self.assertEqual(list(self.root.glob(".recovery-*")), [])
        maintenance.recover_copy(self.source, target)
        self.complete_or_absent(target)

    def test_real_process_killed_at_rename_boundary_never_exposes_half_case(self):
        program = '''import os,signal,sys
from probentium import maintenance
original=maintenance._rename_noreplace
def rename(*args):
    if sys.argv[3]=='before':os.kill(os.getpid(),signal.SIGKILL)
    original(*args)
    os.kill(os.getpid(),signal.SIGKILL)
maintenance._rename_noreplace=rename
maintenance.recover_copy(sys.argv[1],sys.argv[2])
'''
        for phase in ("before", "after"):
            with self.subTest(phase=phase):
                target = self.root / ("crash-" + phase)
                child = subprocess.run([sys.executable, "-c", program, str(self.source), str(target), phase],
                                       capture_output=True, timeout=20)
                self.assertEqual(child.returncode, -signal.SIGKILL, child.stderr)
                self.assertEqual(target.exists(), phase == "after")
                self.complete_or_absent(target)
                self.assertEqual(tree(self.source), self.original)

    def test_existing_destination_survives_failed_recovery(self):
        target = self.root / "existing"
        target.mkdir(mode=0o700)
        (target / "marker").write_bytes(b"retain")
        with self.assertRaisesRegex(ProbentiumError, "destination_exists"):
            maintenance.recover_copy(self.source, target)
        self.assertEqual(tree(target), {"marker": hashlib.sha256(b"retain").hexdigest()})
        self.assertEqual(tree(self.source), self.original)

    def test_direct_snapshot_restore_partial_reader_failure_has_no_destination(self):
        with CaseStore(self.source) as case:
            snapshot = case.export_snapshot()
            source = snapshot["artifacts"][0]
            @contextmanager
            def broken_reader(_):
                class Reader:
                    def read(self, _):
                        raise OSError(errno.ENOSPC, "synthetic private canary")
                yield Reader()
            target = self.root / "snapshot-restore"
            with self.assertRaisesRegex(ProbentiumError, "storage_resource_limit") as caught:
                maintenance.restore_snapshot(snapshot, broken_reader, target)
            self.assertEqual(caught.exception.exit_code, 6)
            self.assertFalse(target.exists())
            self.assertEqual(list(self.root.glob(".restore-snapshot-*")), [])
            maintenance.restore_snapshot(snapshot, lambda identity: case._blob(identity, source["size"]), target)
        self.complete_or_absent(target)
        self.assertEqual(tree(self.source), self.original)
