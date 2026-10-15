import hashlib
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from testifex import safeio
from testifex.model import CaseError


class VerifiedReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / "evidence.bin"
        self.raw = b"original synthetic record\n"
        self.path.write_bytes(self.raw)
        self.sha = hashlib.sha256(self.raw).hexdigest()

    def tearDown(self):
        self.temp.cleanup()

    def test_verified_stream_is_rewound_and_retains_original_descriptor(self):
        replacement = self.root / "replacement"
        replacement.write_bytes(b"replacement synthetic record\n")
        with self.assertRaisesRegex(CaseError, "input_changed_during_read"):
            with safeio.verified_reader(self.path, self.sha) as (stream, info):
                self.assertEqual(stream.tell(), 0)
                self.assertEqual(info.st_size, len(self.raw))
                os.replace(replacement, self.path)
                self.assertEqual(stream.read(), self.raw)

    def test_changes_to_same_inode_are_detected_on_exit(self):
        with self.assertRaisesRegex(CaseError, "input_changed_during_read"):
            with safeio.verified_reader(self.path, self.sha) as (stream, _):
                self.path.write_bytes(b"modified synthetic record\n")
                stream.read()

    def test_revalidation_ignores_buffer_cache_and_coarse_stat_values(self):
        original_stat = self.path.stat()
        with patch.object(safeio.os, "stat", return_value=original_stat), patch.object(safeio.os, "fstat", return_value=original_stat):
            with self.assertRaisesRegex(CaseError, "input_changed_during_read"):
                with safeio.verified_reader(self.path, self.sha) as (stream, _):
                    self.assertEqual(stream.read(1), self.raw[:1])
                    self.path.write_bytes(b"modified synthetic record\n")

    def test_wrong_digest_never_yields_unverified_data(self):
        entered = False
        with self.assertRaisesRegex(CaseError, "evidence_digest_mismatch"):
            with safeio.verified_reader(self.path, "0" * 64):
                entered = True
        self.assertFalse(entered)

    def test_digest_shape_is_checked_before_any_file_access(self):
        for value in (None, 1, "", "a" * 63, "a" * 65, "A" * 64, "../outside", "g" * 64):
            with self.subTest(value=value), patch.object(safeio, "regular_reader") as reader:
                with self.assertRaisesRegex(CaseError, "invalid_evidence_digest"):
                    with safeio.verified_reader(self.path, value):
                        self.fail("unvalidated digest yielded")
                reader.assert_not_called()

    def test_size_bound_and_special_files_are_rejected(self):
        with self.assertRaisesRegex(CaseError, "input_size_limit"):
            with safeio.verified_reader(self.path, self.sha, len(self.raw) - 1):
                self.fail("oversize file yielded")
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(CaseError, "regular_file_required"):
            with safeio.verified_reader(fifo, self.sha):
                self.fail("special file yielded")

    def test_empty_file_and_exact_size_bound(self):
        self.path.write_bytes(b"")
        with safeio.verified_reader(self.path, hashlib.sha256(b"").hexdigest(), 0) as (stream, info):
            self.assertEqual(stream.read(), b"")
            self.assertEqual(info.st_size, 0)
        self.path.write_bytes(self.raw)
        with safeio.verified_reader(self.path, self.sha, len(self.raw)) as (stream, _):
            self.assertEqual(stream.read(), self.raw)


class AtomicOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.output = self.root / "report.json"

    def tearDown(self):
        self.temp.cleanup()

    def test_complete_private_file_appears_only_at_publication(self):
        real_link = os.link
        payload = b"synthetic complete report\n" * 5000
        def link_after_complete(source, destination, **kwargs):
            self.assertFalse(self.output.exists())
            candidate = self.root / source
            self.assertEqual(candidate.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o600)
            return real_link(source, destination, **kwargs)
        with patch.object(safeio.os, "link", side_effect=link_after_complete):
            safeio.write_new(self.output, payload)
        self.assertEqual(self.output.read_bytes(), payload)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["report.json"])

    def test_existing_output_and_race_winner_are_never_overwritten(self):
        self.output.write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            safeio.write_new(self.output, b"replacement")
        self.assertEqual(self.output.read_bytes(), b"existing")
        self.output.unlink()
        real_link = os.link
        def competing_output(source, destination, **kwargs):
            self.output.write_bytes(b"other writer wins")
            return real_link(source, destination, **kwargs)
        with patch.object(safeio.os, "link", side_effect=competing_output):
            with self.assertRaises(FileExistsError):
                safeio.write_new(self.output, b"replacement")
        self.assertEqual(self.output.read_bytes(), b"other writer wins")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["report.json"])

    def test_parent_and_final_symlinks_cannot_redirect_output(self):
        actual = self.root / "actual"
        actual.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(CaseError):
            safeio.write_new(alias / "new", b"forbidden redirect")
        self.assertEqual(list(actual.iterdir()), [])
        target = actual / "target"
        target.write_bytes(b"retain target")
        self.output.symlink_to(target)
        with self.assertRaisesRegex(CaseError, "output_symlink_refused"):
            safeio.write_new(self.output, b"replacement")
        self.assertEqual(target.read_bytes(), b"retain target")
        self.assertTrue(self.output.is_symlink())

    def test_replaced_temporary_is_not_accepted_as_published_output(self):
        target = self.root / "untouched"
        target.write_bytes(b"unrelated synthetic data")
        real_link = os.link
        def substituted_temporary(source, destination, **kwargs):
            candidate = self.root / source
            candidate.unlink()
            candidate.symlink_to(target)
            return real_link(source, destination, **kwargs)
        with patch.object(safeio.os, "link", side_effect=substituted_temporary):
            with self.assertRaisesRegex(CaseError, "output_temporary_changed"):
                safeio.write_new(self.output, b"synthetic report")
        self.assertFalse(self.output.exists())
        self.assertFalse(self.output.is_symlink())
        self.assertEqual(target.read_bytes(), b"unrelated synthetic data")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["untouched"])

    def test_prepublication_failure_cleans_temporary_without_output(self):
        with patch.object(safeio.os, "fsync", side_effect=OSError("synthetic storage failure")):
            with self.assertRaises(OSError):
                safeio.write_new(self.output, b"synthetic report")
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.iterdir()), [])
        with self.assertRaises(TypeError):
            safeio.write_new(self.output, "bytes required")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_process_crash_before_publication_leaves_no_partial_final(self):
        program = """
import os, sys
from testifex import safeio
safeio.os.fsync = lambda fd: os._exit(19)
safeio.write_new(sys.argv[1], b"complete synthetic report" * 10000)
"""
        result = subprocess.run([sys.executable, "-c", program, str(self.output)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 19, result.stderr)
        self.assertFalse(self.output.exists())
        leftovers = list(self.root.iterdir())
        self.assertEqual(len(leftovers), 1)
        self.assertTrue(leftovers[0].name.startswith(".output-"))
        self.assertEqual(stat.S_IMODE(leftovers[0].stat().st_mode), 0o600)

    def test_process_crash_after_publication_leaves_complete_final(self):
        program = """
import os, sys
from testifex import safeio
real_link = os.link
def publish_then_exit(*args, **kwargs):
    real_link(*args, **kwargs)
    os._exit(23)
safeio.os.link = publish_then_exit
safeio.write_new(sys.argv[1], b"complete synthetic report" * 10000)
"""
        result = subprocess.run([sys.executable, "-c", program, str(self.output)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(self.output.read_bytes(), b"complete synthetic report" * 10000)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
