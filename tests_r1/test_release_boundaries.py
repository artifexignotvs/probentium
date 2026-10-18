"""Fines publicationis et absentiae adversis casibus servantur."""
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from probentium import intake, maintenance, retention
from probentium.contracts import ProbentiumError, canonical_bytes
from probentium.store import CaseStore


class ReleaseBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _tree_digests(self, path):
        return {str(item.relative_to(path)): hashlib.sha256(item.read_bytes()).hexdigest()
                for item in path.rglob("*") if item.is_file()}

    def _two_cases(self):
        first, second = self.root / "first", self.root / "second"
        with CaseStore.create(first, "Synthetic first case") as case:
            first_id = case.meta["case_id"]
        with CaseStore.create(second, "Synthetic second case") as case:
            second_id = case.meta["case_id"]
        return first, second, first_id, second_id

    def _replace_with_link(self, first, second):
        database = first / "case.sqlite3"
        saved = first / "checked-database.bin"
        database.rename(saved)
        database.symlink_to(second / "case.sqlite3")
        return saved

    def _restore_database(self, first, saved):
        (first / "case.sqlite3").unlink()
        saved.rename(first / "case.sqlite3")

    def test_reacquired_source_is_available_but_authorization_remains_historical(self):
        source = self.root / "synthetic.txt"
        source.write_bytes(b"Synthetic evidence for retention regression.\n")
        with CaseStore.create(self.root / "case") as case:
            identity = case.ingest(source, "opaque", "Synthetic source")["id"]
            plan = retention.plan(case, [identity], "Synthetic owner", "Exercise ended",
                                  "2000-01-01T00:00:00Z")
            approval = retention.approve(case, plan["id"], "Synthetic reviewer", "Scope accepted")
            result = retention.execute(case, plan["id"], approval["id"])
            expected = [{"artifact_id": identity, "tombstone_id": result["tombstone_id"]}]
            before = retention.status(case)
            self.assertEqual(before["unavailable"], expected)
            self.assertEqual(before["historical_authorizations"], expected)
            self.assertEqual(case.verify()["exit_code"], 3)

            reacquired = case.ingest(source, "opaque", "Synthetic reacquisition")
            self.assertEqual(reacquired["id"], identity)
            after = retention.status(case)
            self.assertEqual(after["unavailable"], [])
            self.assertEqual(after["historical_authorizations"], expected)
            self.assertTrue((case.path / "blobs" / (identity + ".bin")).is_file())
            self.assertEqual(case.verify()["exit_code"], 0)

    def test_database_replaced_during_connect_is_rejected_without_mutating_other_case(self):
        """Mutatio ab eodem UID simulatur; hostilis dominus non arcetur."""
        first, second, first_id, second_id = self._two_cases()
        original_first = self._tree_digests(first)
        original_second = self._tree_digests(second)
        real_connect = sqlite3.connect
        expected_uri = (first / "case.sqlite3").as_uri() + "?mode=rw"
        replaced = []
        opened = []

        def replace_before_sqlite_open(path, *args, **kwargs):
            if str(path) == expected_uri and not replaced:
                replaced.append(self._replace_with_link(first, second))
            return real_connect(path, *args, **kwargs)

        try:
            with patch("probentium.store.sqlite3.connect", side_effect=replace_before_sqlite_open):
                with self.assertRaises(ProbentiumError) as caught:
                    with CaseStore(first) as case:
                        opened.append(case.meta["case_id"])
                        case.put_object("audit-proof", {"synthetic": True})
            self.assertEqual(len(replaced), 1)
            self.assertEqual(opened, [])
            self.assertEqual(self._tree_digests(second), original_second)
            with CaseStore(second) as case:
                self.assertEqual(case.meta["case_id"], second_id)
                self.assertEqual(case.objects("audit-proof"), [])
                self.assertEqual(case.verify()["exit_code"], 0)
        finally:
            if replaced:
                self._restore_database(first, replaced[0])
        self.assertEqual(self._tree_digests(first), original_first)
        with CaseStore(first) as case:
            self.assertEqual(case.meta["case_id"], first_id)
            self.assertEqual(case.verify()["exit_code"], 0)
        self.assertEqual(caught.exception.exit_code, 4)

    def test_database_replaced_after_open_blocks_write_and_leaves_both_cases_unchanged(self):
        """Nomen mutatum deprehenditur; omnia certamina eiusdem UID non probantur."""
        first, second, _, _ = self._two_cases()
        original_first = self._tree_digests(first)
        original_second = self._tree_digests(second)
        with CaseStore(first) as case:
            revision = case.revision
            saved = self._replace_with_link(first, second)
            try:
                with self.assertRaises(ProbentiumError) as caught:
                    case.put_object("audit-proof", {"synthetic": True})
            finally:
                self._restore_database(first, saved)
            self.assertEqual(case.revision, revision)
            self.assertEqual(case.objects("audit-proof"), [])
            self.assertEqual(case.verify()["exit_code"], 0)
        self.assertEqual(self._tree_digests(first), original_first)
        self.assertEqual(self._tree_digests(second), original_second)
        self.assertEqual(caught.exception.exit_code, 4)

    def test_interrupted_migration_publishes_nothing_and_retry_preserves_all_sources(self):
        from testifex.case import Case

        legacy_path, destination = self.root / "legacy", self.root / "migrated"
        with Case.create(legacy_path, "Synthetic legacy case") as legacy:
            for index in range(2):
                source = self.root / ("source-" + str(index) + ".jsonl")
                source.write_bytes(canonical_bytes({"kind": "auth.failure",
                    "timestamp": "2026-10-18T12:00:00Z", "actor": "synthetic-" + str(index)}) + b"\n")
                legacy.ingest(source, "events", "Synthetic " + str(index))
        original = self._tree_digests(legacy_path)
        real_ingest = CaseStore.ingest
        attempts = []

        def interrupt_second(case, *args, **kwargs):
            attempts.append(True)
            if len(attempts) == 2:
                raise ProbentiumError("synthetic_interruption", 6)
            return real_ingest(case, *args, **kwargs)

        with patch.object(CaseStore, "ingest", new=interrupt_second):
            with self.assertRaisesRegex(ProbentiumError, "synthetic_interruption"):
                maintenance.migrate_v1(legacy_path, destination)
        self.assertEqual(len(attempts), 2)
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".migration-*")), [])
        self.assertEqual(self._tree_digests(legacy_path), original)

        result = maintenance.migrate_v1(legacy_path, destination)
        self.assertEqual(result["completion"], "atomically_published_after_verification")
        self.assertEqual(result["sources"], 2)
        with CaseStore(destination) as case:
            self.assertEqual(len(case.sources()), 2)
            self.assertEqual(case.query_events()["total"], 2)
            self.assertEqual(len(case.objects("migration")), 1)
            self.assertEqual(case.verify()["exit_code"], 0)
        self.assertEqual(self._tree_digests(legacy_path), original)

    def test_inspect_aggregate_byte_limit_accepts_exact_boundary(self):
        source = self.root / "sample.txt"
        source.write_bytes(b" \n \n \n")
        with patch.object(intake, "MAX_SAMPLE_BYTES", 6):
            result = intake.inspect_file(source, format_name="events", sample_lines=3)
        self.assertEqual(result["sampled_bytes"], 6)
        self.assertEqual(result["sampled_lines"], 3)
        self.assertFalse(result["sample_only"])
        self.assertEqual(result["candidates"][0]["blank"], 3)

    def test_inspect_aggregate_byte_limit_fails_before_worker_at_one_byte_over(self):
        source = self.root / "sample.txt"
        source.write_bytes(b" \n \n \n")
        with patch.object(intake, "MAX_SAMPLE_BYTES", 5), patch.object(intake, "ParserWorker") as worker:
            with self.assertRaisesRegex(ProbentiumError, "sample_byte_limit") as caught:
                intake.inspect_file(source, format_name="events", sample_lines=3)
        self.assertEqual(caught.exception.exit_code, 6)
        worker.assert_not_called()

    def test_failed_initialization_publishes_nothing_and_retry_creates_verified_case(self):
        destination = self.root / "initialized"
        failure = ProbentiumError("synthetic_initialization_failure", 6)
        with patch("probentium.store._dump", side_effect=failure) as metadata:
            with self.assertRaisesRegex(ProbentiumError, "synthetic_initialization_failure"):
                CaseStore.create(destination, "Synthetic initialization")
        metadata.assert_called_once()
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".case-*")), [])

        with CaseStore.create(destination, "Synthetic initialization") as case:
            self.assertEqual(case.meta["name"], "Synthetic initialization")
            self.assertEqual(case.revision, 0)
            self.assertEqual(case.sources(), [])
            self.assertEqual(case.objects(), [])
            self.assertEqual(case.verify()["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
