"""Custodia et fines adversis exemplis probantur."""
import hashlib
import json
import os
import sqlite3
import stat
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from probentium.contracts import ProbentiumError, canonical_bytes, object_digest
from probentium.store import CaseStore
import probentium.store as module


def event(actor="operator", timestamp="2026-10-18T12:00:00Z", **extra):
    return json.dumps({"kind": "auth.failure", "timestamp": timestamp, "actor": actor, **extra}, ensure_ascii=False).encode() + b"\n"


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.case = self.root / "case"
        self.input = self.root / "input.log"

    def tearDown(self):
        self.temp.cleanup()

    def create(self):
        return CaseStore.create(self.case, "Local synthetic case")

    def write(self, data):
        self.input.write_bytes(data)
        return self.input

    def assertCode(self, code, callable_, *args, **kwargs):
        with self.assertRaises(ProbentiumError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def alter(self, sql, args=()):
        with closing(sqlite3.connect(self.case / "case.sqlite3")) as db:
            with db:
                db.execute(sql, args)

    def test_create_modes_metadata_and_reopen(self):
        with self.create() as store:
            self.assertEqual(store.revision, 0)
            self.assertEqual(store.meta["schema_version"], 2)
            self.assertTrue(store.verify()["ok"])
        for path in (self.case, self.case / "blobs"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        for path in (self.case / "case.lock", self.case / "case.sqlite3"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with CaseStore(self.case) as store:
            self.assertEqual(store.meta["name"], "Local synthetic case")
        self.assertCode("case_already_exists", CaseStore.create, self.case)

    def test_exact_locator_crlf_unknown_alignment(self):
        first = b" \t\r\n"
        raw = event(actor="Straße").replace(b"\n", b"\r\n")
        with self.create() as store:
            source = store.ingest(self.write(first + raw), "events", "Synthetic")
            row = store.query_events()["rows"][0]
            self.assertEqual(row["offset"], len(first))
            self.assertEqual(row["length"], len(raw))
            self.assertEqual(row["ordinal"], 2)
            self.assertEqual(row["raw_digest"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(store.raw(row["id"]), raw)
            self.assertEqual(source["id"], hashlib.sha256(first + raw).hexdigest())
            self.assertEqual(row["record_refs"], [row["primary_record_ref"]])
            self.assertEqual(row["clock_alignment"], "unknown")
            self.assertIsNone(row["reference_time"])
            cell = row["recorded_time"]
            self.assertEqual(int(cell["hi_us"]) - int(cell["lo_us"]), 1_000_000)
            self.assertFalse(cell["hi_closed"])
            self.assertTrue(store.verify()["ok"])

    def test_catalog_hex_encoding_matches_independent_canonical_reference(self):
        with self.create() as store:
            store.ingest(self.write(event()), "events", "Synthetic")
            store.put_object("note", {"text": "Catalog reference"})
            expected = hashlib.sha256(b"PROBENTIUM-CATALOG-V1\0")
            columns = {"artifacts": "id,digest", "acquisitions": "id,digest", "records": "id,digest", "parse_runs": "id,digest",
                       "active_runs": "artifact_id,parse_run_id,digest", "parse_records": "parse_run_id,record_id,digest",
                       "events": "id,digest", "objects": "id,digest"}
            for table, fields in sorted(columns.items()):
                expected.update(canonical_bytes(table) + b"\n")
                order = fields.rsplit(",", 1)[0]
                for row in store.db.execute("SELECT " + fields + " FROM " + table + " ORDER BY " + order):
                    expected.update(canonical_bytes(list(row)) + b"\n")
            self.assertEqual(module._catalog_digest(store.db), expected.hexdigest())

    def test_unknown_time_preserved(self):
        with self.create() as store:
            store.ingest(self.write(event(timestamp=None)), "events", "Unknown")
            row = store.query_events()["rows"][0]
            self.assertIsNone(row["recorded_time"])
            self.assertIsNone(row["time_low_us"])
            self.assertEqual(row["time_basis"], "unknown_explicit")

    def test_duplicate_acquisition_not_independent_events(self):
        with self.create() as store:
            self.write(event())
            first = store.ingest(self.input, "events", "One")
            before = store.query_events()["rows"][0]
            second = store.ingest(self.input, "events", "Two")
            self.assertEqual(first["id"], second["id"])
            self.assertTrue(second["duplicate_artifact"])
            self.assertEqual(len(store.sources()), 1)
            self.assertEqual(len(second["acquisitions"]), 2)
            self.assertEqual(store.query_events()["total"], 1)
            self.assertEqual(store.query_events()["rows"][0]["id"], before["id"])
            self.assertTrue(store.verify()["ok"])

    def test_record_identity_independent_of_parser(self):
        raw = b'2026-10-18T12:00:00Z local sshd[4]: Failed password for operator from 192.0.2.30 port 2222 ssh2\n'
        with self.create() as store:
            first = store.ingest(self.write(raw), "auth", "Auth")
            original = store.query_events()["rows"][0]
            second = store.ingest(self.input, "events", "Other parser")
            self.assertEqual(first["id"], second["id"])
            self.assertNotEqual(first["active_parse_run"], second["active_parse_run"])
            self.assertEqual(store.query_events()["total"], 0)
            self.assertEqual(store.raw(original["id"]), raw)
            self.assertEqual(store.db.execute("SELECT count(*) FROM records").fetchone()[0], 1)
            self.assertTrue(store.verify()["ok"])

    def test_error_blank_unsupported_and_oversize_accounting(self):
        raw = (b"\n" + b"unrecognised line\n" +
               b"2026-10-18T12:00:00Z local other[3]: ignored message\n" +
               b"x" * (module.MAX_LINE + 1) + b"\n" +
               b"2026-10-18T12:00:00Z local sshd[4]: Failed password for operator from 192.0.2.30 port 2222 ssh2\n")
        with self.create() as store:
            result = store.ingest(self.write(raw), "auth", "Accounting")
            self.assertEqual(result["status"], "complete")
            self.assertFalse(result["interpretation_complete"])
            self.assertEqual(result["counters"], {"parsed": 1, "blank": 1, "unsupported": 1, "malformed": 1, "oversize": 1, "known_out_of_scope": 0})
            self.assertEqual(result["records_total"], 5)
            self.assertEqual(result["cursor"], len(raw))
            self.assertEqual(store.query_events()["rows"][0]["ordinal"], 5)
            self.assertTrue(store.verify()["ok"])

    def test_partial_tail_is_unknown_not_zero(self):
        with self.create() as store, patch.object(module, "MAX_RECORDS", 2):
            result = store.ingest(self.write(event() * 3), "events", "Bounded")
            self.assertEqual(result["status"], "incomplete")
            self.assertIsNone(result["unprocessed_records"])
            self.assertEqual(result["unprocessed_bytes"], len(event()))
            self.assertFalse(result["interpretation_complete"])
            self.assertEqual(store.query_events()["total"], 2)
            self.assertTrue(store.verify()["ok"])

    def test_empty_artifact_complete_zero_records(self):
        with self.create() as store:
            result = store.ingest(self.write(b""), "auth", "Empty")
            self.assertEqual(result["records_total"], 0)
            self.assertEqual(result["status"], "complete")
            self.assertTrue(store.verify()["ok"])

    def test_strict_json_errors_do_not_echo_payload(self):
        secret = "private-canary-never-diagnostic"
        rows = [b'{"kind":"generic","kind":"auth.success","timestamp":null,"actor":"' + secret.encode() + b'"}\n',
                b'{"kind":"generic","timestamp":null,"attributes":{"pid":NaN}}\n',
                b'{"kind":"generic","timestamp":null,"attributes":{"pid":1.5}}\n',
                b'{"nested":' + b'[' * 40 + b'0' + b']' * 40 + b'}\n']
        with self.create() as store:
            result = store.ingest(self.write(b"".join(rows)), "events", "Malformed")
            self.assertEqual(result["counters"]["malformed"], len(rows))
            self.assertEqual(store.query_events()["total"], 0)
            codes = list(store.db.execute("SELECT code FROM parse_records"))
            self.assertNotIn(secret, repr(codes))
            self.assertTrue(store.verify()["ok"])

    def test_literal_unicode_query_is_whole_case_past_ten_thousand(self):
        raw = event() * 10_001 + event(actor="Straße_%target")
        with self.create() as store:
            store.ingest(self.write(raw), "events", "Large")
            result = store.query_events("STRASSE_%TARGET", limit=1)
            self.assertEqual(result["total"], 1)
            self.assertEqual(result["rows"][0]["ordinal"], 10_002)
            self.assertEqual(store.query_events("%target")["total"], 1)
            self.assertEqual(store.query_events("%')[OR 1=1]")["total"], 0)
            seen = []
            for offset in range(0, 10_002, module.MAX_PAGE):
                seen.extend(row["id"] for row in store.query_events(limit=module.MAX_PAGE, offset=offset)["rows"])
            self.assertEqual(len(seen), 10_002)
            self.assertEqual(len(set(seen)), 10_002)

    def test_expected_revision_on_reads_and_writes(self):
        with self.create() as store:
            store.put_object("note", {"text": "One"}, expected_revision=0)
            self.assertCode("revision_conflict", store.put_object, "note", {"text": "Two"}, expected_revision=0)
            self.assertCode("revision_conflict", store.query_events, expected_revision=0)
            self.assertCode("invalid_expected_revision", store.query_events, expected_revision=True)
            self.assertEqual(store.revision, 1)
            self.assertEqual(len(store.objects()), 1)

    def test_shared_snapshot_blocks_writer_until_reader_closes(self):
        with self.create() as one:
            with CaseStore(self.case) as two:
                error = self.assertCode("case_locked", one.put_object, "note", {"text": "Blocked"})
                self.assertEqual(error.exit_code, 5)
                self.assertEqual(two.revision, 0)
                self.assertEqual(one.revision, 0)
            one.put_object("note", {"text": "Accepted"})
            self.assertEqual(one.revision, 1)

    def test_event_limit_rolls_back_all_database_changes(self):
        with self.create() as store, patch.object(module, "MAX_EVENTS", 1):
            self.assertCode("case_event_limit", store.ingest, self.write(event() * 2), "events", "Overflow")
            self.assertEqual(store.revision, 0)
            self.assertEqual(store.sources(), [])
            self.assertEqual(store.query_events()["total"], 0)
            self.assertTrue(store.verify()["ok"])
            self.assertEqual(len(list((self.case / "blobs").glob("*.bin"))), 1)

    def test_fsync_failure_never_commits_artifact(self):
        with self.create() as store:
            with patch.object(module.os, "fsync", side_effect=OSError("synthetic")):
                self.assertCode("evidence_copy_failed", store.ingest, self.write(event()), "events", "Fail")
            self.assertEqual(store.revision, 0)
            self.assertEqual(store.sources(), [])
            self.assertEqual(list((self.case / "blobs").glob(".incoming-*")), [])

    def test_source_symlink_and_parent_symlink_are_rejected(self):
        self.write(event())
        link = self.root / "alias"
        link.symlink_to(self.input)
        with self.create() as store:
            self.assertCode("source_access_failed", store.ingest, link, "events", "Link")
            folder = self.root / "real"
            folder.mkdir()
            (folder / "data").write_bytes(event())
            (self.root / "directory-link").symlink_to(folder, target_is_directory=True)
            self.assertCode("source_access_failed", store.ingest, self.root / "directory-link" / "data", "events", "Link")

    def test_fifo_rejected_without_blocking(self):
        os.mkfifo(self.input)
        with self.create() as store:
            self.assertCode("source_access_failed", store.ingest, self.input, "auth", "FIFO")

    def test_case_symlink_and_unsafe_modes_rejected(self):
        with self.create():
            pass
        link = self.root / "alias"
        link.symlink_to(self.case, target_is_directory=True)
        self.assertCode("safe_directory_access_failed", CaseStore, link)
        (self.case / "case.sqlite3").chmod(0o644)
        self.assertCode("case_file_permissions", CaseStore, self.case)

    def test_foreign_sqlite_and_added_trigger_rejected(self):
        with self.create():
            pass
        self.alter("CREATE TRIGGER changed AFTER INSERT ON objects BEGIN DELETE FROM events; END")
        self.assertCode("case_schema_mismatch", CaseStore, self.case)

    def test_changed_blob_is_detected_before_raw(self):
        with self.create() as store:
            source = store.ingest(self.write(event()), "events", "Evidence")
            row = store.query_events()["rows"][0]
            blob = self.case / "blobs" / (source["id"] + ".bin")
            value = blob.read_bytes()
            blob.write_bytes(value.replace(b"operator", b"operat0r"))
            self.assertCode("evidence_digest_mismatch", store.raw, row["id"])
            result = store.verify()
            self.assertFalse(result["ok"])
            self.assertEqual(result["issues"][0]["code"], "evidence_digest_mismatch")

    def test_missing_blob_fails_and_existing_blob_not_overwritten(self):
        with self.create() as store:
            source = store.ingest(self.write(event()), "events", "Evidence")
            blob = self.case / "blobs" / (source["id"] + ".bin")
            blob.write_bytes(b"tampered")
            self.assertCode("evidence_size_mismatch", store.ingest, self.input, "events", "Again")
            self.assertEqual(blob.read_bytes(), b"tampered")
            blob.unlink()
            self.assertFalse(store.verify()["ok"])

    def test_changed_event_and_derived_index_are_detected(self):
        with self.create() as store:
            store.ingest(self.write(event()), "events", "Evidence")
        self.alter("UPDATE events SET actor='forged'")
        with CaseStore(self.case) as store:
            self.assertFalse(store.verify()["ok"])
            self.assertCode("event_identity_mismatch", store.query_events)

    def test_changed_range_with_rehashed_object_still_rejected(self):
        with self.create() as store:
            store.ingest(self.write(event()), "events", "Evidence")
            record = store._record(store.query_events()["rows"][0]["primary_record_ref"])
        record["offset"] += 1
        self.alter("UPDATE records SET data=?,digest=?,offset=?", (canonical_bytes(record), object_digest(record), record["offset"]))
        with CaseStore(self.case) as store:
            self.assertFalse(store.verify()["ok"])

    def test_object_tamper_revision_and_digest_are_detected(self):
        with self.create() as store:
            saved = store.put_object("claim", {"predicate": "observed"})
            store.put_object("note", {"text": "Another"})
        self.alter("UPDATE objects SET revision=2 WHERE id=?", (saved["id"],))
        with CaseStore(self.case) as store:
            self.assertFalse(store.verify()["ok"])
            self.assertCode("stored_object_invalid", store.get_object, saved["id"])

    def test_object_data_change_even_with_new_payload_hash_fails(self):
        with self.create() as store:
            saved = store.put_object("claim", {"predicate": "observed"})
        altered = {"predicate": "forged"}
        digest = object_digest({"kind": "claim", "data": altered, "revision": 1})
        self.alter("UPDATE objects SET data=?,digest=? WHERE id=?", (canonical_bytes(altered), digest, saved["id"]))
        with CaseStore(self.case) as store:
            self.assertCode("object_identity_mismatch", store.get_object, saved["id"])

    def test_objects_are_copied_filtered_and_bounded(self):
        original = {"text": "Review", "nested": [1, 2]}
        with self.create() as store:
            saved = store.put_object("note", original)
            original["nested"].append(3)
            self.assertEqual(store.get_object(saved["id"])["data"]["nested"], [1, 2])
            store.put_object("claim", {"kind": "record_observed"})
            self.assertEqual(len(store.objects("note")), 1)
            self.assertEqual(len(store.objects()), 2)
            with patch.object(module, "MAX_LIST_BYTES", 1):
                self.assertCode("object_listing_limit", store.objects)
            self.assertCode("invalid_object_value", store.put_object, "note", {"x": float("nan")})
            self.assertCode("invalid_object_value", store.put_object, "note", {"x": 2**63})
            self.assertCode("invalid_object_schema", store.put_object, "../note", {})
            deep = {}
            for _ in range(40):
                deep = {"nested": deep}
            self.assertCode("object_structure_limit", store.put_object, "note", deep)

    def test_active_run_digest_tamper_detected(self):
        with self.create() as store:
            store.ingest(self.write(event()), "events", "Evidence")
        self.alter("UPDATE active_runs SET digest=?", ("0" * 64,))
        with CaseStore(self.case) as store:
            self.assertFalse(store.verify()["ok"])
            self.assertCode("source_identity_mismatch", store.sources)

    def test_disposition_tamper_detected(self):
        with self.create() as store:
            store.ingest(self.write(b"\nunknown\n"), "auth", "Evidence")
        self.alter("UPDATE parse_records SET code='forged'")
        with CaseStore(self.case) as store:
            self.assertFalse(store.verify()["ok"])

    def test_journal_reuse_and_string_microseconds(self):
        raw = b'{"__REALTIME_TIMESTAMP":"1792324800000000","__MONOTONIC_TIMESTAMP":"123","_HOSTNAME":"local","MESSAGE":"hello"}\n'
        with self.create() as store:
            store.ingest(self.write(raw), "journal", "Journal")
            row = store.query_events()["rows"][0]
            self.assertEqual(row["attributes"]["monotonic_us"], "123")
            self.assertEqual(int(row["recorded_time"]["hi_us"]) - int(row["recorded_time"]["lo_us"]), 1)
            self.assertTrue(store.verify()["ok"])

    def test_unsupported_format_does_not_mutate(self):
        with self.create() as store:
            self.assertCode("format_unsupported", store.ingest, self.write(event()), "events-v3", "Future")
            self.assertEqual(store.revision, 0)

    def test_surrogate_and_mutable_recursive_objects_are_bounded(self):
        with self.create() as store:
            self.assertCode("invalid_object_text", store.put_object, "note", {"x": "\ud800"})
            cycle = {}
            cycle["cycle"] = cycle
            self.assertCode("object_structure_limit", store.put_object, "note", cycle)
            self.assertEqual(store.revision, 0)

    def test_bounded_encoding_matches_independent_canonical_oracle(self):
        import random
        import rfc8785
        randomizer = random.Random(32765)
        alphabet = ['x', '\\', '\"', '\n', '\x00', '\u202e', '\u00e9', '\U0001f600', '\uffff']
        for _ in range(1000):
            value = {"ascii": [None, True, randomizer.randint(-9007199254740991, 9007199254740991)],
                     "nested": {"value": "".join(randomizer.choices(alphabet, k=40))}}
            if randomizer.choice((True, False)):
                value.update({'\ue000': 1, '\U0001f600': 2})
            self.assertEqual(module._bounded(value), rfc8785.dumps(value))

    def test_bounded_encoding_keeps_validation_before_encoding(self):
        invalid = [({1: "value"}, "invalid_object_structure"),
                   ({"bad": 1.5}, "invalid_object_value"),
                   ({"bad": 9007199254740992}, "invalid_object_value"),
                   ({"bad": "\ud800"}, "invalid_object_text"),
                   ({"\ud800": "value"}, "invalid_object_text"),
                   ({"bad": (1, 2)}, "invalid_object_value")]
        for value, code in invalid:
            with self.subTest(code=code):
                self.assertCode(code, module._bounded, value)
        self.assertCode("object_size_limit", module._bounded, {"value": "x" * 1024}, 100)

    def test_object_budget_counts_json_escape_expansion_before_encoding(self):
        import rfc8785
        for value in ({"controls": "\x00\n\\\"\t" * 100}, {"é": [True, False, None, -123, "\U0001f600"]},
                      {"empty": {}, "list": [1, 2, 3]}, {}):
            expected = rfc8785.dumps(value)
            self.assertEqual(module._bounded(value, len(expected)), expected)
            with patch.object(module, "_canonical_validated", side_effect=AssertionError("encoded_before_budget_check")):
                self.assertCode("object_size_limit", module._bounded, value, len(expected) - 1)

    def test_rehashed_malformed_event_produces_safe_error(self):
        with self.create() as store:
            store.ingest(self.write(event()), "events", "Evidence")
        malformed = {"private-canary": "not a valid normalized event"}
        self.alter("UPDATE events SET data=?,digest=?", (canonical_bytes(malformed), object_digest(malformed)))
        with CaseStore(self.case) as store:
            self.assertCode("event_identity_mismatch", store.query_events)
            self.assertFalse(store.verify()["ok"])

    def test_deleted_object_detected_and_cannot_be_masked_by_mutation(self):
        with self.create() as store:
            saved = store.put_object("note", {"text": "Retain"})
        self.alter("DELETE FROM objects WHERE id=?", (saved["id"],))
        with CaseStore(self.case) as store:
            self.assertEqual(store.verify()["issues"][0]["code"], "catalog_digest_mismatch")
            self.assertCode("catalog_digest_mismatch", store.put_object, "note", {"text": "New"})
            self.assertEqual(store.revision, 1)


if __name__ == "__main__":
    unittest.main()
