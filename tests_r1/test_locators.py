"""Loci compositi nec ordinem nec absentiam occultant."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from probentium import exchange, maintenance, store as storage
from probentium.contracts import ProbentiumError, strict_json
from probentium.locators import event_records
from probentium.store import CaseStore, _load


class LocatorTests(unittest.TestCase):
    def fixture(self, root):
        source = root / "source.jsonl"
        lines = [json.dumps({"kind": "generic", "timestamp": None, "actor": actor}).encode() + b"\n"
                 for actor in ("first", "middle", "last")]
        source.write_bytes(b"".join(lines))
        case = CaseStore.create(root / "case", "Synthetic composite")
        result = case.ingest(source, "events", "Synthetic")
        rows = sorted(case.query_events()["rows"], key=lambda item: item["ordinal"])
        run = _load(*case.db.execute("SELECT data,digest FROM parse_runs").fetchone())
        refs = [case._record(rows[index]["primary_record_ref"]) for index in (0, 2)]
        with case._write():
            case.db.execute("DELETE FROM events WHERE id IN (?,?)", (rows[0]["id"], rows[2]["id"]))
            first = case._append_event(run, refs, rows[0]["normalized_output"], 0, refs[1]["id"])
            second = case._append_event(run, refs, rows[2]["normalized_output"], 1, refs[1]["id"])
            run["events_total"] = 3
            case._save_run({"id": result["id"], "size": result["size"]}, run)
        return case, lines, first, second

    def test_nonadjacent_ranges_and_multiple_outputs_survive_transport_and_restore(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            case, lines, first, second = self.fixture(root)
            with case:
                self.assertTrue(case.verify()["ok"], case.verify())
                segments = case.raw_records(first["id"])
                self.assertEqual([part["bytes"] for part in segments], [lines[0], lines[2]])
                self.assertEqual([part["primary"] for part in segments], [False, True])
                self.assertNotEqual(first["id"], second["id"])
                with self.assertRaisesRegex(ProbentiumError, "composite_raw_requires_segments"):
                    case.raw(first["id"])
                packet = root / "composite.pbp"
                exchange.export_case(case, packet)
            check = exchange.verify_packet(packet)
            self.assertTrue(check["ok"], check)
            replay = exchange.verify_packet(packet, scope="replay", replay=maintenance.replay_packet)
            self.assertEqual(replay["normalization_replay"], "unsupported", replay)
            maintenance.restore_packet(packet, root / "restored")
            with CaseStore(root / "restored") as restored:
                self.assertTrue(restored.verify()["ok"])
                self.assertEqual(restored.raw_records(first["id"]), segments)

    def test_missing_record_coverage_and_duplicate_output_index_fail_integrity(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate), tempfile.TemporaryDirectory() as folder:
                case, _, first, second = self.fixture(Path(folder))
                with case:
                    with case._write():
                        if duplicate:
                            run = _load(*case.db.execute("SELECT data,digest FROM parse_runs").fetchone())
                            records = [case._record(ref) for ref in first["record_refs"]]
                            output = copy.deepcopy(first["normalized_output"])
                            output["actor"] = "different interpretation"
                            case._append_event(run, records, output, first["output_index"], first["primary_record_ref"])
                            run["events_total"] += 1
                        else:
                            case.db.execute("DELETE FROM events WHERE id NOT IN (?,?)", (first["id"], second["id"]))
                            run = _load(*case.db.execute("SELECT data,digest FROM parse_runs").fetchone())
                            run["events_total"] = 2
                        size = case.db.execute("SELECT size FROM artifacts").fetchone()[0]
                        case._save_run({"id": run["artifact_id"], "size": size}, run)
                    check = case.verify()
                    self.assertFalse(check["ok"])
                    self.assertEqual(check["issues"][0]["code"], "duplicate_normalized_observation" if duplicate else "parse_accounting_invalid")

    def test_locator_constraints_are_checked_before_raw_allocation(self):
        with tempfile.TemporaryDirectory() as folder:
            case, _, event, _ = self.fixture(Path(folder))
            with case:
                records = {ref: case._record(ref) for ref in event["record_refs"]}
                for mutate in (lambda e: e.update(record_refs=list(reversed(e["record_refs"]))),
                               lambda e: e.update(record_refs=e["record_refs"] * 2),
                               lambda e: e.update(primary_record_ref="f" * 64),
                               lambda e: e.update(output_index=True),
                               lambda e: e.update(output_index=-1),
                               lambda e: e.update(record_refs=e["record_refs"] * 17)):
                    altered = copy.deepcopy(event)
                    mutate(altered)
                    with self.assertRaises(ProbentiumError):
                        event_records(altered, records.get)
                overlapping = copy.deepcopy(records)
                overlapping[event["record_refs"][1]]["offset"] = 1
                with self.assertRaisesRegex(ProbentiumError, "event_record_order_invalid"):
                    event_records(event, overlapping.get)
                oversized = copy.deepcopy(records)
                oversized[event["record_refs"][0]]["length"] = 8 * 1024 ** 2 + 1
                with self.assertRaisesRegex(ProbentiumError, "event_record_byte_limit"):
                    event_records(event, oversized.get)
                foreign = copy.deepcopy(records)
                foreign[event["record_refs"][0]]["artifact_id"] = "f" * 64
                with self.assertRaisesRegex(ProbentiumError, "event_record_mismatch"):
                    event_records(event, foreign.get)

    def test_old_single_output_layout_remains_readable(self):
        old = storage._SCHEMA.replace("search TEXT NOT NULL, data BLOB NOT NULL, digest TEXT NOT NULL);",
                                      "search TEXT NOT NULL, data BLOB NOT NULL, digest TEXT NOT NULL, UNIQUE(parse_run_id,ordinal));")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.object(storage, "_SCHEMA", old), CaseStore.create(root / "case"):
                pass
            with CaseStore(root / "case") as case:
                self.assertTrue(case._single_output_layout)
                self.assertTrue(case.verify()["ok"])


class JsonPreflightTests(unittest.TestCase):
    def test_escaped_quotes_backslash_parity_and_brackets_do_not_change_depth(self):
        for count in range(20):
            value = {"payload": "\\" * count + '\"' + "[{}]" * 100 + "\\" * count}
            self.assertEqual(strict_json(json.dumps(value).encode()), value)
            for depth in (30, 31):
                nested = value
                for _ in range(depth):
                    nested = [nested]
                self.assertEqual(strict_json(json.dumps(nested).encode()), nested)
            nested = value
            for _ in range(33):
                nested = [nested]
            with self.assertRaisesRegex(ProbentiumError, "json_depth_limit"):
                strict_json(json.dumps(nested).encode())

    def test_invalid_quotes_and_deep_suffix_never_bypass_json_validation(self):
        for raw in (b'{"a":"\\"}', b'{"a":"x\\\\" "b":2}', b'{"a":"ok"}' + b'[' * 40,
                    b'{"a":1,"a":2}', b'{"a":1e3}'):
            with self.subTest(raw=raw), self.assertRaises(ProbentiumError):
                strict_json(raw)
