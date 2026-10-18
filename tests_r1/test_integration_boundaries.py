"""Limites inter mandata, acquisitiones et locos compositos probantur."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from probentium import exchange, parser_artifact
from probentium.contracts import ProbentiumError, object_digest
from probentium.regulatory import prepare_filing
from probentium.store import CaseStore, _dump, _load


class IntegrationBoundaryTests(unittest.TestCase):
    def test_composite_event_reference_survives_recipient_projection_without_source_disclosure(self):
        from tests_r1.test_locators import LocatorTests
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case, lines, event, _ = LocatorTests().fixture(root)
            with case:
                self.assertTrue(case.verify()["ok"])
                self.assertEqual([part["bytes"] for part in case.raw_records(event["id"])], [lines[0], lines[2]])
                self.assertEqual([part["primary"] for part in case.raw_records(event["id"])], [False, True])
                track = {"id": "synthetic-incident", "profile": "gdpr-controller",
                         "anchors": {"awareness": "2026-10-18T10:00:00Z"}}
                fields = [{"id": "selected", "value": "Synthetic scoped assertion", "basis": "source_backed", "refs": [event["id"]]}]
                filing = case.put_object("filing", prepare_filing(track, fields, case.revision, "2026-10-18T12:00:00Z"))
                target = root / "recipient.pbp"
                result = exchange.export_case(case, target, "recipient_dossier", object_ids=[filing["id"]],
                                              field_allowlist={filing["id"]: ["selected"]}, purpose="Synthetic scoped handoff")
                self.assertEqual(result["profile"], "recipient_dossier")
                self.assertTrue(case.verify()["ok"])
            packet = target.read_bytes()
            for original_line in lines:
                self.assertNotIn(original_line, packet)
            report = exchange.verify_packet(target)
            self.assertTrue(report["ok"], report)
            self.assertEqual(exchange.verify_packet(target, scope="replay")["exit_code"], 3)
            self.assertIn(event["id"].encode(), packet)
            self.assertIn(b"excluded_by_projection", packet)

    def test_cli_restore_requires_requested_signature_before_creating_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "synthetic.jsonl"
            source.write_bytes(b'{"kind":"generic","timestamp":null}\n')
            packet = root / "unsigned.pbp"
            with CaseStore.create(root / "source-case") as case:
                case.ingest(source, "events", "Synthetic unsigned fixture")
                exchange.export_case(case, packet)
            self.assertEqual(exchange.verify_packet(packet, require_signature=True)["exit_code"], 3)
            destination = root / "signature-required"
            args = [sys.executable, "-m", "probentium", "--format", "json", "packet", "restore",
                    "--input", str(packet), "--output", str(destination), "--require-signature"]
            result = subprocess.run(args, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertEqual(result.stdout, b"")
            report = json.loads(result.stderr)
            self.assertEqual(report["errors"], [{"code": "signature_required", "exit_code": 3}])
            self.assertFalse(destination.exists())
            self.assertNotIn(b"Traceback", result.stderr)
            # Sine hoc requisito forma antiqua adhuc restitui potest.
            args[-2:] = [str(root / "unsigned-allowed")]
            result = subprocess.run(args, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            with CaseStore(root / "unsigned-allowed") as restored:
                self.assertTrue(restored.verify()["ok"])

    def test_parser_approval_acquisition_chronology_and_shape_are_checked_locally_and_in_packet(self):
        from tests_r1.test_parser_artifact import ParserArtifactTests
        fixture = ParserArtifactTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        manifest = fixture.manifest()
        with CaseStore.create(fixture.root / "case") as case:
            case.put_object("note", {"synthetic": True})
            approval = case.put_object("parser_approval", {
                "schema": parser_artifact.APPROVAL_SCHEMA, "manifest": manifest,
                "manifest_digest": object_digest(manifest, parser_artifact.DOMAIN),
                "approved_by": "Synthetic operator", "reason": "Synthetic structural fixture",
                "statement": "operator_approved_for_explicit_selection"})
            source = fixture.root / "synthetic.jsonl"
            source.write_bytes(b'{"kind":"generic","timestamp":null}\n')
            # Manifestum fictum ad nexus probandos, non ad distributionem certificandam.
            with patch.object(parser_artifact, "resolve_approval", return_value=manifest):
                case.ingest(source, "events", "Synthetic parser approval", parser_approval_id=approval["id"])
            self.assertTrue(case.verify()["ok"])
            snapshot = case.export_snapshot()
            exchange._snapshot(snapshot)
            row = case.db.execute("SELECT id,data,digest FROM acquisitions").fetchone()
            original = _load(row[1], row[2])
            self.assertLess(approval["revision"], original["acquired_revision"])
            variants = {
                "before_approval": {**original, "acquired_revision": approval["revision"] - 1},
                "at_approval": {**original, "acquired_revision": approval["revision"]},
                "orphan_parse_run": {key: value for key, value in original.items() if key != "parser_approval_ref"},
                "unknown_field": {**original, "undeclared_approval": True},
            }
            for name, altered in variants.items():
                with self.subTest(name=name):
                    with case._write():
                        case.db.execute("UPDATE acquisitions SET data=?,digest=? WHERE id=?", (*_dump(altered), row[0]))
                    local = case.verify()
                    self.assertFalse(local["ok"], local)
                    self.assertEqual(local["exit_code"], 4)
                    candidate = copy.deepcopy(snapshot)
                    candidate["acquisitions"][0] = altered
                    with self.assertRaises(ProbentiumError) as rejected:
                        exchange._snapshot(candidate)
                    self.assertEqual(rejected.exception.exit_code, 4)
            with case._write():
                case.db.execute("UPDATE acquisitions SET data=?,digest=? WHERE id=?", (*_dump(original), row[0]))
            self.assertTrue(case.verify()["ok"])


if __name__ == "__main__":
    unittest.main()
