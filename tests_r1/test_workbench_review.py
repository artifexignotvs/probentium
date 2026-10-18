"""Errores obscuri et conclusiones sine fundamento deteguntur."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from probentium.contracts import ProbentiumError, canonical_bytes, strict_json, timestamp


class ContractReviewTests(unittest.TestCase):
    def test_invalid_offset_minutes_are_not_normalized(self):
        for offset in ("+00:60", "+00:99", "-05:75"):
            with self.subTest(offset=offset):
                with self.assertRaises(ProbentiumError):
                    timestamp("2026-10-18T12:00:00" + offset)

    def test_utc_overflow_uses_a_stable_domain_error(self):
        for value in ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"):
            with self.subTest(value=value):
                with self.assertRaises(ProbentiumError):
                    timestamp(value)

    def test_oversize_integer_has_no_raw_parser_exception(self):
        with self.assertRaises(ProbentiumError):
            strict_json(b"1" * 5000)

    def test_unencodable_text_has_no_raw_encoding_exception(self):
        with self.assertRaises(ProbentiumError):
            strict_json("\ud800")

    def test_non_utf8_json_is_rejected(self):
        for encoding in ("utf-16", "utf-32"):
            with self.subTest(encoding=encoding):
                with self.assertRaises(ProbentiumError):
                    strict_json('{"ok":true}'.encode(encoding))


class WorkbenchReviewTests(unittest.TestCase):
    def setUp(self):
        from probentium.demo import make_demo
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.result = make_demo(self.directory / "exercise")
        self.case_path = self.result["case"]

    def test_demo_mfa_references_describe_tests_not_ordinary_logins(self):
        from probentium.store import CaseStore
        with CaseStore(self.case_path) as case:
            controls = case.objects("control")
            control = next(item["data"] for item in controls if item["data"]["kind"] == "mfa")
            refs = [ref for row in control["observations"] for ref in row["evidence_refs"]]
            self.assertEqual(len(refs), 2)
            self.assertEqual(len(set(refs)), 2)
            for ref in refs:
                raw = strict_json(case.raw(ref))
                self.assertEqual(raw["kind"], "generic")
                self.assertEqual(raw["action"], "mfa-exercise")
            sources = case.sources()
            self.assertTrue(all(source["interpretation_complete"] for source in sources))

    def test_extra_source_cannot_keep_unqualified_synthetic_case_label(self):
        from probentium.store import CaseStore
        from probentium.workbench import Workbench
        before = Workbench(self.case_path).refresh()
        self.assertTrue(before["synthetic"])
        path = self.directory / "additional.jsonl"
        path.write_bytes(canonical_bytes({"timestamp": "2026-10-18T15:00:00Z", "kind": "generic", "action": "unclassified-import"}) + b"\n")
        with CaseStore(self.case_path) as case:
            case.ingest(path, "events", "Additional source without synthetic declaration")
        after = Workbench(self.case_path).refresh()
        self.assertFalse(after["synthetic"])

    def test_malformed_controls_use_domain_errors(self):
        from probentium.store import CaseStore
        from probentium.workbench import assess_control
        values = [[], None, {"kind": "mfa", "observations": [None]}, {"kind": "mfa", "observations": "invalid"}]
        with CaseStore(self.case_path) as case:
            for value in values:
                with self.subTest(value=value):
                    with self.assertRaises(ProbentiumError):
                        assess_control(case, value)

    def test_malformed_references_use_domain_errors(self):
        from probentium.store import CaseStore
        from probentium.workbench import validate_refs
        with CaseStore(self.case_path) as case:
            for fields in (None, [None], [{"refs": [{}]}], [{"refs": "not-a-list"}]):
                with self.subTest(fields=fields):
                    with self.assertRaises(ProbentiumError):
                        validate_refs(case, fields)

    def test_prepare_never_copies_a_different_tracks_fields(self):
        from probentium.store import CaseStore
        from probentium.workbench import Workbench
        with CaseStore(self.case_path) as case:
            track = dict(case.objects("track")[-1]["data"])
            track.update(id="I-008", title="Separate synthetic incident")
            case.put_object("track", track)
            count = len(case.objects("filing"))
        workbench = Workbench(self.case_path)
        workbench.refresh()
        workbench.command("track I-008")
        with self.assertRaises(ProbentiumError):
            workbench.command("prepare")
        with CaseStore(self.case_path) as case:
            self.assertEqual(len(case.objects("filing")), count)

    def test_unrelated_filing_does_not_create_a_cross_track_diff(self):
        from probentium.regulatory import prepare_filing
        from probentium.store import CaseStore
        from probentium.workbench import Workbench
        with CaseStore(self.case_path) as case:
            track = dict(case.objects("track")[-1]["data"])
            track.update(id="I-008", title="Separate synthetic incident")
            case.put_object("track", track)
            fields = [{"id": "summary", "value": "Separate exercise", "basis": "human_attested", "refs": [], "reason": "Synthetic declaration"}]
            case.put_object("filing", prepare_filing(track, fields, case.revision, "2026-10-18T12:00:00Z"))
        workbench = Workbench(self.case_path)
        workbench.refresh()
        workbench.command("track I-008")
        model = workbench.refresh()
        self.assertEqual(model["changes"], [])

    def test_unreferenced_declarations_are_not_labelled_tested(self):
        from probentium.store import CaseStore
        from probentium.workbench import Workbench
        with CaseStore(self.case_path) as case:
            case.put_object("control", {"id": "C-04", "kind": "mfa", "population": 3,
                                       "observations": [{"id": "O-04", "subject": "extra path", "configured": True, "enforced": True, "evidence_refs": []}]})
        model = Workbench(self.case_path).refresh()
        control = next(item for item in model["controls"] if item["id"] == "C-04")
        self.assertEqual(control["coverage"]["unknown"], 1)
        self.assertNotIn("tested", control["coverage_summary"].casefold())

    def test_interval_deadline_and_operational_status_survive_view_model(self):
        from probentium.store import CaseStore
        from probentium.workbench import Workbench
        with CaseStore(self.case_path) as case:
            track = dict(case.objects("track")[-1]["data"])
            track["anchors"] = {"awareness": {"status": "interval", "earliest": "2026-10-18T10:00:00Z", "latest": "2026-10-18T11:00:00Z",
                                               "earliest_inclusive": True, "latest_inclusive": False}, "submitted": None}
            case.put_object("track", track)
        with patch("probentium.workbench.utc_now", return_value="2026-10-20T12:00:00Z"):
            model = Workbench(self.case_path).refresh()
        early = next(row for row in model["incident"]["deadline_rows"] if row["stage"] == "early")
        self.assertNotEqual(early["target"], "not supplied")
        self.assertIn("2026-10-19T10:00:00Z", str(early["target"]))
        self.assertIn("2026-10-19T11:00:00Z", str(early["target"]))
        self.assertIn("past_all_possible_operational_targets", early["status"])


if __name__ == "__main__":
    unittest.main()
