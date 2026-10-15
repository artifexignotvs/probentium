"""Conspectus fidelis et occultatio materiarum probantur."""

import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

from testifex.analysis import analyze
from testifex.case import Case
from testifex.cli import main
from testifex.demo import run_demo
from testifex.model import canonical
from testifex.report import make_report
from testifex.triage import render_text, summarize_report
from test_analysis import event, sequence, source
from test_report import report


class TriageReportTests(unittest.TestCase):
    def test_counts_and_threshold_qualification_are_preserved(self):
        value = summarize_report(report())
        self.assertEqual(value["schema"], "testifex.triage.v1")
        self.assertEqual(value["records"], {"read": 10, "parsed": 10, "ignored": 0, "errors": 0})
        self.assertEqual(value["findings"]["total"], 2)
        self.assertEqual(value["findings"]["certain"], 2)
        auth = next(item for item in value["findings"]["items"] if item["rule_id"] == "auth_after_failures")
        self.assertEqual(auth["failures"], {"failure_count": 8, "certain_failure_count": 8, "threshold_status": "certain"})
        self.assertEqual(auth["evidence_records"], 9)
        self.assertEqual(value["coverage"]["collection_completeness"], "unknown")

    def test_possible_ordering_is_not_promoted_to_certain(self):
        events = [event(1, low=0, high=999999), event(2, "auth.success", low=500000, high=1499999)]
        value = summarize_report(report(events, threshold=1))
        self.assertEqual(value["findings"]["certain"], 0)
        self.assertEqual(value["findings"]["possible"], 1)
        self.assertEqual(value["findings"]["items"][0]["failures"]["threshold_status"], "possible")
        self.assertEqual(value["ordering_qualifications"]["reasons"]["overlapping_time_intervals"], 1)
        self.assertIn("not confidence in an incident", render_text(report(events, threshold=1)))

    def test_display_truncation_preserves_totals_and_deterministic_order(self):
        events = sequence() + [event(i, "process.exec") for i in range(11, 17)]
        original = report(events)
        summary = summarize_report(original, limit=2)
        self.assertEqual(summary["findings"]["total"], 8)
        self.assertEqual(summary["findings"]["shown"], 2)
        self.assertEqual(summary["findings"]["omitted"], 6)
        self.assertEqual([item["id"] for item in summary["findings"]["items"]],
                         [item["id"] for item in original["analysis"]["findings"][:2]])
        output = render_text(original, limit=2)
        self.assertIn("Display truncated", output)
        self.assertIn("Showing 2 of 8 findings; omitted 6.", output)
        self.assertLessEqual(len(output.splitlines()), 22 + 3 * 2)

    def test_summary_is_stable_and_does_not_mutate_report(self):
        original = report()
        saved = copy.deepcopy(original)
        self.assertEqual(canonical(summarize_report(original)), canonical(summarize_report(copy.deepcopy(original))))
        self.assertEqual(render_text(original), render_text(copy.deepcopy(original)))
        self.assertEqual(original, saved)

    def test_private_and_terminal_active_free_text_is_withheld(self):
        marker = "PRIVATE_FIXTURE_VALUE\x1b[31m\u202e\nsecond-line"
        events = sequence()
        for item in events:
            item.update(host=marker, actor=marker, path=marker, action=marker,
                        time_raw=marker, attributes={"message": marker})
        sources = [source(events, label=marker)]
        hypotheses = [{"id": "hypothesis-one", "title": marker, "status": "open", "assumptions": [marker],
                       "evidence": [{"event_id": events[0]["id"], "stance": "context", "note": marker}]}]
        original = make_report({"schema_version": 1, "tool_version": "0.1.0a1", "case_id": "case-one", "name": marker},
                               sources, events, analyze(events, sources), hypotheses)
        for output in (render_text(original), canonical(summarize_report(original))):
            for forbidden in ("PRIVATE_FIXTURE_VALUE", "second-line", "\x1b", "\u202e", "192.0.2.10", "source-1", "case-one", "hypothesis-one"):
                self.assertNotIn(forbidden, output)
        self.assertTrue(render_text(original).isascii())

    def test_empty_case_has_no_false_clean_verdict(self):
        original = report([], [])
        summary = summarize_report(original)
        self.assertEqual(summary["events"]["total"], 0)
        self.assertEqual(summary["findings"]["total"], 0)
        output = render_text(original)
        self.assertIn("No findings is not a clean-state verdict", output)
        self.assertIn("Collection completeness: unknown", output)

    def test_event_subset_and_declared_span_are_explicit(self):
        events = sequence()
        item = source(events)
        item["options"].update(declared_start_us=20_000_000, declared_end_us=30_000_000)
        value = summarize_report(report(events[:-1], [item]))
        self.assertEqual(value["coverage"]["event_subset_sources"], 1)
        self.assertEqual(value["coverage"]["declared_span_sources"], 1)
        self.assertEqual(value["coverage"]["outside_declared_span_sources"], 1)
        self.assertEqual(value["records"]["parsed"], 10)
        self.assertEqual(value["events"]["total"], 9)

    def test_forged_clean_report_is_rejected_before_rendering(self):
        original = report()
        original["analysis"]["findings"] = []
        with self.assertRaisesRegex(ValueError, "analysis_does_not_match_evidence"):
            render_text(original)

    def test_limit_is_strict_and_checked_before_report(self):
        for limit in (0, -1, 101, True, 1.0, "1", None):
            with self.subTest(limit=limit), self.assertRaisesRegex(ValueError, "triage_limit"):
                summarize_report(None, limit=limit)
        self.assertEqual(summarize_report(report(), limit=100)["findings"]["limit"], 100)


class TriageCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def invoke(self, *args):
        output, diagnostic = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(diagnostic):
            status = main(list(map(str, args)))
        return status, output.getvalue(), diagnostic.getvalue()

    def test_verified_demo_preserves_clock_uncertainty_change(self):
        run_demo(self.root / "demo")
        results = {}
        for name in ("auth-case", "uncertain-case"):
            status, output, diagnostic = self.invoke("triage", "--case", self.root / "demo" / name, "--format", "json")
            self.assertEqual((status, diagnostic), (0, ""))
            results[name] = json.loads(output)
        self.assertEqual(results["auth-case"]["findings"]["certain"], 2)
        self.assertEqual(results["uncertain-case"]["findings"]["certain"], 1)
        self.assertEqual(results["uncertain-case"]["findings"]["possible"], 1)
        self.assertEqual(results["uncertain-case"]["events"]["total"], 10)

    def test_partial_error_and_unknown_time_counts_are_visible(self):
        auth = self.root / "auth.log"
        auth.write_bytes(b"Jan  1 00:00:00 edge-demo sshd[1234]: Failed password for operator from 192.0.2.30 port 22 ssh2\ninvalid-private-data\n")
        events = self.root / "events.jsonl"
        events.write_bytes(b'{"timestamp":"2026-01-01T00:00:00Z","kind":"generic"}\n' * 2)
        with Case.create(self.root / "case") as case:
            case.ingest(auth, "auth", "private-auth")
            case.ingest(events, "events", "private-events", max_records=1)
        status, output, diagnostic = self.invoke("triage", "--case", self.root / "case", "--format", "json")
        self.assertEqual((status, diagnostic), (0, ""))
        summary = json.loads(output)
        self.assertEqual(summary["sources"]["statuses"], {"complete": 0, "incomplete": 1, "interrupted": 1, "pending": 0})
        self.assertEqual(summary["records"], {"read": 3, "parsed": 2, "ignored": 0, "errors": 1})
        self.assertEqual(summary["events"]["unknown_time"], 1)
        self.assertEqual(summary["coverage"]["unfinished_sources"], 1)
        self.assertEqual(summary["coverage"]["sources_with_errors"], 1)
        self.assertNotIn("invalid-private-data", output)
        self.assertNotIn("private-auth", output)

    def test_changed_evidence_fails_without_partial_overview(self):
        run_demo(self.root / "demo")
        case = self.root / "demo/auth-case"
        next((case / "evidence").glob("*.bin")).write_bytes(b"changed")
        status, output, diagnostic = self.invoke("triage", "--case", case)
        self.assertEqual(status, 2)
        self.assertEqual(output, "")
        self.assertIn("case_verification_failed", diagnostic)

    def test_text_output_is_stable_bounded_and_never_overwrites(self):
        run_demo(self.root / "demo")
        args = ("triage", "--case", self.root / "demo/auth-case", "--limit", "1")
        first = self.invoke(*args)
        self.assertEqual(first, self.invoke(*args))
        self.assertEqual(first[0], 0)
        self.assertIn("Showing 1 of 2 findings; omitted 1.", first[1])
        self.assertLessEqual(len(first[1].splitlines()), 25)
        for private in ("edge-demo", "operator", "192.0.2.30", "/usr/bin/id"):
            self.assertNotIn(private, first[1])
        target = self.root / "overview.txt"
        self.assertEqual(self.invoke(*args, "--output", target)[0], 0)
        self.assertEqual(target.read_text(), first[1])
        self.assertEqual(self.invoke(*args, "--output", target)[0], 2)
        self.assertEqual(target.read_text(), first[1])

    def test_configuration_is_applied_and_invalid_limits_fail_closed(self):
        run_demo(self.root / "demo")
        case = self.root / "demo/auth-case"
        status, output, _ = self.invoke("triage", "--case", case, "--threshold", "9", "--format", "json")
        self.assertEqual(status, 0)
        summary = json.loads(output)
        self.assertEqual(summary["config"]["threshold"], 9)
        self.assertEqual(summary["findings"]["total"], 1)
        for arguments in (("--limit", "0"), ("--limit", "101"), ("--max-events", "9")):
            status, output, diagnostic = self.invoke("triage", "--case", case, *arguments)
            self.assertEqual((status, output), (2, ""))
            self.assertIn("error:", diagnostic)


if __name__ == "__main__":
    unittest.main()
