"""Relatio stricta et publicatio parcissima probantur."""

import copy
import hashlib
import json
import unittest

from testifex.analysis import analyze
from testifex.report import compare_reports, make_report, render_markdown, share_report, validate_report
from test_analysis import event, sequence, source


def report(events=None, sources=None, **config):
    events = sequence() if events is None else events
    sources = [source(events)] if sources is None else sources
    return make_report({"schema_version": 1, "tool_version": "0.1.0a1", "case_id": "case-one", "name": "Fixture case"}, sources, events, analyze(events, sources, **config), [])


class ReportTests(unittest.TestCase):
    def test_report_is_deterministic_and_retains_verifiable_references(self):
        first = report(); second = report(list(reversed(sequence())))
        self.assertEqual(first, second)
        self.assertEqual(validate_report(first), first)
        self.assertEqual(first["sources"][0]["source_metadata"]["copied_sha256"], "a"*64)
        self.assertEqual(first["events"][0]["raw_sha256"], hashlib.sha256(b"1").hexdigest())

    def test_default_report_omits_acquisition_paths_and_stat_metadata(self):
        events = sequence(); s = source(events, label="/evidence/private/auth.log")
        s["source_metadata"].update(original_name="private-name.log", original_path="/evidence/private/auth.log", stat={"mtime_ns": 123})
        value = report(events, [s]); serialized = json.dumps(value)
        self.assertEqual(value["sources"][0]["label"], "auth.log")
        for forbidden in ("/evidence/private", "private-name.log", "mtime_ns", "original_path"):
            self.assertNotIn(forbidden, serialized)

    def test_changed_evidence_changes_existing_finding_with_stable_anchor(self):
        before = report(); events = sequence()
        events.append(event(11, low=8_500_000))
        after = report(events)
        delta = compare_reports(before, after)
        self.assertEqual(delta["status"], "different")
        self.assertEqual(len(delta["findings"]["changed"]), 1)
        self.assertEqual(delta["findings"]["changed"][0]["before"]["details"]["failure_count"], 8)
        self.assertEqual(delta["findings"]["changed"][0]["after"]["details"]["failure_count"], 9)
        self.assertIn("event_evidence_changed", delta["reasons"])

    def test_configuration_change_explains_removed_finding(self):
        delta = compare_reports(report(), report(threshold=9))
        self.assertEqual(len(delta["findings"]["removed"]), 1)
        self.assertIn("analysis_configuration_changed", delta["reasons"])
        self.assertEqual(delta["config_changes"][0]["field"], "threshold")
        self.assertTrue(any("resolution" in x for x in delta["limitations"]))

    def test_parser_changes_are_detected_even_when_source_identity_changes(self):
        before = report(); events = sequence(); s = source(events, id="source-new", parser_version="2")
        for item in events:
            item["source_id"] = "source-new"
        delta = compare_reports(before, report(events, [s]))
        self.assertEqual(delta["parser_changes"][0]["fields"], ["parser_version"])
        self.assertIn("parser_or_source_options_changed", delta["reasons"])
        self.assertEqual(len(delta["sources"]["added"]), 1)

    def test_clock_and_declared_span_options_are_compared(self):
        before = report(); events = sequence(); s = source(events)
        s["options"].update(declared_start_us=0, declared_end_us=30_000_000)
        delta = compare_reports(before, report(events, [s]))
        self.assertEqual(delta["parser_changes"][0]["fields"], ["options"])

    def test_identical_report_is_not_claimed_authentic_or_complete(self):
        value = report(); delta = compare_reports(value, copy.deepcopy(value))
        self.assertEqual(delta["status"], "same")
        self.assertFalse(delta["reasons"])
        self.assertEqual(delta["before_report_sha256"], delta["after_report_sha256"])
        self.assertTrue(any("not completeness" in x for x in delta["limitations"]))

    def test_forged_clean_analysis_is_rejected(self):
        value = report(); value["analysis"]["findings"] = []
        with self.assertRaisesRegex(ValueError, "analysis_does_not_match_evidence"):
            compare_reports(report(), value)

    def test_unknown_fields_in_any_private_structure_are_rejected(self):
        for location in ((), ("case",), ("sources", 0), ("events", 0), ("analysis",)):
            value = report(); cursor = value
            for part in location:
                cursor = cursor[part]
            cursor["unexpected"] = "extra"
            with self.subTest(location=location), self.assertRaises(ValueError):
                validate_report(value)

    def test_malformed_recursive_and_oversize_reports_fail_without_trace_content(self):
        value = report(); value["unexpected"] = value
        with self.assertRaises(ValueError):
            validate_report(value)
        value = report(); value["case"]["name"] = "x" * 4097
        with self.assertRaises(ValueError):
            validate_report(value)
        value = report(); value["analysis"]["coverage"]["event_count"] = True
        with self.assertRaises(ValueError):
            validate_report(value)

    def test_public_export_contains_no_freeform_or_original_identifiers(self):
        events = sequence(); marker = "PRIVATE_FIXTURE_VALUE"
        for item in events:
            item.update(host=marker, actor=marker, src_ip="203.0.113.77", dst_ip="203.0.113.77", path="/private/"+marker, action=marker, time_raw=marker, time_basis=marker, attributes={"message": marker})
        s = source(events, label=marker, parser_version=marker)
        s["options"]["correction_reason"] = marker
        s["source_metadata"]["original_name"] = marker
        hypotheses = [{"id": "hypothesis-one", "title": marker, "status": "open", "assumptions": [marker], "evidence": [{"event_id": events[0]["id"], "stance": "context", "note": marker}]}]
        value = make_report({"schema_version": 1, "tool_version": marker, "case_id": "case-original", "name": marker}, [s], events, analyze(events, [s]), hypotheses)
        shared = share_report(value, b"k"*32); serialized = json.dumps(shared)
        for original in (marker, "203.0.113.77", "case-original", "source-1", "event-1", "hypothesis-one", "a"*64, events[0]["raw_sha256"]):
            self.assertNotIn(original, serialized)
        self.assertEqual(shared["events"][0]["src_ip"], shared["events"][0]["dst_ip"])
        self.assertNotEqual(shared["events"][0]["host"], shared["events"][0]["actor"])
        self.assertEqual(shared["events"][0]["source_id"], shared["sources"][0]["id"])
        self.assertEqual(shared["findings"][0]["evidence"][0]["event_id"], shared["events"][0]["id"])
        self.assertEqual(shared["hypotheses"][0]["evidence"][0]["event_id"], shared["events"][0]["id"])
        self.assertIn("not anonymous", " ".join(shared["limitations"]))
        self.assertEqual(shared["withheld"]["hypothesis_assumptions"], 1)

    def test_hmac_is_stable_for_same_key_domain_separated_and_changes_with_key(self):
        value = report(); first = share_report(value, b"x"*32)
        self.assertEqual(first, share_report(copy.deepcopy(value), b"x"*32))
        second = share_report(value, b"y"*32)
        self.assertNotEqual(first["case_id"], second["case_id"])
        self.assertNotEqual(first["sources"][0]["digest_id"], second["sources"][0]["digest_id"])
        for key in (b"", b"x"*31, b"x"*33, "x"*32, bytearray(b"x"*32)):
            with self.subTest(size=len(key)), self.assertRaises(ValueError):
                share_report(value, key)

    def test_public_export_does_not_accept_malicious_freeform_analysis(self):
        value = report(); value["analysis"]["findings"][0]["details"]["message"] = "PRIVATE_FIXTURE_VALUE"
        with self.assertRaises(ValueError):
            share_report(value, b"k"*32)

    def test_markdown_escapes_html_links_control_and_bidi(self):
        events = sequence()
        attack = '<script>alert(1)</script> [link](javascript:alert(1)) |\x1b[31m\u202e'
        for item in events:
            item["host"] = attack
        value = report(events); value["case"]["name"] = attack
        output = render_markdown(value)
        for raw in ("<script>", "</script>", "[link](", "\x1b", "\u202e"):
            self.assertNotIn(raw, output)
        self.assertIn("&#60;script&#62;", output)
        self.assertIn("a"*64, output)

    def test_empty_report_has_no_false_clean_verdict(self):
        output = render_markdown(report([], []))
        self.assertIn("not a clean-state verdict", output)
        self.assertIn("completeness: unknown", output)

    def test_public_markdown_preserves_warning_and_withheld_summary(self):
        output = render_markdown(share_report(report(), b"z"*32))
        self.assertIn("Pseudonymized, not anonymous", output)
        self.assertIn("Withheld fields", output)
        self.assertNotIn("host-a", output)
        self.assertNotIn("192.0.2.10", output)

    def test_public_render_rejects_missing_nested_fields_and_forged_clean_findings(self):
        shared = share_report(report(), b"z"*32)
        mutations = [lambda x: x["sources"][0].pop("status"),
                     lambda x: x["events"][0].update(source_id="source_" + "0"*64),
                     lambda x: x.update(findings=[]),
                     lambda x: x["findings"][0]["details"].update(failure_count=900),
                     lambda x: x["coverage"].update(event_count=True),
                     lambda x: x["sources"][0].update(status=[]),
                     lambda x: x["events"][0].update(kind={}),
                     lambda x: x["withheld"].update(case_names=2)]
        for mutate in mutations:
            value = copy.deepcopy(shared); mutate(value)
            with self.subTest(mutation=mutations.index(mutate)), self.assertRaises(ValueError):
                render_markdown(value)

    def test_public_render_handles_equal_time_order_and_multiple_sources(self):
        events = [event(i, low=0, high=999999) for i in range(1, 8)] + [event(8, "auth.success", low=2_000_000)]
        s1 = source(events); s2 = source([], id="source-2", sha256="b"*64, source_metadata={"copied_sha256": "b"*64})
        shared = share_report(report(events, [s2, s1]), b"z"*32)
        self.assertIn("auth_after_failures", render_markdown(shared))

    def test_public_render_retains_unknown_and_blank_identifier_semantics(self):
        events = [event(1, host="  "), event(2, "auth.success", src_ip=""), event(3, "process.exec", src_ip=None)]
        shared = share_report(report(events), b"z"*32)
        self.assertIsNone(shared["events"][0]["host"])
        self.assertIsNone(shared["events"][1]["src_ip"])
        self.assertIn("post_auth_process", render_markdown(shared))

    def test_public_hypothesis_reference_and_free_text_are_rejected(self):
        events = sequence(); sources = [source(events)]
        h = [{"id": "h1", "title": "Review", "status": "open", "assumptions": [], "evidence": [{"event_id": "event-1", "stance": "supports", "note": ""}]}]
        value = make_report({"schema_version": 1, "tool_version": "0.1", "case_id": "case-one", "name": ""}, sources, events, analyze(events, sources), h)
        shared = share_report(value, b"z"*32)
        self.assertIn("Analyst hypotheses", render_markdown(shared))
        shared["hypotheses"][0]["evidence"][0]["note"] = "private"
        with self.assertRaises(ValueError):
            render_markdown(shared)

    def test_invalid_hypothesis_links_are_rejected(self):
        events = sequence(); sources = [source(events)]
        h = [{"id": "h1", "title": "Review", "status": "open", "assumptions": [], "evidence": [{"event_id": "absent", "stance": "supports", "note": ""}]}]
        with self.assertRaisesRegex(ValueError, "invalid_hypothesis_reference"):
            make_report({"schema_version": 1, "tool_version": "0.1", "case_id": "case-one", "name": ""}, sources, events, analyze(events, sources), h)


if __name__ == "__main__":
    unittest.main()
