"""Casus adversi fines et dubitationes probant."""

import copy
import hashlib
import unittest
from unittest.mock import patch

from testifex.analysis import analyze


def event(number, kind="auth.failure", low=None, high=None, **changes):
    low = number * 1_000_000 if low is None else low
    high = low if high is None else high
    item = {"id": "event-" + str(number), "source_id": "source-1", "ordinal": number,
            "offset": number * 100, "length": 50, "raw_sha256": hashlib.sha256(str(number).encode()).hexdigest(),
            "kind": kind, "time_raw": "2026-01-01T00:00:00Z", "time_low_us": low, "time_high_us": high,
            "time_basis": "utc_microsecond", "host": "host-a", "actor": "operator", "src_ip": "192.0.2.10",
            "dst_ip": None, "path": None, "action": None, "attributes": {},
            "original_low_us": low, "original_high_us": high, "clock_offset_us": 0, "clock_error_us": 0}
    item.update(changes)
    return item


def source(events, **changes):
    timed = [x for x in events if x["time_low_us"] is not None]
    item = {"id": "source-1", "label": "fixture", "sha256": "a" * 64, "size": 10_000_000,
            "format": "events", "parser_version": "1", "status": "complete", "lines_total": len(events),
            "parsed_count": len(events), "ignored_count": 0, "error_count": 0,
            "cursor": 10_000_000, "last_line": len(events),
            "observed_low_us": min((x["time_low_us"] for x in timed), default=None),
            "observed_high_us": max((x["time_high_us"] for x in timed), default=None),
            "options": {"clock_offset_us": 0, "clock_error_us": 0, "correction_reason": "", "declared_start_us": None, "declared_end_us": None},
            "source_metadata": {"acquisition": "copied-regular-file", "copied_sha256": "a" * 64}}
    item.update(changes)
    return item


def sequence():
    return [event(i) for i in range(1, 9)] + [event(9, "auth.success"), event(10, "process.exec", path="/usr/bin/id", action="exec")]


class AnalysisTests(unittest.TestCase):
    def test_certain_failure_success_and_process_leads_have_evidence(self):
        events = sequence()
        report = analyze(events, [source(events)])
        findings = {x["rule_id"]: x for x in report["findings"]}
        self.assertEqual(set(findings), {"auth_after_failures", "post_auth_process"})
        auth = findings["auth_after_failures"]
        self.assertEqual(auth["details"]["failure_count"], 8)
        self.assertEqual(auth["details"]["certain_failure_count"], 8)
        self.assertEqual(auth["details"]["threshold_status"], "certain")
        self.assertEqual(auth["event_ids"], ["event-" + str(i) for i in range(1, 10)])
        self.assertEqual(findings["post_auth_process"]["event_ids"], ["event-9", "event-10"])
        self.assertIn("no causal or session attribution", auth["limitation"])

    def test_input_order_is_irrelevant_and_inputs_unchanged(self):
        events = sequence(); sources = [source(events)]
        saved = copy.deepcopy((events, sources))
        self.assertEqual(analyze(events, sources), analyze(reversed(events), sources))
        self.assertEqual((events, sources), saved)

    def test_overlapping_precision_is_possible_not_certain(self):
        events = [event(1, low=0, high=999999), event(2, "auth.success", low=500000, high=1499999)]
        report = analyze(events, [source(events)], threshold=1)
        finding = report["findings"][0]
        self.assertEqual(finding["ordering"], "possible")
        self.assertEqual(finding["details"]["certain_failure_count"], 0)
        self.assertEqual(finding["details"]["threshold_status"], "possible")
        self.assertEqual(report["ordering_conflicts"][0]["reason"], "overlapping_time_intervals")

    def test_window_membership_may_be_uncertain_despite_order(self):
        events = [event(1, low=0, high=9), event(2, "auth.success", low=10, high=19)]
        report = analyze(events, [source(events)], threshold=1, window_us=10)
        self.assertEqual(report["findings"][0]["ordering"], "possible")
        self.assertEqual(report["ordering_conflicts"][0]["reason"], "uncertain_window_boundary")

    def test_window_boundary_is_inclusive(self):
        events = [event(1, low=0), event(2, "auth.success", low=10)]
        self.assertEqual(analyze(events, [source(events)], threshold=1, window_us=10)["findings"][0]["ordering"], "certain")
        self.assertEqual(analyze(events, [source(events)], threshold=1, window_us=9)["findings"], [])

    def test_later_failure_does_not_explain_earlier_success(self):
        events = [event(1, low=20), event(2, "auth.success", low=10)]
        report = analyze(events, [source(events)], threshold=1)
        self.assertFalse(report["findings"])
        self.assertEqual(report["ordering_conflicts"][0]["reason"], "source_sequence_time_reversal")

    def test_unknown_times_are_preserved_and_excluded_from_links(self):
        events = sequence()
        for x in events:
            x.update(time_low_us=None, time_high_us=None, original_low_us=None, original_high_us=None, time_basis="unknown_no_year")
        report = analyze(events, [source(events)])
        self.assertEqual(report["coverage"]["unknown_time_events"], 10)
        self.assertFalse(report["findings"])
        self.assertTrue(any("unknown time" in x for x in report["limitations"]))

    def test_required_identifiers_prevent_cross_host_actor_or_address_links(self):
        for key in ("host", "actor", "src_ip"):
            with self.subTest(key=key):
                events = [event(1), event(2, "auth.success", **{key: "different"})]
                self.assertFalse(analyze(events, [source(events)], threshold=1)["findings"])

    def test_missing_address_prevents_auth_chain_but_not_host_actor_process_lead(self):
        events = [event(1), event(2, "auth.success", src_ip=None), event(3, "process.exec", src_ip=None)]
        report = analyze(events, [source(events)], threshold=1)
        self.assertEqual([x["rule_id"] for x in report["findings"]], ["post_auth_process"])
        self.assertEqual(report["coverage"]["missing_identifier_events"], 1)

    def test_process_with_two_recent_successes_creates_two_unattributed_leads(self):
        events = [event(1, "auth.success"), event(2, "auth.success"), event(3, "process.exec")]
        findings = analyze(events, [source(events)])["findings"]
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(x["rule_id"] == "post_auth_process" for x in findings))

    def test_declared_span_and_partial_source_never_claim_completeness(self):
        events = [event(1), event(2, "auth.success")]
        s = source(events, status="incomplete", lines_total=3, error_count=1, last_line=3)
        s["options"].update(declared_start_us=0, declared_end_us=100_000_000)
        report = analyze(events, [s], threshold=1)
        coverage = report["coverage"]["sources"][0]
        self.assertEqual(coverage["span_relation"], "within_declared_bounds")
        self.assertEqual(coverage["collection_completeness"], "unknown")
        self.assertEqual(coverage["declaration"], "analyst_assertion")
        self.assertTrue(any("parsing errors" in x for x in report["limitations"]))
        self.assertTrue(any("assertions" in x for x in report["limitations"]))

    def test_subset_count_is_visible(self):
        events = sequence()
        report = analyze(events[:-1], [source(events)])
        self.assertTrue(any("subset" in x for x in report["limitations"]))

    def test_conflicting_import_versions_fail_closed(self):
        events = sequence(); first = source(events); second = copy.deepcopy(first)
        second.update(id="source-2", parser_version="2")
        with self.assertRaisesRegex(ValueError, "conflicting_source_versions"):
            analyze(events, [first, second])

    def test_same_input_under_other_format_is_not_independent_evidence(self):
        first = source([]); second = copy.deepcopy(first); second.update(id="source-2", format="journal")
        with self.assertRaisesRegex(ValueError, "conflicting_source_versions"):
            analyze([], [first, second])

    def test_clock_correction_expands_interval_and_invalid_provenance_rejected(self):
        events = [event(1, low=8, high=12, original_low_us=20, original_high_us=20, clock_offset_us=10, clock_error_us=2)]
        s = source(events); s["options"].update(clock_offset_us=10, clock_error_us=2, correction_reason="measured test offset")
        self.assertEqual(analyze(events, [s])["coverage"]["sources"][0]["observed_low_us"], 8)
        events[0]["time_low_us"] = 7
        with self.assertRaisesRegex(ValueError, "event_clock_interval_mismatch"):
            analyze(events, [s])

    def test_duplicate_ids_ordinals_and_unknown_source_rejected(self):
        original = sequence()
        for change in ({"id": "event-1"}, {"ordinal": 1}, {"source_id": "missing"}):
            events = copy.deepcopy(original); events[1].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                analyze(events, [source(events)])

    def test_malformed_counters_and_timestamps_rejected(self):
        for change in ({"time_low_us": True}, {"time_high_us": None}, {"time_low_us": 2**63}, {"time_high_us": -1}):
            events = [event(1, **change)]
            with self.subTest(change=change), self.assertRaises(ValueError):
                analyze(events, [source(events)])
        with self.assertRaisesRegex(ValueError, "inconsistent_source_counters"):
            analyze([], [source([], parsed_count=1)])

    def test_materialization_stops_at_limit(self):
        consumed = []
        def records():
            for i in range(1, 100):
                consumed.append(i); yield event(i)
        with self.assertRaisesRegex(ValueError, "event_bounds_exceeded"):
            analyze(records(), [source([event(i) for i in range(1, 100)])], max_events=2)
        self.assertEqual(consumed, [1, 2, 3])

    def test_dense_relations_have_an_explicit_bound(self):
        events = [event(i) for i in range(1, 4)] + [event(i, "auth.success") for i in range(4, 7)]
        with patch("testifex.analysis.MAX_RELATIONS", 4), self.assertRaises(ValueError):
            analyze(events, [source(events)], threshold=1)

    def test_sparse_old_history_is_pruned_before_relation_budget(self):
        events = [event(i, low=i) for i in range(1, 2001)] + [event(2001, "auth.success", low=9_000_000)]
        with patch("testifex.analysis.MAX_RELATIONS", 1):
            self.assertFalse(analyze(events, [source(events)], window_us=10)["findings"])

    def test_bad_limits_and_recursive_attributes_fail_safely(self):
        for options in ({"threshold": True}, {"window_us": 0}, {"max_events": 100001}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                analyze([], [], **options)
        item = event(1); item["attributes"]["cycle"] = item["attributes"]
        with self.assertRaises(ValueError):
            analyze([item], [source([item])])

    def test_false_complete_status_and_impossible_provenance_fail_closed(self):
        events = sequence()
        for changes in ({"cursor": 0}, {"lines_total": 11, "last_line": 11, "error_count": 1}, {"observed_low_us": None, "observed_high_us": None}, {"last_line": 1}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                analyze(events, [source(events, **changes)])


if __name__ == "__main__":
    unittest.main()
