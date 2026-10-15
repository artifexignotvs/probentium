"""Termini et vestigia contra errores probantur."""
import unittest
from unittest.mock import patch

from testifex.tui import (
    MAX_EVENTS, MAX_RAW_PREVIEW, Snapshot, cell_width, coverage_lines,
    display_text, event_details, filter_events, fit_text, layout_detail,
    load_snapshot, time_interval, viewport, wrap_text, _browse,
)


def example_event():
    return {
        "id": "a" * 64, "source_id": "b" * 64, "kind": "auth.failure",
        "time_low_us": 0, "time_high_us": 999999,
        "original_low_us": 0, "original_high_us": 999999,
        "time_raw": "1970-01-01T00:00:00Z", "time_basis": "resolution_second",
        "host": "server", "actor": "analyst", "src_ip": "192.0.2.1",
        "ordinal": 3, "offset": 42, "length": 80, "raw_sha256": "c" * 64,
        "attributes": {},
    }


class TextTests(unittest.TestCase):
    def test_control_sequences_and_bidi_are_never_emitted(self):
        raw = "name\x1b[2J\x07\r\n\t\u202eevil\u2066text\u009b31m"
        result = display_text(raw)
        self.assertNotIn("\x1b", result)
        self.assertNotIn("\u202e", result)
        self.assertNotIn("\u009b", result)
        self.assertTrue(all(character.isprintable() for character in result))
        self.assertIn("\\u001b[2J", result)
        self.assertIn("\\u202e", result)

    def test_ascii_mode_and_wide_character_bounds(self):
        self.assertEqual(display_text("č界", True), "\\u010d\\u754c")
        self.assertEqual(fit_text("a界b", 3), "a界")
        self.assertEqual(fit_text("a界b", 2), "a")
        self.assertEqual(fit_text("abc", 0), "")
        self.assertEqual(wrap_text("a界b", 3), ["a界", "b"])
        self.assertTrue(all(sum(map(cell_width, line)) <= 7 for line in wrap_text("abc界\x1b[31m", 7)))

    def test_wrapping_retains_safe_content(self):
        text = "first\nsecond\x1b[2J界"
        self.assertEqual("".join(wrap_text(text, 8)), display_text(text))
        self.assertEqual(wrap_text("", 8), [""])
        self.assertEqual(wrap_text("value", 0), [])


class SnapshotTests(unittest.TestCase):
    def test_loading_reads_only_cap_and_one_sentinel(self):
        class Case:
            read = 0
            closed = False

            def events(self):
                try:
                    for index in range(MAX_EVENTS * 2):
                        self.read += 1
                        yield {"id": str(index)}
                finally:
                    self.closed = True

            def sources(self):
                return []

        case = Case()
        snapshot = load_snapshot(case)
        self.assertEqual(len(snapshot.events), MAX_EVENTS)
        self.assertEqual(case.read, MAX_EVENTS + 1)
        self.assertTrue(snapshot.truncated)
        self.assertTrue(case.closed)

    def test_exact_limit_is_not_reported_truncated(self):
        class Case:
            def events(self):
                return iter({"id": str(index)} for index in range(MAX_EVENTS))

            def sources(self):
                return []

        self.assertFalse(load_snapshot(Case()).truncated)

    def test_coverage_keeps_errors_and_unfinished_visible(self):
        snapshot = Snapshot([], [
            {"status": "complete", "parsed_count": 4, "ignored_count": 2, "error_count": 0},
            {"status": "incomplete", "parsed_count": 1, "ignored_count": 0, "error_count": 3},
            {"status": "interrupted", "parsed_count": 0, "ignored_count": 0, "error_count": 0},
        ], False)
        lines = coverage_lines(snapshot)
        self.assertIn("parsed 5 | ignored 2 | errors 3", lines[0])
        self.assertIn("not complete 2", lines[1])
        self.assertIn("do not prove", lines[1])

    def test_filter_is_literal_and_case_insensitive(self):
        event = example_event()
        event["path"] = "/tmp/a[1]"
        self.assertEqual(filter_events([event], "ANALYST"), [event])
        self.assertEqual(filter_events([event], "[1]"), [event])
        self.assertEqual(filter_events([event], ".*"), [])
        self.assertEqual(filter_events([event], "192.0.2.1"), [event])


class DetailTests(unittest.TestCase):
    def test_interval_has_both_bounds_and_unknown_is_explicit(self):
        interval = time_interval(example_event())
        self.assertIn("1970-01-01", interval)
        self.assertIn(" .. ", interval)
        self.assertIn("999999", interval)
        self.assertEqual(time_interval({"time_low_us": None, "time_high_us": None}), "[unknown time]")

    def test_details_include_original_and_corrected_bounds_and_locator(self):
        event = example_event()
        event["time_low_us"] = -1000000
        event["time_high_us"] = -1
        event["clock_offset_us"] = 1000000
        source = {"id": event["source_id"], "label": "source", "sha256": "d" * 64, "status": "incomplete", "format": "auth", "parser_version": "1"}
        details = "\n".join(event_details(event, source))
        self.assertIn("1969-12-31", details)
        self.assertIn("Original bounds: [1970-01-01", details)
        self.assertIn("Byte offset / length: 42 / 80", details)
        self.assertIn("Original line: 3", details)
        self.assertIn("Record SHA-256: " + "c" * 64, details)
        self.assertIn("Source SHA-256: " + "d" * 64, details)
        self.assertIn("not confidence", details)

    def test_raw_details_are_safe_and_preview_bound_is_explicit(self):
        event = example_event()
        event["actor"] = "\x1b]0;unsafe\x07"
        raw = b"\x1b[2J\xff\n" + b"x" * MAX_RAW_PREVIEW
        lines = layout_detail(event, {"label": "\u202eunsafe"}, 69, True, raw)
        self.assertTrue(all(line.isascii() and all(c.isprintable() for c in line) for line in lines))
        self.assertTrue(all(len(line) <= 69 for line in lines))
        joined = "".join(lines)
        self.assertIn("preview truncated", joined)
        self.assertIn("\\u001b[2J", joined)
        self.assertIn("\\xff", joined)
        self.assertNotIn("\x1b", joined)

    def test_raw_failure_has_no_success_claim(self):
        details = "\n".join(event_details(example_event(), {}, raw_error=True))
        self.assertIn("Raw record unavailable", details)
        self.assertNotIn("Escaped raw record:", details)

    def test_viewport_clamps_empty_and_boundary_navigation(self):
        self.assertEqual(viewport(20, 0, 4), (0, 0))
        self.assertEqual(viewport(-1, 10, 4), (0, 0))
        self.assertEqual(viewport(12, 10, 4), (9, 8))
        self.assertEqual(viewport(4, 10, 4), (4, 4))


class InteractionTests(unittest.TestCase):
    class Screen:
        def __init__(self, keys, size=(18, 70)):
            self.keys, self.size, self.writes = iter(keys), size, []

        def getmaxyx(self):
            return self.size

        def get_wch(self):
            return next(self.keys)

        def addstr(self, row, column, text, attribute=0):
            self.writes.append(text)

        def keypad(self, enabled):
            pass

        def timeout(self, milliseconds):
            pass

        def erase(self):
            pass

        def refresh(self):
            pass

    class Case:
        metadata = {"name": "case\x1b[2J"}
        raw_reads = 0

        def raw_event(self, event_id):
            self.raw_reads += 1
            return b"\x1b[2J\n"

    def test_small_terminal_has_resize_hint_and_clean_quit(self):
        screen = self.Screen(["q"], (10, 30))
        with patch("curses.curs_set"):
            _browse(screen, self.Case(), Snapshot([], [], False), False)
        self.assertIn("Resize terminal to 70 x 18.", screen.writes)
        self.assertIn("q: exit", screen.writes)

    def test_raw_read_is_explicit_and_detail_quit_returns_to_list(self):
        event = example_event()
        for keys, expected_reads in ((["\n", "q", "q"], 0), (["\n", "r", "q", "q"], 1)):
            with self.subTest(keys=keys):
                screen, case = self.Screen(keys), self.Case()
                with patch("curses.curs_set"):
                    _browse(screen, case, Snapshot([event], [], False), True)
                self.assertEqual(case.raw_reads, expected_reads)
                self.assertTrue(all("\x1b" not in line and line.isascii() for line in screen.writes))
                self.assertTrue(any("Event 1 / 1" in line for line in screen.writes))


if __name__ == "__main__":
    unittest.main()
