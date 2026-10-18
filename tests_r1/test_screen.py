"""Tabula vera, tuta et finita probatur."""

import copy
import unittest
import unicodedata

from probentium.screen import MIN_HEIGHT, MIN_WIDTH, STYLES, cell_width, fit_text, render, safe_text


def fixture():
    return {
        "product": "PROBENTIUM", "version": "0.2.0.dev1", "case_name": "case-a", "revision": 7,
        "synthetic": True, "integrity": {"ok": True, "issues": []},
        "counts": {"sources": 2, "events": 30001, "controls": 1, "filings": 1},
        "sources": [{"id": "src-a", "label": "auth.log", "format": "auth", "status": "complete", "parsed_count": 12}],
        "events": {"rows": [{"id": "evt-a", "time_raw": "2026-10-18T08:04:05Z", "kind": "auth.success", "host": "host-a", "actor": "account-a"}], "total": 30001, "offset": 30000},
        "controls": [{"id": "ctrl-a", "title": "Restore test", "status": "not_demonstrated", "coverage": "1 / 5", "reason": "Function check absent"}],
        "incident": {"id": "inc-a", "title": "Synthetic interruption", "profile": "draft-local", "status": "unresolved", "awareness": "not established", "deadline_rows": [{"stage": "draft", "target": "unknown", "status": "waiting_for_trigger", "basis": "No reviewed awareness"}], "limitations": ["Synthetic exercise only"]},
        "filings": [{"id": "fil-a", "status": "prepared", "title": "Initial draft", "cutoff": "2026-10-18T10:00:00Z", "fields_count": 4}],
        "changes": [{"field": "affected_accounts", "before": 2, "after": 3, "reason": "Later record"}],
        "detail_lines": ["Event evt-a", "Source SHA-256: " + "a" * 64, "Raw locator: offset 10 length 20"],
    }


class ScreenTests(unittest.TestCase):
    def assert_frame(self, frame, width, height):
        self.assertEqual(set(frame), {"width", "height", "lines"})
        self.assertEqual((frame["width"], frame["height"]), (width, height))
        self.assertEqual(len(frame["lines"]), height)
        for line in frame["lines"]:
            self.assertEqual(set(line), {"text", "style"})
            self.assertIn(line["style"], STYLES)
            self.assertEqual(cell_width(line["text"]), width)
            self.assertFalse(any(unicodedata.category(c) in ("Cc", "Cf", "Cs", "Cn", "Zl", "Zp") for c in line["text"]))

    def text(self, frame):
        return "\n".join(line["text"] for line in frame["lines"])

    def test_all_views_fit_small_and_large_screens(self):
        for width, height in ((80, 24), (120, 36), (173, 51)):
            for view in ("overview", "evidence", "timeline", "controls", "incident", "filings", "changes", "help"):
                with self.subTest(width=width, height=height, view=view):
                    self.assert_frame(render(fixture(), {"view": view}, width, height), width, height)

    def test_small_screen_is_informative_without_fabricated_case(self):
        for width, height in ((79, 24), (80, 23), (40, 8), (1, 1)):
            frame = render({}, {}, width, height)
            self.assert_frame(frame, width, height)
            if width >= 40:
                self.assertIn("Terminal too small", self.text(frame))
                self.assertIn("80 columns x 24 rows", self.text(frame))
        self.assertEqual((MIN_WIDTH, MIN_HEIGHT), (80, 24))

    def test_dimensions_reject_unbounded_or_invalid_values(self):
        for width, height in ((0, 24), (80, 0), (True, 24), (80, 24.0), (4097, 24), (80, 2049)):
            with self.subTest(width=width, height=height):
                with self.assertRaises(ValueError):
                    render({}, {}, width, height)

    def test_control_and_bidi_characters_are_visible_not_executed(self):
        text = safe_text("ok\x1b[2J\n\r\t\x9b31m\u202eabc\u2066x\u2069\u200b\u2028\ud800")
        for escaped in ("\\x1b", "\\x0a", "\\x0d", "\\x09", "\\x9b", "\\u202e", "\\u2066", "\\u2069", "\\u200b", "\\u2028", "\\ud800"):
            self.assertIn(escaped, text)
        self.assertFalse(any(unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zl", "Zp") for c in text))

    def test_hostile_values_reach_no_render_surface_as_controls(self):
        model = fixture()
        hostile = "\x1b]0;owned\x07\u202e"
        model["case_name"] = hostile
        model["product"] = hostile
        model["sources"][0]["label"] = hostile
        model["detail_lines"] = [hostile]
        for state in ({"view": "evidence", "filter": hostile, "message": hostile}, {"detail": True, "prompt": hostile}):
            frame = render(model, state, 120, 36)
            self.assert_frame(frame, 120, 36)
            self.assertIn("\\x1b", self.text(frame))
            self.assertNotIn("\x1b", self.text(frame))

    def test_unicode_width_combining_and_clipping(self):
        self.assertEqual(cell_width("A界e\u0301"), 4)
        self.assertEqual(fit_text("A界e\u0301", 4), "A界e\u0301")
        self.assertEqual(fit_text("界界界", 5), "界...")
        self.assertEqual(fit_text("界", 3, pad=True), "界 ")
        self.assertEqual(fit_text("abcdef", 2), "..")
        self.assertEqual(fit_text("abcdef", 0), "")
        self.assertEqual(safe_text("\u0301x"), "\\u0301x")
        self.assertIn("\\u0301", safe_text("a" + "\u0301" * 100))
        self.assertIn("\\ufe0f", safe_text("x\ufe0f"))
        self.assertEqual(safe_text("\U0001f44d\U0001f3fb"), "\U0001f44d\\U0001f3fb")
        self.assertEqual(safe_text("1\u20e3"), "1\\u20e3")
        self.assertEqual(safe_text("\u1100\u1161"), "\u1100\\u1161")

    def test_ascii_mode_preserves_visible_escapes_and_column_bounds(self):
        model = fixture()
        model["case_name"] = "Case \u00e9\u754c\u202e\x1b"
        frame = render(model, {}, 120, 36, ascii_only=True)
        text = self.text(frame)
        self.assertTrue(text.isascii())
        self.assertIn("\\xe9\\u754c\\u202e\\x1b", text)
        self.assertTrue(all(cell_width(line["text"]) == 120 for line in frame["lines"]))
        self.assertEqual(model["case_name"], "Case \u00e9\u754c\u202e\x1b")

    def test_deep_rows_remain_accessible_and_selected(self):
        model = fixture()
        model["sources"] = [{"label": "source-%05d" % n, "format": "auth", "status": "complete", "parsed_count": n} for n in range(12001)]
        frame = render(model, {"view": "evidence", "selected": 12000, "scroll": 0}, 80, 24)
        self.assert_frame(frame, 80, 24)
        selected = [line["text"] for line in frame["lines"][4:-3] if line["style"] == "inverse"]
        self.assertEqual(len(selected), 1)
        self.assertIn("source-12000", selected[0])
        self.assertNotIn("source-00000", self.text(frame))

    def test_selection_is_page_local_and_total_offset_are_explicit(self):
        frame = render(fixture(), {"view": "timeline", "selected": 0}, 120, 36)
        self.assertIn("loaded 1  total 30001  offset 30000", self.text(frame))
        selected = [line for line in frame["lines"][4:-3] if line["style"] == "inverse"]
        self.assertEqual(len(selected), 1)
        self.assertIn("account-a", selected[0]["text"])

    def test_selection_and_scroll_are_clamped_without_changing_inputs(self):
        model, state = fixture(), {"view": "evidence", "selected": -50, "scroll": 999999}
        original_model, original_state = copy.deepcopy(model), copy.deepcopy(state)
        first = render(model, state)
        second = render(model, state)
        self.assertEqual(first, second)
        self.assertEqual((model, state), (original_model, original_state))
        self.assertTrue(any(line["style"] == "inverse" and "auth.log" in line["text"] for line in first["lines"]))

    def test_detail_wraps_source_digest_instead_of_losing_tail(self):
        model = fixture()
        model["detail_lines"] = ["source: " + "a" * 170 + " END", "next record"]
        frame = render(model, {"detail": True}, 80, 24)
        self.assert_frame(frame, 80, 24)
        self.assertIn("END", self.text(frame))
        self.assertIn("next record", self.text(frame))
        self.assertNotIn("...", self.text(frame))

    def test_detail_scroll_accesses_deep_supplied_lines(self):
        model = fixture()
        model["detail_lines"] = ["row %05d" % n for n in range(12000)]
        frame = render(model, {"detail": True, "scroll": 11990}, 80, 24)
        self.assertIn("row 11990", self.text(frame))
        self.assertIn("row 11999", self.text(frame))
        self.assertNotIn("row 00000", self.text(frame))

    def test_unknown_values_do_not_become_zero_or_verified(self):
        frame = render({}, {}, 80, 24)
        text = self.text(frame)
        self.assertIn("not supplied", text)
        self.assertNotIn("passed", text)
        self.assertNotIn("sources 0", text)
        self.assertNotIn("synthetic case", text)
        self.assertNotIn("local case", text)

    def test_positive_integrity_with_issues_does_not_say_passed(self):
        model = fixture()
        model["integrity"] = {"ok": True, "issues": ["digest mismatch"]}
        text = self.text(render(model, {}))
        self.assertIn("issues reported", text)
        self.assertIn("digest mismatch", text)
        self.assertNotIn("passed", text)

    def test_origin_development_and_keyboard_navigation_are_visible(self):
        model = fixture()
        frame = render(model, {}, 80, 24)
        text = self.text(frame)
        for expected in ("development", "synthetic case", "1Overview", "7Changes", "/filter", "v verify", ":command", "q quit"):
            self.assertIn(expected, text)
        model["synthetic"] = False
        self.assertIn("local case", self.text(render(model, {})))

    def test_prompt_takes_precedence_and_filter_is_not_applied_twice(self):
        state = {"view": "evidence", "filter": "unmatched", "message": "ready", "prompt": ":status"}
        frame = render(fixture(), state, 80, 24)
        self.assertEqual(frame["lines"][-3]["text"].strip(), ":status")
        self.assertEqual(frame["lines"][-3]["style"], "strong")
        self.assertIn("auth.log", self.text(frame))
        state["prompt"] = None
        self.assertIn("Timeline filter: unmatched  |  ready", self.text(render(fixture(), state, 80, 24)))

    def test_long_labels_cannot_hide_development_or_case_origin(self):
        model = fixture()
        model.update({"product": "p" * 1000, "version": "v" * 1000, "case_name": "c" * 1000, "revision": "r" * 1000})
        frame = render(model, {}, 80, 24)
        self.assert_frame(frame, 80, 24)
        self.assertIn("development", frame["lines"][0]["text"])
        self.assertIn("synthetic case", frame["lines"][1]["text"])

    def test_empty_views_and_unknown_view_are_explicit(self):
        for view in ("evidence", "timeline", "controls", "filings", "changes"):
            self.assertIn("No rows supplied.", self.text(render({}, {"view": view})))
        self.assertIn("No deadline rows supplied.", self.text(render({}, {"view": "incident"})))
        self.assertIn("No detail supplied.", self.text(render({}, {"detail": True})))
        self.assertIn("Unknown view.", self.text(render({}, {"view": "unrecognized"})))

    def test_supplied_incident_and_control_states_are_not_upgraded(self):
        model = fixture()
        incident = self.text(render(model, {"view": "incident"}))
        self.assertIn("waiting_for_trigger", incident)
        self.assertIn("No reviewed awareness", incident)
        self.assertIn("Synthetic exercise only", incident)
        self.assertIn("not_demonstrated", self.text(render(model, {"view": "controls"})))
        self.assertIn("prepared", self.text(render(model, {"view": "filings"})))
        self.assertNotIn("submitted", self.text(render(model, {"view": "filings"})))

    def test_long_text_is_explicitly_bounded_and_wide_rows_fit(self):
        self.assertTrue(safe_text("a" * 20000).endswith("[text limited]"))
        model = fixture()
        model["sources"][0]["label"] = "界" * 200
        frame = render(model, {"view": "evidence"}, 80, 24)
        self.assert_frame(frame, 80, 24)
        self.assertIn("...", self.text(frame))


if __name__ == "__main__":
    unittest.main()
