"""Mandata publica per cursum integrum probantur."""
import base64
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from probentium.demo import make_demo
from probentium.store import CaseStore
from probentium.workbench import Workbench


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.case = make_demo(self.root / "exercise")["case"]

    def tearDown(self):
        self.temporary.cleanup()

    def cli(self, *args):
        return subprocess.run([sys.executable, "-m", "probentium", *args], capture_output=True, timeout=20)

    def test_actual_demo_counts_and_all_views(self):
        result = self.cli("status", "--case", self.case)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual((data["sources"], data["events"]), (2, 132))
        board = Workbench(self.case)
        for key in ("1", "2", "3", "4", "5", "6", "7", "?"):
            board.key(key)
            frame = board.frame(120, 36)
            self.assertEqual(len(frame["lines"]), 36)
            self.assertTrue(board.model["synthetic"])

    def test_json_transport_escapes_terminal_controls_and_unicode(self):
        from probentium.cli import main
        name = "Evidence \u202eabc\u2069 \u001b[31m \u017elu\u0165ou\u010dk\u00fd"
        output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with patch("probentium.cli.run", return_value={"untrusted_record": name}), patch("sys.stdout", output):
            status = main(["status", "--case", self.case])
        raw = output.buffer.getvalue()
        self.assertEqual(status, 0)
        self.assertTrue(raw.isascii())
        self.assertNotIn(b"\x1b", raw)
        self.assertIn(b"\\u202e", raw)
        self.assertEqual(json.loads(raw)["untrusted_record"], name)

    def test_filter_beyond_first_page_and_exact_raw(self):
        page = json.loads(self.cli("timeline", "--case", self.case, "--filter", "auth.success").stdout)
        self.assertEqual(page["total"], 1)
        event = page["rows"][0]
        raw_result = self.cli("event", "--case", self.case, event["id"])
        raw = json.loads(raw_result.stdout)
        content = base64.b64decode(raw["raw_base64"], validate=True)
        self.assertEqual(hashlib.sha256(content).hexdigest(), raw["raw_sha256"])
        self.assertEqual(json.loads(content)["kind"], "auth.success")
        board = Workbench(self.case)
        board.frame()
        board.key("3")
        board.key("PageDown")
        board.frame()
        self.assertEqual(board.model["events"]["offset"], 100)
        self.assertEqual(len(board.model["events"]["rows"]), 32)

    def test_prepare_preserves_previous_snapshot_and_synthetic_scope(self):
        board = Workbench(self.case)
        board.frame()
        with CaseStore(self.case) as store:
            previous = store.objects("filing")
        board.command("prepare")
        board.frame()
        with CaseStore(self.case) as store:
            now = store.objects("filing")
            self.assertTrue(store.verify()["ok"])
        self.assertEqual(now[:2], previous)
        self.assertEqual(len(now), 3)
        self.assertTrue(board.model["synthetic"])
        self.assertEqual(now[-1]["data"]["submission_status"], "not_submitted")

    def test_cli_invalid_input_never_emits_traceback(self):
        bad = self.root / "bad.json"
        for content in ("[]", '{"id":"c","kind":"mfa","observations":[null]}', '{"a":1,"a":2}'):
            bad.write_text(content)
            result = self.cli("control", "--case", self.case, "--input", str(bad))
            self.assertEqual(result.returncode, 2, result.stderr)
            error = json.loads(result.stderr)
            self.assertIn("error", error)
            self.assertNotIn(str(self.root), result.stderr.decode())

    def test_verify_detects_changed_evidence_with_integrity_exit(self):
        with CaseStore(self.case) as store:
            source_id = store.sources()[0]["id"]
        candidates = list(Path(self.case).rglob(source_id + "*"))
        self.assertEqual(len(candidates), 1)
        candidates[0].chmod(0o600)
        data = candidates[0].read_bytes()
        candidates[0].write_bytes(b"X" + data[1:])
        result = self.cli("verify", "--case", self.case)
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertFalse(json.loads(result.stdout)["ok"])

    def test_filter_and_command_do_not_execute_shell(self):
        board = Workbench(self.case)
        board.frame()
        for character in ":!touch " + str(self.root / "marker"):
            board.key(character)
        board.key("Enter")
        self.assertIn("unknown_command", board.state["message"])
        self.assertFalse((self.root / "marker").exists())
        board.command("filter 'auth.success'")
        board.frame()
        self.assertEqual(board.model["events"]["total"], 1)

    def test_extended_review_and_shared_correlation_commands(self):
        extended = make_demo(self.root / "extended", extended=True)["case"]
        document = self.root / "command.json"
        document.write_text(json.dumps({"text": "Synthetic review rationale."}))
        rationale = self.cli("review", "rationale", "--case", extended, "--input", str(document))
        self.assertEqual(rationale.returncode, 0, rationale.stderr)
        self.assertEqual(json.loads(rationale.stdout)["rationale_digest"], hashlib.sha256(b"Synthetic review rationale.").hexdigest())
        document.write_text(json.dumps([{"template": "auth_after_failures", "window_us": "100000000", "threshold": 5},
                                        {"template": "post_auth_process", "window_us": "100000000"}]))
        result = self.cli("correlate", "batch", "--case", extended, "--input", str(document))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)["templates"]), 2)
        with CaseStore(extended) as case:
            evaluations = case.objects("evaluation")
            review = case.objects("review_decision")[0]["data"]
            self.assertEqual(review["decision"]["disposition"], "abstain")
            self.assertEqual(review["verification"]["key_trust"], "unknown")
            self.assertEqual(review["approval_effect"], "none")
        document.write_text(json.dumps({"before": evaluations[0]["id"], "after": evaluations[1]["id"]}))
        diff = self.cli("analysis", "compare", "--case", extended, "--input", str(document))
        self.assertEqual(diff.returncode, 0, diff.stderr)
        self.assertIsInstance(json.loads(diff.stdout), dict)

        explanation = self.cli("claim", "explain", "--case", extended, "--id", evaluations[1]["id"])
        self.assertEqual(explanation.returncode, 0, explanation.stderr)
        proof = json.loads(explanation.stdout)
        self.assertIn("witness_graph", proof)
        self.assertTrue(proof["witness_graph"])


if __name__ == "__main__":
    unittest.main()
