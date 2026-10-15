import json
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args, expected=0):
        result = subprocess.run([sys.executable, "-m", "testifex", *map(str, args)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, expected, result.stderr + result.stdout[:300])
        return result

    def test_two_demo_reports_and_replay(self):
        result = json.loads(self.run_cli("demo", "--directory", self.root / "demo").stdout)
        self.assertEqual(len(result["scenarios"]), 2)
        case = self.root / "demo/auth-case"
        self.assertTrue(json.loads(self.run_cli("verify", "--case", case).stdout)["ok"])
        self.run_cli("replay", "--case", case, "--into", self.root / "copy")
        original = json.loads(self.run_cli("analyze", "--case", case).stdout)
        replay = json.loads(self.run_cli("analyze", "--case", self.root / "copy").stdout)
        self.assertEqual(original, replay)

    def test_replay_preserves_import_with_raised_record_ceiling(self):
        from testifex.case import Case
        from testifex.cli import execute, parser
        self.run_cli("demo", "--directory", self.root / "demo")
        original_ingest = Case.ingest
        def lower_default(instance, *args, **kwargs):
            kwargs.setdefault("max_records", 1)
            return original_ingest(instance, *args, **kwargs)
        args = parser().parse_args(["replay", "--case", str(self.root / "demo/auth-case"), "--into", str(self.root / "replay-limit")])
        with patch.object(Case, "ingest", lower_default), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(execute(args), 0)
        result = json.loads(output.getvalue())
        self.assertTrue(result["replayed"])
        self.assertEqual(result["events"], 10)
        with Case(self.root / "replay-limit") as case:
            self.assertTrue(case.verify()["ok"])
            self.assertTrue(all(source["status"] == "complete" for source in case.sources()))

    def test_preview_does_not_write_without_public_flag(self):
        self.run_cli("demo", "--directory", self.root / "demo")
        key = self.root / "key"; key.write_bytes(b"s" * 32); key.chmod(0o600)
        out = self.root / "public.json"
        self.run_cli("share", "--case", self.root / "demo/auth-case", "--key-file", key, "--output", out, expected=2)
        self.assertFalse(out.exists())
        self.run_cli("share", "--case", self.root / "demo/auth-case", "--key-file", key, "--output", out, "--public")
        text = out.read_text()
        for secret in ("192.0.2.30", "edge-demo", "operator", "/usr/bin/id"):
            self.assertNotIn(secret, text)
        self.assertNotIn(key.read_text(), text)

    def test_invalid_input_has_json_only_on_stdout_when_successful(self):
        self.run_cli("init", self.root / "case")
        data = self.root / "broken"; data.write_text('private-data-not-to-echo\n')
        result = self.run_cli("ingest", data, "--case", self.root / "case", "--format", "events", "--label", "fixture", expected=3)
        self.assertNotIn("private-data-not-to-echo", result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["error_count"], 1)

    def test_report_refuses_changed_evidence(self):
        self.run_cli("demo", "--directory", self.root / "demo")
        case = self.root / "demo/auth-case"
        copy = next((case / "evidence").glob("*.bin"))
        copy.write_bytes(b"changed")
        result = self.run_cli("report", "--case", case, expected=2)
        self.assertEqual(result.stdout, "")
        self.assertIn("case_verification_failed", result.stderr)

    def test_output_existing_file_is_not_overwritten(self):
        self.run_cli("demo", "--directory", self.root / "demo")
        output = self.root / "existing"; output.write_text("keep")
        self.run_cli("report", "--case", self.root / "demo/auth-case", "--output", output, expected=2)
        self.assertEqual(output.read_text(), "keep")

    def test_tui_nonterminal_refuses_without_traceback(self):
        self.run_cli("init", self.root / "case")
        result = self.run_cli("browse", "--case", self.root / "case", expected=2)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
