"""Canaria ficta in erroribus et relationibus auxilii non apparent."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from probentium.cli import parser
from probentium.contracts import ProbentiumError, canonical_bytes
from probentium.store import CaseStore
from probentium.worker import ParserWorker


CANARY = "sensitive_canary_token"
GROUPS = {"issues", "resume", "replay", "support", "recover", "batch", "claim", "clock", "family",
          "duplicates", "identity", "scenario", "sensitivity", "correlate", "analysis", "graph",
          "governance", "legal", "reporting", "retention", "review", "packet", "key", "parser-artifact"}


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="diagnostic-")
        self.root = Path(self.temporary.name)
        self.case = self.root / (CANARY + "-case")
        self.inputs = {}
        with CaseStore.create(self.case, CANARY):
            pass
        self.malformed = self.input("malformed.json", b'{"private":"' + CANARY.encode() + b'",')
        self.document = self.input("document.json", canonical_bytes({"private": CANARY}))
        self.environment = {**os.environ, "PRIVATE_DIAGNOSTIC_TOKEN": CANARY}

    def tearDown(self):
        try:
            for path, content in self.inputs.items():
                self.assertEqual(path.read_bytes(), content)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        finally:
            self.temporary.cleanup()

    def input(self, name, content):
        path = self.root / (CANARY + "-" + name)
        path.write_bytes(content)
        path.chmod(0o600)
        self.inputs[path] = content
        return path

    def cli(self, *args):
        return subprocess.run([sys.executable, "-m", "probentium", *(str(arg) for arg in args)],
                              cwd=self.root, env=self.environment, capture_output=True, timeout=20)

    def clean_error(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        for value in (result.stdout, result.stderr):
            self.assertNotIn(CANARY.encode(), value)
            self.assertNotIn(str(self.root).encode(), value)
            self.assertNotIn(b"Traceback", value)
            self.assertNotIn(b"\x1b", value)
        self.assertLess(len(result.stdout) + len(result.stderr), 32768)

    def test_every_registered_group_rejects_private_unknown_arguments_without_echo(self):
        registered = next(action.choices for action in parser()._actions if isinstance(action, argparse._SubParsersAction))
        expected = GROUPS | {"init", "demo", "status", "sources", "verify", "browse", "console", "ingest", "timeline", "event",
                             "control", "incident", "filing", "diff", "doctor", "formats", "schema", "inspect", "migrate"}
        self.assertEqual(set(registered), expected)
        for group in sorted(expected):
            for prefix in ((), ("--format", "json")):
                with self.subTest(group=group, machine=bool(prefix)):
                    result = self.cli(*prefix, group, "--" + CANARY, CANARY)
                    self.clean_error(result)
                    if prefix:
                        self.assertEqual(result.stdout, b"")
                        envelope = json.loads(result.stderr)
                        self.assertEqual(set(envelope), {"schema", "status", "case_revision", "verification", "data", "limitations", "errors"})
                        self.assertEqual(envelope["schema"], "probentium.cli-result.v1")
                        self.assertEqual(envelope["errors"], [{"code": "invalid_arguments", "exit_code": 2}])
                        self.assertIsNone(envelope["data"])

    def test_registered_document_groups_reject_malformed_json_without_echo(self):
        for group in sorted(GROUPS - {"packet"}):
            with self.subTest(group=group):
                self.clean_error(self.cli(group, "--case", self.case, "--input", self.malformed))
        for group in ("control", "incident"):
            with self.subTest(group=group):
                self.clean_error(self.cli(group, "--case", self.case, "--input", self.malformed))
        for action in ("encrypt", "decrypt", "export"):
            with self.subTest(packet=action):
                self.clean_error(self.cli("packet", action, "--case", self.case, "--input", self.malformed))
        self.clean_error(self.cli("filing", "--case", self.case, "--track", self.malformed,
                                  "--fields", self.document, "--cutoff", "2026-10-18T00:00:00Z"))

    def test_invalid_domain_documents_keep_private_values_out_of_diagnostics(self):
        actions = {"claim": "add", "clock": "add", "family": "add", "duplicates": "add", "identity": "add",
                   "scenario": "run", "sensitivity": "run", "correlate": "run", "analysis": "compare", "graph": "save",
                   "governance": "put", "legal": "import", "reporting": "track", "retention": "hold", "review": "create",
                   "batch": "plan", "packet": "encrypt"}
        for group, action in actions.items():
            with self.subTest(group=group):
                self.clean_error(self.cli(group, action, "--case", self.case, "--input", self.document))
        for group in ("control", "incident"):
            with self.subTest(group=group):
                self.clean_error(self.cli(group, "--case", self.case, "--input", self.document))

    def test_missing_paths_identifiers_and_invalid_numbers_do_not_echo(self):
        missing = self.root / (CANARY + "-missing")
        commands = [
            ("status", "--case", missing), ("sources", "--case", missing), ("verify", "--case", missing),
            ("inspect", missing), ("migrate", missing, self.root / "new-case"),
            ("event", "--case", self.case, CANARY), ("diff", "--case", self.case, CANARY, CANARY),
            ("timeline", "--case", self.case, "--limit", CANARY),
            ("timeline", "--case", self.case, "--cursor", CANARY),
            ("ingest", "--case", self.case, missing, "--format", "events", "--label", CANARY),
            ("packet", "verify", "--input", self.malformed),
            ("key", "generate", "--output", missing / CANARY),
        ]
        for command in commands:
            with self.subTest(command=command[0]):
                self.clean_error(self.cli(*command))

    def test_real_worker_malformed_requests_and_crash_sanitize_errors(self):
        with patch.dict(os.environ, {"PRIVATE_DIAGNOSTIC_TOKEN": CANARY}), ParserWorker() as worker:
            inherited = Path("/proc") / str(worker.process.pid) / "environ"
            self.assertNotIn(CANARY.encode(), inherited.read_bytes())
            for request in ({"op": CANARY}, {"op": "parse", "raw": CANARY, "format": "events", "ordinal": 1}):
                with self.assertRaises(ProbentiumError) as caught:
                    worker.request(request)
                self.assertEqual(caught.exception.code, "invalid_worker_request")
                self.assertNotIn(CANARY, str(caught.exception))
            for raw, format_name in ((self.malformed.read_bytes(), "events"),
                                     (canonical_bytes({"kind": "generic", "timestamp": CANARY}), "events")):
                with self.assertRaises(ProbentiumError) as caught:
                    worker.parse(raw, format_name, 1)
                self.assertEqual(caught.exception.exit_code, 2)
                self.assertNotIn(CANARY, str(caught.exception))
            worker.process.kill()
            worker.process.wait(timeout=5)
            with self.assertRaises(ProbentiumError) as caught:
                worker.request({"op": CANARY})
            self.assertEqual((caught.exception.code, caught.exception.exit_code), ("parser_process_failed", 6))

    def test_machine_errors_and_runtime_diagnostics_omit_environment_and_input_values(self):
        commands = [
            ("timeline", "--case", self.case, "--limit", CANARY),
            ("control", "--case", self.case, "--input", self.malformed),
            ("legal", "import", "--case", self.case, "--input", self.document),
            ("event", "--case", self.case, CANARY),
        ]
        for command in commands:
            result = self.cli("--format", "json", *command)
            self.clean_error(result)
            self.assertEqual(result.stdout, b"")
            envelope = json.loads(result.stderr)
            self.assertEqual(envelope["schema"], "probentium.cli-result.v1")
            self.assertIsNone(envelope["verification"])
            self.assertIsNone(envelope["data"])
            self.assertEqual(len(envelope["errors"]), 1)
            self.assertEqual(envelope["errors"][0]["exit_code"], result.returncode)
        for command in (("doctor",), ("inspect", self.malformed, "--format", "events")):
            result = self.cli(*command)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(CANARY.encode(), result.stdout + result.stderr)
            self.assertNotIn(str(self.root).encode(), result.stdout + result.stderr)

    def test_real_worker_preserves_supported_domain_errors_and_exit_codes(self):
        v2 = {"schema": "testifex.events.v2", "kind": "auth.success", "recorded_time": None,
              "origin": None, "payload": {"service": None}}
        examples = [
            (b"{", "events", "invalid_json", 2),
            (b'{"kind":1,"kind":2}', "events", "duplicate_json_key", 2),
            (b"[" * 34 + b"0" + b"]" * 34, "events", "json_depth_limit", 2),
            (b'{"value":1.5}', "events", "floating_point_not_supported", 2),
            (canonical_bytes({"kind": CANARY, "timestamp": None}), "events", "event_kind_unsupported", 2),
            (canonical_bytes({"kind": "generic", "timestamp": "2026-10-18T01:00:00-00:00"}), "events", "timestamp_timezone_unknown", 2),
            (CANARY.encode(), "auth", "auth_header_unsupported", 2),
            (b"{}", "journal", "journal_message_missing", 2),
            (b"{}", "events-v2", "invalid_event_fields", 2),
            (canonical_bytes({**v2, "kind": CANARY}), "events-v2", "unsupported_event_kind", 7),
            (canonical_bytes({**v2, "schema": CANARY}), "events-v2", "unsupported_event_schema", 7),
            (canonical_bytes({**v2, "recorded_time": {"encoding": CANARY, "value": "0", "resolution_us": "1"}}),
             "events-v2", "unsupported_time_encoding", 7),
            (b"{}", CANARY, "unsupported_format", 7),
        ]
        with ParserWorker() as worker:
            for raw, format_name, code, exit_code in examples:
                with self.subTest(code=code), self.assertRaises(ProbentiumError) as caught:
                    worker.parse(raw, format_name, 1)
                self.assertEqual((caught.exception.code, caught.exception.exit_code), (code, exit_code))


    def hostile_worker(self, response):
        worker = ParserWorker()
        worker.process.terminate()
        worker.process.wait(timeout=5)
        worker.process.stdin.close()
        worker.process.stdout.close()
        raw = canonical_bytes(response)
        program = ("import sys,struct; n=struct.unpack('>I',sys.stdin.buffer.read(4))[0];"
                   "sys.stdin.buffer.read(n);sys.stderr.write(" + repr(CANARY) + ");"
                   "sys.stdout.buffer.write(" + repr(struct.pack(">I", len(raw)) + raw) + ");sys.stdout.buffer.flush()")
        worker.process = subprocess.Popen([sys.executable, "-I", "-c", program], stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=self.root,
                                          env={"PATH": os.defpath}, close_fds=True)
        os.set_blocking(worker.process.stdin.fileno(), False)
        os.set_blocking(worker.process.stdout.fileno(), False)
        return worker

    def test_real_hostile_worker_frames_cannot_invent_diagnostic_codes_or_severity(self):
        responses = [{"error": CANARY, "exit_code": 2}, {"error": "invalid_json", "exit_code": 7},
                     {"error": "unsupported_event_kind", "exit_code": 2}, {"error": "échec", "exit_code": 2},
                     {"error": "invalid_json", "exit_code": True}, {"private": CANARY}]
        for response in responses:
            with self.subTest(response=sorted(response)), self.hostile_worker(response) as worker:
                with self.assertRaises(ProbentiumError) as caught:
                    worker.request({"op": "start"})
                self.assertEqual((caught.exception.code, caught.exception.exit_code), ("invalid_worker_protocol", 4))
                self.assertNotIn(CANARY, str(caught.exception))

    def test_support_allowlist_omits_private_fields_in_partial_and_retained_cases(self):
        from probentium import retention
        source = self.input("events.jsonl", b"".join(canonical_bytes({"kind": "generic", "timestamp": None,
                            "actor": CANARY, "host": CANARY}) + b"\n" for _ in range(2)))
        with CaseStore(self.case) as case, patch("probentium.store.MAX_RECORDS", 1):
            artifact = case.ingest(source, "events", CANARY)
            self.assertEqual(artifact["state"], "incomplete")
            case.put_object("note", {"text": CANARY})
        for purged in (False, True):
            if purged:
                with CaseStore(self.case) as case:
                    plan = retention.plan(case, [artifact["id"]], CANARY, CANARY, "2026-01-01T00:00:00Z")
                    approval = retention.approve(case, plan["id"], CANARY, CANARY)
                    retention.execute(case, plan["id"], approval["id"])
            result = self.cli("support", "--case", self.case)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(CANARY.encode(), result.stdout + result.stderr)
            self.assertNotIn(artifact["id"].encode(), result.stdout)
            value = json.loads(result.stdout)
            self.assertEqual(set(value), {"schema", "runtime", "case_schema", "source_count", "event_count", "object_count",
                                         "integrity", "availability", "authorized_unavailable_count", "issue_codes", "evidence_included",
                                         "paths_included", "environment_included", "identifiers_included"})
            self.assertEqual(set(value["runtime"]), {"schema", "version", "python", "platform", "dependencies", "parser_process_isolation",
                                                   "strict_resource_limits", "analysis_resources", "parser_network_sandbox", "age_available", "offline_operation",
                                                   "telemetry", "legal_profiles_verified"})
            self.assertEqual(value["authorized_unavailable_count"], int(purged))
            self.assertEqual(value["event_count"], 1)
            self.assertEqual(value["integrity"], "passed")
            self.assertEqual(value["availability"], "partial" if purged else "acquired_bytes_present")
            for key in ("evidence_included", "paths_included", "environment_included", "identifiers_included"):
                self.assertIs(value[key], False)
