"""Imago localis contra origines alienas et fontes privatos probatur."""
import ast
import http.client
import importlib.util
import json
import re
import tempfile
import threading
import unittest
from pathlib import Path

from probentium.contracts import ProbentiumError
from probentium.demo import make_demo
from probentium.store import CaseStore
from probentium.workbench import Workbench

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("preview_security_server", ROOT / "dev/livepreview/server.py")
SERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERVER)


class PreviewHarness:
    def start_preview(self, case):
        self.server = SERVER.build_server(case, port=0)
        self.worker = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.worker.start()
        self.port = self.server.server_port
        self.host = "127.0.0.1:" + str(self.port)
        self.origin = "http://" + self.host
        status, _, body = self.request("GET", "/", authenticated=False)
        self.assertEqual(status, 200)
        self.token = re.search(rb'name="preview-token" content="([A-Za-z0-9_-]+)"', body).group(1).decode("ascii")

    def stop_preview(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=3)

    def request(self, method, path, body=None, headers=None, authenticated=True):
        supplied = {"Host": self.host}
        if authenticated:
            supplied["X-Preview-Token"] = self.token
        if method == "POST":
            supplied.update({"Origin": self.origin, "Content-Type": "application/json"})
        supplied.update(headers or {})
        supplied = {key: value for key, value in supplied.items() if value is not None}
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=supplied)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read(1024 * 1024)
        finally:
            connection.close()

    def key(self, key):
        return self.request("POST", "/api/key", json.dumps({"key": key, "width": 120, "height": 36}).encode())


class PreviewBoundaryTests(PreviewHarness, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.demo = make_demo(Path(cls.temp.name) / "demo")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.start_preview(self.demo["case"])

    def tearDown(self):
        self.stop_preview()

    def test_loopback_only_and_successful_real_frame(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        status, headers, body = self.request("GET", "/api/frame?width=120&height=36")
        self.assertEqual(status, 200)
        frame = json.loads(body)
        self.assertEqual(len(frame["lines"]), 36)
        self.assertIn(b"CEDAR", body)
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        summary = frame["summary"]
        self.assertEqual(set(summary), {"case_name", "origin", "integrity", "version", "counts"})
        self.assertEqual(summary["case_name"], "CEDAR / 007")
        self.assertEqual(summary["origin"], "synthetic case")
        self.assertEqual(summary["integrity"], "not checked at this revision")
        self.assertEqual(summary["counts"], {"sources": 2, "events": 132, "controls": 3, "filings": 2})
        status, _, body = self.key("v")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["summary"]["integrity"], "passed")

    def test_foreign_host_and_origin_fail_before_token_or_data(self):
        for path in ("/", "/app.js", "/api/frame"):
            for headers in ({"Host": "attacker.example"}, {"Origin": "https://attacker.example"}, {"Origin": "null"}):
                with self.subTest(path=path, headers=headers):
                    status, _, body = self.request("GET", path, headers=headers)
                    self.assertEqual(status, 403)
                    self.assertNotIn(self.token.encode(), body)
                    self.assertNotIn(b"CEDAR", body)

    def test_missing_wrong_nonascii_and_oversize_token_rejected(self):
        for token in (None, "wrong", "caf\u00e9", "x" * 257):
            with self.subTest(token_kind=type(token).__name__):
                status, _, body = self.request("GET", "/api/frame", headers={"X-Preview-Token": token})
                self.assertEqual(status, 403)
                self.assertEqual(json.loads(body), {"error": "request_rejected"})

    def test_token_is_unique_for_separate_server_instance(self):
        other = SERVER.build_server(self.demo["case"], port=0)
        worker = threading.Thread(target=other.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        connection = http.client.HTTPConnection("127.0.0.1", other.server_port, timeout=3)
        try:
            connection.request("GET", "/api/frame", headers={"X-Preview-Token": self.token})
            self.assertEqual(connection.getresponse().status, 403)
        finally:
            connection.close()
            other.shutdown()
            other.server_close()
            worker.join(timeout=3)

    def test_post_requires_exact_origin_and_token(self):
        body = b'{"key":"1","width":120,"height":36}'
        for header in ({"Origin": None}, {"Origin": "https://attacker.example"}, {"Origin": "null"}, {"X-Preview-Token": None}, {"Host": "attacker.example"}):
            with self.subTest(headers=header):
                self.assertEqual(self.request("POST", "/api/key", body, headers=header)[0], 403)

    def test_body_limit_and_transfer_encoding_rejected(self):
        self.assertEqual(self.request("POST", "/api/key", b"x" * 4097)[0], 413)
        self.assertEqual(self.request("POST", "/api/key", b"{}", headers={"Transfer-Encoding": "chunked"})[0], 413)
        self.assertEqual(self.request("POST", "/api/key", b"", headers={"Content-Length": "-1"})[0], 413)
        self.assertEqual(self.request("POST", "/api/key", b"", headers={"Content-Length": "not-a-number"})[0], 400)

    def test_strict_json_and_exact_body_schema(self):
        bodies = [
            b'{"key":"1","key":"2","width":120,"height":36}',
            b'{"key":"1","width":true,"height":36}',
            b'{"key":"1","width":120.0,"height":36}',
            b'{"key":"1","width":120,"height":36,"path":"/etc/passwd"}',
            b'{"key":[],"width":120,"height":36}',
            b'{"key":' + b'[' * 40 + b'0' + b']' * 40 + b',"width":120,"height":36}',
        ]
        for body in bodies:
            with self.subTest(body_shape=len(body)):
                status, _, result = self.request("POST", "/api/key", body)
                self.assertEqual(status, 400)
                self.assertNotIn(b"/etc/passwd", result)
                self.assertNotIn(b"Traceback", result)

    def test_dimensions_bounded_and_invalid_values_rejected(self):
        status, _, body = self.request("GET", "/api/frame?width=999999&height=999999")
        self.assertEqual(status, 200)
        frame = json.loads(body)
        self.assertEqual(len(frame["lines"]), 70)
        self.assertTrue(all(len(row["text"]) <= 220 for row in frame["lines"]))
        self.assertEqual(self.request("GET", "/api/frame?width=secret-canary")[0], 400)

    def test_no_file_shell_upload_or_traversal_endpoint(self):
        for path in ("/etc/passwd", "/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/api/raw", "/api/file?path=/etc/passwd", "/api/shell", "/api/exec", "/api/upload"):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", path)[0], 404)
                self.assertEqual(self.request("POST", path, b"{}")[0], 400)

    def test_shell_text_is_not_executed_by_command_prompt(self):
        sentinel = Path(self.temp.name) / "must-not-exist"
        self.key(":")
        for char in "!touch " + str(sentinel):
            self.key(char)
        status, _, body = self.key("Enter")
        self.assertEqual(status, 200)
        self.assertFalse(sentinel.exists())
        self.assertIn(b"unknown_command_use_help", body)

    def test_server_and_controller_have_no_process_or_dynamic_execution_calls(self):
        for path in (ROOT / "dev/livepreview/server.py", ROOT / "probentium/workbench.py"):
            tree = ast.parse(path.read_text())
            calls = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        calls.add(node.func.id)
                    elif isinstance(node.func, ast.Attribute):
                        calls.add(node.func.attr)
            self.assertFalse(calls & {"eval", "exec", "system", "popen", "Popen", "check_output", "check_call"})


class PreviewProvenanceTests(PreviewHarness, unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.demo = make_demo(self.root / "demo")
        self.start_preview(self.demo["case"])

    def tearDown(self):
        self.stop_preview()
        self.temp.cleanup()

    def assertNoPreview(self, canary):
        for method, path, body in (("GET", "/api/frame", None), ("POST", "/api/key", b'{"key":"2","width":120,"height":36}')):
            status, _, response = self.request(method, path, body)
            self.assertEqual(status, 400)
            self.assertNotIn(canary.encode(), response)
            self.assertNotIn(b"CEDAR", response)

    def test_non_synthetic_case_rejected_at_startup(self):
        case = self.root / "private-case"
        with CaseStore.create(case, "Private case"):
            pass
        with self.assertRaises(ProbentiumError) as caught:
            SERVER.build_server(case, port=0)
        self.assertEqual(caught.exception.code, "preview_requires_synthetic_case")

    def test_added_private_artifact_revokes_live_preview(self):
        canary = "private-actor-canary"
        data = self.root / "private.jsonl"
        data.write_text(json.dumps({"kind": "generic", "timestamp": None, "actor": canary}) + "\n")
        with CaseStore(self.demo["case"]) as case:
            case.ingest(data, "events", "Private source")
        self.assertNoPreview(canary)

    def test_added_private_object_revokes_live_preview(self):
        canary = "private-note-canary"
        with CaseStore(self.demo["case"]) as case:
            case.put_object("note", {"text": canary})
        self.assertNoPreview(canary)

    def test_duplicate_artifact_private_acquisition_label_revokes_live_preview(self):
        canary = "private-acquisition-label-canary"
        with CaseStore(self.demo["case"]) as case:
            case.ingest(self.root / "demo" / "activity.jsonl", "events", canary)
        self.assertNoPreview(canary)

    def test_legitimate_prepare_preserves_synthetic_scope(self):
        before = Workbench(self.demo["case"]).refresh()
        self.key(":")
        for char in "prepare":
            self.key(char)
        status, _, body = self.key("Enter")
        self.assertEqual(status, 200)
        self.assertIn(b"Nothing submitted", body)
        after = Workbench(self.demo["case"]).refresh()
        self.assertTrue(after["synthetic"])
        self.assertEqual(after["counts"]["filings"], before["counts"]["filings"] + 1)


if __name__ == "__main__":
    unittest.main()
