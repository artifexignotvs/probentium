"""Mandata eadem vincula atque nucleus servant."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from probentium.demo import make_demo
from probentium.store import CaseStore


class ExtendedCommandsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.demo = make_demo(self.root / "demo", extended=True)
        self.case = self.demo["case"]
        self.sequence = 0

    def tearDown(self):
        self.tmp.cleanup()

    def invoke(self, *arguments, document=None, expected=0):
        args = list(arguments)
        if document is not None:
            self.sequence += 1
            file = self.root / (str(self.sequence) + ".json")
            file.write_text(json.dumps(document))
            args += ["--input", str(file)]
        result = subprocess.run([sys.executable, "-m", "probentium", "--format", "json", *args], capture_output=True, timeout=45)
        self.assertEqual(result.returncode, expected, result.stderr)
        value = json.loads(result.stdout if result.stdout else result.stderr)
        self.assertEqual(value["schema"], "probentium.cli-result.v1")
        self.assertNotIn("Traceback", result.stderr.decode())
        return value

    def test_child_receipt_binds_real_revision_and_rejects_stale_read(self):
        with CaseStore(self.case) as case:
            revision = case.revision
        request = {"template": "auth_after_failures", "window_us": "100000000", "threshold": 5}
        from probentium.budgets import capabilities
        mode = "strict" if capabilities()["strict_supported"] else "monitored"
        value = self.invoke("correlate", "run", "--case", self.case, "--execution-receipt", "--resource-mode", mode, "--expect-revision", str(revision), document=request)
        receipt = value["data"]
        self.assertEqual(receipt["input_revision"], revision)
        self.assertEqual(receipt["case_revision"], revision)
        self.assertEqual(value["case_revision"], revision)
        self.assertEqual(receipt["resources"]["memory_mode"], capabilities()["memory_mode"])
        failed = self.invoke("correlate", "run", "--case", self.case, "--expect-revision", str(revision - 1), document=request, expected=5)
        self.assertEqual(failed["errors"][0]["code"], "revision_conflict")
        bad = self.root / "limits.json"
        bad.write_text('{"schema":"probentium.analysis-limits.v1","max_events":100001}')
        self.invoke("correlate", "run", "--case", self.case, "--analysis-limits", str(bad), document=request, expected=2)

    def test_new_eu_inputs_deadline_replay_and_typed_packet_roundtrip(self):
        with CaseStore(self.case) as case:
            observation = case.objects("eu.control_observation")[0]
            deadline = case.objects("eu.deadline_evaluation")[0]
            pack = case.objects("eu.legal_pack")[0]
            source = case.sources()[0]["id"]
        self.invoke("governance", "observation-assess", "--case", self.case, "--id", observation["id"])
        self.invoke("reporting", "deadline-replay", "--case", self.case, "--id", deadline["id"])
        self.invoke("reporting", "deadline-status", "--case", self.case, "--id", deadline["id"], document={"as_of":"2026-10-19T00:00:00Z"})
        from tests_r1.test_legalcoverage import catalogue
        cat = self.invoke("legal", "import-catalogue", "--case", self.case, document=catalogue(pack["data"], source))["data"]
        audit = self.invoke("legal", "audit-coverage", "--case", self.case, "--id", pack["id"], "--catalogue", cat["id"], "--as-of", "2026-10-19T00:00:00Z")["data"]
        self.assertFalse(audit["data"]["result"]["legally_verified"])
        self.invoke("legal", "coverage-status", "--case", self.case, "--id", audit["id"], "--as-of", "2026-10-19T00:00:00Z")
        self.invoke("legal", "coverage-replay", "--case", self.case, "--id", audit["id"])
        with CaseStore(self.case) as case:
            service = case.objects("eu.service")[0]
        anchor = {"kind":"obligation_anchor", "data": {
            "logical_id":"synthetic-delivery-cli", "actor":"synthetic-operator",
            "recorded_at":"2026-10-18T14:00:00Z", "basis_refs":[source],
            "rationale":"Synthetic supplied delivery assertion; not an authenticated receipt.", "supersedes":None,
            "service_ref":service["id"], "profile":"cz-nis2-lower", "trigger_kind":"registration_delivery",
            "anchor":"2026-10-18T13:00:00Z", "review_decision":"unreviewed"}}
        saved = self.invoke("governance", "put", "--case", self.case, document=anchor)["data"]
        status = self.invoke("governance", "anchor-status", "--case", self.case, "--id", saved["id"], document={"as_of":"2026-10-19T00:00:00Z"})["data"]
        self.assertFalse(status["legal_status_inferred"])
        self.invoke("governance", "anchor-replay", "--case", self.case, "--id", saved["id"])
        packet = self.root / "case.pbp"
        self.invoke("packet", "export", "--case", self.case, "--output", str(packet))
        self.invoke("packet", "verify", "--input", str(packet))
        restored = self.root / "restored"
        self.invoke("packet", "restore", "--input", str(packet), "--output", str(restored))
        with CaseStore(restored) as case:
            self.assertTrue(case.verify()["ok"])
            self.assertEqual(case.get_object(audit["id"]), audit)

    def test_explicit_resource_policy_survives_resume_and_packet_without_raising_receiver_limits(self):
        from probentium.limits import configured, digest
        isolated = self.root / "policy-case"
        self.invoke("init", str(isolated), "--name", "Synthetic limits")
        source = self.root / "small-source.jsonl"
        source.write_text(''.join(json.dumps({"kind": kind, "timestamp": "2026-10-18T12:00:00Z",
                                             "actor": "synthetic-user"}) + "\n"
                                  for kind in ("auth.failure", "auth.success")))
        policy = configured(max_source_bytes=4096, max_case_bytes=8192, max_import_records=1,
                            max_case_events=10, max_packet_bytes=1048576)
        selected = self.root / "resource-policy.json"
        selected.write_text(json.dumps(policy))
        source_result = self.invoke("ingest", "--case", str(isolated), str(source), "--format", "events",
                                    "--label", "Synthetic", "--resource-policy", str(selected))["data"]
        self.assertEqual(source_result["records_total"], 1)
        self.assertEqual(source_result["state"], "incomplete")
        resumed = self.invoke("resume", "--case", str(isolated), "--id", source_result["parse_run_id"], "--resource-policy", str(selected))["data"]
        self.assertEqual(resumed["records_total"], 2)
        packet = self.root / "policy.pbp"
        exported = self.invoke("packet", "export", "--case", str(isolated), "--output", str(packet), "--resource-policy", str(selected))["data"]
        self.assertEqual(exported["resource_policy_digest"], digest(policy))
        verified = self.invoke("packet", "verify", "--input", str(packet), "--resource-policy", str(selected))["data"]
        self.assertTrue(verified["ok"])
        self.assertEqual(verified["packet_resource_policy"], policy)
        restrictive = {**policy, "max_packet_bytes": 1024}
        selected.write_text(json.dumps(restrictive))
        rejected = self.invoke("packet", "verify", "--input", str(packet), "--resource-policy", str(selected), expected=6)
        self.assertFalse(rejected["data"]["ok"])
        with CaseStore(isolated) as case:
            self.assertTrue(case.verify()["ok"])
            self.assertEqual(case.query_events()["total"], 2)

    def test_unified_graph_cli_and_unknown_extension_gap(self):
        graph = self.invoke("graph", "build", "--case", self.case)["data"]
        with CaseStore(self.case) as case:
            custom = case.put_object("extension_unreviewed", {"synthetic":True})
        report = self.invoke("graph", "impact", "--case", self.case, "--id", graph["id"], document={"changed_ids":[custom["id"]]})
        self.assertIsInstance(report["data"], dict)
        self.assertEqual(self.invoke("verify", "--case", self.case)["data"]["ok"], True)


if __name__ == "__main__":
    unittest.main()
