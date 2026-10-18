"""Consilium deletionis copias communes et residua aperte numerat."""
from pathlib import Path
import tempfile
import unittest

from probentium import retention
from probentium.contracts import ProbentiumError
from probentium.store import CaseStore


POLICY = {"purpose": "Synthetic investigation closed", "data_category": "Synthetic event bytes",
          "retention_basis": "Internal exercise policy, not a legal conclusion", "review_at": "2026-10-18T00:00:00Z"}


class RetentionInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "synthetic.jsonl"
        self.source.write_bytes(b'{"kind":"generic","timestamp":null}\n')
        self.case = CaseStore.create(self.root / "case")
        self.artifact = self.case.ingest(self.source, "events", "Synthetic")

    def tearDown(self):
        self.case.close()
        self.temp.cleanup()

    def plan(self, policy=None):
        return retention.plan(self.case, [self.artifact["id"]], "synthetic-operator", "Close exercise",
                              "2026-10-18T00:00:00Z", policy=POLICY if policy is None else policy)

    def test_shared_blob_copies_inventory_approval_removal_and_replay_loss(self):
        self.case.ingest(self.source, "events", "Second acquisition of same bytes")
        plan = self.plan()
        self.assertEqual(plan["data"]["schema"], "probentium.retention-plan.v2")
        row = plan["data"]["removal_inventory"]["artifacts"][0]
        self.assertEqual((row["acquisitions"], row["records"], row["events"], row["parse_runs"]), (2, 1, 1, 1))
        self.assertIn("normalized_events", plan["data"]["removal_inventory"]["retained_derived_data"])
        self.assertEqual(plan["data"]["removal_inventory"]["physical_erasure"], "not_guaranteed")
        approval = retention.approve(self.case, plan["id"], "synthetic-reviewer", "Scope acknowledged")
        result = retention.execute(self.case, plan["id"], approval["id"], as_of="2026-10-19T00:00:00Z")
        self.assertFalse(result["storage_wipe_guaranteed"])
        check = self.case.verify()
        self.assertEqual((check["ok"], check["exit_code"]), (True, 3))
        self.assertEqual(self.case.query_events()["total"], 1)
        repeated = retention.execute(self.case, plan["id"], approval["id"], as_of="2026-10-19T00:00:00Z")
        self.assertEqual(result["tombstone_id"], repeated["tombstone_id"])

    def test_new_shared_acquisition_requires_replanning_before_approval_or_delete(self):
        for stage in ("approve", "execute"):
            with self.subTest(stage=stage):
                plan = self.plan()
                approval = retention.approve(self.case, plan["id"], "synthetic-reviewer", "Scope acknowledged")
                self.case.ingest(self.source, "events", "New shared acquisition")
                with self.assertRaisesRegex(ProbentiumError, "retention_inventory_changed_replan_required"):
                    if stage == "approve":
                        retention.approve(self.case, plan["id"], "synthetic-reviewer", "Scope acknowledged")
                    else:
                        retention.execute(self.case, plan["id"], approval["id"], as_of="2026-10-19T00:00:00Z")
                self.assertTrue(self.case._blob_present(self.artifact["id"]))

    def test_reacquisition_invalidates_old_absence_authorization_and_allows_a_new_plan(self):
        plan = self.plan()
        approval = retention.approve(self.case, plan["id"], "synthetic-reviewer", "Scope acknowledged")
        retention.execute(self.case, plan["id"], approval["id"], as_of="2026-10-19T00:00:00Z")
        self.case.ingest(self.source, "events", "Reacquired bytes")
        self.assertEqual(retention.authorized_unavailable(self.case), {})
        path = self.case.path / "blobs" / (self.artifact["id"] + ".bin")
        path.unlink()
        self.assertEqual(self.case.verify()["exit_code"], 4)
        self.case.ingest(self.source, "events", "Recovered reacquisition")
        with self.assertRaisesRegex(ProbentiumError, "retention_inventory_changed_replan_required"):
            retention.execute(self.case, plan["id"], approval["id"], as_of="2026-10-19T00:00:00Z")
        new_plan = self.plan()
        new_approval = retention.approve(self.case, new_plan["id"], "synthetic-reviewer", "New acquisition acknowledged")
        result = retention.execute(self.case, new_plan["id"], new_approval["id"], as_of="2026-10-19T00:00:00Z")
        self.assertEqual(self.case.verify()["exit_code"], 3)
        self.assertEqual(retention.authorized_unavailable(self.case), {self.artifact["id"]: result["tombstone_id"]})

    def test_unknown_policy_fields_and_unexpected_missing_bytes_fail_closed(self):
        for policy in ({**POLICY, "secret_override": True}, {k: v for k, v in POLICY.items() if k != "review_at"}, {**POLICY, "review_at": "tomorrow"}):
            with self.assertRaises(ProbentiumError):
                self.plan(policy)
        plan = self.plan()
        approval = retention.approve(self.case, plan["id"], "synthetic-reviewer", "Scope acknowledged")
        (self.case.path / "blobs" / (self.artifact["id"] + ".bin")).unlink()
        self.assertEqual(self.case.verify()["exit_code"], 4)
        with self.assertRaisesRegex(ProbentiumError, "retention_integrity_failed"):
            retention.execute(self.case, plan["id"], approval["id"], as_of="2026-10-19T00:00:00Z")
