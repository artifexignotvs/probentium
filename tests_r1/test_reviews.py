"""Consensus vetus novam revisionem non approbat."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from probentium.contracts import ProbentiumError
from probentium.store import CaseStore
from probentium.signatures import generate_key
from probentium import reviews


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key = self.root / "key"
        self.public = generate_key(self.key)
        self.decision = reviews.create_decision("1" * 64, 2, "2" * 64, "3" * 64, self.public["key_id"], "approve", reviews.rationale_digest("Reviewed synthetic evidence."))
        self.signature = reviews.sign_review(self.decision, self.key)

    def tearDown(self):
        self.temp.cleanup()

    def trust(self):
        return {"schema": "probentium.trust.v1", "keys": [{"key_id": self.public["key_id"], "alias": "reviewer", "status": "active", "reason": None}]}

    def test_signature_remains_valid_when_new_revision_no_longer_matches(self):
        verified = reviews.verify_review(self.decision, self.signature)
        self.assertEqual(verified["signature_status"], "valid")
        self.assertEqual(verified["revision_binding"], "unchecked")
        self.assertTrue(reviews.review_applicability(self.decision, 2, "2" * 64, "3" * 64)["applies_to_current_revision"])
        changed = reviews.review_applicability(self.decision, 3, "2" * 64, "3" * 64)
        self.assertFalse(changed["applies_to_current_revision"])
        self.assertEqual(reviews.verify_review(self.decision, self.signature)["signature_status"], "valid")

    def test_missing_references_recorded_without_approval(self):
        with CaseStore.create(self.root / "case") as case:
            result = reviews.import_review(case, self.decision, self.signature, trust_store=self.trust())
            self.assertEqual(result["status"], "pending_references")
            self.assertEqual(result["approval_effect"], "none")
            self.assertEqual(len(case.objects("review_decision")), 1)
            self.assertTrue(case.verify()["ok"])

    def test_trust_and_current_reference_binding_both_required(self):
        current = lambda case, decision: {"status": "current", "missing": []}
        historical = lambda case, decision: {"status": "historical", "missing": []}
        with CaseStore.create(self.root / "case") as case:
            unknown = reviews.import_review(case, self.decision, self.signature, reference_resolver=current)
            self.assertEqual(unknown["approval_effect"], "none")
            trusted = reviews.import_review(case, self.decision, self.signature, trust_store=self.trust(), reference_resolver=current)
            self.assertEqual(trusted["approval_effect"], "eligible_for_current_review")
            old = reviews.import_review(case, self.decision, self.signature, trust_store=self.trust(), reference_resolver=historical)
            self.assertEqual(old["approval_effect"], "none")

    def test_bad_binding_and_stale_revision_do_not_write(self):
        with CaseStore.create(self.root / "case") as case:
            for resolver in (lambda c, d: {"status": "current", "missing": ["evaluation_digest"]}, lambda c, d: {"status": "approved", "missing": []}):
                with self.assertRaises(ProbentiumError):
                    reviews.import_review(case, self.decision, self.signature, reference_resolver=resolver)
            with self.assertRaises(ProbentiumError):
                reviews.import_review(case, self.decision, self.signature, expected_revision=9)
            self.assertEqual(case.revision, 0)

    def test_signature_context_key_and_rationale_bounds(self):
        wrong = self.root / "wrong"
        generate_key(wrong)
        with self.assertRaises(ProbentiumError):
            reviews.sign_review(self.decision, wrong)
        with self.assertRaises(ProbentiumError):
            reviews.verify_review({**self.decision, "disposition": "reject"}, self.signature)
        with self.assertRaises(ProbentiumError):
            reviews.rationale_digest("x" * 65537)
        with self.assertRaises(ProbentiumError):
            reviews.rationale_digest("\ud800")
        self.assertEqual(reviews.rationale_digest("abc"), hashlib.sha256(b"abc").hexdigest())

    def test_authorized_missing_evidence_cannot_activate_current_approval(self):
        with CaseStore.create(self.root / "case") as case:
            partial = {"ok": True, "completeness": "partial", "authorized_unavailable": [{"artifact_id": "a" * 64}]}
            with patch.object(case, "verify", return_value=partial):
                result = reviews.import_review(case, self.decision, self.signature, trust_store=self.trust(),
                            reference_resolver=lambda c, d: {"status": "current", "missing": []})
            self.assertEqual(result["status"], "pending_references")
            self.assertEqual(result["binding"]["missing"], ["raw_evidence"])
            self.assertEqual(result["approval_effect"], "none")
            self.assertEqual(result["verification"]["signature_status"], "valid")

    def test_stored_review_signature_is_rechecked_without_inheriting_trust(self):
        import copy
        with CaseStore.create(self.root / "case") as case:
            stored = reviews.import_review(case, self.decision, self.signature, trust_store=self.trust(),
                       reference_resolver=lambda c, d: {"status": "current", "missing": []})["stored"]["data"]
        fresh = reviews.validate_stored(stored)
        self.assertEqual(fresh["key_trust"], "unknown")
        self.assertEqual(fresh["revision_binding"], "unchecked")
        tampered = copy.deepcopy(stored)
        tampered["decision"]["disposition"] = "reject"
        with self.assertRaises(ProbentiumError):
            reviews.validate_stored(tampered)
        tampered = copy.deepcopy(stored)
        tampered["binding"] = {"status": "historical", "missing": []}
        with self.assertRaises(ProbentiumError):
            reviews.validate_stored(tampered)


if __name__ == "__main__":
    unittest.main()
