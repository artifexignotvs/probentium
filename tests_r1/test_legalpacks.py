"""Recensio attestata numquam fit certificatio ficta."""
from copy import deepcopy
import unittest

from probentium import legalpacks as lp
from tests_r1.test_governance import Fixture, pack_fixture, T0, T1, T2, T3


class LegalPackTests(Fixture, unittest.TestCase):
    def review(self, role="legal", **changes):
        return {"actor": "synthetic-" + role, "at": T1, "rationale": "Supplied synthetic review only.",
                "document_refs": [self.source], "role": role, "review_due": T3,
                "independence_attested": True, "attestation": "Synthetic review fixture; no outside reviewer.",
                "reference_cases": [{"id": "vector-1", "input": {"awareness": T0}, "expected": {"status": "manual_review"},
                                     "document_ref": self.source}], **changes}

    def activation(self, **changes):
        return {"actor": "synthetic-owner", "at": T2, "rationale": "Enable operational planning only.", "document_refs": [self.source],
                "mode": "draft_operational", "review_refs": [], "acknowledged_limits": True, **changes}

    def test_import_does_not_activate_or_certify(self):
        status = lp.pack_status(self.case, self.pack["id"], T2)
        self.assertEqual(status["state"], "draft_inactive")
        self.assertEqual(status["currentness"], "currentness_unverified")
        self.assertFalse(status["legally_verified"])

    def test_same_version_different_content_conflicts(self):
        data = pack_fixture(self.source)
        data["rules"][0]["title"] = "Other meaning"
        before = self.case.revision
        self.assertCode("legal_version_content_conflict", lp.import_pack, self.case, data)
        self.assertEqual(self.case.revision, before)

    def test_source_document_hash_and_kind_required(self):
        data = pack_fixture(self.source)
        data["sources"][0]["sha256"] = "0" * 64
        self.assertCode("legal_source_digest_mismatch", lp.import_pack, self.case, data)
        data["sources"][0].update(sha256=self.service["id"], document_ref=self.service["id"])
        self.assertCode("legal_source_digest_mismatch", lp.import_pack, self.case, data)

    def test_executable_code_unknown_fields_and_proposal_rejected(self):
        data = pack_fixture(self.source)
        data["rules"][0]["operator"] = "eval"
        self.assertCode("invalid_governance_enum", lp.validate_pack, data)
        data["rules"][0].update(operator="hours_after", parameters={"anchor": "awareness", "amount": 24}, origin="contextual_proposal")
        self.assertCode("proposal_cannot_execute", lp.validate_pack, data)
        data["rules"][0].update(operator="manual_review", parameters={}, origin="enacted")
        data["sources"][0]["origin"] = "contextual_proposal"
        self.assertCode("proposal_cannot_be_enacted_rule", lp.validate_pack, data)

    def test_reviewer_cannot_override_pack_or_review_self(self):
        self.assertCode("invalid_regulatory_fields", lp.review_pack, self.case, self.pack["id"], self.review(pack_ref=self.service["id"]))
        self.assertCode("pack_author_cannot_independently_review", lp.review_pack, self.case, self.pack["id"], self.review(actor="synthetic-author"))

    def test_review_requires_attached_original_source_bytes(self):
        data = pack_fixture(self.source, "missing-doc")
        data["sources"][0]["document_ref"] = None
        obj = lp.import_pack(self.case, data)
        self.assertCode("legal_source_documents_missing", lp.review_pack, self.case, obj["id"], self.review())

    def test_operational_activation_explicit_and_unverified(self):
        self.assertCode("activation_limits_acknowledgement_required", lp.activate_pack, self.case, self.pack["id"], self.activation(acknowledged_limits=False))
        lp.activate_pack(self.case, self.pack["id"], self.activation())
        status = lp.pack_status(self.case, self.pack["id"], T2)
        self.assertEqual(status["state"], "active_operational")
        self.assertEqual(status["currentness"], "currentness_unverified")
        self.assertTrue(status["offline_new_amendments_unknown"])

    def test_two_reviews_and_expiry_boundary(self):
        legal = lp.review_pack(self.case, self.pack["id"], self.review())
        self.assertCode("legal_and_technical_review_required", lp.activate_pack, self.case, self.pack["id"], self.activation(mode="review_attested", review_refs=[legal["id"]]))
        tech = lp.review_pack(self.case, self.pack["id"], self.review("technical"))
        lp.activate_pack(self.case, self.pack["id"], self.activation(mode="review_attested", review_refs=[legal["id"], tech["id"]]))
        self.assertEqual(lp.pack_status(self.case, self.pack["id"], T3)["currentness"], "review_attested_current")
        later = lp.pack_status(self.case, self.pack["id"], "2026-10-18T13:00:01Z")
        self.assertEqual(later["currentness"], "currentness_unverified")
        self.assertFalse(later["legally_verified"])
        self.assertEqual(later["review_origin"], "supplied_attestations_only")

    def test_review_for_other_pack_or_stale_cannot_activate(self):
        review = lp.review_pack(self.case, self.pack["id"], self.review())
        new = lp.import_pack(self.case, pack_fixture(self.source, "2"))
        self.assertCode("activation_review_mismatch_or_stale", lp.activate_pack, self.case, new["id"], self.activation(review_refs=[review["id"]]))
        self.assertCode("activation_review_mismatch_or_stale", lp.activate_pack, self.case, self.pack["id"], self.activation(at="2026-10-18T13:00:01Z", review_refs=[review["id"]]))

    def test_new_version_requires_activation_and_old_history_survives(self):
        old = lp.activate_pack(self.case, self.pack["id"], self.activation())
        new = lp.import_pack(self.case, pack_fixture(self.source, "2"))
        self.assertEqual(lp.pack_status(self.case, new["id"], T3)["state"], "draft_inactive")
        active = lp.activate_pack(self.case, new["id"], self.activation(at=T3))
        self.assertEqual(active["data"]["previous_pack_ref"], self.pack["id"])
        self.assertIn("templates", active["data"]["change_impact"]["changed"])
        self.assertEqual(lp.pack_status(self.case, self.pack["id"], T3)["state"], "draft_inactive")
        self.assertEqual(self.case.get_object(old["id"]), old)
        self.assertCode("activation_time_reversed", lp.activate_pack, self.case, self.pack["id"], self.activation(at=T0))

    def test_tampered_impact_is_rejected(self):
        obj = lp.activate_pack(self.case, self.pack["id"], self.activation())
        data = deepcopy(obj["data"])
        data["change_impact"]["requires_review"] = False
        self.assertCode("invalid_pack_change_impact", lp.validate_stored, "eu.legal_activation", data)

    def test_czech_drafts_have_separate_primary_source_mapping(self):
        for regime in ("higher", "lower", "digital"):
            pack = lp.draft_czech_pack(regime)
            self.assertEqual(lp.validate_pack(pack)["status"], "draft")
            self.assertTrue(all(source["document_ref"] is None for source in pack["sources"]))
            self.assertTrue(all(rule["operator"] == "manual_review" for rule in pack["rules"]))
            ids = {rule["id"] for rule in pack["rules"]}
            self.assertIn("CZ-264-S6", ids)
            self.assertIn("CZ-264-S71", ids)
            self.assertIn("CZ-264-S18", ids)
            self.assertGreater(len(ids), 25)
        higher, lower = lp.draft_czech_pack("higher"), lp.draft_czech_pack("lower")
        self.assertIn("CZ-409-S27", {r["id"] for r in higher["rules"]})
        self.assertIn("CZ-410-S14", {r["id"] for r in lower["rules"]})


if __name__ == "__main__":
    unittest.main()
