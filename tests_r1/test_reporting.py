"""Exemplaria parata, missa et recepta distinguuntur."""
from copy import deepcopy
import unittest

from probentium import reporting as r, governance as g
from probentium.contracts import ProbentiumError
from tests_r1.test_governance import Fixture, T0, T1, T2, T3


class ReportingTests(Fixture, unittest.TestCase):
    def track_input(self, **changes):
        return {"id": "incident-a", "title": "Synthetic incident", "profile": "dora", "incident_id": "synthetic-incident",
                "service_refs": [self.service["id"]], "recipient": "synthetic authority", "role": "operator",
                "qualification": {"status": "unknown", "basis_refs": [], "reason": "Unknown significance", "reviewer": "synthetic-reviewer"},
                "pack_ref": self.pack["id"], "template_id": "incident", "awareness_refs": {}, "supersedes": None,
                "actor": "synthetic-operator", "recorded_at": T1, "rationale": "Synthetic scenario only.", **changes}

    def track(self, anchors=None, **changes):
        data = self.track_input(**changes)
        first = r.create_track(self.case, data)
        if anchors is None:
            return first
        refs = {}
        for name, anchor in anchors.items():
            refs[name] = g.put_record(self.case, "awareness", {**self.common("anchor-" + name), "track_ref": first["id"],
                "event_type": name, "anchor": anchor, "actor_role": "incident analyst", "review_decision": "confirmed"})["id"]
        data.update(supersedes=first["id"], awareness_refs=refs)
        return r.create_track(self.case, data)

    def filing(self, fields=None, **changes):
        tr = self.track(**changes)
        return r.prepare(self.case, tr["id"], fields or [], T2)

    def audit(self, **changes):
        return {"actor": "synthetic-reviewer", "at": T3, "rationale": "Synthetic fixture; supplied statement only.", "document_refs": [self.source], **changes}

    def approval(self, obj, **changes):
        return r.approve(self.case, obj["id"], {**self.audit(), "role": "incident manager", "decision": "approved", "field_ids": ["scope"], **changes})

    def submission(self, obj, **changes):
        return r.record_submission(self.case, obj["id"], {**self.audit(), "sent_at": T3, "channel": "synthetic record only",
            "recipient": "synthetic authority", "external_id": "synthetic-id-1", "approval_ref": None,
            "evidence_strength": "human_asserted", **changes})

    def receipt(self, obj, **changes):
        return r.link_receipt(self.case, obj["id"], {**self.audit(), "strength": "delivery_only", "external_submission_id": None,
            "content_digest": None, "binding_attestation": "Synthetic delivery receipt; no content binding.", **changes})

    def test_prepare_freezes_revision_and_unknown_does_not_become_zero(self):
        obj = self.filing()
        data = obj["data"]
        self.assertEqual(data["case_revision"], obj["revision"] - 1)
        self.assertEqual(data["snapshot"]["fields"][0]["value"], None)
        self.assertEqual(data["unknown_tasks"], [{"field": "scope", "task": "supply_or_review_missing_fact"}])
        self.assertEqual(r.filing_status(self.case, obj["id"])["state"], "prepared")
        self.assertFalse(data["pack_state"]["legally_verified"])
        old = deepcopy(obj)
        g.put_record(self.case, "service", self.service_input("new-service"))
        self.assertEqual(self.case.get_object(obj["id"]), old)

    def test_required_basis_reference_unknown_field_and_foreign_key(self):
        tr = self.track()
        self.assertCode("unknown_template_field", r.prepare, self.case, tr["id"], [{"id": "extra"}], T2)
        self.assertCode("eu_reference_missing", r.prepare, self.case, tr["id"], [{"id": "scope", "value": "unknown source", "basis": "source_backed", "refs": ["0" * 64]}], T2)
        self.assertCode("filing_cutoff_precedes_track", r.prepare, self.case, tr["id"], [], T0)
        self.assertCode("invalid_regulatory_fields", r.prepare, self.case, tr["id"], [{"id": "scope", "verified": True}], T2)

    def test_awareness_is_explicit_and_contested_is_unknown(self):
        tr = self.track({"awareness": T0, "classification": T1})
        result = r.deadlines(self.case, tr["id"], T2)
        initial = next(x for x in result["deadlines"] if x["stage"] == "initial")
        self.assertEqual(initial["operational_target"], "2026-10-18T15:00:00Z")
        self.assertIsNone(initial["legal_deadline"])
        self.assertFalse(result["obligation_determined"])
        self.assertEqual(result["anchor_review"]["awareness"], "confirmed")
        a = g.get_record(self.case, tr["data"]["awareness_refs"]["awareness"])
        data = {k: v for k, v in a["data"].items() if k not in {"schema", "kind", "legal_certification"}}
        data.update(supersedes=a["id"], review_decision="contested")
        corrected = g.put_record(self.case, "awareness", data)
        track_data = {k: v for k, v in tr["data"].items() if k not in {"schema", "kind"}}
        track_data.update(supersedes=tr["id"], awareness_refs={"awareness": corrected["id"], "classification": tr["data"]["awareness_refs"]["classification"]})
        latest = r.create_track(self.case, track_data)
        initial = r.deadlines(self.case, latest["id"], T2)["deadlines"][0]
        self.assertIsNone(initial["operational_target"])

    def test_wrong_awareness_kind_and_cross_track_rejected(self):
        self.assertCode("reporting_template_recipient_mismatch", r.create_track, self.case, self.track_input(recipient="other recipient"))
        self.assertCode("awareness_track_mismatch", r.create_track, self.case, self.track_input(awareness_refs={"awareness": self.service["id"]}))
        first = self.track()
        aw = g.put_record(self.case, "awareness", {**self.common("aw"), "track_ref": first["id"], "event_type": "awareness",
             "anchor": T0, "actor_role": "analyst", "review_decision": "confirmed"})
        self.assertCode("awareness_track_mismatch", r.create_track, self.case, self.track_input(id="other", awareness_refs={"awareness": aw["id"]}))

    def test_approval_does_not_mark_submission(self):
        obj = self.filing()
        approval = self.approval(obj)
        status = r.filing_status(self.case, obj["id"])
        self.assertEqual(status["state"], "prepared")
        self.assertEqual(status["approval_refs"], [approval["id"]])
        self.assertCode("approval_field_not_in_snapshot", self.approval, obj, field_ids=["unrelated"])

    def test_prepared_submission_receipt_have_separate_meanings(self):
        obj = self.filing()
        approval = self.approval(obj)
        submission = self.submission(obj, approval_ref=approval["id"])
        self.assertEqual(r.filing_status(self.case, obj["id"])["state"], "submission_recorded")
        self.receipt(submission)
        status = r.filing_status(self.case, obj["id"])
        self.assertEqual(status["state"], "receipt_linked")
        self.assertEqual(status["content_binding"], "not_established")
        self.assertEqual(status["legal_acceptance"], "not_determined")

    def test_receipt_strength_and_exact_digest(self):
        obj = self.filing()
        sub = self.submission(obj)
        self.assertCode("delivery_receipt_cannot_bind_content", self.receipt, sub, content_digest=obj["data"]["snapshot"]["digest"])
        self.assertCode("receipt_content_digest_mismatch", self.receipt, sub, strength="content_digest", content_digest="0" * 64)
        self.assertCode("receipt_external_id_mismatch", self.receipt, sub, strength="submission_id", external_submission_id="wrong")
        rec = self.receipt(sub, strength="content_digest", content_digest=obj["data"]["snapshot"]["digest"])
        self.assertFalse(rec["data"]["binding_verified"])
        self.assertEqual(r.filing_status(self.case, obj["id"])["content_binding"], "attested_only")

    def test_prior_version_approval_cannot_approve_new_snapshot(self):
        old = self.filing()
        approval = self.approval(old)
        new = r.prepare(self.case, old["data"]["track_ref"], [{"id": "scope", "value": "Updated", "basis": "human_attested", "reason": "Revised assessment."}], T2)
        self.assertCode("submission_approval_mismatch", self.submission, new, approval_ref=approval["id"])

    def test_submission_time_recipient_and_document_guards(self):
        obj = self.filing()
        self.assertCode("submission_recipient_or_time_mismatch", self.submission, obj, recipient="other authority")
        self.assertCode("submission_recipient_or_time_mismatch", self.submission, obj, sent_at=T1)
        self.assertCode("submission_in_future_of_attestation", self.submission, obj, sent_at="2026-10-18T14:00:00Z")
        self.assertCode("reporting_document_required", self.submission, obj, document_refs=[])

    def test_correction_preserves_submission_and_dependency_path(self):
        old = self.filing([{"id": "scope", "basis": "source_backed", "value": "original", "refs": [self.service["id"]]}])
        sub = self.submission(old)
        new = r.prepare(self.case, old["data"]["track_ref"], [{"id": "scope", "basis": "contested", "value": "contested", "refs": [self.source], "reason": "Synthetic counter-evidence."}], T3)
        impact = r.correction_impact(self.case, old["id"], new["id"], [self.source])
        self.assertEqual(impact["data"]["changes"][0]["reason"], "value_changed")
        self.assertEqual(impact["data"]["old_submission_refs"], [sub["id"]])
        self.assertEqual(impact["data"]["causal_paths"][0]["via_refs"], [self.source, self.service["id"]])
        self.assertFalse(impact["data"]["history_rewritten"])
        tampered = deepcopy(impact["data"])
        tampered["changes"][0]["reason"] = "evidence_basis_changed"
        self.assertCode("correction_reason_mismatch", r.validate_stored, "eu.correction_impact", tampered)
        self.assertEqual(self.case.get_object(sub["id"])["data"]["snapshot_digest"], old["data"]["snapshot"]["digest"])
        self.assertEqual(r.filing_status(self.case, new["id"])["state"], "prepared")

    def test_cross_track_correction_rejected(self):
        old = self.filing()
        other = self.track(id="other-track")
        new = r.prepare(self.case, other["id"], [], T2)
        self.assertCode("filing_tracks_differ", r.correction_impact, self.case, old["id"], new["id"])

    def test_snapshot_mutation_and_false_legal_verification_rejected(self):
        obj = self.filing()
        data = deepcopy(obj["data"])
        data["snapshot"]["fields"][0]["value"] = 0
        with self.assertRaises(ProbentiumError):
            r.validate_stored("eu.filing_snapshot", data)
        data = deepcopy(obj["data"])
        data["pack_state"]["legally_verified"] = True
        self.assertCode("filing_cannot_certify_law", r.validate_stored, "eu.filing_snapshot", data)
        data = deepcopy(obj["data"])
        data["dependency_refs"] = []
        self.assertCode("filing_dependency_incomplete", r.validate_stored, "eu.filing_snapshot", data)

    def test_synthetic_exercise_is_not_submitted_or_externally_reviewed(self):
        self.assertCode("synthetic_acknowledgement_required", r.build_demonstration, self.case)
        demo = r.build_demonstration(self.case, acknowledged_synthetic=True)
        self.assertEqual(demo["submission_status"], "not_submitted")
        self.assertEqual(len(demo["filing_refs"]), 2)
        latest = self.case.get_object(demo["filing_refs"][1])["data"]
        fields = {f["id"]: f for f in latest["snapshot"]["fields"]}
        self.assertEqual(fields["event_count"]["value"], self.case.query_events()["total"])
        self.assertIsNone(fields["affected_people"]["value"])
        self.assertEqual(self.case.objects("eu.legal_review"), [])
        self.assertEqual(self.case.objects("eu.submission_record"), [])
        self.assertCode("regulatory_demonstration_exists", r.build_demonstration, self.case, acknowledged_synthetic=True)


if __name__ == "__main__":
    unittest.main()
