"""Catalogus fictus testes structurae praebet, non iudicium iuris."""
from copy import deepcopy
import unittest

from probentium import governance as g, legalpacks as lp
from probentium.legalcoverage import compute_coverage, validate_catalogue, validate_stored
from probentium.contracts import ProbentiumError, object_digest
from tests_r1.test_governance import Fixture, T0, T1, T2, T3


def catalogue(pack, source):
    rule = pack["rules"][0]
    return {"schema": "probentium.eu.v1", "kind": "requirement_catalogue", "id": "synthetic-catalogue", "version": "1",
            "jurisdiction": pack["jurisdiction"], "regime": pack["regime"], "author": "synthetic-author", "recorded_at": T1,
            "document_refs": [source], "completeness_claim": "partial", "review_status": "unverified",
            "sources": [{key: value for key, value in pack["sources"][0].items() if key != "title"}],
            "requirements": [{"id": "synthetic-clause", "source_id": rule["source_id"], "provision": rule["provision"],
                "effective_from": pack["effective_from"], "applicable_from": pack["applicable_from"], "branches": [
                    {"id": "ordinary", "condition": rule["condition"], "rule_ids": [rule["id"]], "evidence": rule["evidence"], "trigger_kind": None}]}]}


class CoverageTests(Fixture, unittest.TestCase):
    def test_internal_sources_do_not_become_legal_completeness(self):
        data = catalogue(self.pack["data"], self.source)
        result = compute_coverage(self.pack["data"], data)
        self.assertEqual(result["status"], "gaps")
        self.assertIn("source_not_enacted", result["rows"][0]["issues"])
        self.assertFalse(result["evidence_reuse_implies_equivalence"])
        self.assertFalse(result["legally_verified"])
        self.assertEqual(result["catalogue_completeness"], "supplied_claim_not_verified")

    def test_missing_branch_condition_evidence_trigger_and_dates_are_separate_gaps(self):
        data = catalogue(self.pack["data"], self.source)
        req = data["requirements"][0]; branch = req["branches"][0]
        req.update(effective_from="2026-02-01", applicable_from=None)
        branch.update(condition="Additional conditional branch", evidence=["absent evidence type"], trigger_kind="registration_delivery")
        req["branches"].append({**deepcopy(branch), "id": "transitional", "rule_ids": ["missing-rule"]})
        result = compute_coverage(self.pack["data"], data)
        issues = result["rows"][0]["issues"]
        for code in ("condition_mismatch", "evidence_expectation_missing", "trigger_mapping_missing", "conflicting_effective_from", "date_expectation_unknown"):
            self.assertIn(code, issues)
        self.assertIn("missing_clause_or_branch", result["rows"][1]["issues"])
        self.assertEqual(result["branches"], 2)
        self.assertEqual(result["matched_branches"], 0)

    def test_even_exact_declared_enacted_mapping_is_only_structural(self):
        pack = deepcopy(self.pack["data"])
        pack["sources"][0]["origin"] = "enacted"; pack["rules"][0]["origin"] = "enacted"
        result = compute_coverage(pack, catalogue(pack, self.source))
        self.assertEqual(result["status"], "structural_match_only")
        self.assertEqual(result["matched_branches"], 1)
        self.assertFalse(result["legally_verified"])
        self.assertEqual(result["review_status"], "unverified")

    def test_source_identity_and_proposal_cannot_hide_in_shared_evidence(self):
        data = catalogue(self.pack["data"], self.source)
        data["sources"][0].update(sha256="0" * 64, origin="contextual_proposal")
        issues = compute_coverage(self.pack["data"], data)["rows"][0]["issues"]
        self.assertIn("source_identity_mismatch", issues)
        self.assertIn("source_not_enacted", issues)
        self.assertIn("rule_origin_mismatch", issues)

    def test_closed_schema_and_duplicate_branches_reject(self):
        original = catalogue(self.pack["data"], self.source)
        mutations = (lambda d: d.update(review_status="verified"), lambda d: d.update(execute="code"),
                     lambda d: d["requirements"][0]["branches"].append(deepcopy(d["requirements"][0]["branches"][0])),
                     lambda d: d["requirements"][0]["branches"][0].update(trigger_kind="unknown-auto"),
                     lambda d: d["requirements"][0].update(effective_from="2026-02-30"))
        for mutate in mutations:
            supplied = deepcopy(original); mutate(supplied)
            with self.assertRaises(ProbentiumError):
                validate_catalogue(supplied)

    def test_immutable_catalogue_version_conflict_and_missing_basis(self):
        data = catalogue(self.pack["data"], self.source)
        obj = lp.import_catalogue(self.case, data)
        self.assertEqual(obj["data"], data)
        data["requirements"][0]["branches"][0]["condition"] = "Different condition"
        self.assertCode("catalogue_version_content_conflict", lp.import_catalogue, self.case, data)
        data["version"] = "2"; data["document_refs"] = ["0" * 64]
        self.assertCode("eu_reference_missing", lp.import_catalogue, self.case, data)

    def test_snapshot_replays_and_new_catalogue_stales_without_rewriting(self):
        supplied = catalogue(self.pack["data"], self.source)
        obj = lp.import_catalogue(self.case, supplied); revision = self.case.revision
        audit = lp.audit_coverage(self.case, self.pack["id"], obj["id"], T2, expected_revision=revision)
        self.assertEqual(lp.replay_coverage(self.case, audit["id"])["status"], "replayed")
        self.assertEqual(lp.coverage_status(self.case, audit["id"], T3)["state"], "current_for_recorded_inputs")
        self.assertCode("revision_conflict", lp.audit_coverage, self.case, self.pack["id"], obj["id"], T2, expected_revision=revision)
        supplied.update(version="2", recorded_at=T3)
        supplied["requirements"][0]["branches"].append({"id": "additional", "condition": "Unmapped branch", "rule_ids": [], "evidence": [], "trigger_kind": "registration_delivery"})
        lp.import_catalogue(self.case, supplied)
        self.assertIn("newer_requirement_catalogue_available", lp.coverage_status(self.case, audit["id"], T3)["reasons"])
        self.assertEqual(lp.replay_coverage(self.case, audit["id"])["status"], "replayed")
        self.assertEqual(self.case.get_object(audit["id"]), audit)

    def test_payload_forgery_and_future_revision_are_detected(self):
        cat = lp.import_catalogue(self.case, catalogue(self.pack["data"], self.source))
        audit = lp.audit_coverage(self.case, self.pack["id"], cat["id"], T2)
        broken = deepcopy(audit["data"]); broken["result"]["legally_verified"] = True
        self.assertCode("coverage_cannot_certify_law", validate_stored, audit["kind"], broken)
        broken = deepcopy(audit["data"]); broken["pack_digest"] = "0" * 64
        saved = self.case.put_object("eu.legal_coverage_audit", broken)
        self.assertCode("coverage_replay_mismatch", lp.replay_coverage, self.case, saved["id"])
        broken = deepcopy(audit["data"]); broken["case_revision"] = self.case.revision + 100
        saved = self.case.put_object("eu.legal_coverage_audit", broken)
        self.assertCode("coverage_snapshot_revision_invalid", lp.replay_coverage, self.case, saved["id"])

    def test_registration_delivery_and_effectivity_are_distinct_typed_assertions(self):
        def supplied(identifier, trigger, anchor=T0):
            return {**self.common(identifier), "service_ref": self.service["id"], "profile": "cz-nis2-lower",
                    "trigger_kind": trigger, "anchor": anchor, "review_decision": "unreviewed"}
        delivery = g.put_record(self.case, "obligation_anchor", supplied("delivery", "registration_delivery"))
        decision = g.put_record(self.case, "obligation_anchor", supplied("decision", "registration_decision", None))
        effectivity = g.put_record(self.case, "obligation_anchor", supplied("effectivity", "law_effective", "2027-01-01T00:00:00Z"))
        self.assertEqual(g.obligation_anchor_status(self.case, decision["id"], T2)["trigger_status"], "trigger_status_unknown")
        self.assertFalse(g.obligation_anchor_status(self.case, effectivity["id"], T2)["legal_status_inferred"])
        corrected = supplied("delivery", "registration_delivery", "2026-10-17T10:00:00Z")
        corrected.update(supersedes=delivery["id"], recorded_at=T3)
        new = g.put_record(self.case, "obligation_anchor", corrected)
        self.assertEqual(g.obligation_anchor_status(self.case, delivery["id"], T3)["state"], "superseded")
        self.assertEqual(g.replay_obligation_anchor(self.case, new["id"])["status"], "record_bindings_checked")
        corrected.update(supersedes=new["id"], trigger_kind="registration_decision")
        self.assertCode("obligation_anchor_domain_changed", g.put_record, self.case, "obligation_anchor", corrected)


if __name__ == "__main__":
    unittest.main()
