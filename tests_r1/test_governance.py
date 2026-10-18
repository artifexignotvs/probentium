"""Exempla ficta fines probationis demonstrant."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from probentium.contracts import ProbentiumError
from probentium.store import CaseStore
from probentium import governance as g, legalpacks as lp

T0 = "2026-10-18T10:00:00Z"
T1 = "2026-10-18T11:00:00Z"
T2 = "2026-10-18T12:00:00Z"
T3 = "2026-10-18T13:00:00Z"
PERIOD = {"start": T0, "end": T1}


def pack_fixture(source, version="1"):
    return {"schema": g.SCHEMA, "kind": "legal_pack", "id": "synthetic-procedure", "version": version,
            "jurisdiction": "CZ", "regime": "synthetic-test", "roles": ["operator"], "author": "synthetic-author",
            "status": "draft", "effective_from": "2026-01-01", "applicable_from": "2026-01-01", "source_checked_at": T0,
            "sources": [{"id": "procedure", "title": "Synthetic procedure, not legal advice", "url": "https://example.invalid/procedure",
                         "sha256": source, "document_ref": source, "origin": "internal"}],
            "rules": [{"id": "restore", "source_id": "procedure", "provision": "synthetic 1", "title": "Recovery test",
                       "origin": "internal", "condition": "Synthetic service only", "evidence": ["restoration observation"],
                       "operator": "manual_review", "parameters": {}}], "calendars": [],
            "templates": [{"id": "incident", "version": version, "recipient": "synthetic authority", "stage": "initial",
                           "source_ids": ["procedure"], "fields": [{"id": "scope", "required": True, "allow_unknown": True},
                           {"id": "count", "required": False, "allow_unknown": True}]}],
            "limitations": ["Synthetic fixture; no legal certification."]}


class Fixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.case = CaseStore.create(self.root / "case", "Synthetic governance case")
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.case.close)
        path = self.root / "procedure.jsonl"
        path.write_text('{"kind":"test.observation","timestamp":"2026-10-18T10:00:00Z","actor":"synthetic-operator"}\n')
        self.source = self.case.ingest(path, "events", "Synthetic procedure")["id"]
        self.pack = lp.import_pack(self.case, pack_fixture(self.source))
        self.service = g.put_record(self.case, "service", self.service_input("payments"))

    def common(self, logical_id, **changes):
        return {"logical_id": logical_id, "actor": "synthetic-operator", "recorded_at": T1,
                "basis_refs": [self.source], "rationale": "Synthetic test assertion.", "supersedes": None, **changes}

    def service_input(self, logical_id, **changes):
        return {**self.common(logical_id), "name": logical_id, "entity": "synthetic organization", "jurisdiction": "CZ",
                "owner": "synthetic-owner", "criticality": "important", "unknown_dependencies": True, **changes}

    def implementation(self):
        existing = g.list_records(self.case, "control_implementation")
        if existing:
            return existing[0]
        return g.put_record(self.case, "control_implementation", {
            **self.common("implementation"), "service_refs": [self.service["id"]], "pack_ref": self.pack["id"],
            "requirement_ids": ["restore"], "owner": "synthetic-owner", "description": "Test restore procedure", "period": PERIOD})

    def control_test(self, **changes):
        impl = self.implementation()
        value = {**self.common("test"), "implementation_ref": impl["id"], "procedure_id": "restore-run",
                 "procedure_version": "1", "period": PERIOD, "population": 1, "sample": ["service-a"], "excluded": [],
                 "population_complete": True, "attestation": "Synthetic observation only.",
                 "control": {"id": "restore", "kind": "restore", "population": 1, "rto_seconds": 120,
                             "rpo_seconds": 60, "evidence_refs": [self.source], "observations": [
                                 {"id": "obs-1", "subject": "service-a", "evidence_refs": [self.source], "restored": True,
                                  "functional_check": True, "elapsed_seconds": 100, "data_age_seconds": 30}]}, **changes}
        return g.put_record(self.case, "control_test", value)

    def assertCode(self, code, fn, *args, **kwargs):
        with self.assertRaises(ProbentiumError) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)


class GovernanceTests(Fixture, unittest.TestCase):
    def test_immutable_revision_and_conflict(self):
        revision = self.case.revision
        updated = g.put_record(self.case, "service", self.service_input("payments", name="Payments revised", supersedes=self.service["id"], recorded_at=T2), expected_revision=revision)
        self.assertEqual(len(g.list_records(self.case, "service")), 1)
        self.assertEqual(g.get_record(self.case, self.service["id"])["data"]["name"], "payments")
        self.assertEqual(g.list_records(self.case, "service")[0]["id"], updated["id"])
        self.assertCode("governance_revision_conflict", g.put_record, self.case, "service", self.service_input("payments"))

    def test_schema_cannot_assert_certification_or_extra_keys(self):
        data = deepcopy(self.service["data"])
        data["legal_certification"] = True
        self.assertCode("governance_record_integrity", g.validate_stored, "eu.service", data)
        data = self.service_input("bad", command="eval")
        self.assertCode("invalid_regulatory_fields", g.put_record, self.case, "service", data)
        self.assertCode("unsupported_governance_kind", g.validate_record, [], {})

    def test_missing_reference_and_wrong_kind(self):
        self.assertCode("eu_reference_missing", g.put_record, self.case, "service", self.service_input("bad", basis_refs=["0" * 64]))
        self.assertCode("eu_reference_kind_mismatch", g.reference, self.case, self.service["id"], {"eu.legal_pack"})
        self.assertCode("invalid_eu_reference", g.validate_record, "service", self.service_input("invalid-ref", basis_refs=["not-an-object-id"]))

    def test_document_and_incomplete_inventory_are_not_effectiveness(self):
        row = self.control_test(population_complete=False)
        result = g.assess_scope(self.case, row["id"], T2)
        self.assertEqual(result["status"], "partially_demonstrated")
        self.assertIn("inventory_completeness_not_demonstrated", result["reasons"])
        self.assertIn("evidence_references_are_not_authentication", result["reasons"])
        self.assertEqual(result["coverage"]["passed"], 1)
        self.assertEqual(g.assess_scope(self.case, row["id"], T0)["status"], "not_demonstrated")

    def test_sample_mismatch_exclusion_and_unknown_denominator(self):
        self.assertCode("control_sample_mismatch", self.control_test, sample=["unobserved"])
        data = {**self.common("bad-test"), "implementation_ref": self.implementation()["id"], "procedure_id": "p", "procedure_version": "1",
                "period": PERIOD, "population": None, "population_complete": True, "sample": [], "excluded": [], "attestation": "Test",
                "control": {"id": "mfa", "kind": "mfa", "population": None, "observations": []}}
        self.assertCode("complete_population_requires_denominator", g.put_record, self.case, "control_test", data)

    def test_dependency_cycle_and_branch_specific_impact(self):
        other = g.put_record(self.case, "service", self.service_input("other"))
        supplier = g.put_record(self.case, "supplier", {**self.common("supplier"), "name": "Supplier A", "entity": "Entity A",
            "statement": "Availability assertion", "period": PERIOD, "replacement_plan": "Manual failover", "contract_refs": [self.source]})
        edge = g.put_record(self.case, "dependency", {**self.common("edge"), "service_ref": self.service["id"], "target_ref": supplier["id"],
            "relationship": "supplier", "period": PERIOD, "known": True})
        impact = g.dependency_impact(self.case, [supplier["id"]])
        self.assertIn(edge["id"], impact["affected"])
        self.assertIn(self.service["id"], impact["affected"])
        self.assertNotIn(other["id"], impact["affected"])
        g.put_record(self.case, "dependency", {**self.common("a-b"), "service_ref": self.service["id"], "target_ref": other["id"],
            "relationship": "service", "period": PERIOD, "known": True})
        self.assertCode("service_dependency_cycle", g.put_record, self.case, "dependency", {**self.common("b-a"), "service_ref": other["id"],
            "target_ref": self.service["id"], "relationship": "service", "period": PERIOD, "known": True})

    def test_approval_bound_to_superseded_version(self):
        approval = g.put_record(self.case, "approval", {**self.common("approval"), "target_ref": self.service["id"],
            "scope_refs": [self.service["id"]], "decision": "approved", "role": "management", "attestation": "Scope approved as stated."})
        g.put_record(self.case, "service", self.service_input("payments", supersedes=self.service["id"], recorded_at=T2, criticality="critical"))
        result = g.dashboard(self.case, T3)
        self.assertIn(approval["id"], result["review_required_refs"])
        self.assertFalse(result["legal_certification"])

    def test_unknown_applicability_cannot_be_exemption(self):
        data = {**self.common("scope"), "entity": "synthetic organization", "service_refs": [self.service["id"]], "jurisdiction": "CZ",
            "role": "operator", "regime": "cz-nis2-lower", "facts": {"size": None, "group_relationships": None, "regulated_service": None,
            "registration_delivered": None, "previously_regulated": None, "digital_service": None, "trust_service": None},
            "exceptions": [], "pack_ref": self.pack["id"], "disposition": "unresolved", "reviewer": "synthetic-reviewer", "reviewed_at": None}
        obj = g.put_record(self.case, "applicability", data)
        self.assertIn(obj["id"], g.dashboard(self.case, T2)["unresolved_scope_refs"])
        data.update(disposition="not_applicable_by_review", reviewed_at=T1, supersedes=obj["id"])
        self.assertCode("applicability_review_incomplete", g.put_record, self.case, "applicability", data)
        data["facts"] = {"size": "Reviewed synthetic size", "group_relationships": "Reviewed synthetic group",
                         "regulated_service": "Synthetic reviewed out-of-scope decision", "registration_delivered": {
                             "status": "not_applicable", "reason": "No regulated service in this fictional reviewed scope.", "basis_refs": [self.source]},
                         "previously_regulated": False, "digital_service": False, "trust_service": False}
        reviewed = g.put_record(self.case, "applicability", data)
        self.assertEqual(reviewed["data"]["disposition"], "not_applicable_by_review")
        self.assertFalse(reviewed["data"]["legal_certification"])

    def test_expiry_is_explicit_policy_and_training_is_attendance(self):
        evidence = g.put_record(self.case, "evidence_assertion", {**self.common("policy"), "evidence_type": "policy_document",
            "source_family": "organization policy", "period": PERIOD, "review_due": T2, "expiry_origin": "internal",
            "expiry_reason": "Quarterly internal review", "statement": "Policy existence only"})
        training = g.put_record(self.case, "training", {**self.common("training"), "subjects": ["operator"], "course": "Synthetic recovery exercise",
            "attended": True, "assessment_method": None, "assessment_result": "not_assessed", "period": PERIOD})
        self.assertIn(evidence["id"], g.dashboard(self.case, T3)["stale_refs"])
        self.assertEqual(training["data"]["assessment_result"], "not_assessed")

    def test_count_limit_is_atomic_and_expected_revision_guarded(self):
        from unittest.mock import patch
        before = self.case.revision
        with patch.dict(g.CAPS, {"service": 1}):
            self.assertCode("governance_count_limit", g.put_record, self.case, "service", self.service_input("overflow"))
        self.assertEqual(self.case.revision, before)
        with self.assertRaises(ProbentiumError):
            g.put_record(self.case, "service", self.service_input("conflict"), expected_revision=before - 1)
        self.assertEqual(self.case.revision, before)

    def test_observation_limit_is_aggregate_across_revisions(self):
        from unittest.mock import patch
        first = self.control_test()
        value = {k: v for k, v in first["data"].items() if k not in {"schema", "kind", "legal_certification"}}
        value.update(supersedes=first["id"], recorded_at=T2)
        before = self.case.revision
        with patch.object(g, "CONTROL_OBSERVATION_LIMIT", 1):
            self.assertCode("case_control_observation_limit", g.put_record, self.case, "control_test", value)
        self.assertEqual(self.case.revision, before)

    def test_future_observation_not_accepted_as_past_test(self):
        self.assertCode("control_observation_in_future_of_attestation", self.control_test, period={"start": T0, "end": T2})


if __name__ == "__main__":
    unittest.main()
