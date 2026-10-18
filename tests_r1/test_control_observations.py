"""Observationes fictae, numeri ignoti et ambitus separatim probantur."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from probentium import governance as g
from probentium.control_observation import PROCEDURES, validate_control_observation, validate_stored
from probentium.contracts import ProbentiumError
from tests_r1.test_governance import Fixture, PERIOD, T0, T1


def observation(procedure="mfa.v1", service="a" * 64, population="b" * 64, source="c" * 64):
    expected = {"restore.v1": {"rto_us": "1000000", "rpo_us": "500000"},
                "mfa.v1": {"configured": True, "enforced": True},
                "remediation.v1": {"remediated": True, "retest_passed": True}}[procedure]
    observed = {"restore.v1": {"restored": True, "functional_check": True, "elapsed_us": "1000000", "data_age_us": "500000"},
                "mfa.v1": {"configured": True, "enforced": True},
                "remediation.v1": {"applicable": True, "remediated": True, "retest_passed": True}}[procedure]
    return {"schema": "control-observation.v1", "procedure_id": procedure, "service_ref": service,
            "population_ref": population, "period": deepcopy(PERIOD), "expected": expected,
            "observed": [{"subject": "subject-a", "source_refs": [source], **observed}], "source_refs": [source],
            "attestation": {"actor": "synthetic-operator", "at": T1, "statement": "Synthetic supplied declaration, no independent audit."}}


class ControlInputTests(unittest.TestCase):
    def test_all_three_closed_contracts_accept_explicit_unknowns(self):
        for procedure in PROCEDURES:
            with self.subTest(procedure=procedure):
                value = observation(procedure)
                self.assertEqual(validate_control_observation(value), value)
                for key in set(value["observed"][0]) - {"subject", "source_refs"}:
                    value["observed"][0][key] = None
                self.assertEqual(validate_control_observation(value), value)

    def test_missing_is_not_null_and_extra_fields_are_rejected_at_every_level(self):
        for procedure in PROCEDURES:
            value = observation(procedure)
            for path in ((), ("period",), ("expected",), ("attestation",), ("observed", 0)):
                for extra in (True, False):
                    supplied = deepcopy(value); selected = supplied
                    for key in path:
                        selected = selected[key]
                    if extra:
                        selected["unexpected"] = None
                    else:
                        del selected[next(iter(selected))]
                    with self.subTest(procedure=procedure, path=path, extra=extra), self.assertRaises(ProbentiumError):
                        validate_control_observation(supplied)

    def test_microseconds_are_exact_canonical_nonnegative_decimal_strings(self):
        for duration in (True, 1, 0.5, "-1", "1.0", "01", "1e6", "9" * 20, " 1"):
            value = observation("restore.v1"); value["observed"][0]["elapsed_us"] = duration
            with self.subTest(duration=duration), self.assertRaises(ProbentiumError):
                validate_control_observation(value)
        value["observed"][0]["elapsed_us"] = "0"
        self.assertEqual(validate_control_observation(value)["observed"][0]["elapsed_us"], "0")

    def test_subject_reference_attestation_and_expectation_boundaries(self):
        mutations = (
            lambda d: d["observed"].append(deepcopy(d["observed"][0])),
            lambda d: d["observed"][0].update(source_refs=["d" * 64]),
            lambda d: d["attestation"].update(at=T0),
            lambda d: d["attestation"].update(actor="unsafe\x1b[31m"),
            lambda d: d["expected"].update(enforced=False),
            lambda d: d["observed"][0].update(enforced="true"),
            lambda d: d.update(service_ref="not-an-id"),
            lambda d: d.update(procedure_id=[]),
        )
        for mutate in mutations:
            value = observation(); mutate(value)
            with self.assertRaises(ProbentiumError):
                validate_control_observation(value)


class StoredControlTests(Fixture, unittest.TestCase):
    def population(self, procedure="mfa.v1", complete=True, members=None, **changes):
        return g.put_record(self.case, "control_population", {**self.common("population-" + procedure),
            "service_ref": self.service["id"], "unit": PROCEDURES[procedure], "members": members or ["subject-a"],
            "complete": complete, "period": deepcopy(PERIOD), **changes})

    def supplied(self, procedure="mfa.v1", complete=True, members=None):
        population = self.population(procedure, complete, members)
        return observation(procedure, self.service["id"], population["id"], self.source)

    def assess(self, supplied):
        row = g.put_control_observation(self.case, supplied)
        return g.assess_control_observation(self.case, row["id"])

    def test_restore_exact_boundary_and_failed_retest_have_real_outcomes(self):
        supplied = self.supplied("restore.v1")
        result = self.assess(supplied)
        self.assertEqual(result["status"], "effective_in_scope")
        self.assertEqual(result["basis"], "supplied_declarations")
        self.assertFalse(result["legal_certification"])
        supplied["observed"][0]["elapsed_us"] = "1000001"
        self.assertEqual(self.assess(supplied)["coverage"]["failed"], 1)
        remediation = self.supplied("remediation.v1")
        remediation["observed"][0]["retest_passed"] = False
        self.assertEqual(self.assess(remediation)["status"], "failed_in_scope")

    def test_unknown_denominator_missing_sample_and_unproved_rows_are_not_passes(self):
        supplied = self.supplied(complete=False, members=["subject-a", "subject-b"])
        result = self.assess(supplied)
        self.assertEqual(result["status"], "partially_demonstrated")
        self.assertIsNone(result["coverage"]["population"])
        self.assertIsNone(result["coverage"]["missing"])
        supplied["observed"][0]["source_refs"] = []
        result = self.assess(supplied)
        self.assertEqual(result["coverage"]["unknown"], 1)
        self.assertEqual(result["coverage"]["passed"], 0)
        supplied["observed"][0].update(source_refs=[self.source], enforced=None)
        self.assertEqual(self.assess(supplied)["coverage"]["unknown"], 1)
        known = self.supplied("restore.v1", members=["subject-a", "subject-b"])
        self.assertEqual(self.assess(known)["coverage"]["missing"], 1)

    def test_population_scope_period_units_and_source_existence_are_enforced(self):
        supplied = self.supplied()
        mutations = (
            ("observation_outside_population", lambda d: d["observed"][0].update(subject="outsider")),
            ("observation_outside_population_period", lambda d: d["period"].update(start="2026-10-17T00:00:00Z")),
            ("eu_reference_kind_mismatch", lambda d: d.update(service_ref=self.pack["id"])),
            ("control_population_scope_mismatch", lambda d: d.update(procedure_id="remediation.v1", expected={"remediated": True, "retest_passed": True}, observed=[])),
            ("eu_reference_missing", lambda d: d.update(source_refs=["d" * 64], observed=[])),
        )
        for code, mutate in mutations:
            data = deepcopy(supplied); mutate(data)
            self.assertCode(code, g.put_control_observation, self.case, data)

    def test_immutable_binding_and_shared_budget_reject_without_mutation(self):
        supplied = self.supplied(); revision = self.case.revision
        obj = g.put_control_observation(self.case, supplied, expected_revision=revision)
        self.assertEqual(g.validate_stored("eu.control_observation", obj["data"]), obj["data"])
        self.assertCode("revision_conflict", g.put_control_observation, self.case, supplied, expected_revision=revision)
        for mutate in (lambda d: d.update(input_digest="0" * 64), lambda d: d.update(dependency_refs=[]), lambda d: d.update(legal_certification=True)):
            data = deepcopy(obj["data"]); mutate(data)
            with self.assertRaises(ProbentiumError):
                validate_stored(data)
        before = self.case.revision
        with patch("probentium.control_observation.MAX_OBSERVATIONS", 1):
            self.assertCode("case_control_observation_limit", g.put_control_observation, self.case, supplied)
        self.assertEqual(self.case.revision, before)
        with patch("probentium.governance.CONTROL_OBSERVATION_LIMIT", 1):
            self.implementation()
            before = self.case.revision
            self.assertCode("case_control_observation_limit", self.control_test)
            self.assertEqual(self.case.revision, before)

    def test_synthetic_helper_creates_all_three_actual_stored_workflows(self):
        result = g.append_demo_control_observations(self.case, self.service["id"], self.source, PERIOD)
        self.assertEqual(len(result["population_refs"]), 3)
        self.assertEqual(len(result["observation_refs"]), 3)
        self.assertEqual([r["status"] for r in result["assessments"]], ["effective_in_scope", "partially_demonstrated", "failed_in_scope"])
        self.assertTrue(self.case.verify()["ok"])
        for identity in result["observation_refs"]:
            self.assertIn(identity, g.dependency_impact(self.case, [self.service["id"]])["affected"])


if __name__ == "__main__":
    unittest.main()
