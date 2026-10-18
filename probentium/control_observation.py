"""Observationes stricte typatae ad ambitum declaratum tantum valent."""
from copy import deepcopy
import re

from .contracts import ProbentiumError, canonical_bytes, object_digest, timestamp
from .regulatory import _dict, _text, _refs, _boolean
from .governance import _hex, _period, reference, check_refs

SCHEMA = "control-observation.v1"
FIELDS = {"schema", "procedure_id", "service_ref", "population_ref", "period", "expected", "observed", "source_refs", "attestation"}
PROCEDURES = {"restore.v1": "service_restore", "mfa.v1": "account_access_path", "remediation.v1": "asset_finding"}
MAX_OBSERVATIONS = 20000


def _duration(value):
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,18}", value):
        raise ProbentiumError("invalid_observation_microseconds")
    return int(value)


def validate_control_observation(data):
    _dict(data, FIELDS, FIELDS)
    if data["schema"] != SCHEMA or not isinstance(data["procedure_id"], str) or data["procedure_id"] not in PROCEDURES:
        raise ProbentiumError("unsupported_control_observation_schema_or_procedure")
    _hex(data["service_ref"]); _hex(data["population_ref"]); _period(data["period"])
    for ref in _refs(data["source_refs"]):
        _hex(ref)
    attestation = data["attestation"]
    _dict(attestation, {"actor", "at", "statement"}, {"actor", "at", "statement"})
    _text(attestation["actor"]); _text(attestation["statement"], 4096)
    if timestamp(attestation["at"]) < timestamp(data["period"]["end"]):
        raise ProbentiumError("observation_after_attestation")
    procedure = data["procedure_id"]
    expected_keys = {"restore.v1": {"rto_us", "rpo_us"}, "mfa.v1": {"configured", "enforced"},
                     "remediation.v1": {"remediated", "retest_passed"}}[procedure]
    _dict(data["expected"], expected_keys, expected_keys)
    for item in data["expected"].values():
        if procedure == "restore.v1":
            _duration(item)
        elif item is not True:
            raise ProbentiumError("control_expected_effectiveness_must_be_true")
    extras = {"restore.v1": {"restored", "functional_check", "elapsed_us", "data_age_us"},
              "mfa.v1": {"configured", "enforced"},
              "remediation.v1": {"applicable", "remediated", "retest_passed"}}[procedure]
    observed = data["observed"]
    if not isinstance(observed, list) or len(observed) > MAX_OBSERVATIONS:
        raise ProbentiumError("control_observation_limit", 6)
    subjects = set()
    for row in observed:
        keys = {"subject", "source_refs"} | extras
        _dict(row, keys, keys)
        _text(row["subject"])
        if row["subject"] in subjects:
            raise ProbentiumError("duplicate_control_observation")
        subjects.add(row["subject"])
        if not set(_refs(row["source_refs"])) <= set(data["source_refs"]):
            raise ProbentiumError("observation_source_not_declared")
        for key in extras:
            _duration(row[key]) if key in {"elapsed_us", "data_age_us"} else _boolean(row[key])
    if len(canonical_bytes(data)) > 16 * 1024 * 1024:
        raise ProbentiumError("control_observation_bytes_limit", 6)
    return deepcopy(data)


def validate_stored(data):
    keys = {"schema", "kind", "observation", "input_digest", "dependency_refs", "legal_certification"}
    _dict(data, keys, keys)
    if data["schema"] != "probentium.eu.v1" or data["kind"] != "control_observation" or data["legal_certification"] is not False:
        raise ProbentiumError("invalid_stored_control_observation")
    observation = validate_control_observation(data["observation"])
    expected = sorted({observation["service_ref"], observation["population_ref"], *observation["source_refs"]})
    if data["dependency_refs"] != expected or data["input_digest"] != object_digest(observation, domain="PROBENTIUM-CONTROL-OBSERVATION-V1"):
        raise ProbentiumError("control_observation_binding_failed", 4)
    return deepcopy(data)


def _population(case, data):
    from .governance import validate_stored as governance_validate
    reference(case, data["service_ref"], {"eu.service"})
    population = reference(case, data["population_ref"], {"eu.control_population"})["data"]
    governance_validate("eu.control_population", population)
    if population["service_ref"] != data["service_ref"] or population["unit"] != PROCEDURES[data["procedure_id"]]:
        raise ProbentiumError("control_population_scope_mismatch")
    if not {row["subject"] for row in data["observed"]} <= set(population["members"]):
        raise ProbentiumError("observation_outside_population")
    if timestamp(data["period"]["start"]) < timestamp(population["period"]["start"]) or timestamp(data["period"]["end"]) > timestamp(population["period"]["end"]):
        raise ProbentiumError("observation_outside_population_period")
    check_refs(case, data["source_refs"])
    return population


def put_control_observation(case, data, expected_revision=None):
    observation = validate_control_observation(data)
    _population(case, observation)
    existing = case.objects("eu.control_observation")
    count = sum(len(validate_stored(row["data"])["observation"]["observed"]) for row in existing)
    count += sum(len(row["data"]["control"]["observations"]) for row in case.objects("eu.control_test"))
    if count + len(observation["observed"]) > MAX_OBSERVATIONS or len(existing) >= MAX_OBSERVATIONS:
        raise ProbentiumError("case_control_observation_limit", 6)
    payload = {"schema": "probentium.eu.v1", "kind": "control_observation", "observation": observation,
               "input_digest": object_digest(observation, domain="PROBENTIUM-CONTROL-OBSERVATION-V1"),
               "dependency_refs": sorted({observation["service_ref"], observation["population_ref"], *observation["source_refs"]}),
               "legal_certification": False}
    return case.put_object("eu.control_observation", payload, expected_revision=expected_revision)


def assess_control_observation(case, object_id):
    data = validate_stored(reference(case, object_id, {"eu.control_observation"})["data"])["observation"]
    population = _population(case, data)
    counts = {"passed": 0, "failed": 0, "unknown": 0};details = []
    for row in data["observed"]:
        if data["procedure_id"] == "restore.v1":
            checks = [row["restored"], row["functional_check"]]
            for actual, target in (("elapsed_us", "rto_us"), ("data_age_us", "rpo_us")):
                a, t = _duration(row[actual]), _duration(data["expected"][target])
                checks.append(None if a is None or t is None else a <= t)
        elif data["procedure_id"] == "mfa.v1":
            checks = [row["configured"], row["enforced"]]
        else:
            checks = [row["remediated"], row["retest_passed"]] if row["applicable"] is True else [None]
        outcome = "unknown" if not row["source_refs"] else "failed" if False in checks else "passed" if all(x is True for x in checks) else "unknown"
        counts[outcome] += 1
        details.append({"subject": row["subject"], "outcome": outcome, "source_refs": row["source_refs"]})
    denominator = len(population["members"]) if population["complete"] else None
    missing = None if denominator is None else denominator - len(details)
    status = "failed_in_scope" if counts["failed"] else "effective_in_scope" if denominator and counts["passed"] == denominator else "partially_demonstrated" if counts["passed"] else "not_demonstrated"
    return {"observation_ref": object_id, "procedure_id": data["procedure_id"], "period": data["period"], "status": status,
            "coverage": {"population": denominator, "assessed": len(details), **counts, "missing": missing},
            "observations": details, "basis": "supplied_declarations", "evidence_verification": "references_only",
            "legal_certification": False, "limitations": ["references_do_not_authenticate_truth", "result_limited_to_declared_scope", "document_alone_is_not_effectiveness"]}


def append_demo_control_observations(case, service_ref, source_ref, period, actor="synthetic-operator"):
    """Exempla ficta tantum adduntur; eventus reales non finguntur."""
    from .governance import put_record
    _period(period); reference(case, service_ref, {"eu.service"}); check_refs(case, [source_ref])
    populations, observations, assessments = [], [], []
    samples = {
        "restore.v1": ({"rto_us": "120000000", "rpo_us": "60000000"}, [
            {"subject": "synthetic-service-a", "restored": True, "functional_check": True, "elapsed_us": "100000000", "data_age_us": "30000000"}]),
        "mfa.v1": ({"configured": True, "enforced": True}, [
            {"subject": "synthetic-operator-console", "configured": True, "enforced": True},
            {"subject": "synthetic-recovery-console", "configured": True, "enforced": None}]),
        "remediation.v1": ({"remediated": True, "retest_passed": True}, [
            {"subject": "synthetic-host-finding", "applicable": True, "remediated": True, "retest_passed": False}]),
    }
    for procedure, (expected, rows) in samples.items():
        population = put_record(case, "control_population", {
            "logical_id": "synthetic-population-" + procedure, "actor": actor, "recorded_at": period["end"],
            "basis_refs": [source_ref], "rationale": "Fictional exercise population; no real control or legal certification.", "supersedes": None,
            "service_ref": service_ref, "unit": PROCEDURES[procedure], "members": [row["subject"] for row in rows],
            "complete": True, "period": deepcopy(period)})
        observation = put_control_observation(case, {"schema": SCHEMA, "procedure_id": procedure,
            "service_ref": service_ref, "population_ref": population["id"], "period": deepcopy(period), "expected": expected,
            "observed": [{**row, "source_refs": [source_ref]} for row in rows], "source_refs": [source_ref],
            "attestation": {"actor": actor, "at": period["end"], "statement": "Synthetic fixture values, not an independent audit or observed production results."}})
        populations.append(population["id"]); observations.append(observation["id"])
        assessments.append(assess_control_observation(case, observation["id"]))
    return {"population_refs": populations, "observation_refs": observations, "assessments": assessments, "synthetic": True}
