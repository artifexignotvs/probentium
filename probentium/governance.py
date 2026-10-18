"""Consilia cum fontibus servantur; historia non deletur."""
from copy import deepcopy

from .contracts import ProbentiumError, canonical_bytes, object_digest, timestamp
from .regulatory import _dict, _text, _refs, _integer, _boolean, _value, _anchor, evaluate_control

SCHEMA = "probentium.eu.v1"
COMMON = {"logical_id", "actor", "recorded_at", "basis_refs", "rationale", "supersedes"}
FIELDS = {
    "service": {"name", "entity", "jurisdiction", "owner", "criticality", "unknown_dependencies"},
    "supplier": {"name", "entity", "statement", "period", "replacement_plan", "contract_refs"},
    "dependency": {"service_ref", "target_ref", "relationship", "period", "known"},
    "control_implementation": {"service_refs", "pack_ref", "requirement_ids", "owner", "description", "period"},
    "evidence_assertion": {"evidence_type", "source_family", "period", "review_due", "expiry_origin", "expiry_reason", "statement"},
    "control_test": {"implementation_ref", "procedure_id", "procedure_version", "period", "population", "sample", "excluded", "population_complete", "control", "attestation"},
    "control_population": {"service_ref", "unit", "members", "complete", "period"},
    "exception": {"scope_refs", "owner", "risk", "compensating_measures", "review_due", "disposition"},
    "approval": {"target_ref", "scope_refs", "decision", "role", "attestation"},
    "training": {"subjects", "course", "attended", "assessment_method", "assessment_result", "period"},
    "awareness": {"track_ref", "event_type", "anchor", "actor_role", "review_decision"},
    "obligation_anchor": {"service_ref", "profile", "trigger_kind", "anchor", "review_decision"},
    "applicability": {"entity", "service_refs", "jurisdiction", "role", "regime", "facts", "exceptions", "pack_ref", "disposition", "reviewer", "reviewed_at"},
}
CAPS = {"service": 100, "supplier": 2000, "dependency": 20000, "control_implementation": 2000,
        "evidence_assertion": 20000, "control_test": 20000, "exception": 2000, "approval": 20000,
        "training": 20000, "awareness": 20000, "applicability": 4000}
CONTROL_OBSERVATION_LIMIT = 20000
CAPS["control_population"] = 20000
CAPS["obligation_anchor"] = 20000
OBLIGATION_ANCHORS = {"registration_conditions_met", "registration_decision", "registration_delivery", "law_effective", "data_change", "prior_regulation_review"}
CZ_PROFILES = {"cz-nis2-higher", "cz-nis2-lower", "cz-nis2-digital"}


def _period(value):
    _dict(value, {"start", "end"}, {"start", "end"})
    if timestamp(value["start"]) > timestamp(value["end"]):
        raise ProbentiumError("invalid_scope_period")
    return deepcopy(value)


def _strings(value, limit=20000):
    if not isinstance(value, list) or len(value) > limit:
        raise ProbentiumError("governance_list_limit", 6)
    result = [_text(v) for v in value]
    if len(result) != len(set(result)):
        raise ProbentiumError("duplicate_governance_item")
    return result


def _enum(value, choices):
    if not isinstance(value, str) or value not in choices:
        raise ProbentiumError("invalid_governance_enum")
    return value


def _hex(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ProbentiumError("invalid_eu_reference")
    return value


def reference(case, ref, kinds=None):
    """Identitas fontis inspicitur, non veritas."""
    _hex(ref)
    try:
        obj = case.get_object(ref)
    except ProbentiumError as exc:
        if exc.code != "object_not_found":
            raise
    else:
        if kinds and obj["kind"] not in kinds:
            raise ProbentiumError("eu_reference_kind_mismatch")
        return obj
    if kinds:
        raise ProbentiumError("eu_reference_missing")
    for source in case.sources():
        if source["id"] == ref:
            return {"id": ref, "kind": "artifact", "data": source}
    try:
        case.raw(ref)
        return {"id": ref, "kind": "event", "data": {}}
    except ProbentiumError as exc:
        if exc.exit_code == 4:
            raise
        raise ProbentiumError("eu_reference_missing") from exc


def check_refs(case, refs, nonempty=False):
    values = _strings(refs, 32000)
    if nonempty and not values:
        raise ProbentiumError("eu_evidence_required")
    for ref in values:
        reference(case, ref)
    return values


def _common(data):
    for key in ("logical_id", "actor"):
        _text(data[key])
    timestamp(data["recorded_at"])
    _text(data["rationale"], 4096)
    _refs(data["basis_refs"])
    if data["supersedes"] is not None:
        _hex(data["supersedes"])


def validate_record(kind, data):
    kind = kind.removeprefix("eu.") if isinstance(kind, str) else kind
    if not isinstance(kind, str) or kind not in FIELDS:
        raise ProbentiumError("unsupported_governance_kind")
    _dict(data, COMMON | FIELDS[kind], COMMON | FIELDS[kind])
    _common(data)
    for key in {"period"} & data.keys():
        _period(data[key])
    for key in {"service_refs", "scope_refs", "contract_refs"} & data.keys():
        _refs(data[key])
    for key in {"implementation_ref", "pack_ref", "target_ref", "service_ref", "track_ref"} & data.keys():
        _hex(data[key])
    for key in {"review_due", "reviewed_at"} & data.keys():
        if data[key] is not None:
            timestamp(data[key])
    if kind == "service":
        for key in ("name", "entity", "jurisdiction", "owner"):
            _text(data[key])
        _enum(data["criticality"], {"critical", "important", "ordinary", "unknown"})
        if type(data["unknown_dependencies"]) is not bool:
            raise ProbentiumError("invalid_unknown_dependencies")
    elif kind == "supplier":
        for key in ("name", "entity", "statement", "replacement_plan"):
            _text(data[key], 4096)
    elif kind == "dependency":
        _enum(data["relationship"], {"supplier", "subcontractor", "service", "technical"})
        if type(data["known"]) is not bool:
            raise ProbentiumError("invalid_dependency_status")
    elif kind == "control_implementation":
        _strings(data["requirement_ids"], 5000)
        if not data["service_refs"] or not data["requirement_ids"]:
            raise ProbentiumError("control_scope_required")
        _text(data["owner"])
        _text(data["description"], 4096)
    elif kind == "evidence_assertion":
        _enum(data["evidence_type"], {"policy_document", "supplier_statement", "human_attestation", "observed_test", "derived_result"})
        _text(data["source_family"])
        _text(data["statement"], 4096)
        _enum(data["expiry_origin"], {"internal", "legal", "none"})
        if data["expiry_origin"] == "none":
            if data["review_due"] is not None or data["expiry_reason"] is not None:
                raise ProbentiumError("unexpected_expiry")
        else:
            if data["review_due"] is None:
                raise ProbentiumError("expiry_time_required")
            _text(data["expiry_reason"], 4096)
            if data["expiry_origin"] == "legal" and not data["basis_refs"]:
                raise ProbentiumError("legal_expiry_basis_required")
    elif kind == "control_population":
        _enum(data["unit"], {"service_restore", "account_access_path", "asset_finding"})
        _strings(data["members"], CONTROL_OBSERVATION_LIMIT)
        if type(data["complete"]) is not bool:
            raise ProbentiumError("invalid_population_completeness")
    elif kind == "control_test":
        _text(data["procedure_id"])
        _text(data["procedure_version"])
        _text(data["attestation"], 4096)
        _integer(data["population"], nullable=True)
        sample, excluded = _strings(data["sample"]), _strings(data["excluded"])
        if set(sample) & set(excluded) or type(data["population_complete"]) is not bool:
            raise ProbentiumError("invalid_control_sample")
        if data["population_complete"] and data["population"] is None:
            raise ProbentiumError("complete_population_requires_denominator")
        if data["population"] is not None and len(sample) + len(excluded) > data["population"]:
            raise ProbentiumError("sample_exceeds_population")
        evaluate_control(data["control"])
        if data["control"].get("population") != data["population"] or set(sample) != {o["subject"] for o in data["control"]["observations"]}:
            raise ProbentiumError("control_sample_mismatch")
    elif kind == "exception":
        if not data["scope_refs"]:
            raise ProbentiumError("exception_scope_required")
        for key in ("owner", "risk", "compensating_measures"):
            _text(data[key], 4096)
        _enum(data["disposition"], {"proposed", "accepted", "rejected", "withdrawn"})
        if data["review_due"] is None:
            raise ProbentiumError("exception_review_due_required")
        if data["disposition"] == "accepted" and not data["basis_refs"]:
            raise ProbentiumError("accepted_exception_basis_required")
    elif kind == "approval":
        _enum(data["decision"], {"approved", "rejected", "needs_revision"})
        _text(data["role"])
        _text(data["attestation"], 4096)
        if not data["scope_refs"]:
            raise ProbentiumError("approval_scope_required")
        if not data["basis_refs"]:
            raise ProbentiumError("approval_basis_required")
    elif kind == "training":
        _strings(data["subjects"])
        _text(data["course"])
        if type(data["attended"]) is not bool:
            raise ProbentiumError("invalid_training_attendance")
        _enum(data["assessment_result"], {"passed", "failed", "not_assessed", "unknown"})
        if data["assessment_result"] in {"passed", "failed"}:
            _text(data["assessment_method"], 4096)
        elif data["assessment_method"] is not None:
            _text(data["assessment_method"], 4096)
    elif kind == "obligation_anchor":
        _enum(data["profile"], CZ_PROFILES)
        _enum(data["trigger_kind"], OBLIGATION_ANCHORS)
        _enum(data["review_decision"], {"unreviewed", "confirmed", "contested"})
        anchor = _anchor(data["anchor"])
        if anchor["status"] != "trigger_status_unknown" and not data["basis_refs"]:
            raise ProbentiumError("obligation_anchor_basis_required")
        if data["trigger_kind"] != "law_effective" and anchor.get("latest") is not None and anchor["latest"] > timestamp(data["recorded_at"]):
            raise ProbentiumError("obligation_anchor_after_attestation")
    elif kind == "awareness":
        _text(data["actor_role"])
        _enum(data["event_type"], {"occurrence", "detection", "awareness", "classification", "submitted", "intermediate", "latest_intermediate", "measure_available", "resolved"})
        anchor = _anchor(data["anchor"])
        _enum(data["review_decision"], {"unreviewed", "confirmed", "contested"})
        if anchor["status"] != "trigger_status_unknown" and not data["basis_refs"]:
            raise ProbentiumError("awareness_basis_required")
    elif kind == "applicability":
        for key in ("entity", "jurisdiction", "role", "regime", "reviewer"):
            _text(data[key])
        _dict(data["facts"], {"size", "group_relationships", "regulated_service", "registration_delivered", "previously_regulated", "digital_service", "trust_service"},
              {"size", "group_relationships", "regulated_service", "registration_delivered", "previously_regulated", "digital_service", "trust_service"})
        _value(data["facts"])
        registration = data["facts"]["registration_delivered"]
        if isinstance(registration, dict):
            _dict(registration, {"status", "reason", "basis_refs"}, {"status", "reason", "basis_refs"})
            if registration["status"] != "not_applicable":
                raise ProbentiumError("invalid_registration_fact")
            _text(registration["reason"], 4096)
            if not _refs(registration["basis_refs"]):
                raise ProbentiumError("registration_not_applicable_basis_required")
        elif registration is not None:
            timestamp(registration)
        for key in ("previously_regulated", "digital_service", "trust_service"):
            _boolean(data["facts"][key])
        _strings(data["exceptions"], 64)
        _enum(data["disposition"], {"applicable", "not_applicable_by_review", "unresolved"})
        if data["disposition"] != "unresolved":
            if not data["basis_refs"] or data["reviewed_at"] is None or any(v is None for v in data["facts"].values()):
                raise ProbentiumError("applicability_review_incomplete")
    result = {"schema": SCHEMA, "kind": kind, **deepcopy(data), "legal_certification": False}
    for ref in record_dependencies(result):
        _hex(ref)
    return result


def validate_stored(kind, data):
    """Forma clausa ante importationem inspicitur."""
    if kind == "eu.control_observation":
        from .control_observation import validate_stored as validate_observation
        return validate_observation(data)
    if not isinstance(data, dict):
        raise ProbentiumError("invalid_governance_record")
    normalized = validate_record(kind, {k: v for k, v in data.items() if k not in {"schema", "kind", "legal_certification"}})
    if canonical_bytes(normalized) != canonical_bytes(data):
        raise ProbentiumError("governance_record_integrity", 4)
    return normalized


def get_record(case, object_id):
    obj = reference(case, object_id)
    if not obj["kind"].startswith("eu.") or obj["kind"][3:] not in FIELDS:
        raise ProbentiumError("not_governance_record")
    validate_stored(obj["kind"], obj["data"])
    return obj


def list_records(case, kind=None, current_only=True):
    if kind is not None:
        if not isinstance(kind, str):
            raise ProbentiumError("unsupported_governance_kind")
        kind = kind.removeprefix("eu.")
        if kind not in FIELDS:
            raise ProbentiumError("unsupported_governance_kind")
    rows = [get_record(case, obj["id"]) for obj in case.objects() if obj["kind"].startswith("eu.") and obj["kind"][3:] in FIELDS and (kind is None or obj["kind"] == "eu." + kind)]
    if current_only:
        superseded = {obj["data"]["supersedes"] for obj in rows}
        rows = [obj for obj in rows if obj["id"] not in superseded]
    return rows


def record_dependencies(data):
    refs = set(data.get("basis_refs", []))
    for key in ("service_refs", "scope_refs", "contract_refs", "document_refs", "review_refs", "dependency_refs"):
        refs.update(data.get(key, []))
    for key in ("service_ref", "population_ref", "target_ref", "implementation_ref", "pack_ref", "track_ref", "filing_ref", "submission_ref", "approval_ref", "before_ref", "after_ref"):
        if data.get(key):
            refs.add(data[key])
    control = data.get("control", {})
    refs.update(control.get("evidence_refs", []))
    for obs in control.get("observations", []):
        refs.update(obs.get("evidence_refs", []))
    refs.update(data.get("awareness_refs", {}).values())
    if data.get("kind") in {"legal_pack", "requirement_catalogue"}:
        refs.update(source["document_ref"] for source in data["sources"] if source["document_ref"] is not None)
    refs.update(data.get("qualification", {}).get("basis_refs", []))
    registration = data.get("facts", {}).get("registration_delivered")
    if isinstance(registration, dict):
        refs.update(registration.get("basis_refs", []))
    return sorted(refs)


def put_record(case, kind, data, expected_revision=None):
    normalized = validate_record(kind, data)
    kind = normalized["kind"]
    rows = list_records(case, kind)
    current = [row for row in rows if row["data"]["logical_id"] == data["logical_id"]]
    if current:
        if len(current) != 1 or data["supersedes"] != current[0]["id"]:
            raise ProbentiumError("governance_revision_conflict", 5)
        if timestamp(data["recorded_at"]) < timestamp(current[0]["data"]["recorded_at"]):
            raise ProbentiumError("governance_time_reversed")
        if kind == "obligation_anchor" and any(data[key] != current[0]["data"][key] for key in ("service_ref", "profile", "trigger_kind")):
            raise ProbentiumError("obligation_anchor_domain_changed")
    elif data["supersedes"] is not None:
        raise ProbentiumError("governance_supersedes_mismatch")
    if not current and len(rows) >= CAPS[kind]:
        raise ProbentiumError("governance_count_limit", 6)
    if kind == "control_test":
        observations = sum(len(row["data"]["control"]["observations"]) for row in list_records(case, "control_test", current_only=False))
        observations += sum(len(row["data"]["observation"]["observed"]) for row in case.objects("eu.control_observation"))
        if observations + len(data["control"]["observations"]) > CONTROL_OBSERVATION_LIMIT:
            raise ProbentiumError("case_control_observation_limit", 6)
        if timestamp(data["period"]["end"]) > timestamp(data["recorded_at"]):
            raise ProbentiumError("control_observation_in_future_of_attestation")
    check_refs(case, record_dependencies(normalized))
    expected_kinds = {"service_ref": {"eu.service"}, "implementation_ref": {"eu.control_implementation"},
                      "pack_ref": {"eu.legal_pack"}, "track_ref": {"eu.reporting_track", "track"}}
    for key, kinds in expected_kinds.items():
        if key in data:
            reference(case, data[key], kinds)
    for ref in data.get("service_refs", []):
        reference(case, ref, {"eu.service"})
    if kind == "control_implementation":
        pack = reference(case, data["pack_ref"], {"eu.legal_pack"})["data"]
        rules = {rule["id"] for rule in pack["rules"]}
        if not set(data["requirement_ids"]) <= rules:
            raise ProbentiumError("unknown_pack_requirement")
    if kind == "dependency" and data["known"]:
        edges = [(r["data"]["service_ref"], r["data"]["target_ref"]) for r in list_records(case, "dependency") if r["data"]["known"] and r["id"] != data["supersedes"]]
        edges.append((data["service_ref"], data["target_ref"]))
        graph = {}
        for a, b in edges:
            graph.setdefault(a, set()).add(b)
        todo, visited = [data["target_ref"]], set()
        while todo:
            node = todo.pop()
            if node == data["service_ref"]:
                raise ProbentiumError("service_dependency_cycle")
            if node not in visited:
                visited.add(node)
                todo.extend(graph.get(node, ()))
    return case.put_object("eu." + kind, normalized, expected_revision=expected_revision)


def dependency_impact(case, changed_refs):
    changed = set(_strings(changed_refs, 32000))
    check_refs(case, list(changed))
    rows = list_records(case, current_only=True)
    others = [row for row in case.objects() if row["kind"] in {
        "eu.legal_review", "eu.legal_activation", "eu.reporting_track", "eu.filing_snapshot", "eu.filing_approval",
        "eu.submission_record", "eu.receipt", "eu.correction_impact", "eu.control_observation", "eu.deadline_evaluation",
        "eu.legal_pack", "eu.requirement_catalogue", "eu.legal_coverage_audit"}]
    superseded_tracks = {row["data"].get("supersedes") for row in others if row["kind"] == "eu.reporting_track"}
    rows += [row for row in others if row["id"] not in superseded_tracks]
    reverse = {}
    for row in rows:
        for ref in record_dependencies(row["data"]):
            reverse.setdefault(ref, set()).add(row["id"])
        if row["kind"] == "eu.dependency" and row["data"]["known"]:
            reverse.setdefault(row["id"], set()).add(row["data"]["service_ref"])
    affected, paths = set(), {ref: [ref] for ref in changed}
    frontier = set(changed)
    while frontier:
        nxt = set()
        for parent in sorted(frontier):
            for dependent in sorted(reverse.get(parent, ())):
                if dependent not in affected and dependent not in changed:
                    affected.add(dependent)
                    paths[dependent] = paths[parent] + [dependent]
                    nxt.add(dependent)
        frontier = nxt
    return {"changed_refs": sorted(changed), "affected": sorted(affected),
            "paths": {ref: paths[ref] for ref in sorted(affected)}, "history_rewritten": False,
            "review_required": bool(affected), "path_scope": "one_representative_path_per_affected_object"}


def assess_scope(case, control_test_id, as_of):
    obj = get_record(case, control_test_id)
    if obj["kind"] != "eu.control_test":
        raise ProbentiumError("control_test_required")
    data = obj["data"]
    check_refs(case, record_dependencies(data))
    result = evaluate_control(data["control"])
    result.update({"test_ref": obj["id"], "period": data["period"], "procedure_id": data["procedure_id"],
                   "sample": data["sample"], "excluded": data["excluded"], "as_of": as_of,
                   "population_complete": data["population_complete"]})
    timestamp(as_of)
    if not data["population_complete"] and result["status"] == "effective_in_scope":
        result["status"] = "partially_demonstrated"
        result["reasons"].append("inventory_completeness_not_demonstrated")
    if timestamp(as_of) < timestamp(data["period"]["end"]) or timestamp(as_of) < timestamp(data["recorded_at"]):
        result["status"] = "not_demonstrated"
        result["reasons"].append("assessment_before_completed_observation_and_attestation")
    return result


def dashboard(case, as_of):
    now = timestamp(as_of)
    rows = list_records(case)
    stale, unknown, open_decisions = [], [], []
    superseded = {r["data"]["supersedes"] for r in list_records(case, current_only=False) if r["data"]["supersedes"]}
    affected = dependency_impact(case, sorted(superseded)) if superseded else {"affected": [], "paths": {}}
    for row in rows:
        data = row["data"]
        if data.get("review_due") and now > timestamp(data["review_due"]):
            stale.append(row["id"])
        if data["kind"] == "applicability" and data["disposition"] == "unresolved":
            unknown.append(row["id"])
        if data["kind"] == "exception" and data["disposition"] == "proposed":
            open_decisions.append(row["id"])
    return {"as_of": as_of, "revision": case.revision, "stale_refs": stale, "unresolved_scope_refs": unknown,
            "open_decision_refs": open_decisions, "review_required_refs": affected["affected"],
            "legal_certification": False, "limits": "Evidence freshness is an explicit policy, not a universal statutory expiry."}


def validate_control_observation(data):
    from .control_observation import validate_control_observation as execute
    return execute(data)


def put_control_observation(case, data, expected_revision=None):
    from .control_observation import put_control_observation as execute
    return execute(case, data, expected_revision=expected_revision)


def assess_control_observation(case, object_id):
    from .control_observation import assess_control_observation as execute
    return execute(case, object_id)


def append_demo_control_observations(case, service_ref, source_ref, period, actor="synthetic-operator"):
    from .control_observation import append_demo_control_observations as execute
    return execute(case, service_ref, source_ref, period, actor)


def replay_obligation_anchor(case, object_id):
    """Assertio et successiones inspiciuntur; obligatio non deducitur."""
    integrity = case.verify()
    if not integrity["ok"]:
        raise ProbentiumError("obligation_case_integrity_failed", 4)
    row = reference(case, object_id, {"eu.obligation_anchor"}); current = validate_stored(row["kind"], row["data"])
    check_refs(case, record_dependencies(current))
    seen = {object_id}; previous_ref = current["supersedes"]
    while previous_ref is not None:
        if previous_ref in seen or len(seen) >= CAPS["obligation_anchor"]:
            raise ProbentiumError("obligation_history_invalid", 4)
        seen.add(previous_ref)
        previous = reference(case, previous_ref, {"eu.obligation_anchor"})
        data = validate_stored(previous["kind"], previous["data"])
        if previous["revision"] >= row["revision"] or timestamp(data["recorded_at"]) > timestamp(current["recorded_at"]) or any(data[key] != current[key] for key in ("logical_id", "service_ref", "profile", "trigger_kind")):
            raise ProbentiumError("obligation_history_invalid", 4)
        check_refs(case, record_dependencies(data))
        row, current, previous_ref = previous, data, data["supersedes"]
    return {"anchor_ref": object_id, "status": "partial" if integrity["exit_code"] else "record_bindings_checked", "exit_code": integrity["exit_code"],
            "legal_status_inferred": False, "legally_verified": False, "history_rewritten": False}


def obligation_anchor_status(case, object_id, as_of):
    replay = replay_obligation_anchor(case, object_id)
    row = reference(case, object_id, {"eu.obligation_anchor"}); data = row["data"]; now = timestamp(as_of)
    if now < timestamp(data["recorded_at"]):
        raise ProbentiumError("currentness_precedes_anchor")
    newer = [obj["id"] for obj in case.objects("eu.obligation_anchor") if obj["revision"] > row["revision"] and
             obj["data"]["logical_id"] == data["logical_id"] and timestamp(obj["data"]["recorded_at"]) <= now]
    return {"anchor_ref": object_id, "state": "superseded" if newer else "current_supplied_assertion", "newer_refs": newer,
            "profile": data["profile"], "trigger_kind": data["trigger_kind"], "trigger_status": _anchor(data["anchor"])["status"],
            "review_decision": data["review_decision"], "checked_as_of": as_of, "legal_status_inferred": False,
            "legally_verified": False, "exit_code": replay["exit_code"], "history_rewritten": False}
