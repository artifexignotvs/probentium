"""Investigationes immutabiles; conclusiones fontibus et condicionibus ligantur."""
from collections import deque
from collections.abc import Mapping, Sequence
from copy import deepcopy
import base64
import hashlib

from .contracts import ProbentiumError, canonical_bytes, object_digest, text_field
from . import claims
from . import time_model as tm
from .budgets import normalize_analysis_limits

MAX_GRAPH_NODES = 20000
MAX_GRAPH_EDGES = 250000
MAX_SCENARIOS = 64
MAX_ANALYSIS_BYTES = 64 * 1024 * 1024
_GAPS = {
    "clock_alignment_unknown": "Declare a supported clock model or retain an unknown temporal relation.",
    "clock_error_unknown": "Supply finite attributed clock bounds; do not infer zero error.",
    "clock_segment_gap_or_overlap": "Resolve the clock segment gap or overlap with supporting records.",
    "recorded_time_unknown": "Inspect the original timestamp and parser disposition.",
    "source_coverage_incomplete": "Inspect unsupported records and unprocessed source tails.",
    "scope_source_unavailable": "Restore the referenced source or create a new explicit scope revision.",
    "active_parser_changed": "Review the new parser output and explicitly revise the selected parse run.",
    "identity_assumption_unavailable_or_conflicting": "Resolve or retain the conflicting identity assertion.",
    "assumption_reference_missing": "Provide the referenced assumption or withdraw the dependent claim.",
    "joint_feasibility_not_evaluated": "Review joint membership constraints; possible counts are not a feasible joint witness.",
    "anchor_unavailable": "Restore the scoped anchor or mark the comparison unevaluated.",
    "anchor_time_unknown": "Establish the anchor clock basis before interpreting a temporal count.",
    "input_integrity_not_verified": "Verify the supplied source bytes and parser lineage before interpretation.",
    "matching_or_time_unknown": "Inspect missing fields and time bounds before claiming absence.",
    "operand_unavailable_in_scope": "Review the operand references and explicit scope.",
    "field_value_unknown": "Retain the missing field as unknown; do not substitute an identity.",
}


def _expect(case, expected):
    if expected is not None:
        tm.integer(expected, 0, 9007199254740991)
        if case.revision != expected:
            tm.error("revision_conflict", 5)
    return case.revision


def _object(case, identity, kind=None):
    item = case.get_object(tm.identifier(identity))
    if kind is not None and item["kind"] != kind:
        tm.error("investigation_object_kind_mismatch")
    return item


def _coverage(source):
    keys = ("id", "parse_run_id", "state", "counters", "records_total", "events_total", "cursor", "unprocessed_bytes", "unprocessed_records", "interpretation_complete", "parser_artifact_digest")
    return {key: source.get(key) for key in keys}


def _compact_event(row):
    keys = ("id", "artifact_id", "parse_run_id", "kind", "host", "actor", "src_ip", "dst_ip", "path", "action", "recorded_time")
    event = {key: row[key] for key in keys if key in row}
    for key in ("attributes", "payload"):
        fields = {field: value for field, value in row.get(key, {}).items() if "payload." + field in claims.FIELDS}
        if fields:
            event[key] = fields
    return event


def _collect_events(rows):
    result, size = [], 0
    for row in rows:
        event = _compact_event(row)
        size += len(canonical_bytes(event))
        if size > MAX_ANALYSIS_BYTES or len(result) >= claims.MAX_EVENTS:
            tm.error("analysis_data_size_limit", 6)
        result.append(event)
    return result


def _assemble(sources, events, objects, revision, integrity, *, consume_events=False):
    """Nomina humana et viae locales vim semanticam non habent."""
    clocks, families, identities = {}, {}, {}
    duplicates = []
    active_ids = {row["id"] for row in events}
    source_ids = {row["id"] for row in sources}
    for obj in sorted(objects, key=lambda item: (item["revision"], item["id"])):
        data, kind = obj["data"], obj["kind"]
        if kind == "clock_model":
            tm.validate_clock_model(data["model"])
            for artifact in tm.refs(data["artifact_ids"], 20000):
                if artifact in source_ids:
                    clocks[artifact] = data["model"]
        elif kind == "source_family":
            text_field(data["family_id"], 128)
            for artifact in tm.refs(data["artifact_ids"], 20000):
                if artifact in source_ids:
                    families[artifact] = data["family_id"]
        elif kind == "duplicate_groups":
            duplicates = deepcopy(data["groups"])
        elif kind == "identity_assertion":
            assertion = deepcopy(data["assertion"])
            logical_id = assertion.pop("id")
            identities[logical_id] = (obj["id"], assertion)
    assertions = []
    event_assertions = {}
    for _, (identity, value) in sorted(identities.items()):
        members = [member for member in value["event_ids"] if member in active_ids]
        status = value["status"] if len(members) == len(value["event_ids"]) else "withdrawn"
        assertion = {"id": identity, "status": status, "event_ids": members, "source_family_ids": value["source_family_ids"]}
        assertion.update({key: value[key] for key in ("namespace", "canonical_value", "rationale") if key in value})
        assertions.append(assertion)
        for member in members:
            event_assertions.setdefault(member, []).append(identity)
    result = {"schema": "testifex.analysis-data.v1", "revision": revision, "integrity": integrity,
              "sources": [], "events": [], "duplicate_groups": [], "identity_assertions": assertions, "limitations": []}
    for source in sorted(sources, key=lambda item: item["id"]):
        complete = source.get("interpretation_complete") is True and source.get("unprocessed_bytes") == 0
        reasons = [] if complete else ["source_coverage_incomplete"]
        result["sources"].append({"artifact_id": source["id"], "parse_run_id": source["parse_run_id"], "complete": complete,
                                  "family_id": families.get(source["id"]), "coverage_digest": object_digest(_coverage(source)), "reasons": reasons})
    renames = {"src_ip": "source_ip", "dst_ip": "destination_ip", "path": "payload.path", "action": "payload.action"}
    ordered_events = events if consume_events else sorted(events, key=lambda item: item["id"])
    if consume_events:
        ordered_events.sort(key=lambda item: item["id"])
        result["events"] = ordered_events
    for index, event in enumerate(ordered_events):
        fields = {}
        for field in ("kind", "host", "actor", "src_ip", "dst_ip", "path", "action"):
            if field in event:
                fields[renames.get(field, field)] = event[field]
        for key, value in event.get("attributes", {}).items():
            target = "payload." + key
            if target in claims.FIELDS:
                fields[target] = value
        for key, value in event.get("payload", {}).items():
            target = "payload." + key
            if target in claims.FIELDS:
                fields[target] = value
        normalized = {"id": event["id"], "artifact_id": event["artifact_id"], "parse_run_id": event["parse_run_id"],
                                 "fields": fields, "recorded_time": event.get("recorded_time"), "clock_model": clocks.get(event["artifact_id"]),
                                 "entity_assertion_ids": sorted(event_assertions.get(event["id"], []))}
        if consume_events:
            ordered_events[index] = normalized
        else:
            result["events"].append(normalized)
    for group in duplicates:
        members = [member for member in group["event_ids"] if member in active_ids]
        if members:
            result["duplicate_groups"].append({"id": group["id"], "event_ids": members})
    claims.validate_data(result)
    return result


def load_data(case, *, analysis_limits=None):
    """Lectio in una imagine SQLite fit; pagina nulla tacite omittitur."""
    configured = normalize_analysis_limits(analysis_limits) if analysis_limits is not None else None
    revision = case.revision
    verification = case.verify()
    sources, rows, offset, size = case.sources(), [], 0, 0
    while True:
        page = case.query_events(limit=1000, offset=offset, expected_revision=revision)
        if page["total"] > (configured["max_events"] if configured else claims.MAX_EVENTS):
            tm.error("analysis_event_limit", 6)
        for row in page["rows"]:
            event = _compact_event(row)
            size += len(canonical_bytes(event))
            if size > MAX_ANALYSIS_BYTES:
                tm.error("analysis_data_size_limit", 6)
            rows.append(event)
        offset += len(page["rows"])
        if offset >= page["total"]:
            break
        if not page["rows"]:
            tm.error("analysis_pagination_incomplete", 4)
    try:
        integrity = "verified" if verification["ok"] else "failed"
        if verification["ok"] and (verification.get("completeness") == "partial" or verification.get("authorized_unavailable")):
            integrity = "unavailable"
        return _assemble(sources, rows, case.objects(), revision, integrity, consume_events=True)
    except (KeyError, TypeError, AttributeError):
        tm.error("invalid_investigation_object", 4)


def data_fingerprint(data):
    claims.validate_data(data)
    return claims.semantic_digest(data, "TESTIFEX-CASE-ANALYSIS-INPUT-V1")


def _known_refs(case, data):
    return ({item["artifact_id"] for item in data["sources"]} | {item["parse_run_id"] for item in data["sources"]}
            | {item["id"] for item in data["events"]} | {item["id"] for item in case.objects()})


def _require_refs(values, known):
    if not set(values) <= known:
        tm.error("dependency_reference_missing")


def validate_graph(nodes, edges):
    tm.refs(nodes, MAX_GRAPH_NODES)
    claims._list(edges, MAX_GRAPH_EDGES, "dependency_edge_limit")
    known, successors, degrees, seen = set(nodes), {}, dict.fromkeys(nodes, 0), set()
    for edge in edges:
        tm.exact_dict(edge, {"dependency", "dependent", "type"}, {"dependency", "dependent", "type"})
        tm.identifier(edge["dependency"])
        tm.identifier(edge["dependent"])
        text_field(edge["type"], 64)
        if edge["dependency"] not in known or edge["dependent"] not in known:
            tm.error("dependency_reference_missing")
        pair = (edge["dependency"], edge["dependent"], edge["type"])
        if pair in seen:
            tm.error("duplicate_dependency_edge")
        seen.add(pair)
        successors.setdefault(edge["dependency"], []).append(edge["dependent"])
        degrees[edge["dependent"]] += 1
    queue = deque(sorted(key for key, value in degrees.items() if value == 0))
    visited = 0
    while queue:
        node = queue.popleft()
        visited += 1
        for dependent in successors.get(node, []):
            degrees[dependent] -= 1
            if degrees[dependent] == 0:
                queue.append(dependent)
    if visited != len(nodes):
        tm.error("dependency_cycle")
    return {"nodes": sorted(nodes), "edges": sorted(deepcopy(edges), key=lambda item: (item["dependency"], item["dependent"], item["type"]))}


def stale_descendants(nodes, edges, changed):
    graph = validate_graph(nodes, edges)
    tm.refs(changed, MAX_GRAPH_NODES)
    _require_refs(changed, set(nodes))
    successors, found = {}, set(changed)
    for edge in graph["edges"]:
        successors.setdefault(edge["dependency"], []).append(edge["dependent"])
    queue = deque(changed)
    while queue:
        for item in successors.get(queue.popleft(), []):
            if item not in found:
                found.add(item)
                queue.append(item)
    return sorted(found - set(changed))


def save_dependency_graph(case, nodes, edges, *, expected_revision=None):
    revision = _expect(case, expected_revision)
    graph = validate_graph(nodes, edges)
    _require_refs(nodes, _known_refs(case, load_data(case)))
    merged_nodes, merged_edges = set(nodes), {(edge["dependency"], edge["dependent"], edge["type"]): edge for edge in edges}
    for previous in case.objects("dependency_graph"):
        prior = validate_graph(previous["data"]["nodes"], previous["data"]["edges"])
        merged_nodes.update(prior["nodes"])
        for edge in prior["edges"]:
            merged_edges[(edge["dependency"], edge["dependent"], edge["type"])] = edge
    validate_graph(sorted(merged_nodes), list(merged_edges.values()))
    return case.put_object("dependency_graph", {"schema": "testifex.dependency-graph.v1", **graph}, expected_revision=revision)


def save_claim(case, claim, *, expected_revision=None, previous_id=None, author="local"):
    revision = _expect(case, expected_revision)
    value = claims.validate_claim(claim)
    text_field(author, 128)
    data = load_data(case)
    requested = deepcopy(value["scope"])
    value["scope"] = claims.resolve_scope(value["scope"], data)
    _require_refs(value["scope"]["artifact_ids"], {row["artifact_id"] for row in data["sources"]})
    active = {row["artifact_id"]: row["parse_run_id"] for row in data["sources"]}
    if any(active[run["artifact_id"]] != run["parse_run_id"] for run in value["scope"]["active_parse_runs"]):
        tm.error("scope_parse_selection_unavailable")
    operands = value["operands"]
    event_refs = [operands[key] for key in ("before", "after", "anchor_event") if key in operands]
    event_refs += [operands[key]["event_id"] for key in ("left", "right") if key in operands]
    _require_refs(event_refs, {row["id"] for row in data["events"]})
    available = {row["id"] for row in data["identity_assertions"]}
    available.update(row["clock_model"].get("assumption_id") for row in data["events"] if row["clock_model"] is not None)
    _require_refs(value["assumptions"], available)
    previous = _object(case, previous_id, "claim") if previous_id is not None else None
    records = list_claims(case)
    matching = [item for item in records if item["data"]["claim"]["id"] == value["id"]]
    if matching and (previous is None or previous["id"] != matching[-1]["id"]):
        tm.error("claim_previous_revision_required", 5)
    if previous is not None and previous["data"]["claim"]["id"] != value["id"]:
        tm.error("claim_history_mismatch")
    payload = {"schema": "testifex.claim-record.v1", "claim": value, "scope_request": requested,
               "previous_id": previous_id, "author": author, "input_revision": revision}
    return case.put_object("claim", payload, expected_revision=revision)


def list_claims(case):
    return case.objects("claim")


def save_clock(case, model, artifact_ids, *, expected_revision=None):
    revision = _expect(case, expected_revision)
    tm.validate_clock_model(model)
    tm.refs(artifact_ids, 20000)
    if not artifact_ids:
        tm.error("clock_artifacts_required")
    data = load_data(case)
    _require_refs(artifact_ids, {row["artifact_id"] for row in data["sources"]})
    _require_refs(model["basis_refs"], {row["artifact_id"] for row in data["sources"]} | {row["id"] for row in data["events"]})
    available_families = {row["family_id"] for row in data["sources"] if row["family_id"] is not None}
    _require_refs(model.get("source_family_ids", []), available_families)
    candidate = deepcopy(data)
    checked_model = deepcopy(model)
    for event in candidate["events"]:
        if event["artifact_id"] in artifact_ids:
            event["clock_model"] = checked_model
    claims.validate_data(candidate)
    return case.put_object("clock_model", {"model": model, "artifact_ids": sorted(artifact_ids)}, expected_revision=revision)


def save_family(case, family_id, artifact_ids, basis_refs, rationale, *, expected_revision=None):
    revision = _expect(case, expected_revision)
    text_field(family_id, 128)
    text_field(rationale, 4096)
    tm.refs(artifact_ids, 20000)
    tm.refs(basis_refs, 32)
    if not artifact_ids:
        tm.error("family_artifacts_required")
    data = load_data(case)
    _require_refs(artifact_ids, {row["artifact_id"] for row in data["sources"]})
    _require_refs(basis_refs, _known_refs(case, data))
    return case.put_object("source_family", {"family_id": family_id, "artifact_ids": sorted(artifact_ids), "basis_refs": basis_refs, "rationale": rationale}, expected_revision=revision)


def save_duplicates(case, groups, *, expected_revision=None):
    revision = _expect(case, expected_revision)
    data = load_data(case)
    data["duplicate_groups"] = deepcopy(groups)
    claims.validate_data(data)
    return case.put_object("duplicate_groups", {"groups": groups}, expected_revision=revision)


def save_identity(case, assertion, *, expected_revision=None):
    revision = _expect(case, expected_revision)
    data = load_data(case)
    tm.exact_dict(assertion, {"id", "status", "event_ids", "source_family_ids", "namespace", "canonical_value", "rationale"}, {"id", "status", "event_ids", "source_family_ids"})
    tm.identifier(assertion["id"])
    data["identity_assertions"] = [row for row in data["identity_assertions"] if row["id"] != assertion["id"]] + [deepcopy(assertion)]
    claims.validate_data(data)
    _require_refs(assertion["source_family_ids"], {row["family_id"] for row in data["sources"] if row["family_id"] is not None})
    return case.put_object("identity_assertion", {"assertion": assertion}, expected_revision=revision)


def evaluate(case, claim_id, *, expected_revision=None, persist=True, analysis_limits=None):
    revision = _expect(case, expected_revision)
    if type(persist) is not bool:
        tm.error("invalid_persist_flag")
    record = _object(case, claim_id, "claim")
    data = load_data(case, analysis_limits=analysis_limits)
    dependency = _dependency_snapshot(record["data"]["claim"], data, case.objects(), analysis_limits=analysis_limits)
    result = _analyze_dependency_snapshot(dependency)
    by_id = {row["id"]: row for row in data["events"]}
    witnesses = result["evaluations"][0]["witness_set"]
    lineage = [{"event_id": key, "artifact_id": by_id[key]["artifact_id"], "parse_run_id": by_id[key]["parse_run_id"],
                "clock_model_digest": object_digest(by_id[key]["clock_model"]) if by_id[key]["clock_model"] is not None else None,
                "entity_assertion_ids": by_id[key]["entity_assertion_ids"]} for key in witnesses]
    payload = {"schema": "testifex.case-evaluation.v1", "claim_object_id": record["id"], "claim_revision": record["revision"],
               "result": result, "data_fingerprint": data_fingerprint(data), "input_revision": revision,
               "evaluation_dependencies": dependency["binding"],
               "witness_lineage": lineage,
               "dependency_bindings": {"claim_revision": record["id"], "scope": result["evaluations"][0]["scope_digest"],
                                       "query": result["evaluations"][0]["query_digest"], "coverage": result["evaluations"][0]["coverage_digest"],
                                       "interpretations": result["evaluations"][0]["interpretation_set_digest"], "engine_version": claims.ENGINE_VERSION},
               "source_catalog": [{"artifact_id": row["id"], "parse_run_id": row["parse_run_id"], "coverage_digest": object_digest(_coverage(row)),
                                   "coverage_snapshot": _coverage(row)} for row in case.sources()]}
    _bounded_report(payload, normalize_analysis_limits(analysis_limits) if analysis_limits is not None else None)
    return case.put_object("evaluation", payload, expected_revision=revision) if persist else payload


def _dependency_snapshot(claim, data, objects, *, analysis_limits=None):
    """Familiae declaratae etiam a fundamento immutabili pendent."""
    premises = {}
    for obj in sorted(objects, key=lambda row: (row["revision"], row["id"])):
        if obj["kind"] == "source_family":
            value = obj["data"]
            tm.refs(value["artifact_ids"], 20000)
            tm.refs(value["basis_refs"], 32)
            for identity in value["artifact_ids"]:
                premises[identity] = {"binding_id": obj["id"], "basis_refs": value["basis_refs"]}
    return claims.dependency_snapshot(claim, data, family_premises=premises, analysis_limits=analysis_limits)


def _analyze_dependency_snapshot(selected):
    result = claims.analyze([selected["claim"]], selected["data"], max_memberships=selected["binding"]["execution_limits"]["max_memberships"],
                            analysis_limits=selected["binding"].get("analysis_limits"))
    result["dependency_fingerprint"] = selected["binding"]["fingerprint"]
    result["digest"] = object_digest({key: item for key, item in result.items() if key != "digest"}, "TESTIFEX-ANALYSIS-RESULT-V1")
    return result


def stale_status_many(case, evaluation_ids, *, max_evaluations=1000):
    """Una imago communis; idem examen singulis et pluribus valet."""
    tm.integer(max_evaluations, 1, 10000)
    tm.refs(evaluation_ids, max_evaluations)
    revision = case.revision
    objects = case.objects()
    latest = {}
    for row in sorted(objects, key=lambda item: (item["revision"], item["id"])):
        if row["kind"] == "claim":
            try:
                latest[row["data"]["claim"]["id"]] = row
            except (KeyError, TypeError, AttributeError):
                tm.error("invalid_investigation_object", 4)
    context = {"objects": objects, "objects_by_id": {row["id"]: row for row in objects}, "latest_claims": latest,
               "sources": case.sources(), "bindings": {}, "work": 0, "load_error": None, "fingerprint": None, "data": None}
    if evaluation_ids:
        try:
            context["data"] = load_data(case)
            context["fingerprint"] = data_fingerprint(context["data"])
        except ProbentiumError as exc:
            if exc.exit_code != 6:
                raise
            context["load_error"] = exc
    try:
        statuses = [{"evaluation_id": identity, **_stale_status_loaded(context, identity)} for identity in evaluation_ids]
    except (KeyError, TypeError, AttributeError):
        tm.error("invalid_investigation_object", 4)
    if case.revision != revision:
        tm.error("revision_conflict", 5)
    return {"schema": "testifex.currentness-batch.v1", "revision": revision, "statuses": statuses,
            "execution_state": "aborted_limit" if any("dependency_recomputation_limit" in row["reasons"] for row in statuses) else "complete",
            "limits": {"max_evaluations": max_evaluations, "max_event_evaluation_memberships": 1000000}}


def stale_status(case, evaluation_id):
    row = stale_status_many(case, [evaluation_id])["statuses"][0]
    return {key: value for key, value in row.items() if key != "evaluation_id"}


def _stale_status_loaded(context, evaluation_id):
    tm.identifier(evaluation_id)
    record = context["objects_by_id"].get(evaluation_id)
    if record is None or record["kind"] != "evaluation":
        tm.error("investigation_object_kind_mismatch")
    value = record["data"]
    binding = value.get("evaluation_dependencies")
    if binding is not None and not isinstance(binding, dict):
        tm.error("evaluation_dependency_binding_invalid", 4)
    claim = context["objects_by_id"].get(value["claim_object_id"])
    if claim is None or claim["kind"] != "claim":
        tm.error("investigation_object_kind_mismatch")
    latest = context["latest_claims"][claim["data"]["claim"]["id"]]
    if binding is not None and binding.get("schema") == "testifex.evaluation-dependencies.v1":
        if binding.get("fingerprint") != object_digest({key: item for key, item in binding.items() if key != "fingerprint"}, "TESTIFEX-EVALUATION-DEPENDENCIES-V1"):
            tm.error("evaluation_dependency_binding_invalid", 4)
        analysis = value["result"]["input"]
        if (value["result"].get("dependency_fingerprint") != binding["fingerprint"]
                or any(binding.get(key) != analysis.get(key) for key in ("analysis_data_digest", "event_set_digest", "interpretation_set_digest"))):
            tm.error("evaluation_dependency_analysis_mismatch", 4)
        reasons = []
        try:
            if context["load_error"] is not None:
                raise context["load_error"]
            data, current = context["data"], context["fingerprint"]
            cache_key = object_digest([claim["id"], binding.get("analysis_limits")])
            if cache_key not in context["bindings"]:
                context["work"] += max(1, len(data["events"]))
                if context["work"] > 1000000:
                    tm.error("dependency_recomputation_limit", 6)
                context["bindings"][cache_key] = _dependency_snapshot(claim["data"]["claim"], data, context["objects"], analysis_limits=binding.get("analysis_limits"))["binding"]
            actual = context["bindings"][cache_key]
            if actual != binding:
                reasons.append("scoped_evidence_or_premises_changed")
        except ProbentiumError as exc:
            if exc.exit_code != 6:
                raise
            current, actual = None, None
            reasons.append("dependency_recomputation_limit")
        if latest["id"] != claim["id"]:
            reasons.append("claim_revision_superseded")
        return {"status": "stale" if reasons else "current", "reasons": reasons,
                "comparison_basis": "scoped_dependencies_v1", "original_input_digest": value["data_fingerprint"],
                "current_input_digest": current, "current_input_recomputed": current is not None,
                "global_input_changed": current != value["data_fingerprint"] if current is not None else None,
                "original_dependency_digest": binding["fingerprint"],
                "current_dependency_digest": actual["fingerprint"] if actual is not None else None}
    catalog = [{"artifact_id": row["id"], "parse_run_id": row["parse_run_id"], "coverage_digest": object_digest(_coverage(row))} for row in context["sources"]]
    previous_catalog = [{key: row[key] for key in ("artifact_id", "parse_run_id", "coverage_digest")} for row in value["source_catalog"]]
    catalog_changed = catalog != previous_catalog
    current = None if catalog_changed else context["fingerprint"]
    reasons = ["legacy_dependency_binding_unavailable" if binding is None else "dependency_version_unsupported"]
    if catalog_changed or current != value["data_fingerprint"]:
        reasons.append("evidence_query_or_coverage_changed")
    if latest["id"] != claim["id"]:
        reasons.append("claim_revision_superseded")
    return {"status": "stale" if reasons else "current", "reasons": reasons,
            "comparison_basis": "legacy_conservative",
            "original_input_digest": value["data_fingerprint"], "current_input_digest": current,
            "current_input_recomputed": not catalog_changed}


def _explanation_record(case, evaluation_id):
    """Nexus immutabiles ante expositionem comprobantur."""
    try:
        record = _object(case, evaluation_id, "evaluation")
        value = record["data"]
        claim = _object(case, value["claim_object_id"], "claim")
        claims.validate_claim(claim["data"]["claim"])
        result = value["result"]
        if len(result["evaluations"]) != 1 or result["digest"] != object_digest({k: v for k, v in result.items() if k != "digest"}, "TESTIFEX-ANALYSIS-RESULT-V1"):
            tm.error("explanation_result_binding_invalid", 4)
        evaluation = result["evaluations"][0]
        if (evaluation["id"] != object_digest({k: v for k, v in evaluation.items() if k != "id"}, "TESTIFEX-EVALUATION-V1")
                or result["evaluation_ids"] != [evaluation["id"]]
                or value["claim_revision"] != claim["revision"]
                or evaluation["claim_digest"] != object_digest({k: v for k, v in claim["data"]["claim"].items() if k != "human_label"})):
            tm.error("explanation_claim_binding_invalid", 4)
        tm.integer(value["input_revision"], claim["revision"], record["revision"] - 1)
        ids = tm.refs(evaluation["witness_set"], 256)
        tm.integer(evaluation["witness_count"], len(ids), claims.MAX_EVENTS)
        if (type(evaluation["witness_set_complete"]) is not bool
                or evaluation["witness_set_complete"] != (evaluation["witness_count"] == len(ids))
                or ids != sorted(ids)
                or evaluation["witness_set_complete"] and evaluation["witness_set_digest"] != object_digest(ids)):
            tm.error("explanation_witness_set_invalid", 4)
        tm.identifier(evaluation["witness_set_digest"])
        return value, claim, evaluation
    except (KeyError, TypeError, AttributeError, IndexError):
        tm.error("explanation_schema_invalid", 4)


def _build_witness_graph(case, value, claim, evaluation):
    """Locatores ex tabulis probatis, non ex verbis humanis, ducuntur."""
    verification = case.verify()
    if not verification["ok"]:
        tm.error("explanation_integrity_failed", 4)
    wanted = set(evaluation["witness_set"])
    rows = {}
    if wanted:
        for index, row in enumerate(case.iter_snapshot_rows("events")):
            if index >= 10000000:
                tm.error("explanation_event_limit", 6)
            if row["id"] in wanted:
                rows[row["id"]] = row
            if len(rows) == len(wanted):
                break
    if set(rows) != wanted:
        tm.error("explanation_witness_missing", 4)
    record_ids = {ref for row in rows.values() for ref in tm.refs(row["record_refs"], 32)}
    record_rows = {}
    if record_ids:
        for index, record in enumerate(case.iter_snapshot_rows("records")):
            if index >= 10000000:
                tm.error("explanation_record_limit", 6)
            if record["id"] in record_ids:
                record_rows[record["id"]] = record
            if len(record_rows) == len(record_ids):
                break
    if set(record_rows) != record_ids:
        tm.error("explanation_record_missing", 4)
    from .locators import event_records
    event_locators = {key: event_records(row, record_rows.get) for key, row in rows.items()}
    catalog = {}
    for entry in value["source_catalog"]:
        source = entry.get("coverage_snapshot")
        if source is None or object_digest(source) != entry["coverage_digest"]:
            tm.error("explanation_coverage_binding_invalid", 4)
        if source["id"] != entry["artifact_id"] or source["parse_run_id"] != entry["parse_run_id"]:
            tm.error("explanation_coverage_binding_invalid", 4)
        catalog[source["id"]] = source
    for row in rows.values():
        source = catalog.get(row["artifact_id"])
        if (source is None or row["parse_run_id"] != source["parse_run_id"]
                or any(record["offset"] + record["length"] > source["cursor"] for record in event_locators[row["id"]])):
            tm.error("explanation_historical_witness_invalid", 4)
    objects = [row for row in case.objects() if row["revision"] <= value["input_revision"]]
    historical = _assemble(list(catalog.values()), _collect_events(rows.values()), objects, value["input_revision"], "verified")
    interpretations = {row["id"]: row for row in historical["events"]}
    lineage_rows = value.get("witness_lineage", [])
    claims._list(lineage_rows, 256, "explanation_lineage_limit")
    lineage = {row["event_id"]: row for row in lineage_rows}
    if len(lineage) != len(lineage_rows) or set(lineage) != wanted:
        tm.error("explanation_lineage_binding_invalid", 4)
    unavailable = {row["artifact_id"] for row in verification.get("authorized_unavailable", [])}
    witnesses, edges = [], []
    for identity in sorted(wanted):
        row, saved, interpreted = rows[identity], lineage[identity], interpretations[identity]
        clock_digest = object_digest(interpreted["clock_model"]) if interpreted["clock_model"] is not None else None
        if (saved["artifact_id"] != row["artifact_id"] or saved["parse_run_id"] != row["parse_run_id"]
                or saved["clock_model_digest"] != clock_digest or saved["entity_assertion_ids"] != interpreted["entity_assertion_ids"]):
            tm.error("explanation_interpretation_binding_invalid", 4)
        interpretation = claims.interpretation_id(interpreted)
        locators = [{"record_id": record["id"], **{key: record[key] for key in ("artifact_id", "ordinal", "offset", "length", "raw_digest")}}
                    for record in event_locators[identity]]
        item = {"event_id": identity, "interpretation_id": interpretation, "parse_run_id": row["parse_run_id"],
                          "artifact_id": row["artifact_id"], "record_refs": row["record_refs"], "records": locators,
                          "clock_model_digest": clock_digest, "entity_assertion_ids": interpreted["entity_assertion_ids"],
                          "raw_verification": "authorized_unavailable" if row["artifact_id"] in unavailable else "case_record_bytes_verified"}
        if len(locators) > 1:
            item["primary_record_ref"] = row["primary_record_ref"]
        witnesses.append(item)
        edges.extend([{"from": claim["id"], "to": interpretation, "type": "uses_interpretation"},
                      {"from": interpretation, "to": identity, "type": "interprets_event"}])
        for locator in locators:
            edges.extend([{"from": identity, "to": locator["record_id"], "type": "derived_from_record"},
                          {"from": locator["record_id"], "to": row["artifact_id"], "type": "located_in_artifact"}])
    return {"schema": "testifex.witness-graph.v1", "witnesses": witnesses, "edges": edges,
            "count": evaluation["witness_count"], "shown": len(witnesses), "limit": 256,
            "complete": evaluation["witness_set_complete"], "witness_set_digest": evaluation["witness_set_digest"],
            "excerpt_digest": object_digest(sorted(wanted)), "case_integrity": verification["completeness"],
            "basis": "stored_historical_interpretation_and_verified_record_locators",
            "limitations": ["not_a_globally_minimal_proof", "stored_evaluation_not_reexecuted_by_explain",
                            "hashes_do_not_authenticate_record_authorship", "parser_reexecution_not_performed"]}


def _witness_graph(case, value, claim, evaluation):
    try:
        return _build_witness_graph(case, value, claim, evaluation)
    except (KeyError, TypeError, AttributeError, IndexError):
        tm.error("explanation_lineage_schema_invalid", 4)


def _typed_gaps(value, claim, evaluation, evaluation_id, graph):
    """Condiciones ex limite noto deducuntur; numeri ignoti non finguntur."""
    specification = claim["data"]["claim"]
    predicate, operands = specification["predicate"], specification["operands"]
    reasons = list(evaluation["reasons"])
    if predicate == "ordered_within" and evaluation["verdict"] == "unresolved" and evaluation["difference"] is not None:
        reasons.append("temporal_boundary_overlap")
    if any(row["raw_verification"] == "authorized_unavailable" for row in graph["witnesses"]):
        reasons.append("raw_evidence_unavailable")
    gaps = []
    for reason in sorted(set(reasons)):
        category = ("temporal" if reason.startswith(("clock_", "recorded_time", "anchor_time", "temporal_"))
                    else "coverage" if reason in ("source_coverage_incomplete", "matching_or_time_unknown")
                    else "identity" if reason.startswith(("identity_", "assumption_"))
                    else "integrity" if reason in ("input_integrity_not_verified", "raw_evidence_unavailable")
                    else "execution" if reason == "analysis_membership_limit"
                    else "membership" if reason == "joint_feasibility_not_evaluated"
                    else "field" if reason == "field_value_unknown" else "scope")
        condition = {"status": "unquantified", "criterion": "Additional attributable evidence or an explicit scope revision is required.",
                     "expected_effect": "May permit reevaluation; no resulting verdict is guaranteed.",
                     "limitations": ["no_numeric_evidence_requirement_derivable_from_this_result"]}
        if reason == "temporal_boundary_overlap":
            condition = {"status": "derived", "type": "relation_interval_separation",
                         "observed_difference": evaluation["difference"],
                         "accepted_interval": tm.interval(0, int(operands["window_us"]), False, True),
                         "entailed_when": "Every supported after-minus-before value lies inside the accepted interval.",
                         "ruled_out_when": "No supported after-minus-before value intersects the accepted interval.",
                         "expected_effect": "Resolves this temporal boundary ambiguity if supported bounds establish containment or disjointness.",
                         "limitations": ["no_specific_clock_tightening_amount_inferred", "new_bounds_require_evidence_or_an_attributed_assumption"]}
        elif reason == "joint_feasibility_not_evaluated" and evaluation["count"] is not None:
            count = evaluation["count"]
            condition = {"status": "derived", "type": "count_bound_separation", "unit": count["unit"],
                         "current_lower": count["lower"], "current_upper": count["upper"], "threshold": count["threshold"],
                         "additional_definite_units_required": max(0, count["threshold"] - count["lower"]),
                         "refutation_upper_at_most": count["threshold"] - 1,
                         "expected_effect": "A supported lower bound at threshold entails; a complete supported upper bound below threshold refutes.",
                         "limitations": ["possible_memberships_are_not_a_jointly_feasible_assignment", "units_are_not_real_world_attempts"]}
        elif reason == "source_coverage_incomplete":
            condition["type"] = "source_disposition_completion"
            condition["supplied_coverage"] = [{"artifact_id": row["artifact_id"], "parse_run_id": row["parse_run_id"],
                                               "unprocessed_bytes": row["coverage_snapshot"]["unprocessed_bytes"],
                                               "counters": row["coverage_snapshot"]["counters"]} for row in value["source_catalog"]
                                              if row["artifact_id"] in specification["scope"]["artifact_ids"]]
            condition["criterion"] = "Account for unprocessed bytes and unsupported, malformed or oversize records in the declared stream before an absence or finite count upper bound. Reparse or explicitly revise scope; do not discard contrary records."
        elif reason == "field_value_unknown":
            condition["required_fields"] = [operands[key] for key in ("left", "right")]
            condition["criterion"] = "Provide supported non-null values for the specified fields; equal typed values entail and unequal typed values refute this equality only."
        gap = {"schema": "testifex.gap.v1", "type": category, "code": reason, "reason": reason,
               "affected_claim_ids": [claim["id"]], "evaluation_id": evaluation_id,
               "basis": {"evaluation_result_id": evaluation["id"], "verdict": evaluation["verdict"],
                         "scope_digest": evaluation["scope_digest"], "query_digest": evaluation["query_digest"],
                         "coverage_digest": evaluation["coverage_digest"]},
               "next_step": _GAPS.get(reason, "Inspect the recorded limitation and the supplied source scope."),
               "discrimination_condition": condition}
        gap["id"] = object_digest(gap, "TESTIFEX-GAP-V1")
        gaps.append(gap)
    return gaps


def explain(case, evaluation_id):
    value, claim, evaluation = _explanation_record(case, evaluation_id)
    graph = _witness_graph(case, value, claim, evaluation)
    paths = [[evaluation_id, claim["id"], identity] for identity in evaluation["witness_set"]]
    clock_objects = {object_digest(row["data"]["model"]): row for row in case.objects("clock_model") if row["revision"] <= value["input_revision"]}
    for item in graph["witnesses"]:
        paths.append([evaluation_id, claim["id"], item["event_id"], item["parse_run_id"], item["artifact_id"]])
        for record_ref in item["record_refs"]:
            paths.append([evaluation_id, claim["id"], item["interpretation_id"], item["event_id"], record_ref, item["artifact_id"]])
        binding = clock_objects.get(item["clock_model_digest"])
        if binding is not None:
            for basis in binding["data"]["model"]["basis_refs"]:
                paths.append([evaluation_id, claim["id"], item["event_id"], binding["id"], basis])
    return {"evaluation_id": evaluation_id, "evaluation": evaluation, "staleness": stale_status(case, evaluation_id),
            "paths": paths, "path_description": "available direct witness and support paths; not a globally minimal proof", "dependency_bindings": value.get("dependency_bindings", {}),
            "gaps": _typed_gaps(value, claim, evaluation, evaluation_id, graph), "witness_graph": graph,
            "interpretation": "Conditional on declared source, parser, clock and identity inputs; no physical causality asserted."}


def witness(case, evaluation_id, event_id):
    """Octeti originales solum forma base64 redduntur; historia manet explicita."""
    tm.identifier(event_id)
    value, claim, evaluation = _explanation_record(case, evaluation_id)
    if event_id not in evaluation["witness_set"]:
        tm.error("event_not_in_saved_witness_excerpt", 2)
    graph = _witness_graph(case, value, claim, evaluation)
    identity = next(row for row in graph["witnesses"] if row["event_id"] == event_id)
    if len(identity["records"]) > 1:
        segments = case.raw_records(event_id)
        if not isinstance(segments, list) or len(segments) != len(identity["records"]):
            tm.error("witness_raw_binding_invalid", 4)
        output, total = [], 0
        for segment, locator in zip(segments, identity["records"]):
            if (not isinstance(segment, dict) or set(segment) != {"record", "bytes", "primary"}
                    or not isinstance(segment["record"], dict)):
                tm.error("witness_raw_binding_invalid", 4)
            record, raw = segment["record"], segment["bytes"]
            primary = locator["record_id"] == identity["primary_record_ref"]
            if (not isinstance(raw, bytes) or type(segment["primary"]) is not bool or segment["primary"] != primary
                    or record.get("id") != locator["record_id"]
                    or any(record.get(key) != locator[key] for key in ("artifact_id", "ordinal", "offset", "length", "raw_digest"))):
                tm.error("witness_raw_binding_invalid", 4)
            digest = hashlib.sha256(raw).hexdigest()
            if digest != locator["raw_digest"] or len(raw) != locator["length"]:
                tm.error("witness_raw_binding_invalid", 4)
            total += len(raw)
            output.append({"record_id": locator["record_id"], "primary": primary, "offset": locator["offset"],
                           "raw_base64": base64.b64encode(raw).decode("ascii"), "raw_sha256": digest, "raw_bytes": len(raw)})
        return {"schema": "testifex.witness.v2", "evaluation_id": evaluation_id, "claim_id": claim["id"], "identity": identity,
                "raw_encoding": "base64_per_record", "raw_segments": output, "raw_bytes": total,
                "history": {"input_revision": value["input_revision"], "claim_revision": value["claim_revision"],
                            "evaluation_result_id": evaluation["id"], "analysis_input_digest": value["result"]["input_digest"],
                            "staleness": stale_status(case, evaluation_id)},
                "membership": "saved_witness_excerpt_only", "witness_set_complete": evaluation["witness_set_complete"],
                "limitations": graph["limitations"] + ["record_segments_are_not_a_concatenated_original"]}
    raw = case.raw(event_id)
    digest = hashlib.sha256(raw).hexdigest()
    locator = identity["records"][0]
    if digest != locator["raw_digest"] or len(raw) != locator["length"]:
        tm.error("witness_raw_binding_invalid", 4)
    return {"schema": "testifex.witness.v1", "evaluation_id": evaluation_id, "claim_id": claim["id"],
            "identity": identity, "raw_encoding": "base64", "raw_base64": base64.b64encode(raw).decode("ascii"),
            "raw_sha256": digest, "raw_bytes": len(raw), "history": {"input_revision": value["input_revision"],
             "claim_revision": value["claim_revision"], "evaluation_result_id": evaluation["id"],
             "analysis_input_digest": value["result"]["input_digest"], "staleness": stale_status(case, evaluation_id)},
            "membership": "saved_witness_excerpt_only", "witness_set_complete": evaluation["witness_set_complete"],
            "limitations": graph["limitations"]}


def validate_scenario(scenario):
    tm.exact_dict(scenario, {"schema", "id", "remove_families", "exclude_duplicate_groups", "revoke_identities", "widen_clock_errors"},
                  {"schema", "id", "remove_families", "exclude_duplicate_groups", "revoke_identities", "widen_clock_errors"})
    if scenario["schema"] != "testifex.scenario.v1":
        tm.error("unsupported_scenario_schema", 7)
    text_field(scenario["id"], 128)
    claims._names(scenario["remove_families"], 64)
    claims._names(scenario["exclude_duplicate_groups"], 64)
    tm.refs(scenario["revoke_identities"], 64)
    claims._list(scenario["widen_clock_errors"], 64, "scenario_clock_limit")
    seen = set()
    for row in scenario["widen_clock_errors"]:
        tm.exact_dict(row, {"clock_id", "local_error"}, {"clock_id", "local_error"})
        text_field(row["clock_id"], 128)
        tm.validate_interval(row["local_error"], nullable=False)
        if row["clock_id"] in seen:
            tm.error("duplicate_clock_overlay")
        seen.add(row["clock_id"])
    return deepcopy(scenario)


def apply_scenario(data, scenario):
    claims.validate_data(data)
    validate_scenario(scenario)
    result = deepcopy(data)
    families = {row["family_id"] for row in data["sources"] if row["family_id"] is not None}
    _require_refs(scenario["remove_families"], families)
    group_map = {row["id"]: row["event_ids"] for row in data["duplicate_groups"]}
    _require_refs(scenario["exclude_duplicate_groups"], set(group_map))
    _require_refs(scenario["revoke_identities"], {row["id"] for row in data["identity_assertions"]})
    removed_families = set(scenario["remove_families"])
    removed_sources = {row["artifact_id"] for row in data["sources"] if row["family_id"] in removed_families}
    removed_events = {row["id"] for row in data["events"] if row["artifact_id"] in removed_sources}
    excluded = set(member for group in scenario["exclude_duplicate_groups"] for member in group_map[group])
    removed_events.update(excluded)
    affected_sources = {row["artifact_id"] for row in data["events"] if row["id"] in excluded}
    result["sources"] = [row for row in result["sources"] if row["artifact_id"] not in removed_sources]
    for row in result["sources"]:
        if row["artifact_id"] in affected_sources:
            row["complete"] = False
            row["reasons"] = sorted(set(row["reasons"] + ["scenario_observations_excluded"]))
    result["events"] = [row for row in result["events"] if row["id"] not in removed_events]
    present = {row["id"] for row in result["events"]}
    result["duplicate_groups"] = [{"id": row["id"], "event_ids": [item for item in row["event_ids"] if item in present]} for row in result["duplicate_groups"]]
    result["duplicate_groups"] = [row for row in result["duplicate_groups"] if row["event_ids"]]
    for row in result["identity_assertions"]:
        if row["id"] in scenario["revoke_identities"] or set(row["source_family_ids"]) & removed_families or set(row["event_ids"]) & removed_events:
            row["status"] = "withdrawn"
        row["event_ids"] = [item for item in row["event_ids"] if item in present]
    widening = {row["clock_id"]: row["local_error"] for row in scenario["widen_clock_errors"]}
    known_clocks = {row["clock_model"]["id"] for row in data["events"] if row["clock_model"] is not None}
    _require_refs(widening, known_clocks)
    for row in result["events"]:
        model = row["clock_model"]
        if model is None:
            continue
        if set(model.get("source_family_ids", [])) & removed_families or set(model["basis_refs"]) & (removed_events | removed_sources):
            row["clock_model"] = None
            continue
        if model["id"] in widening:
            for segment in model["segments"]:
                if segment["local_error"] is None or not tm.contains(widening[model["id"]], segment["local_error"]):
                    tm.error("scenario_clock_must_widen")
                segment["local_error"] = deepcopy(widening[model["id"]])
    result["limitations"] = sorted(set(result["limitations"] + ["scenario_overlay_not_original_evidence"]))
    claims.validate_data(result)
    return result


def _bounded_report(value, configured):
    if len(canonical_bytes(value)) > (configured["max_report_bytes"] if configured else MAX_ANALYSIS_BYTES):
        tm.error("analysis_report_limit", 6)


def run_scenario(case, claim_ids, scenario, *, expected_revision=None, persist=True, analysis_limits=None):
    revision = _expect(case, expected_revision)
    configured = normalize_analysis_limits(analysis_limits) if analysis_limits is not None else None
    tm.refs(claim_ids, configured["max_claims"] if configured else claims.MAX_CLAIMS)
    if type(persist) is not bool:
        tm.error("invalid_persist_flag")
    records = [_object(case, item, "claim") for item in claim_ids]
    data = load_data(case, analysis_limits=analysis_limits)
    values = [row["data"]["claim"] for row in records]
    baseline = claims.analyze(values, data, analysis_limits=analysis_limits)
    altered_data = apply_scenario(data, scenario)
    altered = claims.analyze(values, altered_data, analysis_limits=analysis_limits)
    remaining = {row["id"] for row in altered_data["events"]}
    lost = sorted(row["id"] for row in data["events"] if row["id"] not in remaining)
    old_clocks = {row["id"] for row in data["events"] if row["clock_model"] is not None}
    lost_clock = sorted(row["id"] for row in altered_data["events"] if row["id"] in old_clocks and row["clock_model"] is None)
    def summarized(identities):
        return {"count": len(identities), "digest": object_digest(identities), "references": identities[:256], "complete": len(identities) <= 256}
    result = {"schema": "testifex.scenario-result.v1", "scenario": validate_scenario(scenario), "claim_object_ids": claim_ids,
              "data_fingerprint": data_fingerprint(data), "baseline": baseline, "scenario_result": altered,
              "comparison": claims.compare_results(baseline, altered), "execution_state": "complete" if baseline["execution_state"] == altered["execution_state"] == "complete" else "aborted_limit",
              "lost_support": {"observations": summarized(lost), "clock_alignment": summarized(lost_clock)},
              "skipped_evaluations": [{"claim_id": row["claim_id"], "reasons": row["reasons"]} for row in altered["evaluations"] if row["verdict"] == "not_evaluated"],
              "limitations": ["scenario_is_not_new_evidence", "no_probability_or_global_robustness_claim"]}
    _bounded_report(result, configured)
    return case.put_object("analysis_scenario", result, expected_revision=revision) if persist else result


def sensitivity(case, claim_ids, *, family_ids=None, limit=64, analysis_limits=None):
    tm.integer(limit, 1, MAX_SCENARIOS)
    configured = normalize_analysis_limits(analysis_limits) if analysis_limits is not None else None
    tm.refs(claim_ids, configured["max_claims"] if configured else claims.MAX_CLAIMS)
    data = load_data(case, analysis_limits=analysis_limits)
    values = [_object(case, item, "claim")["data"]["claim"] for item in claim_ids]
    if configured is not None:
        limit = min(limit, configured["max_scenarios"])
    all_families = sorted({row["family_id"] for row in data["sources"] if row["family_id"] is not None})
    if family_ids is None:
        if len(all_families) > limit:
            tm.error("explicit_sensitivity_plan_required", 6)
        selected = all_families
    else:
        selected = claims._names(family_ids, limit)
        _require_refs(selected, set(all_families))
    if max(1, len(values)) * max(1, len(data["events"])) * max(1, len(selected)) > (configured["max_memberships"] if configured else 1000000):
        tm.error("sensitivity_membership_limit", 6)
    baseline = claims.analyze(values, data, analysis_limits=analysis_limits)
    results = []
    report_bytes = len(canonical_bytes(baseline))
    for family in selected:
        scenario = {"schema": "testifex.scenario.v1", "id": "without-" + family[:100], "remove_families": [family],
                    "exclude_duplicate_groups": [], "revoke_identities": [], "widen_clock_errors": []}
        altered = claims.analyze(values, apply_scenario(data, scenario), analysis_limits=analysis_limits)
        item = {"family_id": family, "result": altered, "comparison": claims.compare_results(baseline, altered)}
        report_bytes += len(canonical_bytes(item))
        if report_bytes > (configured["max_report_bytes"] if configured else MAX_ANALYSIS_BYTES):
            tm.error("analysis_report_limit", 6)
        results.append(item)
    unknown = sum(row["family_id"] is None for row in data["sources"])
    complete = set(selected) == set(all_families) and not unknown
    result = {"schema": "testifex.sensitivity.v1", "execution_state": "complete" if baseline["execution_state"] == "complete" and all(row["result"]["execution_state"] == "complete" for row in results) else "aborted_limit", "plan_complete": complete, "plan_status": "complete" if complete else "incomplete",
            "tested_families": selected, "untested_families": sorted(set(all_families) - set(selected)), "sources_without_family": unknown,
            "baseline": baseline, "results": results, "limitations": ["family_assignment_does_not_prove_independence", "limited_plan_not_global_robustness"]}
    _bounded_report(result, configured)
    return result


def correlate(case, template, *, window_us, threshold=5, analysis_limits=None):
    return correlate_data(load_data(case, analysis_limits=analysis_limits), template, window_us=window_us, threshold=threshold, analysis_limits=analysis_limits)


def _correlation_claims(data, template, *, window_us, threshold=5, analysis_limits=None):
    configured = normalize_analysis_limits(analysis_limits) if analysis_limits is not None else None
    max_claims = configured["max_claims"] if configured else claims.MAX_CLAIMS
    if template not in ("auth_after_failures", "post_auth_process"):
        tm.error("correlation_template_unsupported", 7)
    tm.integer(threshold, 1, 100000)
    if tm.microseconds(window_us, tm.MAX_WINDOW_US) < 0:
        tm.error("negative_order_window")
    scope = claims.resolve_scope({"all_at_revision": data["revision"]}, data)
    successes = [row for row in data["events"] if row["fields"]["kind"] == "auth.success"]
    if template == "post_auth_process" and len(successes) * len(data["events"]) > (configured["max_memberships"] if configured else 1000000):
        tm.error("correlation_scan_limit", 6)
    skipped = 0
    values = []
    for success in successes:
        host, actor = success["fields"].get("host"), success["fields"].get("actor")
        if host is None or actor is None:
            skipped += 1
            continue
        if template == "auth_after_failures":
            value = {"schema": "testifex.claim.v1", "id": "failures-before-" + success["id"], "predicate": "count_at_least", "scope": scope,
                           "selector": [{"field": "kind", "op": "eq", "value": "auth.failure"}, {"field": "host", "op": "eq", "value": host}, {"field": "actor", "op": "eq", "value": actor}],
                           "operands": {"threshold": threshold, "unit": "normalized_observation", "anchor_event": success["id"], "window_us": window_us}, "assumptions": []}
            grouped = deepcopy(value)
            grouped["id"] = "grouped-before-" + success["id"]
            grouped["operands"]["unit"] = "explicit_duplicate_group"
            values.extend([value, grouped])
            if len(values) > max_claims:
                tm.error("correlation_candidate_limit", 6)
        else:
            for event in data["events"]:
                if event["fields"]["kind"] not in ("process.exec", "process.start", "process.command") or event["fields"].get("host") != host or event["fields"].get("actor") != actor:
                    continue
                if len(values) >= max_claims:
                    tm.error("correlation_candidate_limit", 6)
                values.append({"schema": "testifex.claim.v1", "id": "order-" + object_digest([success["id"], event["id"]]), "predicate": "ordered_within", "scope": scope, "selector": [],
                               "operands": {"before": success["id"], "after": event["id"], "window_us": window_us}, "assumptions": []})
    return values, skipped


def _correlation_findings(template, evaluations):
    findings = []
    for evaluation in evaluations:
        findings.append({"id": evaluation["id"], "template": template, "verdict": evaluation["verdict"], "witness_set": evaluation["witness_set"],
                         "witness_count": evaluation["witness_count"], "witness_set_complete": evaluation["witness_set_complete"], "witness_set_digest": evaluation["witness_set_digest"],
                         "reason_codes": evaluation["reasons"], "count": evaluation["count"],
                         "limitation": "Matching host and account plus temporal order do not establish a shared session or causality."})
    return findings


def correlate_data(data, template, *, window_us, threshold=5, analysis_limits=None):
    configured = normalize_analysis_limits(analysis_limits) if analysis_limits is not None else None
    claims.validate_data(data)
    values, skipped = _correlation_claims(data, template, window_us=window_us, threshold=threshold, analysis_limits=analysis_limits)
    result = claims.analyze(values, data, analysis_limits=analysis_limits)
    findings = _correlation_findings(template, result["evaluations"])
    output = {"schema": "testifex.correlation.v1", "template": template, "analysis": result, "findings": findings,
              "skipped_missing_identity": skipped, "execution_state": result["execution_state"], "classification": "conditional_leads_not_incident_determinations"}
    _bounded_report(output, configured)
    return output


def correlate_many_data(data, requests, *, analysis_limits=None):
    """Una imago probata pluribus regulis simul servit."""
    configured = normalize_analysis_limits(analysis_limits) if analysis_limits is not None else None
    max_claims = configured["max_claims"] if configured else claims.MAX_CLAIMS
    claims.validate_data(data)
    claims._list(requests, 2, "correlation_template_limit")
    if not requests:
        tm.error("correlation_templates_required")
    values, groups, used = [], [], set()
    for request in requests:
        tm.exact_dict(request, {"template", "window_us", "threshold"}, {"template", "window_us"})
        if type(request["template"]) is not str or request["template"] in used:
            tm.error("duplicate_correlation_template")
        used.add(request["template"])
        candidates, skipped = _correlation_claims(data, request["template"], window_us=request["window_us"], threshold=request.get("threshold", 5), analysis_limits=analysis_limits)
        groups.append({"template": request["template"], "claim_ids": {item["id"] for item in candidates}, "skipped": skipped})
        values.extend(candidates)
        if len(values) > max_claims:
            tm.error("correlation_candidate_limit", 6)
    result = claims.analyze(values, data, analysis_limits=analysis_limits)
    templates = []
    for group in groups:
        evaluations = [item for item in result["evaluations"] if item["claim_id"] in group["claim_ids"]]
        templates.append({"template": group["template"], "findings": _correlation_findings(group["template"], evaluations), "skipped_missing_identity": group["skipped"]})
    output = {"schema": "testifex.correlation-batch.v1", "analysis": result, "templates": templates, "execution_state": result["execution_state"],
            "classification": "conditional_leads_not_incident_determinations"}
    _bounded_report(output, configured)
    return output


def correlate_many(case, requests, *, analysis_limits=None):
    return correlate_many_data(load_data(case, analysis_limits=analysis_limits), requests, analysis_limits=analysis_limits)


def build_demonstration(case, *, expected_revision=None):
    """Exercitatio declarata sola exempla automatica accipit."""
    _expect(case, expected_revision)
    sources = {row["id"] for row in case.sources()}
    declarations = case.objects("scenario")
    if not declarations or declarations[-1]["data"].get("synthetic") is not True or set(declarations[-1]["data"].get("artifacts", [])) != sources:
        tm.error("synthetic_case_declaration_required")
    if case.objects("clock_model") or case.objects("claim"):
        tm.error("demonstration_already_initialized", 5)
    data = load_data(case)
    if len(data["events"]) > 10000:
        tm.error("demonstration_event_limit", 6)
    processes = {}
    for row in sorted(data["events"], key=lambda item: item["id"]):
        if row["fields"]["kind"] in ("process.exec", "process.start"):
            processes.setdefault((row["fields"].get("host"), row["fields"].get("actor")), row)
    pair = None
    for row in sorted(data["events"], key=lambda item: item["id"]):
        key = (row["fields"].get("host"), row["fields"].get("actor"))
        if row["fields"]["kind"] == "auth.success" and None not in key and key in processes:
            pair = (row, processes[key])
            break
    if pair is None:
        tm.error("synthetic_demo_pair_missing")
    first, second = pair
    scope = claims.resolve_scope({"all_at_revision": case.revision}, data)
    claim = {"schema": "testifex.claim.v1", "id": "synthetic-post-auth-order", "predicate": "ordered_within", "scope": scope,
             "selector": [], "operands": {"before": first["id"], "after": second["id"], "window_us": "10000000"}, "assumptions": [],
             "human_label": "Synthetic process record follows the authentication record within ten seconds under a declared clock model."}
    saved = save_claim(case, claim, expected_revision=case.revision, author="synthetic-exercise")
    baseline = evaluate(case, saved["id"], expected_revision=case.revision)
    artifacts = sorted({first["artifact_id"], second["artifact_id"]})
    save_family(case, "synthetic-exercise-family", artifacts, [], "The exercise explicitly declares this shared source family.", expected_revision=case.revision)
    model = {"schema": "testifex.clock-model.v1", "id": "synthetic-exercise-clock", "basis_refs": [],
             "rationale": "A zero-error assumption for a synthetic exercise only; this is not measured clock calibration.",
             "assumption_id": "synthetic-zero-error-assumption", "source_family_ids": ["synthetic-exercise-family"],
             "segments": [{"validity": tm.interval(tm.MIN_TIME_US, tm.MAX_TIME_US, True, False), "fixed_offset_us": "0", "local_error": tm.interval(0, 0), "shared_errors": []}]}
    save_clock(case, model, artifacts, expected_revision=case.revision)
    aligned = evaluate(case, saved["id"], expected_revision=case.revision)
    scenario = {"schema": "testifex.scenario.v1", "id": "synthetic-clock-widening", "remove_families": [], "exclude_duplicate_groups": [], "revoke_identities": [],
                "widen_clock_errors": [{"clock_id": model["id"], "local_error": tm.interval(-10000000, 10000000)}]}
    altered = run_scenario(case, [saved["id"]], scenario, expected_revision=case.revision)
    return {"claim_id": saved["id"], "unknown_evaluation_id": baseline["id"], "aligned_evaluation_id": aligned["id"], "scenario_id": altered["id"],
            "unknown_verdict": baseline["data"]["result"]["evaluations"][0]["verdict"], "aligned_verdict": aligned["data"]["result"]["evaluations"][0]["verdict"],
            "scenario_verdict": altered["data"]["scenario_result"]["evaluations"][0]["verdict"]}


def resolve_review_references(case, decision):
    missing = []
    try:
        claim = _object(case, decision["claim_id"], "claim")
        if claim["revision"] != decision["claim_revision"]:
            missing.append("claim_revision")
    except (ProbentiumError, KeyError, TypeError):
        claim = None
        missing.append("claim_id")
    candidates = [row for row in case.objects("evaluation") if row["data"].get("result", {}).get("digest") == decision.get("evaluation_digest")
                  and row["data"].get("claim_object_id") == decision.get("claim_id")]
    matching = [row for row in candidates if row["data"].get("data_fingerprint") == decision.get("snapshot_digest")]
    if not candidates:
        missing.append("evaluation_digest")
    elif not matching:
        missing.append("snapshot_digest")
    rationale = [row for row in case.objects("review_rationale") if isinstance(row["data"].get("text"), str)
                 and hashlib.sha256(row["data"]["text"].encode("utf-8")).hexdigest() == decision.get("rationale_digest")]
    if not rationale:
        missing.append("rationale_digest")
    previous = decision.get("previous_decision_id")
    if previous is not None:
        prior = [row for row in case.objects("review_decision") if object_digest(row["data"].get("decision"), "TESTIFEX-REVIEW-V1") == previous]
        if not prior or prior[-1]["data"]["decision"].get("claim_id") != decision.get("claim_id"):
            missing.append("previous_decision_id")
    if missing:
        return {"status": "pending_references", "missing": sorted(set(missing))}
    stale = stale_status(case, matching[-1]["id"])
    return {"status": "historical" if stale["status"] == "stale" else "current", "missing": []}


class _PrefixRecords(Mapping):
    """Tabula locorum in disco manet; solae petitiones explicitae leguntur."""
    def __init__(self, snapshot, source):
        self.snapshot, self.source = snapshot, source

    def __len__(self):
        return self.source["records_total"]

    def __iter__(self):
        for row in self.snapshot.iter_run_records(self.source["parse_run_id"]):
            if row["offset"] >= self.source["cursor"]:
                break
            yield row["id"]

    def __getitem__(self, identity):
        row = self.snapshot.lookup("records", identity)
        if row is None or row["artifact_id"] != self.source["id"] or row["offset"] + row["length"] > self.source["cursor"]:
            raise KeyError(identity)
        return row["offset"], row["length"]


def _stream_historical_prefixes(snapshot, sources, by_run, prefixes, dispositions):
    """Continuatio, dispositiones et numeri in uno cursu probantur."""
    for source in sources:
        cursor, ordinal, counts = 0, 0, dict.fromkeys(dispositions, 0)
        for record in snapshot.iter_run_records(source["parse_run_id"]):
            if record["offset"] >= source["cursor"]:
                break
            ordinal += 1
            if (record["artifact_id"] != source["id"] or record["ordinal"] != ordinal or record["offset"] != cursor
                    or record["length"] <= 0 or cursor + record["length"] > source["cursor"]):
                tm.error("analysis_coverage_prefix_invalid", 4)
            cursor += record["length"]
            link = snapshot.lookup("parse_records", source["parse_run_id"] + ":" + record["id"])
            if (link is None or link["record_id"] != record["id"] or link["parse_run_id"] != source["parse_run_id"]
                    or link["disposition"] not in counts):
                tm.error("analysis_coverage_disposition_invalid", 4)
            counts[link["disposition"]] += 1
        if cursor != source["cursor"] or ordinal != source["records_total"] or counts != source["counters"]:
            tm.error("analysis_coverage_accounting_mismatch", 4)
        prefixes[source["id"]]["records"] = _PrefixRecords(snapshot, source)
    return sources, by_run, prefixes


def _historical_sources(snapshot, catalog, artifacts, runs):
    sources, by_run, prefixes = [], {}, {}
    dispositions = ("parsed", "blank", "known_out_of_scope", "unsupported", "malformed", "oversize")
    for entry in catalog:
        artifact, run = artifacts[entry["artifact_id"]], runs[entry["parse_run_id"]]
        if run["artifact_id"] != artifact["id"]:
            tm.error("analysis_source_binding_mismatch", 4)
        source = {**artifact, **run, "id": artifact["id"], "parse_run_id": run["id"]}
        saved = entry.get("coverage_snapshot", _coverage(source))
        tm.exact_dict(saved, set(_coverage(source)), set(_coverage(source)))
        if object_digest(saved) != entry["coverage_digest"] or saved["id"] != artifact["id"] or saved["parse_run_id"] != run["id"] or saved["parser_artifact_digest"] != run["parser_artifact_digest"]:
            tm.error("analysis_coverage_binding_mismatch", 4)
        tm.integer(saved["cursor"], 0, artifact["size"])
        if saved["cursor"] > run["cursor"] or saved["unprocessed_bytes"] != artifact["size"] - saved["cursor"]:
            tm.error("analysis_coverage_range_invalid", 4)
        complete = saved["cursor"] == artifact["size"]
        if saved["state"] != ("complete" if complete else "incomplete") or saved["unprocessed_records"] != (0 if complete else None):
            tm.error("analysis_coverage_state_invalid", 4)
        tm.exact_dict(saved["counters"], set(dispositions), set(dispositions))
        for count in saved["counters"].values():
            tm.integer(count, 0, 10000000)
        if type(saved["interpretation_complete"]) is not bool or saved["interpretation_complete"] and (not complete or any(saved["counters"][key] for key in dispositions[2:])):
            tm.error("analysis_coverage_complete_invalid", 4)
        source.update(saved)
        sources.append(source)
        by_run[run["id"]] = source
        prefixes[artifact["id"]] = {"cursor": saved["cursor"], "records": {}}
    if callable(getattr(snapshot, "iter_run_records", None)) and callable(getattr(snapshot, "lookup", None)):
        return _stream_historical_prefixes(snapshot, sources, by_run, prefixes, dispositions)
    if len(snapshot["records"]) > 250000:
        tm.error("analysis_replay_record_limit", 6)
    for record in snapshot["records"]:
        prefix = prefixes.get(record["artifact_id"])
        if prefix is not None and record["offset"] + record["length"] <= prefix["cursor"]:
            prefix["records"][record["id"]] = (record["offset"], record["length"])
    for prefix in prefixes.values():
        cursor = 0
        for offset, length in sorted(prefix["records"].values()):
            if offset != cursor or length <= 0:
                tm.error("analysis_coverage_prefix_invalid", 4)
            cursor += length
        if cursor != prefix["cursor"]:
            tm.error("analysis_coverage_prefix_invalid", 4)
    counts = {identity: dict.fromkeys(dispositions, 0) for identity in by_run}
    accounted = set()
    for row in snapshot["parse_records"]:
        source = by_run.get(row["parse_run_id"])
        if source is None or row["record_id"] not in prefixes[source["id"]]["records"]:
            continue
        pair = (row["parse_run_id"], row["record_id"])
        if pair in accounted or row["disposition"] not in counts[row["parse_run_id"]]:
            tm.error("analysis_coverage_disposition_invalid", 4)
        accounted.add(pair)
        counts[row["parse_run_id"]][row["disposition"]] += 1
    for identity, source in by_run.items():
        if counts[identity] != source["counters"] or sum(counts[identity].values()) != source["records_total"] or source["records_total"] != len(prefixes[source["id"]]["records"]):
            tm.error("analysis_coverage_accounting_mismatch", 4)
    return sources, by_run, prefixes


def replay_snapshot(snapshot):
    """Repetitio semantica a probatione octetorum manifeste separatur."""
    try:
        if not isinstance(snapshot, Mapping) or snapshot.get("schema") != "probentium.case-snapshot.v1":
            return {"analysis_replay": "unsupported", "issues": ["snapshot_schema_unsupported"]}
        objects = snapshot["objects"]
        if not isinstance(objects, Sequence) or len(objects) > 100000:
            tm.error("snapshot_object_limit", 6)
        evaluations = [row for row in objects if row["kind"] == "evaluation"]
        if not evaluations:
            return {"analysis_replay": "unavailable", "issues": ["no_stored_evaluations"]}
        artifacts = {row["id"]: row for row in snapshot["artifacts"]}
        runs = {row["id"]: row for row in snapshot["parse_runs"]}
        stored = {row["id"]: row for row in objects}
        events = snapshot["events"]
        if not isinstance(events, Sequence) or len(events) > 10000000:
            tm.error("analysis_event_limit", 6)
        if len(evaluations) * max(1, len(events), len(snapshot["records"])) > 10000000:
            return {"analysis_replay": "unavailable", "issues": ["analysis_replay_work_limit"]}
        for record in evaluations:
            value = record["data"]
            revision = value["input_revision"]
            tm.integer(revision, 0, 9007199254740991)
            claim_record = stored[value["claim_object_id"]]
            if claim_record["kind"] != "claim" or claim_record["revision"] != value["claim_revision"]:
                tm.error("analysis_claim_binding_mismatch", 4)
            sources, selected_runs, prefixes = _historical_sources(snapshot, value["source_catalog"], artifacts, runs)
            selected_events = _collect_events(row for row in events if row["parse_run_id"] in selected_runs
                                             and set(row["record_refs"]) <= prefixes[row["artifact_id"]]["records"].keys())
            observed_counts = dict.fromkeys(selected_runs, 0)
            for event in selected_events:
                observed_counts[event["parse_run_id"]] += 1
            if any(observed_counts[run] != source["events_total"] for run, source in selected_runs.items()):
                tm.error("analysis_coverage_event_count_mismatch", 4)
            data = _assemble(sources, selected_events,
                             [row for row in objects if row["revision"] <= revision], revision, "verified", consume_events=True)
            if data_fingerprint(data) != value["data_fingerprint"]:
                tm.error("analysis_input_replay_mismatch", 4)
            dependency = value.get("evaluation_dependencies")
            if dependency is not None:
                selected = _dependency_snapshot(claim_record["data"]["claim"], data, [row for row in objects if row["revision"] <= revision],
                                                analysis_limits=dependency.get("analysis_limits"))
                if selected["binding"] != dependency:
                    tm.error("analysis_dependency_replay_mismatch", 4)
                actual = _analyze_dependency_snapshot(selected)
            else:
                actual = claims.analyze([claim_record["data"]["claim"]], data)
            if actual != value["result"]:
                tm.error("analysis_result_replay_mismatch", 4)
        return {"analysis_replay": "passed", "issues": [], "basis": "canonical_snapshot_semantics_only_raw_byte_verification_separate"}
    except ProbentiumError as exc:
        if exc.exit_code == 6:
            return {"analysis_replay": "unavailable", "issues": ["analysis_replay_resource_limit"]}
        return {"analysis_replay": "failed", "issues": ["analysis_snapshot_replay_failed"]}
    except (KeyError, TypeError, ValueError, UnicodeError):
        return {"analysis_replay": "failed", "issues": ["analysis_snapshot_replay_failed"]}
