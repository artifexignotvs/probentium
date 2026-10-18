"""Praedicata finita conclusionem sub condicionibus tantum reddunt."""
from copy import deepcopy
from collections import deque, OrderedDict
import hashlib

from .contracts import ProbentiumError, canonical_bytes, object_digest, text_field
from . import time_model as tm
from .budgets import AnalysisBudget, normalize_analysis_limits

ENGINE_VERSION = "1"
PREDICATES = frozenset(("record_observed", "ordered_within", "count_at_least", "field_equal", "absent_in_stream"))
KINDS = frozenset(("auth.failure", "auth.success", "process.exec", "process.start", "process.command", "file.observed", "file.changed", "file.create", "file.modify", "file.delete", "network.connect", "network.connection", "account.change", "generic"))
STRING_FIELDS = frozenset(("kind", "host", "actor", "source_ip", "destination_ip", "payload.path", "payload.action", "payload.protocol", "payload.service", "payload.executable", "payload.result", "payload.unit", "payload.boot_id", "payload.target_account", "payload.method", "payload.reason", "payload.command", "payload.digest_algorithm", "payload.digest", "payload.local_ip", "payload.remote_ip", "payload.direction"))
INT_FIELDS = frozenset(("payload.pid", "payload.parent_pid", "payload.port", "payload.dst_port", "payload.uid", "payload.gid", "payload.local_port", "payload.remote_port"))
FIELDS = STRING_FIELDS | INT_FIELDS
MAX_EVENTS = 100000
MAX_CLAIMS = 1000
_EMPTY_CONTEXT_DIGEST = object_digest({})


def _list(value, maximum, code):
    if not isinstance(value, list) or len(value) > maximum:
        tm.error(code, 6)
    return value


def _names(value, maximum=64):
    _list(value, maximum, "analysis_name_limit")
    for item in value:
        text_field(item, 128)
    if len(set(value)) != len(value):
        tm.error("duplicate_analysis_name")
    return value


def _scalar(field, value, nullable=True):
    if value is None and nullable:
        return
    if field in INT_FIELDS:
        upper = 65535 if "port" in field else 2147483647 if field in ("payload.pid", "payload.parent_pid") else 4294967295
        tm.integer(value, 0, upper)
    elif field in STRING_FIELDS:
        if type(value) is not str or len(value) > 4096:
            tm.error("invalid_selector_value")
        canonical_bytes(value)
    else:
        tm.error("unsupported_analysis_field")


def validate_selector(selector):
    _list(selector, 32, "selector_condition_limit")
    for item in selector:
        tm.exact_dict(item, {"field", "op", "value"}, {"field", "op"})
        if type(item["field"]) is not str or item["field"] not in FIELDS:
            tm.error("unsupported_analysis_field")
        operation = item["op"]
        if operation == "is_null":
            if "value" in item:
                tm.error("unexpected_selector_value")
        elif operation == "eq":
            if "value" not in item:
                tm.error("selector_value_required")
            _scalar(item["field"], item["value"])
        elif operation == "in":
            values = item.get("value")
            _list(values, 64, "selector_value_limit")
            if not values:
                tm.error("empty_selector_values")
            for value in values:
                _scalar(item["field"], value)
        else:
            tm.error("unsupported_selector_operator")
    return deepcopy(selector)


def validate_scope(scope):
    if isinstance(scope, dict) and set(scope) == {"all_at_revision"}:
        tm.integer(scope["all_at_revision"], 0, 9007199254740991)
        return deepcopy(scope)
    tm.exact_dict(scope, {"artifact_ids", "active_parse_runs", "event_kinds", "time_filter"},
                  {"artifact_ids", "active_parse_runs", "event_kinds", "time_filter"})
    artifacts = tm.refs(scope["artifact_ids"], 20000)
    runs = _list(scope["active_parse_runs"], 20000, "scope_run_limit")
    used = set()
    for run in runs:
        tm.exact_dict(run, {"artifact_id", "parse_run_id"}, {"artifact_id", "parse_run_id"})
        tm.identifier(run["artifact_id"])
        tm.identifier(run["parse_run_id"])
        if run["artifact_id"] in used or run["artifact_id"] not in artifacts:
            tm.error("invalid_scope_parse_selection")
        used.add(run["artifact_id"])
    if used != set(artifacts):
        tm.error("scope_parse_selection_required")
    kinds = _names(scope["event_kinds"], len(KINDS))
    if any(kind not in KINDS for kind in kinds):
        tm.error("unsupported_event_kind")
    time_filter = scope["time_filter"]
    if time_filter is not None:
        tm.exact_dict(time_filter, {"after_us", "before_us", "basis", "mode"}, {"after_us", "before_us", "basis", "mode"})
        lo, hi = tm.microseconds(time_filter["after_us"]), tm.microseconds(time_filter["before_us"])
        if lo >= hi or time_filter["basis"] not in ("recorded", "reference") or time_filter["mode"] not in ("overlap", "contained"):
            tm.error("invalid_time_filter")
        tm.validate_interval(tm.interval(lo, hi, True, False), calendar=True)
    return deepcopy(scope)


def _field_ref(value):
    tm.exact_dict(value, {"event_id", "field"}, {"event_id", "field"})
    tm.identifier(value["event_id"])
    if type(value["field"]) is not str or value["field"] not in FIELDS:
        tm.error("unsupported_analysis_field")


def validate_claim(claim):
    tm.exact_dict(claim, {"schema", "id", "predicate", "scope", "selector", "operands", "assumptions", "human_label"},
                  {"schema", "id", "predicate", "scope", "selector", "operands", "assumptions"})
    if claim["schema"] != "testifex.claim.v1":
        tm.error("unsupported_claim_schema", 7)
    text_field(claim["id"], 128)
    if type(claim["predicate"]) is not str or claim["predicate"] not in PREDICATES:
        tm.error("unsupported_predicate", 7)
    validate_scope(claim["scope"])
    validate_selector(claim["selector"])
    _names(claim["assumptions"], 32)
    if "human_label" in claim:
        text_field(claim["human_label"], 4096)
    operands = claim["operands"]
    predicate = claim["predicate"]
    if predicate in ("ordered_within", "field_equal") and claim["selector"]:
        tm.error("pair_predicate_selector_must_be_empty")
    if predicate in ("record_observed", "absent_in_stream"):
        tm.exact_dict(operands, set())
    elif predicate == "ordered_within":
        tm.exact_dict(operands, {"before", "after", "window_us"}, {"before", "after", "window_us"})
        tm.identifier(operands["before"])
        tm.identifier(operands["after"])
        if tm.microseconds(operands["window_us"], tm.MAX_WINDOW_US) < 0:
            tm.error("negative_order_window")
    elif predicate == "count_at_least":
        tm.exact_dict(operands, {"threshold", "unit", "anchor_event", "window_us"}, {"threshold", "unit"})
        tm.integer(operands["threshold"], 1, 100000)
        if operands["unit"] not in ("normalized_observation", "explicit_duplicate_group"):
            tm.error("unsupported_count_unit")
        if ("anchor_event" in operands) != ("window_us" in operands):
            tm.error("count_anchor_window_required")
        if "anchor_event" in operands:
            tm.identifier(operands["anchor_event"])
            if tm.microseconds(operands["window_us"], tm.MAX_WINDOW_US) < 0:
                tm.error("negative_order_window")
    else:
        tm.exact_dict(operands, {"left", "right"}, {"left", "right"})
        _field_ref(operands["left"])
        _field_ref(operands["right"])
        if operands["left"]["field"] != operands["right"]["field"]:
            tm.error("field_namespace_mismatch")
    return deepcopy(claim)


def validate_data(data):
    tm.exact_dict(data, {"schema", "revision", "integrity", "events", "sources", "duplicate_groups", "identity_assertions", "limitations"},
                  {"schema", "revision", "integrity", "events", "sources", "duplicate_groups", "identity_assertions"})
    if data["schema"] != "testifex.analysis-data.v1":
        tm.error("unsupported_analysis_data", 7)
    tm.integer(data["revision"], 0, 9007199254740991)
    if data["integrity"] not in ("verified", "failed", "unavailable"):
        tm.error("invalid_integrity_status")
    sources, source_ids = {}, set()
    for source in _list(data["sources"], 20000, "source_limit"):
        tm.exact_dict(source, {"artifact_id", "parse_run_id", "complete", "family_id", "coverage_digest", "reasons"},
                      {"artifact_id", "parse_run_id", "complete", "family_id", "coverage_digest", "reasons"})
        for key in ("artifact_id", "parse_run_id", "coverage_digest"):
            tm.identifier(source[key])
        if type(source["complete"]) is not bool or source["artifact_id"] in source_ids:
            tm.error("invalid_source_coverage")
        if source["family_id"] is not None:
            text_field(source["family_id"], 128)
        _names(source["reasons"])
        sources[source["artifact_id"]] = source
        source_ids.add(source["artifact_id"])
    events = {}
    shared, checked_models = {}, set()
    for event in _list(data["events"], MAX_EVENTS, "analysis_event_limit"):
        tm.exact_dict(event, {"id", "artifact_id", "parse_run_id", "fields", "recorded_time", "clock_model", "entity_assertion_ids"},
                      {"id", "artifact_id", "parse_run_id", "fields", "recorded_time", "clock_model", "entity_assertion_ids"})
        for key in ("id", "artifact_id", "parse_run_id"):
            tm.identifier(event[key])
        if event["id"] in events or event["artifact_id"] not in sources or event["parse_run_id"] != sources[event["artifact_id"]]["parse_run_id"]:
            tm.error("invalid_event_source_selection")
        tm.exact_dict(event["fields"], FIELDS, {"kind"})
        for field, value in event["fields"].items():
            _scalar(field, value)
        if event["fields"]["kind"] not in KINDS:
            tm.error("unsupported_event_kind")
        tm.validate_interval(event["recorded_time"], calendar=True)
        tm.refs(event["entity_assertion_ids"], 32)
        if event["clock_model"] is not None and id(event["clock_model"]) not in checked_models:
            model = tm.validate_clock_model(event["clock_model"])
            checked_models.add(id(event["clock_model"]))
            for segment in model["segments"]:
                for term in segment["shared_errors"]:
                    if term["id"] in shared and shared[term["id"]] != term["interval"]:
                        tm.error("inconsistent_shared_error")
                    shared[term["id"]] = term["interval"]
        events[event["id"]] = event
    grouped, group_ids = set(), set()
    for group in _list(data["duplicate_groups"], MAX_EVENTS, "duplicate_group_limit"):
        tm.exact_dict(group, {"id", "event_ids"}, {"id", "event_ids"})
        text_field(group["id"], 128)
        members = tm.refs(group["event_ids"], 100000)
        if not members or group["id"] in group_ids or grouped.intersection(members) or not set(members) <= events.keys():
            tm.error("invalid_duplicate_partition")
        group_ids.add(group["id"])
        grouped.update(members)
    assertions = {}
    for assertion in _list(data["identity_assertions"], 10000, "identity_assertion_limit"):
        tm.exact_dict(assertion, {"id", "status", "event_ids", "source_family_ids", "namespace", "canonical_value", "rationale"}, {"id", "status", "event_ids", "source_family_ids"})
        tm.identifier(assertion["id"])
        if assertion["status"] not in ("active", "conflicting", "withdrawn") or assertion["id"] in assertions:
            tm.error("invalid_identity_assertion")
        if not set(tm.refs(assertion["event_ids"], 32)) <= events.keys():
            tm.error("identity_reference_missing")
        _names(assertion["source_family_ids"])
        binding = {"namespace", "canonical_value", "rationale"}
        if binding & assertion.keys():
            if not binding <= assertion.keys() or assertion["namespace"] not in ("host", "actor", "source_ip"):
                tm.error("invalid_identity_binding")
            _scalar(assertion["namespace"], assertion["canonical_value"], nullable=False)
            text_field(assertion["rationale"], 4096)
        assertions[assertion["id"]] = assertion
    for event in events.values():
        if not set(event["entity_assertion_ids"]) <= assertions.keys():
            tm.error("identity_reference_missing")
    _names(data.get("limitations", []))
    return data


def resolve_scope(scope, data):
    validate_scope(scope)
    if "all_at_revision" in scope:
        if scope["all_at_revision"] != data["revision"]:
            tm.error("scope_revision_conflict", 5)
        return {"artifact_ids": sorted(source["artifact_id"] for source in data["sources"]),
                "active_parse_runs": sorted(({"artifact_id": source["artifact_id"], "parse_run_id": source["parse_run_id"]} for source in data["sources"]), key=lambda run: run["artifact_id"]),
                "event_kinds": sorted(KINDS), "time_filter": None}
    return deepcopy(scope)


def selector_match(fields, selector):
    unknown = False
    for condition in selector:
        field, operation = condition["field"], condition["op"]
        if field not in fields:
            unknown = True
            continue
        value = fields[field]
        if operation == "is_null":
            matches = value is None
        elif value is None or (operation == "eq" and condition["value"] is None):
            unknown = True
            continue
        elif operation == "eq":
            matches = type(value) is type(condition["value"]) and value == condition["value"]
        else:
            matches = any(type(value) is type(other) and value == other for other in condition["value"] if other is not None)
            if not matches and None in condition["value"]:
                unknown = True
                continue
        if not matches:
            return "no"
    return "possible" if unknown else "yes"


def _time_membership(event, time_filter):
    if time_filter is None:
        return "yes", []
    if time_filter["basis"] == "recorded":
        value = event["recorded_time"]
        reasons = ["recorded_time_unknown"] if value is None else []
    else:
        expression = tm.reference_time(event["id"], event["recorded_time"], event["clock_model"])
        value, reasons = tm.bounds(expression), expression["reasons"]
    if value is None:
        return "possible", reasons
    wanted = tm.interval(int(time_filter["after_us"]), int(time_filter["before_us"]), True, False)
    matches = tm.intersects(value, wanted) if time_filter["mode"] == "overlap" else tm.contains(wanted, value)
    return ("yes" if matches else "no"), []


def _reference(event, cache):
    expressions = cache.setdefault("expressions", OrderedDict())
    if event["id"] not in expressions:
        digest = _clock_digest(event, cache.setdefault("clock_models", {}))
        if len(expressions) >= 1024:
            expressions.popitem(last=False)
        expressions[event["id"]] = tm._reference_time_validated(event["id"], event["recorded_time"], event["clock_model"], digest)
    else:
        expressions.move_to_end(event["id"])
    return expressions[event["id"]]


def _ordered(a, b, window_us, budget=None):
    if budget is not None:
        budget.relation(tm._pair_variable_count(a, b))
    difference = tm._difference_validated(a, b)
    return {"verdict": tm.interval_verdict(difference, window_us), "difference": difference,
            "reasons": sorted(set(a["reasons"] + b["reasons"])) if difference is None else [],
            "assumption_ids": sorted(set(a["assumption_ids"] + b["assumption_ids"]))}


def semantic_data(data):
    result = {key: data[key] for key in ("schema", "integrity", "sources", "duplicate_groups", "identity_assertions")}
    cache, models, events = {}, {}, []
    for event in data["events"]:
        digest = _clock_digest(event, cache)
        if digest is not None:
            models[digest] = event["clock_model"]
        events.append({**{key: value for key, value in event.items() if key != "clock_model"}, "clock_model_digest": digest})
    result["events"] = events
    result["clock_models"] = models
    return result


def semantic_digest(data, domain="PROBENTIUM-OBJECT-V1"):
    """Eadem octeta canonica per partes limitatas, sine duplicata tabula."""
    cache, models = {}, {}
    for event in data["events"]:
        digest = _clock_digest(event, cache)
        if digest is not None:
            models[digest] = event["clock_model"]
    values = {key: data[key] for key in ("schema", "integrity", "sources", "duplicate_groups", "identity_assertions")}
    values.update(events=None, clock_models=models)
    digest = hashlib.sha256(domain.encode("ascii") + b"\0")
    digest.update(b"{")
    for position, key in enumerate(sorted(values)):
        if position:
            digest.update(b",")
        digest.update(canonical_bytes(key) + b":")
        if key != "events":
            digest.update(canonical_bytes(values[key]))
            continue
        digest.update(b"[")
        for start in range(0, len(data["events"]), 1024):
            if start:
                digest.update(b",")
            rows = [{**{name: value for name, value in event.items() if name != "clock_model"},
                     "clock_model_digest": _clock_digest(event, cache)} for event in data["events"][start:start + 1024]]
            digest.update(canonical_bytes(rows)[1:-1])
        digest.update(b"]")
    digest.update(b"}")
    return digest.hexdigest()


def _clock_digest(event, cache):
    model = event["clock_model"]
    if model is None:
        return None
    key = id(model)
    if key not in cache:
        cache[key] = object_digest(model)
    return cache[key]


def interpretation_id(event, _cache=None):
    cache = {} if _cache is None else _cache
    return object_digest({"event_id": event["id"], "clock_model_digest": _clock_digest(event, cache),
                          "entity_assertion_ids": sorted(event["entity_assertion_ids"]), "context_digest": _EMPTY_CONTEXT_DIGEST}, "TESTIFEX-INTERPRETATION-V2")


def dependency_snapshot(claim, data, *, family_premises=None, analysis_limits=None):
    """Clausura praemissarum servatur; limites electi tacite non augentur."""
    value = validate_claim(claim)
    validate_data(data)
    configured = normalize_analysis_limits(analysis_limits) if analysis_limits is not None else None
    if configured is not None and len(data["events"]) > configured["max_events"]:
        tm.error("analysis_event_limit", 6)
    family_premises = {} if family_premises is None else family_premises
    if not isinstance(family_premises, dict) or len(family_premises) > 20000:
        tm.error("dependency_family_premise_limit", 6)
    for identity, premise in family_premises.items():
        tm.identifier(identity)
        tm.exact_dict(premise, {"binding_id", "basis_refs"}, {"binding_id", "basis_refs"})
        tm.identifier(premise["binding_id"])
        tm.refs(premise["basis_refs"], 32)
    scope = resolve_scope(value["scope"], data)
    value["scope"] = scope
    sources = {row["artifact_id"]: row for row in data["sources"]}
    events = {row["id"]: row for row in data["events"]}
    identities = {row["id"]: row for row in data["identity_assertions"]}
    groups = {row["id"]: row for row in data["duplicate_groups"]}
    member_groups = {identity: row["id"] for row in data["duplicate_groups"] for identity in row["event_ids"]}
    family_sources = {}
    for source in sources.values():
        if source["family_id"] is not None:
            family_sources.setdefault(source["family_id"], []).append(source["artifact_id"])
    runs = {row["artifact_id"]: row["parse_run_id"] for row in scope["active_parse_runs"]}
    queue, enqueued = deque(), set()
    registries = {"source": sources, "event": events, "identity": identities, "group": groups, "family": family_sources}
    edge_count = 0
    def enqueue(kind, values):
        nonlocal edge_count
        for identity in values:
            key = (kind, identity)
            if configured is not None and identity in registries[kind]:
                edge_count += 1
                if edge_count > configured["max_dependency_edges"]:
                    tm.error("dependency_edge_limit", 6)
            if identity not in registries[kind] or key in enqueued:
                continue
            if len(enqueued) >= 250000:
                tm.error("dependency_closure_limit", 6)
            enqueued.add(key)
            queue.append(key)
    enqueue("source", scope["artifact_ids"])
    enqueue("event", (row["id"] for row in data["events"] if row["artifact_id"] in runs
                      and row["parse_run_id"] == runs[row["artifact_id"]] and row["fields"]["kind"] in scope["event_kinds"]))
    enqueue("identity", value["assumptions"])
    selected = {kind: set() for kind in registries}
    while queue:
        kind, identity = queue.popleft()
        selected[kind].add(identity)
        if kind == "source":
            family = sources[identity]["family_id"]
            if family is not None:
                enqueue("family", [family])
            if identity in family_premises:
                enqueue("event", family_premises[identity]["basis_refs"])
                enqueue("source", family_premises[identity]["basis_refs"])
        elif kind == "event":
            event = events[identity]
            enqueue("source", [event["artifact_id"]])
            enqueue("identity", event["entity_assertion_ids"])
            if identity in member_groups:
                enqueue("group", [member_groups[identity]])
            if event["clock_model"] is not None:
                model = event["clock_model"]
                enqueue("event", model["basis_refs"])
                enqueue("source", model["basis_refs"])
                enqueue("family", model.get("source_family_ids", []))
        elif kind == "identity":
            enqueue("event", identities[identity]["event_ids"])
            enqueue("family", identities[identity]["source_family_ids"])
        elif kind == "group":
            enqueue("event", groups[identity]["event_ids"])
        elif kind == "family":
            enqueue("source", family_sources[identity])
    projected = {"schema": data["schema"], "revision": data["revision"], "integrity": data["integrity"],
                 "sources": [sources[key] for key in sorted(selected["source"]) if key in sources],
                 "events": [events[key] for key in sorted(selected["event"]) if key in events],
                 "identity_assertions": [identities[key] for key in sorted(selected["identity"]) if key in identities],
                 "duplicate_groups": [groups[key] for key in sorted(selected["group"])],
                 "limitations": data.get("limitations", [])}
    validate_data(projected)
    cache = {}
    binding = {"schema": "testifex.evaluation-dependencies.v1", "semantics_version": "1", "engine_version": ENGINE_VERSION,
               "rule_config": {"count_joint_feasibility": "not_evaluated"},
               "execution_limits": {"max_memberships": 1000000, "max_analysis_events": MAX_EVENTS, "max_dependency_nodes": 250000},
               "claim_digest": object_digest({key: item for key, item in value.items() if key != "human_label"}),
               "scope_digest": object_digest(scope), "query_digest": object_digest({"scope": scope, "selector": value["selector"]}),
               "coverage_digest": object_digest(projected["sources"]),
               "event_set_digest": object_digest(sorted(selected["event"])),
               "interpretation_set_digest": object_digest(sorted(interpretation_id(row, cache) for row in projected["events"])),
               "analysis_data_digest": semantic_digest(projected),
               "family_premise_digest": object_digest([{ "artifact_id": key, **family_premises[key]}
                                                        for key in sorted(selected["source"]) if key in family_premises]),
               "counts": {"sources": len(projected["sources"]), "events": len(projected["events"]),
                          "identities": len(projected["identity_assertions"]), "duplicate_groups": len(projected["duplicate_groups"])},
               "selection": "frozen_scope_with_transitive_identity_duplicate_clock_basis_and_source_family_closure",
               "conservatism": "all_scope_kinds_before_selector_or_time_filter; global_integrity_guard"}
    if configured is not None:
        binding["analysis_limits"] = configured
        binding["execution_limits"]["max_memberships"] = configured["max_memberships"]
    binding["fingerprint"] = object_digest(binding, "TESTIFEX-EVALUATION-DEPENDENCIES-V1")
    return {"claim": value, "data": projected, "binding": binding}


def _evaluate(claim, data, *, aborted=False, cache=None):
    cache = {} if cache is None else cache
    scope = resolve_scope(claim["scope"], data)
    sources = {source["artifact_id"]: source for source in data["sources"]}
    source_coverage = [sources[key] for key in scope["artifact_ids"] if key in sources]
    selected_runs = {run["artifact_id"]: run["parse_run_id"] for run in scope["active_parse_runs"]}
    missing = set(scope["artifact_ids"]) - sources.keys()
    changed_runs = any(sources[key]["parse_run_id"] != run for key, run in selected_runs.items() if key in sources)
    complete = not missing and not changed_runs and all(source["complete"] for source in source_coverage)
    selected = {event["id"]: event for event in data["events"] if event["artifact_id"] in selected_runs
                and event["parse_run_id"] == selected_runs[event["artifact_id"]] and event["fields"]["kind"] in scope["event_kinds"]}
    scope_digest = object_digest(scope)
    context = cache.get(scope_digest)
    if context is None:
        clock_cache = {}
        context = {"coverage_digest": object_digest(source_coverage), "event_set_digest": object_digest(sorted(selected)),
                   "interpretation_set_digest": object_digest(sorted(interpretation_id(selected[key], clock_cache) for key in selected)),
                   "interpretation_count": len(selected),
                   "clock_digest": object_digest([{ "id": key, "clock_model_digest": _clock_digest(selected[key], clock_cache)} for key in sorted(selected)]),
                   "entity_digest": object_digest(data["identity_assertions"]), "duplicate_digest": object_digest(data["duplicate_groups"])}
        cache[scope_digest] = context
    reasons = []
    if missing:
        reasons.append("scope_source_unavailable")
    if changed_runs:
        reasons.append("active_parser_changed")
    if not complete:
        reasons.append("source_coverage_incomplete")
    for source in source_coverage:
        reasons.extend(source["reasons"])
    predicate, operands = claim["predicate"], claim["operands"]
    result = {"schema": "testifex.evaluation.v1", "engine_version": ENGINE_VERSION, "claim_id": claim["id"],
              "claim_digest": object_digest({key: value for key, value in claim.items() if key != "human_label"}),
              "scope_digest": scope_digest, "query_digest": object_digest({"scope": scope, "selector": claim["selector"]}), **context,
              "verdict": "unknown", "completeness": "complete" if complete else "incomplete", "integrity": data["integrity"],
              "assumption_status": "declared" if claim["assumptions"] else "none_declared", "assumption_ids": list(claim["assumptions"]),
              "reasons": reasons, "witness_set": [], "count": None, "difference": None,
              "execution_state": "complete", "limitations": ["record_content_is_not_factual_truth", "no_physical_causality_claim"]}
    def finish(verdict):
        result["verdict"] = verdict
        result["reasons"] = sorted(set(result["reasons"]))
        result["assumption_ids"] = sorted(set(result["assumption_ids"]))
        result["assumption_status"] = "declared" if result["assumption_ids"] else "none_declared"
        witnesses = sorted(result["witness_set"])
        result["witness_count"] = len(witnesses)
        result["witness_set_digest"] = object_digest(witnesses)
        result["witness_set_complete"] = len(witnesses) <= 256
        result["witness_set"] = witnesses[:256]
        if not result["witness_set_complete"]:
            result["limitations"].append("witness_set_is_bounded_excerpt")
        result["id"] = object_digest(result, "TESTIFEX-EVALUATION-V1")
        return result
    if aborted:
        result["execution_state"] = "aborted_limit"
        result["reasons"].append("analysis_membership_limit")
        return finish("not_evaluated")
    if data["integrity"] != "verified":
        result["reasons"].append("input_integrity_not_verified")
        return finish("invalid")
    identities = {item["id"]: item for item in data["identity_assertions"]}
    required = set(claim["assumptions"])
    for event in selected.values():
        required.update(event["entity_assertion_ids"])
    if any(identities[key]["status"] != "active" for key in required if key in identities):
        result["reasons"].append("identity_assumption_unavailable_or_conflicting")
        return finish("unknown")
    bindings = {}
    for identity in identities.values():
        if identity["id"] not in required or "namespace" not in identity:
            continue
        for event in identity["event_ids"]:
            key = (event, identity["namespace"])
            if key in bindings and bindings[key] != identity["canonical_value"]:
                result["reasons"].append("identity_assumption_unavailable_or_conflicting")
                return finish("unknown")
            bindings[key] = identity["canonical_value"]
    declared_clocks = {event["clock_model"].get("assumption_id") for event in selected.values() if event["clock_model"] is not None}
    if any(key not in identities and key not in declared_clocks for key in claim["assumptions"]):
        result["reasons"].append("assumption_reference_missing")
        return finish("unknown")
    if predicate in ("ordered_within", "field_equal"):
        left = operands["before"] if predicate == "ordered_within" else operands["left"]["event_id"]
        right = operands["after"] if predicate == "ordered_within" else operands["right"]["event_id"]
        if left not in selected or right not in selected:
            result["reasons"].append("operand_unavailable_in_scope")
            return finish("unknown")
        for key in (left, right):
            matched, why = _time_membership(selected[key], scope["time_filter"])
            if matched != "yes":
                result["reasons"].extend(why + ["operand_unavailable_in_scope"])
                return finish("unknown")
        result["witness_set"] = sorted({left, right})
        if predicate == "field_equal":
            field = operands["left"]["field"]
            a, b = selected[left]["fields"].get(field), selected[right]["fields"].get(field)
            if a is None or b is None:
                result["reasons"].append("field_value_unknown")
                return finish("unknown")
            return finish("entailed" if type(a) is type(b) and a == b else "ruled_out")
        a, b = [_reference(selected[key], cache) for key in (left, right)]
        outcome = _ordered(a, b, operands["window_us"], cache.get("budget"))
        result["difference"] = outcome["difference"]
        result["reasons"].extend(outcome["reasons"])
        result["assumption_ids"].extend(outcome["assumption_ids"])
        return finish(outcome["verdict"])
    anchor = None
    if "anchor_event" in operands:
        if operands["anchor_event"] not in selected:
            result["reasons"].append("anchor_unavailable")
            return finish("unknown")
        event = selected[operands["anchor_event"]]
        anchor = _reference(event, cache)
        result["assumption_ids"].extend(anchor["assumption_ids"])
        if anchor["status"] == "unknown":
            result["reasons"].extend(anchor["reasons"] + ["anchor_time_unknown"])
            return finish("unknown")
    membership_key = object_digest([scope_digest, claim["selector"], operands.get("anchor_event"), operands.get("window_us")])
    prior = cache.get("membership")
    if prior is not None and prior[0] == membership_key:
        memberships, membership_reasons, membership_assumptions = prior[1:]
    else:
        memberships, membership_reasons, membership_assumptions = {}, set(), set()
        for identity, event in selected.items():
            matched = selector_match(event["fields"], claim["selector"])
            if matched == "no":
                continue
            timed, why = _time_membership(event, scope["time_filter"])
            if timed == "no":
                continue
            membership_reasons.update(why)
            matched = "possible" if "possible" in (matched, timed) else "yes"
            if anchor is not None:
                expression = _reference(event, cache)
                ordered = _ordered(expression, anchor, operands["window_us"], cache.get("budget"))
                membership_assumptions.update(ordered["assumption_ids"])
                if ordered["verdict"] == "ruled_out":
                    continue
                if ordered["verdict"] != "entailed":
                    matched = "possible"
                membership_reasons.update(ordered["reasons"])
            memberships[identity] = matched
        # Unus selector tantum retinetur; ordines eventuum non mutantur.
        cache["membership"] = (membership_key, memberships, membership_reasons, membership_assumptions)
    result["reasons"].extend(membership_reasons)
    result["assumption_ids"].extend(membership_assumptions)
    certain = sorted(key for key, value in memberships.items() if value == "yes")
    possible = sorted(key for key, value in memberships.items() if value == "possible")
    if possible:
        result["reasons"].append("matching_or_time_unknown")
    if predicate in ("record_observed", "absent_in_stream"):
        if certain:
            result["witness_set"] = certain[:1]
            return finish("entailed" if predicate == "record_observed" else "ruled_out")
        if not complete or possible:
            return finish("unknown")
        if predicate == "absent_in_stream":
            result["limitations"].append("not_observed_in_the_supplied_stream")
        return finish("ruled_out" if predicate == "record_observed" else "entailed")
    groups = {key: "event:" + key for key in memberships}
    if operands["unit"] == "explicit_duplicate_group":
        for group in data["duplicate_groups"]:
            for member in group["event_ids"]:
                if member in groups:
                    groups[member] = "group:" + group["id"]
    lower = len({groups[key] for key in certain})
    upper = len(set(groups.values())) if complete else None
    result["count"] = {"unit": operands["unit"], "lower": lower, "upper": upper, "threshold": operands["threshold"],
                       "joint_feasibility": "not_evaluated", "source_families": sorted({sources[selected[key]["artifact_id"]]["family_id"] for key in memberships if sources[selected[key]["artifact_id"]]["family_id"] is not None})}
    family_members = {}
    for key in memberships:
        family = sources[selected[key]["artifact_id"]]["family_id"]
        family_members.setdefault(family, []).append(key)
    result["count"]["family_breakdown"] = [{"family_id": family,
        "lower": len({groups[key] for key in members if memberships[key] == "yes"}),
        "upper": len({groups[key] for key in members}) if complete else None}
        for family, members in sorted(family_members.items(), key=lambda item: (item[0] is not None, item[0] or ""))]
    result["count"]["family_breakdown_limit"] = "Groups spanning families may appear in more than one row; rows are not additive or independent."
    witnesses = {}
    for key in certain:
        witnesses.setdefault(groups[key], key)
    result["witness_set"] = list(witnesses.values())[:operands["threshold"]]
    if lower >= operands["threshold"]:
        return finish("entailed")
    if upper is None:
        return finish("unknown")
    if upper < operands["threshold"]:
        return finish("ruled_out")
    result["reasons"].append("joint_feasibility_not_evaluated")
    return finish("unresolved")


def evaluate_claim(claim, analysis_data):
    validate_claim(claim)
    validate_data(analysis_data)
    return _evaluate(claim, analysis_data)


def _skipped_evaluation(claim, data, reason):
    scope = resolve_scope(claim["scope"], data)
    skipped = {"schema": "testifex.evaluation.v1", "engine_version": ENGINE_VERSION, "claim_id": claim["id"],
               "claim_digest": object_digest({key: value for key, value in claim.items() if key != "human_label"}),
               "scope_digest": object_digest(scope), "query_digest": object_digest({"scope": scope, "selector": claim["selector"]}),
               "coverage_digest": None, "event_set_digest": None, "interpretation_set_digest": None,
               "interpretation_count": None, "clock_digest": None, "entity_digest": None, "duplicate_digest": None,
               "verdict": "not_evaluated", "completeness": "not_evaluated", "integrity": data["integrity"],
               "assumption_status": "not_evaluated", "assumption_ids": list(claim["assumptions"]),
               "reasons": [reason], "witness_set": [], "count": None, "difference": None,
               "witness_count": 0, "witness_set_digest": object_digest([]), "witness_set_complete": True,
               "execution_state": "aborted_limit", "limitations": ["predicate_not_executed"]}
    skipped["id"] = object_digest(skipped, "TESTIFEX-EVALUATION-V1")
    return skipped


def analyze(claims, analysis_data, *, max_memberships=1000000, analysis_limits=None):
    configured = normalize_analysis_limits(analysis_limits) if analysis_limits is not None else None
    budget = AnalysisBudget(configured) if configured is not None else None
    if configured is not None:
        if max_memberships != 1000000 and max_memberships != configured["max_memberships"]:
            tm.error("conflicting_analysis_limits")
        max_memberships = configured["max_memberships"]
    tm.integer(max_memberships, 1, 10000000)
    _list(claims, configured["max_claims"] if configured else MAX_CLAIMS, "claim_count_limit")
    validate_data(analysis_data)
    if configured is not None and len(analysis_data["events"]) > configured["max_events"]:
        tm.error("analysis_event_limit", 6)
    for claim in claims:
        validate_claim(claim)
    if len({claim["id"] for claim in claims}) != len(claims):
        tm.error("duplicate_claim_id")
    semantic_claims = [{key: value for key, value in claim.items() if key != "human_label"} for claim in sorted(claims, key=lambda item: item["id"])]
    clock_cache = {}
    limits = {"max_memberships": max_memberships}
    if configured is not None:
        limits["analysis_limits"] = configured
    input_contract = {"schema": "testifex.analysis-input.v1", "semantic_engine_version": ENGINE_VERSION,
                      "scope_digest": object_digest([resolve_scope(item["scope"], analysis_data) for item in semantic_claims]),
                      "event_set_digest": object_digest(sorted(item["id"] for item in analysis_data["events"])),
                      "interpretation_set_digest": object_digest(sorted(interpretation_id(item, clock_cache) for item in analysis_data["events"])),
                      "claim_set_digest": object_digest(semantic_claims), "analysis_data_digest": semantic_digest(analysis_data),
                      "rule_config": {"count_joint_feasibility": "not_evaluated"}, "limits": limits}
    input_digest = object_digest(input_contract, "TESTIFEX-ANALYSIS-INPUT-V1")
    reason = "analysis_membership_limit" if len(claims) * max(1, len(analysis_data["events"])) > max_memberships else None
    evaluations = []
    if budget is not None:
        budget.check_time()
    context_cache = {"budget": budget} if budget is not None else {}
    if reason is None:
        try:
            for claim in sorted(claims, key=lambda item: item["id"]):
                evaluated = _evaluate(claim, analysis_data, cache=context_cache)
                if budget is not None:
                    budget.support(evaluated["witness_count"])
                evaluations.append(evaluated)
            if configured is not None and len(evaluations) > configured["max_findings"]:
                tm.error("analysis_finding_limit", 6)
        except ProbentiumError as exc:
            if exc.code not in ("analysis_relation_limit", "analysis_time_variable_limit", "analysis_support_limit", "analysis_finding_limit"):
                raise
            reason = exc.code
    if reason is not None:
        evaluations = [_skipped_evaluation(claim, analysis_data, reason) for claim in sorted(claims, key=lambda item: item["id"])]
    result = {"schema": "testifex.analysis-result.v1", "engine_version": ENGINE_VERSION, "input_digest": input_digest, "input": input_contract,
              "execution_state": "aborted_limit" if reason is not None else "complete", "limits": limits,
              "evaluation_ids": [item["id"] for item in evaluations], "evaluations": evaluations, "findings": [],
              "coverage": {"sources": len(analysis_data["sources"]), "events": len(analysis_data["events"]), "complete": all(source["complete"] for source in analysis_data["sources"])},
              "limitations": sorted(set(analysis_data.get("limitations", []) + ["conditional_on_declared_inputs", "not_an_independent_expert_review"]))}
    result["digest"] = object_digest(result, "TESTIFEX-ANALYSIS-RESULT-V1")
    if budget is not None:
        budget.check_time()
    if configured is not None and len(canonical_bytes(result)) > configured["max_report_bytes"]:
        tm.error("analysis_report_limit", 6)
    return result


def compare_results(before, after):
    for value in (before, after):
        if not isinstance(value, dict) or value.get("schema") != "testifex.analysis-result.v1":
            tm.error("invalid_analysis_result")
        digest = value.get("digest")
        if digest != object_digest({key: item for key, item in value.items() if key != "digest"}, "TESTIFEX-ANALYSIS-RESULT-V1"):
            tm.error("analysis_result_integrity_failed", 4)
        fields = {"schema", "engine_version", "input_digest", "input", "execution_state", "limits", "evaluation_ids", "evaluations", "findings", "coverage", "limitations", "digest"}
        # Additamentum v1 clausum est; campi ignoti numquam omittuntur.
        tm.exact_dict(value, fields | {"dependency_fingerprint"}, fields)
        if "dependency_fingerprint" in value:
            tm.identifier(value["dependency_fingerprint"])
            if not isinstance(value["evaluations"], list) or len(value["evaluations"]) != 1:
                tm.error("invalid_scoped_analysis_result")
        tm.identifier(value["input_digest"])
        tm.exact_dict(value["coverage"], {"sources", "events", "complete"}, {"sources", "events", "complete"})
        tm.integer(value["coverage"]["sources"], 0, 20000)
        tm.integer(value["coverage"]["events"], 0, MAX_EVENTS)
        if type(value["coverage"]["complete"]) is not bool or value["findings"] != []:
            tm.error("invalid_analysis_result")
        _names(value["limitations"])
        if value["execution_state"] not in ("complete", "aborted_limit"):
            tm.error("invalid_analysis_result")
        tm.exact_dict(value["limits"], {"max_memberships", "analysis_limits"}, {"max_memberships"})
        tm.integer(value["limits"]["max_memberships"], 1, 10000000)
        configured = None
        if "analysis_limits" in value["limits"]:
            configured = normalize_analysis_limits(value["limits"]["analysis_limits"])
            if configured != value["limits"]["analysis_limits"] or configured["max_memberships"] != value["limits"]["max_memberships"]:
                tm.error("invalid_analysis_input_binding")
        if not isinstance(value["input"], dict) or value["input"].get("semantic_engine_version") != value["engine_version"] or value["input"].get("limits") != value["limits"]:
            tm.error("invalid_analysis_input_binding")
        input_fields = {"schema", "semantic_engine_version", "scope_digest", "event_set_digest", "interpretation_set_digest",
                        "claim_set_digest", "analysis_data_digest", "rule_config", "limits"}
        tm.exact_dict(value["input"], input_fields, input_fields)
        if value["input"]["schema"] != "testifex.analysis-input.v1" or value["input"]["rule_config"] != {"count_joint_feasibility": "not_evaluated"}:
            tm.error("invalid_analysis_input_binding")
        for key in ("scope_digest", "event_set_digest", "interpretation_set_digest", "claim_set_digest", "analysis_data_digest"):
            tm.identifier(value["input"][key])
        if object_digest(value["input"], "TESTIFEX-ANALYSIS-INPUT-V1") != value["input_digest"]:
            tm.error("analysis_input_integrity_failed", 4)
        if type(value.get("engine_version")) is not str or not isinstance(value.get("evaluations"), list) or len(value["evaluations"]) > (configured["max_claims"] if configured else MAX_CLAIMS):
            tm.error("invalid_analysis_result")
        seen = set()
        for item in value["evaluations"]:
            if not isinstance(item, dict) or item.get("schema") != "testifex.evaluation.v1":
                tm.error("invalid_analysis_result")
            for field in ("id", "scope_digest", "claim_digest"):
                tm.identifier(item.get(field))
            for field in ("event_set_digest", "interpretation_set_digest", "clock_digest", "entity_digest", "duplicate_digest"):
                if item.get(field) is None and item.get("execution_state") == "aborted_limit":
                    continue
                tm.identifier(item.get(field))
            text_field(item.get("claim_id"), 128)
            if item["claim_id"] in seen or item.get("verdict") not in ("entailed", "ruled_out", "unresolved", "unknown", "invalid", "not_evaluated"):
                tm.error("invalid_analysis_result")
            seen.add(item["claim_id"])
            if item["id"] != object_digest({key: part for key, part in item.items() if key != "id"}, "TESTIFEX-EVALUATION-V1"):
                tm.error("evaluation_integrity_failed", 4)
        if value["evaluation_ids"] != [item["id"] for item in value["evaluations"]]:
            tm.error("analysis_evaluation_binding_mismatch", 4)
    if before["engine_version"] != after["engine_version"]:
        return {"status": "incomparable", "reason": "semantic_engine_version_changed", "added": [], "removed": [], "changed": []}
    if ("dependency_fingerprint" in before) != ("dependency_fingerprint" in after):
        return {"status": "incomparable", "reason": "dependency_contract_changed", "added": [], "removed": [], "changed": []}
    dependency_changed = before.get("dependency_fingerprint") != after.get("dependency_fingerprint")
    budget_changed = before["limits"] != after["limits"]
    old, new = ({item["claim_id"]: item for item in result["evaluations"]} for result in (before, after))
    changes = []
    for key in sorted(old.keys() & new.keys()):
        if old[key]["id"] != new[key]["id"] or dependency_changed or budget_changed:
            if old[key]["scope_digest"] != new[key]["scope_digest"]:
                reason = "scope"
            elif old[key]["claim_digest"] != new[key]["claim_digest"]:
                reason = "rule"
            elif old[key]["event_set_digest"] != new[key]["event_set_digest"]:
                reason = "parser" if "active_parser_changed" in old[key].get("reasons", []) + new[key].get("reasons", []) else "unknown"
            elif old[key]["entity_digest"] != new[key]["entity_digest"]:
                reason = "entity"
            else:
                reason = "clock" if old[key]["clock_digest"] != new[key]["clock_digest"] else "dependency" if dependency_changed else "resource_budget" if budget_changed else "unknown"
            changes.append({"claim_id": key, "before": old[key]["verdict"], "after": new[key]["verdict"], "reason_class": reason})
    result = {"status": "comparable", "added": sorted(new.keys() - old.keys()), "removed": sorted(old.keys() - new.keys()), "changed": changes}
    if "dependency_fingerprint" in before:
        result["dependencies"] = {"schema": "testifex.dependency-comparison.v1", "changed": dependency_changed,
                                  "before": before["dependency_fingerprint"], "after": after["dependency_fingerprint"]}
    return result
