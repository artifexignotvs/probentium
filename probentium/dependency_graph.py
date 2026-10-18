"""Nexus expliciti servantur; absentia nexus non probat independentiam."""
from collections import deque
import hashlib

from .contracts import ProbentiumError, canonical_bytes, object_digest
from . import time_model as tm

MAX_NODES = 250000
MAX_EDGES = 250000
MAX_SCAN_ROWS = 10000000
MAX_BYTES = 64 * 1024 ** 2
CHUNK_ROWS = 2048
SCHEMA = "probentium.unified-graph.v1"
_RECEIPTS = {"unified_graph", "unified_graph_chunk", "graph_impact"}
_LIMITATIONS = ["explicit_references_only_not_real_world_completeness", "structural_impact_requires_review_not_automatic_invalidity",
               "historical_results_and_signatures_are_not_rewritten", "hash_lineage_does_not_authenticate_observed_facts", "graph_receipts_and_valid_synthetic_markers_excluded", "impact_includes_requested_and_all_observed_structural_changes"]
_REPORTING = {"reporting_track", "filing_snapshot", "filing_approval", "submission_record", "receipt", "correction_impact", "deadline_evaluation"}
_LEGAL = {"legal_pack", "legal_review", "legal_activation", "requirement_catalogue", "legal_coverage_audit"}


def _fail(code, exit_code=4):
    raise ProbentiumError(code, exit_code)


def _expect(case, expected):
    if expected is not None:
        tm.integer(expected, 0, 9007199254740991)
        if case.revision != expected:
            _fail("revision_conflict", 5)
    return case.revision


def _node_id(kind, ref):
    return object_digest({"kind": kind, "ref": ref}, "PROBENTIUM-GRAPH-NODE-V1")


def _refs(value, limit=20000):
    return tm.refs(value, limit)


class _Graph:
    def __init__(self):
        self.nodes, self.refs, self.edges, self.gaps = {}, {}, set(), set()

    def node(self, kind, ref, data, *, lookup=True):
        tm.identifier(ref)
        identity = _node_id(kind, ref)
        if identity not in self.nodes and len(self.nodes) >= MAX_NODES:
            _fail("unified_graph_node_limit", 6)
        row = {"id": identity, "kind": kind, "ref": ref, "content_digest": object_digest(data)}
        if identity in self.nodes and self.nodes[identity] != row:
            _fail("unified_graph_node_conflict")
        self.nodes[identity] = row
        if lookup:
            self.refs.setdefault(ref, set()).add(identity)
        return identity

    def edge(self, dependency, dependent, relation):
        if dependency not in self.nodes or dependent not in self.nodes:
            _fail("unified_graph_edge_missing")
        key = (dependency, dependent, relation)
        if key not in self.edges and len(self.edges) >= MAX_EDGES:
            _fail("unified_graph_edge_limit", 6)
        self.edges.add(key)

    def gap(self, node, code):
        if len(self.gaps) >= MAX_NODES:
            _fail("unified_graph_gap_limit", 6)
        self.gaps.add((node, code))

    def link(self, ref, dependent, relation="declared_reference"):
        tm.identifier(ref)
        targets = self.refs.get(ref, set())
        if not targets:
            missing = self.node("unresolved_reference", ref, {"ref": ref})
            self.gap(missing, "referenced_identity_unavailable_in_scope")
            targets = {missing}
        for source in targets:
            self.edge(source, dependent, relation)


def _engine_refs(kind, data):
    """Campi nominati tantum identitates sunt; valores liberi non leguntur."""
    from . import claims, investigation
    refs = set()
    if kind == "claim":
        tm.exact_dict(data, {"schema", "claim", "scope_request", "previous_id", "author", "input_revision"},
                      {"schema", "claim", "scope_request", "previous_id", "author", "input_revision"})
        if data["schema"] != "testifex.claim-record.v1":
            _fail("unified_graph_invalid_claim")
        value = claims.validate_claim(data["claim"])
        scope = value["scope"]
        if "all_at_revision" in scope:
            _fail("unified_graph_unresolved_scope")
        refs.update(scope["artifact_ids"])
        refs.update(row["parse_run_id"] for row in scope["active_parse_runs"])
        refs.update(value["assumptions"])
        for field in ("before", "after", "left", "right", "anchor"):
            if value["operands"].get(field) is not None:
                refs.add(value["operands"][field])
        if data["previous_id"] is not None:
            refs.add(data["previous_id"])
    elif kind == "clock_model":
        tm.exact_dict(data, {"model", "artifact_ids"}, {"model", "artifact_ids"})
        tm.validate_clock_model(data["model"])
        refs.update(_refs(data["artifact_ids"]))
        refs.update(data["model"]["basis_refs"])
    elif kind == "source_family":
        tm.exact_dict(data, {"family_id", "artifact_ids", "basis_refs", "rationale"}, {"family_id", "artifact_ids", "basis_refs", "rationale"})
        refs.update(_refs(data["artifact_ids"]))
        refs.update(_refs(data["basis_refs"], 32))
    elif kind == "identity_assertion":
        tm.exact_dict(data, {"assertion"}, {"assertion"})
        assertion = data["assertion"]
        tm.exact_dict(assertion, {"id", "status", "event_ids", "source_family_ids", "namespace", "canonical_value", "rationale"},
                      {"id", "status", "event_ids", "source_family_ids"})
        tm.identifier(assertion["id"])
        if assertion["status"] not in ("active", "withdrawn", "conflicting"):
            _fail("unified_graph_invalid_identity")
        refs.update(_refs(assertion["event_ids"], 100000))
    elif kind == "duplicate_groups":
        tm.exact_dict(data, {"groups"}, {"groups"})
        if not isinstance(data["groups"], list) or len(data["groups"]) > 100000:
            _fail("unified_graph_group_limit", 6)
        for group in data["groups"]:
            tm.exact_dict(group, {"id", "event_ids"}, {"id", "event_ids"})
            refs.update(_refs(group["event_ids"], 100000))
    elif kind == "evaluation":
        required = {"schema", "claim_object_id", "claim_revision", "result", "data_fingerprint", "input_revision", "witness_lineage", "dependency_bindings", "source_catalog"}
        tm.exact_dict(data, required | {"evaluation_dependencies"}, required)
        if data["schema"] != "testifex.case-evaluation.v1":
            _fail("unified_graph_invalid_evaluation")
        claims.compare_results(data["result"], data["result"])
        refs.add(data["claim_object_id"])
        for row in data["witness_lineage"]:
            refs.add(row["event_id"])
            refs.add(row["parse_run_id"])
            refs.update(row["entity_assertion_ids"])
        for row in data["source_catalog"]:
            refs.update((row["artifact_id"], row["parse_run_id"]))
        binding = data.get("evaluation_dependencies")
        if binding is not None:
            if (not isinstance(binding, dict) or binding.get("schema") != "testifex.evaluation-dependencies.v1"
                    or binding.get("fingerprint") != object_digest({k: v for k, v in binding.items() if k != "fingerprint"}, "TESTIFEX-EVALUATION-DEPENDENCIES-V1")
                    or data["result"].get("dependency_fingerprint") != binding["fingerprint"]):
                _fail("evaluation_dependency_binding_invalid")
    elif kind == "analysis_scenario":
        investigation.validate_scenario(data["scenario"])
        claims.compare_results(data["baseline"], data["baseline"])
        claims.compare_results(data["scenario_result"], data["scenario_result"])
        refs.update(_refs(data["claim_object_ids"], 10000))
        refs.update(data["scenario"]["revoke_identities"])
    elif kind == "dependency_graph":
        graph = investigation.validate_graph(data["nodes"], data["edges"])
        refs.update(graph["nodes"])
    elif kind == "review_rationale":
        tm.exact_dict(data, {"text"}, {"text"})
        from .reviews import rationale_digest
        rationale_digest(data["text"])
    elif kind == "review_decision":
        from .reviews import validate_stored
        validate_stored(data)
        refs.add(data["decision"]["claim_id"])
    elif kind == "parser_approval":
        from .parser_artifact import validate_approval
        validate_approval(data)
    else:
        return None
    for identity in refs:
        tm.identifier(identity)
    return refs


def _excluded(obj):
    if obj["kind"] in _RECEIPTS:
        return True
    if obj["kind"] != "scenario":
        return False
    data = obj["data"]
    required = {"synthetic", "as_of", "artifacts", "source_digest", "objects", "limits"}
    if set(data) - (required | {"title"}) or not required <= data.keys() or data["synthetic"] is not True:
        return False
    from .contracts import timestamp, text_field
    timestamp(data["as_of"])
    if "title" in data:
        text_field(data["title"], 4096)
    _refs(data["artifacts"])
    _refs(data["objects"], 10000)
    tm.identifier(data["source_digest"])
    if not isinstance(data["limits"], list) or len(data["limits"]) > 100:
        _fail("unified_graph_invalid_synthetic_marker")
    for item in data["limits"]:
        text_field(item, 4096)
    return True


def _object_refs(obj):
    from . import governance, reporting, legalpacks, retention
    kind, data = obj["kind"], obj["data"]
    if kind in {"control", "track", "filing"}:
        from .regulatory import evaluate_control, evaluate_deadlines, _verified_snapshot
        if kind == "control":
            evaluate_control(data)
            refs = set(data.get("evidence_refs", []))
            for row in data.get("observations", []):
                refs.update(row.get("evidence_refs", []))
            return refs
        if kind == "track":
            evaluate_deadlines(data, "2026-01-01T00:00:00Z")
            return set()
        _verified_snapshot(data)
        return {ref for field in data["fields"] for ref in field["refs"]}
    if kind.startswith("eu."):
        name = kind[3:]
        if name in governance.FIELDS or name == "control_observation":
            governance.validate_stored(kind, data)
        elif name in _REPORTING:
            reporting.validate_stored(kind, data)
        elif name in _LEGAL:
            legalpacks.validate_stored(kind, data)
        else:
            return None
        refs = set(governance.record_dependencies(data))
        for field in ("supersedes", "previous_pack_ref", "catalogue_ref"):
            if data.get(field) is not None:
                refs.add(data[field])
        for field in ("changed_refs", "old_submission_refs", "pack_state_refs"):
            refs.update(data.get(field, []))
        if name in {"legal_pack", "requirement_catalogue"}:
            refs.update(row["document_ref"] for row in data["sources"] if row.get("document_ref") is not None)
        elif name == "deadline_evaluation":
            refs.update(data["anchor_refs"].values())
        for ref in refs:
            tm.identifier(ref)
        return refs
    if kind.startswith("retention."):
        retention.validate_stored(kind, data)
        refs = set(data.get("artifact_ids", []))
        for field in ("released_hold_id", "plan_id", "approval_id"):
            if data.get(field) is not None:
                refs.add(data[field])
        refs.update(data.get("removal_inventory", {}).get("known_export_refs", []))
        return refs
    return _engine_refs(kind, data)


def _complete_typed_references(objects, references):
    """Summaria cryptographica ad species certas, non ad textum, resolvuntur."""
    evaluations, rationales, reviews, clocks, families = {}, {}, {}, {}, {}
    for identity, obj in objects.items():
        data, kind = obj["data"], obj["kind"]
        if kind == "evaluation":
            evaluations.setdefault((data["claim_object_id"], data["result"]["digest"], data["data_fingerprint"]), []).append(identity)
        elif kind == "review_rationale":
            rationales.setdefault(hashlib.sha256(data["text"].encode("utf-8")).hexdigest(), []).append(identity)
        elif kind == "review_decision":
            reviews.setdefault(object_digest(data["decision"], "TESTIFEX-REVIEW-V1"), []).append(identity)
        elif kind == "clock_model":
            clocks.setdefault(object_digest(data["model"]), []).append(identity)
        elif kind == "source_family":
            families.setdefault(data["family_id"], []).append(identity)
    for identity, obj in objects.items():
        data, kind, refs = obj["data"], obj["kind"], references[identity]
        if refs is None:
            continue
        if kind == "review_decision":
            decision = data["decision"]
            refs.update(evaluations.get((decision["claim_id"], decision["evaluation_digest"], decision["snapshot_digest"]), ()))
            refs.update(rationales.get(decision["rationale_digest"], ()))
            refs.update(reviews.get(decision["previous_decision_id"], ()))
        elif kind == "evaluation":
            for row in data["witness_lineage"]:
                refs.update(ref for ref in clocks.get(row["clock_model_digest"], ()) if objects[ref]["revision"] <= data["input_revision"])
        if kind in {"clock_model", "identity_assertion"}:
            value = data["model"] if kind == "clock_model" else data["assertion"]
            for family in value.get("source_family_ids", []):
                refs.update(ref for ref in families.get(family, ()) if objects[ref]["revision"] <= obj["revision"])


def _revision_candidates(objects):
    revisions, packs = {}, {}
    for identity, obj in objects.items():
        if obj["kind"].startswith("eu."):
            previous = obj["data"].get("supersedes")
            if previous is not None:
                revisions.setdefault(previous, set()).add(identity)
        elif obj["kind"] == "claim" and obj["data"]["previous_id"] is not None:
            revisions.setdefault(obj["data"]["previous_id"], set()).add(identity)
        if obj["kind"] in {"eu.legal_review", "eu.legal_activation"}:
            packs.setdefault(obj["data"]["pack_ref"], set()).add(identity)
            if obj["kind"] == "eu.legal_activation" and obj["data"]["previous_pack_ref"] is not None:
                packs.setdefault(obj["data"]["previous_pack_ref"], set()).add(identity)
    return revisions, packs


def _expand_current_objects(objects, references, included):
    revisions, packs = _revision_candidates(objects)
    queue, seen = deque(sorted(included)), set(included)
    while queue:
        identity = queue.popleft()
        candidates = set(revisions.get(identity, ())) | set(packs.get(identity, ()))
        if identity in objects:
            candidates.update(references[identity] or ())
        for ref in sorted(candidates - seen):
            seen.add(ref)
            queue.append(ref)
            if len(seen) > MAX_NODES:
                _fail("unified_graph_node_limit", 6)
    return seen & objects.keys()


def _revision_context_edges(graph, objects, references, included):
    """Nova declaratio usum praesentem tangit; scriptum vetus non mutatur."""
    revisions, packs = _revision_candidates(objects)
    updated, work = {}, 0
    needed = {ref for identity in included if objects[identity]["kind"].startswith("eu.") for ref in references[identity] or ()} & revisions.keys()
    for previous in sorted(needed):
        found, queue = {previous}, deque([previous])
        while queue:
            for ref in sorted(revisions.get(queue.popleft(), ())):
                work += 1
                if work > MAX_EDGES:
                    _fail("unified_graph_revision_work_limit", 6)
                if ref not in found:
                    found.add(ref)
                    queue.append(ref)
        updated[previous] = sorted(found - {previous})
    for identity in sorted(included):
        obj = objects[identity]
        if not obj["kind"].startswith("eu.") or references[identity] is None:
            continue
        dependencies = set(references[identity])
        dependencies.discard(obj["data"].get("supersedes"))
        changes = {ref: [new for new in updated.get(ref, ()) if new in included] for ref in sorted(dependencies)}
        changes = {ref: rows for ref, rows in changes.items() if rows}
        if changes:
            state = graph.node("declared_revision_context", identity, {"revisions": changes}, lookup=False)
            graph.edge(state, _node_id(obj["kind"], identity), "new_dependency_revision_requires_review")
            for rows in changes.values():
                for ref in rows:
                    graph.link(ref, state, "new_dependency_revision")
        pack = obj["data"].get("pack_ref")
        if pack is not None and obj["kind"] not in {"eu.legal_review", "eu.legal_activation"}:
            context_refs = sorted(ref for ref in packs.get(pack, ()) if ref in included)
            state = graph.node("legal_pack_review_context", pack, {"review_activation_refs": context_refs}, lookup=False)
            graph.edge(state, _node_id(obj["kind"], identity), "pack_review_context_candidate")
            for ref in context_refs:
                graph.link(ref, state, "pack_review_or_activation")


def _closure(roots, edges, *, reverse=False):
    neighbors = {}
    for left, right, _ in edges:
        if reverse:
            left, right = right, left
        neighbors.setdefault(left, set()).add(right)
    found, queue = set(roots), deque(sorted(roots))
    while queue:
        for identity in sorted(neighbors.get(queue.popleft(), ())):
            if identity not in found:
                found.add(identity)
                queue.append(identity)
                if len(found) > MAX_NODES:
                    _fail("unified_graph_node_limit", 6)
    return found


def _scan(case, table, counts):
    observed = 0
    for row in case.iter_snapshot_rows(table):
        observed += 1
        if observed > counts[table] or observed > MAX_SCAN_ROWS:
            _fail("unified_graph_scan_limit", 6)
        yield row
    if observed != counts[table]:
        _fail("unified_graph_snapshot_changed")


def _structure(value):
    return {key: value[key] for key in ("scope", "nodes", "edges", "gaps", "completeness")}


def build_case_graph(case, *, artifact_ids=None, object_ids=None, expected_revision=None, persist=True):
    """Imago integra vel error explicitus; nullus finis tacitus."""
    revision = _expect(case, expected_revision)
    if type(persist) is not bool:
        _fail("invalid_persist_flag", 2)
    selected = artifact_ids is not None or object_ids is not None
    artifact_roots = sorted(_refs(artifact_ids or [])) if artifact_ids is not None else []
    object_roots = sorted(_refs(object_ids or [], 10000)) if object_ids is not None else []
    if selected and not artifact_roots and not object_roots:
        _fail("unified_graph_roots_required", 2)
    header = case.snapshot_header()
    counts = header["counts"]
    if any(type(value) is not int or not 0 <= value <= MAX_SCAN_ROWS for value in counts.values()):
        _fail("unified_graph_scan_limit", 6)
    objects = {row["id"]: row for row in case.objects() if not _excluded(row)}
    # Numeri totius casus ante tabularum allocationem inspiciuntur.
    if not selected and sum(counts[key] for key in ("artifacts", "records", "parse_runs", "events")) + len(objects) > MAX_NODES:
        _fail("unified_graph_node_limit", 6)
    if not selected and counts["records"] + 2 * counts["events"] + counts["parse_runs"] > MAX_EDGES:
        _fail("unified_graph_edge_limit", 6)
    graph = _Graph()
    artifacts = {row["id"]: row for row in _scan(case, "artifacts", counts)}
    runs = {row["id"]: row for row in _scan(case, "parse_runs", counts)}
    if not set(artifact_roots) <= artifacts.keys() or not set(object_roots) <= objects.keys():
        _fail("unified_graph_root_missing", 2)
    references = {}
    try:
        for identity, obj in objects.items():
            references[identity] = _object_refs(obj)
    except (KeyError, TypeError, ValueError, AttributeError):
        _fail("unified_graph_invalid_object")
    _complete_typed_references(objects, references)
    if sum(len(refs or ()) for refs in references.values()) > MAX_EDGES:
        _fail("unified_graph_reference_scan_limit", 6)
    included_objects = set(objects)
    wanted_refs = set()
    if selected:
        # Radices cum dependentibus et praemissis explicitis clauduntur.
        pairs = [(ref, identity, "reference") for identity, refs in references.items() for ref in refs or ()]
        included_objects = _closure(set(artifact_roots + object_roots), pairs) & objects.keys()
        included_objects |= set(object_roots)
        included_objects = _closure(included_objects, pairs, reverse=True) & objects.keys()
        included_objects = _expand_current_objects(objects, references, included_objects)
        wanted_refs = {ref for identity in included_objects for ref in references[identity] or ()}
    included_artifacts = set(artifacts) if not selected else set(artifact_roots) | (wanted_refs & artifacts.keys())
    included_artifacts.update(runs[ref]["artifact_id"] for ref in wanted_refs & runs.keys())
    if selected and wanted_refs - artifacts.keys() - objects.keys() - runs.keys():
        for event in _scan(case, "events", counts):
            if event["id"] in wanted_refs:
                included_artifacts.add(event["artifact_id"])
    from .retention import authorized_unavailable
    unavailable = authorized_unavailable(case)
    active = {row["artifact_id"]: row["parse_run_id"] for row in _scan(case, "active_runs", counts)}
    for identity in sorted(included_artifacts):
        node = graph.node("artifact", identity, {"artifact": artifacts[identity], "availability": "authorized_unavailable" if identity in unavailable else "present"})
        if identity in unavailable:
            graph.gap(node, "source_bytes_authorized_unavailable")
    for identity, obj in objects.items():
        if identity in included_objects:
            node = graph.node(obj["kind"], identity, obj)
            if references[identity] is None:
                graph.gap(node, "unsupported_object_schema")
            elif obj["kind"] == "eu.service" and obj["data"]["unknown_dependencies"]:
                graph.gap(node, "service_dependencies_declared_unknown")
            elif obj["kind"] == "eu.dependency" and not obj["data"]["known"]:
                graph.gap(node, "dependency_declared_unknown")
    for identity, run in runs.items():
        if run["artifact_id"] not in included_artifacts:
            continue
        node = graph.node("parse_run", identity, run)
        graph.link(run["artifact_id"], node, "parse_source")
        parser = graph.node("parser_artifact", run["parser_artifact_digest"], {"digest": run["parser_artifact_digest"]})
        graph.edge(parser, node, "parser_version")
        if run["adapter_id"] == "opaque":
            graph.gap(node, "opaque_source_interpretation_unavailable")
        elif not run["interpretation_complete"]:
            graph.gap(node, "parse_coverage_incomplete")
        if active.get(run["artifact_id"]) == identity:
            slot = graph.node("active_parse_selection", run["artifact_id"], {"parse_run_id": identity}, lookup=False)
            graph.edge(node, slot, "active_parse_selection")
    record_map = {}
    for row in _scan(case, "records", counts):
        if row["artifact_id"] in included_artifacts:
            node = graph.node("record", row["id"], row)
            record_map[row["id"]] = row
            graph.link(row["artifact_id"], node, "raw_record_in_artifact")
    from .locators import event_records
    for row in _scan(case, "events", counts):
        if row["artifact_id"] not in included_artifacts:
            continue
        event_records(row, record_map.__getitem__)
        node = graph.node("event", row["id"], row)
        graph.link(row["parse_run_id"], node, "event_parse_run")
        for ref in row["record_refs"]:
            graph.link(ref, node, "event_record")
    del record_map
    for identity in sorted(included_objects):
        obj = objects[identity]
        node = _node_id(obj["kind"], identity)
        for ref in sorted(references[identity] or ()):
            relation = "historical_replay_input" if obj["kind"] == "evaluation" and ref in {r[key] for r in obj["data"]["source_catalog"] for key in ("artifact_id", "parse_run_id")} else "declared_reference"
            graph.link(ref, node, relation)
    _special_edges(case, graph, objects, included_objects, runs)
    _revision_context_edges(graph, objects, references, included_objects)
    if selected:
        root_nodes = {_node_id("artifact", identity) for identity in artifact_roots} | {_node_id(objects[identity]["kind"], identity) for identity in object_roots}
        connected = _closure(root_nodes, graph.edges)
        connected = _closure(connected, graph.edges, reverse=True)
        graph.nodes = {key: row for key, row in graph.nodes.items() if key in connected}
        graph.edges = {edge for edge in graph.edges if edge[0] in connected and edge[1] in connected}
        graph.gaps = {gap for gap in graph.gaps if gap[0] in connected}
    if case.revision != revision:
        _fail("revision_conflict", 5)
    value = {"schema": SCHEMA, "snapshot_revision": revision,
             "scope": {"mode": "explicit_reference_closure" if selected else "whole_case", "artifact_ids": artifact_roots, "object_ids": object_roots},
             "nodes": [graph.nodes[key] for key in sorted(graph.nodes)],
             "edges": [{"dependency": a, "dependent": b, "type": kind} for a, b, kind in sorted(graph.edges)],
             "gaps": [{"node_id": node, "code": code} for node, code in sorted(graph.gaps)],
             "completeness": "incomplete" if graph.gaps else "complete_explicit_schema_references",
             "limits": {"max_nodes": MAX_NODES, "max_edges": MAX_EDGES, "max_scan_rows_per_table": MAX_SCAN_ROWS, "max_bytes": MAX_BYTES},
             "limitations": list(_LIMITATIONS)}
    value["structure_digest"] = object_digest(_structure(value), "PROBENTIUM-GRAPH-STRUCTURE-V1")
    value["counts"] = {"nodes": len(value["nodes"]), "edges": len(value["edges"]), "gaps": len(value["gaps"])}
    if len(canonical_bytes(value)) > MAX_BYTES:
        _fail("unified_graph_byte_limit", 6)
    return _persist(case, value, revision) if persist else value


def _special_edges(case, graph, objects, included, runs):
    from . import investigation
    evaluations = [identity for identity in sorted(included) if objects[identity]["kind"] == "evaluation"]
    current = investigation.stale_status_many(case, evaluations, max_evaluations=10000) if evaluations else {"statuses": []}
    status_map = {row["evaluation_id"]: row for row in current["statuses"]}
    clock_digests, rationales, decision_ids, evaluation_ids, premises = {}, {}, {}, {}, {}
    for identity, row in objects.items():
        data = row["data"]
        if row["kind"] in {"clock_model", "source_family"} and identity in included:
            for aid in data["artifact_ids"]:
                premises.setdefault(aid, set()).add(identity)
        if row["kind"] == "evaluation":
            evaluation_ids.setdefault((data["claim_object_id"], data["result"]["digest"], data["data_fingerprint"]), []).append(identity)
        if row["kind"] == "clock_model":
            clock_digests.setdefault(object_digest(data["model"]), []).append(identity)
        elif row["kind"] == "review_rationale":
            rationales.setdefault(hashlib.sha256(data["text"].encode("utf-8")).hexdigest(), []).append(identity)
        elif row["kind"] == "review_decision":
            decision_ids.setdefault(object_digest(data["decision"], "TESTIFEX-REVIEW-V1"), []).append(identity)
    for identity in sorted(included, key=lambda key: (objects[key]["kind"] != "eu.legal_pack", key)):
        obj, data = objects[identity], objects[identity]["data"]
        node = _node_id(obj["kind"], identity)
        if obj["kind"] == "evaluation":
            state = status_map[identity]
            state_node = graph.node("evaluation_currentness", identity, {key: state[key] for key in ("status", "reasons", "original_dependency_digest", "current_dependency_digest") if key in state}, lookup=False)
            graph.edge(state_node, node, "currentness_assessment")
            if "dependency_recomputation_limit" in state["reasons"]:
                graph.gap(state_node, "semantic_currentness_resource_limit")
            if "evaluation_dependencies" not in data:
                graph.gap(node, "legacy_evaluation_dependencies_unavailable")
            else:
                binding = graph.node("evaluation_dependency_binding", data["evaluation_dependencies"]["fingerprint"], data["evaluation_dependencies"], lookup=False)
                graph.edge(binding, node, "saved_semantic_dependency_binding")
            for lineage in data["witness_lineage"]:
                digest = lineage["clock_model_digest"]
                for ref in clock_digests.get(digest, ()):
                    if objects[ref]["revision"] <= data["input_revision"] and ref in included:
                        graph.link(ref, node, "witness_clock_basis")
            claim = objects.get(data["claim_object_id"])
            if claim is not None:
                scoped = set(claim["data"]["claim"]["scope"]["artifact_ids"])
                for ref in sorted({ref for aid in scoped for ref in premises.get(aid, ())}):
                    graph.link(ref, state_node, "scoped_premise_candidate")
                for aid in scoped:
                    slot = _node_id("active_parse_selection", aid)
                    if slot in graph.nodes:
                        graph.edge(slot, state_node, "selected_run_currentness")
        elif obj["kind"] == "review_decision":
            decision = data["decision"]
            claim = objects.get(decision["claim_id"])
            if claim is None or claim["kind"] != "claim" or claim["revision"] != decision["claim_revision"]:
                graph.gap(node, "review_claim_revision_unavailable")
            matching = evaluation_ids.get((decision["claim_id"], decision["evaluation_digest"], decision["snapshot_digest"]), [])
            for code, refs in (("review_evaluation_unavailable", matching), ("review_rationale_unavailable", rationales.get(decision["rationale_digest"], []))):
                if not refs:
                    graph.gap(node, code)
                for ref in refs:
                    graph.link(ref, node, "signed_review_binding")
            if decision["previous_decision_id"] is not None:
                refs = decision_ids.get(decision["previous_decision_id"], [])
                if not refs:
                    graph.gap(node, "previous_review_unavailable")
                for ref in refs:
                    graph.link(ref, node, "review_revision")
        elif obj["kind"] == "eu.legal_pack":
            for field, kind in (("rules", "legal_rule"), ("calendars", "calendar_policy"), ("templates", "filing_template")):
                for member in data[field]:
                    ref = object_digest({"pack_ref": identity, "kind": kind, "member_id": member["id"]}, "PROBENTIUM-GRAPH-MEMBER-V1")
                    part = graph.node(kind, ref, member)
                    graph.edge(node, part, "versioned_pack_member")
        elif obj["kind"] == "eu.deadline_evaluation":
            for field, kind in (("rule", "legal_rule"), ("calendar", "calendar_policy")):
                member = data["inputs"][field]
                ref = object_digest({"pack_ref": data["pack_ref"], "kind": kind, "member_id": member["id"]}, "PROBENTIUM-GRAPH-MEMBER-V1")
                member_node = _node_id(kind, ref)
                if member_node not in graph.nodes:
                    member_node = graph.node(kind, ref, member)
                    graph.gap(member_node, "pack_member_source_unavailable")
                elif graph.nodes[member_node]["content_digest"] != object_digest(member):
                    _fail("unified_graph_deadline_member_mismatch")
                graph.edge(member_node, node, "deadline_policy_input")
        elif obj["kind"] == "dependency_graph":
            for edge in data["edges"]:
                for dependency in graph.refs.get(edge["dependency"], ()):
                    for dependent in graph.refs.get(edge["dependent"], ()):
                        graph.edge(dependency, dependent, "operator_declared_dependency")
        elif obj["kind"] == "parser_approval":
            parser = _node_id("parser_artifact", data["manifest_digest"])
            if parser in graph.nodes:
                graph.edge(node, parser, "operator_parser_approval")


def _persist(case, value, revision):
    """Partes parvae ante caput immutabile scribuntur; defectus caput non fingit."""
    chunks = {"nodes": [], "edges": []}
    for table in chunks:
        for offset in range(0, len(value[table]), CHUNK_ROWS):
            payload = {"schema": "probentium.unified-graph-chunk.v1", "table": table, "rows": value[table][offset:offset + CHUNK_ROWS]}
            row = case.put_object("unified_graph_chunk", payload, expected_revision=revision)
            chunks[table].append(row["id"])
            revision = case.revision
    receipt = {key: item for key, item in value.items() if key not in ("nodes", "edges")}
    receipt["storage"] = {"mode": "immutable_chunks", "node_chunks": chunks["nodes"], "edge_chunks": chunks["edges"]}
    return case.put_object("unified_graph", receipt, expected_revision=revision)


def load_case_graph(case, identity):
    obj = case.get_object(tm.identifier(identity))
    if obj["kind"] != "unified_graph":
        _fail("unified_graph_kind_mismatch", 2)
    validate_graph(obj["data"])
    value = dict(obj["data"])
    required = {"schema", "snapshot_revision", "scope", "gaps", "completeness", "limits", "limitations", "structure_digest", "counts", "storage"}
    if set(value) != required or value["schema"] != SCHEMA:
        _fail("unified_graph_schema_invalid")
    storage = value.pop("storage")
    if not isinstance(storage, dict) or set(storage) != {"mode", "node_chunks", "edge_chunks"} or storage["mode"] != "immutable_chunks":
        _fail("unified_graph_storage_invalid")
    for table, maximum in (("nodes", MAX_NODES), ("edges", MAX_EDGES)):
        refs = _refs(storage[table[:-1] + "_chunks"], (maximum + CHUNK_ROWS - 1) // CHUNK_ROWS)
        rows = []
        for ref in refs:
            chunk = case.get_object(ref)
            data = chunk["data"]
            validate_stored(chunk["kind"], data)
            if (chunk["kind"] != "unified_graph_chunk" or set(data) != {"schema", "table", "rows"}
                    or data["schema"] != "probentium.unified-graph-chunk.v1" or data["table"] != table
                    or not isinstance(data["rows"], list) or not 1 <= len(data["rows"]) <= CHUNK_ROWS):
                _fail("unified_graph_chunk_invalid")
            rows.extend(data["rows"])
            if len(rows) > maximum:
                _fail("unified_graph_node_limit" if table == "nodes" else "unified_graph_edge_limit", 6)
        value[table] = rows
    _validate_graph(value)
    return value


def _validate_graph(value):
    if not isinstance(value["nodes"], list) or len(value["nodes"]) > MAX_NODES or not isinstance(value["edges"], list) or len(value["edges"]) > MAX_EDGES:
        _fail("unified_graph_structure_limit", 6)
    if len(canonical_bytes(value)) > MAX_BYTES:
        _fail("unified_graph_byte_limit", 6)
    nodes = {}
    for table in ("nodes", "edges"):
        for offset in range(0, len(value[table]), CHUNK_ROWS):
            validate_stored("unified_graph_chunk", {"schema": "probentium.unified-graph-chunk.v1", "table": table, "rows": value[table][offset:offset + CHUNK_ROWS]})
    for row in value["nodes"]:
        if not isinstance(row, dict) or set(row) != {"id", "kind", "ref", "content_digest"}:
            _fail("unified_graph_node_invalid")
        for field in ("id", "ref", "content_digest"):
            tm.identifier(row[field])
        if not isinstance(row["kind"], str) or not 1 <= len(row["kind"]) <= 128 or row["id"] != _node_id(row["kind"], row["ref"]) or row["id"] in nodes:
            _fail("unified_graph_node_invalid")
        nodes[row["id"]] = row
    if list(nodes) != sorted(nodes) or any(gap["node_id"] not in nodes for gap in value["gaps"]):
        _fail("unified_graph_node_invalid")
    previous = None
    for edge in value["edges"]:
        if not isinstance(edge, dict) or set(edge) != {"dependency", "dependent", "type"} or edge["dependency"] not in nodes or edge["dependent"] not in nodes:
            _fail("unified_graph_edge_invalid")
        current = (edge["dependency"], edge["dependent"], edge["type"])
        if not isinstance(edge["type"], str) or previous is not None and current <= previous:
            _fail("unified_graph_edge_invalid")
        previous = current
    if value["counts"] != {"nodes": len(nodes), "edges": len(value["edges"]), "gaps": len(value["gaps"])}:
        _fail("unified_graph_count_mismatch")
    if value["structure_digest"] != object_digest(_structure(value), "PROBENTIUM-GRAPH-STRUCTURE-V1"):
        _fail("unified_graph_digest_mismatch")


def impact(case, graph_id, changed_ids, *, expected_revision=None, persist=False):
    """Immutata historia manet; mutatae praemissae iterum recensendae sunt."""
    revision = _expect(case, expected_revision)
    if type(persist) is not bool:
        _fail("invalid_persist_flag", 2)
    changed = _refs(changed_ids, 10000)
    old = load_case_graph(case, graph_id)
    scope = old["scope"]
    current = build_case_graph(case, artifact_ids=scope["artifact_ids"] if scope["mode"] != "whole_case" else None,
                               object_ids=scope["object_ids"] if scope["mode"] != "whole_case" else None,
                               expected_revision=revision, persist=False)
    before, after = ({row["id"]: row for row in value["nodes"]} for value in (old, current))
    known = {**before, **after}
    roots = {identity for identity, row in known.items() if identity in changed or row["ref"] in changed}
    represented = set(known) | {row["ref"] for row in known.values()}
    if not set(changed) <= represented:
        _fail("unified_graph_changed_reference_missing", 2)
    modified = {identity for identity in before.keys() & after.keys() if before[identity] != after[identity]}
    added, removed = after.keys() - before.keys(), before.keys() - after.keys()
    edges_before = {(r["dependency"], r["dependent"], r["type"]) for r in old["edges"]}
    edges_after = {(r["dependency"], r["dependent"], r["type"]) for r in current["edges"]}
    seeds = roots | modified | added | removed
    # Utraque imago requiritur: nexus remotus quoque effectum habet.
    all_edges = {edge for edge in edges_before | edges_after if edge[2] != "historical_replay_input"}
    predecessors = {identity: None for identity in sorted(seeds)}
    queue, successors = deque(sorted(seeds)), {}
    for left, right, _ in sorted(all_edges):
        successors.setdefault(left, set()).add(right)
    while queue:
        parent = queue.popleft()
        for child in sorted(successors.get(parent, ())):
            if child not in predecessors:
                predecessors[child] = parent
                queue.append(child)
    affected = sorted(set(predecessors) - roots)
    paths, paths_complete = {}, len(affected) <= 256
    for identity in affected[:256]:
        path, cursor = [], identity
        while cursor is not None and len(path) < 256:
            path.append(cursor)
            cursor = predecessors[cursor]
        if cursor is not None:
            paths_complete = False
        paths[identity] = list(reversed(path))
    result = {"schema": "probentium.graph-impact.v1", "graph_id": graph_id, "snapshot_revision": old["snapshot_revision"], "current_revision": revision,
              "original_structure_digest": old["structure_digest"], "current_structure_digest": current["structure_digest"],
              "graph_currentness": "current" if old["structure_digest"] == current["structure_digest"] else "changed",
              "changed_ids": sorted(changed), "affected": affected, "paths": paths, "path_details_complete": paths_complete,
              "predecessors": {key: predecessors[key] for key in sorted(predecessors)},
              "node_changes": {"added": sorted(added), "removed": sorted(removed), "modified": sorted(modified)},
              "edge_changes": {"added": [{"dependency": a, "dependent": b, "type": t} for a, b, t in sorted(edges_after - edges_before)],
                               "removed": [{"dependency": a, "dependent": b, "type": t} for a, b, t in sorted(edges_before - edges_after)]},
              "completeness": "incomplete" if "incomplete" in (old["completeness"], current["completeness"]) else "complete_explicit_schema_references",
              "required_action": "review_affected_dependencies" if affected else "none_from_explicit_graph", "limitations": list(_LIMITATIONS)}
    if len(canonical_bytes(result)) > MAX_BYTES:
        _fail("unified_graph_byte_limit", 6)
    if case.revision != revision:
        _fail("revision_conflict", 5)
    return case.put_object("graph_impact", result, expected_revision=revision) if persist else result


def _manifest_fields(value):
    required = {"schema", "snapshot_revision", "scope", "gaps", "completeness", "limits", "limitations", "structure_digest", "counts", "storage"}
    if not isinstance(value, dict) or set(value) != required or value["schema"] != SCHEMA:
        _fail("unified_graph_schema_invalid")
    tm.integer(value["snapshot_revision"], 0, 9007199254740991)
    tm.identifier(value["structure_digest"])
    scope = value["scope"]
    if not isinstance(scope, dict) or set(scope) != {"mode", "artifact_ids", "object_ids"} or scope["mode"] not in {"whole_case", "explicit_reference_closure"}:
        _fail("unified_graph_scope_invalid")
    _refs(scope["artifact_ids"])
    _refs(scope["object_ids"], 10000)
    if (scope["mode"] == "whole_case") != (not scope["artifact_ids"] and not scope["object_ids"]):
        _fail("unified_graph_scope_invalid")
    expected_limits = {"max_nodes": MAX_NODES, "max_edges": MAX_EDGES, "max_scan_rows_per_table": MAX_SCAN_ROWS, "max_bytes": MAX_BYTES}
    if not isinstance(value["limits"], dict) or value["limits"] != expected_limits or any(type(v) is not int for v in value["limits"].values()) or value["limitations"] != _LIMITATIONS:
        _fail("unified_graph_limits_invalid")
    counts = value["counts"]
    if not isinstance(counts, dict) or set(counts) != {"nodes", "edges", "gaps"}:
        _fail("unified_graph_count_mismatch")
    for key, maximum in (("nodes", MAX_NODES), ("edges", MAX_EDGES), ("gaps", MAX_NODES)):
        tm.integer(counts[key], 0, maximum)
    gaps = value["gaps"]
    if not isinstance(gaps, list) or len(gaps) != counts["gaps"]:
        _fail("unified_graph_count_mismatch")
    import re
    last = None
    for gap in gaps:
        if not isinstance(gap, dict) or set(gap) != {"node_id", "code"}:
            _fail("unified_graph_gap_invalid")
        tm.identifier(gap["node_id"])
        if not isinstance(gap["code"], str) or not re.fullmatch(r"[a-z_]{1,128}", gap["code"]):
            _fail("unified_graph_gap_invalid")
        key = (gap["node_id"], gap["code"])
        if last is not None and key <= last:
            _fail("unified_graph_gap_invalid")
        last = key
    if value["completeness"] != ("incomplete" if gaps else "complete_explicit_schema_references"):
        _fail("unified_graph_completeness_invalid")
    storage = value["storage"]
    if not isinstance(storage, dict) or set(storage) != {"mode", "node_chunks", "edge_chunks"} or storage["mode"] != "immutable_chunks":
        _fail("unified_graph_storage_invalid")
    for table, maximum in (("nodes", MAX_NODES), ("edges", MAX_EDGES)):
        ids = _refs(storage[table[:-1] + "_chunks"], (maximum + CHUNK_ROWS - 1) // CHUNK_ROWS)
        if len(ids) != (counts[table] + CHUNK_ROWS - 1) // CHUNK_ROWS:
            _fail("unified_graph_chunk_count_invalid")
    return value


def validate_graph(data):
    """Caput validatur; partes per validate_snapshot_graphs probantur."""
    return _manifest_fields(data)


def validate_stored(kind, data):
    if kind == "unified_graph":
        return validate_graph(data)
    if kind == "unified_graph_chunk":
        if (not isinstance(data, dict) or set(data) != {"schema", "table", "rows"}
                or data["schema"] != "probentium.unified-graph-chunk.v1" or data["table"] not in {"nodes", "edges"}
                or not isinstance(data["rows"], list) or not 1 <= len(data["rows"]) <= CHUNK_ROWS):
            _fail("unified_graph_chunk_invalid")
        import re
        for row in data["rows"]:
            fields = {"id", "kind", "ref", "content_digest"} if data["table"] == "nodes" else {"dependency", "dependent", "type"}
            if not isinstance(row, dict) or set(row) != fields:
                _fail("unified_graph_chunk_invalid")
            for field in fields - {"kind", "type"}:
                tm.identifier(row[field])
            label = row.get("kind", row.get("type"))
            if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", label):
                _fail("unified_graph_chunk_invalid")
            if data["table"] == "nodes" and row["id"] != _node_id(row["kind"], row["ref"]):
                _fail("unified_graph_node_invalid")
        return data
    if kind != "graph_impact":
        _fail("unified_graph_kind_unsupported", 7)
    fields = {"schema", "graph_id", "snapshot_revision", "current_revision", "original_structure_digest", "current_structure_digest",
              "graph_currentness", "changed_ids", "affected", "paths", "path_details_complete", "predecessors", "node_changes", "edge_changes",
              "completeness", "required_action", "limitations"}
    if not isinstance(data, dict) or set(data) != fields or data["schema"] != "probentium.graph-impact.v1":
        _fail("unified_graph_impact_invalid")
    for key in ("graph_id", "original_structure_digest", "current_structure_digest"):
        tm.identifier(data[key])
    tm.integer(data["snapshot_revision"], 0, 9007199254740991)
    tm.integer(data["current_revision"], data["snapshot_revision"], 9007199254740991)
    _refs(data["changed_ids"], 10000)
    _refs(data["affected"], MAX_NODES)
    if (data["graph_currentness"] != ("current" if data["original_structure_digest"] == data["current_structure_digest"] else "changed")
            or data["completeness"] not in {"incomplete", "complete_explicit_schema_references"}
            or data["required_action"] != ("review_affected_dependencies" if data["affected"] else "none_from_explicit_graph")
            or data["limitations"] != _LIMITATIONS or type(data["path_details_complete"]) is not bool):
        _fail("unified_graph_impact_invalid")
    if not isinstance(data["node_changes"], dict) or set(data["node_changes"]) != {"added", "removed", "modified"}:
        _fail("unified_graph_impact_invalid")
    for values in data["node_changes"].values():
        _refs(values, MAX_NODES)
    if not isinstance(data["edge_changes"], dict) or set(data["edge_changes"]) != {"added", "removed"}:
        _fail("unified_graph_impact_invalid")
    for rows in data["edge_changes"].values():
        if not isinstance(rows, list) or len(rows) > MAX_EDGES:
            _fail("unified_graph_impact_invalid")
        for offset in range(0, len(rows), CHUNK_ROWS):
            validate_stored("unified_graph_chunk", {"schema": "probentium.unified-graph-chunk.v1", "table": "edges", "rows": rows[offset:offset + CHUNK_ROWS]})
    predecessors, paths = data["predecessors"], data["paths"]
    if not isinstance(predecessors, dict) or len(predecessors) > MAX_NODES or not isinstance(paths, dict) or len(paths) > 256:
        _fail("unified_graph_impact_invalid")
    for identity, parent in predecessors.items():
        tm.identifier(identity)
        if parent is not None:
            tm.identifier(parent)
            if parent not in predecessors:
                _fail("unified_graph_impact_invalid")
    complete = set()
    for identity in predecessors:
        seen, current = set(), identity
        while current is not None and current not in complete:
            if current in seen:
                _fail("unified_graph_impact_cycle")
            seen.add(current)
            current = predecessors[current]
        complete.update(seen)
    if not set(data["affected"]) <= predecessors.keys() or not paths.keys() <= set(data["affected"]):
        _fail("unified_graph_impact_invalid")
    for identity, path in paths.items():
        _refs(path, 256)
        if not path or path[-1] != identity or any(predecessors[right] != left for left, right in zip(path, path[1:])):
            _fail("unified_graph_impact_invalid")
    if data["path_details_complete"] and (paths.keys() != set(data["affected"]) or any(predecessors[path[0]] is not None for path in paths.values())):
        _fail("unified_graph_impact_invalid")
    return data


def validate_snapshot_graphs(snapshot):
    """Partes absentes vel mutatae etiam in fasciculo externo recusantur."""
    objects = {}
    for obj in snapshot["objects"]:
        if obj["kind"] in _RECEIPTS:
            validate_stored(obj["kind"], obj["data"])
            objects[obj["id"]] = ({"id": obj["id"], "kind": obj["kind"], "revision": obj["revision"]}
                                  if obj["kind"] == "unified_graph_chunk" and callable(getattr(snapshot, "lookup", None)) else obj)
            if len(objects) > 10000:
                _fail("unified_graph_object_limit", 6)
    for obj in objects.values():
        if obj["kind"] != "unified_graph":
            continue
        value = dict(obj["data"])
        storage = value.pop("storage")
        for table in ("nodes", "edges"):
            rows = []
            refs = storage[table[:-1] + "_chunks"]
            for index, ref in enumerate(refs):
                chunk = objects.get(ref)
                if chunk is not None and "data" not in chunk:
                    chunk = snapshot.lookup("objects", ref)
                    if chunk is not None:
                        validate_stored(chunk["kind"], chunk["data"])
                if (chunk is None or chunk["kind"] != "unified_graph_chunk" or chunk["data"]["table"] != table
                        or chunk["revision"] > obj["revision"]
                        or index < len(refs) - 1 and len(chunk["data"]["rows"]) != CHUNK_ROWS):
                    _fail("unified_graph_chunk_missing_or_mismatched")
                rows.extend(chunk["data"]["rows"])
            value[table] = rows
        if value["snapshot_revision"] >= obj["revision"]:
            _fail("unified_graph_revision_invalid")
        _validate_graph(value)
    for obj in objects.values():
        if obj["kind"] == "graph_impact":
            graph = objects.get(obj["data"]["graph_id"])
            if (graph is None or graph["kind"] != "unified_graph"
                    or graph["data"]["structure_digest"] != obj["data"]["original_structure_digest"]
                    or graph["data"]["snapshot_revision"] != obj["data"]["snapshot_revision"]):
                _fail("unified_graph_impact_binding_invalid")
    return {"schema": "probentium.graph-validation.v1", "status": "consistent", "graphs": sum(obj["kind"] == "unified_graph" for obj in objects.values()),
            "basis": "stored_graph_structure_only_not_semantic_replay"}
