"""Catalogus declaratus lacunas ostendit; plenitudinem iuris non fingit."""
from copy import deepcopy

from .contracts import ProbentiumError, canonical_bytes, object_digest, timestamp
from .regulatory import _dict, _text, _refs, _integer
from .governance import _hex, _enum, _strings, reference, check_refs, OBLIGATION_ANCHORS

CATALOGUE_KEYS = {"schema", "kind", "id", "version", "jurisdiction", "regime", "author", "recorded_at", "document_refs",
                  "completeness_claim", "review_status", "sources", "requirements"}
AUDIT_KEYS = {"schema", "kind", "pack_ref", "catalogue_ref", "case_revision", "as_of", "pack_digest", "catalogue_digest",
              "pack_state", "pack_state_refs", "dependency_refs", "result", "result_digest"}
ISSUES = {"jurisdiction_mismatch", "regime_mismatch", "source_identity_mismatch", "missing_source", "source_not_enacted",
          "missing_clause_or_branch", "provision_mismatch", "condition_mismatch", "evidence_expectation_missing",
          "trigger_mapping_missing", "conflicting_effective_from", "conflicting_applicable_from", "date_expectation_unknown",
          "rule_origin_mismatch"}


def validate_catalogue(data):
    from .legalpacks import _date, _ORIGINS
    _dict(data, CATALOGUE_KEYS, CATALOGUE_KEYS)
    if data["schema"] != "probentium.eu.v1" or data["kind"] != "requirement_catalogue" or data["review_status"] != "unverified":
        raise ProbentiumError("catalogue_cannot_self_certify")
    for key in ("id", "version", "jurisdiction", "regime", "author"):
        _text(data[key])
    timestamp(data["recorded_at"])
    for ref in _refs(data["document_refs"]):
        _hex(ref)
    if not data["document_refs"]:
        raise ProbentiumError("catalogue_basis_required")
    _enum(data["completeness_claim"], {"partial", "declared_complete"})
    if not isinstance(data["sources"], list) or not 1 <= len(data["sources"]) <= 64:
        raise ProbentiumError("catalogue_source_limit", 6)
    sources = set()
    for source in data["sources"]:
        keys = {"id", "url", "sha256", "document_ref", "origin"}
        _dict(source, keys, keys); _text(source["id"]); _text(source["url"], 2048); _hex(source["sha256"])
        if not source["url"].startswith("https://"):
            raise ProbentiumError("legal_source_https_required")
        _enum(source["origin"], _ORIGINS)
        if source["document_ref"] is not None:
            _hex(source["document_ref"])
        if source["id"] in sources:
            raise ProbentiumError("duplicate_catalogue_source")
        sources.add(source["id"])
    requirements = data["requirements"]
    if not isinstance(requirements, list) or not 1 <= len(requirements) <= 5000:
        raise ProbentiumError("catalogue_requirement_limit", 6)
    identities, total = set(), 0
    for requirement in requirements:
        keys = {"id", "source_id", "provision", "effective_from", "applicable_from", "branches"}
        _dict(requirement, keys, keys)
        for key in ("id", "source_id", "provision"):
            _text(requirement[key], 4096)
        if requirement["id"] in identities or requirement["source_id"] not in sources:
            raise ProbentiumError("invalid_catalogue_requirement_reference")
        identities.add(requirement["id"])
        for key in ("effective_from", "applicable_from"):
            if requirement[key] is not None:
                _date(requirement[key])
        branches = requirement["branches"]
        if not isinstance(branches, list) or not branches:
            raise ProbentiumError("catalogue_branches_required")
        total += len(branches)
        if total > 5000:
            raise ProbentiumError("catalogue_branch_limit", 6)
        seen = set()
        for branch in branches:
            keys = {"id", "condition", "rule_ids", "evidence", "trigger_kind"}
            _dict(branch, keys, keys); _text(branch["id"]); _text(branch["condition"], 4096)
            if branch["id"] in seen:
                raise ProbentiumError("duplicate_catalogue_branch")
            seen.add(branch["id"])
            _strings(branch["rule_ids"], 64); _strings(branch["evidence"], 64)
            if branch["trigger_kind"] is not None:
                _enum(branch["trigger_kind"], OBLIGATION_ANCHORS)
    if len(canonical_bytes(data)) > 16 * 1024 * 1024:
        raise ProbentiumError("catalogue_bytes_limit", 6)
    return deepcopy(data)


def compute_coverage(pack, catalogue):
    from .legalpacks import validate_pack
    validate_pack(pack); validate_catalogue(catalogue)
    global_issues = []
    for key in ("jurisdiction", "regime"):
        if pack[key] != catalogue[key]:
            global_issues.append(key + "_mismatch")
    sources = {s["id"]: s for s in pack["sources"]}; expected_sources = {s["id"]: s for s in catalogue["sources"]}
    rules = {r["id"]: r for r in pack["rules"]}; rows = []
    for requirement in catalogue["requirements"]:
        source = sources.get(requirement["source_id"]); wanted = expected_sources[requirement["source_id"]]
        base = []
        if source is None:
            base.append("missing_source")
        elif any(source[k] != wanted[k] for k in ("url", "sha256", "origin")):
            base.append("source_identity_mismatch")
        if wanted["origin"] != "enacted":
            base.append("source_not_enacted")
        for branch in requirement["branches"]:
            issues = list(base); matched = []
            if not branch["rule_ids"]:
                issues.append("missing_clause_or_branch")
            for identifier in branch["rule_ids"]:
                rule = rules.get(identifier)
                if rule is None:
                    issues.append("missing_clause_or_branch"); continue
                matched.append(identifier)
                if rule["source_id"] != requirement["source_id"] or rule["provision"] != requirement["provision"]:
                    issues.append("provision_mismatch")
                if rule["condition"] != branch["condition"]:
                    issues.append("condition_mismatch")
                if rule["origin"] != wanted["origin"]:
                    issues.append("rule_origin_mismatch")
                if not set(branch["evidence"]) <= set(rule["evidence"]):
                    issues.append("evidence_expectation_missing")
                if branch["trigger_kind"] is not None and rule.get("trigger_kind") != branch["trigger_kind"]:
                    issues.append("trigger_mapping_missing")
                for key in ("effective_from", "applicable_from"):
                    if requirement[key] is None:
                        issues.append("date_expectation_unknown")
                    elif rule.get(key, pack[key]) != requirement[key]:
                        issues.append("conflicting_" + key)
            rows.append({"requirement_id": requirement["id"], "branch_id": branch["id"], "matched_rule_ids": sorted(matched), "issues": sorted(set(issues))})
    matched = sum(not row["issues"] for row in rows)
    return {"schema": "probentium.legal-coverage.v1", "status": "gaps" if global_issues or matched != len(rows) else "structural_match_only",
            "requirements": len(catalogue["requirements"]), "branches": len(rows), "matched_branches": matched,
            "global_issues": sorted(global_issues), "rows": rows, "catalogue_completeness": "supplied_claim_not_verified",
            "review_status": "unverified", "legally_verified": False, "evidence_reuse_implies_equivalence": False,
            "limitations": ["catalogue_may_omit_requirements", "exact_mapping_not_legal_interpretation", "evidence_expectation_not_effectiveness", "no_external_legal_review"]}


def _validate_result(result):
    keys = {"schema", "status", "requirements", "branches", "matched_branches", "global_issues", "rows", "catalogue_completeness", "review_status",
            "legally_verified", "evidence_reuse_implies_equivalence", "limitations"}
    _dict(result, keys, keys)
    if result["schema"] != "probentium.legal-coverage.v1" or result["catalogue_completeness"] != "supplied_claim_not_verified" or result["review_status"] != "unverified" or result["legally_verified"] is not False or result["evidence_reuse_implies_equivalence"] is not False:
        raise ProbentiumError("coverage_cannot_certify_law")
    for key in ("requirements", "branches", "matched_branches"):
        _integer(result[key])
        if result[key] > 5000:
            raise ProbentiumError("coverage_count_limit", 6)
    if not set(_strings(result["global_issues"], 64)) <= ISSUES:
        raise ProbentiumError("unsupported_coverage_issue")
    rows = result["rows"]
    if not isinstance(rows, list) or len(rows) != result["branches"]:
        raise ProbentiumError("coverage_rows_mismatch")
    seen = set()
    for row in rows:
        _dict(row, {"requirement_id", "branch_id", "matched_rule_ids", "issues"}, {"requirement_id", "branch_id", "matched_rule_ids", "issues"})
        _text(row["requirement_id"], 4096); _text(row["branch_id"])
        identity = (row["requirement_id"], row["branch_id"])
        if identity in seen:
            raise ProbentiumError("duplicate_coverage_branch")
        seen.add(identity); _strings(row["matched_rule_ids"], 64)
        if not set(_strings(row["issues"], 64)) <= ISSUES:
            raise ProbentiumError("unsupported_coverage_issue")
    matched = sum(not row["issues"] for row in rows)
    status = "gaps" if result["global_issues"] or matched != len(rows) else "structural_match_only"
    if result["matched_branches"] != matched or result["requirements"] != len({r["requirement_id"] for r in rows}) or result["status"] != status:
        raise ProbentiumError("coverage_summary_mismatch", 4)
    if result["limitations"] != ["catalogue_may_omit_requirements", "exact_mapping_not_legal_interpretation", "evidence_expectation_not_effectiveness", "no_external_legal_review"]:
        raise ProbentiumError("coverage_limitations_mismatch")


def validate_stored(kind, data):
    if kind == "eu.requirement_catalogue":
        return validate_catalogue(data)
    if kind != "eu.legal_coverage_audit":
        raise ProbentiumError("unsupported_coverage_object")
    _dict(data, AUDIT_KEYS, AUDIT_KEYS)
    if data["schema"] != "probentium.eu.v1" or data["kind"] != "legal_coverage_audit":
        raise ProbentiumError("invalid_coverage_schema")
    for key in ("pack_ref", "catalogue_ref", "pack_digest", "catalogue_digest", "result_digest"):
        _hex(data[key])
    _integer(data["case_revision"]); timestamp(data["as_of"]); _validate_result(data["result"])
    if data["result_digest"] != object_digest(data["result"], domain="PROBENTIUM-LEGAL-COVERAGE-V1"):
        raise ProbentiumError("coverage_result_digest_mismatch", 4)
    keys = {"state", "currentness", "review_origin", "legally_verified"}
    _dict(data["pack_state"], keys, keys)
    _enum(data["pack_state"]["state"], {"active_operational", "draft_inactive"})
    _enum(data["pack_state"]["currentness"], {"review_attested_current", "currentness_unverified"})
    if data["pack_state"]["legally_verified"] is not False or data["pack_state"]["review_origin"] != "supplied_attestations_only":
        raise ProbentiumError("coverage_cannot_certify_law")
    for ref in _strings(data["pack_state_refs"], 32000):
        _hex(ref)
    if data["dependency_refs"] != sorted({data["pack_ref"], data["catalogue_ref"], *data["pack_state_refs"]}):
        raise ProbentiumError("coverage_dependency_mismatch", 4)
    if len(canonical_bytes(data)) > 16 * 1024 * 1024:
        raise ProbentiumError("coverage_bytes_limit", 6)
    return deepcopy(data)


def import_catalogue(case, data, expected_revision=None):
    data = validate_catalogue(data)
    check_refs(case, data["document_refs"], nonempty=True)
    for source in data["sources"]:
        if source["document_ref"] is not None:
            found = reference(case, source["document_ref"])
            if found["kind"] != "artifact" or found["id"] != source["sha256"]:
                raise ProbentiumError("catalogue_source_digest_mismatch")
    rows = case.objects("eu.requirement_catalogue")
    if len(rows) >= 2000:
        raise ProbentiumError("catalogue_count_limit", 6)
    for row in rows:
        if row["data"]["id"] == data["id"] and row["data"]["version"] == data["version"] and canonical_bytes(row["data"]) != canonical_bytes(data):
            raise ProbentiumError("catalogue_version_content_conflict", 5)
    return case.put_object("eu.requirement_catalogue", data, expected_revision=expected_revision)


def audit_coverage(case, pack_id, catalogue_id, as_of, *, persist=True, expected_revision=None):
    from .deadline_records import _pack_context, _pack_state
    pack = reference(case, pack_id, {"eu.legal_pack"})["data"]
    catalogue = reference(case, catalogue_id, {"eu.requirement_catalogue"})["data"]
    if timestamp(as_of) < timestamp(catalogue["recorded_at"]):
        raise ProbentiumError("coverage_precedes_catalogue")
    result = compute_coverage(pack, catalogue); context = _pack_context(case, pack, as_of)
    data = {"schema": "probentium.eu.v1", "kind": "legal_coverage_audit", "pack_ref": pack_id, "catalogue_ref": catalogue_id,
            "case_revision": case.revision, "as_of": as_of, "pack_digest": object_digest(pack), "catalogue_digest": object_digest(catalogue),
            "pack_state": _pack_state(case, pack_id, as_of), "pack_state_refs": context,
            "dependency_refs": sorted({pack_id, catalogue_id, *context}), "result": result,
            "result_digest": object_digest(result, domain="PROBENTIUM-LEGAL-COVERAGE-V1")}
    validate_stored("eu.legal_coverage_audit", data)
    if not persist:
        return data
    if len(case.objects("eu.legal_coverage_audit")) >= 20000:
        raise ProbentiumError("coverage_audit_count_limit", 6)
    return case.put_object("eu.legal_coverage_audit", data, expected_revision=expected_revision)


def replay_coverage(case, audit_id):
    from .deadline_records import _pack_context, _pack_state
    integrity = case.verify()
    if not integrity["ok"]:
        raise ProbentiumError("coverage_case_integrity_failed", 4)
    stored = reference(case, audit_id, {"eu.legal_coverage_audit"}); data = validate_stored(stored["kind"], stored["data"])
    if data["case_revision"] >= stored["revision"]:
        raise ProbentiumError("coverage_snapshot_revision_invalid", 4)
    pack = reference(case, data["pack_ref"], {"eu.legal_pack"})["data"]
    catalogue = reference(case, data["catalogue_ref"], {"eu.requirement_catalogue"})["data"]
    if object_digest(pack) != data["pack_digest"] or object_digest(catalogue) != data["catalogue_digest"] or compute_coverage(pack, catalogue) != data["result"]:
        raise ProbentiumError("coverage_replay_mismatch", 4)
    if _pack_context(case, pack, data["as_of"], data["case_revision"]) != data["pack_state_refs"] or _pack_state(case, data["pack_ref"], data["as_of"], data["case_revision"]) != data["pack_state"]:
        raise ProbentiumError("coverage_pack_context_mismatch", 4)
    check_refs(case, data["dependency_refs"])
    if any(reference(case, ref).get("revision", 0) > data["case_revision"] for ref in data["dependency_refs"]):
        raise ProbentiumError("coverage_dependency_after_cutoff", 4)
    return {"audit_ref": audit_id, "status": "partial" if integrity["exit_code"] else "replayed", "exit_code": integrity["exit_code"],
            "computation_status": "replayed", "legally_verified": False, "history_rewritten": False}


def coverage_status(case, audit_id, as_of):
    from .deadline_records import _pack_state, _pack_context
    replay = replay_coverage(case, audit_id); data = reference(case, audit_id)["data"]
    if timestamp(as_of) < timestamp(data["as_of"]):
        raise ProbentiumError("currentness_precedes_evaluation")
    pack = reference(case, data["pack_ref"])["data"]; catalogue = reference(case, data["catalogue_ref"])["data"]; reasons = []
    if _pack_state(case, data["pack_ref"], as_of) != data["pack_state"] or _pack_context(case, pack, as_of) != data["pack_state_refs"]:
        reasons.append("pack_review_or_activation_changed")
    for kind, original, ref, time_key in (("eu.legal_pack", pack, data["pack_ref"], "source_checked_at"), ("eu.requirement_catalogue", catalogue, data["catalogue_ref"], "recorded_at")):
        old = reference(case, ref)
        if any(row["data"]["id"] == original["id"] and row["revision"] > old["revision"] and timestamp(row["data"][time_key]) <= timestamp(as_of) for row in case.objects(kind)):
            reasons.append("newer_" + kind[3:] + "_available")
    return {"audit_ref": audit_id, "state": "stale" if reasons else "current_for_recorded_inputs", "reasons": sorted(reasons),
            "checked_as_of": as_of, "legally_verified": False, "exit_code": replay["exit_code"], "history_rewritten": False}
