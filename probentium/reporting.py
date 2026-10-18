"""Relatio parata non est relatio missa."""
from copy import deepcopy

from .contracts import ProbentiumError, canonical_bytes, object_digest, timestamp
from .regulatory import (_dict, _text, _refs, _integer, _anchor, profiles, prepare_filing,
                         compare_filings, _verified_snapshot, evaluate_deadlines, _field, _value, _boolean)
from .governance import reference, check_refs, get_record, _hex, _enum, _strings
from .legalpacks import validate_pack, pack_status

SCHEMA = "probentium.eu.v1"
_TRACK_KEYS = {"id", "title", "profile", "incident_id", "service_refs", "recipient", "role", "qualification",
               "pack_ref", "template_id", "awareness_refs", "supersedes", "actor", "recorded_at", "rationale"}
_TRACK_OPTIONAL = {"ongoing", "trust_service"}
_AUDIT = {"actor", "at", "rationale", "document_refs"}


def validate_stored(kind, data):
    if kind == "eu.deadline_evaluation":
        from .deadline_records import validate_stored as validate_deadline
        return validate_deadline(data)
    if kind == "eu.reporting_track":
        fields = {"schema", "kind"} | _TRACK_KEYS
    elif kind == "eu.filing_snapshot":
        fields = {"schema", "kind", "track_ref", "pack_ref", "template_id", "template_version", "snapshot",
                  "dependency_refs", "case_revision", "cutoff", "unknown_tasks", "pack_state"}
    elif kind == "eu.filing_approval":
        fields = {"schema", "kind", "filing_ref", "snapshot_digest", "role", "decision", "field_ids"} | _AUDIT
    elif kind == "eu.submission_record":
        fields = {"schema", "kind", "filing_ref", "snapshot_digest", "sent_at", "channel", "recipient", "external_id", "approval_ref", "evidence_strength"} | _AUDIT
    elif kind == "eu.receipt":
        fields = {"schema", "kind", "submission_ref", "filing_ref", "strength", "external_submission_id", "content_digest", "binding_attestation", "binding_verified"} | _AUDIT
    elif kind == "eu.correction_impact":
        fields = {"schema", "kind", "before_ref", "after_ref", "changed_refs", "changes", "causal_paths", "required_decisions", "old_submission_refs", "history_rewritten"}
    else:
        raise ProbentiumError("unsupported_reporting_kind")
    _dict(data, fields | (_TRACK_OPTIONAL if kind == "eu.reporting_track" else set()), fields)
    if data["schema"] != SCHEMA or data["kind"] != kind[3:]:
        raise ProbentiumError("reporting_schema_mismatch")
    for key in ("filing_ref", "track_ref", "pack_ref", "submission_ref", "before_ref", "after_ref", "snapshot_digest"):
        if key in data:
            _hex(data[key])
    if _AUDIT <= fields:
        _text(data["actor"])
        timestamp(data["at"])
        _text(data["rationale"], 4096)
        for ref in _refs(data["document_refs"]):
            _hex(ref)
        if not data["document_refs"]:
            raise ProbentiumError("reporting_document_required")
    if kind == "eu.reporting_track":
        for key in ("id", "title", "incident_id", "recipient", "role", "template_id", "actor"):
            _text(data[key])
        _text(data["rationale"], 4096)
        timestamp(data["recorded_at"])
        if not isinstance(data["profile"], str) or data["profile"] not in profiles():
            raise ProbentiumError("unsupported_reporting_profile")
        for key in _TRACK_OPTIONAL & data.keys():
            _boolean(data[key])
        if data["supersedes"] is not None:
            _hex(data["supersedes"])
        if not _refs(data["service_refs"]):
            raise ProbentiumError("reporting_service_required")
        for ref in data["service_refs"]:
            _hex(ref)
        _dict(data["qualification"], {"status", "basis_refs", "reason", "reviewer"}, {"status", "basis_refs", "reason", "reviewer"})
        _enum(data["qualification"]["status"], {"qualified", "not_qualified", "unknown"})
        for ref in _refs(data["qualification"]["basis_refs"]):
            _hex(ref)
        _text(data["qualification"]["reason"], 4096)
        _text(data["qualification"]["reviewer"])
        if data["qualification"]["status"] != "unknown" and not data["qualification"]["basis_refs"]:
            raise ProbentiumError("qualification_basis_required")
        _dict(data["awareness_refs"], {"occurrence", "detection", "awareness", "classification", "submitted", "intermediate", "latest_intermediate", "measure_available", "resolved"})
        for ref in data["awareness_refs"].values():
            _hex(ref)
    elif kind == "eu.filing_snapshot":
        _verified_snapshot(data["snapshot"])
        _integer(data["case_revision"])
        timestamp(data["cutoff"])
        _text(data["template_id"])
        _text(data["template_version"])
        for ref in _strings(data["dependency_refs"], 32000):
            _hex(ref)
        minimum_refs = {data["track_ref"], data["pack_ref"]}
        for field in data["snapshot"]["fields"]:
            minimum_refs.update(field["refs"])
        if not minimum_refs <= set(data["dependency_refs"]):
            raise ProbentiumError("filing_dependency_incomplete")
        if data["case_revision"] != data["snapshot"]["case_revision"] or data["cutoff"] != data["snapshot"]["cutoff"]:
            raise ProbentiumError("filing_cutoff_mismatch")
        if data["unknown_tasks"] != [{"field": f, "task": "supply_or_review_missing_fact"} for f in data["snapshot"]["unknown_fields"]]:
            raise ProbentiumError("filing_unknown_task_mismatch")
        _dict(data["pack_state"], {"state", "currentness", "review_origin", "legally_verified"}, {"state", "currentness", "review_origin", "legally_verified"})
        if data["pack_state"]["legally_verified"] is not False:
            raise ProbentiumError("filing_cannot_certify_law")
        _enum(data["pack_state"]["state"], {"active_operational", "draft_inactive"})
        _enum(data["pack_state"]["currentness"], {"review_attested_current", "currentness_unverified"})
        if data["pack_state"]["review_origin"] != "supplied_attestations_only":
            raise ProbentiumError("filing_review_origin_mismatch")
    elif kind == "eu.filing_approval":
        _enum(data["decision"], {"approved", "rejected", "needs_revision"})
        _text(data["role"])
        if not _strings(data["field_ids"], 500):
            raise ProbentiumError("approval_fields_required")
    elif kind == "eu.submission_record":
        timestamp(data["sent_at"])
        if timestamp(data["sent_at"]) > timestamp(data["at"]):
            raise ProbentiumError("submission_in_future_of_attestation")
        for key in ("channel", "recipient"):
            _text(data[key])
        if data["external_id"] is not None:
            _text(data["external_id"])
        if data["approval_ref"] is not None:
            _hex(data["approval_ref"])
        _enum(data["evidence_strength"], {"human_asserted", "document_linked"})
    elif kind == "eu.receipt":
        _enum(data["strength"], {"delivery_only", "submission_id", "content_digest"})
        if data["external_submission_id"] is not None:
            _text(data["external_submission_id"])
        if data["content_digest"] is not None:
            _hex(data["content_digest"])
        _text(data["binding_attestation"], 4096)
        if data["binding_verified"] is not False:
            raise ProbentiumError("receipt_binding_requires_external_verification")
        if data["strength"] == "delivery_only" and (data["content_digest"] is not None or data["external_submission_id"] is not None):
            raise ProbentiumError("delivery_receipt_cannot_bind_content")
        if data["strength"] == "submission_id" and (data["external_submission_id"] is None or data["content_digest"] is not None):
            raise ProbentiumError("receipt_submission_id_required")
        if data["strength"] == "content_digest" and data["content_digest"] is None:
            raise ProbentiumError("receipt_content_digest_required")
    else:
        for ref in _strings(data["changed_refs"], 32000):
            _hex(ref)
        if data["history_rewritten"] is not False:
            raise ProbentiumError("correction_cannot_rewrite_history")
        for ref in _strings(data["old_submission_refs"], 20000):
            _hex(ref)
        _strings(data["required_decisions"], 64)
        if not set(data["required_decisions"]) <= {"review_changed_premises", "assess_need_to_correct_external_submission"}:
            raise ProbentiumError("invalid_correction_decision")
        if not isinstance(data["changes"], list) or len(data["changes"]) > 500 or not isinstance(data["causal_paths"], list) or len(data["causal_paths"]) > 32000:
            raise ProbentiumError("correction_size_limit", 6)
        for row in data["changes"]:
            _dict(row, {"field", "before", "after", "reason"}, {"field", "before", "after", "reason"})
            _text(row["field"])
            _enum(row["reason"], {"field_added", "field_removed", "value_changed", "evidence_basis_changed"})
            for key in ("before", "after"):
                if row[key] is not None:
                    normalized = _field({k: v for k, v in row[key].items() if not (k in {"reason", "calculation"} and v is None)}) if isinstance(row[key], dict) else _field(row[key])
                    if normalized["id"] != row["field"] or canonical_bytes(normalized) != canonical_bytes(row[key]):
                        raise ProbentiumError("correction_field_integrity", 4)
                    for ref in normalized["refs"]:
                        _hex(ref)
            first, second = row["before"], row["after"]
            if canonical_bytes(first) == canonical_bytes(second):
                raise ProbentiumError("correction_has_no_change")
            expected = "field_added" if first is None else "field_removed" if second is None else "value_changed" if canonical_bytes(first["value"]) != canonical_bytes(second["value"]) else "evidence_basis_changed"
            if row["reason"] != expected:
                raise ProbentiumError("correction_reason_mismatch")
        for path in data["causal_paths"]:
            _dict(path, {"changed_ref", "field", "via_refs"}, {"changed_ref", "field", "via_refs"})
            _hex(path["changed_ref"])
            _text(path["field"])
            for ref in _strings(path["via_refs"], 32000):
                _hex(ref)
            if not path["via_refs"] or path["via_refs"][0] != path["changed_ref"] or path["changed_ref"] not in data["changed_refs"]:
                raise ProbentiumError("correction_path_mismatch")
    return deepcopy(data)


def _read(case, ref, kind):
    row = reference(case, ref, {kind})
    validate_stored(kind, row["data"])
    return row


def create_track(case, data, expected_revision=None):
    payload = {"schema": SCHEMA, "kind": "reporting_track", **data}
    _dict(data, _TRACK_KEYS | _TRACK_OPTIONAL, _TRACK_KEYS)
    validate_stored("eu.reporting_track", payload)
    pack = reference(case, data["pack_ref"], {"eu.legal_pack"})["data"]
    validate_pack(pack)
    if pack["regime"] in profiles() and pack["regime"] != data["profile"]:
        raise ProbentiumError("reporting_profile_pack_mismatch")
    if data["role"] not in pack["roles"]:
        raise ProbentiumError("reporting_role_pack_mismatch")
    template = next((t for t in pack["templates"] if t["id"] == data["template_id"]), None)
    if template is None:
        raise ProbentiumError("reporting_template_missing")
    if data["recipient"] != template["recipient"]:
        raise ProbentiumError("reporting_template_recipient_mismatch")
    for ref in data["service_refs"]:
        reference(case, ref, {"eu.service"})
    check_refs(case, data["qualification"]["basis_refs"])
    prior = [row for row in case.objects("eu.reporting_track") if row["data"]["id"] == data["id"]]
    if (prior and data["supersedes"] != prior[-1]["id"]) or (not prior and data["supersedes"] is not None):
        raise ProbentiumError("reporting_track_revision_conflict", 5)
    if prior and timestamp(data["recorded_at"]) < timestamp(prior[-1]["data"]["recorded_at"]):
        raise ProbentiumError("reporting_track_time_reversed")
    if not prior and len({r["data"]["id"] for r in case.objects("eu.reporting_track")}) >= 4000:
        raise ProbentiumError("reporting_track_limit", 6)
    if not prior and len({r["data"]["incident_id"] for r in case.objects("eu.reporting_track")}) >= 1000:
        raise ProbentiumError("incident_limit", 6)
    for name, ref in data["awareness_refs"].items():
        awareness = get_record(case, ref)["data"]
        if awareness["kind"] != "awareness":
            raise ProbentiumError("awareness_track_mismatch")
        origin_track = reference(case, awareness["track_ref"], {"eu.reporting_track", "track"})["data"]
        if awareness["kind"] != "awareness" or awareness["event_type"] != name or origin_track["id"] != data["id"]:
            raise ProbentiumError("awareness_track_mismatch")
        if timestamp(awareness["recorded_at"]) > timestamp(data["recorded_at"]):
            raise ProbentiumError("awareness_recorded_after_track")
    return case.put_object("eu.reporting_track", payload, expected_revision=expected_revision)


def planning_track(case, track_id):
    track = _read(case, track_id, "eu.reporting_track")["data"]
    anchors = {}
    for name, ref in track["awareness_refs"].items():
        if name in {"occurrence", "detection"}:
            continue
        value = get_record(case, ref)["data"]
        anchors[name] = value["anchor"] if value["review_decision"] != "contested" else None
    return {"id": track["id"], "title": track["title"], "profile": track["profile"], "anchors": anchors,
            **{key: track[key] for key in _TRACK_OPTIONAL & track.keys()}}


def deadlines(case, track_id, as_of):
    tr = _read(case, track_id, "eu.reporting_track")["data"]
    pack = validate_pack(reference(case, tr["pack_ref"], {"eu.legal_pack"})["data"])
    result = evaluate_deadlines(planning_track(case, track_id), as_of)
    result.update({"track_ref": track_id, "pack_ref": tr["pack_ref"],
                   "anchor_refs": deepcopy(tr["awareness_refs"]), "pack_state": pack_status(case, tr["pack_ref"], as_of),
                   "qualification": deepcopy(tr["qualification"]),
                   "anchor_review": {name: get_record(case, ref)["data"]["review_decision"] for name, ref in tr["awareness_refs"].items()},
                   "calendar_refs": [{"id": row["id"], "version": row["version"], "status": row["status"]} for row in pack["calendars"]],
                   "obligation_determined": False})
    return result


def evaluate_deadline(case, track_id, **kwargs):
    from .deadline_records import evaluate_deadline as execute
    return execute(case, track_id, **kwargs)


def deadline_status(case, evaluation_id, as_of):
    from .deadline_records import deadline_status as execute
    return execute(case, evaluation_id, as_of)


def replay_deadline(case, evaluation_id):
    from .deadline_records import replay_deadline as execute
    return execute(case, evaluation_id)


def prepare(case, track_id, fields, cutoff, expected_revision=None):
    tr = _read(case, track_id, "eu.reporting_track")["data"]
    if timestamp(cutoff) < timestamp(tr["recorded_at"]):
        raise ProbentiumError("filing_cutoff_precedes_track")
    pack = reference(case, tr["pack_ref"], {"eu.legal_pack"})["data"]
    validate_pack(pack)
    template = next((t for t in pack["templates"] if t["id"] == tr["template_id"]), None)
    if template is None:
        raise ProbentiumError("filing_template_missing")
    if not isinstance(fields, list):
        raise ProbentiumError("invalid_filing_fields")
    known = {f["id"]: f for f in template["fields"]}
    provided = {f.get("id") for f in fields if isinstance(f, dict) and isinstance(f.get("id"), str)}
    if not provided <= known.keys():
        raise ProbentiumError("unknown_template_field")
    fields = deepcopy(fields)
    for fid, definition in known.items():
        if fid not in provided and definition["required"]:
            if not definition["allow_unknown"]:
                raise ProbentiumError("required_template_field_missing")
            fields.append({"id": fid, "basis": "unknown", "reason": "Required fact not yet supplied."})
    snapshot = prepare_filing(planning_track(case, track_id), fields, case.revision, cutoff)
    refs = {track_id, tr["pack_ref"], *tr["service_refs"], *tr["awareness_refs"].values()}
    for field in snapshot["fields"]:
        if field["basis"] == "unknown" and not known[field["id"]]["allow_unknown"]:
            raise ProbentiumError("template_unknown_not_allowed")
        check_refs(case, field["refs"])
        refs.update(field["refs"])
    if len(refs) > 32000:
        raise ProbentiumError("filing_dependency_limit", 6)
    state = pack_status(case, tr["pack_ref"], cutoff)
    data = {"schema": SCHEMA, "kind": "filing_snapshot", "track_ref": track_id, "pack_ref": tr["pack_ref"],
            "template_id": template["id"], "template_version": template["version"], "snapshot": snapshot,
            "dependency_refs": sorted(refs), "case_revision": case.revision, "cutoff": snapshot["cutoff"],
            "unknown_tasks": [{"field": f, "task": "supply_or_review_missing_fact"} for f in snapshot["unknown_fields"]],
            "pack_state": {key: state[key] for key in ("state", "currentness", "review_origin", "legally_verified")}}
    validate_stored("eu.filing_snapshot", data)
    if len(case.objects("eu.filing_snapshot")) >= 20000:
        raise ProbentiumError("filing_revision_limit", 6)
    return case.put_object("eu.filing_snapshot", data, expected_revision=expected_revision)


def approve(case, filing_id, approval, expected_revision=None):
    filing = _read(case, filing_id, "eu.filing_snapshot")["data"]
    _dict(approval, _AUDIT | {"role", "decision", "field_ids"}, _AUDIT | {"role", "decision", "field_ids"})
    data = {"schema": SCHEMA, "kind": "filing_approval", "filing_ref": filing_id,
            "snapshot_digest": filing["snapshot"]["digest"], **approval}
    validate_stored("eu.filing_approval", data)
    check_refs(case, approval["document_refs"], nonempty=True)
    if not set(approval["field_ids"]) <= {f["id"] for f in filing["snapshot"]["fields"]}:
        raise ProbentiumError("approval_field_not_in_snapshot")
    if timestamp(approval["at"]) < timestamp(filing["cutoff"]):
        raise ProbentiumError("approval_precedes_snapshot")
    return case.put_object("eu.filing_approval", data, expected_revision=expected_revision)


def record_submission(case, filing_id, submission, expected_revision=None):
    filing = _read(case, filing_id, "eu.filing_snapshot")["data"]
    fields = _AUDIT | {"sent_at", "channel", "recipient", "external_id", "approval_ref", "evidence_strength"}
    _dict(submission, fields, fields)
    data = {"schema": SCHEMA, "kind": "submission_record", "filing_ref": filing_id,
            "snapshot_digest": filing["snapshot"]["digest"], **submission}
    validate_stored("eu.submission_record", data)
    check_refs(case, submission["document_refs"], nonempty=True)
    track = _read(case, filing["track_ref"], "eu.reporting_track")["data"]
    if submission["recipient"] != track["recipient"] or timestamp(submission["sent_at"]) < timestamp(filing["cutoff"]):
        raise ProbentiumError("submission_recipient_or_time_mismatch")
    if submission["approval_ref"] is not None:
        approval = _read(case, submission["approval_ref"], "eu.filing_approval")["data"]
        if approval["filing_ref"] != filing_id or approval["decision"] != "approved" or timestamp(approval["at"]) > timestamp(submission["sent_at"]):
            raise ProbentiumError("submission_approval_mismatch")
    return case.put_object("eu.submission_record", data, expected_revision=expected_revision)


def link_receipt(case, submission_id, receipt, expected_revision=None):
    submission = _read(case, submission_id, "eu.submission_record")["data"]
    fields = _AUDIT | {"strength", "external_submission_id", "content_digest", "binding_attestation"}
    _dict(receipt, fields, fields)
    data = {"schema": SCHEMA, "kind": "receipt", "submission_ref": submission_id,
            "filing_ref": submission["filing_ref"], "binding_verified": False, **receipt}
    validate_stored("eu.receipt", data)
    check_refs(case, receipt["document_refs"], nonempty=True)
    if receipt["content_digest"] is not None and receipt["content_digest"] != submission["snapshot_digest"]:
        raise ProbentiumError("receipt_content_digest_mismatch")
    if receipt["external_submission_id"] is not None and receipt["external_submission_id"] != submission["external_id"]:
        raise ProbentiumError("receipt_external_id_mismatch")
    if timestamp(receipt["at"]) < timestamp(submission["sent_at"]):
        raise ProbentiumError("receipt_precedes_submission")
    return case.put_object("eu.receipt", data, expected_revision=expected_revision)


def filing_status(case, filing_id):
    filing = _read(case, filing_id, "eu.filing_snapshot")["data"]
    approvals = [row for row in case.objects("eu.filing_approval") if row["data"]["filing_ref"] == filing_id]
    submissions = [row for row in case.objects("eu.submission_record") if row["data"]["filing_ref"] == filing_id]
    receipts = [row for row in case.objects("eu.receipt") if row["data"]["filing_ref"] == filing_id]
    for row in approvals + submissions + receipts:
        validate_stored(row["kind"], row["data"])
    return {"filing_ref": filing_id, "snapshot_digest": filing["snapshot"]["digest"],
            "state": "receipt_linked" if receipts else "submission_recorded" if submissions else "prepared",
            "approval_refs": [r["id"] for r in approvals], "submission_refs": [r["id"] for r in submissions],
            "receipt_refs": [r["id"] for r in receipts], "legal_acceptance": "not_determined",
            "content_binding": "attested_only" if any(r["data"]["strength"] == "content_digest" for r in receipts) else "not_established",
            "legally_verified": False}


def correction_impact(case, before_id, after_id, changed_refs=None, expected_revision=None):
    before = _read(case, before_id, "eu.filing_snapshot")["data"]
    after = _read(case, after_id, "eu.filing_snapshot")["data"]
    changed = check_refs(case, changed_refs or [])
    diff = compare_filings(before["snapshot"], after["snapshot"])
    paths = []
    from .governance import dependency_impact
    impact = dependency_impact(case, changed) if changed else {"affected": [], "paths": {}}
    for field in before["snapshot"]["fields"]:
        for ref in field["refs"]:
            if ref in changed:
                paths.append({"changed_ref": ref, "field": field["id"], "via_refs": [ref]})
            elif ref in impact["affected"]:
                path = impact["paths"][ref]
                paths.append({"changed_ref": path[0], "field": field["id"], "via_refs": path})
    data = {"schema": SCHEMA, "kind": "correction_impact", "before_ref": before_id, "after_ref": after_id,
            "changed_refs": changed, "changes": diff["changes"], "causal_paths": paths,
            "required_decisions": ["review_changed_premises", "assess_need_to_correct_external_submission"] if paths or diff["changes"] or diff["context_changes"] else [],
            "old_submission_refs": [r["id"] for r in case.objects("eu.submission_record") if r["data"]["filing_ref"] == before_id],
            "history_rewritten": False}
    validate_stored("eu.correction_impact", data)
    return case.put_object("eu.correction_impact", data, expected_revision=expected_revision)


def build_demonstration(case, *, acknowledged_synthetic=False, expected_revision=None):
    """Exercitatio ficta nihil mittit neque ius certificat."""
    from .governance import put_record
    from .legalpacks import import_pack
    if acknowledged_synthetic is not True:
        raise ProbentiumError("synthetic_acknowledgement_required")
    if expected_revision is not None and expected_revision != case.revision:
        raise ProbentiumError("revision_conflict", 5)
    if any(row["data"]["id"] == "synthetic-incident-procedure" for row in case.objects("eu.legal_pack")):
        raise ProbentiumError("regulatory_demonstration_exists", 5)
    sources = case.sources()
    if not sources or len(sources) > 64:
        raise ProbentiumError("synthetic_sources_required")
    source = sources[0]["id"]
    source_refs = [row["id"] for row in sources]
    start, prepared_at, corrected_at = "2026-10-18T10:00:00Z", "2026-10-18T11:00:00Z", "2026-10-18T12:00:00Z"
    pack = import_pack(case, {"schema": SCHEMA, "kind": "legal_pack", "id": "synthetic-incident-procedure", "version": "1",
        "jurisdiction": "synthetic", "regime": "synthetic-exercise", "roles": ["exercise_operator"], "author": "Synthetic exercise author",
        "status": "draft", "effective_from": "2026-10-18", "applicable_from": "2026-10-18", "source_checked_at": start,
        "sources": [{"id": "synthetic-input", "title": "Synthetic acquired evidence; no legal authority",
                     "url": "https://example.invalid/synthetic-exercise", "sha256": source, "document_ref": source, "origin": "internal"}],
        "rules": [{"id": "exercise-review", "source_id": "synthetic-input", "provision": "Fictional exercise instruction",
                   "title": "Review synthetic incident evidence", "origin": "internal", "condition": "Exercise only; no real reporting obligation.",
                   "evidence": ["acquired synthetic records"], "operator": "manual_review", "parameters": {}},
                  {"id": "exercise-followup", "version": "1", "stage": "exercise_only", "source_id": "synthetic-input",
                   "provision": "Fictional follow-up instruction", "title": "Synthetic 24-hour follow-up", "origin": "internal",
                   "condition": "Exercise only; not a legal deadline.", "evidence": ["supplied synthetic awareness"],
                   "operator": "hours_after", "parameters": {"anchor": "awareness", "amount": 24}, "without_undue_delay": False}],
        "calendars": [{"schema": "probentium.calendar-policy.v1", "id": "exercise-utc", "version": "1", "timezone": "UTC",
            "timezone_data": None, "source_ids": ["synthetic-input"], "hour_rule": "elapsed_hours", "day_rule": "elapsed_days",
            "month_rule": "same_local_time_clamp", "nonworking_rule": "none", "weekend_days": [5, 6], "holidays": [],
            "holiday_coverage": {"start": "2026-01-01", "end": "2026-12-31"}, "status": "unverified"}],
        "templates": [{"id": "exercise", "version": "1", "recipient": "Synthetic exercise desk", "stage": "exercise_only",
            "source_ids": ["synthetic-input"], "fields": [{"id": "scope", "required": True, "allow_unknown": True},
            {"id": "event_count", "required": True, "allow_unknown": True}, {"id": "affected_people", "required": True, "allow_unknown": True}]}],
        "limitations": ["Fictional operational procedure and supplied synthetic assertions; not a Czech legal pack.",
                        "No external reviewer, real submission or legal certification."]})

    def common(logical_id):
        return {"logical_id": logical_id, "actor": "Synthetic exercise operator", "recorded_at": start,
                "basis_refs": [source], "rationale": "Synthetic scenario assertion; no independent verification.", "supersedes": None}

    service = put_record(case, "service", {**common("exercise-service"), "name": "Synthetic monitored service", "entity": "Fictional organization",
        "jurisdiction": "synthetic", "owner": "Synthetic owner", "criticality": "unknown", "unknown_dependencies": True})
    applicability = put_record(case, "applicability", {**common("exercise-applicability"), "entity": "Fictional organization",
        "service_refs": [service["id"]], "jurisdiction": "synthetic", "role": "exercise_operator", "regime": "synthetic-exercise",
        "facts": {"size": None, "group_relationships": None, "regulated_service": None, "registration_delivered": None,
                  "previously_regulated": None, "digital_service": None, "trust_service": None}, "exceptions": [],
        "pack_ref": pack["id"], "disposition": "unresolved", "reviewer": "Synthetic exercise operator", "reviewed_at": None})
    track_data = {"id": "exercise-track", "title": "Synthetic incident exercise", "profile": "cz-nis2-higher", "incident_id": "exercise-incident",
        "service_refs": [service["id"]], "recipient": "Synthetic exercise desk", "role": "exercise_operator",
        "qualification": {"status": "unknown", "basis_refs": [], "reason": "Fictional facts do not establish legal reportability.", "reviewer": "Synthetic operator"},
        "pack_ref": pack["id"], "template_id": "exercise", "awareness_refs": {}, "supersedes": None,
        "actor": "Synthetic exercise operator", "recorded_at": start, "rationale": "Operational timer illustration only."}
    initial_track = create_track(case, track_data)
    awareness = put_record(case, "awareness", {**common("exercise-awareness"), "track_ref": initial_track["id"], "event_type": "awareness",
        "anchor": {"status": "known", "at": start}, "actor_role": "exercise_operator", "review_decision": "unreviewed"})
    track_data.update(supersedes=initial_track["id"], awareness_refs={"awareness": awareness["id"]})
    track = create_track(case, track_data)
    first = prepare(case, track["id"], [{"id": "scope", "value": "Synthetic acquired dataset; completeness unknown.", "basis": "human_attested",
                     "refs": [source], "reason": "Synthetic operator's scope statement; no claim about an actual organization."}], prepared_at)
    count = case.query_events()["total"]
    second = prepare(case, track["id"], [{"id": "scope", "value": "Synthetic acquired dataset; completeness unknown.", "basis": "human_attested",
                       "refs": [source], "reason": "Synthetic operator's scope statement; no claim about an actual organization."},
                     {"id": "event_count", "value": count, "basis": "derived", "refs": source_refs,
                      "reason": "Count of currently selected parsed events in this acquired dataset; not affected people or the full incident.",
                      "calculation": {"id": "selected-event-count", "version": "1", "input_refs": source_refs}}], corrected_at)
    correction = correction_impact(case, first["id"], second["id"])
    deadline = evaluate_deadline(case, track["id"], rule_id="exercise-followup", calendar_id="exercise-utc", as_of=corrected_at)
    return {"synthetic": True, "pack_ref": pack["id"], "service_ref": service["id"], "applicability_ref": applicability["id"],
            "track_ref": track["id"], "awareness_ref": awareness["id"], "filing_refs": [first["id"], second["id"]],
            "correction_ref": correction["id"], "deadline_evaluation_ref": deadline["id"], "submission_status": "not_submitted", "legally_verified": False}
