"""Termini cum versionibus servantur; historia non rescribitur."""
from copy import deepcopy

from .contracts import ProbentiumError, canonical_bytes, object_digest, timestamp
from .regulatory import _dict, _integer, _stamp
from .governance import reference, check_refs, _hex, _strings
from .deadlines import evaluate_rule, validate_calendar, VERSION

FIELDS = {"schema", "kind", "version", "track_ref", "pack_ref", "case_revision", "as_of", "inputs",
          "anchor_refs", "dependency_refs", "pack_state", "pack_state_refs", "filing_states", "result", "input_digest", "result_digest"}
PACK_STATE_FIELDS = ("state", "currentness", "review_origin", "legally_verified")


def _pack_state(case, pack_id, as_of, revision=None):
    from .legalpacks import pack_status
    state = pack_status(case, pack_id, as_of, revision=revision)
    return {key: state[key] for key in PACK_STATE_FIELDS}


def validate_stored(data):
    _dict(data, FIELDS, FIELDS)
    if data["schema"] != "probentium.eu.v1" or data["kind"] != "deadline_evaluation" or data["version"] != VERSION:
        raise ProbentiumError("unsupported_deadline_evaluation", 7)
    _hex(data["track_ref"]); _hex(data["pack_ref"]); _integer(data["case_revision"]); timestamp(data["as_of"])
    inputs = data["inputs"]
    _dict(inputs, {"track", "rule", "calendar", "exception"}, {"track", "rule", "calendar", "exception"})
    expected = evaluate_rule(inputs["track"], inputs["rule"], inputs["calendar"], data["as_of"], inputs["exception"])
    if canonical_bytes(expected) != canonical_bytes(data["result"]) or data["result_digest"] != object_digest(expected, domain="PROBENTIUM-DEADLINE-RESULT-V1"):
        raise ProbentiumError("deadline_result_binding_failed", 4)
    if data["input_digest"] != object_digest(inputs, domain="PROBENTIUM-DEADLINE-INPUT-V1"):
        raise ProbentiumError("deadline_input_binding_failed", 4)
    _dict(data["anchor_refs"], {"occurrence", "detection", "awareness", "classification", "submitted", "intermediate", "latest_intermediate", "measure_available", "resolved"})
    for ref in data["anchor_refs"].values():
        _hex(ref)
    required = {data["track_ref"], data["pack_ref"], *data["anchor_refs"].values()}
    for ref in _strings(data["pack_state_refs"], 32000):
        _hex(ref); required.add(ref)
    if inputs["exception"]:
        required.update(inputs["exception"]["basis_refs"])
    _dict(data["pack_state"], {"state", "currentness", "review_origin", "legally_verified"}, {"state", "currentness", "review_origin", "legally_verified"})
    if data["pack_state"]["legally_verified"] is not False or data["pack_state"]["review_origin"] != "supplied_attestations_only":
        raise ProbentiumError("deadline_cannot_certify_law")
    if data["pack_state"]["state"] not in ("active_operational", "draft_inactive") or data["pack_state"]["currentness"] not in ("review_attested_current", "currentness_unverified"):
        raise ProbentiumError("invalid_deadline_pack_state")
    if not isinstance(data["filing_states"], list) or len(data["filing_states"]) > 20000:
        raise ProbentiumError("deadline_filing_limit", 6)
    seen = set()
    for row in data["filing_states"]:
        keys = {"filing_ref", "state", "approval_refs", "submission_refs", "receipt_refs"}
        _dict(row, keys, keys); _hex(row["filing_ref"])
        if row["filing_ref"] in seen:
            raise ProbentiumError("duplicate_deadline_filing")
        seen.add(row["filing_ref"]); required.add(row["filing_ref"])
        for key in ("approval_refs", "submission_refs", "receipt_refs"):
            for ref in _strings(row[key], 20000):
                _hex(ref); required.add(ref)
        state = "receipt_linked" if row["receipt_refs"] else "submission_recorded" if row["submission_refs"] else "prepared"
        if row["state"] != state:
            raise ProbentiumError("deadline_filing_state_mismatch")
    if data["dependency_refs"] != sorted(required):
        raise ProbentiumError("deadline_dependency_mismatch", 4)
    if len(canonical_bytes(data)) > 16 * 1024 * 1024:
        raise ProbentiumError("deadline_evaluation_bytes_limit", 6)
    return deepcopy(data)


def _filings(case, logical_id, as_of, revision=None):
    from .reporting import validate_stored as validate_reporting
    now = timestamp(as_of); results = []
    by_filing = {}
    for key, kind in (("approval_refs", "eu.filing_approval"), ("submission_refs", "eu.submission_record"), ("receipt_refs", "eu.receipt")):
        for entry in case.objects(kind):
            if revision is not None and entry["revision"] > revision:
                continue
            payload = validate_reporting(kind, entry["data"])
            if timestamp(payload["at"]) <= now:
                by_filing.setdefault(payload["filing_ref"], {}).setdefault(key, []).append(entry["id"])
    for row in case.objects("eu.filing_snapshot"):
        data = validate_reporting(row["kind"], row["data"])
        if data["snapshot"]["track"]["id"] != logical_id or timestamp(data["cutoff"]) > now or (revision is not None and row["revision"] > revision):
            continue
        state = {"filing_ref": row["id"]}
        for key in ("approval_refs", "submission_refs", "receipt_refs"):
            state[key] = sorted(by_filing.get(row["id"], {}).get(key, []))
        state["state"] = "receipt_linked" if state["receipt_refs"] else "submission_recorded" if state["submission_refs"] else "prepared"
        results.append(state)
    return sorted(results, key=lambda r: r["filing_ref"])


def _pack_context(case, pack, as_of, revision=None):
    from .legalpacks import validate_stored as validate_legal
    refs = set()
    for row in case.objects("eu.legal_activation"):
        data = validate_legal(row["kind"], row["data"])
        linked = reference(case, data["pack_ref"], {"eu.legal_pack"})["data"]
        if linked["id"] == pack["id"] and timestamp(data["at"]) <= timestamp(as_of) and (revision is None or row["revision"] <= revision):
            refs.add(row["id"]); refs.update(data["review_refs"])
    return sorted(refs)


def evaluate_deadline(case, track_id, *, rule_id, calendar_id, as_of, exception=None, expected_revision=None, persist=True):
    from .reporting import _read, planning_track
    from .legalpacks import validate_pack, pack_status
    track = _read(case, track_id, "eu.reporting_track")["data"]
    now = timestamp(as_of)
    if now < timestamp(track["recorded_at"]):
        raise ProbentiumError("deadline_as_of_precedes_track")
    pack = validate_pack(reference(case, track["pack_ref"], {"eu.legal_pack"})["data"])
    rule = next((r for r in pack["rules"] if r["id"] == rule_id), None)
    calendar = next((r for r in pack["calendars"] if r["id"] == calendar_id), None)
    if rule is None or calendar is None:
        raise ProbentiumError("deadline_rule_or_calendar_missing")
    validate_calendar(calendar)
    inputs = {"track": planning_track(case, track_id), "rule": rule, "calendar": calendar, "exception": exception}
    result = evaluate_rule(inputs["track"], rule, calendar, as_of, exception)
    refs = {track_id, track["pack_ref"], *track["awareness_refs"].values()}
    context = _pack_context(case, pack, as_of)
    refs.update(context)
    if exception:
        refs.update(check_refs(case, exception["basis_refs"], nonempty=True))
    filings = _filings(case, track["id"], as_of)
    for row in filings:
        refs.add(row["filing_ref"])
        for key in ("approval_refs", "submission_refs", "receipt_refs"):
            refs.update(row[key])
    payload = {"schema": "probentium.eu.v1", "kind": "deadline_evaluation", "version": VERSION,
               "track_ref": track_id, "pack_ref": track["pack_ref"], "case_revision": case.revision,
               "as_of": _stamp(now), "inputs": deepcopy(inputs), "anchor_refs": deepcopy(track["awareness_refs"]),
               "dependency_refs": sorted(refs), "pack_state": _pack_state(case, track["pack_ref"], as_of), "pack_state_refs": context,
               "filing_states": filings, "result": result,
               "input_digest": object_digest(inputs, domain="PROBENTIUM-DEADLINE-INPUT-V1"),
               "result_digest": object_digest(result, domain="PROBENTIUM-DEADLINE-RESULT-V1")}
    validate_stored(payload)
    if not persist:
        return payload
    if len(case.objects("eu.deadline_evaluation")) >= 20000:
        raise ProbentiumError("deadline_evaluation_count_limit", 6)
    return case.put_object("eu.deadline_evaluation", payload, expected_revision=expected_revision)


def replay_deadline(case, evaluation_id):
    from .reporting import planning_track
    from .legalpacks import validate_pack
    integrity = case.verify()
    if not integrity["ok"]:
        raise ProbentiumError("deadline_case_integrity_failed", 4)
    stored = reference(case, evaluation_id, {"eu.deadline_evaluation"})
    data = validate_stored(stored["data"])
    if data["case_revision"] >= stored["revision"]:
        raise ProbentiumError("deadline_snapshot_revision_invalid", 4)
    check_refs(case, data["dependency_refs"])
    pack = validate_pack(reference(case, data["pack_ref"], {"eu.legal_pack"})["data"])
    inputs = data["inputs"]
    if inputs["rule"] not in pack["rules"] or inputs["calendar"] not in pack["calendars"] or canonical_bytes(inputs["track"]) != canonical_bytes(planning_track(case, data["track_ref"])):
        raise ProbentiumError("deadline_frozen_reference_mismatch", 4)
    track = reference(case, data["track_ref"], {"eu.reporting_track"})["data"]
    if track["pack_ref"] != data["pack_ref"] or track["awareness_refs"] != data["anchor_refs"]:
        raise ProbentiumError("deadline_anchor_binding_failed", 4)
    if data["filing_states"] != _filings(case, track["id"], data["as_of"], data["case_revision"]):
        raise ProbentiumError("deadline_filing_snapshot_mismatch", 4)
    if data["pack_state_refs"] != _pack_context(case, pack, data["as_of"], data["case_revision"]):
        raise ProbentiumError("deadline_pack_context_mismatch", 4)
    if data["pack_state"] != _pack_state(case, data["pack_ref"], data["as_of"], data["case_revision"]):
        raise ProbentiumError("deadline_pack_state_mismatch", 4)
    for ref in data["dependency_refs"]:
        row = reference(case, ref)
        if row.get("revision", 0) > data["case_revision"]:
            raise ProbentiumError("deadline_dependency_after_cutoff", 4)
    return {"evaluation_ref": evaluation_id, "status": "partial" if integrity["exit_code"] == 3 else "replayed",
            "computation_status": "replayed", "exit_code": integrity["exit_code"], "result_digest": data["result_digest"],
            "legal_deadline_verified": False, "history_rewritten": False,
            "case_integrity": {key: integrity[key] for key in ("ok", "completeness", "exit_code")},
            "limitations": ["computation_replayed_not_legal_validation", "source_content_does_not_authenticate_assertions"]}


def deadline_status(case, evaluation_id, as_of):
    from .legalpacks import pack_status
    replay = replay_deadline(case, evaluation_id)
    data = reference(case, evaluation_id, {"eu.deadline_evaluation"})["data"]
    now = timestamp(as_of)
    if now < timestamp(data["as_of"]):
        raise ProbentiumError("currentness_precedes_evaluation")
    reasons = []
    dependencies = set(data["dependency_refs"])
    for row in case.objects():
        if row["kind"] in {"eu.awareness", "eu.reporting_track"} and row["data"].get("supersedes") in dependencies and timestamp(row["data"]["recorded_at"]) <= now:
            reasons.append("anchor_or_track_revision_changed")
    pack = reference(case, data["pack_ref"], {"eu.legal_pack"})["data"]
    if _pack_state(case, data["pack_ref"], as_of) != data["pack_state"] or _pack_context(case, pack, as_of) != data["pack_state_refs"]:
        reasons.append("pack_review_or_activation_changed")
    if _filings(case, data["inputs"]["track"]["id"], as_of) != data["filing_states"]:
        reasons.append("filing_state_changed")
    return {"evaluation_ref": evaluation_id, "state": "stale" if reasons else "current_for_recorded_inputs",
            "reasons": sorted(set(reasons)), "evaluated_as_of": data["as_of"], "checked_as_of": _stamp(now),
            "operational_status_requires_new_evaluation": now != timestamp(data["as_of"]),
            "case_integrity": replay["case_integrity"], "exit_code": replay["exit_code"],
            "legally_verified": False, "legal_countdown_enabled": False, "history_rewritten": False}
