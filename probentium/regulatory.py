"""Evidentia ante conclusionem; ius nondum verificatum."""

from calendar import monthrange
from copy import deepcopy
from datetime import timedelta

from .contracts import ProbentiumError, canonical_bytes, object_digest, safe_text, timestamp


_PROFILE_NAMES = {
    "cz-nis2-higher": "Czech NIS2 higher-obligation incident planning",
    "cz-nis2-lower": "Czech NIS2 lower-obligation incident planning",
    "cz-nis2-digital": "Czech specified digital-service incident planning",
    "gdpr-controller": "GDPR controller breach notification planning",
    "gdpr-processor": "GDPR processor notification to controller",
    "gdpr-communication": "GDPR high-risk communication planning",
    "dora": "DORA major ICT incident planning",
    "cra-vulnerability": "CRA actively exploited vulnerability planning",
    "cra-incident": "CRA severe product security incident planning",
}
_ANCHORS = {"awareness", "classification", "submitted", "intermediate",
            "latest_intermediate", "measure_available", "resolved"}
_BASES = {"source_backed", "human_attested", "derived", "contested", "unknown"}
_MAX_INT = 9007199254740991


def _dict(value, allowed, required=()):
    if not isinstance(value, dict) or any(not isinstance(k, str) for k in value):
        raise ProbentiumError("invalid_regulatory_object")
    if set(value) - set(allowed) or set(required) - set(value):
        raise ProbentiumError("invalid_regulatory_fields")
    return value


def _text(value, limit=256):
    if not isinstance(value, str) or not value.strip() or len(value) > limit or safe_text(value) != value:
        raise ProbentiumError("invalid_regulatory_text")
    return value


def _integer(value, nullable=False):
    if value is None and nullable:
        return None
    if type(value) is not int or not 0 <= value <= _MAX_INT:
        raise ProbentiumError("invalid_regulatory_integer")
    return value


def _boolean(value):
    if value is not None and type(value) is not bool:
        raise ProbentiumError("invalid_regulatory_boolean")
    return value


def _refs(value):
    if not isinstance(value, list) or len(value) > 64:
        raise ProbentiumError("invalid_evidence_refs")
    refs = [_text(item) for item in value]
    if len(refs) != len(set(refs)):
        raise ProbentiumError("duplicate_evidence_ref")
    return sorted(refs)


def _value(value, depth=0):
    if depth > 8:
        raise ProbentiumError("regulatory_value_depth_limit", 6)
    if value is None or type(value) is bool:
        return value
    if type(value) is int and abs(value) <= _MAX_INT:
        return value
    if isinstance(value, str):
        if len(value.encode("utf-8")) > 65536 or safe_text(value) != value:
            raise ProbentiumError("invalid_field_value")
        return value
    if isinstance(value, list) and len(value) <= 500:
        return [_value(item, depth + 1) for item in value]
    if isinstance(value, dict) and len(value) <= 500:
        return {_text(key): _value(item, depth + 1) for key, item in value.items()}
    raise ProbentiumError("invalid_field_value")


def _stamp(value):
    return value.isoformat(timespec="microseconds" if value.microsecond else "seconds").replace("+00:00", "Z")


def profiles():
    """Exemplaria separata; nullum ius certificatum."""
    return {key: {"id": key, "name": name, "version": "draft-2026-10-18",
                  "status": "draft", "legal_currentness": "unverified",
                  "legal_calendar": "unverified", "legally_verified": False,
                  "automatic_submission": False,
                  "scope": "Operational planning only; applicability and legal deadlines require independent review."}
            for key, name in _PROFILE_NAMES.items()}


def evaluate_control(control):
    """Observationes declaratae examinantur, non auctoritas fontium."""
    _dict(control, {"id", "title", "kind", "population", "observations", "evidence_refs",
                    "rto_seconds", "rpo_seconds"}, {"id", "kind", "observations"})
    control_id = _text(control["id"])
    if "title" in control:
        _text(control["title"])
    kind = control["kind"]
    if not isinstance(kind, str) or kind not in {"restore", "mfa", "remediation"}:
        raise ProbentiumError("unsupported_control_kind")
    if kind != "restore" and ({"rto_seconds", "rpo_seconds"} & control.keys()):
        raise ProbentiumError("unexpected_control_target")
    population = _integer(control.get("population"), nullable=True)
    document_refs = _refs(control.get("evidence_refs", []))
    observations = control["observations"]
    if not isinstance(observations, list) or len(observations) > 20000:
        raise ProbentiumError("control_observation_limit", 6)
    if population is not None and len(observations) > population:
        raise ProbentiumError("observations_exceed_population")
    targets = {key: _integer(control.get(key), nullable=True) for key in ("rto_seconds", "rpo_seconds")}
    details, subjects, ids = [], set(), set()
    counts = {"passed": 0, "failed": 0, "unknown": 0}
    extras = {"restore": {"restored", "functional_check", "elapsed_seconds", "data_age_seconds"},
              "mfa": {"configured", "enforced"},
              "remediation": {"applicable", "remediated", "retest_passed"}}[kind]
    for obs in observations:
        _dict(obs, {"id", "subject", "evidence_refs"} | extras, {"id", "subject"})
        obs_id, subject = _text(obs["id"]), _text(obs["subject"])
        if obs_id in ids or subject in subjects:
            raise ProbentiumError("duplicate_control_observation")
        ids.add(obs_id)
        subjects.add(subject)
        refs = _refs(obs.get("evidence_refs", []))
        reasons = []
        if kind == "restore":
            restored = _boolean(obs.get("restored"))
            functional = _boolean(obs.get("functional_check"))
            elapsed = _integer(obs.get("elapsed_seconds"), nullable=True)
            age = _integer(obs.get("data_age_seconds"), nullable=True)
            checks = [restored, functional]
            checks += [None if elapsed is None or targets["rto_seconds"] is None else elapsed <= targets["rto_seconds"],
                       None if age is None or targets["rpo_seconds"] is None else age <= targets["rpo_seconds"]]
            if functional is None:
                reasons.append("functional_recovery_not_demonstrated")
        elif kind == "mfa":
            checks = [_boolean(obs.get("configured")), _boolean(obs.get("enforced"))]
            if checks[1] is not True:
                reasons.append("configuration_does_not_demonstrate_enforcement")
        else:
            applicable = _boolean(obs.get("applicable"))
            remediated = _boolean(obs.get("remediated"))
            retested = _boolean(obs.get("retest_passed"))
            checks = [applicable, remediated, retested]
            if applicable is not True:
                checks = [None]
                reasons.append("applicability_requires_review")
            if retested is not True:
                reasons.append("closure_does_not_demonstrate_remediation")
        # Documentum solum effectum non probat.
        if not refs:
            outcome = "unknown"
            reasons.append("observation_has_no_evidence_reference")
        elif any(check is False for check in checks):
            outcome = "failed"
        elif all(check is True for check in checks):
            outcome = "passed"
        else:
            outcome = "unknown"
            reasons.append("required_observation_or_target_unknown")
        counts[outcome] += 1
        details.append({"id": obs_id, "subject": subject, "outcome": outcome,
                        "refs": refs, "reasons": reasons})
    missing = None if population is None else population - len(observations)
    reasons = ["evidence_references_are_not_authentication", "result_limited_to_declared_scope"]
    if population is None:
        reasons.append("population_unknown_no_coverage_percentage")
    elif population == 0:
        reasons.append("empty_population_does_not_demonstrate_effectiveness")
    if missing:
        reasons.append("declared_population_not_fully_assessed")
    if counts["failed"]:
        status = "failed_in_scope"
    elif population and missing == 0 and counts["passed"] == population:
        status = "effective_in_scope"
    elif counts["passed"]:
        status = "partially_demonstrated"
    else:
        status = "not_demonstrated"
    return {"control_id": control_id, "kind": kind, "status": status,
            "coverage": {"population": population, "assessed": len(observations), **counts, "missing": missing},
            "evidence": {"document_refs": document_refs, "observations": details,
                         "verification": "references_only", "observation_basis": "supplied_declarations"},
            "reasons": reasons, "profile_status": "draft", "legally_verified": False}


def _anchor(value):
    if isinstance(value, str):
        value = {"status": "known", "at": value}
    if value is None:
        return {"status": "trigger_status_unknown"}
    _dict(value, {"status", "at", "earliest", "latest", "earliest_inclusive", "latest_inclusive"}, {"status"})
    status = value["status"]
    if not isinstance(status, str):
        raise ProbentiumError("unsupported_anchor_status")
    if status in {"waiting", "time_unknown", "unknown"}:
        if set(value) != {"status"}:
            raise ProbentiumError("unexpected_anchor_time")
        return {"status": {"waiting": "waiting_for_trigger", "time_unknown": "trigger_time_unknown",
                           "unknown": "trigger_status_unknown"}[status]}
    if status == "known":
        if set(value) != {"status", "at"}:
            raise ProbentiumError("invalid_known_anchor")
        at = timestamp(value["at"])
        return {"status": "known", "earliest": at, "latest": at,
                "earliest_inclusive": True, "latest_inclusive": True}
    if status == "interval":
        if "at" in value or not {"earliest", "latest"} <= value.keys():
            raise ProbentiumError("invalid_interval_anchor")
        low = timestamp(value["earliest"]) if value["earliest"] is not None else None
        high = timestamp(value["latest"]) if value["latest"] is not None else None
        li, hi = value.get("earliest_inclusive", True), value.get("latest_inclusive", True)
        if type(li) is not bool or type(hi) is not bool or (low is None and high is None):
            raise ProbentiumError("invalid_interval_anchor")
        if low is not None and high is not None and (low > high or (low == high and not (li and hi))):
            raise ProbentiumError("empty_interval_anchor")
        return {"status": "interval", "earliest": low, "latest": high,
                "earliest_inclusive": li if low is not None else False,
                "latest_inclusive": hi if high is not None else False}
    raise ProbentiumError("unsupported_anchor_status")


def _track(track):
    _dict(track, {"id", "title", "profile", "anchors", "ongoing", "trust_service", "profile_review_due"},
          {"id", "profile", "anchors"})
    _text(track["id"])
    if "title" in track:
        _text(track["title"])
    if not isinstance(track["profile"], str) or track["profile"] not in _PROFILE_NAMES:
        raise ProbentiumError("unsupported_regulatory_profile")
    _dict(track["anchors"], _ANCHORS)
    _boolean(track.get("ongoing"))
    _boolean(track.get("trust_service"))
    if "profile_review_due" in track:
        timestamp(track["profile_review_due"])
    return {name: _anchor(track["anchors"].get(name)) for name in _ANCHORS}


def _shift(value, hours=0, days=0, months=0):
    if value is None:
        return None
    try:
        if months:
            year, month = divmod(value.year * 12 + value.month - 1 + months, 12)
            value = value.replace(year=year, month=month + 1,
                                  day=min(value.day, monthrange(year, month + 1)[1]))
        return value + timedelta(hours=hours, days=days)
    except (ValueError, OverflowError) as exc:
        raise ProbentiumError("operational_date_out_of_range") from exc


def _deadline(stage, anchor_name, anchor, as_of, hours=0, days=0, months=0, reasons=()):
    result = {"stage": stage, "anchor": anchor_name, "status": anchor["status"],
              "operational_target": None, "operational_target_range": None,
              "operational_status": "unknown", "legal_deadline": None,
              "legally_verified": False, "reasons": list(reasons)}
    if anchor["status"] not in {"known", "interval"}:
        return result
    low = _shift(anchor["earliest"], hours, days, months)
    high = _shift(anchor["latest"], hours, days, months)
    if anchor["status"] == "known":
        result["operational_target"] = _stamp(low)
        result["operational_status"] = "past_operational_target" if as_of > low else "at_operational_target" if as_of == low else "before_operational_target"
    else:
        result["operational_target_range"] = {
            "earliest": _stamp(low) if low else None, "latest": _stamp(high) if high else None,
            "earliest_inclusive": anchor["earliest_inclusive"], "latest_inclusive": anchor["latest_inclusive"]}
        if high is not None and (as_of > high or (as_of == high and not anchor["latest_inclusive"])):
            result["operational_status"] = "past_all_possible_operational_targets"
        elif low is not None and as_of < low:
            result["operational_status"] = "before_all_possible_operational_targets"
        else:
            result["operational_status"] = "possibly_past_operational_target"
        result["reasons"].append("anchor_interval_preserved")
    result["reasons"].append("utc_operational_calendar_not_a_verified_legal_deadline")
    return result


def _dora_initial(anchors, as_of):
    awareness, classification = anchors["awareness"], anchors["classification"]
    available = {"known", "interval"}
    if classification["status"] not in available:
        return _deadline("initial", "awareness+classification", classification, as_of)
    if awareness["status"] not in available:
        return _deadline("initial", "awareness+classification", awareness, as_of)
    al, ah = awareness["earliest"], awareness["latest"]
    cl, ch = classification["earliest"], classification["latest"]
    if al is not None and ch is not None and ch < al:
        raise ProbentiumError("classification_precedes_awareness")
    if awareness["status"] == classification["status"] == "known":
        if cl < al:
            raise ProbentiumError("classification_precedes_awareness")
        late = cl > _shift(al, hours=24)
        target = _shift(cl, hours=4) if late else min(_shift(cl, hours=4), _shift(al, hours=24))
        combined = {"status": "known", "earliest": target, "latest": target,
                    "earliest_inclusive": True, "latest_inclusive": True}
        return _deadline("initial", "awareness+classification", combined, as_of,
                         reasons=["late_classification_four_hour_branch" if late else "earlier_of_classification_plus_four_hours_and_awareness_plus_twenty_four_hours"])
    if any(v is None for v in (al, ah, cl, ch)):
        return _deadline("initial", "awareness+classification", {"status": "trigger_time_unknown"}, as_of,
                         reasons=["unbounded_anchor_interval_no_precise_target"])
    if cl > _shift(ah, hours=24):
        return _deadline("initial", "classification", classification, as_of, hours=4,
                         reasons=["late_classification_four_hour_branch", "awareness_interval_considered"])
    earliest = min(_shift(cl, hours=4), _shift(al, hours=24))
    if ch <= _shift(al, hours=24):
        latest = min(_shift(ch, hours=4), _shift(ah, hours=24))
        reason = "standard_branch_interval_envelope"
    else:
        latest = max(_shift(ch, hours=4), _shift(ah, hours=24))
        reason = "late_classification_branch_uncertain_conservative_envelope"
    combined = {"status": "interval", "earliest": earliest, "latest": latest,
                "earliest_inclusive": True, "latest_inclusive": True}
    return _deadline("initial", "awareness+classification", combined, as_of, reasons=[reason])


def evaluate_deadlines(track, as_of):
    """Termini operativi tantum; terminus iuris manet incertus."""
    anchors, now = _track(track), timestamp(as_of)
    profile = track["profile"]
    due = []
    def add(stage, anchor, **kwargs):
        due.append(_deadline(stage, anchor, anchors[anchor], now, **kwargs))
    if profile.startswith("cz-nis2-"):
        add("early", "awareness", hours=24)
        add("notification", "awareness", hours=24 if track.get("trust_service") is True else 72,
            reasons=["national_scope_and_significance_require_review"])
        add("progress_if_ongoing" if track.get("ongoing") is True else "final_or_progress", "submitted", days=30,
            reasons=["submitted_means_detailed_notification_not_early_warning", "ongoing_state_at_milestone_requires_review"])
        if track.get("ongoing") is True:
            add("final_after_resolution", "resolved", days=30)
    elif profile == "gdpr-controller":
        add("supervisory_notification", "awareness", hours=72,
            reasons=["without_undue_delay_is_separate", "unlikely_risk_exception_requires_review"])
    elif profile in {"gdpr-processor", "gdpr-communication"}:
        stage = "notify_controller" if profile == "gdpr-processor" else "communicate_to_affected_people"
        row = _deadline(stage, "awareness", anchors["awareness"], now,
                        reasons=["without_undue_delay_no_fixed_hour_allowance", "applicability_and_exceptions_require_review"])
        row["operational_target"] = row["operational_target_range"] = None
        row["operational_status"] = "human_action_review_required" if anchors["awareness"]["status"] in {"known", "interval"} else "unknown"
        due.append(row)
    elif profile == "dora":
        due.append(_dora_initial(anchors, now))
        add("intermediate", "submitted", hours=72, reasons=["report_required_even_if_unchanged"])
        final_anchor = "latest_intermediate" if "latest_intermediate" in track["anchors"] else "intermediate"
        first, latest = anchors["intermediate"], anchors["latest_intermediate"]
        if first["status"] == latest["status"] == "known" and latest["earliest"] < first["earliest"]:
            raise ProbentiumError("updated_intermediate_precedes_intermediate")
        add("final", final_anchor, months=1,
            reasons=["one_calendar_month_not_thirty_days", "weekend_and_holiday_exceptions_not_applied"])
    elif profile == "cra-vulnerability":
        add("early", "awareness", hours=24)
        add("notification", "awareness", hours=72)
        add("final", "measure_available", days=14,
            reasons=["availability_of_corrective_or_mitigating_measure_is_required_anchor"])
    else:
        add("early", "awareness", hours=24)
        add("notification", "awareness", hours=72)
        add("final", "submitted", months=1,
            reasons=["submitted_means_incident_notification_not_early_warning", "one_calendar_month_not_thirty_days"])
    review_due = track.get("profile_review_due")
    stale = review_due is not None and now > timestamp(review_due)
    reasons = ["draft_profile_only", "applicability_requires_human_review", "legal_calendar_unverified",
               "no_automatic_submission_or_background_monitoring"]
    if profile == "dora":
        reasons += ["update_without_undue_delay_and_on_recovery", "notify_delay_reasons_by_relevant_deadline",
                    "major_classification_and_entity_exceptions_require_review"]
    if stale:
        reasons.append("declared_profile_review_date_passed")
    return {"track_id": track["id"], "profile": profile, "profile_status": "draft",
            "profile_version": profiles()[profile]["version"],
            "legal_currentness": "stale_unverified" if stale else "unverified",
            "legal_calendar": "unverified", "legally_verified": False,
            "as_of": _stamp(now), "deadlines": due, "reasons": reasons}


def _field(field):
    _dict(field, {"id", "value", "basis", "refs", "reason", "calculation"}, {"id"})
    field_id = _text(field["id"])
    basis = field.get("basis", "unknown")
    if not isinstance(basis, str) or basis not in _BASES:
        raise ProbentiumError("unsupported_field_basis")
    refs = _refs(field.get("refs", []))
    value = _value(field.get("value"))
    reason = _text(field["reason"], 4096) if "reason" in field else None
    calculation = None
    if "calculation" in field:
        calc = _dict(field["calculation"], {"id", "version", "input_refs"}, {"id", "version", "input_refs"})
        calculation = {"id": _text(calc["id"]), "version": _text(calc["version"]), "input_refs": _refs(calc["input_refs"])}
    if basis == "unknown":
        if value is not None:
            raise ProbentiumError("unknown_field_cannot_assert_value")
        reason = reason or "fact_not_provided"
    else:
        if value is None:
            raise ProbentiumError("asserted_field_requires_value")
        if basis in {"source_backed", "derived", "contested"} and not refs:
            raise ProbentiumError("field_basis_requires_refs")
        if basis in {"human_attested", "contested"} and not reason:
            raise ProbentiumError("field_basis_requires_reason")
    if basis == "derived":
        if calculation is None or not calculation["input_refs"] or not set(calculation["input_refs"]) <= set(refs):
            raise ProbentiumError("derived_field_requires_calculation_inputs")
    elif calculation is not None:
        raise ProbentiumError("unexpected_field_calculation")
    return {"id": field_id, "value": value, "basis": basis, "refs": refs,
            "reason": reason, "calculation": calculation}


def prepare_filing(track, fields, case_revision, cutoff):
    """Vestigium contenti parati, non approbatio neque missio."""
    _track(track)
    _integer(case_revision)
    cutoff_at = _stamp(timestamp(cutoff))
    if not isinstance(fields, list) or len(fields) > 500:
        raise ProbentiumError("filing_field_limit", 6)
    normalized = [_field(field) for field in fields]
    if len({field["id"] for field in normalized}) != len(normalized):
        raise ProbentiumError("duplicate_filing_field")
    normalized.sort(key=lambda field: field["id"])
    snapshot = {"schema": "probentium.filing.v1", "state": "prepared",
                "track": deepcopy(track), "case_revision": case_revision, "cutoff": cutoff_at,
                "profile_status": "draft", "legally_verified": False,
                "fields": normalized,
                "unknown_fields": [field["id"] for field in normalized if field["basis"] == "unknown"],
                "evidence_verification": "references_only",
                "submission_status": "not_submitted"}
    if len(canonical_bytes(snapshot)) > 16 * 1024 * 1024:
        raise ProbentiumError("filing_size_limit", 6)
    digest = object_digest(snapshot, domain="PROBENTIUM-FILING-V1")
    return {**snapshot, "id": digest, "digest": digest}


def _verified_snapshot(snapshot):
    _dict(snapshot, {"schema", "state", "track", "case_revision", "cutoff", "profile_status", "legally_verified",
                     "fields", "unknown_fields", "evidence_verification", "submission_status", "id", "digest"},
          {"track", "fields", "case_revision", "cutoff", "id", "digest"})
    # Integritas non est veritas.
    normalized_input = []
    if not isinstance(snapshot["fields"], list) or len(snapshot["fields"]) > 500:
        raise ProbentiumError("filing_field_limit", 6)
    for field in snapshot["fields"]:
        _dict(field, {"id", "value", "basis", "refs", "reason", "calculation"}, {"id"})
        normalized_input.append({key: value for key, value in field.items() if value is not None})
    expected = prepare_filing(snapshot["track"], normalized_input, snapshot["case_revision"], snapshot["cutoff"])
    if canonical_bytes(snapshot) != canonical_bytes(expected):
        raise ProbentiumError("filing_snapshot_integrity_failed", 4)
    return expected


def compare_filings(before, after):
    """Mutationes indicantur; obligatio correctionis non praesumitur."""
    old, new = _verified_snapshot(before), _verified_snapshot(after)
    if old["track"]["id"] != new["track"]["id"]:
        raise ProbentiumError("filing_tracks_differ")
    old_fields, new_fields = ({field["id"]: field for field in snap["fields"]} for snap in (old, new))
    changes = []
    for field_id in sorted(old_fields.keys() | new_fields.keys()):
        first, second = old_fields.get(field_id), new_fields.get(field_id)
        if canonical_bytes(first) == canonical_bytes(second):
            continue
        if first is None:
            reason = "field_added"
        elif second is None:
            reason = "field_removed"
        elif canonical_bytes(first["value"]) != canonical_bytes(second["value"]):
            reason = "value_changed"
        else:
            reason = "evidence_basis_changed"
        changes.append({"field": field_id, "before": deepcopy(first), "after": deepcopy(second), "reason": reason})
    context_changes = [key for key in ("track", "case_revision", "cutoff") if old[key] != new[key]]
    return {"before_digest": old["digest"], "after_digest": new["digest"], "changes": changes,
            "context_changes": context_changes,
            "correction_impact": {"affected_fields": [change["field"] for change in changes],
                                  "review_required": bool(changes or context_changes),
                                  "legal_correction_required": "undetermined",
                                  "submission_changed": False,
                                  "reason": "A new prepared snapshot does not amend any prior filing."},
            "profile_status": "draft", "legally_verified": False}
