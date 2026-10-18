"""Calendarium explicitum computatur; ius non certificatur."""
import base64
from calendar import monthrange
from copy import deepcopy
from datetime import date, datetime, time, timedelta, timezone
from io import BytesIO
import re
import struct
from zoneinfo import ZoneInfo

from .contracts import ProbentiumError, object_digest, timestamp
from .regulatory import _dict, _text, _refs, _stamp, _anchor, _dora_initial, _track

VERSION = "1"
CALENDAR_SCHEMA = "probentium.calendar-policy.v1"
CALENDAR_FIELDS = {"schema", "id", "version", "timezone", "timezone_data", "source_ids", "hour_rule",
                   "day_rule", "month_rule", "nonworking_rule", "weekend_days", "holidays",
                   "holiday_coverage", "status"}


def _date(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ProbentiumError("invalid_calendar_date")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ProbentiumError("invalid_calendar_date") from exc


def _zone(policy):
    if policy["timezone"] == "UTC":
        if policy["timezone_data"] is not None:
            raise ProbentiumError("utc_calendar_has_timezone_data")
        return timezone.utc
    data = policy["timezone_data"]
    if not isinstance(data, str) or len(data) > 90000:
        raise ProbentiumError("calendar_timezone_snapshot_required")
    try:
        raw = base64.b64decode(data, validate=True)
        if len(raw) > 65536 or not raw.startswith(b"TZif"):
            raise ValueError()
        return ZoneInfo.from_file(BytesIO(raw), key=policy["timezone"])
    except (ValueError, TypeError, OSError, EOFError, AssertionError, struct.error) as exc:
        raise ProbentiumError("invalid_calendar_timezone_snapshot") from exc


def validate_calendar(policy):
    _dict(policy, CALENDAR_FIELDS, CALENDAR_FIELDS)
    if policy["schema"] != CALENDAR_SCHEMA or policy["status"] != "unverified":
        raise ProbentiumError("calendar_cannot_self_certify")
    for key in ("id", "version", "timezone"):
        _text(policy[key], 128)
    if not _refs(policy["source_ids"]):
        raise ProbentiumError("calendar_source_required")
    allowed = {"hour_rule": {"elapsed_hours", "exclude_started_hour"},
               "day_rule": {"elapsed_days", "exclude_start_day_end_of_day"},
               "month_rule": {"same_local_time_clamp", "exclude_start_day_end_of_day"},
               "nonworking_rule": {"none", "next_working_day_end", "dora_next_working_day_noon"}}
    for key, choices in allowed.items():
        if not isinstance(policy[key], str) or policy[key] not in choices:
            raise ProbentiumError("unsupported_calendar_operator")
    days = policy["weekend_days"]
    if not isinstance(days, list) or len(days) > 6 or any(type(n) is not int or not 0 <= n <= 6 for n in days) or len(set(days)) != len(days):
        raise ProbentiumError("invalid_calendar_weekend")
    holidays = policy["holidays"]
    if not isinstance(holidays, list) or len(holidays) > 1000:
        raise ProbentiumError("calendar_holiday_limit", 6)
    parsed = [_date(day) for day in holidays]
    if len(set(parsed)) != len(parsed):
        raise ProbentiumError("duplicate_calendar_holiday")
    coverage = policy["holiday_coverage"]
    _dict(coverage, {"start", "end"}, {"start", "end"})
    low, high = _date(coverage["start"]), _date(coverage["end"])
    if low > high or any(not low <= day <= high for day in parsed):
        raise ProbentiumError("calendar_holiday_coverage_invalid")
    _zone(policy)
    return deepcopy(policy)


def validate_exception(value):
    if value is None:
        return None
    keys = {"kind", "stage", "entity_class", "nis2_essential_or_important", "authority_exclusion", "actor", "at", "rationale", "basis_refs"}
    _dict(value, keys, keys)
    if value["kind"] != "dora_nonworking" or value["stage"] not in ("initial", "intermediate", "final"):
        raise ProbentiumError("unsupported_deadline_exception")
    if value["entity_class"] not in ("credit_institution", "central_counterparty", "trading_venue", "other"):
        raise ProbentiumError("invalid_exception_entity")
    for key in ("nis2_essential_or_important", "authority_exclusion"):
        if value[key] is not None and type(value[key]) is not bool:
            raise ProbentiumError("invalid_exception_fact")
    _text(value["actor"]); _text(value["rationale"], 4096); timestamp(value["at"])
    refs = _refs(value["basis_refs"])
    if not refs:
        raise ProbentiumError("exception_basis_required")
    if any(not re.fullmatch("[0-9a-f]{64}", ref) for ref in refs):
        raise ProbentiumError("invalid_exception_basis_reference")
    return deepcopy(value)


def _local(naive, zone):
    # Ambiguitas aut hora omissa non tacite solvitur.
    choices = set()
    for fold in (0, 1):
        local = naive.replace(tzinfo=zone, fold=fold)
        instant = local.astimezone(timezone.utc)
        if instant.astimezone(zone).replace(tzinfo=None) == naive:
            choices.add(instant)
    if len(choices) != 1:
        raise ProbentiumError("calendar_local_time_unresolved")
    return next(iter(choices))


def _shift(instant, operator, amount, policy):
    zone = _zone(policy)
    try:
        local = instant.astimezone(zone).replace(tzinfo=None)
        if operator == "hours_after":
            base = instant if policy["hour_rule"] == "elapsed_hours" else _local(local.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1), zone)
            return base + timedelta(hours=amount)
        if operator == "days_after" and policy["day_rule"] == "elapsed_days":
            return instant + timedelta(days=amount)
        if operator == "days_after":
            local = datetime.combine(local.date() + timedelta(days=amount), time.max)
        elif operator == "months_after":
            year, month = divmod(local.year * 12 + local.month - 1 + amount, 12)
            local = local.replace(year=year, month=month + 1, day=min(local.day, monthrange(year, month + 1)[1]))
            if policy["month_rule"] == "exclude_start_day_end_of_day":
                local = datetime.combine(local.date(), time.max)
        else:
            raise ProbentiumError("unsupported_deadline_operator")
        return _local(local, zone)
    except ProbentiumError:
        raise
    except (ValueError, OverflowError) as exc:
        raise ProbentiumError("operational_date_out_of_range") from exc


def _adjust(instant, policy, apply):
    if not apply or policy["nonworking_rule"] == "none":
        return instant
    zone = _zone(policy)
    try:
        local = instant.astimezone(zone)
    except (ValueError, OverflowError) as exc:
        raise ProbentiumError("operational_date_out_of_range") from exc
    day = local.date()
    start, end = (_date(policy["holiday_coverage"][key]) for key in ("start", "end"))
    holidays = {_date(d) for d in policy["holidays"]}
    for _ in range(370):
        if not start <= day <= end:
            raise ProbentiumError("calendar_holiday_coverage_unknown")
        if day.weekday() not in policy["weekend_days"] and day not in holidays:
            if day == local.date():
                return instant
            target = time(12) if policy["nonworking_rule"] == "dora_next_working_day_noon" else time.max
            return _local(datetime.combine(day, target), zone)
        try:
            day += timedelta(days=1)
        except OverflowError as exc:
            raise ProbentiumError("operational_date_out_of_range") from exc
    raise ProbentiumError("calendar_adjustment_limit", 6)


def evaluate_rule(track, rule, calendar, as_of, exception=None):
    """Terminus operationalis ex versionibus explicitis derivatur."""
    from .legalpacks import validate_rule
    validate_rule(rule)
    policy = validate_calendar(calendar); ex = validate_exception(exception)
    anchors = _track(track); now = timestamp(as_of)
    stage = rule.get("stage", rule["id"])
    result = {"schema": "probentium.deadline-result.v1", "engine_version": VERSION, "stage": stage,
              "as_of": _stamp(now), "rule_digest": object_digest(rule), "calendar_digest": object_digest(policy),
              "anchor_digests": {key: object_digest(value) for key, value in sorted(track["anchors"].items())},
              "status": "trigger_status_unknown", "operational_target": None, "operational_target_range": None,
              "operational_status": "unknown", "legal_deadline": None, "legally_verified": False,
              "legal_countdown_enabled": False, "reference_vectors_reviewed": False,
              "without_undue_delay": rule.get("without_undue_delay", False),
              "exception_status": "not_requested", "reasons": ["legal_calendar_unverified", "supplied_policy_not_legal_certification", "reportability_not_determined_by_calculation"]}
    if rule["operator"] == "calendar_plan":
        from .calendar_plan import evaluate_plan
        return evaluate_plan(track, anchors, rule, policy, now, ex, result)
    apply = policy["nonworking_rule"] == "next_working_day_end"
    if ex is not None:
        if track["profile"] != "dora" or stage != ex["stage"] or policy["nonworking_rule"] != "dora_next_working_day_noon":
            raise ProbentiumError("exception_scope_mismatch")
        if timestamp(ex["at"]) > now:
            raise ProbentiumError("exception_attestation_in_future")
        excluded = ex["stage"] != "final" and (ex["entity_class"] != "other" or ex["nis2_essential_or_important"] is True or ex["authority_exclusion"] is True)
        unknown = ex["stage"] != "final" and (ex["nis2_essential_or_important"] is None or ex["authority_exclusion"] is None)
        apply = not excluded and not unknown
        result["exception_status"] = "excluded_by_supplied_facts" if excluded else "eligibility_unknown" if unknown else "supplied_eligibility_only"
    elif policy["nonworking_rule"] == "dora_next_working_day_noon":
        result["exception_status"] = "explicit_eligibility_required"
    operator = rule["operator"]
    if operator == "manual_review" or rule["origin"] == "contextual_proposal":
        result["status"] = "human_review_required"; return result
    if operator == "dora_initial":
        interim = _dora_initial(anchors, now)
        result["reasons"] += interim["reasons"]
        if interim["operational_target"]:
            anchor = _anchor(interim["operational_target"])
        elif interim["operational_target_range"]:
            anchor = _anchor({"status": "interval", **interim["operational_target_range"]})
        else:
            result["status"] = interim["status"]; return result
        shift = lambda value: value
    else:
        anchor = anchors[rule["parameters"]["anchor"]]
        shift = lambda value: _shift(value, operator, rule["parameters"]["amount"], policy)
    result["status"] = anchor["status"]
    if anchor["status"] not in ("known", "interval"):
        return result
    try:
        low, high = [None if anchor[key] is None else _adjust(shift(anchor[key]), policy, apply) for key in ("earliest", "latest")]
    except ProbentiumError as exc:
        if exc.code not in {"calendar_local_time_unresolved", "calendar_holiday_coverage_unknown"}:
            raise
        result["status"] = "calendar_unknown"; result["reasons"].append(exc.code); return result
    if anchor["status"] == "known":
        result["operational_target"] = _stamp(low)
        result["operational_status"] = "past_operational_target" if now > low else "at_operational_target" if now == low else "before_operational_target"
    else:
        # Calendaria extrema comprimere possunt; clausura non fingitur.
        enclosure = apply or operator == "months_after" or (operator == "days_after" and policy["day_rule"] != "elapsed_days") or (operator == "hours_after" and policy["hour_rule"] != "elapsed_hours")
        result["operational_target_range"] = {"earliest": _stamp(low) if low else None, "latest": _stamp(high) if high else None,
            "earliest_inclusive": bool(low) if enclosure else anchor["earliest_inclusive"],
            "latest_inclusive": bool(high) if enclosure else anchor["latest_inclusive"]}
        bounds = result["operational_target_range"]
        past = high is not None and (now > high or (now == high and not bounds["latest_inclusive"]))
        before = low is not None and (now < low or (now == low and not bounds["earliest_inclusive"]))
        result["operational_status"] = "past_all_possible_operational_targets" if past else "before_all_possible_operational_targets" if before else "possibly_past_operational_target"
        result["reasons"].append("calendar_mapping_conservative_closed_enclosure" if enclosure else "anchor_interval_and_open_bounds_preserved")
    return result
