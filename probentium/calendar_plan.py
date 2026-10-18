"""Calculus finitus ex ordine declarato; nulla lex sponte eligitur."""
from copy import deepcopy
from datetime import datetime, time, timedelta, timezone
import re

from .contracts import ProbentiumError, canonical_bytes, object_digest, timestamp
from .regulatory import _dict, _stamp, _ANCHORS, _anchor, _dora_initial

SCHEMA = "probentium.deadline-plan.v1"
MAX_NODES = 16
MAX_INPUTS = 8
MAX_BYTES = 65536
MAX_DAY_STEPS = 3700
OPS = {"anchor", "shift", "working_days", "nonworking_adjust", "combine", "precedence", "dora_initial"}
MODES = {"none", "next_working_day_end", "dora_next_working_day_noon"}


def _id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", value):
        raise ProbentiumError("invalid_deadline_node_id")
    return value


def _inputs(node):
    if node["op"] == "anchor":
        return []
    if node["op"] == "combine":
        return node["inputs"]
    if node["op"] == "precedence":
        return [item["input"] for item in node["candidates"]]
    if node["op"] == "dora_initial":
        return [node["awareness"], node["classification"]]
    return [node["input"]]


def validate_plan(plan):
    _dict(plan, {"schema", "nodes", "output"}, {"schema", "nodes", "output"})
    if plan["schema"] != SCHEMA:
        raise ProbentiumError("unsupported_deadline_plan", 7)
    nodes = plan["nodes"]
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_NODES:
        raise ProbentiumError("deadline_plan_node_limit", 6)
    seen = {}; dependencies = {}
    fields = {"anchor": {"anchor"}, "shift": {"input", "unit", "amount"},
              "working_days": {"input", "count", "include_start_day", "completion"},
              "nonworking_adjust": {"input", "mode"}, "combine": {"inputs", "mode"}, "precedence": {"candidates"},
              "dora_initial": {"awareness", "classification"}}
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("op"), str) or node["op"] not in OPS:
            raise ProbentiumError("unsupported_deadline_node")
        keys = {"id", "op"} | fields[node["op"]]
        _dict(node, keys, keys); identity = _id(node["id"])
        if identity in seen:
            raise ProbentiumError("duplicate_deadline_node")
        op = node["op"]
        if op == "anchor":
            if not isinstance(node["anchor"], str) or node["anchor"] not in _ANCHORS:
                raise ProbentiumError("invalid_deadline_plan_anchor")
        elif op == "shift":
            if node["unit"] not in ("hours", "days", "months") or type(node["amount"]) is not int or not 1 <= node["amount"] <= 366:
                raise ProbentiumError("invalid_deadline_plan_shift")
        elif op == "working_days":
            if type(node["count"]) is not int or not 1 <= node["count"] <= 366 or type(node["include_start_day"]) is not bool or node["completion"] not in ("local_end_of_day", "same_local_time"):
                raise ProbentiumError("invalid_deadline_working_days")
        elif op == "nonworking_adjust":
            if not isinstance(node["mode"], str) or node["mode"] not in MODES:
                raise ProbentiumError("invalid_deadline_adjustment")
        elif op == "combine":
            if node["mode"] not in ("minimum", "maximum") or not isinstance(node["inputs"], list) or not 2 <= len(node["inputs"]) <= MAX_INPUTS:
                raise ProbentiumError("invalid_deadline_combination")
        elif op == "precedence":
            if not isinstance(node["candidates"], list) or not 1 <= len(node["candidates"]) <= MAX_INPUTS:
                raise ProbentiumError("deadline_precedence_limit", 6)
            for item in node["candidates"]:
                _dict(item, {"input", "applies"}, {"input", "applies"})
                if item["applies"] is not None and type(item["applies"]) is not bool:
                    raise ProbentiumError("invalid_deadline_precedence_fact")
        inputs = [_id(value) for value in _inputs(node)]
        if len(inputs) != len(set(inputs)):
            raise ProbentiumError("duplicate_deadline_input")
        if any(value not in seen for value in inputs):
            raise ProbentiumError("deadline_forward_or_missing_reference")
        if op == "dora_initial" and any(seen[node[key]]["op"] != "anchor" or seen[node[key]]["anchor"] != key for key in ("awareness", "classification")):
            raise ProbentiumError("invalid_dora_plan_anchor_binding")
        seen[identity] = node; dependencies[identity] = inputs
    output = _id(plan["output"])
    if output != nodes[-1]["id"]:
        raise ProbentiumError("deadline_output_must_be_last")
    reached, todo = set(), [output]
    while todo:
        item = todo.pop()
        if item not in reached:
            reached.add(item); todo.extend(dependencies[item])
    if reached != set(seen):
        raise ProbentiumError("deadline_plan_unused_node")
    if len(canonical_bytes(plan)) > MAX_BYTES:
        raise ProbentiumError("deadline_plan_bytes_limit", 6)
    return deepcopy(plan)


def _working_target(instant, count, include_start_day, completion, policy):
    from .deadlines import _zone, _date, _local
    zone = _zone(policy)
    try:
        local = instant.astimezone(zone)
        day = local.date() if include_start_day else local.date() + timedelta(days=1)
        low, high = (_date(policy["holiday_coverage"][key]) for key in ("start", "end"))
        holidays = {_date(value) for value in policy["holidays"]}
        remaining = count
        for _ in range(MAX_DAY_STEPS):
            if not low <= day <= high:
                raise ProbentiumError("calendar_holiday_coverage_unknown")
            if day.weekday() not in policy["weekend_days"] and day not in holidays:
                remaining -= 1
                if remaining == 0:
                    clock = time.max if completion == "local_end_of_day" else local.timetz().replace(tzinfo=None)
                    return _local(datetime.combine(day, clock), zone)
            day += timedelta(days=1)
    except ProbentiumError:
        raise
    except (ValueError, OverflowError) as exc:
        raise ProbentiumError("operational_date_out_of_range") from exc
    raise ProbentiumError("deadline_working_day_limit", 6)


def _map(value, transform, enclosure):
    if value["status"] not in {"known", "interval"}:
        return deepcopy(value)
    low, high = [None if value[key] is None else transform(value[key]) for key in ("earliest", "latest")]
    return {"status": value["status"], "earliest": low, "latest": high,
            "earliest_inclusive": (low is not None) if enclosure else value["earliest_inclusive"],
            "latest_inclusive": (high is not None) if enclosure else value["latest_inclusive"]}


def _combine(values, mode):
    missing = [value for value in values if value["status"] not in {"known", "interval"}]
    if missing:
        # Ignorantia non eliminatur per alterum terminum commodum.
        priorities = ("trigger_status_unknown", "trigger_time_unknown", "calendar_unknown", "waiting_for_trigger")
        return deepcopy(next((value for status in priorities for value in missing if value["status"] == status), missing[0]))
    lows = [value["earliest"] for value in values]; highs = [value["latest"] for value in values]
    low = None if (all(v is None for v in lows) or (mode == "minimum" and any(v is None for v in lows))) else (min if mode == "minimum" else max)(v for v in lows if v is not None)
    high = None if (all(v is None for v in highs) or (mode == "maximum" and any(v is None for v in highs))) else (min if mode == "minimum" else max)(v for v in highs if v is not None)
    return {"status": "known" if all(value["status"] == "known" for value in values) else "interval",
            "earliest": low, "latest": high, "earliest_inclusive": low is not None, "latest_inclusive": high is not None}


def _presentation(value):
    point, interval = None, None
    if value["status"] == "known":
        point = _stamp(value["earliest"])
    elif value["status"] == "interval":
        interval = {"earliest": _stamp(value["earliest"]) if value["earliest"] else None,
                    "latest": _stamp(value["latest"]) if value["latest"] else None,
                    "earliest_inclusive": value["earliest_inclusive"], "latest_inclusive": value["latest_inclusive"]}
    return {"status": value["status"], "operational_target": point, "operational_target_range": interval}


def evaluate_plan(track, anchors, rule, policy, now, exception, result):
    from .deadlines import _shift, _adjust
    plan = validate_plan(rule["parameters"])
    if exception is not None and (track["profile"] != "dora" or rule.get("stage", rule["id"]) != exception["stage"] or
                                  not any(n["op"] == "nonworking_adjust" and n["mode"] == "dora_next_working_day_noon" for n in plan["nodes"])):
        raise ProbentiumError("exception_scope_mismatch")
    if exception is not None and timestamp(exception["at"]) > now:
        raise ProbentiumError("exception_attestation_in_future")
    values, trace = {}, []
    for node in plan["nodes"]:
        op, inputs = node["op"], _inputs(node); reasons = []; selection = None
        try:
            if op == "anchor":
                value = deepcopy(anchors[node["anchor"]])
            elif op == "dora_initial":
                if track["profile"] != "dora":
                    raise ProbentiumError("dora_plan_profile_mismatch")
                interim = _dora_initial({"awareness": values[node["awareness"]], "classification": values[node["classification"]]}, now)
                if interim["operational_target"]:
                    value = _anchor(interim["operational_target"])
                elif interim["operational_target_range"]:
                    value = _anchor({"status": "interval", **interim["operational_target_range"]})
                else:
                    value = {"status": interim["status"]}
                reasons.extend(interim["reasons"])
            elif op == "shift":
                enclosure = node["unit"] == "months" or (node["unit"] == "days" and policy["day_rule"] != "elapsed_days") or (node["unit"] == "hours" and policy["hour_rule"] != "elapsed_hours")
                value = _map(values[node["input"]], lambda instant: _shift(instant, node["unit"] + "_after", node["amount"], policy), enclosure)
                if enclosure:
                    reasons.append("calendar_mapping_conservative_closed_enclosure")
            elif op == "working_days":
                value = _map(values[node["input"]], lambda instant: _working_target(instant, node["count"], node["include_start_day"], node["completion"], policy), True)
                reasons.append("explicit_working_day_count_not_legal_applicability")
                if value["status"] == "interval":
                    reasons.append("calendar_mapping_conservative_closed_enclosure")
            elif op == "nonworking_adjust":
                apply = node["mode"] != "none"; selected_policy = {**policy, "nonworking_rule": node["mode"]}
                if node["mode"] == "dora_next_working_day_noon":
                    if track["profile"] != "dora":
                        raise ProbentiumError("exception_scope_mismatch")
                    excluded = exception is not None and exception["stage"] != "final" and (exception["entity_class"] != "other" or exception["nis2_essential_or_important"] is True or exception["authority_exclusion"] is True)
                    unknown = exception is not None and exception["stage"] != "final" and (exception["nis2_essential_or_important"] is None or exception["authority_exclusion"] is None)
                    apply = exception is not None and not excluded and not unknown
                    result["exception_status"] = "explicit_eligibility_required" if exception is None else "excluded_by_supplied_facts" if excluded else "eligibility_unknown" if unknown else "supplied_eligibility_only"
                    reasons.append(result["exception_status"])
                value = _map(values[node["input"]], lambda instant: _adjust(instant, selected_policy, apply), apply)
                reasons.append("explicit_nonworking_policy_precedence")
            elif op == "combine":
                value = _combine([values[ref] for ref in inputs], node["mode"])
                reasons.append("declared_" + node["mode"] + "_combination")
                if value["status"] == "interval":
                    reasons.append("combination_conservative_closed_enclosure")
            else:
                value = {"status": "not_applicable_by_supplied_policy"}
                for candidate in node["candidates"]:
                    if candidate["applies"] is None:
                        value = {"status": "trigger_status_unknown"}; reasons.append("precedence_applicability_unknown"); break
                    if candidate["applies"]:
                        selection = candidate["input"]; value = deepcopy(values[selection]); break
                reasons.append("supplied_precedence_not_legal_determination")
        except ProbentiumError as exc:
            if exc.code not in {"calendar_local_time_unresolved", "calendar_holiday_coverage_unknown"}:
                raise
            value = {"status": "calendar_unknown"}; reasons.append(exc.code)
        values[node["id"]] = value
        trace.append({"id": node["id"], "op": op, "input_ids": inputs, **_presentation(value), "selection": selection, "reasons": reasons})
    final = values[plan["output"]]
    result.update(_presentation(final)); result["plan_digest"] = object_digest(plan, domain="PROBENTIUM-DEADLINE-PLAN-V1")
    result["plan_trace"] = trace
    result["reasons"].append("explicit_bounded_calendar_plan")
    if final["status"] == "known":
        target = final["earliest"]
        result["operational_status"] = "past_operational_target" if now > target else "at_operational_target" if now == target else "before_operational_target"
    elif final["status"] == "interval":
        low, high = final["earliest"], final["latest"]
        past = high is not None and (now > high or (now == high and not final["latest_inclusive"]))
        before = low is not None and (now < low or (now == low and not final["earliest_inclusive"]))
        result["operational_status"] = "past_all_possible_operational_targets" if past else "before_all_possible_operational_targets" if before else "possibly_past_operational_target"
    return result
