"""Tempora relata sunt; limites non sunt probabilitates."""
from copy import deepcopy
import re

from .contracts import ProbentiumError, object_digest, text_field

MIN_TIME_US = -62135596800000000
MAX_TIME_US = 253402300800000000
MAX_MAGNITUDE = 10 ** 18
MAX_WINDOW_US = 365 * 86400 * 1000000
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_DECIMAL = re.compile(r"(?:0|-?[1-9][0-9]*)\Z")


def error(code, exit_code=2):
    raise ProbentiumError(code, exit_code)


def exact_dict(value, allowed, required=()):
    if not isinstance(value, dict) or any(type(k) is not str for k in value):
        error("invalid_analysis_object")
    if set(value) - set(allowed) or set(required) - set(value):
        error("invalid_analysis_fields")
    return value


def identifier(value):
    if type(value) is not str or not _HEX.fullmatch(value):
        error("invalid_analysis_reference")
    return value


def integer(value, low=0, high=1000000):
    if type(value) is not int or not low <= value <= high:
        error("invalid_analysis_integer")
    return value


def microseconds(value, limit=MAX_MAGNITUDE):
    if type(value) is not str or len(value) > 22 or not _DECIMAL.fullmatch(value):
        error("invalid_microsecond_string")
    number = int(value)
    if abs(number) > limit:
        error("time_magnitude_limit")
    return number


def refs(value, maximum=64):
    if not isinstance(value, list) or len(value) > maximum:
        error("analysis_reference_limit", 6)
    result = [identifier(item) for item in value]
    if len(set(result)) != len(result):
        error("duplicate_analysis_reference")
    return result


def interval(lo, hi, lo_closed=True, hi_closed=True):
    return {"lo_us": str(lo), "hi_us": str(hi), "lo_closed": lo_closed, "hi_closed": hi_closed}


def validate_interval(value, *, calendar=False, nullable=True):
    if value is None and nullable:
        return None
    exact_dict(value, {"lo_us", "hi_us", "lo_closed", "hi_closed"}, {"lo_us", "hi_us", "lo_closed", "hi_closed"})
    lo, hi = microseconds(value["lo_us"]), microseconds(value["hi_us"])
    if type(value["lo_closed"]) is not bool or type(value["hi_closed"]) is not bool:
        error("invalid_interval_boundary")
    if lo > hi or (lo == hi and not (value["lo_closed"] and value["hi_closed"])):
        error("empty_time_interval")
    if calendar and (lo < MIN_TIME_US or hi > MAX_TIME_US or (hi == MAX_TIME_US and value["hi_closed"])):
        error("calendar_range_exceeded")
    return deepcopy(value)


def add(a, b):
    return interval(int(a["lo_us"]) + int(b["lo_us"]), int(a["hi_us"]) + int(b["hi_us"]),
                    a["lo_closed"] and b["lo_closed"], a["hi_closed"] and b["hi_closed"])


def scale(a, coefficient):
    if coefficient == 0:
        return interval(0, 0)
    if coefficient > 0:
        return interval(int(a["lo_us"]) * coefficient, int(a["hi_us"]) * coefficient, a["lo_closed"], a["hi_closed"])
    return interval(int(a["hi_us"]) * coefficient, int(a["lo_us"]) * coefficient, a["hi_closed"], a["lo_closed"])


def contains(outer, inner):
    ol, oh, il, ih = (int(v) for v in (outer["lo_us"], outer["hi_us"], inner["lo_us"], inner["hi_us"]))
    return ((ol < il or (ol == il and (outer["lo_closed"] or not inner["lo_closed"])))
            and (oh > ih or (oh == ih and (outer["hi_closed"] or not inner["hi_closed"]))))


def intersects(a, b):
    al, ah, bl, bh = (int(v) for v in (a["lo_us"], a["hi_us"], b["lo_us"], b["hi_us"]))
    return not (ah < bl or bh < al or (ah == bl and not (a["hi_closed"] and b["lo_closed"]))
                or (bh == al and not (b["hi_closed"] and a["lo_closed"])))


def validate_clock_model(value):
    exact_dict(value, {"schema", "id", "segments", "basis_refs", "rationale", "assumption_id", "source_family_ids"},
               {"schema", "id", "segments", "basis_refs", "rationale"})
    if value["schema"] != "testifex.clock-model.v1":
        error("unsupported_clock_model", 7)
    text_field(value["id"], 128)
    text_field(value["rationale"], 4096)
    refs(value["basis_refs"], 32)
    assumption = value.get("assumption_id")
    if assumption is not None:
        text_field(assumption, 128)
    if not value["basis_refs"] and assumption is None:
        error("clock_basis_required")
    families = value.get("source_family_ids", [])
    if not isinstance(families, list) or len(families) > 64 or len(set(map(str, families))) != len(families):
        error("invalid_clock_families")
    for family in families:
        text_field(family, 128)
    segments = value["segments"]
    if not isinstance(segments, list) or not 1 <= len(segments) <= 64:
        error("clock_segment_limit", 6)
    shared_bounds = {}
    for segment in segments:
        exact_dict(segment, {"validity", "fixed_offset_us", "local_error", "shared_errors"},
                   {"validity", "fixed_offset_us", "local_error", "shared_errors"})
        validate_interval(segment["validity"], calendar=True, nullable=False)
        microseconds(segment["fixed_offset_us"])
        validate_interval(segment["local_error"])
        terms = segment["shared_errors"]
        if not isinstance(terms, list) or len(terms) > 64:
            error("shared_error_limit", 6)
        used = set()
        for term in terms:
            exact_dict(term, {"id", "coefficient", "interval"}, {"id", "coefficient", "interval"})
            name = text_field(term["id"], 128)
            integer(term["coefficient"], -1, 1)
            bounds = validate_interval(term["interval"])
            if name in used or (name in shared_bounds and shared_bounds[name] != bounds):
                error("inconsistent_shared_error")
            used.add(name)
            shared_bounds[name] = bounds
    return deepcopy(value)


def _expression(event_id, recorded, model, base, terms, reasons, model_digest):
    result = {"schema": "testifex.time-expression.v1", "event_id": event_id,
            "base": base, "terms": terms, "status": "unknown" if reasons else "known", "reasons": reasons,
            "clock_model_digest": model_digest,
            "assumption_ids": [model["assumption_id"]] if model and model.get("assumption_id") else [],
            "basis_refs": model["basis_refs"] if model else []}
    result["id"] = object_digest(result, "TESTIFEX-TIME-EXPRESSION-V1")
    return result


def reference_time(event_id, recorded_time, clock_model=None):
    """Solum exemplar explicitum horologium ad referentiam ligat."""
    identifier(event_id)
    recorded = validate_interval(recorded_time, calendar=True)
    model = validate_clock_model(clock_model) if clock_model is not None else None
    return _reference_time_validated(event_id, recorded, model, object_digest(model) if model is not None else None)


def _reference_time_validated(event_id, recorded, model, model_digest):
    """Vocans schema et exemplar ante iter probavit."""
    if recorded is None:
        return _expression(event_id, recorded, model, None, [], ["recorded_time_unknown"], model_digest)
    if model is None:
        return _expression(event_id, recorded, model, None, [], ["clock_alignment_unknown"], model_digest)
    active = [segment for segment in model["segments"] if intersects(segment["validity"], recorded)]
    if len(active) != 1 or not contains(active[0]["validity"], recorded):
        return _expression(event_id, recorded, model, None, [], ["clock_segment_gap_or_overlap"], model_digest)
    segment = active[0]
    if segment["local_error"] is None or any(term["interval"] is None for term in segment["shared_errors"]):
        return _expression(event_id, recorded, model, None, [], ["clock_error_unknown"], model_digest)
    offset = -microseconds(segment["fixed_offset_us"])
    base = add(add(recorded, interval(offset, offset)), segment["local_error"])
    terms = sorted(deepcopy(segment["shared_errors"]), key=lambda term: term["id"])
    bounds = deepcopy(base)
    for term in terms:
        bounds = add(bounds, scale(term["interval"], term["coefficient"]))
    validate_interval(bounds, calendar=True, nullable=False)
    return _expression(event_id, recorded, model, base, terms, [], model_digest)


def validate_expression(value):
    exact_dict(value, {"schema", "id", "event_id", "base", "terms", "status", "reasons", "clock_model_digest", "assumption_ids", "basis_refs"},
               {"schema", "id", "event_id", "base", "terms", "status", "reasons", "clock_model_digest", "assumption_ids", "basis_refs"})
    if value["schema"] != "testifex.time-expression.v1" or value["status"] not in ("known", "unknown"):
        error("invalid_time_expression")
    identifier(value["id"])
    identifier(value["event_id"])
    validate_interval(value["base"])
    if value["clock_model_digest"] is not None:
        identifier(value["clock_model_digest"])
    refs(value["basis_refs"], 32)
    for key in ("assumption_ids", "reasons"):
        if not isinstance(value[key], list) or len(value[key]) > 64:
            error("invalid_time_expression")
        for item in value[key]:
            text_field(item, 128)
    if not isinstance(value["terms"], list) or len(value["terms"]) > 64:
        error("shared_error_limit", 6)
    used = set()
    for term in value["terms"]:
        exact_dict(term, {"id", "coefficient", "interval"}, {"id", "coefficient", "interval"})
        text_field(term["id"], 128)
        integer(term["coefficient"], -1, 1)
        validate_interval(term["interval"], nullable=False)
        if term["id"] in used:
            error("inconsistent_shared_error")
        used.add(term["id"])
    if value["status"] == "known" and (value["base"] is None or value["reasons"]):
        error("invalid_time_expression")
    if value["status"] == "unknown" and (value["base"] is not None or value["terms"] or not value["reasons"]):
        error("invalid_time_expression")
    if value["id"] != object_digest({key: item for key, item in value.items() if key != "id"}, "TESTIFEX-TIME-EXPRESSION-V1"):
        error("time_expression_digest_mismatch", 4)
    return value


def bounds(expression):
    validate_expression(expression)
    if expression["status"] == "unknown":
        return None
    result = deepcopy(expression["base"])
    for term in expression["terms"]:
        result = add(result, scale(term["interval"], term["coefficient"]))
    return result


def difference(a, b):
    """Coefficientes communes ante fines computandos subtrahuntur."""
    validate_expression(a)
    validate_expression(b)
    return _difference_validated(a, b)


def _difference_validated(a, b):
    """Expressiones aut recens computatae aut iam probatae sunt."""
    if a["status"] == "unknown" or b["status"] == "unknown":
        return None
    if a["id"] == b["id"]:
        if a != b:
            error("inconsistent_interpretation_identity")
        return interval(0, 0)
    result = add(b["base"], scale(a["base"], -1))
    terms = {}
    for expression, sign in ((a, -1), (b, 1)):
        for term in expression["terms"]:
            old = terms.setdefault(term["id"], {"interval": term["interval"], "coefficient": 0})
            if old["interval"] != term["interval"]:
                error("inconsistent_shared_error")
            old["coefficient"] += sign * term["coefficient"]
    for term in terms.values():
        result = add(result, scale(term["interval"], term["coefficient"]))
    return result


def _pair_variable_count(a, b):
    """Variabiles communes semel, bases independentes separatim numerantur."""
    if a["status"] == "unknown" or b["status"] == "unknown" or a["id"] == b["id"]:
        return 0
    shared = {term["id"] for expression in (a, b) for term in expression["terms"] if term["coefficient"] != 0}
    local = sum(expression["base"]["lo_us"] != expression["base"]["hi_us"] for expression in (a, b))
    return len(shared) + local


def interval_verdict(value, window_us):
    width = microseconds(window_us, MAX_WINDOW_US)
    if width < 0:
        error("negative_order_window")
    validate_interval(value)
    if value is None:
        return "unknown"
    if width == 0:
        return "ruled_out"
    wanted = interval(0, width, False, True)
    return "entailed" if contains(wanted, value) else "ruled_out" if not intersects(wanted, value) else "unresolved"


def ordered_within(a, b, window_us):
    result = difference(a, b)
    verdict = interval_verdict(result, window_us)
    return {"verdict": verdict, "difference": result,
            "reasons": sorted(set(a["reasons"] + b["reasons"])) if result is None else [],
            "assumption_ids": sorted(set(a["assumption_ids"] + b["assumption_ids"]))}
