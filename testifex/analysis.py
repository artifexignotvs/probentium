"""Ordo temporum indicium est, non causa."""

from collections import defaultdict
import hashlib
import json
import math
import re

SCHEMA = "testifex.analysis.v1"
MAX_EVENTS = 100_000
MAX_SOURCES = 10_000
MAX_FINDINGS = 20_000
MAX_RELATIONS = 250_000
MAX_BYTES = 64 * 1024 * 1024
MAX_WINDOW = 365 * 86400 * 1_000_000
MIN_INT, MAX_INT = -(2**63), 2**63 - 1
KINDS = {"auth.failure", "auth.success", "process.exec", "file.observed", "file.changed", "network.connect", "generic"}
BASE_LIMITATIONS = [
    "Temporal proximity does not prove causality, compromise or session membership.",
    "Absence of an event does not establish collection completeness or an activity gap.",
    "Time intervals depend on supplied timestamps and declared clock corrections; clock accuracy is not independently verified.",
    "Counts refer to matching records, not independently established attempts; overlapping collections can record the same activity more than once.",
    "A logged command or process record does not establish successful execution or completion.",
]


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def integer(value, low=MIN_INT, high=MAX_INT, nullable=False):
    if value is None and nullable:
        return None
    if type(value) is not int or not low <= value <= high:
        raise ValueError("invalid_integer")
    return value


def text(value, limit=4096, nullable=False):
    if value is None and nullable:
        return None
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError("invalid_text")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ValueError("invalid_text") from None
    return value


def identifier(value):
    value = text(value, 256)
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", value):
        raise ValueError("invalid_identifier")
    return value


def sha256(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError("invalid_digest")
    return value


def bounded_json(value, depth=0, budget=None):
    """Arbor finita ante serializationem probatur."""
    budget = [0] if budget is None else budget
    budget[0] += 1
    if depth > 8 or budget[0] > 2048:
        raise ValueError("json_bounds_exceeded")
    if value is None or type(value) is bool:
        return value
    if isinstance(value, str):
        return text(value)
    if type(value) is int:
        return integer(value)
    if type(value) is float and math.isfinite(value):
        return value
    if isinstance(value, list) and len(value) <= 256:
        return [bounded_json(x, depth + 1, budget) for x in value]
    if isinstance(value, dict) and len(value) <= 64:
        return {text(k, 128): bounded_json(v, depth + 1, budget) for k, v in value.items()}
    raise ValueError("invalid_json_value")


def bounds(low, high):
    integer(low, nullable=True); integer(high, nullable=True)
    if (low is None) != (high is None) or (low is not None and low > high):
        raise ValueError("invalid_time_interval")
    return low, high


def source_options(value):
    fields = {"clock_offset_us", "clock_error_us", "correction_reason", "declared_start_us", "declared_end_us"}
    if not isinstance(value, dict) or set(value) - fields:
        raise ValueError("invalid_source_options")
    result = {"clock_offset_us": integer(value.get("clock_offset_us", 0), -MAX_WINDOW, MAX_WINDOW),
              "clock_error_us": integer(value.get("clock_error_us", 0), 0, MAX_WINDOW),
              "correction_reason": text(value.get("correction_reason", "")),
              "declared_start_us": value.get("declared_start_us"), "declared_end_us": value.get("declared_end_us")}
    bounds(result["declared_start_us"], result["declared_end_us"])
    if (result["clock_offset_us"] or result["clock_error_us"]) and not result["correction_reason"].strip():
        raise ValueError("clock_correction_reason_required")
    return result


def normalize_sources(sources):
    if not isinstance(sources, list) or len(sources) > MAX_SOURCES:
        raise ValueError("source_bounds_exceeded")
    result, ids, digests = [], set(), set()
    for item in sources:
        if not isinstance(item, dict):
            raise ValueError("invalid_source")
        sid, digest = identifier(item.get("id")), sha256(item.get("sha256"))
        if sid in ids:
            raise ValueError("duplicate_source_id")
        if digest in digests:
            raise ValueError("conflicting_source_versions")
        ids.add(sid); digests.add(digest)
        fmt, status = item.get("format"), item.get("status")
        if fmt not in ("auth", "journal", "events") or status not in ("pending", "complete", "incomplete", "interrupted"):
            raise ValueError("invalid_source")
        label = text(item.get("label", ""))
        if label.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", label):
            label = re.split(r"[\\/]", label)[-1]
        source = {"id": sid, "label": label, "sha256": digest, "size": integer(item.get("size"), 0),
                  "format": fmt, "parser_version": text(item.get("parser_version"), 128),
                  "options": source_options(item.get("options", {})), "status": status}
        for key in ("lines_total", "parsed_count", "ignored_count", "error_count", "cursor", "last_line"):
            source[key] = integer(item.get(key), 0)
        if source["cursor"] > source["size"] or source["last_line"] > source["lines_total"]:
            raise ValueError("inconsistent_source_counters")
        if sum(source[k] for k in ("parsed_count", "ignored_count", "error_count")) != source["lines_total"]:
            raise ValueError("inconsistent_source_counters")
        if status in ("complete", "incomplete") and source["cursor"] != source["size"]:
            raise ValueError("inconsistent_source_completion")
        if status == "complete" and source["error_count"]:
            raise ValueError("inconsistent_source_completion")
        source["observed_low_us"], source["observed_high_us"] = bounds(item.get("observed_low_us"), item.get("observed_high_us"))
        meta = item.get("source_metadata", {})
        if not isinstance(meta, dict):
            raise ValueError("invalid_source_metadata")
        copied = meta.get("copied_sha256", digest)
        if sha256(copied) != digest:
            raise ValueError("source_digest_mismatch")
        acquisition = meta.get("acquisition", "not_declared")
        if acquisition not in ("copied-regular-file", "not_declared"):
            raise ValueError("invalid_acquisition_method")
        source["source_metadata"] = {"acquisition": acquisition, "copied_sha256": copied}
        result.append(source)
    return sorted(result, key=lambda x: x["id"])


EVENT_KEYS = {"id", "source_id", "ordinal", "offset", "length", "raw_sha256", "kind", "time_raw", "time_low_us", "time_high_us", "time_basis", "host", "actor", "src_ip", "dst_ip", "path", "action", "attributes", "original_low_us", "original_high_us", "clock_offset_us", "clock_error_us"}


def event_key(event):
    return (event["time_low_us"] is None, event["time_low_us"] or 0, event["time_high_us"] or 0, event["id"])


def normalize_events(events, sources, maximum):
    source_map = {s["id"]: s for s in sources}
    result, ids, ordinals, size = [], set(), set(), 0
    try:
        records = iter(events)
    except TypeError:
        raise ValueError("invalid_events") from None
    for index, item in enumerate(records):
        if index >= maximum:
            raise ValueError("event_bounds_exceeded")
        if not isinstance(item, dict):
            raise ValueError("invalid_event")
        event = {"id": identifier(item.get("id")), "source_id": identifier(item.get("source_id")),
                 "ordinal": integer(item.get("ordinal"), 1), "offset": integer(item.get("offset"), 0),
                 "length": integer(item.get("length"), 0, 1024 * 1024), "raw_sha256": sha256(item.get("raw_sha256"))}
        if event["id"] in ids or (event["source_id"], event["ordinal"]) in ordinals:
            raise ValueError("duplicate_event")
        ids.add(event["id"]); ordinals.add((event["source_id"], event["ordinal"]))
        if event["source_id"] not in source_map:
            raise ValueError("unknown_event_source")
        source = source_map[event["source_id"]]
        if event["offset"] + event["length"] > source["cursor"] or event["ordinal"] > source["last_line"]:
            raise ValueError("event_outside_source")
        if not isinstance(item.get("kind"), str) or item["kind"] not in KINDS:
            raise ValueError("invalid_event_kind")
        event["kind"] = item["kind"]
        event["time_low_us"], event["time_high_us"] = bounds(item.get("time_low_us"), item.get("time_high_us"))
        for key in ("time_raw", "host", "actor", "src_ip", "dst_ip", "path", "action"):
            event[key] = text(item.get(key), nullable=True)
        event["time_basis"] = text(item.get("time_basis"), 128)
        attrs = item.get("attributes", {})
        if not isinstance(attrs, dict):
            raise ValueError("invalid_event_attributes")
        event["attributes"] = bounded_json(attrs)
        event["original_low_us"], event["original_high_us"] = bounds(item.get("original_low_us", event["time_low_us"]), item.get("original_high_us", event["time_high_us"]))
        for key in ("clock_offset_us", "clock_error_us"):
            event[key] = integer(item.get(key, 0), 0 if key == "clock_error_us" else -MAX_WINDOW, MAX_WINDOW)
            if event[key] != source["options"][key]:
                raise ValueError("event_clock_config_mismatch")
        if (event["original_low_us"] is None) != (event["time_low_us"] is None):
            raise ValueError("event_clock_interval_mismatch")
        if event["time_low_us"] is not None:
            low = event["original_low_us"] - event["clock_offset_us"] - event["clock_error_us"]
            high = event["original_high_us"] - event["clock_offset_us"] + event["clock_error_us"]
            if (low, high) != (event["time_low_us"], event["time_high_us"]):
                raise ValueError("event_clock_interval_mismatch")
            if source["observed_low_us"] is None or low < source["observed_low_us"] or high > source["observed_high_us"]:
                raise ValueError("event_outside_observed_span")
        size += len(canonical(event))
        if size > MAX_BYTES:
            raise ValueError("event_bytes_exceeded")
        result.append(event)
    return sorted(result, key=event_key)


class _Intervals:
    """Rami impossibiles sine enumeratione omittuntur."""

    def __init__(self, events):
        self.events = sorted(events, key=event_key)
        self.size = 1
        while self.size < len(self.events):
            self.size *= 2
        self.low = [None] * (2 * self.size)
        self.high = [None] * (2 * self.size)
        for i, event in enumerate(self.events, self.size):
            self.low[i], self.high[i] = event["time_low_us"], event["time_high_us"]
        for i in range(self.size - 1, 0, -1):
            vals = [j for j in (2*i, 2*i+1) if self.low[j] is not None]
            if vals:
                self.low[i] = min(self.low[j] for j in vals)
                self.high[i] = max(self.high[j] for j in vals)

    def query(self, minimum_high, maximum_low):
        stack = [1]
        while stack:
            i = stack.pop()
            if self.low[i] is None or self.low[i] > maximum_low or self.high[i] < minimum_high:
                continue
            if i >= self.size:
                yield self.events[i - self.size]
            else:
                stack.extend((2*i+1, 2*i))


def _relation(before, after, window):
    al, ah = before["time_low_us"], before["time_high_us"]
    bl, bh = after["time_low_us"], after["time_high_us"]
    if al > bh or bl - ah > window:
        return None, []
    reasons = []
    if ah >= bl:
        reasons.append("overlapping_time_intervals")
    if bh - al > window:
        reasons.append("uncertain_window_boundary")
    return ("possible" if reasons else "certain"), reasons


def _finding(rule, anchors, evidence, events, details):
    digest = hashlib.sha256(canonical({"rule": rule, "anchors": anchors}).encode()).hexdigest()
    anchor = events[-1]
    return {"id": digest, "rule_id": rule, "title": "Authentication success after repeated failures" if rule == "auth_after_failures" else "Process or command record near authentication success",
            "host": anchor["host"], "actor": anchor["actor"], "src_ip": events[-1 if rule == "auth_after_failures" else 0]["src_ip"],
            "ordering": "possible" if any(x["relation"] == "possible" for x in evidence) else "certain",
            "time_low_us": min(x["time_low_us"] for x in events), "time_high_us": max(x["time_high_us"] for x in events),
            "event_ids": [x["event_id"] for x in evidence], "evidence": evidence, "details": details,
            "limitation": "Temporal lead only; no causal or session attribution."}


def analyze(events, sources, *, window_us=300_000_000, threshold=5, max_events=MAX_EVENTS):
    integer(window_us, 1, MAX_WINDOW); integer(threshold, 1, MAX_EVENTS); integer(max_events, 1, MAX_EVENTS)
    sources = normalize_sources(sources)
    events = normalize_events(events, sources, max_events)
    by_source, failures, processes, successes = defaultdict(list), defaultdict(list), defaultdict(list), []
    missing_keys = 0
    for event in events:
        by_source[event["source_id"]].append(event)
        if event["time_low_us"] is None:
            continue
        required = ("host", "actor", "src_ip") if event["kind"] == "auth.failure" else ("host", "actor")
        if event["kind"] in {"auth.failure", "auth.success", "process.exec"} and any(not event[k] or not event[k].strip() for k in required):
            missing_keys += 1
            continue
        if event["kind"] == "auth.failure":
            failures[tuple(event[k] for k in ("host", "actor", "src_ip"))].append(event)
        elif event["kind"] == "auth.success":
            if not event["src_ip"] or not event["src_ip"].strip():
                missing_keys += 1
            successes.append(event)
        elif event["kind"] == "process.exec":
            processes[(event["host"], event["actor"])].append(event)
    failure_indexes = {key: _Intervals(value) for key, value in failures.items()}
    process_indexes = {key: _Intervals(value) for key, value in processes.items()}
    findings, conflicts, used_relations, used_evidence = [], set(), 0, 0

    def relation(before, after):
        nonlocal used_relations
        used_relations += 1
        if used_relations > MAX_RELATIONS:
            raise ValueError("analysis_relations_exceeded")
        order, reasons = _relation(before, after, window_us)
        for reason in reasons:
            conflicts.add((before["id"], after["id"], reason))
        return order

    def append(finding):
        nonlocal used_evidence
        used_evidence += len(finding["evidence"])
        if used_evidence > MAX_RELATIONS:
            raise ValueError("analysis_evidence_exceeded")
        if len(findings) >= MAX_FINDINGS:
            raise ValueError("analysis_findings_exceeded")
        findings.append(finding)

    for success in successes:
        index = failure_indexes.get(tuple(success[k] for k in ("host", "actor", "src_ip")))
        matched, evidence = [], []
        if index:
            for failure in index.query(success["time_low_us"] - window_us, success["time_high_us"]):
                order = relation(failure, success)
                if order:
                    matched.append(failure); evidence.append({"event_id": failure["id"], "role": "failure", "relation": order})
        if len(matched) >= threshold:
            certain = sum(x["relation"] == "certain" for x in evidence)
            evidence.append({"event_id": success["id"], "role": "success", "relation": "anchor"})
            append(_finding("auth_after_failures", [success["id"]], evidence, matched + [success], {"failure_count": len(matched), "certain_failure_count": certain, "threshold": threshold, "threshold_status": "certain" if certain >= threshold else "possible", "window_us": window_us}))
        index = process_indexes.get((success["host"], success["actor"]))
        if index:
            for process in index.query(success["time_low_us"], success["time_high_us"] + window_us):
                order = relation(success, process)
                if order:
                    append(_finding("post_auth_process", [success["id"], process["id"]], [{"event_id": success["id"], "role": "success", "relation": "anchor"}, {"event_id": process["id"], "role": "process", "relation": order}], [success, process], {"window_us": window_us}))
    coverage = []
    for source in sources:
        subset = by_source[source["id"]]
        if len(subset) > source["parsed_count"]:
            raise ValueError("inconsistent_included_event_count")
        timed = [x for x in subset if x["time_low_us"] is not None]
        low = min((x["time_low_us"] for x in timed), default=None)
        high = max((x["time_high_us"] for x in timed), default=None)
        start, end = source["options"]["declared_start_us"], source["options"]["declared_end_us"]
        span = "not_declared" if start is None else "no_known_times" if low is None else "extends_outside_declaration" if low < start or high > end else "within_declared_bounds"
        coverage.append({"source_id": source["id"], "status": source["status"], **{k: source[k] for k in ("lines_total", "parsed_count", "ignored_count", "error_count")}, "included_events": len(subset), "known_time_events": len(timed), "unknown_time_events": len(subset)-len(timed), "observed_low_us": low, "observed_high_us": high, "declared_start_us": start, "declared_end_us": end, "span_relation": span, "declaration": "not_declared" if start is None else "analyst_assertion", "collection_completeness": "unknown"})
        ordered = sorted(timed, key=lambda x: x["ordinal"])
        for first, second in zip(ordered, ordered[1:]):
            if first["time_low_us"] > second["time_high_us"]:
                conflicts.add((first["id"], second["id"], "source_sequence_time_reversal"))
    if len(conflicts) > MAX_RELATIONS:
        raise ValueError("analysis_conflicts_exceeded")
    limitations = list(BASE_LIMITATIONS)
    unknown = sum(x["time_low_us"] is None for x in events)
    if unknown:
        limitations.append("Events with unknown time cannot establish a temporal link.")
    if missing_keys:
        limitations.append("Events missing required host, actor or source address identifiers are excluded from the corresponding temporal rules.")
    if any(x["status"] != "complete" or x["error_count"] for x in sources):
        limitations.append("At least one source is partial, pending, interrupted or contains parsing errors.")
    if any(x["included_events"] != x["parsed_count"] for x in coverage):
        limitations.append("Included event counts differ from source parser counts; this report may represent a subset.")
    if any(x["declaration"] == "analyst_assertion" for x in coverage):
        limitations.append("Declared time spans are analyst assertions, not verified collection coverage.")
    return {"schema": SCHEMA, "findings": sorted(findings, key=lambda x: (x["time_low_us"], x["time_high_us"], x["id"])),
            "coverage": {"sources": coverage, "event_count": len(events), "known_time_events": len(events)-unknown, "unknown_time_events": unknown, "missing_identifier_events": missing_keys, "collection_completeness": "unknown"},
            "ordering_conflicts": [{"event_ids": [a, b], "reason": reason} for a, b, reason in sorted(conflicts)], "limitations": limitations,
            "config": {"window_us": window_us, "threshold": threshold, "max_events": max_events, "rule_version": "1"}}
