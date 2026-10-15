"""Testimonia servantur; secreta consulto subtrahuntur."""

import hashlib
import hmac
import re
import unicodedata

from .analysis import (MAX_BYTES, MAX_EVENTS, MAX_FINDINGS, MAX_RELATIONS, MAX_SOURCES,
                       analyze, bounded_json, canonical, identifier, integer,
                       normalize_events, normalize_sources, text)

SCHEMA = "testifex.report.v1"
PUBLIC_SCHEMA = "testifex.public.v1"
REPORT_LIMITATIONS = [
    "Source and record digests support consistency checks against retained evidence; they do not prove authorship or acquisition time.",
    "The report describes supplied records. Source completeness and clock accuracy are not independently established.",
]
PUBLIC_LIMITATIONS = [
    "Pseudonymized, not anonymous: timestamps, counts, ordering and repeated identifiers can permit correlation.",
    "A shared export key creates stable links across exports; keep that key private.",
    "Digest pseudonyms preserve internal links but cannot independently verify the original evidence bytes.",
    "Temporal proximity does not prove causality, compromise or session membership.",
    "Collection completeness and clock accuracy remain unverified.",
    "Matching record counts do not establish independent attempts; a logged command does not establish successful execution.",
]


def _shape(value, depth=0, budget=None):
    """Forma et magnitudo ante comparationem finiuntur."""
    budget = [0, 0] if budget is None else budget
    budget[0] += 1
    if depth > 16 or budget[0] > 4_000_000 or budget[1] > MAX_BYTES:
        raise ValueError("report_bounds_exceeded")
    if isinstance(value, str):
        text(value); budget[1] += len(value.encode("utf-8"))
    elif isinstance(value, dict):
        if len(value) > 128:
            raise ValueError("report_bounds_exceeded")
        for key, item in value.items():
            text(key, 128); budget[1] += len(key)
            _shape(item, depth+1, budget)
    elif isinstance(value, list):
        if len(value) > MAX_RELATIONS:
            raise ValueError("report_bounds_exceeded")
        for item in value:
            _shape(item, depth+1, budget)
    elif value is not None:
        bounded_json(value)


def _exact(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError("invalid_report_schema")


def _case(value):
    if not isinstance(value, dict):
        raise ValueError("invalid_case_metadata")
    version = integer(value.get("schema_version"), 1, 1)
    return {"schema_version": version, "tool_version": text(value.get("tool_version"), 128),
            "case_id": identifier(value.get("case_id")), "name": text(value.get("name", ""))}


def _hypotheses(items, events):
    if not isinstance(items, list) or len(items) > 10_000:
        raise ValueError("hypothesis_bounds_exceeded")
    known = {e["id"] for e in events}
    result, seen, references = [], set(), 0
    for item in items:
        _exact(item, {"id", "title", "status", "assumptions", "evidence"})
        hid = identifier(item["id"])
        if hid in seen:
            raise ValueError("duplicate_hypothesis")
        seen.add(hid)
        if item["status"] not in ("open", "supported", "refuted", "inconclusive"):
            raise ValueError("invalid_hypothesis_status")
        if not isinstance(item["assumptions"], list) or len(item["assumptions"]) > 32:
            raise ValueError("hypothesis_bounds_exceeded")
        if not isinstance(item["evidence"], list) or len(item["evidence"]) > MAX_EVENTS:
            raise ValueError("hypothesis_bounds_exceeded")
        evidence, links = [], set()
        for entry in item["evidence"]:
            references += 1
            if references > MAX_RELATIONS:
                raise ValueError("hypothesis_bounds_exceeded")
            _exact(entry, {"event_id", "stance", "note"})
            eid, stance = identifier(entry["event_id"]), entry["stance"]
            if eid not in known or stance not in ("supports", "contradicts", "context"):
                raise ValueError("invalid_hypothesis_reference")
            if (eid, stance) in links:
                raise ValueError("duplicate_hypothesis_reference")
            links.add((eid, stance))
            evidence.append({"event_id": eid, "stance": stance, "note": text(entry["note"])})
        result.append({"id": hid, "title": text(item["title"]), "status": item["status"],
                       "assumptions": [text(x) for x in item["assumptions"]],
                       "evidence": sorted(evidence, key=lambda x: (x["event_id"], x["stance"]))})
    return sorted(result, key=lambda x: x["id"])


def _config(analysis):
    if not isinstance(analysis, dict):
        raise ValueError("invalid_analysis_schema")
    config = analysis.get("config")
    _exact(config, {"window_us", "threshold", "max_events", "rule_version"})
    if config["rule_version"] != "1":
        raise ValueError("unsupported_rule_version")
    return {k: config[k] for k in ("window_us", "threshold", "max_events")}


def make_report(case_metadata, sources, events, analysis, hypotheses):
    _shape(analysis)
    config = _config(analysis)
    normalized_sources = normalize_sources(sources)
    normalized_events = normalize_events(events, normalized_sources, integer(config["max_events"], 1, MAX_EVENTS))
    expected = analyze(normalized_events, normalized_sources, **config)
    if canonical(expected) != canonical(analysis):
        raise ValueError("analysis_does_not_match_evidence")
    report = {"schema": SCHEMA, "case": _case(case_metadata), "sources": normalized_sources,
              "events": normalized_events, "analysis": expected,
              "hypotheses": _hypotheses(hypotheses, normalized_events), "limitations": list(REPORT_LIMITATIONS)}
    if len(canonical(report).encode()) > MAX_BYTES:
        raise ValueError("report_bytes_exceeded")
    return report


def validate_report(report):
    _shape(report)
    _exact(report, {"schema", "case", "sources", "events", "analysis", "hypotheses", "limitations"})
    if report["schema"] != SCHEMA:
        raise ValueError("unsupported_report_schema")
    if not isinstance(report["events"], list):
        raise ValueError("invalid_report_events")
    expected = make_report(report["case"], report["sources"], report["events"], report["analysis"], report["hypotheses"])
    if canonical(report) != canonical(expected):
        raise ValueError("noncanonical_or_unknown_report_fields")
    return expected


def _delta(before, after, key="id"):
    old, new = {x[key]: x for x in before}, {x[key]: x for x in after}
    return {"added": [new[k] for k in sorted(new.keys()-old.keys())],
            "removed": [old[k] for k in sorted(old.keys()-new.keys())],
            "changed": [{"id": k, "before": old[k], "after": new[k],
                         "fields": [f for f in sorted(set(old[k]) | set(new[k])) if old[k].get(f) != new[k].get(f)]}
                        for k in sorted(old.keys() & new.keys()) if old[k] != new[k]]}


def compare_reports(before, after):
    before, after = validate_report(before), validate_report(after)
    findings = _delta(before["analysis"]["findings"], after["analysis"]["findings"])
    sources = _delta(before["sources"], after["sources"])
    events = _delta(before["events"], after["events"])
    hypotheses = _delta(before["hypotheses"], after["hypotheses"])
    config_changes = [{"field": k, "before": before["analysis"]["config"][k], "after": after["analysis"]["config"][k]}
                      for k in sorted(before["analysis"]["config"]) if before["analysis"]["config"][k] != after["analysis"]["config"][k]]
    parser_changes = []
    old = {s["sha256"]: s for s in before["sources"]}
    new = {s["sha256"]: s for s in after["sources"]}
    for digest in sorted(old.keys() & new.keys()):
        fields = [k for k in ("format", "parser_version", "options") if old[digest][k] != new[digest][k]]
        if fields:
            parser_changes.append({"source_sha256": digest, "before_source_id": old[digest]["id"], "after_source_id": new[digest]["id"], "fields": fields,
                                   "before": {k: old[digest][k] for k in fields}, "after": {k: new[digest][k] for k in fields}})
    reasons = []
    for name, delta in (("source_set_or_provenance_changed", sources), ("event_evidence_changed", events), ("hypotheses_changed", hypotheses)):
        if any(delta.values()):
            reasons.append(name)
    if config_changes:
        reasons.append("analysis_configuration_changed")
    if parser_changes:
        reasons.append("parser_or_source_options_changed")
    case_changed = before["case"] != after["case"]
    if case_changed:
        reasons.append("case_metadata_changed")
    for group in (findings["changed"],):
        for item in group:
            item["reasons"] = list(reasons) or ["finding_changed"]
    result = {"schema": "testifex.report-delta.v1", "status": "different" if before != after else "same",
            "before_report_sha256": hashlib.sha256(canonical(before).encode()).hexdigest(),
            "after_report_sha256": hashlib.sha256(canonical(after).encode()).hexdigest(),
            "findings": findings, "sources": sources, "events": events, "hypotheses": hypotheses,
            "config_changes": config_changes, "parser_changes": parser_changes, "case_changed": case_changed,
            "reasons": reasons,
            "limitations": ["Added or removed findings can result from changed evidence, parser options or rule configuration; they do not prove onset or resolution of an incident.", "Matching reports establish equality of these report structures, not completeness or independent authenticity of the underlying evidence."]}
    if len(canonical(result).encode()) > MAX_BYTES:
        raise ValueError("report_delta_bytes_exceeded")
    return result


def share_report(report, key):
    report = validate_report(report)
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("public_export_requires_32_byte_key")

    def token(kind, value):
        if value is None or (kind in {"host", "actor", "ip"} and not value.strip()):
            return None
        message = canonical(["testifex.public.v1", kind, value]).encode()
        return kind + "_" + hmac.new(key, message, hashlib.sha256).hexdigest()

    sources = []
    for source in report["sources"]:
        sources.append({"id": token("source", source["id"]), "digest_id": token("digest", source["sha256"]),
                        "size": source["size"], "format": source["format"], "parser_version_id": token("parser", source["parser_version"]),
                        "status": source["status"], **{k: source[k] for k in ("lines_total", "parsed_count", "ignored_count", "error_count", "cursor", "last_line", "observed_low_us", "observed_high_us")},
                        "clock_offset_us": source["options"]["clock_offset_us"], "clock_error_us": source["options"]["clock_error_us"],
                        "declared_start_us": source["options"]["declared_start_us"], "declared_end_us": source["options"]["declared_end_us"]})
    events = []
    for event in report["events"]:
        item = {"id": token("event", event["id"]), "source_id": token("source", event["source_id"]), "record_digest_id": token("digest", event["raw_sha256"]),
                **{k: event[k] for k in ("kind", "ordinal", "offset", "length", "time_low_us", "time_high_us", "original_low_us", "original_high_us", "clock_offset_us", "clock_error_us")}}
        for field, kind in (("host", "host"), ("actor", "actor"), ("src_ip", "ip"), ("dst_ip", "ip"), ("path", "path"), ("action", "action")):
            item[field] = token(kind, event[field])
        events.append(item)
    findings = []
    for finding in report["analysis"]["findings"]:
        findings.append({"id": token("finding", finding["id"]), "rule_id": finding["rule_id"], "ordering": finding["ordering"],
                         "host": token("host", finding["host"]), "actor": token("actor", finding["actor"]), "src_ip": token("ip", finding["src_ip"]),
                         "time_low_us": finding["time_low_us"], "time_high_us": finding["time_high_us"], "details": dict(finding["details"]),
                         "event_ids": [token("event", x) for x in finding["event_ids"]],
                         "evidence": [{"event_id": token("event", x["event_id"]), "role": x["role"], "relation": x["relation"]} for x in finding["evidence"]]})
    hypotheses = [{"id": token("hypothesis", h["id"]), "status": h["status"], "evidence": [{"event_id": token("event", x["event_id"]), "stance": x["stance"]} for x in h["evidence"]]} for h in report["hypotheses"]]
    coverage = {k: v for k, v in report["analysis"]["coverage"].items() if k != "sources"}
    coverage["sources"] = [{**x, "source_id": token("source", x["source_id"])} for x in report["analysis"]["coverage"]["sources"]]
    result = {"schema": PUBLIC_SCHEMA, "case_id": token("case", report["case"]["case_id"]),
              "source_report_id": token("report", hashlib.sha256(canonical(report).encode()).hexdigest()),
              "sources": sources, "events": events, "findings": findings, "hypotheses": hypotheses,
              "coverage": coverage, "config": dict(report["analysis"]["config"]),
              "ordering_conflicts": [{"event_ids": [token("event", x) for x in c["event_ids"]], "reason": c["reason"]} for c in report["analysis"]["ordering_conflicts"]],
              "withheld": {"case_names": 1, "source_labels": len(sources), "source_metadata_records": len(sources), "event_attribute_records": len(events), "raw_timestamp_fields": len(events), "finding_titles": len(findings), "hypothesis_titles": len(hypotheses), "hypothesis_assumptions": sum(len(h["assumptions"]) for h in report["hypotheses"]), "evidence_notes": sum(len(h["evidence"]) for h in report["hypotheses"]), "original_identifiers_and_digests": "replaced_with_typed_hmac_sha256_pseudonyms"},
              "limitations": list(PUBLIC_LIMITATIONS)}
    if len(canonical(result).encode()) > MAX_BYTES:
        raise ValueError("public_report_bytes_exceeded")
    return result


def _safe(value):
    """Signa activa in textum inertem mutantur."""
    value = str(value)
    clean = "".join(c if c.isprintable() and unicodedata.category(c) not in {"Cf", "Cs"} else "\\u%04x" % ord(c) for c in value)
    return "".join(c if c.isalnum() or c in " -_.,:/" else "&#%d;" % ord(c) for c in clean)


def _public_for_render(report):
    _shape(report)
    _exact(report, {"schema", "case_id", "source_report_id", "sources", "events", "findings", "hypotheses", "coverage", "config", "ordering_conflicts", "withheld", "limitations"})
    if report["schema"] != PUBLIC_SCHEMA or report["limitations"] != PUBLIC_LIMITATIONS:
        raise ValueError("invalid_public_report")
    def pseudonym(value, prefix, nullable=False):
        if nullable and value is None:
            return None
        if not isinstance(value, str) or not re.fullmatch(prefix + r"_[a-f0-9]{64}", value):
            raise ValueError("invalid_public_report")
        return value

    pseudonym(report["case_id"], "case"); pseudonym(report["source_report_id"], "report")
    for field, limit in (("sources", MAX_SOURCES), ("events", MAX_EVENTS), ("findings", MAX_FINDINGS), ("hypotheses", 10_000), ("ordering_conflicts", MAX_RELATIONS)):
        if not isinstance(report[field], list) or len(report[field]) > limit:
            raise ValueError("invalid_public_report")
    config = _config({"config": report["config"]})
    sources = []
    source_fields = {"id", "digest_id", "size", "format", "parser_version_id", "status", "lines_total", "parsed_count", "ignored_count", "error_count", "cursor", "last_line", "observed_low_us", "observed_high_us", "clock_offset_us", "clock_error_us", "declared_start_us", "declared_end_us"}
    for source in report["sources"]:
        _exact(source, source_fields)
        pseudonym(source["id"], "source"); pseudonym(source["digest_id"], "digest"); pseudonym(source["parser_version_id"], "parser")
        sources.append({"id": source["id"], "label": "", "sha256": source["digest_id"][7:], "size": source["size"], "format": source["format"], "parser_version": source["parser_version_id"], "status": source["status"],
                        **{k: source[k] for k in ("lines_total", "parsed_count", "ignored_count", "error_count", "cursor", "last_line", "observed_low_us", "observed_high_us")},
                        "options": {**{k: source[k] for k in ("clock_offset_us", "clock_error_us", "declared_start_us", "declared_end_us")}, "correction_reason": "Withheld"}})
    event_fields = {"id", "source_id", "record_digest_id", "kind", "ordinal", "offset", "length", "time_low_us", "time_high_us", "original_low_us", "original_high_us", "clock_offset_us", "clock_error_us", "host", "actor", "src_ip", "dst_ip", "path", "action"}
    events = []
    for event in report["events"]:
        _exact(event, event_fields)
        pseudonym(event["id"], "event"); pseudonym(event["source_id"], "source"); pseudonym(event["record_digest_id"], "digest")
        for field, prefix in (("host", "host"), ("actor", "actor"), ("src_ip", "ip"), ("dst_ip", "ip"), ("path", "path"), ("action", "action")):
            pseudonym(event[field], prefix, True)
        events.append({k: v for k, v in event.items() if k != "record_digest_id"} | {"raw_sha256": event["record_digest_id"][7:], "time_raw": None, "time_basis": "withheld", "attributes": {}})
    expected = analyze(events, sources, **config)
    coverage = dict(report["coverage"]) if isinstance(report["coverage"], dict) else {}
    if not isinstance(coverage.get("sources"), list) or any(not isinstance(x, dict) or "source_id" not in x for x in coverage["sources"]):
        raise ValueError("invalid_public_coverage")
    coverage["sources"] = sorted(coverage["sources"], key=lambda x: pseudonym(x["source_id"], "source"))
    if canonical(coverage) != canonical(expected["coverage"]):
        raise ValueError("public_coverage_mismatch")
    projected = []
    finding_fields = {"id", "rule_id", "ordering", "host", "actor", "src_ip", "time_low_us", "time_high_us", "details", "event_ids", "evidence"}
    seen = set()
    for finding in report["findings"]:
        _exact(finding, finding_fields)
        fid = pseudonym(finding["id"], "finding")
        if fid in seen:
            raise ValueError("duplicate_public_finding")
        seen.add(fid)
        projected.append({k: v for k, v in finding.items() if k != "id"})
    expected_findings = [{k: v for k, v in f.items() if k in finding_fields - {"id"}} for f in expected["findings"]]
    def comparable(finding):
        return canonical({**finding, "event_ids": sorted(finding["event_ids"]), "evidence": sorted(finding["evidence"], key=canonical)})

    try:
        equivalent = sorted(map(comparable, projected)) == sorted(map(comparable, expected_findings))
    except (KeyError, TypeError):
        raise ValueError("invalid_public_finding") from None
    if not equivalent:
        raise ValueError("public_findings_mismatch")
    if sorted(map(canonical, report["ordering_conflicts"])) != sorted(map(canonical, expected["ordering_conflicts"])):
        raise ValueError("public_ordering_conflicts_mismatch")
    hypotheses = []
    for hypothesis in report["hypotheses"]:
        _exact(hypothesis, {"id", "status", "evidence"})
        pseudonym(hypothesis["id"], "hypothesis")
        if not isinstance(hypothesis["evidence"], list) or len(hypothesis["evidence"]) > MAX_EVENTS:
            raise ValueError("invalid_public_hypothesis")
        evidence = []
        for item in hypothesis["evidence"]:
            _exact(item, {"event_id", "stance"}); pseudonym(item["event_id"], "event")
            evidence.append({**item, "note": ""})
        hypotheses.append({**hypothesis, "title": "", "assumptions": [], "evidence": evidence})
    _hypotheses(hypotheses, events)
    withheld_fields = {"case_names", "source_labels", "source_metadata_records", "event_attribute_records", "raw_timestamp_fields", "finding_titles", "hypothesis_titles", "hypothesis_assumptions", "evidence_notes", "original_identifiers_and_digests"}
    _exact(report["withheld"], withheld_fields)
    for key in withheld_fields - {"original_identifiers_and_digests"}:
        integer(report["withheld"][key], 0, MAX_RELATIONS * 32)
    if report["withheld"]["original_identifiers_and_digests"] != "replaced_with_typed_hmac_sha256_pseudonyms":
        raise ValueError("invalid_withheld_summary")
    for key, number in {"case_names": 1, "source_labels": len(sources), "source_metadata_records": len(sources), "event_attribute_records": len(events), "raw_timestamp_fields": len(events), "finding_titles": len(projected), "hypothesis_titles": len(hypotheses), "evidence_notes": sum(len(x["evidence"]) for x in hypotheses)}.items():
        if report["withheld"][key] != number:
            raise ValueError("invalid_withheld_summary")
    return report


def render_markdown(report):
    public = isinstance(report, dict) and report.get("schema") == PUBLIC_SCHEMA
    report = _public_for_render(report) if public else validate_report(report)
    analysis = report if public else report["analysis"]
    case = report["case_id"] if public else report["case"]["name"]
    lines = ["# Temporal evidence report", "", "Case: " + _safe(case), "", "This report presents temporal leads for review. It does not establish causality or session membership.", "", "## Sources", "", "| Source | Format | Status | Parsed / ignored / errors | Evidence digest |", "| --- | --- | --- | --- | --- |"]
    for source in report["sources"]:
        values = [source["id"], source["format"], source["status"], str(source["parsed_count"])+" / "+str(source["ignored_count"])+" / "+str(source["error_count"]), source["digest_id"] if public else source["sha256"]]
        lines.append("| " + " | ".join(_safe(x) for x in values) + " |")
    lines += ["", "## Coverage", "", "Collection completeness: unknown. Declared spans are assertions, not independently verified coverage.", "", "| Source | Included / known / unknown time | Observed UTC microsecond bounds | Declared UTC microsecond bounds | Span relation |", "| --- | --- | --- | --- | --- |"]
    for source in analysis["coverage"]["sources"]:
        values = [source["source_id"], str(source["included_events"])+" / "+str(source["known_time_events"])+" / "+str(source["unknown_time_events"]), str(source["observed_low_us"])+" .. "+str(source["observed_high_us"]), str(source["declared_start_us"])+" .. "+str(source["declared_end_us"]), source["span_relation"]]
        lines.append("| " + " | ".join(_safe(x) for x in values) + " |")
    lines += ["", "## Temporal leads", "", "Window: " + _safe(analysis["config"]["window_us"]) + " microseconds; failure threshold: " + _safe(analysis["config"]["threshold"]) + "; rule version: " + _safe(analysis["config"]["rule_version"]) + ".", ""]
    if not analysis["findings"]:
        lines.append("No matching temporal leads in the supplied evidence under this configuration. This is not a clean-state verdict.")
    for finding in analysis["findings"]:
        lines += ["### " + _safe(finding["rule_id"]), "", "Finding: " + _safe(finding["id"]), "", "Ordering/window membership: " + _safe(finding["ordering"]), "", "Host: " + _safe(finding["host"]) + "; actor: " + _safe(finding["actor"]), "", "Inclusive UTC microseconds: " + _safe(finding["time_low_us"]) + " .. " + _safe(finding["time_high_us"]), "", "Evidence:", ""]
        for item in finding["evidence"]:
            lines.append("- " + _safe(item["event_id"]) + " — " + _safe(item["role"]) + "; " + _safe(item["relation"]))
        if finding["rule_id"] == "auth_after_failures":
            details = finding["details"]
            lines += ["", "Matching failures: " + _safe(details["failure_count"]) + "; certain within-window predecessors: " + _safe(details["certain_failure_count"]) + "; threshold: " + _safe(details["threshold"]) + " (" + _safe(details["threshold_status"]) + ")."]
        lines.append("")
    if analysis["ordering_conflicts"]:
        lines += ["## Ordering qualifications", ""]
        for conflict in analysis["ordering_conflicts"]:
            lines.append("- " + _safe(conflict["reason"]) + ": " + ", ".join(_safe(x) for x in conflict["event_ids"]))
        lines.append("")
    if report["hypotheses"]:
        lines += ["## Analyst hypotheses", "", "Statuses are analyst assessments, not independent confirmation.", ""]
        for hypothesis in report["hypotheses"]:
            lines += ["### " + _safe(hypothesis["id"] if public else hypothesis["title"]), "", "Status: " + _safe(hypothesis["status"]), ""]
            if not public:
                lines += ["- Assumption: " + _safe(x) for x in hypothesis["assumptions"]]
            for item in hypothesis["evidence"]:
                lines.append("- " + _safe(item["event_id"]) + "; " + _safe(item["stance"]) + ("; note: " + _safe(item["note"]) if not public and item["note"] else ""))
            lines.append("")
    lines += ["## Limitations", ""]
    limitations = report["limitations"] + ([] if public else analysis["limitations"])
    lines += ["- " + _safe(x) for x in limitations]
    if public:
        lines += ["", "## Withheld fields", "", "Names, labels, titles, notes, assumptions, raw timestamps, attributes and acquisition metadata are withheld. Identifiers and digests are keyed pseudonyms; timing and structure remain visible."]
    return "\n".join(lines).rstrip() + "\n"
