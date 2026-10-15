"""Conspectus brevis, limites aperti, materia privata retenta."""

from .model import safe_text
from .report import validate_report

SCHEMA = "testifex.triage.v1"
MAX_FINDING_ROWS = 100
LIMITATIONS = [
    "Certain and possible describe ordering/window membership under supplied time bounds, not confidence in an incident.",
    "Temporal proximity does not prove causality, compromise or session membership.",
    "No findings is not a clean-state verdict; collection completeness remains unknown.",
    "This local overview is not a public-share export; counts and stable finding identifiers can permit correlation.",
]


def validate_limit(limit):
    """Numerus linearum ante analysim finitur."""
    if type(limit) is not int or not 1 <= limit <= MAX_FINDING_ROWS:
        raise ValueError("triage_limit_must_be_1_to_100")
    return limit


def summarize_report(report, *, limit=10):
    """Relatio probata in numeros et indices certos contrahitur."""
    validate_limit(limit)
    report = validate_report(report)
    analysis = report["analysis"]
    coverage = analysis["coverage"]
    sources = coverage["sources"]
    findings = analysis["findings"]
    statuses = {name: sum(source["status"] == name for source in sources)
                for name in ("complete", "incomplete", "interrupted", "pending")}
    items = []
    for finding in findings[:limit]:
        item = {"id": finding["id"], "rule_id": finding["rule_id"],
                "ordering": finding["ordering"], "evidence_records": len(finding["evidence"])}
        if finding["rule_id"] == "auth_after_failures":
            item["failures"] = {key: finding["details"][key] for key in
                                ("failure_count", "certain_failure_count", "threshold_status")}
        items.append(item)
    reasons = {reason: sum(item["reason"] == reason for item in analysis["ordering_conflicts"])
               for reason in ("overlapping_time_intervals", "uncertain_window_boundary", "source_sequence_time_reversal")}
    return {
        "schema": SCHEMA,
        "config": dict(analysis["config"]),
        "sources": {"total": len(sources), "statuses": statuses},
        "records": {name: sum(source[field] for source in sources) for name, field in
                    (("read", "lines_total"), ("parsed", "parsed_count"), ("ignored", "ignored_count"), ("errors", "error_count"))},
        "events": {"total": coverage["event_count"], "known_time": coverage["known_time_events"],
                   "unknown_time": coverage["unknown_time_events"], "missing_identifiers": coverage["missing_identifier_events"]},
        "coverage": {"collection_completeness": coverage["collection_completeness"],
                     "unfinished_sources": sum(source["status"] in ("pending", "interrupted") for source in sources),
                     "sources_with_errors": sum(source["error_count"] > 0 for source in sources),
                     "event_subset_sources": sum(source["included_events"] != source["parsed_count"] for source in sources),
                     "declared_span_sources": sum(source["declaration"] == "analyst_assertion" for source in sources),
                     "outside_declared_span_sources": sum(source["span_relation"] == "extends_outside_declaration" for source in sources)},
        "ordering_qualifications": {"total": len(analysis["ordering_conflicts"]), "reasons": reasons},
        "findings": {"total": len(findings), "certain": sum(item["ordering"] == "certain" for item in findings),
                     "possible": sum(item["ordering"] == "possible" for item in findings), "shown": len(items),
                     "omitted": len(findings) - len(items), "limit": limit, "items": items},
        "limitations": list(LIMITATIONS),
    }


def render_text(report, *, limit=10):
    """Textus terminalis ex indice clauso tantum componitur."""
    summary = summarize_report(report, limit=limit)
    sources, records, events = (summary[key] for key in ("sources", "records", "events"))
    states, coverage = sources["statuses"], summary["coverage"]
    findings, config = summary["findings"], summary["config"]
    lines = [
        "TESTIFEX / TRIAGE",
        f"Sources: {sources['total']} | complete {states['complete']} | incomplete {states['incomplete']}",
        f"         interrupted {states['interrupted']} | pending {states['pending']}",
        f"Records: {records['read']} read | {records['parsed']} parsed | {records['ignored']} ignored | {records['errors']} errors",
        f"Events: {events['total']} | known time {events['known_time']} | unknown time {events['unknown_time']}",
        f"        missing identifiers {events['missing_identifiers']} (required by temporal rules)",
        "Collection completeness: unknown",
        f"Coverage: {coverage['unfinished_sources']} unfinished sources | {coverage['sources_with_errors']} with errors | {coverage['event_subset_sources']} event subsets",
        f"Declared spans: {coverage['declared_span_sources']} | outside declaration {coverage['outside_declared_span_sources']}",
        f"Ordering qualifications: {summary['ordering_qualifications']['total']}",
        f"Rules: failure threshold {config['threshold']} | window {config['window_us']} microseconds",
        f"Findings: {findings['total']} | certain {findings['certain']} | possible {findings['possible']}",
        f"Showing {findings['shown']} of {findings['total']} findings; omitted {findings['omitted']}.",
        "",
    ]
    for number, finding in enumerate(findings["items"], 1):
        lines.append(f"{number:02d} {finding['rule_id']} / {finding['ordering']} / evidence records {finding['evidence_records']}")
        lines.append("   id: " + finding["id"])
        if "failures" in finding:
            failures = finding["failures"]
            lines.append(f"   failures {failures['failure_count']} | certain {failures['certain_failure_count']} | threshold {failures['threshold_status']}")
    if findings["omitted"]:
        lines.append("Display truncated. Increase --limit (up to 100); use report for all findings.")
    if not findings["total"]:
        lines.append("No temporal leads matched the supplied records and rule settings.")
    lines.extend(["", *LIMITATIONS])
    return "\n".join(safe_text(line) for line in lines) + "\n"
