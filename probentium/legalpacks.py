"""Leges versionatae sunt; interpretatio approbationem separatam requirit."""
from copy import deepcopy
from datetime import date
import re

from .contracts import ProbentiumError, canonical_bytes, object_digest, timestamp
from .regulatory import _dict, _text, _refs, _value
from .governance import reference, check_refs, _strings, _enum, _hex

SCHEMA = "probentium.eu.v1"
_ORIGINS = {"enacted", "guidance", "internal", "contextual_proposal"}
_OPERATORS = {"manual_review", "hours_after", "days_after", "months_after", "dora_initial", "calendar_plan"}


def validate_rule(rule):
    """Operatores clausi sunt; verba arbitraria non exsequuntur."""
    required = {"id", "source_id", "provision", "title", "origin", "condition", "evidence", "operator", "parameters"}
    _dict(rule, required | {"version", "stage", "without_undue_delay", "trigger_kind", "effective_from", "applicable_from"}, required)
    for key in ("id", "source_id", "provision", "title", "condition"):
        _text(rule[key], 4096)
    for key in ("version", "stage"):
        if key in rule:
            _text(rule[key])
    if "without_undue_delay" in rule and type(rule["without_undue_delay"]) is not bool:
        raise ProbentiumError("invalid_undue_delay_flag")
    if "trigger_kind" in rule:
        from .governance import OBLIGATION_ANCHORS
        _enum(rule["trigger_kind"], OBLIGATION_ANCHORS)
    for key in ("effective_from", "applicable_from"):
        if key in rule:
            _date(rule[key])
    _enum(rule["origin"], _ORIGINS)
    _strings(rule["evidence"], 64)
    _enum(rule["operator"], _OPERATORS)
    parameters = rule["parameters"]
    if rule["operator"] == "calendar_plan":
        from .calendar_plan import validate_plan
        validate_plan(parameters)
    elif rule["operator"] in {"manual_review", "dora_initial"}:
        _dict(parameters, set(), set())
    else:
        _dict(parameters, {"anchor", "amount"}, {"anchor", "amount"})
        if type(parameters["amount"]) is not int or not 1 <= parameters["amount"] <= 366:
            raise ProbentiumError("invalid_rule_parameters")
        _enum(parameters["anchor"], {"awareness", "classification", "submitted", "intermediate", "latest_intermediate", "measure_available", "resolved"})
    if rule["origin"] == "contextual_proposal" and rule["operator"] != "manual_review":
        raise ProbentiumError("proposal_cannot_execute")
    return deepcopy(rule)


def _date(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ProbentiumError("invalid_legal_date")
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise ProbentiumError("invalid_legal_date") from exc
    return value


def validate_pack(data):
    _dict(data, {"schema", "kind", "id", "version", "jurisdiction", "regime", "roles", "author",
                 "status", "effective_from", "applicable_from", "source_checked_at", "sources", "rules",
                 "calendars", "templates", "limitations"},
          {"schema", "kind", "id", "version", "jurisdiction", "regime", "roles", "author", "status",
           "effective_from", "applicable_from", "source_checked_at", "sources", "rules", "calendars", "templates", "limitations"})
    if data["schema"] != SCHEMA or data["kind"] != "legal_pack" or data["status"] != "draft":
        raise ProbentiumError("legal_pack_must_be_draft_on_import")
    for key in ("id", "version", "jurisdiction", "regime", "author"):
        _text(data[key])
    _strings(data["roles"], 64)
    _date(data["effective_from"])
    _date(data["applicable_from"])
    timestamp(data["source_checked_at"])
    _strings(data["limitations"], 64)
    if not isinstance(data["sources"], list) or not 1 <= len(data["sources"]) <= 64:
        raise ProbentiumError("legal_source_limit", 6)
    source_ids = set()
    for source in data["sources"]:
        _dict(source, {"id", "title", "url", "sha256", "document_ref", "origin"}, {"id", "title", "url", "sha256", "document_ref", "origin"})
        for key in ("id", "title", "url"):
            _text(source[key], 2048)
        if not source["url"].startswith("https://"):
            raise ProbentiumError("legal_source_https_required")
        _hex(source["sha256"])
        if source["document_ref"] is not None:
            _hex(source["document_ref"])
        _enum(source["origin"], _ORIGINS)
        if source["id"] in source_ids:
            raise ProbentiumError("duplicate_legal_source")
        source_ids.add(source["id"])
    if not isinstance(data["rules"], list) or not 1 <= len(data["rules"]) <= 5000:
        raise ProbentiumError("legal_rule_limit", 6)
    rule_ids = set()
    for rule in data["rules"]:
        validate_rule(rule)
        _dict(rule, {"id", "source_id", "provision", "title", "origin", "condition", "evidence", "operator", "parameters", "version", "stage", "without_undue_delay", "trigger_kind", "effective_from", "applicable_from"},
              {"id", "source_id", "provision", "title", "origin", "condition", "evidence", "operator", "parameters"})
        for key in ("id", "source_id", "provision", "title", "condition"):
            _text(rule[key], 4096)
        _enum(rule["origin"], _ORIGINS)
        _strings(rule["evidence"], 64)
        _enum(rule["operator"], _OPERATORS)
        if rule["operator"] == "calendar_plan":
            pass
        elif rule["operator"] == "manual_review":
            if rule["parameters"]:
                raise ProbentiumError("manual_rule_has_parameters")
        elif rule["operator"] == "dora_initial":
            if rule["parameters"]:
                raise ProbentiumError("dora_rule_has_parameters")
        else:
            if set(rule["parameters"]) != {"anchor", "amount"} or type(rule["parameters"]["amount"]) is not int or not 1 <= rule["parameters"]["amount"] <= 366:
                raise ProbentiumError("invalid_rule_parameters")
            _enum(rule["parameters"]["anchor"], {"awareness", "classification", "submitted", "intermediate", "latest_intermediate", "measure_available", "resolved"})
        if rule["origin"] == "contextual_proposal" and rule["operator"] != "manual_review":
            raise ProbentiumError("proposal_cannot_execute")
        if rule["id"] in rule_ids or rule["source_id"] not in source_ids:
            raise ProbentiumError("invalid_legal_rule_reference")
        source = next(s for s in data["sources"] if s["id"] == rule["source_id"])
        if source["origin"] == "contextual_proposal" and rule["origin"] != "contextual_proposal":
            raise ProbentiumError("proposal_cannot_be_enacted_rule")
        rule_ids.add(rule["id"])
    if not isinstance(data["calendars"], list) or len(data["calendars"]) > 64:
        raise ProbentiumError("calendar_limit", 6)
    seen = set()
    for calendar in data["calendars"]:
        if isinstance(calendar, dict) and calendar.get("schema") == "probentium.calendar-policy.v1":
            from .deadlines import validate_calendar
            validate_calendar(calendar)
            if calendar["id"] in seen or not set(calendar["source_ids"]) <= source_ids:
                raise ProbentiumError("invalid_calendar_identity_or_source")
            seen.add(calendar["id"])
            continue
        _dict(calendar, {"id", "version", "timezone", "source_ids", "hour_rule", "day_rule", "month_rule", "nonworking_rule", "holidays", "status"},
              {"id", "version", "timezone", "source_ids", "hour_rule", "day_rule", "month_rule", "nonworking_rule", "holidays", "status"})
        for key in ("id", "version", "timezone", "hour_rule", "day_rule", "month_rule", "nonworking_rule"):
            _text(calendar[key], 4096)
        if calendar["status"] != "unverified" or calendar["id"] in seen:
            raise ProbentiumError("calendar_review_separate")
        if not set(_strings(calendar["source_ids"], 64)) <= source_ids:
            raise ProbentiumError("calendar_source_missing")
        for day in _strings(calendar["holidays"], 1000):
            _date(day)
        seen.add(calendar["id"])
    if not isinstance(data["templates"], list) or len(data["templates"]) > 64:
        raise ProbentiumError("template_limit", 6)
    seen = set()
    for template in data["templates"]:
        _dict(template, {"id", "version", "recipient", "stage", "fields", "source_ids"}, {"id", "version", "recipient", "stage", "fields", "source_ids"})
        for key in ("id", "version", "recipient", "stage"):
            _text(template[key])
        if template["id"] in seen or not set(_strings(template["source_ids"], 64)) <= source_ids:
            raise ProbentiumError("invalid_template_identity")
        seen.add(template["id"])
        if not isinstance(template["fields"], list) or len(template["fields"]) > 500:
            raise ProbentiumError("template_field_limit", 6)
        ids = set()
        for field in template["fields"]:
            _dict(field, {"id", "required", "allow_unknown"}, {"id", "required", "allow_unknown"})
            _text(field["id"])
            if field["id"] in ids or type(field["required"]) is not bool or type(field["allow_unknown"]) is not bool:
                raise ProbentiumError("invalid_template_field")
            ids.add(field["id"])
    if len(canonical_bytes(data)) > 16 * 1024 * 1024:
        raise ProbentiumError("legal_pack_size_limit", 6)
    return deepcopy(data)


def validate_stored(kind, data):
    if kind in {"eu.requirement_catalogue", "eu.legal_coverage_audit"}:
        from .legalcoverage import validate_stored as validate_coverage
        return validate_coverage(kind, data)
    if kind == "eu.legal_pack":
        return validate_pack(data)
    base = {"schema", "kind", "pack_ref", "actor", "at", "rationale", "document_refs"}
    if kind == "eu.legal_review":
        fields = base | {"role", "review_due", "independence_attested", "attestation", "reference_cases"}
    elif kind == "eu.legal_activation":
        fields = base | {"mode", "previous_pack_ref", "review_refs", "change_impact", "acknowledged_limits"}
    else:
        raise ProbentiumError("unsupported_legal_object")
    _dict(data, fields, fields)
    if data["schema"] != SCHEMA or data["kind"] != kind[3:]:
        raise ProbentiumError("legal_object_schema_mismatch")
    _hex(data["pack_ref"])
    _text(data["actor"])
    timestamp(data["at"])
    _text(data["rationale"], 4096)
    for ref in _refs(data["document_refs"]):
        _hex(ref)
    if not data["document_refs"]:
        raise ProbentiumError("review_document_required")
    if kind == "eu.legal_review":
        _enum(data["role"], {"legal", "technical"})
        timestamp(data["review_due"])
        if timestamp(data["review_due"]) <= timestamp(data["at"]):
            raise ProbentiumError("invalid_review_window")
        if data["independence_attested"] is not True:
            raise ProbentiumError("independent_review_attestation_required")
        _text(data["attestation"], 4096)
        if not isinstance(data["reference_cases"], list) or not 1 <= len(data["reference_cases"]) <= 500:
            raise ProbentiumError("reference_cases_required")
        ids = set()
        for row in data["reference_cases"]:
            _dict(row, {"id", "input", "expected", "document_ref"}, {"id", "input", "expected", "document_ref"})
            _text(row["id"])
            _hex(row["document_ref"])
            _value(row["input"])
            _value(row["expected"])
            if row["id"] in ids or row["document_ref"] not in data["document_refs"]:
                raise ProbentiumError("invalid_review_vector")
            ids.add(row["id"])
    else:
        _enum(data["mode"], {"draft_operational", "review_attested"})
        if data["previous_pack_ref"] is not None:
            _hex(data["previous_pack_ref"])
        for ref in _refs(data["review_refs"]):
            _hex(ref)
        _dict(data["change_impact"], {"before", "after", "changed", "requires_review"}, {"before", "after", "changed", "requires_review"})
        impact = data["change_impact"]
        if impact["before"] is not None:
            _hex(impact["before"])
        _hex(impact["after"])
        changed = _strings(impact["changed"], 32)
        if not set(changed) <= {"jurisdiction", "regime", "roles", "effective_from", "applicable_from", "sources", "rules", "calendars", "templates"} or type(impact["requires_review"]) is not bool or impact["requires_review"] != bool(changed):
            raise ProbentiumError("invalid_pack_change_impact")
        if data["acknowledged_limits"] is not True:
            raise ProbentiumError("activation_limits_acknowledgement_required")
    return deepcopy(data)


def import_pack(case, pack, expected_revision=None):
    pack = validate_pack(pack)
    for source in pack["sources"]:
        if source["document_ref"] is not None:
            ref = reference(case, source["document_ref"])
            if ref["kind"] != "artifact" or ref["id"] != source["sha256"]:
                raise ProbentiumError("legal_source_digest_mismatch")
    for existing in case.objects("eu.legal_pack"):
        if existing["data"]["id"] == pack["id"] and existing["data"]["version"] == pack["version"] and canonical_bytes(existing["data"]) != canonical_bytes(pack):
            raise ProbentiumError("legal_version_content_conflict", 5)
    return case.put_object("eu.legal_pack", pack, expected_revision=expected_revision)


def review_pack(case, pack_id, review, expected_revision=None):
    keys = {"actor", "at", "rationale", "document_refs", "role", "review_due", "independence_attested", "attestation", "reference_cases"}
    _dict(review, keys, keys)
    pack = reference(case, pack_id, {"eu.legal_pack"})["data"]
    validate_pack(pack)
    payload = {"schema": SCHEMA, "kind": "legal_review", "pack_ref": pack_id, **review}
    validate_stored("eu.legal_review", payload)
    if review["actor"] == pack["author"]:
        raise ProbentiumError("pack_author_cannot_independently_review")
    if any(source["document_ref"] is None for source in pack["sources"]):
        raise ProbentiumError("legal_source_documents_missing")
    for source in pack["sources"]:
        ref = reference(case, source["document_ref"])
        if ref["kind"] != "artifact" or ref["id"] != source["sha256"]:
            raise ProbentiumError("legal_source_digest_mismatch")
    check_refs(case, review["document_refs"], nonempty=True)
    return case.put_object("eu.legal_review", payload, expected_revision=expected_revision)


def pack_diff(before, after):
    if before is not None:
        validate_pack(before)
    validate_pack(after)
    changed = []
    for key in ("jurisdiction", "regime", "roles", "effective_from", "applicable_from", "sources", "rules", "calendars", "templates"):
        if before is None or canonical_bytes(before[key]) != canonical_bytes(after[key]):
            changed.append(key)
    return {"before": object_digest(before) if before else None, "after": object_digest(after),
            "changed": changed, "requires_review": bool(changed)}


def activate_pack(case, pack_id, activation, expected_revision=None):
    pack = reference(case, pack_id, {"eu.legal_pack"})["data"]
    validate_pack(pack)
    _dict(activation, {"actor", "at", "rationale", "document_refs", "mode", "review_refs", "acknowledged_limits"},
          {"actor", "at", "rationale", "document_refs", "mode", "review_refs", "acknowledged_limits"})
    previous = [obj for obj in case.objects("eu.legal_activation") if reference(case, obj["data"]["pack_ref"], {"eu.legal_pack"})["data"]["id"] == pack["id"]]
    previous_ref = previous[-1]["data"]["pack_ref"] if previous else None
    if previous and timestamp(activation["at"]) < timestamp(previous[-1]["data"]["at"]):
        raise ProbentiumError("activation_time_reversed")
    before = reference(case, previous_ref, {"eu.legal_pack"})["data"] if previous_ref else None
    payload = {"schema": SCHEMA, "kind": "legal_activation", "pack_ref": pack_id,
               "previous_pack_ref": previous_ref, "change_impact": pack_diff(before, pack), **activation}
    validate_stored("eu.legal_activation", payload)
    check_refs(case, activation["document_refs"], nonempty=True)
    reviews = []
    for ref in activation["review_refs"]:
        row = reference(case, ref, {"eu.legal_review"})["data"]
        validate_stored("eu.legal_review", row)
        if row["pack_ref"] != pack_id or not timestamp(row["at"]) <= timestamp(activation["at"]) <= timestamp(row["review_due"]):
            raise ProbentiumError("activation_review_mismatch_or_stale")
        reviews.append(row)
    if activation["mode"] == "review_attested":
        if {row["role"] for row in reviews} != {"legal", "technical"} or len({row["actor"] for row in reviews}) < 2:
            raise ProbentiumError("legal_and_technical_review_required")
    return case.put_object("eu.legal_activation", payload, expected_revision=expected_revision)


def pack_status(case, pack_id, as_of, *, revision=None):
    if revision is not None and (type(revision) is not int or not 0 <= revision <= case.revision):
        raise ProbentiumError("invalid_legal_revision")
    now = timestamp(as_of)
    pack = reference(case, pack_id, {"eu.legal_pack"})["data"]
    validate_pack(pack)
    candidates = []
    for row in case.objects("eu.legal_activation"):
        if revision is not None and row["revision"] > revision:
            continue
        data = validate_stored("eu.legal_activation", row["data"])
        p = reference(case, data["pack_ref"], {"eu.legal_pack"})["data"]
        if p["id"] == pack["id"] and timestamp(data["at"]) <= now:
            candidates.append(row)
    active = candidates[-1] if candidates and candidates[-1]["data"]["pack_ref"] == pack_id else None
    reviews = [reference(case, ref, {"eu.legal_review"})["data"] for ref in active["data"]["review_refs"]] if active else []
    if active:
        check_refs(case, active["data"]["document_refs"], nonempty=True)
        for row in reviews:
            validate_stored("eu.legal_review", row)
            check_refs(case, row["document_refs"], nonempty=True)
            if row["pack_ref"] != pack_id or row["actor"] == pack["author"] or not timestamp(row["at"]) <= timestamp(active["data"]["at"]) <= timestamp(row["review_due"]):
                raise ProbentiumError("activation_review_mismatch_or_stale")
        if active["data"]["mode"] == "review_attested":
            if {row["role"] for row in reviews} != {"legal", "technical"} or len({row["actor"] for row in reviews}) < 2:
                raise ProbentiumError("legal_and_technical_review_required")
            for source in pack["sources"]:
                if source["document_ref"] is None:
                    raise ProbentiumError("legal_source_documents_missing")
                found = reference(case, source["document_ref"])
                if found["kind"] != "artifact" or found["id"] != source["sha256"]:
                    raise ProbentiumError("legal_source_digest_mismatch")
    current = bool(active and active["data"]["mode"] == "review_attested" and reviews and all(timestamp(row["review_due"]) >= now for row in reviews))
    return {"pack_ref": pack_id, "activation_ref": active["id"] if active else None,
            "state": "active_operational" if active else "draft_inactive", "mode": active["data"]["mode"] if active else None,
            "currentness": "review_attested_current" if current else "currentness_unverified",
            "review_origin": "supplied_attestations_only", "legally_verified": False,
            "offline_new_amendments_unknown": True, "as_of": as_of}


def import_catalogue(case, data, expected_revision=None):
    from .legalcoverage import import_catalogue as execute
    return execute(case, data, expected_revision)


def audit_coverage(case, pack_id, catalogue_id, as_of, **kwargs):
    from .legalcoverage import audit_coverage as execute
    return execute(case, pack_id, catalogue_id, as_of, **kwargs)


def coverage_status(case, audit_id, as_of):
    from .legalcoverage import coverage_status as execute
    return execute(case, audit_id, as_of)


def replay_coverage(case, audit_id):
    from .legalcoverage import replay_coverage as execute
    return execute(case, audit_id)


_CZ_DIGESTS = {
    264: "ee72b72a3caaa5fb86b91588ed9ab5be3d60f2fa06fe1f23d01965e5b7a9de03",
    334: "6c489ae66bfa65c8aedecdfa3b660224762c32fa3794a8cb2f3ed5f888900cf9",
    408: "419392fc5e77c7f44046e15e717f68c2564c49da80c89ef05cc66e8d3e3bae07",
    409: "09aaa48213c7d37ae3740ada3c547cefbda8eafc44a852818d2fcd1f9756c302",
    410: "3fd120e8c0e9d852b35192e9d0fc41ff780a27a962095255e76f1519bb46bf70",
}
_CZ_HIGHER = [
    "Subject matter", "Definitions", "Information security management system", "Top management requirements",
    "Security roles", "Security policy and documentation", "Asset management", "Risk management", "Supplier management",
    "Human resources security", "Change management", "Acquisition, development and maintenance", "Access management",
    "Cybersecurity event and incident handling", "Business continuity management", "Cybersecurity audit", "Physical security",
    "Communication network security", "Identity management and authentication", "Access rights and authorisations",
    "Cybersecurity event detection", "Event logging", "Cybersecurity event evaluation", "Application security",
    "Cryptographic algorithms", "Regulated service availability", "Industrial, control and other specific technical assets",
    "Transitional provision", "Entry into force",
]
_CZ_LOWER = [
    "Subject matter", "Definitions", "Minimum cybersecurity system", "Top management requirements", "Human resources security",
    "Business continuity management", "Access management", "Identity management and authorisations",
    "Cybersecurity event detection and logging", "Cybersecurity incident handling", "Communication network security",
    "Application security", "Cryptographic algorithms", "Significant incident impact assessment", "Entry into force",
]
_DIGITAL_AREAS = [
    "Network and information system security policy", "Risk management policy", "Incident handling",
    "Business continuity and crisis management", "Supply chain security", "Acquisition, development and maintenance security",
    "Assessment of cybersecurity measure effectiveness", "Cyber hygiene and training", "Cryptography",
    "Human resources security", "Access control", "Asset management", "Environmental and physical security",
]


def draft_czech_pack(regime):
    """Index fontium est initium recensionis, non sententia iuris."""
    _enum(regime, {"higher", "lower", "digital"})
    numbers = [264, 334, 408] + ([409] if regime == "higher" else [410] if regime == "lower" else [])
    sources = [{"id": "CZ-" + str(n), "title": ("Act " if n == 264 else "Decree ") + str(n) + "/2025 Coll., official promulgated PDF",
                "url": "https://e-sbirka.gov.cz/sb/2025/" + str(n), "sha256": _CZ_DIGESTS[n],
                "document_ref": None, "origin": "enacted"} for n in numbers]
    rules = []

    def rule(identifier, source, provision, title, condition, evidence):
        rules.append({"id": identifier, "source_id": source, "provision": provision, "title": title,
                      "origin": "enacted", "condition": condition, "evidence": evidence,
                      "operator": "manual_review", "parameters": {}})

    common = [
        (3, "Regulated service", "Determine the registered service and its scope; an industry label alone is insufficient.", ["service inventory", "registration decision"]),
        (4, "Registration conditions", "Review service category and size or significance against Decree 408/2025; do not infer exemption from missing facts.", ["service classification", "size and group relationship evidence"]),
        (5, "Additional registration conditions", "Review additional significance grounds separately from the ordinary size test.", ["significance assessment", "competent authority decision if supplied"]),
        (6, "Service notification and registration", "Section 6(1): notification no later than 60 days after conditions are met; record that trigger separately from registration delivery.", ["conditions-met assessment", "notification copy", "registration decision and delivery evidence"]),
        (7, "Enterprise size", "Apply the statutory size and group relationship rules to the specific entity; no automatic name matching.", ["size calculation", "group structure", "review rationale"]),
        (11, "Contact and supplementary data", "Section 11(1): 30 days after delivery of registration; section 11(2): changed non-reference data within 14 days after change.", ["registration delivery", "submitted contact data", "change record"]),
        (12, "Cybersecurity management scope", "Unassessed primary assets and undetermined supporting assets are not silently excluded; record excluded assets and reasons.", ["asset inventory", "service dependencies", "scope decision and exclusions"]),
        (13, "Implementation of measures", "Section 13(4): start fulfilling measures no later than one year after registration delivery; review previous regulation under section 71 and digital substitution under section 18.", ["implementation plan", "registration delivery", "prior-regulation review", "supplier contract terms"]),
        (14, "Security measure categories", "Higher and lower obligation regimes have separate categories; evidence reuse is not full legal equivalence.", ["regime decision", "requirement-to-control mapping"]),
        (15, "Incident reportability", "Higher regime: in-scope cyber-origin incident where intent cannot be excluded; lower additionally significant impact. Section 15(4) one-year start is subject to section 71, not a universal reporting holiday.", ["qualification assessment", "scope and impact evidence", "registration delivery", "prior-regulation review"]),
        (16, "Incident reporting procedure", "Early report: without undue delay, at most 24 hours after discovery. Follow-up under section 16(3) requires the applicable significance trigger; 72 hours, or 24 for trust services. Final: 30 days after detailed notification; ongoing incident requires progress and final within 30 days of resolution.", ["awareness assertion", "authority significance response where applicable", "notification copy", "resolution assertion", "submission evidence"]),
        (18, "Specified digital service obligations", "Section 18(1) uses Regulation 2024/2690 measures for listed services instead of section 13(2); section 18(2) significant-incident substitution excludes trust services. Main-establishment/jurisdiction rules require separate review.", ["exact digital-service category", "trust-service status", "main establishment evidence", "jurisdiction review"]),
        (19, "Information to recipients", "Review the statutory circumstances for informing regulated-service recipients; a regulator report is not automatically recipient communication.", ["recipient impact assessment", "communication decision", "communication evidence"]),
        (70, "Sector-specific equivalent rules", "Assess equivalence only for the matched duties and regulated scope; do not disable unrelated GDPR or other obligations.", ["sector and role assessment", "lex specialis rationale", "separate reporting tracks"]),
        (71, "Transitional obligations", "Previously regulated services continue the applicable former obligations during transition; new reporting method applies from delivery of the registration decision.", ["previous regulatory status", "transition assessment", "registration delivery"]),
        (73, "Entry into force", "Act effective 2025-11-01; entity-specific registration and transition anchors remain separate.", ["source version", "entity-specific applicability review"]),
    ]
    for section, title, condition, evidence in common:
        rule(f"CZ-264-S{section}", "CZ-264", f"section {section}", title, condition, evidence)
    for section, title in [(2, "Service list and provider significance"), (3, "Higher and lower obligation classification")]:
        rule(f"CZ-408-S{section}", "CZ-408", f"section {section} and Annex", title,
             "Review the exact Annex service row and conditions, including size and sector-specific exceptions; unknown values remain unresolved.",
             ["exact Annex row reference", "service facts", "size and group evidence", "review attestation"])
    rule("CZ-334-S4", "CZ-334", "section 4", "Incident reporting contents",
         "Select the applicable reporting stage and prescribed fields; this preview template is not the authority form or an automatic submission.",
         ["stage-specific fields", "submission copy", "receipt strength assessment"])
    if regime in {"higher", "lower"}:
        number, titles = (409, _CZ_HIGHER) if regime == "higher" else (410, _CZ_LOWER)
        for section, title in enumerate(titles, 1):
            evidence = ["scoped implementation description", "source-backed procedure and observation", "population, sample, exclusions and period", "responsible review"]
            condition = f"For a service reviewed as {regime}-obligation scope; inspect every applicable paragraph and annex of section {section}, including exceptions. Section-level index is not clause-level legal certification."
            if number == 409 and section == 27:
                condition += " Applicability depends on industrial, control or similar specific technical assets."
            if number == 410 and section == 14:
                condition += " Assess significant impact using all statutory criteria and documented facts."
            rule(f"CZ-{number}-S{section}", f"CZ-{number}", f"section {section}", title, condition, evidence)
        for annex in range(1, 7 if number == 409 else 4):
            rule(f"CZ-{number}-A{annex}", f"CZ-{number}", f"Annex {annex}", f"Annex {annex} review",
                 "Read the Annex with its referring provisions; no universal applicability is inferred from this index.",
                 ["annex-specific review", "scoped evidence and rationale"])
    else:
        sources.append({"id": "EU-2690", "title": "Commission Implementing Regulation (EU) 2024/2690, authentic English OJ PDF",
                        "url": "https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj/eng",
                        "sha256": "8799b1a7c352060c4f155ddc56241b0b2679e2204645361b134bbda3199d7199",
                        "document_ref": None, "origin": "enacted"})
        for article in range(1, 15):
            rule(f"EU-2690-A{article}", "EU-2690", f"Article {article}", f"Digital service scope or significance: Article {article}",
                 "Review the precise service class, general significance criteria, planned maintenance exclusion, recurring incident aggregation and the applicable service-specific criteria; section 18 trust-service exception remains separate.",
                 ["service-specific classification", "impact evidence", "recurrence and root-cause assessment", "review rationale"])
        for section, title in enumerate(_DIGITAL_AREAS, 1):
            rule(f"EU-2690-ANNEX-{section}", "EU-2690", f"Annex section {section}", title,
                 "Apply only to the listed relevant entities and reviewed service scope; read each numbered subclause and proportionality condition.",
                 ["scoped implementation", "procedure and observations", "test population and period", "review rationale"])
    recipient = "National CERT" if regime == "lower" else "NÚKIB or competent recipient after jurisdiction review"
    pack = {"schema": SCHEMA, "kind": "legal_pack", "id": "cz-nis2-" + regime, "version": "draft-2026-10-18.1",
            "jurisdiction": "CZ", "regime": "cz-nis2-" + regime, "roles": ["regulated_service_provider"],
            "author": "PROBENTIUM draft catalogue", "status": "draft", "effective_from": "2025-11-01",
            "applicable_from": "2025-11-01", "source_checked_at": "2026-10-18T00:00:00Z",
            "sources": sources, "rules": rules,
            "calendars": [{"id": "cz-operational-unverified", "version": "draft-1", "timezone": "Europe/Prague",
                           "source_ids": ["CZ-264"], "hour_rule": "Operational elapsed hours only; legal computation unverified.",
                           "day_rule": "Operational elapsed days only; national legal computation requires review.",
                           "month_rule": "Calendar month is not 30 elapsed days; review the applicable specific rule.",
                           "nonworking_rule": "Not automatically applied.", "holidays": [], "status": "unverified"}],
            "templates": [{"id": "incident-review", "version": "draft-1", "recipient": recipient, "stage": "review_before_submission",
                           "source_ids": ["CZ-264", "CZ-334"], "fields": [{"id": field, "required": True, "allow_unknown": True}
                            for field in ("entity", "service", "incident_summary", "awareness", "scope", "impact", "cross_border", "indicators", "mitigation", "unknown_facts")]}],
            "limitations": ["Draft section-level source index; clause-level applicability and evidence sufficiency require documented legal and technical review.",
                            "Source hashes identify official promulgated PDF bytes retrieved on 2026-10-18; source documents are not bundled or attached.",
                            "Source retrieval is not legal review; offline currentness and later amendments remain unverified.",
                            "Applicability date is a source baseline, not an entity-specific start of duties; registration and transition triggers require review.",
                            "No automatic legal countdown, authority form, submission, compliance certification or legal acceptance."]}
    return validate_pack(pack)
