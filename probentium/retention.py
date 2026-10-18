"""Retentio explicita; absentia permissa a corruptione distinguitur."""
from .contracts import ProbentiumError, object_digest, text_field, timestamp, utc_now

RETAINED = ["normalized_events", "metadata", "indexes", "objects", "external_exports", "external_backups"]


def validate_stored(kind, value):
    import re
    specs = {
        "retention.hold": ("probentium.retention-hold.v1", {"artifact_ids", "actor", "rationale", "recorded_at", "released_hold_id"}),
        "retention.plan": ("probentium.retention-plan.v1", {"case_id", "case_revision", "artifact_ids", "actor", "rationale", "retain_until", "scope", "retained", "storage_wipe_guaranteed"}),
        "retention.approval": ("probentium.retention-approval.v1", {"plan_id", "plan_digest", "actor", "rationale", "approved_at", "retained_data_acknowledged"}),
        "retention.tombstone": ("probentium.retention-tombstone.v1", {"plan_id", "approval_id", "artifact_ids", "authorized_at", "scope"})}
    if kind not in specs:
        raise ProbentiumError("unsupported_retention_schema", 7)
    schema, fields = specs[kind]
    modern = kind == "retention.plan" and isinstance(value, dict) and value.get("schema") == "probentium.retention-plan.v2"
    if modern:
        schema, fields = "probentium.retention-plan.v2", fields | {"policy", "removal_inventory", "inventory_digest"}
    if not isinstance(value, dict) or set(value) != fields | {"schema"} or value["schema"] != schema:
        raise ProbentiumError("invalid_retention_schema")
    if modern:
        _policy(value["policy"])
        _validate_inventory(value["removal_inventory"])
        if value["inventory_digest"] != object_digest(value["removal_inventory"]):
            raise ProbentiumError("retention_inventory_digest_mismatch", 4)
    for field in ("actor", "rationale"):
        if field in value:
            text_field(value[field], maximum=4096 if field == "rationale" else 256)
    for field in ("recorded_at", "retain_until", "approved_at", "authorized_at"):
        if field in value:
            timestamp(value[field])
    for field in ("plan_id", "plan_digest", "approval_id", "released_hold_id"):
        if field in value and (field != "released_hold_id" or value[field] is not None):
            _identity(value[field])
    if "artifact_ids" in value:
        ids = value["artifact_ids"]
        if not isinstance(ids, list) or not 1 <= len(ids) <= 20000:
            raise ProbentiumError("invalid_retention_scope")
        for identity in ids:
            _identity(identity)
        if ids != sorted(set(ids)):
            raise ProbentiumError("invalid_retention_scope")
    if "scope" in value and value["scope"] != "source_bytes_only":
        raise ProbentiumError("unsupported_retention_scope", 7)
    if kind == "retention.plan":
        if (not isinstance(value["case_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", value["case_id"])
                or type(value["case_revision"]) is not int or not 0 <= value["case_revision"] <= 9007199254740991
                or value["retained"] != RETAINED or value["storage_wipe_guaranteed"] is not False):
            raise ProbentiumError("invalid_retention_plan")
    if kind == "retention.approval" and value["retained_data_acknowledged"] != RETAINED:
        raise ProbentiumError("retention_scope_not_acknowledged")
    return value



def _policy(value):
    """Causa retentionis ab homine declaratur, non a lege fingitur."""
    if not isinstance(value, dict) or set(value) != {"purpose", "data_category", "retention_basis", "review_at"}:
        raise ProbentiumError("invalid_retention_policy")
    for key in ("purpose", "data_category", "retention_basis"):
        text_field(value[key], maximum=4096)
    timestamp(value["review_at"])
    return value


def _validate_inventory(value):
    fields = {"schema", "artifacts", "retained_derived_data", "known_export_refs", "external_copies", "journals", "physical_erasure"}
    if (not isinstance(value, dict) or set(value) != fields or value["schema"] != "probentium.removal-inventory.v1"
            or value["retained_derived_data"] != ["normalized_events", "metadata", "indexes", "objects"]
            or value["external_copies"] != "unregistered_exports_backups_and_recipient_copies_unknown"
            or value["journals"] != "no_live_journal_in_held_case_snapshot"
            or value["physical_erasure"] != "not_guaranteed"):
        raise ProbentiumError("invalid_removal_inventory")
    if not isinstance(value["artifacts"], list) or not 1 <= len(value["artifacts"]) <= 20000:
        raise ProbentiumError("invalid_removal_inventory")
    previous = ""
    for row in value["artifacts"]:
        if not isinstance(row, dict) or set(row) != {"artifact_id", "byte_length", "acquisitions", "records", "events", "parse_runs"}:
            raise ProbentiumError("invalid_removal_inventory")
        _identity(row["artifact_id"])
        if row["artifact_id"] <= previous or any(type(row[key]) is not int or not 0 <= row[key] <= 100 * 1024 ** 3 for key in row if key != "artifact_id"):
            raise ProbentiumError("invalid_removal_inventory")
        previous = row["artifact_id"]
    if not isinstance(value["known_export_refs"], list) or len(value["known_export_refs"]) > 10000:
        raise ProbentiumError("invalid_removal_inventory")
    for ref in value["known_export_refs"]:
        _identity(ref)
    if value["known_export_refs"] != sorted(set(value["known_export_refs"])):
        raise ProbentiumError("invalid_removal_inventory")
    return value


def removal_inventory(case, artifact_ids):
    """Communes acquisitiones numerantur; exemplaria externa ignota manent."""
    rows = []
    for aid in sorted(artifact_ids):
        _identity(aid)
        artifact = case.db.execute("SELECT size FROM artifacts WHERE id=?", (aid,)).fetchone()
        if artifact is None:
            raise ProbentiumError("invalid_retention_scope")
        row = {"artifact_id": aid, "byte_length": artifact[0]}
        for table in ("acquisitions", "records", "events", "parse_runs"):
            row[table] = case.db.execute("SELECT count(*) FROM " + table + " WHERE artifact_id=?", (aid,)).fetchone()[0]
        rows.append(row)
    known = sorted(obj["id"] for obj in case.objects() if obj["kind"] in {"packet_export", "export_receipt", "eu.filing_snapshot", "filing"})
    return _validate_inventory({"schema": "probentium.removal-inventory.v1", "artifacts": rows,
                               "retained_derived_data": ["normalized_events", "metadata", "indexes", "objects"],
                               "known_export_refs": known,
                               "external_copies": "unregistered_exports_backups_and_recipient_copies_unknown",
                               "journals": "no_live_journal_in_held_case_snapshot", "physical_erasure": "not_guaranteed"})


def _check_inventory(case, decision):
    from .store import _load
    if decision["case_id"] != case.meta["case_id"] or decision["case_revision"] > case.revision:
        raise ProbentiumError("retention_plan_case_mismatch", 4)
    for raw, digest in case.db.execute("SELECT data,digest FROM acquisitions"):
        acquisition = _load(raw, digest)
        if acquisition["artifact_id"] in decision["artifact_ids"] and acquisition.get("acquired_revision", 0) > decision["case_revision"]:
            raise ProbentiumError("retention_inventory_changed_replan_required", 5)
    if decision["schema"] == "probentium.retention-plan.v2":
        if removal_inventory(case, decision["artifact_ids"]) != decision["removal_inventory"]:
            raise ProbentiumError("retention_inventory_changed_replan_required", 5)


def _identity(value):
    from .store import _identifier
    return _identifier(value)


def hold(case, artifact_ids, actor, rationale, *, released_hold_id=None, expected_revision=None):
    text_field(actor)
    text_field(rationale, maximum=4096)
    known = {s["id"] for s in case.sources()}
    if not isinstance(artifact_ids, list) or not artifact_ids or len(artifact_ids) > 20000 or len(set(artifact_ids)) != len(artifact_ids) or not set(artifact_ids) <= known:
        raise ProbentiumError("invalid_hold_scope")
    if released_hold_id is not None:
        old = case.get_object(_identity(released_hold_id))
        if old["kind"] != "retention.hold" or old["data"]["released_hold_id"] is not None or set(old["data"]["artifact_ids"]) != set(artifact_ids):
            raise ProbentiumError("invalid_hold_release")
    return case.put_object("retention.hold", {"schema": "probentium.retention-hold.v1", "artifact_ids": sorted(artifact_ids),
                           "actor": actor, "rationale": rationale, "recorded_at": utc_now(), "released_hold_id": released_hold_id}, expected_revision=expected_revision)


def active_holds(case):
    values = case.objects("retention.hold")
    for item in values:
        validate_stored(item["kind"], item["data"])
    released = {x["data"].get("released_hold_id") for x in values}
    return [x for x in values if x["id"] not in released and x["data"].get("released_hold_id") is None]


def plan(case, artifact_ids, actor, rationale, retain_until, *, policy=None, expected_revision=None):
    text_field(actor)
    text_field(rationale, maximum=4096)
    timestamp(retain_until)
    known = {s["id"] for s in case.sources()}
    if not isinstance(artifact_ids, list) or not artifact_ids or len(artifact_ids) > 20000 or len(set(artifact_ids)) != len(artifact_ids) or not set(artifact_ids) <= known:
        raise ProbentiumError("invalid_retention_scope")
    unavailable = authorized_unavailable(case)
    if set(artifact_ids) & set(unavailable):
        raise ProbentiumError("artifact_already_unavailable")
    held = {aid for item in active_holds(case) for aid in item["data"]["artifact_ids"]}
    if held & set(artifact_ids):
        raise ProbentiumError("retention_blocked_by_hold", 5)
    value = {"schema": "probentium.retention-plan.v1", "case_id": case.meta["case_id"], "case_revision": case.revision,
             "artifact_ids": sorted(artifact_ids), "actor": actor, "rationale": rationale, "retain_until": retain_until,
             "scope": "source_bytes_only", "retained": RETAINED,
             "storage_wipe_guaranteed": False}
    if policy is not None:
        inventory = removal_inventory(case, value["artifact_ids"])
        value.update(schema="probentium.retention-plan.v2", policy=_policy(policy), removal_inventory=inventory,
                     inventory_digest=object_digest(inventory))
    validate_stored("retention.plan", value)
    return case.put_object("retention.plan", value, expected_revision=expected_revision)


def approve(case, plan_id, actor, rationale, *, expected_revision=None):
    item = case.get_object(_identity(plan_id))
    if item["kind"] != "retention.plan":
        raise ProbentiumError("retention_plan_required")
    validate_stored(item["kind"], item["data"])
    _check_inventory(case, item["data"])
    text_field(actor)
    text_field(rationale, maximum=4096)
    return case.put_object("retention.approval", {"schema": "probentium.retention-approval.v1", "plan_id": plan_id,
                           "plan_digest": object_digest(item["data"]), "actor": actor, "rationale": rationale, "approved_at": utc_now(),
                           "retained_data_acknowledged": item["data"]["retained"]}, expected_revision=expected_revision)


def authorized_unavailable(case, *, include_superseded=False):
    from .store import _load
    acquired = {}
    for raw, digest in case.db.execute("SELECT data,digest FROM acquisitions"):
        acquisition = _load(raw, digest)
        revision = acquisition.get("acquired_revision", 0)
        if type(revision) is not int or not 0 <= revision <= case.revision:
            raise ProbentiumError("acquisition_revision_invalid", 4)
        acquired.setdefault(acquisition["artifact_id"], []).append(revision)
    result, authorized_revisions = {}, {}
    for item in case.objects("retention.tombstone"):
        value = item["data"]
        validate_stored(item["kind"], value)
        if set(value) != {"schema", "plan_id", "approval_id", "artifact_ids", "authorized_at", "scope"} or value["schema"] != "probentium.retention-tombstone.v1" or value["scope"] != "source_bytes_only":
            raise ProbentiumError("invalid_retention_tombstone", 4)
        timestamp(value["authorized_at"])
        decision, approval = case.get_object(value["plan_id"]), case.get_object(value["approval_id"])
        validate_stored(decision["kind"], decision["data"])
        validate_stored(approval["kind"], approval["data"])
        if (decision["kind"] != "retention.plan" or approval["kind"] != "retention.approval"
                or decision["data"]["case_id"] != case.meta["case_id"] or approval["data"]["plan_id"] != decision["id"]
                or approval["data"]["plan_digest"] != object_digest(decision["data"])
                or value["artifact_ids"] != decision["data"]["artifact_ids"] or not decision["revision"] < approval["revision"] < item["revision"]
                or timestamp(value["authorized_at"]) < timestamp(decision["data"]["retain_until"])):
            raise ProbentiumError("invalid_retention_authorization", 4)
        for identity in value["artifact_ids"]:
            _identity(identity)
            if identity in result and not any(authorized_revisions[identity] < revision <= decision["data"]["case_revision"] for revision in acquired.get(identity, [])):
                raise ProbentiumError("duplicate_retention_tombstone", 4)
            result[identity] = item["id"]
            authorized_revisions[identity] = item["revision"]
    if include_superseded:
        return result
    return {identity: value for identity, value in result.items() if not any(revision > authorized_revisions[identity] for revision in acquired.get(identity, []))}


def execute(case, plan_id, approval_id, *, expected_revision=None, as_of=None):
    import os
    now = as_of or utc_now()
    timestamp(now)
    decision, approval = case.get_object(_identity(plan_id)), case.get_object(_identity(approval_id))
    if decision["kind"] != "retention.plan" or approval["kind"] != "retention.approval" or approval["data"]["plan_id"] != plan_id or approval["data"]["plan_digest"] != object_digest(decision["data"]):
        raise ProbentiumError("retention_approval_mismatch", 4)
    validate_stored(decision["kind"], decision["data"])
    validate_stored(approval["kind"], approval["data"])
    _check_inventory(case, decision["data"])
    if timestamp(now) < timestamp(decision["data"]["retain_until"]):
        raise ProbentiumError("retention_not_due", 5)
    ids = decision["data"]["artifact_ids"]
    held = {aid for item in active_holds(case) for aid in item["data"]["artifact_ids"]}
    if held & set(ids):
        raise ProbentiumError("retention_blocked_by_hold", 5)
    check = case.verify()
    if not check["ok"]:
        raise ProbentiumError("retention_integrity_failed", 4)
    tombstones = case.objects("retention.tombstone")
    existing = [x for x in tombstones if x["data"]["plan_id"] == plan_id]
    case._expect(expected_revision)
    if not existing:
        if set(ids) & set(authorized_unavailable(case)):
            raise ProbentiumError("retention_already_authorized_by_other_plan", 5)
        tombstone = case.put_object("retention.tombstone", {"schema": "probentium.retention-tombstone.v1", "plan_id": plan_id,
                                  "approval_id": approval_id, "artifact_ids": ids, "authorized_at": now, "scope": "source_bytes_only"}, expected_revision=case.revision)
    else:
        tombstone = existing[0]
        if tombstone["data"]["approval_id"] != approval_id:
            raise ProbentiumError("retention_approval_mismatch", 4)
    with case._write(case.revision):
        for identity in ids:
            try:
                os.unlink(identity + ".bin", dir_fd=case._blobs)
            except FileNotFoundError:
                pass
        os.fsync(case._blobs)
    return {"tombstone_id": tombstone["id"], "source_bytes_removed": ids, "scope": "source_bytes_only",
            "retained": decision["data"]["retained"], "storage_wipe_guaranteed": False, "revision": case.revision}


def status(case):
    authorized = authorized_unavailable(case)
    unavailable = {aid: oid for aid, oid in authorized.items() if not case._blob_present(aid)}
    return {"holds": active_holds(case), "plans": case.objects("retention.plan"),
            "unavailable": [{"artifact_id": aid, "tombstone_id": oid} for aid, oid in sorted(unavailable.items())],
            "historical_authorizations": [{"artifact_id": aid, "tombstone_id": oid} for aid, oid in sorted(authorized_unavailable(case, include_superseded=True).items())],
            "revision": case.revision, "scope": "source_bytes_only"}
