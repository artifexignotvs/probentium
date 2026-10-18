"""Repetitio probat constantiam; migratio fontem non mutat."""
import hashlib
import errno
import os
import re
import sqlite3
import stat
import tempfile
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

from testifex.safeio import regular_reader
from . import adapters
from . import limits as resource_limits
from .contracts import ProbentiumError, canonical_bytes, object_digest, strict_json
from .store import (CaseStore, _normalized, _parser_manifest, _dump, _catalog_digest,
                    _schema_rows, _directory, _private_file, _connect_checked, _assert_database_binding, MAX_LINE, MAX_ARTIFACT)
from .worker import ParserWorker


def _maintenance_errors(function):
    """Errores systematis sine viis privatis ad codices stabiliuntur."""
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except OSError as exc:
            limited = exc.errno in (errno.ENOSPC, errno.EDQUOT)
            raise ProbentiumError("storage_resource_limit" if limited else "maintenance_io_failed", 6 if limited else 4) from None
        except sqlite3.Error as exc:
            limited = getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL
            raise ProbentiumError("storage_resource_limit" if limited else "maintenance_database_failed", 6 if limited else 4) from None
    return checked


def replay_packet(manifest, snapshot, source_reader, *, approved_manifest=None, resource_policy=None):
    from .exchange import _snapshot
    result = {"normalization_replay": "unavailable", "analysis_replay": "unavailable", "issues": []}
    try:
        maps = _snapshot(snapshot, resource_policy)
        current = object_digest(_parser_manifest(), "TESTIFEX-PARSER-ARTIFACT-V2")
        approved_digest = None
        if approved_manifest is not None:
            from .parser_artifact import verify_manifest
            approved_digest = verify_manifest(approved_manifest)["manifest_digest"]
        if any(run["parser_artifact_digest"] not in (current, approved_digest) or run["adapter_version"] != adapters.VERSION for run in maps["parse_runs"].values()):
            return {**result, "normalization_replay": "unsupported", "analysis_replay": "unavailable", "issues": ["parser_version_unavailable"]}
        if any(len(event["record_refs"]) != 1 or event["output_index"] != 0 for event in maps["events"].values()):
            return {**result, "normalization_replay": "unsupported", "analysis_replay": "unavailable", "issues": ["replay_composite_parser_unavailable"]}
        streamed = hasattr(snapshot, "iter_run_records")
        events, links = {}, {}
        if not streamed:
            for event in maps["events"].values():
                key = (event["parse_run_id"], event["primary_record_ref"])
                if key in events:
                    raise ProbentiumError("replay_multiple_outputs_unsupported", 7)
                events[key] = event
            for link in snapshot["parse_records"]:
                links.setdefault(link["parse_run_id"], []).append(link)
        for rid, run in maps["parse_runs"].items():
            with source_reader(run["artifact_id"]) as stream, ParserWorker(maps["artifacts"][run["artifact_id"]]["size"], resource_policy=resource_limits.parse_config(run["config"])) as worker:
                cursor, ordinal, counts = 0, 0, dict.fromkeys(("parsed", "blank", "known_out_of_scope", "unsupported", "malformed", "oversize"), 0)
                records = snapshot.iter_run_records(rid) if streamed else (maps["records"][link["record_id"]] for link in sorted(links.get(rid, []), key=lambda x: maps["records"][x["record_id"]]["offset"]))
                local_links = None if streamed else {link["record_id"]: link for link in links.get(rid, [])}
                for record in records:
                    link = snapshot.lookup("parse_records", rid + ":" + record["id"]) if streamed else local_links[record["id"]]
                    ordinal += 1
                    if record["offset"] != cursor or record["ordinal"] != ordinal or record["artifact_id"] != run["artifact_id"]:
                        raise ProbentiumError("replay_record_order_mismatch", 4)
                    stream.seek(cursor)
                    remaining, digest, raw = record["length"], hashlib.sha256(), bytearray()
                    while remaining:
                        chunk = stream.read(min(remaining, MAX_LINE))
                        if not chunk:
                            raise ProbentiumError("replay_record_truncated", 4)
                        digest.update(chunk)
                        if record["length"] <= MAX_LINE:
                            raw.extend(chunk)
                        remaining -= len(chunk)
                    if digest.hexdigest() != record["raw_digest"]:
                        raise ProbentiumError("replay_record_digest_mismatch", 4)
                    cursor += record["length"]
                    output, code = None, None
                    if record["length"] > MAX_LINE:
                        disposition, code = "oversize", "line_limit"
                    elif run["adapter_id"] == "opaque":
                        disposition = "known_out_of_scope"
                    elif not raw.strip(b" \t\r\n"):
                        disposition = "blank"
                    else:
                        try:
                            event = worker.parse(bytes(raw), run["adapter_id"], ordinal)
                            output = _normalized(event) if event is not None else None
                            disposition = "parsed" if event is not None else "unsupported"
                        except ProbentiumError as exc:
                            if exc.exit_code not in (2, 7):
                                raise
                            disposition, code = "unsupported" if exc.exit_code == 7 else "malformed", exc.code
                    if (link["disposition"], link["code"]) != (disposition, code):
                        raise ProbentiumError("replay_disposition_mismatch", 4)
                    stored = snapshot.event_for_record(rid, record["id"]) if streamed else events.get((rid, record["id"]))
                    if (output is None and stored is not None) or (output is not None and (stored is None or output != stored["normalized_output"])):
                        raise ProbentiumError("replay_normalization_mismatch", 4)
                    counts[disposition] += 1
                complete = cursor == maps["artifacts"][run["artifact_id"]]["size"]
                if (counts != run["counters"] or ordinal != run["records_total"] or cursor != run["cursor"]
                        or counts["parsed"] != run["events_total"] or run["state"] != ("complete" if complete else "incomplete")):
                    raise ProbentiumError("replay_accounting_mismatch", 4)
        result["normalization_replay"] = "passed"
        from .investigation import replay_snapshot
        semantic = replay_snapshot(snapshot)
        # Relatio semantica probationem fontium neque substituit neque amplificat.
        fields = {"analysis_replay", "issues"}
        if isinstance(semantic, dict) and semantic.get("analysis_replay") == "passed":
            fields.add("basis")
        if (not isinstance(semantic, dict) or set(semantic) != fields
                or semantic["analysis_replay"] not in ("passed", "failed", "unsupported", "unavailable")
                or not isinstance(semantic["issues"], list) or len(semantic["issues"]) > 1000
                or any(not isinstance(code, str) or not re.fullmatch(r"[a-z0-9_]{1,128}", code) for code in semantic["issues"])
                or "basis" in fields and semantic["basis"] != "canonical_snapshot_semantics_only_raw_byte_verification_separate"):
            raise ProbentiumError("invalid_analysis_replay_receipt", 4)
        result["analysis_replay"] = semantic["analysis_replay"]
        result["issues"].extend(semantic["issues"])
    except ProbentiumError as exc:
        phase = "normalization_replay" if result["normalization_replay"] != "passed" else "analysis_replay"
        result[phase] = "unsupported" if exc.exit_code == 7 else "unavailable" if exc.exit_code == 3 else "failed"
        result["issues"].append(exc.code)
    except (OSError, ValueError, KeyError, TypeError):
        phase = "normalization_replay" if result["normalization_replay"] != "passed" else "analysis_replay"
        result[phase] = "failed"
        result["issues"].append("replay_invalid_data")
    return result


def replay_case(case, *, parser_approval_id=None, resource_policy=None):
    resource_policy = resource_policy if resource_policy is not None else case._resource_policy
    resource_limits.resolve(resource_policy)
    from .exchange import export_case, open_verified_snapshot
    approved_manifest = None
    if parser_approval_id is not None:
        from .parser_artifact import resolve_approval
        approved_manifest = resolve_approval(case, parser_approval_id)
    with tempfile.TemporaryDirectory(prefix="probentium-replay-") as directory:
        packet = Path(directory) / "case.pbp"
        export_case(case, packet, profile="private_full", resource_policy=resource_policy)
        with open_verified_snapshot(packet, resource_policy=resource_policy) as (manifest, snapshot, reader):
            return replay_packet(manifest, snapshot, reader, approved_manifest=approved_manifest, resource_policy=resource_policy)


def recovery_plan(case):
    check = case.verify()
    if not check["ok"]:
        raise ProbentiumError("recovery_integrity_failed", 4)
    entries = []
    for name in check["unreferenced_blobs"]:
        fd = _private_file(case._blobs, name)
        with os.fdopen(fd, "rb") as stream:
            digest = hashlib.sha256()
            for raw in iter(lambda: stream.read(1024 ** 2), b""):
                digest.update(raw)
            entries.append({"name": name, "size": os.fstat(stream.fileno()).st_size, "sha256": digest.hexdigest()})
    value = {"schema": "probentium.recovery-plan.v1", "case_id": case.meta["case_id"], "revision": case.revision,
             "action": "remove_unreferenced_copies", "entries": entries,
             "resumable": [s["id"] for s in case.sources() if s["state"] == "incomplete"]}
    return {**value, "digest": object_digest(value)}


def apply_recovery(case, plan, *, expected_revision=None):
    current = recovery_plan(case)
    if current != plan:
        raise ProbentiumError("recovery_plan_stale", 5)
    with case._write(expected_revision if expected_revision is not None else plan["revision"]):
        for entry in plan["entries"]:
            os.unlink(entry["name"], dir_fd=case._blobs)
        os.fsync(case._blobs)
    return {"plan_digest": plan["digest"], "removed_copies": len(plan["entries"]), "revision": case.revision}


@_maintenance_errors
def restore_snapshot(snapshot, source_reader, destination, *, resource_policy=None):
    """Exemplar incohatum extra finem publicum manet."""
    resource_limits.resolve(resource_policy)
    target = Path(os.path.abspath(destination))
    with _directory(target.parent):
        pass
    with tempfile.TemporaryDirectory(prefix=".restore-snapshot-", dir=target.parent) as staging:
        case_path = Path(staging) / "case"
        receipt = _restore_snapshot(snapshot, source_reader, case_path, resource_policy=resource_policy)
        _publish_directory(case_path, target)
    return receipt


def _restore_snapshot(snapshot, source_reader, destination, *, resource_policy=None):
    """Columnae fixae tantum scribuntur; SQL externum recusatur."""
    from .exchange import _snapshot
    policy = resource_limits.resolve(resource_policy)
    _snapshot(snapshot, resource_policy)
    with CaseStore.create(destination, snapshot["meta"]["name"], resource_policy=resource_policy) as case:
        with case._write(0):
            for artifact in snapshot["artifacts"]:
                temporary = None
                try:
                    with tempfile.NamedTemporaryFile(prefix="probentium-restore-", delete=False, dir=case.path) as output:
                        temporary = Path(output.name)
                        with source_reader(artifact["id"]) as stream:
                            digest, length = hashlib.sha256(), 0
                            while chunk := stream.read(1024 ** 2):
                                length += len(chunk)
                                if length > artifact["size"] or length > policy["max_source_bytes"]:
                                    raise ProbentiumError("restore_source_size_mismatch", 4)
                                digest.update(chunk)
                                output.write(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                    if length != artifact["size"] or digest.hexdigest() != artifact["id"]:
                        raise ProbentiumError("restore_source_digest_mismatch", 4)
                    case._acquire(temporary)
                finally:
                    if temporary is not None:
                        temporary.unlink(missing_ok=True)
                case.db.execute("INSERT INTO artifacts VALUES(?,?,?,?)", (artifact["id"], artifact["size"], *_dump(artifact)))
            for item in snapshot["acquisitions"]:
                case.db.execute("INSERT INTO acquisitions VALUES(?,?,?,?)", (item["id"], item["artifact_id"], *_dump(item)))
            for item in snapshot["records"]:
                case.db.execute("INSERT INTO records VALUES(?,?,?,?,?,?,?)", (*(item[k] for k in ("id", "artifact_id", "ordinal", "offset", "length")), *_dump(item)))
            for item in snapshot["parse_runs"]:
                case.db.execute("INSERT INTO parse_runs VALUES(?,?,?,?)", (item["id"], item["artifact_id"], *_dump(item)))
            for item in snapshot["active_runs"]:
                case.db.execute("INSERT INTO active_runs VALUES(?,?,?)", tuple(item[k] for k in ("artifact_id", "parse_run_id", "digest")))
            for item in snapshot["parse_records"]:
                case.db.execute("INSERT INTO parse_records VALUES(?,?,?,?,?)", tuple(item[k] for k in ("parse_run_id", "record_id", "disposition", "code", "digest")))
            for item in snapshot["events"]:
                case.db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (*(item[k] for k in ("id", "artifact_id", "parse_run_id", "ordinal")),
                                None if item["time_low_us"] is None else int(item["time_low_us"]), None if item["time_high_us"] is None else int(item["time_high_us"]),
                                item["kind"], item["host"], item["actor"], canonical_bytes(item["normalized_output"]).decode().casefold(), *_dump(item)))
            for item in snapshot["objects"]:
                case.db.execute("INSERT INTO objects VALUES(?,?,?,?,?)", (item["id"], item["kind"], item["revision"], canonical_bytes(item["data"]),
                                object_digest({"kind": item["kind"], "data": item["data"], "revision": item["revision"]})))
            meta = dict(snapshot["meta"])
            if meta["revision"] < 1 and any(snapshot[k] for k in ("objects", "artifacts")):
                raise ProbentiumError("invalid_snapshot_revision", 4)
            meta["catalog_digest"] = _catalog_digest(case.db)
            if meta["catalog_digest"] != snapshot["meta"]["catalog_digest"]:
                raise ProbentiumError("restore_catalog_mismatch", 4)
            case.db.execute("UPDATE meta SET data=?,digest=? WHERE key='case'", _dump(meta))
        # Revisio nova originem conservat, exportum pristinum non usurpat.
        check = case.verify()
        if not check["ok"]:
            raise ProbentiumError("restore_integrity_failed", 4)
        receipt = {"schema": "probentium.restore-receipt.v1", "source_snapshot_digest": snapshot.snapshot_digest if hasattr(snapshot, "snapshot_digest") else hashlib.sha256(canonical_bytes(snapshot)).hexdigest(),
                   "source_revision": snapshot["meta"]["revision"], "revision": case.revision, "integrity": "passed",
                   "resource_policy": policy, "resource_policy_digest": resource_limits.digest(policy)}
        return receipt


@_maintenance_errors
def migrate_v1(source, destination, *, resource_policy=None):
    resource_limits.resolve(resource_policy)
    target = Path(os.path.abspath(destination))
    with _directory(target.parent):
        pass
    with tempfile.TemporaryDirectory(prefix=".migration-", dir=target.parent) as staging:
        case_path = Path(staging) / "case"
        receipt = _migrate_v1(source, case_path, resource_policy=resource_policy)
        _publish_directory(case_path, target)
    return {**receipt, "completion": "atomically_published_after_verification"}


MAX_LEGACY_HISTORY = 32 * 1024 ** 2
MAX_LEGACY_ROWS = 100000
MAX_LEGACY_SNAPSHOTS = 128


def _legacy_snapshot_json(raw):
    """Altitudo et numerus separatorum ante constructionem finiuntur."""
    from testifex.model import strict_json as old_json
    depth = separators = 0
    quoted = escaped = False
    for ch in raw:
        if quoted:
            if escaped:
                escaped = False
            elif ch == 92:
                escaped = True
            elif ch == 34:
                quoted = False
        elif ch == 34:
            quoted = True
        elif ch in (91, 123):
            depth += 1
            separators += 1
        elif ch in (93, 125):
            depth -= 1
        elif ch in (44, 58):
            separators += 1
        if depth > 32 or separators > 2_000_000:
            raise ProbentiumError("legacy_snapshot_structure_limit", 6)
    try:
        return old_json(raw)
    except (ValueError, RecursionError):
        raise ProbentiumError("legacy_snapshot_invalid", 4) from None


def _legacy_bounds(db):
    """Limites SQL ante interpretationem historiarum statuuntur."""
    total = 0
    for table, expression, cap in (("meta", "length(value)", 16), ("sources", "length(data)", 10000),
                                  ("events", "length(data)", MAX_LEGACY_ROWS), ("hypotheses", "length(data)", 10000),
                                  ("hypothesis_evidence", "length(note)+128", MAX_LEGACY_ROWS),
                                  ("issues", "length(code)+128", MAX_LEGACY_ROWS),
                                  ("snapshots", "length(label)+128", MAX_LEGACY_SNAPSHOTS)):
        count, size = db.execute("SELECT count(*),coalesce(sum(" + expression + "),0) FROM " + table).fetchone()
        total += size
        if count > cap or total > MAX_LEGACY_HISTORY:
            raise ProbentiumError("legacy_history_limit", 6)


def _legacy_chunks(target, section, rows, encoding="original_json_text"):
    """Textus JSON pristinus integrum servatur, non approbatur."""
    saved, chunk, size = [], [], 0
    def flush():
        if chunk:
            item = target.put_object("legacy_history", {"schema": "probentium.legacy-history.v1", "interpretation": "legacy_v1",
                "section": section, "encoding": encoding, "rows": list(chunk), "review_status": "not_carried_forward"})
            saved.append(item["id"])
    for raw in rows:
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 2 * 1024 ** 2:
            raise ProbentiumError("legacy_history_row_limit", 6)
        length = len(raw.encode("utf-8"))
        if chunk and (len(chunk) == 128 or size + length > 2 * 1024 ** 2):
            flush(); chunk, size = [], 0
        chunk.append(raw); size += length
    flush()
    return saved


def _legacy_event_mapping(legacy, target, source, run_id):
    """Locatores et interpretatio sine correctione horologii comparantur."""
    from testifex.model import strict_json as old_json, canonical as old_canonical
    extras = {"id", "source_id", "ordinal", "offset", "length", "raw_sha256", "original_low_us", "original_high_us",
              "clock_offset_us", "clock_error_us"}
    def mappings():
        for raw, in legacy.db.execute("SELECT data FROM events WHERE source_id=? ORDER BY ordinal", (source["id"],)):
            event = old_json(raw)
            found = target.db.execute("SELECT data FROM events WHERE parse_run_id=? AND ordinal=?", (run_id, event["ordinal"])).fetchall()
            if len(found) != 1:
                raise ProbentiumError("migration_event_mapping_mismatch", 4)
            current = strict_json(found[0][0])
            uncorrected = {key: value for key, value in event.items() if key not in extras}
            uncorrected["time_low_us"], uncorrected["time_high_us"] = event["original_low_us"], event["original_high_us"]
            if (any(current[key] != event[key] for key in ("ordinal", "offset", "length"))
                    or current["raw_digest"] != event["raw_sha256"] or current["normalized_output"] != _normalized(uncorrected)):
                raise ProbentiumError("migration_normalization_mismatch", 4)
            yield old_canonical({"old": event["id"], "new": current["id"], "raw_sha256": event["raw_sha256"],
                                 "comparison": "same_record_uncorrected_normalization"})
    refs = _legacy_chunks(target, "event_mapping", mappings(), "canonical_mapping_json")
    mapped = target.db.execute("SELECT count(*) FROM events WHERE parse_run_id=? AND ordinal<=?", (run_id, source["lines_total"])).fetchone()[0]
    clock_changes = []
    for row in legacy.db.execute("SELECT ordinal,code FROM issues WHERE source_id=?", (source["id"],)):
        count = target.db.execute("SELECT count(*) FROM events WHERE parse_run_id=? AND ordinal=?", (run_id, row[0])).fetchone()[0]
        if count:
            if row[1] != "corrected_time_out_of_range" or count != 1:
                raise ProbentiumError("migration_disposition_mismatch", 4)
            clock_changes.append(row[0])
    if mapped != source["parsed_count"] + len(clock_changes):
        raise ProbentiumError("migration_event_count_mismatch", 4)
    return refs, clock_changes


def _migrate_v1(source, destination, *, resource_policy=None):
    """Exemplar vetus modo lectionis aperitur; sententiae non transferuntur."""
    policy = resource_limits.resolve(resource_policy)
    from testifex.case import Case, SCHEMA
    from testifex.model import strict_json as old_json
    root = Path(os.path.abspath(source))
    with _directory(root, private=True) as directory:
        for suffix in ("-journal", "-wal", "-shm"):
            try:
                os.stat("case.sqlite3" + suffix, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ProbentiumError("legacy_recovery_required", 4)
        db, identity = _connect_checked(root, directory, readonly=True)
    try:
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        model = sqlite3.connect(":memory:")
        try:
            model.executescript(SCHEMA)
            if db.execute("PRAGMA user_version").fetchone()[0] != 1 or _schema_rows(db) != _schema_rows(model):
                raise ProbentiumError("unsupported_legacy_schema", 7)
        finally:
            model.close()
        db.row_factory = sqlite3.Row
        _legacy_bounds(db)
        legacy = object.__new__(Case)
        legacy.path, legacy.db = root, db
        legacy.metadata = {row["key"]: old_json(row["value"]) for row in db.execute("SELECT * FROM meta")}
        if (set(legacy.metadata) != {"schema_version", "tool_version", "case_id", "name"}
                or legacy.metadata["schema_version"] != 1 or not isinstance(legacy.metadata["case_id"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", legacy.metadata["case_id"])):
            raise ProbentiumError("unsupported_legacy_metadata", 7)
        sources = legacy.sources()
        from testifex.parsers import PARSER_VERSION
        from .store import MAX_CASE_BYTES, MAX_RECORDS
        if any(item["parser_version"] != PARSER_VERSION for item in sources):
            raise ProbentiumError("legacy_parser_version_unavailable", 7)
        if any(item["size"] > policy["max_source_bytes"] for item in sources) or sum(item["size"] for item in sources) > policy["max_case_bytes"]:
            raise ProbentiumError("legacy_source_size_limit", 6)
        if not legacy.verify()["ok"]:
            raise ProbentiumError("legacy_integrity_failed", 4)
        with CaseStore.create(destination, legacy.metadata["name"], resource_policy=resource_policy) as target:
            mappings, assertions, history, snapshots = [], [], {}, []
            for table in ("sources", "events", "hypotheses"):
                history[table] = _legacy_chunks(target, table, (row[0] for row in db.execute("SELECT data FROM " + table + " ORDER BY id")))
            from testifex.model import canonical as old_canonical
            for table, order in (("hypothesis_evidence", "hypothesis_id,event_id,stance"), ("issues", "source_id,ordinal")):
                history[table] = _legacy_chunks(target, table, (old_canonical(dict(row)) for row in db.execute("SELECT * FROM " + table + " ORDER BY " + order)), "canonical_legacy_row_json")
            total_records = 0
            for item in sources:
                result = target.ingest(root / "evidence" / (item["sha256"] + ".bin"), item["format"], item["label"], expected_sha256=item["sha256"])
                if result["state"] != "complete" or total_records + result["records_total"] > policy["max_import_records"]:
                    raise ProbentiumError("migration_record_limit", 6)
                total_records += result["records_total"]
                event_refs, clock_changes = _legacy_event_mapping(legacy, target, item, result["parse_run_id"])
                mappings.append({"old_source_id": item["id"], "artifact_id": result["id"], "parse_run_id": result["parse_run_id"],
                    "event_mapping_objects": event_refs, "mapped_events": item["parsed_count"], "legacy_state": item["status"],
                    "legacy_cursor": item["cursor"], "new_events": result["events_total"],
                    "new_records_after_legacy_prefix": result["records_total"] - item["lines_total"],
                    "clock_neutral_new_event_ordinals": clock_changes})
                assertions.append({"old_source_id": item["id"], "legacy_options": {k: str(v) if k.endswith("_us") and v is not None else v for k, v in item["options"].items()},
                                   "status": "requires_new_clock_review", "activated": False})
            for row in db.execute("SELECT id,label,sha256 FROM snapshots ORDER BY id"):
                if not isinstance(row[0], str) or not re.fullmatch(r"[0-9a-f]{64}", row[0]) or row[0] != row[2]:
                    raise ProbentiumError("legacy_snapshot_identity_invalid", 4)
                path = root / "snapshots" / (row[2] + ".json")
                with regular_reader(path, 64 * 1024 ** 2) as (stream, _):
                    raw = stream.read(64 * 1024 ** 2 + 1)
                if hashlib.sha256(raw).hexdigest() != row[2]:
                    raise ProbentiumError("legacy_snapshot_digest_mismatch", 4)
                value = _legacy_snapshot_json(raw)
                meaning = "opaque_historical_json"
                if isinstance(value, dict) and value.get("schema") == "testifex.report.v1":
                    from testifex.report import validate_report
                    try:
                        validate_report(value)
                    except (ValueError, TypeError, KeyError):
                        raise ProbentiumError("legacy_report_replay_failed", 4) from None
                    meaning = "historical_report_semantics_replayed"
                acquired = target.ingest(path, "opaque", "Legacy snapshot " + row[0][:12], expected_sha256=row[2])
                snapshots.append({"old_snapshot_id": row[0], "artifact_id": acquired["id"], "label": row[1],
                                  "interpretation": "legacy_v1", "verification": meaning, "approval_effect": "none"})
            record = {"schema": "probentium.migration.v2", "interpretation": "legacy_v1", "source_case_id": legacy.metadata["case_id"],
                      "source_metadata_json": old_canonical(legacy.metadata), "mapping": mappings, "historical_objects": history,
                      "historical_snapshots": snapshots, "clock_assertions": assertions,
                      "legacy_review_status": "not_carried_forward", "new_claims_created": False, "source_modified": False}
            saved = target.put_object("migration", record)
            if not target.verify()["ok"]:
                raise ProbentiumError("migration_integrity_failed", 4)
            with _directory(root, private=True) as original:
                _assert_database_binding(root, original, identity)
            return {"migration_id": saved["id"], "sources": len(sources), "revision": target.revision, "source_modified": False,
                    "resource_policy": policy, "resource_policy_digest": resource_limits.digest(policy)}
    finally:
        db.close()


def _sync_publication_tree(path):
    """Folia et directoria prius durabilia fiunt; nexus alieni recusantur."""
    from .store import MAX_ARTIFACTS
    def synchronize(directory, depth):
        with _directory(directory, private=True) as parent:
            names = []
            with os.scandir(parent) as entries:
                for entry in entries:
                    if len(names) >= 2 * MAX_ARTIFACTS + 8:
                        raise ProbentiumError("publication_entry_limit", 6)
                    names.append(entry.name)
            try:
                for name in sorted(names):
                    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        if depth or name != "blobs":
                            raise ProbentiumError("invalid_publication_directory", 4)
                        synchronize(directory / name, depth + 1)
                    else:
                        descriptor = _private_file(parent, name)
                        try:
                            os.fsync(descriptor)
                        finally:
                            os.close(descriptor)
                os.fsync(parent)
            except OSError as exc:
                raise ProbentiumError("storage_resource_limit" if exc.errno in (errno.ENOSPC, errno.EDQUOT)
                                      else "directory_prepare_sync_failed", 6 if exc.errno in (errno.ENOSPC, errno.EDQUOT) else 4) from None
    synchronize(Path(path), 0)


def _rename_noreplace(source_parent, source_name, target_parent, target_name):
    """Unus syscall finem exclusivum constituit."""
    import ctypes
    library = ctypes.CDLL(None, use_errno=True)
    function = getattr(library, "renameat2", None)
    if function is None:
        raise ProbentiumError("exclusive_directory_publish_unsupported", 7)
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(source_parent, os.fsencode(source_name), target_parent, os.fsencode(target_name), 1):
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise ProbentiumError("destination_exists", 2)
        raise OSError(code, "directory publication failed")


def _publish_directory(source, destination):
    """Post renomen exitus incertus exemplum integrum non delet."""
    source, destination = Path(source), Path(os.path.abspath(destination))
    published = False
    with _directory(source.parent) as source_parent, _directory(destination.parent) as target_parent:
        try:
            _sync_publication_tree(source)
            os.fsync(source_parent)
            os.fsync(target_parent)
            _rename_noreplace(source_parent, source.name, target_parent, destination.name)
            published = True
            os.fsync(source_parent)
            os.fsync(target_parent)
        except OSError as exc:
            if published:
                raise ProbentiumError("directory_published_durability_unknown", 4) from None
            if exc.errno in (errno.ENOSPC, errno.EDQUOT):
                raise ProbentiumError("storage_resource_limit", 6) from None
            raise ProbentiumError("directory_publication_failed", 4) from None


@_maintenance_errors
def restore_packet(path, destination, *, trust_store=None, require_trusted_key=False, require_signature=False, resource_policy=None):
    resource_limits.resolve(resource_policy)
    from .exchange import open_verified_snapshot
    target = Path(os.path.abspath(destination))
    with _directory(target.parent):
        pass
    with tempfile.TemporaryDirectory(prefix=".restore-", dir=target.parent) as staging:
        case_path = Path(staging) / "case"
        with open_verified_snapshot(path, trust_store=trust_store, require_trusted_key=require_trusted_key, require_signature=require_signature, resource_policy=resource_policy) as (_, snapshot, reader):
            receipt = restore_snapshot(snapshot, reader, case_path, resource_policy=resource_policy)
        _publish_directory(case_path, target)
    return {**receipt, "completion": "atomically_published_after_packet_verification"}


@_maintenance_errors
def recover_copy(source, destination, *, resource_policy=None):
    """Diarium tantum in exemplari privato reparatur."""
    policy = resource_limits.resolve(resource_policy)
    import fcntl
    import re
    from .store import MAX_DATABASE, MAX_CASE_BYTES, MAX_ARTIFACTS
    source, target = Path(os.path.abspath(source)), Path(os.path.abspath(destination))
    with _directory(source, private=True) as directory, _directory(target.parent):
        lock = _private_file(directory, "case.lock", os.O_RDWR)
        try:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ProbentiumError("case_locked", 5) from None
            for name in ("case.sqlite3-wal", "case.sqlite3-shm"):
                try:
                    os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise ProbentiumError("wal_recovery_unsupported", 7)
            with tempfile.TemporaryDirectory(prefix=".recovery-", dir=target.parent) as staging:
                case_path = Path(staging) / "case"
                case_path.mkdir(mode=0o700)
                (case_path / "blobs").mkdir(mode=0o700)
                total = 0
                def copy_file(parent, name, output, maximum):
                    nonlocal total
                    fd = _private_file(parent, name)
                    with os.fdopen(fd, "rb") as stream:
                        before = os.fstat(stream.fileno())
                        if before.st_size > maximum:
                            raise ProbentiumError("recovery_size_limit", 6)
                        total += before.st_size
                        if total > policy["max_case_bytes"] + 2 * MAX_DATABASE:
                            raise ProbentiumError("recovery_size_limit", 6)
                        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        with os.fdopen(descriptor, "wb") as writer:
                            copied = 0
                            for chunk in iter(lambda: stream.read(1024 ** 2), b""):
                                copied += len(chunk)
                                if copied > before.st_size:
                                    raise ProbentiumError("recovery_source_changed", 4)
                                writer.write(chunk)
                            writer.flush()
                            os.fsync(writer.fileno())
                        after = os.fstat(stream.fileno())
                        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                        if (copied != before.st_size or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
                                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                            raise ProbentiumError("recovery_source_changed", 4)
                copy_file(directory, "case.sqlite3", case_path / "case.sqlite3", MAX_DATABASE)
                journal_present = False
                try:
                    os.stat("case.sqlite3-journal", dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    journal_present = True
                    copy_file(directory, "case.sqlite3-journal", case_path / "case.sqlite3-journal", MAX_DATABASE)
                with _directory(source / "blobs", private=True) as blobs:
                    with os.scandir(blobs) as entries:
                        for count, entry in enumerate(entries, 1):
                            name = entry.name
                            if count > 2 * MAX_ARTIFACTS or not re.fullmatch(r"(?:[a-f0-9]{64}\.bin|\.incoming-[a-f0-9]{32})", name):
                                raise ProbentiumError("invalid_recovery_blob", 4)
                            copy_file(blobs, name, case_path / "blobs" / name, policy["max_source_bytes"])
                descriptor = os.open(case_path / "case.lock", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                db = sqlite3.connect(case_path / "case.sqlite3")
                try:
                    db.enable_load_extension(False)
                    db.execute("PRAGMA trusted_schema=OFF")
                    if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                        raise ProbentiumError("recovery_database_invalid", 4)
                finally:
                    db.close()
                remaining_journal = case_path / "case.sqlite3-journal"
                if remaining_journal.exists():
                    remaining_journal.unlink()
                with CaseStore(case_path) as case:
                    check = case.verify()
                    if not check["ok"]:
                        raise ProbentiumError("recovery_integrity_failed", 4)
                    receipt = {"schema": "probentium.recovery-copy.v1", "source_modified": False, "journal_recovery_attempted": journal_present,
                               "revision": case.revision, "verification": check,
                               "resource_policy": policy, "resource_policy_digest": resource_limits.digest(policy)}
                _publish_directory(case_path, target)
                return receipt
        finally:
            os.close(lock)
