"""Fasciculus finitus sine extractione nec SQL alieno legitur."""
import hashlib
import hmac
import io
import os
import re
import selectors
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from contextlib import contextmanager
from collections.abc import Mapping, Sequence
from pathlib import Path

from testifex.model import CaseError
from testifex.safeio import regular_reader, _parent_directory
from . import __version__
from .contracts import ProbentiumError, canonical_bytes, object_digest, strict_json, text_field
from .signatures import sign_manifest, verify_manifest_signature, read_private_key, validate_trust_store
from . import limits as resource_limits

MAX_PACKET = 8 * 1024 ** 3
MAX_BLOB = 4 * 1024 ** 3
MAX_JSON = 64 * 1024 ** 2
MAX_MEMBERS = 20_000
MAX_SIGNATURES = 16
MAX_PADDING = 10 * 1024
MAX_CHUNK = 16 * 1024 ** 2
MAX_SNAPSHOT_BYTES = 4 * 1024 ** 3
_TABLES = ("acquisitions", "active_runs", "artifacts", "events", "objects", "parse_records", "parse_runs", "records")
_TABLE_CAPS = {"artifacts": 20000, "acquisitions": 20000, "records": 1000000, "parse_runs": 20000,
               "active_runs": 20000, "parse_records": 1000000, "events": 1000000, "objects": 10000}
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_PROFILES = {"testifex.packet.v1": {"private_full", "public_summary"}, "probentium.packet.v1": {"private_full", "recipient_dossier"}}
_TYPES = {"source.bytes", "normalized.events", "interpretation.set", "analysis.result", "review.history", "acquisition.metadata",
          "legal_pack", "applicability", "control_evidence", "reporting_track", "filing_snapshot", "filing_approval", "submission_record", "correction_impact", "retention_record", "recipient_dossier"}
_EU_KINDS = {"control": "control_evidence", "track": "reporting_track", "filing": "filing_snapshot",
             "legal_pack": "legal_pack", "applicability": "applicability", "filing_approval": "filing_approval",
             "submission_record": "submission_record", "correction_impact": "correction_impact", "retention_record": "retention_record"}
_GOVERNANCE = {"service", "supplier", "dependency", "control_implementation", "evidence_assertion", "control_test", "exception", "approval", "training", "awareness", "applicability", "control_population", "control_observation", "obligation_anchor"}
_LEGAL = {"legal_pack", "legal_review", "legal_activation", "requirement_catalogue", "legal_coverage_audit"}
_REPORTING = {"reporting_track", "filing_snapshot", "filing_approval", "submission_record", "receipt", "correction_impact", "deadline_evaluation"}
_RETENTION = {"retention.hold", "retention.plan", "retention.approval", "retention.tombstone"}
_EU_KINDS.update({"eu." + name: "applicability" if name == "applicability" else "reporting_track" if name == "awareness" else "control_evidence" for name in _GOVERNANCE})
_EU_KINDS.update({"eu." + name: "legal_pack" for name in _LEGAL})
_EU_KINDS.update({"eu." + name: "reporting_track" if name == "deadline_evaluation" else "submission_record" if name == "receipt" else name for name in _REPORTING})
_EU_KINDS.update({name: "retention_record" for name in _RETENTION})


def _fail(code, status=4):
    raise ProbentiumError(code, status)


def _hex(value):
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        _fail("invalid_packet_identifier")
    return value


def _json_nodes(raw):
    """Numerus nodorum ante materializationem cohibetur."""
    quoted = escaped = False
    nodes = 0
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
            nodes += 1
        elif byte in (44, 58, 91, 123):
            nodes += 1
        if nodes > 1_000_000:
            _fail("packet_json_nodes_limit", 6)
    return nodes


def _json(raw, maximum=MAX_JSON):
    if len(raw) > maximum:
        _fail("packet_json_limit", 6)
    _json_nodes(raw)
    value = strict_json(raw, maximum)
    if canonical_bytes(value) != raw:
        _fail("packet_json_not_canonical")
    return value


def _header(name, size):
    item = tarfile.TarInfo(name)
    item.size, item.mode, item.uid, item.gid, item.mtime = size, 0o600, 0, 0, 0
    item.uname = item.gname = ""
    return item.tobuf(format=tarfile.USTAR_FORMAT)


def _parse_header(raw):
    if len(raw) != 512:
        _fail("truncated_tar_header")
    try:
        name = raw[:100].split(b"\0", 1)[0].decode("ascii")
        size_raw = raw[124:136]
        if not re.fullmatch(rb"[0-7]{11}\0", size_raw):
            _fail("noncanonical_tar_size")
        size = int(size_raw[:-1], 8)
        if name not in ("manifest.json",) and not re.fullmatch(r"blobs/[a-f0-9]{64}|signatures/[a-f0-9]{64}\.json", name):
            _fail("unexpected_tar_member")
        if size > MAX_BLOB:
            _fail("packet_blob_limit", 6)
        if raw != _header(name, size):
            _fail("noncanonical_ustar_header")
        return name, size
    except (UnicodeError, ValueError, tarfile.TarError):
        _fail("invalid_tar_header")


def _policy(value=None):
    return resource_limits.resolve(value, defaults={"max_packet_bytes": MAX_PACKET})


def _table_caps(policy, explicit=False):
    rows = resource_limits.HARD_CAPS["max_import_records"] if explicit else _TABLE_CAPS["records"]
    return {**_TABLE_CAPS, "records": rows, "parse_records": rows,
            "events": policy["max_case_events"]}


def _manifest(value, resource_policy=None):
    policy = _policy(resource_policy)
    fields = {"schema", "canonicalization", "digest_algorithm", "profile", "case_schema", "case_id", "revision", "snapshot_digest", "tool_version", "parser_versions", "engine_version", "objects", "withheld"}
    if not isinstance(value, dict) or set(value) not in (fields, fields | {"resource_policy"}):
        _fail("invalid_packet_manifest")
    declared = resource_limits.validate(value["resource_policy"]) if "resource_policy" in value else _policy()
    packet_cap = min(policy["max_packet_bytes"], declared["max_packet_bytes"])
    if value["schema"] not in _PROFILES:
        _fail("unsupported_packet_schema", 7)
    if value["profile"] not in _PROFILES[value["schema"]] or value["canonicalization"] != "rfc8785" or value["digest_algorithm"] != "sha256" or value["case_schema"] != 2:
        _fail("invalid_packet_manifest")
    if not isinstance(value["case_id"], str) or not re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{64}", value["case_id"]):
        _fail("invalid_packet_case_id")
    if len(value["case_id"]) != (64 if value["profile"] == "public_summary" else 32):
        _fail("invalid_packet_case_id")
    if type(value["revision"]) is not int or not 0 <= value["revision"] <= 9007199254740991:
        _fail("invalid_packet_revision")
    for key in ("tool_version", "engine_version"):
        if not isinstance(value[key], str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value[key]):
            _fail("invalid_packet_version")
    if not isinstance(value["parser_versions"], list) or len(value["parser_versions"]) > 64 or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", item) for item in value["parser_versions"]):
        _fail("invalid_parser_versions")
    if value["parser_versions"] != sorted(set(value["parser_versions"])):
        _fail("invalid_parser_versions")
    objects = value["objects"]
    if not isinstance(objects, list) or not 1 <= len(objects) < min(MAX_MEMBERS, policy["max_packet_members"]):
        _fail("packet_member_limit", 6)
    previous, total = "", 0
    for obj in objects:
        if not isinstance(obj, dict) or set(obj) != {"sha256", "byte_length", "content_type", "schema"}:
            _fail("invalid_blob_descriptor")
        ident = _hex(obj["sha256"])
        if ident <= previous:
            _fail("blob_order_or_duplicate")
        previous = ident
        if type(obj["byte_length"]) is not int or not 0 <= obj["byte_length"] <= MAX_BLOB:
            _fail("packet_blob_limit", 6)
        total += obj["byte_length"]
        if total > packet_cap:
            _fail("packet_size_limit", 6)
        if obj["content_type"] not in _TYPES or not isinstance(obj["schema"], str) or not re.fullmatch(r"[a-z0-9._-]{1,96}", obj["schema"]):
            _fail("unsupported_blob_schema", 7)
        if value["schema"] == "testifex.packet.v1" and obj["content_type"] in set(_EU_KINDS.values()) | {"recipient_dossier"}:
            _fail("eu_content_in_core_packet")
    if value["snapshot_digest"] not in {obj["sha256"] for obj in objects}:
        _fail("snapshot_reference_missing")
    withheld = value["withheld"]
    if not isinstance(withheld, list) or len(withheld) > MAX_MEMBERS:
        _fail("withholding_limit", 6)
    refs = []
    for item in withheld:
        if not isinstance(item, dict) or set(item) != {"ref", "reason"} or item["reason"] != "excluded_by_projection":
            _fail("invalid_withholding")
        refs.append(_hex(item["ref"]))
    if refs != sorted(set(refs)) or value["profile"] == "private_full" and withheld:
        _fail("invalid_withholding")
    return value


def _row_key(table, row):
    if not isinstance(row, dict):
        _fail("invalid_snapshot_row")
    if table == "active_runs":
        return _hex(row.get("artifact_id"))
    if table == "parse_records":
        return _hex(row.get("parse_run_id")) + ":" + _hex(row.get("record_id"))
    key = row.get("id")
    if table == "acquisitions":
        if not isinstance(key, str) or not re.fullmatch(r"[a-f0-9]{32}", key):
            _fail("invalid_snapshot_identity")
        return key
    return _hex(key)


class _Rows(Sequence):
    def __init__(self, view, table):
        self.view, self.table = view, table

    def __len__(self):
        return self.view.counts[self.table]

    def __iter__(self):
        for raw, in self.view.db.execute("SELECT payload FROM rows WHERE tab=? ORDER BY identity", (self.table,)):
            yield strict_json(raw, MAX_CHUNK)

    def __getitem__(self, index):
        if type(index) is not int:
            raise TypeError("snapshot_integer_index_required")
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError("snapshot_index_out_of_range")
        row = self.view.db.execute("SELECT payload FROM rows WHERE tab=? ORDER BY identity LIMIT 1 OFFSET ?", (self.table, index)).fetchone()
        return strict_json(row[0], MAX_CHUNK)


class _RowMap(Mapping):
    def __init__(self, rows):
        self.rows = rows

    def __len__(self):
        return len(self.rows)

    def __iter__(self):
        for key, in self.rows.view.db.execute("SELECT identity FROM rows WHERE tab=? ORDER BY identity", (self.rows.table,)):
            yield key

    def __getitem__(self, key):
        if not isinstance(key, str):
            raise KeyError(key)
        row = self.rows.view.db.execute("SELECT payload FROM rows WHERE tab=? AND identity=?", (self.rows.table, key)).fetchone()
        if row is None:
            raise KeyError(key)
        return strict_json(row[0], MAX_CHUNK)

    def values(self):
        return iter(self.rows)

    def items(self):
        for row in self.rows:
            yield _row_key(self.rows.table, row), row


class SnapshotView(Mapping):
    """Index localis e JSON tantum; nulla basis aliena aperitur."""
    def __init__(self, resource_policy=None):
        self.resource_policy = _policy(resource_policy)
        self.explicit_policy = resource_policy is not None
        self.table_caps = _table_caps(self.resource_policy, self.explicit_policy)
        self.directory = tempfile.TemporaryDirectory(prefix="snapshot-")
        os.chmod(self.directory.name, 0o700)
        path = Path(self.directory.name) / "index"
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=OFF")
        self.db.execute("PRAGMA temp_store=FILE")
        self.db.execute("PRAGMA cache_size=-8192")
        self.db.execute("CREATE TABLE rows(tab TEXT,identity TEXT,payload BLOB,artifact TEXT,run TEXT,record TEXT,offset INTEGER,disposition TEXT,PRIMARY KEY(tab,identity)) WITHOUT ROWID")
        self.db.execute("CREATE INDEX by_run ON rows(tab,run,offset,identity)")
        self.db.execute("CREATE INDEX by_record ON rows(tab,run,record)")
        self.counts = dict.fromkeys(_TABLES, 0)
        self.meta, self.chunks, self.closed, self.snapshot_digest = None, {}, False, None

    def close(self):
        if not self.closed:
            self.db.close()
            self.directory.cleanup()
            self.closed = True

    def __len__(self):
        return len(_TABLES) + 2

    def __iter__(self):
        return iter(("schema", "meta", *_TABLES))

    def __getitem__(self, name):
        if name == "schema":
            return "probentium.case-snapshot.v1"
        if name == "meta":
            return self.meta
        if name not in _TABLES:
            raise KeyError(name)
        return _Rows(self, name)

    def iter_table(self, name):
        if name not in _TABLES:
            _fail("unsupported_snapshot_table", 7)
        return iter(self[name])

    def lookup(self, table, identity):
        if table not in _TABLES:
            _fail("unsupported_snapshot_table", 7)
        return _RowMap(self[table]).get(identity)

    def iter_run_events(self, run_id):
        _hex(run_id)
        for raw, in self.db.execute("SELECT payload FROM rows WHERE tab='events' AND run=? ORDER BY offset,identity", (run_id,)):
            yield strict_json(raw, MAX_CHUNK)

    def iter_run_records(self, run_id):
        _hex(run_id)
        for raw, in self.db.execute("SELECT r.payload FROM rows p JOIN rows r ON r.tab='records' AND r.identity=p.record WHERE p.tab='parse_records' AND p.run=? ORDER BY r.offset,r.identity", (run_id,)):
            yield strict_json(raw, MAX_CHUNK)

    def event_for_record(self, run_id, record_id):
        _hex(run_id)
        _hex(record_id)
        rows = self.db.execute("SELECT payload FROM rows WHERE tab='events' AND run=? AND record=? LIMIT 2", (run_id, record_id)).fetchall()
        if len(rows) > 1:
            _fail("duplicate_normalized_observation")
        return strict_json(rows[0][0], MAX_CHUNK) if rows else None

    def add_chunk(self, digest, value):
        if (not isinstance(value, dict) or set(value) != {"schema", "table", "rows"}
                or value["schema"] != "probentium.case-snapshot-chunk.v1" or value["table"] not in _TABLES
                or not isinstance(value["rows"], list) or not value["rows"]):
            _fail("invalid_snapshot_chunk")
        table, previous = value["table"], ""
        if self.counts[table] + len(value["rows"]) > self.table_caps[table]:
            _fail("snapshot_count_limit", 6)
        for row in value["rows"]:
            key = _row_key(table, row)
            if key <= previous:
                _fail("snapshot_chunk_row_order")
            previous = key
            scalars = [row.get("artifact_id"), row.get("parse_run_id"), row.get("record_id", row.get("primary_record_ref")), row.get("offset"), row.get("disposition")]
            if any(v is not None and type(v) not in (str, int) for v in scalars) or type(scalars[3]) is int and not 0 <= scalars[3] <= MAX_BLOB:
                _fail("invalid_snapshot_index_value")
            try:
                self.db.execute("INSERT INTO rows VALUES(?,?,?,?,?,?,?,?)", (table, key, canonical_bytes(row), *scalars))
            except (sqlite3.IntegrityError, OverflowError):
                _fail("duplicate_or_invalid_snapshot_row")
        self.counts[table] += len(value["rows"])
        self.chunks[digest] = {"table": table, "count": len(value["rows"]), "first": _row_key(table, value["rows"][0]), "last": previous}

    def bind(self, index):
        if not isinstance(index, dict) or set(index) != {"schema", "meta", "tables"} or index["schema"] != "probentium.case-snapshot-index.v1" or not isinstance(index["tables"], list) or len(index["tables"]) != len(_TABLES):
            _fail("invalid_snapshot_index")
        seen = set()
        for expected, table in zip(_TABLES, index["tables"]):
            if (not isinstance(table, dict) or set(table) != {"name", "count", "chunks"} or table["name"] != expected
                    or type(table["count"]) is not int or table["count"] != self.counts[expected]
                    or not isinstance(table["chunks"], list) or len(table["chunks"]) > MAX_MEMBERS):
                _fail("snapshot_index_count_or_order")
            previous, count = "", 0
            for digest in table["chunks"]:
                chunk = self.chunks.get(_hex(digest))
                if digest in seen or chunk is None or chunk["table"] != expected or chunk["first"] <= previous:
                    _fail("snapshot_chunk_reference_mismatch")
                seen.add(digest)
                previous = chunk["last"]
                count += chunk["count"]
            if count != table["count"]:
                _fail("snapshot_chunk_count_mismatch")
        if seen != self.chunks.keys():
            _fail("unreferenced_snapshot_chunk")
        self.meta = index["meta"]
        self.snapshot_digest = hashlib.sha256(canonical_bytes(index)).hexdigest()
        self.db.commit()


def _normalized_output(value):
    """Tempus relatum alignmentum ignotum retinet."""
    from testifex import parsers
    from testifex.timeutil import MIN_TIME_US, MAX_TIME_US
    from .adapters import KINDS
    base = {"kind", "host", "actor", "src_ip", "dst_ip", "path", "action", "attributes", "time_raw", "time_basis", "time_low_us", "time_high_us",
            "recorded_time", "reference_time", "clock_alignment", "time_bounds_semantics"}
    extra = {"source_ip", "payload", "origin", "upstream_locator_status", "source_record_key", "timestamp_semantics"}
    if not isinstance(value, dict) or set(value) not in (base, base | extra):
        _fail("invalid_normalized_output_schema")
    if not isinstance(value["kind"], str) or value["kind"] not in set(parsers.KINDS) | set(KINDS):
        _fail("unsupported_normalized_event_kind", 7)
    for key in ("host", "actor", "src_ip", "dst_ip", "path", "action", "time_raw"):
        if value[key] is not None and (not isinstance(value[key], str) or len(value[key]) > 4096):
            _fail("invalid_normalized_event_text")
    if not isinstance(value["time_basis"], str) or not re.fullmatch(r"[a-z0-9_]{1,128}", value["time_basis"]):
        _fail("invalid_normalized_time_basis")
    if (value["reference_time"] is not None or value["clock_alignment"] != "unknown"
            or value["time_bounds_semantics"] != "legacy_inclusive_microsecond_cells"):
        _fail("unsupported_normalized_clock_semantics", 7)
    low, high = value["time_low_us"], value["time_high_us"]
    if low is None and high is None:
        if value["recorded_time"] is not None:
            _fail("invalid_normalized_time_bounds")
    else:
        if any(not isinstance(item, str) or not re.fullmatch(r"-?(0|[1-9][0-9]{0,17})", item) for item in (low, high)):
            _fail("invalid_normalized_time_bounds")
        recorded = value["recorded_time"]
        if (not MIN_TIME_US <= int(low) <= int(high) <= MAX_TIME_US or not isinstance(recorded, dict)
                or recorded.get("lo_closed") is not True or recorded.get("hi_closed") is not False
                or recorded != {"lo_us": low, "hi_us": str(int(high) + 1), "lo_closed": True, "hi_closed": False}):
            _fail("invalid_normalized_time_bounds")
    if not isinstance(value["attributes"], dict):
        _fail("invalid_normalized_attributes")
    attributes = {}
    for key, item in value["attributes"].items():
        if key.endswith("_us"):
            if not isinstance(item, str) or not re.fullmatch(r"[0-9]{1,19}", item):
                _fail("invalid_normalized_attributes")
            item = int(item)
        attributes[key] = item
    try:
        parsers._attributes(attributes)
    except (parsers.ParseError, ValueError, TypeError):
        _fail("invalid_normalized_attributes")
    if extra <= value.keys():
        from .adapters import parse_v2
        reconstructed = {"schema": "testifex.events.v2", "kind": value["kind"], "recorded_time": None,
                         "origin": value["origin"], "host": value["host"], "actor": value["actor"], "source_ip": value["source_ip"],
                         "source_record_key": value["source_record_key"], "payload": value["payload"], "timestamp_semantics": value["timestamp_semantics"]}
        parse_v2(canonical_bytes(reconstructed))
        if value["upstream_locator_status"] != "supplied_assertion" or value["attributes"] or value["source_ip"] != value["src_ip"]:
            _fail("invalid_normalized_v2_metadata")
    return value


def _snapshot(value, resource_policy=None, *, extended_rows=None):
    """Identitates, rationes et relationes sine SQLite probantur."""
    from .store import _record_id, _run_id, _event_id
    policy = _policy(value.resource_policy if isinstance(value, SnapshotView) and resource_policy is None else resource_policy)
    explicit_rows = resource_policy is not None if extended_rows is None else extended_rows
    if isinstance(value, SnapshotView):
        policy = {**policy, **{key: min(policy[key], value.resource_policy[key]) for key in resource_limits.DEFAULTS}}
        requested = _table_caps(policy, (explicit_rows or value.explicit_policy) if extended_rows is None else explicit_rows)
        table_caps = {key: min(value.table_caps[key], requested[key]) for key in _TABLES}
    else:
        table_caps = _table_caps(policy, explicit_rows)
    keys = {"schema", "meta", "artifacts", "acquisitions", "records", "parse_runs", "active_runs", "parse_records", "events", "objects"}
    if not isinstance(value, (dict, SnapshotView)) or set(value) != keys or value["schema"] != "probentium.case-snapshot.v1":
        _fail("invalid_case_snapshot")
    from .store import _ACCEPTED_LIMITATIONS, _validate_parser_manifest
    meta = value["meta"]
    if (not isinstance(meta, dict) or set(meta) != {"schema_version", "case_id", "name", "revision", "limitations", "catalog_digest"}
            or meta["schema_version"] != 2 or type(meta["revision"]) is not int or not 0 <= meta["revision"] < 9007199254740991
            or not isinstance(meta["case_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", meta["case_id"])
            or meta["limitations"] not in _ACCEPTED_LIMITATIONS):
        _fail("invalid_case_snapshot_meta")
    _hex(meta["catalog_digest"])
    text_field(meta["name"])
    maps = {}
    for name in keys - {"schema", "meta", "active_runs", "parse_records"}:
        rows = value[name]
        if not isinstance(rows, (list, _Rows)) or len(rows) > table_caps[name]:
            _fail("snapshot_count_limit", 6)
        if isinstance(value, SnapshotView):
            maps[name] = _RowMap(rows)
            continue
        table = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str) or row["id"] in table:
                _fail("invalid_snapshot_identity")
            table[row["id"]] = row
        maps[name] = table
    total_source_bytes = 0
    for aid, artifact in maps["artifacts"].items():
        _hex(aid)
        if set(artifact) != {"id", "sha256", "size", "content_type"} or artifact["sha256"] != aid or artifact["content_type"] != "source.bytes" or type(artifact["size"]) is not int or not 0 <= artifact["size"] <= MAX_BLOB:
            _fail("invalid_snapshot_artifact")
        total_source_bytes += artifact["size"]
        if artifact["size"] > policy["max_source_bytes"] or total_source_bytes > policy["max_case_bytes"]:
            _fail("snapshot_evidence_resource_limit", 6)
    if meta["revision"] == 0 and any(maps[name] for name in ("artifacts", "objects")):
        _fail("invalid_snapshot_revision")
    for record in maps["records"].values():
        if set(record) != {"id", "artifact_id", "ordinal", "offset", "length", "raw_digest"} or record["artifact_id"] not in maps["artifacts"] or _record_id(record) != record["id"]:
            _fail("invalid_snapshot_record")
        _hex(record["raw_digest"])
        if any(type(record[k]) is not int for k in ("ordinal", "offset", "length")) or record["ordinal"] < 1 or record["offset"] < 0 or record["length"] < 1 or record["offset"] + record["length"] > maps["artifacts"][record["artifact_id"]]["size"]:
            _fail("invalid_snapshot_record_range")
    for run in maps["parse_runs"].values():
        run_fields = {"id", "artifact_id", "adapter_id", "adapter_version", "parser_artifact_digest", "parser_manifest", "parser_config_digest", "config", "counters", "records_total", "events_total", "cursor", "state", "coverage", "limitations", "unprocessed_bytes", "unprocessed_records", "interpretation_complete"}
        if set(run) != run_fields:
            _fail("invalid_snapshot_parse_schema")
        run_policy = resource_limits.parse_config(run["config"])
        if run_policy is not None and (run.get("artifact_id") not in maps["artifacts"] or maps["artifacts"][run["artifact_id"]]["size"] > run_policy["max_source_bytes"]):
            _fail("snapshot_run_resource_policy_mismatch")
        if (run["config"]["format"] != run["adapter_id"]
                or run["coverage"] != "acquired_stream_only" or run["limitations"] not in _ACCEPTED_LIMITATIONS):
            _fail("invalid_snapshot_parse_config")
        if (not isinstance(run["counters"], dict) or set(run["counters"]) != {"parsed", "blank", "known_out_of_scope", "unsupported", "malformed", "oversize"}
                or any(type(count) is not int or not 0 <= count <= table_caps["records"] for count in run["counters"].values())
                or any(type(run[key]) is not int or not 0 <= run[key] <= MAX_BLOB for key in ("cursor", "records_total", "events_total", "unprocessed_bytes"))
                or type(run["interpretation_complete"]) is not bool
                or run["unprocessed_records"] is not None and (type(run["unprocessed_records"]) is not int or run["unprocessed_records"] != 0)):
            _fail("invalid_snapshot_parse_accounting")
        for key in ("adapter_id", "adapter_version"):
            if not isinstance(run[key], str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", run[key]):
                _fail("invalid_snapshot_parser_version")
        parser_manifest = run["parser_manifest"]
        _validate_parser_manifest(parser_manifest)
        if run.get("artifact_id") not in maps["artifacts"] or _run_id(run) != run["id"] or object_digest(run.get("config")) != run.get("parser_config_digest") or object_digest(run.get("parser_manifest"), "TESTIFEX-PARSER-ARTIFACT-V2") != run.get("parser_artifact_digest"):
            _fail("invalid_snapshot_parse_run")
    active = value["active_runs"]
    if not isinstance(active, (list, _Rows)) or len(active) != len(maps["artifacts"]):
        _fail("invalid_snapshot_active_runs")
    active_ids = set()
    for row in active:
        if not isinstance(row, dict) or set(row) != {"artifact_id", "parse_run_id", "digest"} or row["artifact_id"] in active_ids or row["parse_run_id"] not in maps["parse_runs"] or maps["parse_runs"][row["parse_run_id"]]["artifact_id"] != row["artifact_id"] or object_digest({k: row[k] for k in ("artifact_id", "parse_run_id")}) != row["digest"]:
            _fail("invalid_snapshot_active_runs")
        active_ids.add(row["artifact_id"])
    disk = isinstance(value, SnapshotView)
    dispositions, records_by_run, events_by_run = {}, {}, {}
    covered_by_run, output_keys = {}, set()
    if not isinstance(value["parse_records"], (list, _Rows)) or len(value["parse_records"]) > table_caps["parse_records"]:
        _fail("snapshot_count_limit", 6)
    for row in value["parse_records"]:
        if not isinstance(row, dict) or set(row) != {"parse_run_id", "record_id", "disposition", "code", "digest"} or row["parse_run_id"] not in maps["parse_runs"] or row["record_id"] not in maps["records"] or object_digest({k: row[k] for k in row if k != "digest"}) != row["digest"]:
            _fail("invalid_snapshot_disposition")
        pair = (row["parse_run_id"], row["record_id"])
        if not disk and pair in dispositions:
            _fail("duplicate_snapshot_disposition")
        if row["code"] is not None and (not isinstance(row["code"], str) or not re.fullmatch(r"[a-z0-9_]{1,128}", row["code"])):
            _fail("invalid_snapshot_disposition_code")
        if not disk:
            dispositions[pair] = row["disposition"]
            records_by_run.setdefault(row["parse_run_id"], []).append((maps["records"][row["record_id"]], row["disposition"]))
    for event in maps["events"].values():
        output = _normalized_output(event.get("normalized_output"))
        if set(event) != set(output) | {"id", "artifact_id", "source_id", "parse_run_id", "record_refs", "primary_record_ref", "output_index", "ordinal", "offset", "length", "raw_digest", "normalized_output", "normalized_output_digest"}:
            _fail("invalid_snapshot_event_schema")
        if _event_id(event) != event["id"] or event.get("parse_run_id") not in maps["parse_runs"] or event.get("artifact_id") != maps["parse_runs"][event["parse_run_id"]]["artifact_id"] or object_digest(event.get("normalized_output")) != event.get("normalized_output_digest"):
            _fail("invalid_snapshot_event")
        from .locators import event_records, observation_key
        records = event_records(event, maps["records"].get)
        key = observation_key(event)
        if key in output_keys:
            _fail("duplicate_normalized_observation")
        output_keys.add(key)
        covered = covered_by_run.setdefault(event["parse_run_id"], set())
        for record in records:
            if disk:
                parsed = value.db.execute("SELECT disposition FROM rows WHERE tab='parse_records' AND run=? AND record=?", (event["parse_run_id"], record["id"])).fetchone()
                disposition = parsed[0] if parsed else None
            else:
                disposition = dispositions.get((event["parse_run_id"], record["id"]))
            if disposition != "parsed":
                _fail("invalid_snapshot_event_refs")
            covered.add(bytes.fromhex(record["id"]))
        if any(event.get(k) != v for k, v in event["normalized_output"].items()) or event.get("source_id") != event["artifact_id"]:
            _fail("invalid_snapshot_event_locator")
        events_by_run[event["parse_run_id"]] = events_by_run.get(event["parse_run_id"], 0) + 1
    for obj in maps["objects"].values():
        if set(obj) != {"id", "kind", "data", "revision"} or not isinstance(obj["data"], dict) or object_digest({"kind": obj["kind"], "data": obj["data"]}, "PROBENTIUM-STORED-OBJECT-V1") != obj["id"] or type(obj["revision"]) is not int or not 1 <= obj["revision"] <= value["meta"].get("revision", -1):
            _fail("invalid_snapshot_object")
        if not isinstance(obj["kind"], str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", obj["kind"]):
            _fail("invalid_snapshot_object_kind")
        if obj["kind"].startswith(("eu.", "retention.")) and obj["kind"] not in _EU_KINDS:
            _fail("unsupported_eu_object_kind", 7)
        if obj["kind"] in {"unified_graph", "unified_graph_chunk", "graph_impact"}:
            from .dependency_graph import validate_stored
            validate_stored(obj["kind"], obj["data"])
        if obj["kind"] == "parser_approval":
            from .parser_artifact import validate_approval
            validate_approval(obj["data"])
        if obj["kind"] == "review_decision":
            from .reviews import validate_stored
            validate_stored(obj["data"])
    for acquisition in maps["acquisitions"].values():
        base_acquisition = {"id", "artifact_id", "label", "method"}
        if (set(acquisition) not in (base_acquisition, base_acquisition | {"acquired_revision"}, base_acquisition | {"acquired_revision", "parser_approval_ref", "parse_run_id"})) or not re.fullmatch(r"[a-f0-9]{32}", acquisition["id"]) or acquisition["artifact_id"] not in maps["artifacts"] or acquisition["method"] != "copied_regular_file":
            _fail("invalid_snapshot_acquisition")
        text_field(acquisition["label"])
        if "acquired_revision" in acquisition and (type(acquisition["acquired_revision"]) is not int or not 1 <= acquisition["acquired_revision"] <= meta["revision"]):
            _fail("acquisition_revision_invalid")
        if "parser_approval_ref" in acquisition:
            from .parser_artifact import validate_approval
            approval = maps["objects"].get(acquisition["parser_approval_ref"])
            if approval is None or approval["kind"] != "parser_approval":
                _fail("parser_approval_required")
            validate_approval(approval["data"])
            if approval["revision"] >= acquisition["acquired_revision"]:
                _fail("acquisition_revision_invalid")
            selected = maps["parse_runs"].get(acquisition["parse_run_id"])
            if selected is None or selected["artifact_id"] != acquisition["artifact_id"] or selected["parser_artifact_digest"] != approval["data"]["manifest_digest"]:
                _fail("parser_approval_binding_invalid")
    for rid, run in maps["parse_runs"].items():
        counts = dict.fromkeys(("parsed", "blank", "known_out_of_scope", "unsupported", "malformed", "oversize"), 0)
        if disk:
            selected = ((strict_json(raw, MAX_CHUNK), disposition) for raw, disposition in value.db.execute(
                "SELECT r.payload,p.disposition FROM rows p JOIN rows r ON r.tab='records' AND r.identity=p.record WHERE p.tab='parse_records' AND p.run=? ORDER BY r.offset,r.identity", (rid,)))
        else:
            selected = sorted(records_by_run.get(rid, []), key=lambda row: row[0]["offset"])
        cursor = n_records = 0
        for ordinal, (record, disposition) in enumerate(selected, 1):
            if record["artifact_id"] != run["artifact_id"] or record["offset"] != cursor or record["ordinal"] != ordinal or disposition not in counts:
                _fail("invalid_snapshot_accounting")
            counts[disposition] += 1
            cursor += record["length"]
            n_records += 1
        size = maps["artifacts"][run["artifact_id"]]["size"]
        n_events = value.db.execute("SELECT count(*) FROM rows WHERE tab='events' AND run=?", (rid,)).fetchone()[0] if disk else events_by_run.get(rid, 0)
        complete = cursor == size
        if (counts != run.get("counters") or cursor != run.get("cursor") or n_records != run.get("records_total")
                or n_events != run.get("events_total") or len(covered_by_run.get(rid, ())) != counts["parsed"]
                or run.get("state") != ("complete" if complete else "incomplete")
                or run.get("unprocessed_bytes") != size - cursor or run.get("unprocessed_records") != (0 if complete else None)
                or run.get("interpretation_complete") != (complete and not any(counts[k] for k in ("known_out_of_scope", "unsupported", "malformed", "oversize")))):
            _fail("invalid_snapshot_accounting")
    if any(obj["kind"] in {"unified_graph", "unified_graph_chunk", "graph_impact"} for obj in maps["objects"].values()):
        from .dependency_graph import validate_snapshot_graphs
        validate_snapshot_graphs(value)
    catalog = hashlib.sha256(b"PROBENTIUM-CATALOG-V1\0")
    for table in sorted(keys - {"schema", "meta"}):
        catalog.update(canonical_bytes(table) + b"\n")
        rows = []
        for row in value[table]:
            if table == "active_runs":
                item = [row["artifact_id"], row["parse_run_id"], row["digest"]]
            elif table == "parse_records":
                item = [row["parse_run_id"], row["record_id"], row["digest"]]
            elif table == "objects":
                item = [row["id"], object_digest({k: row[k] for k in ("kind", "data", "revision")})]
            else:
                item = [row["id"], object_digest(row)]
            if disk:
                catalog.update(canonical_bytes(item) + b"\n")
            else:
                rows.append(item)
        if not disk:
            for row in sorted(rows):
                catalog.update(canonical_bytes(row) + b"\n")
    if catalog.hexdigest() != value["meta"].get("catalog_digest"):
        _fail("snapshot_catalog_mismatch")
    return maps


def _eu(value):
    if (not isinstance(value, dict) or set(value) != {"schema", "kind", "store_kind", "object_id", "data"}
            or value["schema"] != "probentium.eu.v1" or not isinstance(value["store_kind"], str)
            or value["store_kind"] not in _EU_KINDS or value["kind"] != _EU_KINDS[value["store_kind"]]):
        _fail("unsupported_eu_blob_schema", 7)
    _hex(value["object_id"])
    kind = value["store_kind"]
    from .regulatory import evaluate_control, evaluate_deadlines, _verified_snapshot
    if kind in _RETENTION:
        from .retention import validate_stored
        validate_stored(kind, value["data"])
    elif kind.startswith("eu."):
        short = kind[3:]
        if short in _GOVERNANCE:
            from .governance import validate_stored
        elif short in _LEGAL:
            from .legalpacks import validate_stored
        elif short in _REPORTING:
            from .reporting import validate_stored
        else:
            _fail("eu_kind_validator_unavailable", 7)
        validate_stored(kind, value["data"])
    elif kind == "control":
        evaluate_control(value["data"])
    elif kind == "track":
        evaluate_deadlines(value["data"], "2026-01-01T00:00:00Z")
    elif kind == "filing":
        _verified_snapshot(value["data"])
    else:
        _fail("eu_kind_validator_unavailable", 7)
    return value


def _projection(value, profile, resource_policy=None):
    policy = _policy(resource_policy)
    if profile == "public_summary":
        if not isinstance(value, dict) or set(value) != {"schema", "case_token", "source_count", "event_count", "object_count", "withheld"} or value["schema"] != "testifex.public-summary.v1":
            _fail("invalid_public_summary")
        _hex(value["case_token"])
        for key in ("source_count", "event_count", "object_count"):
            if type(value[key]) is not int or not 0 <= value[key] <= (policy["max_case_events"] if key == "event_count" else 1_000_000):
                _fail("invalid_public_summary")
        if value["withheld"] != ["raw_sources", "event_fields", "case_metadata", "objects"]:
            _fail("invalid_public_summary")
    else:
        if not isinstance(value, dict) or set(value) != {"schema", "kind", "purpose", "objects", "withheld"} or value["schema"] != "probentium.eu.v1" or value["kind"] != "recipient_dossier":
            _fail("invalid_recipient_dossier")
        text_field(value["purpose"], 4096)
        if not isinstance(value["objects"], list) or len(value["objects"]) > 500:
            _fail("projection_limit", 6)
        from .regulatory import _field
        seen = set()
        for row in value["objects"]:
            if not isinstance(row, dict) or set(row) != {"object_id", "kind", "fields"} or row["kind"] != "filing_snapshot" or row["object_id"] in seen or not isinstance(row["fields"], list) or len(row["fields"]) > 500:
                _fail("invalid_recipient_object")
            seen.add(_hex(row["object_id"]))
            ids = set()
            for field in row["fields"]:
                if not isinstance(field, dict):
                    _fail("invalid_recipient_field")
                if _field({k: v for k, v in field.items() if v is not None}) != field or field["id"] in ids:
                    _fail("invalid_recipient_field")
                ids.add(field["id"])
        if not isinstance(value["withheld"], list) or value["withheld"] != sorted(set(value["withheld"])):
            _fail("invalid_recipient_withholding")
        for ref in value["withheld"]:
            _hex(ref)
        if any(ref not in value["withheld"] for row in value["objects"] for field in row["fields"] for ref in field["refs"]):
            _fail("unacknowledged_projection_reference")
    return value


@contextmanager
def _new_output(path):
    """Nomen finale tantum post successum sine superpositione apparet."""
    with _parent_directory(path) as (target, directory):
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            _fail("private_output_directory_required", 2)
        try:
            os.stat(target.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _fail("output_exists", 2)
        temp = ".packet-" + os.urandom(16).hex()
        fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                yield stream
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temp, target.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            os.fsync(directory)
        finally:
            os.unlink(temp, dir_fd=directory)
            os.fsync(directory)


def _chunked_snapshot(case, directory, blobs, resource_policy=None, *, source_bytes=0):
    table_caps = _table_caps(_policy(resource_policy), resource_policy is not None)
    header = case.snapshot_header()
    if (not isinstance(header, dict) or set(header) != {"schema", "meta", "counts"}
            or header["schema"] != "probentium.case-snapshot.v1" or set(header["counts"]) != set(_TABLES)):
        _fail("invalid_snapshot_header")
    index = {"schema": "probentium.case-snapshot-index.v1", "meta": header["meta"], "tables": []}
    total = 0
    policy = _policy(resource_policy)
    if source_bytes > policy["max_packet_bytes"]:
        _fail("packet_size_limit", 6)
    for table in _TABLES:
        count = header["counts"][table]
        if type(count) is not int or not 0 <= count <= table_caps[table]:
            _fail("snapshot_count_limit", 6)
        chunks, rows, size, nodes, seen, previous = [], [], 128, 64, 0, ""
        def flush():
            nonlocal total, rows, size, nodes
            raw = canonical_bytes({"schema": "probentium.case-snapshot-chunk.v1", "table": table, "rows": rows})
            if len(raw) > MAX_CHUNK:
                _fail("snapshot_chunk_limit", 6)
            total += len(raw)
            if total + source_bytes > policy["max_packet_bytes"]:
                _fail("packet_size_limit", 6)
            if total > MAX_SNAPSHOT_BYTES:
                _fail("snapshot_total_limit", 6)
            digest = hashlib.sha256(raw).hexdigest()
            target = Path(directory) / digest
            with target.open("xb") as sink:
                os.chmod(target, 0o600)
                sink.write(raw)
            if len(blobs) + 2 >= min(MAX_MEMBERS, policy["max_packet_members"]):
                _fail("packet_member_limit", 6)
            blobs[digest] = ({"sha256": digest, "byte_length": len(raw), "content_type": "acquisition.metadata", "schema": "probentium.case-snapshot-chunk.v1"}, target)
            chunks.append(digest)
            rows, size, nodes = [], 128, 64
        for row in case.iter_snapshot_rows(table):
            key = _row_key(table, row)
            if key <= previous:
                _fail("snapshot_export_row_order")
            previous = key
            raw = canonical_bytes(row)
            row_nodes = _json_nodes(raw)
            if len(raw) + 128 > MAX_CHUNK:
                _fail("snapshot_row_limit", 6)
            if row_nodes + 64 > 1_000_000:
                _fail("snapshot_row_nodes_limit", 6)
            if (size + len(raw) + 1 > MAX_CHUNK or nodes + row_nodes + 1 > 1_000_000) and rows:
                flush()
            rows.append(row)
            size += len(raw) + 1
            nodes += row_nodes + 1
            seen += 1
            if seen > count:
                _fail("snapshot_changed_during_export")
        if rows:
            flush()
        if seen != count:
            _fail("snapshot_changed_during_export")
        index["tables"].append({"name": table, "count": count, "chunks": chunks})
    return index


def export_case(case, path, profile="private_full", *, signing_key=None, packet_schema=None, object_ids=None,
                field_allowlist=None, purpose=None, pseudonym_key_file=None, resource_policy=None):
    if resource_policy is not None:
        resource_policy = _policy(resource_policy)
    with tempfile.TemporaryDirectory(prefix="packet-export-") as directory:
        os.chmod(directory, 0o700)
        return _export_case(case, path, profile, signing_key=signing_key, packet_schema=packet_schema,
                            object_ids=object_ids, field_allowlist=field_allowlist, purpose=purpose,
                            pseudonym_key_file=pseudonym_key_file, directory=directory, resource_policy=resource_policy)


def _export_case(case, path, profile, *, signing_key, packet_schema, object_ids,
                 field_allowlist, purpose, pseudonym_key_file, directory, resource_policy=None):
    policy = _policy(resource_policy)
    verification = case.verify()
    if not verification["ok"]:
        _fail("case_integrity_failed")
    sources, objects = case.sources(), case.objects()
    schema = packet_schema or ("probentium.packet.v1" if str(path).endswith(".pbp") else "testifex.packet.v1")
    if schema not in _PROFILES or profile not in _PROFILES[schema]:
        _fail("unsupported_export_profile", 7)
    if not str(path).endswith(".pbp" if schema == "probentium.packet.v1" else ".tfp"):
        _fail("packet_extension_mismatch", 2)
    blobs, withheld = {}, []
    case_id = case.meta["case_id"]
    parser_versions = []
    if profile == "private_full":
        if verification.get("authorized_unavailable") or verification.get("completeness") == "partial":
            _fail("full_export_evidence_unavailable", 3)
        if any(source["size"] > policy["max_source_bytes"] for source in sources) or sum(source["size"] for source in sources) > policy["max_case_bytes"]:
            _fail("snapshot_evidence_resource_limit", 6)
        if hasattr(case, "snapshot_header") and hasattr(case, "iter_snapshot_rows"):
            snapshot = _chunked_snapshot(case, directory, blobs, resource_policy, source_bytes=sum(item["size"] for item in sources))
            parser_versions = sorted({run["adapter_id"] + ":" + run["adapter_version"] for run in case.iter_snapshot_rows("parse_runs")})
        else:
            snapshot = case.export_snapshot(max_bytes=MAX_JSON)
            _snapshot(snapshot, resource_policy)
            parser_versions = sorted({run["adapter_id"] + ":" + run["adapter_version"] for run in snapshot["parse_runs"]})
        for source in sources:
            blobs[source["id"]] = ({"sha256": source["id"], "byte_length": source["size"], "content_type": "source.bytes", "schema": "source.bytes.v1"}, None)
        for obj in objects:
            if obj["kind"] in _EU_KINDS:
                if schema != "probentium.packet.v1":
                    _fail("eu_content_requires_pbp", 2)
                envelope = _eu({"schema": "probentium.eu.v1", "kind": _EU_KINDS[obj["kind"]], "store_kind": obj["kind"], "object_id": obj["id"], "data": obj["data"]})
                raw = canonical_bytes(envelope)
                digest = hashlib.sha256(raw).hexdigest()
                blobs[digest] = ({"sha256": digest, "byte_length": len(raw), "content_type": envelope["kind"], "schema": "probentium.eu.v1"}, raw)
        snapshot_schema, content_type = snapshot["schema"], "acquisition.metadata"
    elif profile == "public_summary":
        if pseudonym_key_file is None:
            _fail("public_summary_key_file_required", 2)
        key = read_private_key(pseudonym_key_file)
        case_id = hmac.new(key, b"TESTIFEX-PUBLIC-CASE-V1\0" + case_id.encode("ascii"), hashlib.sha256).hexdigest()
        snapshot = {"schema": "testifex.public-summary.v1", "case_token": case_id, "source_count": len(sources),
                    "event_count": case.query_events(limit=1)["total"], "object_count": len(objects),
                    "withheld": ["raw_sources", "event_fields", "case_metadata", "objects"]}
        snapshot_schema, content_type = snapshot["schema"], "analysis.result"
    else:
        text_field(purpose, 4096)
        if not isinstance(object_ids, list) or not object_ids or len(object_ids) > 500 or len(set(object_ids)) != len(object_ids) or not isinstance(field_allowlist, dict) or set(field_allowlist) != set(object_ids):
            _fail("explicit_projection_allowlist_required", 2)
        by_id = {row["id"]: row for row in objects}
        source_ids = {row["id"] for row in sources}
        selected, refs = [], set()
        for oid in sorted(object_ids):
            obj = by_id.get(oid)
            if obj is None or obj["kind"] not in ("filing", "eu.filing_snapshot"):
                _fail("recipient_projection_supports_filing_fields_only", 7)
            _eu({"schema": "probentium.eu.v1", "kind": "filing_snapshot", "store_kind": obj["kind"], "object_id": oid, "data": obj["data"]})
            names = field_allowlist[oid]
            filing = obj["data"]["snapshot"] if obj["kind"] == "eu.filing_snapshot" else obj["data"]
            available = {row["id"]: row for row in filing["fields"]}
            if not isinstance(names, list) or not names or any(not isinstance(name, str) for name in names) or len(set(names)) != len(names) or not set(names) <= available.keys():
                _fail("invalid_field_allowlist", 2)
            fields = [available[name] for name in sorted(names)]
            refs.update(ref for field in fields for ref in field["refs"])
            selected.append({"object_id": oid, "kind": "filing_snapshot", "fields": fields})
        for ref in refs - source_ids - by_id.keys():
            try:
                case.raw_records(ref)
            except ProbentiumError as exc:
                if exc.code != "artifact_authorized_unavailable":
                    _fail("projection_reference_unresolved", 3)
        snapshot = {"schema": "probentium.eu.v1", "kind": "recipient_dossier", "purpose": purpose, "objects": selected, "withheld": sorted(refs)}
        withheld = [{"ref": ref, "reason": "excluded_by_projection"} for ref in sorted(refs)]
        snapshot_schema, content_type = snapshot["schema"], "recipient_dossier"
    if profile != "private_full":
        _projection(snapshot, profile, resource_policy)
    snapshot_bytes = canonical_bytes(snapshot)
    if len(snapshot_bytes) > MAX_JSON:
        _fail("snapshot_size_limit", 6)
    snapshot_digest = hashlib.sha256(snapshot_bytes).hexdigest()
    blobs[snapshot_digest] = ({"sha256": snapshot_digest, "byte_length": len(snapshot_bytes), "content_type": content_type, "schema": snapshot_schema}, snapshot_bytes)
    manifest = _manifest({"schema": schema, "canonicalization": "rfc8785", "digest_algorithm": "sha256", "profile": profile,
                          "case_schema": 2, "case_id": case_id, "revision": case.revision, "snapshot_digest": snapshot_digest,
                          "tool_version": __version__, "parser_versions": parser_versions, "engine_version": "probentium-r1",
                          "objects": [blobs[key][0] for key in sorted(blobs)], "withheld": withheld,
                          **({"resource_policy": policy} if resource_policy is not None else {})}, resource_policy)
    raw = canonical_bytes(manifest)
    signatures = [] if signing_key is None else [sign_manifest(manifest, signing_key)]
    if 1 + len(blobs) + len(signatures) > min(MAX_MEMBERS, policy["max_packet_members"]):
        _fail("packet_member_limit", 6)
    if sum(len(data) for _, data in blobs.values() if isinstance(data, bytes)) > MAX_JSON:
        _fail("packet_total_json_limit", 6)
    total = 1024 + sum(512 + ((len(data) + 511) // 512) * 512 for data in [raw] + [canonical_bytes(env) for env in signatures])
    total += sum(512 + ((desc["byte_length"] + 511) // 512) * 512 for desc, _ in blobs.values())
    if total > policy["max_packet_bytes"]:
        _fail("packet_size_limit", 6)
    with _new_output(path) as stream:
        def member(name, data):
            stream.write(_header(name, len(data)))
            stream.write(data)
            stream.write(b"\0" * (-len(data) % 512))
        member("manifest.json", raw)
        for digest in sorted(blobs):
            desc, data = blobs[digest]
            if isinstance(data, bytes):
                member("blobs/" + digest, data)
            elif isinstance(data, Path):
                stream.write(_header("blobs/" + digest, desc["byte_length"]))
                with regular_reader(data, MAX_CHUNK) as (source, _):
                    shutil.copyfileobj(source, stream, 1024 * 1024)
                stream.write(b"\0" * (-desc["byte_length"] % 512))
            else:
                stream.write(_header("blobs/" + digest, desc["byte_length"]))
                with case._blob(digest, desc["byte_length"]) as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        stream.write(chunk)
                stream.write(b"\0" * (-desc["byte_length"] % 512))
        for env in signatures:
            member("signatures/" + env["key_id"] + ".json", canonical_bytes(env))
        stream.write(b"\0" * 1024)
    return {"schema": schema, "profile": profile, "manifest_sha256": hashlib.sha256(raw).hexdigest(), "snapshot_digest": snapshot_digest,
            "revision": case.revision, "byte_length": total, "signature_count": len(signatures), "status": "exported", "submission_status": "not_submitted",
            "resource_policy": policy, "resource_policy_digest": resource_limits.digest(policy)}


class _Span(io.RawIOBase):
    def __init__(self, fd, offset, length):
        self.fd, self.offset, self.length, self.position = fd, offset, length, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        position = offset if whence == 0 else self.position + offset if whence == 1 else self.length + offset if whence == 2 else -1
        if not 0 <= position <= self.length:
            raise ValueError("span_seek_out_of_range")
        self.position = position
        return position

    def readinto(self, buffer):
        chunk = os.pread(self.fd, min(len(buffer), self.length - self.position), self.offset + self.position)
        buffer[:len(chunk)] = chunk
        self.position += len(chunk)
        return len(chunk)


def _read_packet(stream, resource_policy=None):
    view = SnapshotView(resource_policy)
    try:
        result = _read_packet_body(stream, view)
    except ProbentiumError as exc:
        view.close()
        if exc.exit_code == 2:
            raise ProbentiumError(exc.code, 4) from None
        raise
    except BaseException:
        view.close()
        raise
    if result[1] is not view:
        view.close()
    return result


def _read_packet_body(stream, view):
    name, size = _parse_header(stream.read(512))
    if name != "manifest.json" or size > MAX_JSON:
        _fail("manifest_must_be_first_and_bounded")
    raw = stream.read(size)
    if len(raw) != size:
        _fail("truncated_manifest")
    manifest = _manifest(_json(raw), view.resource_policy)
    declared = resource_limits.validate(manifest["resource_policy"]) if "resource_policy" in manifest else _policy()
    effective = {**view.resource_policy, **{key: min(view.resource_policy[key], declared[key]) for key in resource_limits.DEFAULTS}}
    view.resource_policy = effective
    view.table_caps = _table_caps(effective, view.explicit_policy and "resource_policy" in manifest)
    current = stream.tell()
    stream.seek(0, os.SEEK_END)
    if stream.tell() > effective["max_packet_bytes"]:
        _fail("packet_size_limit", 6)
    stream.seek(current)
    if stream.read(-size % 512) != b"\0" * (-size % 512):
        _fail("nonzero_tar_padding")
    locations, json_blobs, signatures, total_json, total_chunks = {}, {}, [], 0, 0
    for descriptor in manifest["objects"]:
        name, length = _parse_header(stream.read(512))
        digest = descriptor["sha256"]
        if name != "blobs/" + digest or length != descriptor["byte_length"]:
            _fail("member_manifest_mismatch")
        locations[digest] = (stream.tell(), length)
        h, remaining, chunks = hashlib.sha256(), length, []
        is_json = descriptor["content_type"] != "source.bytes"
        is_chunk = descriptor["schema"] == "probentium.case-snapshot-chunk.v1"
        if is_json and length > (MAX_CHUNK if is_chunk else MAX_JSON):
            _fail("packet_json_limit", 6)
        if is_json:
            if is_chunk:
                total_chunks += length
            else:
                total_json += length
            if total_json > MAX_JSON or total_chunks > MAX_SNAPSHOT_BYTES:
                _fail("packet_total_json_limit", 6)
        while remaining:
            chunk = stream.read(min(remaining, 1024 ** 2))
            if not chunk:
                _fail("truncated_blob")
            h.update(chunk)
            if is_json:
                chunks.append(chunk)
            remaining -= len(chunk)
        if h.hexdigest() != digest:
            _fail("blob_digest_mismatch")
        if stream.read(-length % 512) != b"\0" * (-length % 512):
            _fail("nonzero_tar_padding")
        if is_json:
            value = _json(b"".join(chunks), MAX_CHUNK if is_chunk else MAX_JSON)
            if is_chunk:
                view.add_chunk(digest, value)
            else:
                json_blobs[digest] = value
    previous = ""
    while True:
        header = stream.read(512)
        if header == b"\0" * 512:
            if stream.read(512) != b"\0" * 512:
                _fail("tar_end_marker_missing")
            remainder = stream.read(MAX_PADDING + 1)
            if len(remainder) > MAX_PADDING or any(remainder) or len(remainder) % 512:
                _fail("trailing_tar_data")
            break
        if 1 + len(locations) + len(signatures) >= min(MAX_MEMBERS, effective["max_packet_members"]):
            _fail("packet_member_limit", 6)
        name, size = _parse_header(header)
        if not name.startswith("signatures/") or name <= previous or size > 4096 or len(signatures) >= MAX_SIGNATURES:
            _fail("invalid_signature_member")
        previous = name
        env = _json(stream.read(size), 4096)
        if not isinstance(env, dict) or name != "signatures/" + str(env.get("key_id")) + ".json":
            _fail("signature_member_identity_mismatch")
        if stream.read(-size % 512) != b"\0" * (-size % 512):
            _fail("nonzero_tar_padding")
        signatures.append(env)
    snapshot = json_blobs.get(manifest["snapshot_digest"])
    if snapshot is None:
        _fail("snapshot_blob_missing")
    if manifest["profile"] == "private_full":
        indexed = isinstance(snapshot, dict) and snapshot.get("schema") == "probentium.case-snapshot-index.v1"
        if indexed:
            view.bind(snapshot)
            snapshot = view
        elif view.chunks:
            _fail("unreferenced_snapshot_chunk")
        for descriptor in manifest["objects"]:
            if descriptor["sha256"] == manifest["snapshot_digest"]:
                if descriptor["content_type"] != "acquisition.metadata" or descriptor["schema"] != ("probentium.case-snapshot-index.v1" if indexed else "probentium.case-snapshot.v1"):
                    _fail("snapshot_descriptor_mismatch")
            elif descriptor["sha256"] in view.chunks:
                if descriptor["content_type"] != "acquisition.metadata" or descriptor["schema"] != "probentium.case-snapshot-chunk.v1":
                    _fail("snapshot_chunk_descriptor_mismatch")
            elif descriptor["content_type"] == "source.bytes":
                if descriptor["schema"] != "source.bytes.v1":
                    _fail("unsupported_source_schema", 7)
            elif descriptor["content_type"] in _EU_KINDS.values():
                if descriptor["schema"] != "probentium.eu.v1":
                    _fail("unsupported_eu_blob_schema", 7)
            else:
                _fail("unsupported_private_blob_schema", 7)
        maps = _snapshot(snapshot, effective, extended_rows=view.explicit_policy and "resource_policy" in manifest)
        if snapshot["meta"]["case_id"] != manifest["case_id"] or snapshot["meta"]["revision"] != manifest["revision"]:
            _fail("snapshot_manifest_mismatch")
        if manifest["parser_versions"] != sorted({run["adapter_id"] + ":" + run["adapter_version"] for run in maps["parse_runs"].values()}):
            _fail("snapshot_parser_versions_mismatch")
        source_descriptors = {row["sha256"]: row for row in manifest["objects"] if row["content_type"] == "source.bytes"}
        if set(source_descriptors) != set(maps["artifacts"]):
            _fail("source_reference_missing")
        for aid, artifact in maps["artifacts"].items():
            if source_descriptors[aid]["byte_length"] != artifact["size"]:
                _fail("source_size_mismatch")
        for record in maps["records"].values():
            base, _ = locations[record["artifact_id"]]
            h, remaining, offset = hashlib.sha256(), record["length"], base + record["offset"]
            while remaining:
                chunk = os.pread(stream.fileno(), min(remaining, 1024 ** 2), offset)
                if not chunk:
                    _fail("truncated_record")
                h.update(chunk)
                remaining -= len(chunk)
                offset += len(chunk)
            if h.hexdigest() != record["raw_digest"]:
                _fail("record_bytes_mismatch")
        eu_seen = set()
        for descriptor in manifest["objects"]:
            if descriptor["content_type"] in _EU_KINDS.values():
                eu = _eu(json_blobs[descriptor["sha256"]])
                if eu["kind"] != descriptor["content_type"] or eu["object_id"] in eu_seen:
                    _fail("eu_descriptor_mismatch")
                eu_seen.add(eu["object_id"])
                obj = maps["objects"].get(eu["object_id"])
                if obj is None or obj["kind"] != eu["store_kind"] or _EU_KINDS.get(obj["kind"]) != eu["kind"] or obj["data"] != eu["data"]:
                    _fail("eu_snapshot_mismatch")
        expected_eu = {obj["id"] for obj in maps["objects"].values() if obj["kind"] in _EU_KINDS}
        if eu_seen != expected_eu:
            _fail("eu_reference_missing")
    else:
        _projection(snapshot, manifest["profile"], effective)
        descriptor = manifest["objects"][0]
        expected = ("analysis.result", "testifex.public-summary.v1") if manifest["profile"] == "public_summary" else ("recipient_dossier", "probentium.eu.v1")
        if (descriptor["content_type"], descriptor["schema"]) != expected:
            _fail("projection_descriptor_mismatch")
        if len(manifest["objects"]) != 1:
            _fail("projection_contains_extra_blobs")
        if manifest["profile"] == "public_summary" and snapshot["case_token"] != manifest["case_id"]:
            _fail("public_summary_identity_mismatch")
        if manifest["profile"] == "recipient_dossier" and [row["ref"] for row in manifest["withheld"]] != snapshot["withheld"]:
            _fail("projection_withholding_mismatch")
    return manifest, snapshot, locations, signatures


def verify_packet(path, scope="structure", *, trust_store=None, require_signature=False, require_trusted_key=False, replay=None, resource_policy=None):
    if scope not in ("structure", "replay"):
        _fail("invalid_verification_scope", 2)
    receipt = {"requested_scope": scope, "transport_integrity": "not_evaluated", "schema_validity": "not_evaluated",
               "signature_status": "not_evaluated", "key_trust": "unknown", "evidence_integrity": "not_evaluated",
               "normalization_replay": "unavailable", "analysis_replay": "unavailable", "performed_checks": [],
               "passed_checks": [], "failed_checks": [], "unavailable_checks": [], "issues": [], "exit_code": 0, "ok": False}
    snapshot = None
    try:
        policy = _policy(resource_policy)
        receipt.update(resource_policy=policy, resource_policy_digest=resource_limits.digest(policy))
        if trust_store is not None:
            validate_trust_store(trust_store)
        with regular_reader(path, policy["max_packet_bytes"]) as (stream, _):
            manifest, snapshot, locations, signatures = _read_packet(stream, resource_policy)
            if "resource_policy" in manifest:
                receipt["packet_resource_policy"] = manifest["resource_policy"]
            receipt.update(transport_integrity="passed", schema_validity="passed", evidence_integrity="passed" if manifest["profile"] == "private_full" else "withheld",
                           manifest_sha256=hashlib.sha256(canonical_bytes(manifest)).hexdigest(), revision=manifest["revision"], profile=manifest["profile"], schema=manifest["schema"])
            receipt["input_digest"] = receipt["manifest_sha256"]
            receipt["performed_checks"] += ["transport_integrity", "schema_validity", "evidence_integrity"]
            receipt["passed_checks"] += ["transport_integrity", "schema_validity"]
            if manifest["profile"] == "private_full":
                receipt["passed_checks"].append("evidence_integrity")
            verified = [verify_manifest_signature(manifest, env, trust_store) for env in signatures]
            receipt["signatures"] = verified
            if manifest["profile"] == "private_full":
                from .reviews import verify_review
                review_counts = {"valid_signatures": 0, "trusted": 0, "unknown": 0, "revoked": 0}
                for obj in snapshot["objects"]:
                    if obj["kind"] == "review_decision":
                        decision = obj["data"]
                        checked = verify_review(decision["decision"], decision["signature"], trust_store)
                        review_counts["valid_signatures"] += 1
                        review_counts[checked["key_trust"]] += 1
                receipt["review_history"] = {**review_counts, "approval_effect": "none_until_local_references_and_revision_verified"}
            receipt["signature_status"] = "valid" if signatures else "unsigned"
            receipt["key_trust"] = "trusted" if any(row["key_trust"] == "trusted" for row in verified) else "revoked" if any(row["key_trust"] == "revoked" for row in verified) else "unknown"
            if require_signature and not signatures:
                _fail("signature_required", 3)
            if require_trusted_key and receipt["key_trust"] != "trusted":
                _fail("signing_key_revoked" if receipt["key_trust"] == "revoked" else "trusted_key_required", 4 if receipt["key_trust"] == "revoked" else 3)
            if signatures:
                receipt["performed_checks"].append("signature_status")
                receipt["passed_checks"].append("signature_status")
            if scope == "replay":
                if manifest["profile"] != "private_full":
                    _fail("replay_inputs_withheld", 3)
                if replay is None:
                    receipt.update(normalization_replay="unsupported", analysis_replay="unsupported")
                    _fail("replay_backend_unavailable", 7)
                @contextmanager
                def source_reader(artifact_id):
                    descriptor = next((row for row in manifest["objects"] if row["sha256"] == artifact_id and row["content_type"] == "source.bytes"), None)
                    if descriptor is None:
                        _fail("replay_source_not_found")
                    with io.BufferedReader(_Span(stream.fileno(), *locations[artifact_id])) as source:
                        yield source
                result = replay(manifest, snapshot, source_reader)
                if not isinstance(result, dict) or set(result) != {"normalization_replay", "analysis_replay", "issues"} or not isinstance(result["issues"], list) or len(result["issues"]) > 1000 or any(not isinstance(code, str) or not re.fullmatch(r"[a-z0-9_]{1,128}", code) for code in result["issues"]):
                    _fail("invalid_replay_receipt")
                receipt["issues"].extend(result["issues"])
                for layer in ("normalization_replay", "analysis_replay"):
                    if result[layer] not in ("passed", "failed", "unsupported", "unavailable"):
                        _fail("invalid_replay_receipt")
                    receipt[layer] = result[layer]
                    receipt["performed_checks"].append(layer)
                    receipt["passed_checks" if result[layer] == "passed" else "failed_checks" if result[layer] == "failed" else "unavailable_checks"].append(layer)
                if "failed" in (result["normalization_replay"], result["analysis_replay"]):
                    _fail("replay_mismatch")
                if "unsupported" in (result["normalization_replay"], result["analysis_replay"]):
                    _fail("replay_backend_unsupported", 7)
                if "unavailable" in (result["normalization_replay"], result["analysis_replay"]):
                    _fail("replay_incomplete", 3)
            receipt["ok"] = True
    except (ProbentiumError, CaseError, OSError, KeyError, TypeError, ValueError, OverflowError, sqlite3.Error) as exc:
        over_size = isinstance(exc, CaseError) and str(exc) == "input_size_limit"
        code = exc.code if isinstance(exc, ProbentiumError) else "packet_size_limit" if over_size else "packet_invalid_or_unreadable"
        receipt["exit_code"] = exc.exit_code if isinstance(exc, ProbentiumError) else 6 if over_size else 4
        receipt["issues"].append(code)
        if receipt["exit_code"] == 7:
            receipt["schema_validity"] = "unsupported" if receipt["schema_validity"] == "not_evaluated" else receipt["schema_validity"]
        elif receipt["transport_integrity"] == "not_evaluated":
            receipt["transport_integrity"] = "failed"
            receipt["failed_checks"].append("transport_integrity")
        if code.startswith("signature_") and receipt["exit_code"] == 4:
            receipt["signature_status"] = "invalid"
            receipt["failed_checks"].append("signature_status")
    finally:
        if isinstance(snapshot, SnapshotView):
            snapshot.close()
    receipt["limitations"] = ["signatures_do_not_establish_factual_truth", "projection_is_not_anonymity", "no_automatic_submission"]
    for layer in ("normalization_replay", "analysis_replay"):
        if receipt[layer] in ("unavailable", "unsupported") and layer not in receipt["unavailable_checks"]:
            receipt["unavailable_checks"].append(layer)
    return receipt


def _age_binary():
    binary = shutil.which("age")
    if binary is None:
        candidate = Path(sys.executable).parent / "age"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            binary = str(candidate)
    return binary


def age_available():
    binary = _age_binary()
    return {"available": binary is not None, "backend": "external_age", "instructions": "Install the official age CLI and verify its distribution before encrypted handoff."}


@contextmanager
def open_verified_snapshot(packet_path, trust_store=None, require_trusted_key=False, *, require_signature=False, resource_policy=None):
    """Eadem descriptio verificata per totam restitutionem manet."""
    snapshot = None
    try:
        policy = _policy(resource_policy)
        if trust_store is not None:
            validate_trust_store(trust_store)
        with regular_reader(packet_path, policy["max_packet_bytes"]) as (stream, _):
            manifest, snapshot, locations, signatures = _read_packet(stream, resource_policy)
            verified = [verify_manifest_signature(manifest, env, trust_store) for env in signatures]
            if require_signature and not signatures:
                _fail("signature_required", 3)
            if require_trusted_key and not any(row["key_trust"] == "trusted" for row in verified):
                if any(row["key_trust"] == "revoked" for row in verified):
                    _fail("signing_key_revoked", 4)
                _fail("trusted_key_required", 3)
            if manifest["profile"] != "private_full":
                _fail("full_snapshot_withheld", 3)
            source_ids = {row["sha256"] for row in manifest["objects"] if row["content_type"] == "source.bytes"}
            @contextmanager
            def source_reader(artifact_id):
                if artifact_id not in source_ids:
                    _fail("replay_source_not_found")
                with io.BufferedReader(_Span(stream.fileno(), *locations[artifact_id])) as source:
                    yield source
            yield manifest, snapshot, source_reader
    except CaseError as exc:
        if str(exc) == "input_size_limit":
            raise ProbentiumError("packet_size_limit", 6) from None
        raise ProbentiumError("packet_changed_or_unreadable", 4) from None
    finally:
        if isinstance(snapshot, SnapshotView):
            snapshot.close()


def encrypt_packet(path, output, recipients, *, trust_store=None, resource_policy=None):
    report = verify_packet(path, require_signature=True, trust_store=trust_store, resource_policy=resource_policy)
    if not report["ok"]:
        _fail("encryption_requires_verified_signed_packet", report["exit_code"])
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= 32 or len(set(recipients)) != len(recipients) or any(not isinstance(row, str) or not re.fullmatch(r"age1[0-9a-z]{58}", row) for row in recipients):
        _fail("native_age_recipients_required", 2)
    return _age(path, output, [arg for recipient in recipients for arg in ("-r", recipient)], trust_store=trust_store, resource_policy=resource_policy)


def decrypt_packet(path, output, identity_file, *, trust_store=None, require_trusted_key=False, resource_policy=None):
    _policy(resource_policy)
    from .signatures import _private_parent
    _private_parent(identity_file)
    with regular_reader(identity_file, 4096) as (identity, info):
        if info.st_mode & 0o077 or info.st_uid != os.getuid() or info.st_nlink != 1:
            _fail("age_identity_permissions", 2)
        data = identity.read(4097)
        if len(data) > 4096 or not re.fullmatch(rb"(?:#[^\r\n]*\n)*AGE-SECRET-KEY-1[0-9A-Z]{58}\n?", data):
            _fail("native_age_identity_required", 2)
        identity.seek(0)
        descriptor = identity.fileno()
        return _age(path, output, ["--decrypt", "-i", "/dev/fd/" + str(descriptor)], decrypt=True,
                    trust_store=trust_store, require_trusted_key=require_trusted_key, pass_fds=(descriptor,), resource_policy=resource_policy)


def _age(path, output, arguments, *, decrypt=False, trust_store=None, require_trusted_key=False, pass_fds=(), resource_policy=None):
    policy = _policy(resource_policy)
    binary = _age_binary()
    if binary is None:
        return {"ok": False, "exit_code": 7, "status": "unsupported", "resource_policy": policy, "resource_policy_digest": resource_limits.digest(policy), **age_available()}
    with tempfile.TemporaryDirectory(prefix="handoff-") as directory:
        os.chmod(directory, 0o700)
        staging = Path(directory) / "quarantine"
        captured = Path(directory) / "captured"
        with regular_reader(path, policy["max_packet_bytes"]) as (source, _), captured.open("xb") as sink:
            os.chmod(captured, 0o600)
            copied = 0
            while True:
                chunk = source.read(min(1024 * 1024, policy["max_packet_bytes"] - copied + 1))
                if not chunk:
                    break
                copied += len(chunk)
                if copied > policy["max_packet_bytes"]:
                    _fail("encrypted_handoff_size_limit", 6)
                sink.write(chunk)
            sink.flush()
            os.fsync(sink.fileno())
        if not decrypt:
            report = verify_packet(captured, require_signature=True, trust_store=trust_store, resource_policy=resource_policy)
            if not report["ok"]:
                _fail("encryption_requires_verified_signed_packet", report["exit_code"])
        with regular_reader(captured, policy["max_packet_bytes"]) as (source, _):
            with staging.open("xb") as sink:
                os.chmod(staging, 0o600)
                command = [binary, *arguments]
                try:
                    with subprocess.Popen(command, stdin=source, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                          shell=False, pass_fds=pass_fds, env={"PATH": str(Path(binary).parent)}) as process:
                        try:
                            total, deadline = 0, time.monotonic() + 900
                            with selectors.DefaultSelector() as selector:
                                selector.register(process.stdout, selectors.EVENT_READ)
                                while True:
                                    remaining = deadline - time.monotonic()
                                    if remaining <= 0 or not selector.select(remaining):
                                        _fail("age_execution_timeout", 7)
                                    chunk = os.read(process.stdout.fileno(), min(1024 * 1024, policy["max_packet_bytes"] - total + 1))
                                    if not chunk:
                                        break
                                    total += len(chunk)
                                    if total > policy["max_packet_bytes"]:
                                        _fail("encrypted_handoff_size_limit", 6)
                                    sink.write(chunk)
                            result = process.wait(timeout=max(0.01, deadline - time.monotonic()))
                        except BaseException:
                            process.kill()
                            process.wait()
                            raise
                except (OSError, subprocess.TimeoutExpired):
                    _fail("age_execution_failed", 7)
                sink.flush()
                os.fsync(sink.fileno())
        if result != 0:
            _fail("age_authentication_or_execution_failed")
        if staging.stat().st_size > policy["max_packet_bytes"]:
            _fail("encrypted_handoff_size_limit", 6)
        if decrypt:
            report = verify_packet(staging, trust_store=trust_store, require_signature=True, require_trusted_key=require_trusted_key, resource_policy=resource_policy)
            if not report["ok"]:
                _fail("decrypted_packet_verification_failed", report["exit_code"])
        with _new_output(output) as target:
            with regular_reader(staging, policy["max_packet_bytes"]) as (source, _):
                shutil.copyfileobj(source, target, 1024 * 1024)
        return {"ok": True, "exit_code": 0, "status": "decrypted_and_verified" if decrypt else "encrypted",
                "backend": "external_age", "resource_policy": policy, "resource_policy_digest": resource_limits.digest(policy), "limitations": ["temporary_plaintext_removal_is_not_secure_erase"]}
