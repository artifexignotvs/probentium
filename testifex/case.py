"""Vestigia et rationes una servantur."""
import hashlib
import os
import re
import sqlite3
import uuid
from pathlib import Path

from . import __version__
from .model import CaseError, FORMATS, MAX_LINE, MAX_SOURCE, canonical, digest, identifier, label, strict_json
from .safeio import acquire, file_hash, regular_reader, verified_reader, write_new

SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE sources(id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE events(id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES sources(id), ordinal INTEGER NOT NULL,
 low_us INTEGER, high_us INTEGER, kind TEXT NOT NULL, host TEXT, actor TEXT, data TEXT NOT NULL,
 UNIQUE(source_id, ordinal));
CREATE INDEX event_time ON events(low_us, high_us, id);
CREATE INDEX event_actor ON events(host,actor,kind);
CREATE TABLE issues(source_id TEXT NOT NULL REFERENCES sources(id), ordinal INTEGER NOT NULL, offset INTEGER NOT NULL, code TEXT NOT NULL);
CREATE TABLE hypotheses(id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE hypothesis_evidence(hypothesis_id TEXT NOT NULL REFERENCES hypotheses(id), event_id TEXT NOT NULL REFERENCES events(id),
 stance TEXT NOT NULL, note TEXT NOT NULL, PRIMARY KEY(hypothesis_id,event_id,stance));
CREATE TABLE snapshots(id TEXT PRIMARY KEY, label TEXT NOT NULL, sha256 TEXT NOT NULL);
"""


class Case:
    def __init__(self, path):
        self.path = Path(os.path.abspath(path))
        if self.path.is_symlink() or not self.path.is_dir():
            raise CaseError("case_directory_required")
        database = self.path / "case.sqlite3"
        with regular_reader(database, 16 * 1024 ** 3):
            pass
        for name in ("evidence", "snapshots"):
            folder = self.path / name
            if folder.is_symlink() or not folder.is_dir():
                raise CaseError("invalid_case_directory")
        self.db = sqlite3.connect(database)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA trusted_schema=OFF")
        self.db.execute("PRAGMA busy_timeout=5000")
        if self.db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
            self.db.close()
            raise CaseError("unsupported_case_schema_no_automatic_migration")
        self.metadata = {r["key"]: strict_json(r["value"]) for r in self.db.execute("SELECT * FROM meta")}

    @classmethod
    def create(cls, path, name="Untitled case"):
        label(name, "case_name")
        path = Path(path)
        path.mkdir(mode=0o700)
        for directory in ("evidence", "snapshots"):
            (path / directory).mkdir(mode=0o700)
        db = sqlite3.connect(path / "case.sqlite3")
        try:
            os.chmod(path / "case.sqlite3", 0o600)
            db.executescript(SCHEMA)
            db.execute("PRAGMA user_version=1")
            metadata = {"schema_version": 1, "tool_version": __version__, "case_id": uuid.uuid4().hex, "name": name}
            db.executemany("INSERT INTO meta VALUES(?,?)", [(k, canonical(v)) for k, v in metadata.items()])
            db.commit()
        finally:
            db.close()
        return cls(path)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.db.close()

    @staticmethod
    def _decode_source(row_id, data):
        """Identitas ante viam probatur."""
        source = strict_json(data)
        if not isinstance(source, dict):
            raise CaseError("invalid_source_schema")
        for field in ("id", "sha256"):
            value = source.get(field)
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise CaseError("invalid_source_identity")
        if row_id != source["id"] or source.get("format") not in FORMATS or not isinstance(source.get("parser_version"), str):
            raise CaseError("invalid_source_identity")
        options = source.get("options")
        fields = {"clock_offset_us", "clock_error_us", "correction_reason", "declared_start_us", "declared_end_us"}
        if not isinstance(options, dict) or set(options) != fields:
            raise CaseError("invalid_source_options")
        for key in ("clock_offset_us", "clock_error_us"):
            if type(options[key]) is not int or abs(options[key]) > 365 * 86400 * 1000000:
                raise CaseError("invalid_source_options")
        if options["clock_error_us"] < 0 or not isinstance(options["correction_reason"], str):
            raise CaseError("invalid_source_options")
        if options["clock_error_us"] or options["clock_offset_us"]:
            label(options["correction_reason"], "correction_reason")
        start, end = options["declared_start_us"], options["declared_end_us"]
        if (start is None) != (end is None) or (start is not None and (type(start) is not int or type(end) is not int or start > end)):
            raise CaseError("invalid_declared_interval")
        expected = digest({"sha256": source["sha256"], "format": source["format"], "parser_version": source["parser_version"], "options": options})
        if expected != source["id"]:
            raise CaseError("source_identity_mismatch")
        for key in ("size", "cursor", "lines_total", "last_line", "parsed_count", "ignored_count", "error_count"):
            if type(source.get(key)) is not int or source[key] < 0:
                raise CaseError("invalid_source_accounting")
        if not 0 <= source["cursor"] <= source["size"] <= 4 * 1024 ** 3:
            raise CaseError("invalid_source_cursor")
        if source.get("status") not in ("pending", "interrupted", "complete", "incomplete"):
            raise CaseError("invalid_source_status")
        if source["status"] in ("complete", "incomplete") and source["cursor"] != source["size"]:
            raise CaseError("source_status_mismatch")
        return source

    def sources(self):
        return [self._decode_source(r[0], r[1]) for r in self.db.execute("SELECT id,data FROM sources ORDER BY id")]

    def source(self, source_id):
        identifier(source_id)
        row = self.db.execute("SELECT data FROM sources WHERE id=?", (source_id,)).fetchone()
        if row is None:
            raise CaseError("source_not_found")
        return self._decode_source(source_id, row[0])

    def _save_source(self, source):
        self.db.execute("UPDATE sources SET data=? WHERE id=?", (canonical(source), source["id"]))

    def events(self, source_id=None):
        query = "SELECT data FROM events"
        args = ()
        if source_id is not None:
            query += " WHERE source_id=?"
            args = (source_id,)
        query += " ORDER BY low_us IS NULL,low_us,high_us,id"
        for row in self.db.execute(query, args):
            yield strict_json(row[0])

    def event(self, event_id):
        identifier(event_id)
        row = self.db.execute("SELECT data FROM events WHERE id=?", (event_id,)).fetchone()
        if row is None:
            raise CaseError("event_not_found")
        return strict_json(row[0])

    def issues(self):
        for row in self.db.execute("SELECT * FROM issues ORDER BY source_id,ordinal"):
            yield dict(row)

    def ingest(self, path, format_name, source_label, options=None, max_bytes=MAX_SOURCE, max_records=1000000):
        from .parsers import PARSER_VERSION
        if (format_name not in FORMATS or type(max_bytes) is not int or not 1 <= max_bytes <= 4 * 1024 ** 3
                or type(max_records) is not int or not 1 <= max_records <= 10000000):
            raise CaseError("invalid_ingest_options")
        label(source_label)
        options = dict(options or {})
        allowed = {"clock_offset_us", "clock_error_us", "correction_reason", "declared_start_us", "declared_end_us"}
        if set(options) - allowed:
            raise CaseError("unknown_source_option")
        opts = {"clock_offset_us": 0, "clock_error_us": 0, "correction_reason": "", "declared_start_us": None, "declared_end_us": None}
        opts.update(options)
        for field in ("clock_offset_us", "clock_error_us"):
            if type(opts[field]) is not int or abs(opts[field]) > 365 * 86400 * 1000000:
                raise CaseError("invalid_clock_adjustment")
        if opts["clock_error_us"] < 0:
            raise CaseError("negative_clock_error")
        if not isinstance(opts["correction_reason"], str):
            raise CaseError("invalid_correction_reason")
        if opts["clock_offset_us"] or opts["clock_error_us"] or opts["correction_reason"]:
            label(opts["correction_reason"], "correction_reason")
        start, end = opts["declared_start_us"], opts["declared_end_us"]
        if (start is None) != (end is None) or (start is not None and (type(start) is not int or type(end) is not int or start > end)):
            raise CaseError("invalid_declared_interval")
        sha, size, metadata = acquire(path, self.path / "evidence", max_bytes)
        source_id = digest({"sha256": sha, "format": format_name, "parser_version": PARSER_VERSION, "options": opts})
        if self.db.execute("SELECT 1 FROM sources WHERE id=?", (source_id,)).fetchone():
            result = self.source(source_id)
            result["duplicate"] = True
            return result
        if any(existing["sha256"] == sha for existing in self.sources()):
            raise CaseError("conflicting_source_version_use_separate_case")
        source = {"id": source_id, "label": source_label, "sha256": sha, "size": size, "format": format_name,
                  "parser_version": PARSER_VERSION, "options": opts, "status": "pending", "lines_total": 0,
                  "parsed_count": 0, "ignored_count": 0, "error_count": 0, "cursor": 0, "last_line": 0,
                  "observed_low_us": None, "observed_high_us": None, "source_metadata": metadata}
        self.db.execute("INSERT INTO sources VALUES (?,?)", (source_id, canonical(source)))
        self.db.commit()
        return self.resume(source_id, max_records=max_records)

    def normalize(self, source, raw, ordinal, offset):
        from .parsers import ParseError, parse_line
        from .timeutil import MIN_TIME_US, MAX_TIME_US
        event = parse_line(raw, source["format"], ordinal)
        if event is None:
            return None
        event = dict(event)
        event["original_low_us"] = event["time_low_us"]
        event["original_high_us"] = event["time_high_us"]
        opts = source["options"]
        event["clock_offset_us"], event["clock_error_us"] = opts["clock_offset_us"], opts["clock_error_us"]
        if event["time_low_us"] is not None:
            event["time_low_us"] -= opts["clock_offset_us"] + opts["clock_error_us"]
            event["time_high_us"] += -opts["clock_offset_us"] + opts["clock_error_us"]
            if not MIN_TIME_US <= event["time_low_us"] <= event["time_high_us"] <= MAX_TIME_US:
                raise ParseError("corrected_time_out_of_range")
        raw_sha = hashlib.sha256(raw).hexdigest()
        event.update(id=digest({"source": source["id"], "ordinal": ordinal, "raw": raw_sha}),
                     source_id=source["id"], ordinal=ordinal, offset=offset, length=len(raw), raw_sha256=raw_sha)
        return event

    def resume(self, source_id, max_records=1000000, checkpoint=256):
        from .parsers import PARSER_VERSION, ParseError
        source = self.source(source_id)
        if source["parser_version"] != PARSER_VERSION:
            raise CaseError("parser_version_changed_reimport_required")
        if not 1 <= max_records <= 10000000:
            raise CaseError("invalid_record_limit")
        path = self.path / "evidence" / (source["sha256"] + ".bin")
        if type(checkpoint) is not int or checkpoint < 1:
            raise CaseError("invalid_checkpoint")
        try:
            with verified_reader(path, source["sha256"], 4 * 1024 ** 3) as (stream, info):
                if info.st_size != source["size"]:
                    raise CaseError("evidence_size_mismatch")
                if source["status"] in ("complete", "incomplete") and source["cursor"] == source["size"]:
                    return source
                stream.seek(source["cursor"])
                while True:
                    offset = stream.tell()
                    raw = stream.readline(MAX_LINE + 1)
                    if not raw:
                        break
                    if source["lines_total"] >= max_records:
                        source["status"] = "interrupted"
                        self._save_source(source)
                        self.db.commit()
                        return source
                    source["last_line"] += 1
                    source["lines_total"] += 1
                    try:
                        if len(raw) > MAX_LINE:
                            while raw and not raw.endswith(b"\n"):
                                raw = stream.readline(MAX_LINE + 1)
                            raise ParseError("record_size_limit")
                        event = self.normalize(source, raw, source["last_line"], offset)
                        if event is None:
                            source["ignored_count"] += 1
                        else:
                            self.db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                                (event["id"], source_id, event["ordinal"], event["time_low_us"], event["time_high_us"],
                                 event["kind"], event["host"], event["actor"], canonical(event)))
                            source["parsed_count"] += 1
                            if event["time_low_us"] is not None:
                                source["observed_low_us"] = min(source["observed_low_us"], event["time_low_us"]) if source["observed_low_us"] is not None else event["time_low_us"]
                                source["observed_high_us"] = max(source["observed_high_us"], event["time_high_us"]) if source["observed_high_us"] is not None else event["time_high_us"]
                    except ParseError as exc:
                        source["error_count"] += 1
                        self.db.execute("INSERT INTO issues VALUES(?,?,?,?)", (source_id, source["last_line"], offset, str(exc)))
                    source["cursor"] = stream.tell()
                    if source["lines_total"] % checkpoint == 0:
                        self._save_source(source)
                        self.db.commit()
            source["status"] = "incomplete" if source["error_count"] else "complete"
            self._save_source(source)
            self.db.commit()
            return source
        except BaseException:
            self.db.rollback()
            saved = self.source(source_id)
            saved["status"] = "interrupted"
            self._save_source(saved)
            self.db.commit()
            raise

    def raw_event(self, event_id):
        event = self.event(event_id)
        source = self.source(event["source_id"])
        if (type(event["length"]) is not int or type(event["offset"]) is not int
                or not 0 < event["length"] <= MAX_LINE or event["offset"] < 0
                or event["offset"] + event["length"] > source["size"]):
            raise CaseError("invalid_record_locator")
        path = self.path / "evidence" / (source["sha256"] + ".bin")
        with regular_reader(path, 4 * 1024 ** 3) as (stream, _):
            stream.seek(event["offset"])
            raw = stream.read(event["length"])
        if hashlib.sha256(raw).hexdigest() != event["raw_sha256"]:
            raise CaseError("record_digest_mismatch")
        return raw

    def verify(self):
        from .parsers import PARSER_VERSION, ParseError
        failures = []
        if self.db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            failures.append({"code": "database_integrity_failed"})
        if list(self.db.execute("PRAGMA foreign_key_check")):
            failures.append({"code": "database_foreign_key_failed"})
        count = 0
        source_rows = self.db.execute("SELECT id,data FROM sources ORDER BY id").fetchall()
        for source_row in source_rows:
            try:
                source = self._decode_source(source_row[0], source_row[1])
                expected_source = digest({"sha256": source["sha256"], "format": source["format"], "parser_version": source["parser_version"], "options": source["options"]})
                if source["id"] != expected_source:
                    raise CaseError("source_identity_mismatch")
                if source["parser_version"] != PARSER_VERSION:
                    raise CaseError("parser_version_unavailable")
                if not 0 <= source["cursor"] <= source["size"]:
                    raise CaseError("invalid_source_cursor")
                if source["status"] in ("complete", "incomplete") and source["cursor"] != source["size"]:
                    raise CaseError("source_status_mismatch")
                path = self.path / "evidence" / (source["sha256"] + ".bin")
                parsed = ignored = errors = ordinal = 0
                low = high = None
                with verified_reader(path, source["sha256"], 4 * 1024 ** 3) as (stream, info):
                    if info.st_size != source["size"]:
                        raise CaseError("evidence_size_mismatch")
                    while stream.tell() < source["cursor"]:
                        offset = stream.tell()
                        raw = stream.readline(MAX_LINE + 1)
                        if not raw:
                            raise CaseError("source_cursor_not_record_boundary")
                        ordinal += 1
                        try:
                            if len(raw) > MAX_LINE:
                                while raw and not raw.endswith(b"\n"):
                                    raw = stream.readline(MAX_LINE + 1)
                                raise ParseError("record_size_limit")
                            event = self.normalize(source, raw, ordinal, offset)
                            if event is None:
                                ignored += 1
                            else:
                                row = self.db.execute("SELECT * FROM events WHERE source_id=? AND ordinal=?", (source["id"], ordinal)).fetchone()
                                if row is None or strict_json(row["data"]) != event:
                                    raise CaseError("normalized_record_missing_or_changed")
                                if (row["id"], row["low_us"], row["high_us"], row["kind"], row["host"], row["actor"]) != (event["id"], event["time_low_us"], event["time_high_us"], event["kind"], event["host"], event["actor"]):
                                    raise CaseError("record_index_mismatch")
                                parsed += 1; count += 1
                                if event["time_low_us"] is not None:
                                    low = min(low, event["time_low_us"]) if low is not None else event["time_low_us"]
                                    high = max(high, event["time_high_us"]) if high is not None else event["time_high_us"]
                        except ParseError as exc:
                            errors += 1
                            stored = self.db.execute("SELECT offset,code FROM issues WHERE source_id=? AND ordinal=?", (source["id"], ordinal)).fetchall()
                            if len(stored) != 1 or tuple(stored[0]) != (offset, str(exc)):
                                raise CaseError("issue_record_missing_or_changed")
                        if stream.tell() > source["cursor"]:
                            raise CaseError("source_cursor_not_record_boundary")
                actual_rows = self.db.execute("SELECT count(*) FROM events WHERE source_id=?", (source["id"],)).fetchone()[0]
                actual_issues = self.db.execute("SELECT count(*) FROM issues WHERE source_id=?", (source["id"],)).fetchone()[0]
                observed = (parsed, ignored, errors, ordinal, ordinal, low, high)
                declared = tuple(source[k] for k in ("parsed_count", "ignored_count", "error_count", "lines_total", "last_line", "observed_low_us", "observed_high_us"))
                if observed != declared or actual_rows != parsed or actual_issues != errors:
                    raise CaseError("source_accounting_mismatch")
            except (CaseError, ValueError, OSError, TypeError, KeyError) as exc:
                public_id = source_row[0] if re.fullmatch(r"[0-9a-f]{64}", source_row[0]) else "invalid"
                failures.append({"source_id": public_id, "code": str(exc) if isinstance(exc, CaseError) else "verification_failed"})
        return {"schema": "testifex.verification.v1", "ok": not failures, "sources": len(source_rows), "events_checked": count,
                "reparsed": True, "failures": failures, "limitation": "Consistency is not independent proof of authorship, acquisition time or completeness."}

    def add_hypothesis(self, title, assumptions):
        label(title, "hypothesis_title")
        if len(assumptions) > 32:
            raise CaseError("assumptions_limit")
        for value in assumptions:
            label(value, "assumption")
        item = {"id": uuid.uuid4().hex, "title": title, "status": "open", "assumptions": assumptions}
        self.db.execute("INSERT INTO hypotheses VALUES(?,?)", (item["id"], canonical(item)))
        self.db.commit()
        return item

    def link_hypothesis(self, hypothesis_id, event_id, stance, note=""):
        identifier(hypothesis_id)
        self.event(event_id)
        if stance not in ("supports", "contradicts", "context"):
            raise CaseError("invalid_evidence_stance")
        if note:
            label(note, "note")
        if not self.db.execute("SELECT 1 FROM hypotheses WHERE id=?", (hypothesis_id,)).fetchone():
            raise CaseError("hypothesis_not_found")
        self.db.execute("INSERT INTO hypothesis_evidence VALUES(?,?,?,?) ON CONFLICT DO UPDATE SET note=excluded.note", (hypothesis_id, event_id, stance, note))
        self.db.commit()

    def set_hypothesis_status(self, hypothesis_id, status):
        if status not in ("open", "supported", "refuted", "inconclusive"):
            raise CaseError("invalid_hypothesis_status")
        row = self.db.execute("SELECT data FROM hypotheses WHERE id=?", (identifier(hypothesis_id),)).fetchone()
        if row is None:
            raise CaseError("hypothesis_not_found")
        item = strict_json(row[0]); item["status"] = status
        self.db.execute("UPDATE hypotheses SET data=? WHERE id=?", (canonical(item), hypothesis_id))
        self.db.commit()

    def hypotheses(self):
        result = []
        for row in self.db.execute("SELECT data FROM hypotheses ORDER BY id"):
            item = strict_json(row[0])
            item["evidence"] = [dict(r) for r in self.db.execute("SELECT event_id,stance,note FROM hypothesis_evidence WHERE hypothesis_id=? ORDER BY event_id,stance", (item["id"],))]
            result.append(item)
        return result

    def snapshot(self, report, snapshot_label):
        label(snapshot_label)
        data = (canonical(report) + "\n").encode()
        sha = hashlib.sha256(data).hexdigest()
        path = self.path / "snapshots" / (sha + ".json")
        if not path.exists():
            write_new(path, data)
        elif file_hash(path, 64 * 1024 ** 2)[0] != sha:
            raise CaseError("snapshot_digest_mismatch")
        self.db.execute("INSERT OR IGNORE INTO snapshots VALUES(?,?,?)", (sha, snapshot_label, sha))
        self.db.commit()
        return {"id": sha, "label": snapshot_label, "filename": "snapshots/" + path.name, "sha256": sha}
