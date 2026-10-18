"""Octeti servantur; interpretatio a fonte separatur."""
from __future__ import annotations

import fcntl
import errno
import hashlib
import os
import re
import secrets
import sqlite3
import stat
import uuid
from contextlib import contextmanager, nullcontext
from functools import wraps
from pathlib import Path

from testifex import parsers
from testifex.model import CaseError
from testifex.safeio import regular_reader
from .contracts import ProbentiumError, canonical_bytes, _canonical_validated, object_digest, strict_json, text_field
from . import adapters
from .worker import ParserWorker
from . import limits as resource_limits

SCHEMA_VERSION = 2
APPLICATION_ID = 0x50524231
MAX_ARTIFACT = 1024 ** 3
MAX_CASE_BYTES = 20 * 1024 ** 3
MAX_DATABASE = 4 * 1024 ** 3
MAX_RECORDS = 1_000_000
MAX_EVENTS = 1_000_000
MAX_ARTIFACTS = 20_000
MAX_OBJECTS = 10_000
MAX_ACQUISITIONS = 20_000
MAX_OBJECT_BYTES = 16 * 1024 ** 2
MAX_LIST_BYTES = 64 * 1024 ** 2
MAX_LINE = 1024 ** 2
MAX_PAGE = 1000
CHECKPOINT_RECORDS = 4096
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_CATALOG_HEX = re.compile(r"[0-9a-f]{1,64}\Z")
_JSON_ESCAPES = re.compile(r'["\\\x00-\x1f]')
_SIMPLE_JSON_KEY = re.compile(r"[a-zA-Z0-9_.-]{1,128}\Z")
_KIND = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_DISPOSITIONS = ("parsed", "blank", "known_out_of_scope", "unsupported", "malformed", "oversize")
_LIMITATIONS = ["reference_clock_alignment_unknown", "collection_completeness_not_asserted",
                "parser_execution_in_process", "parser_artifact_is_source_manifest", "events_v2_unsupported"]
_BASE_LIMITATIONS = ["reference_clock_alignment_unknown", "collection_completeness_not_asserted", "parser_worker_not_network_sandboxed"]
_CURRENT_LIMITATIONS = [*_BASE_LIMITATIONS, "parser_artifact_is_source_manifest"]
_DISTRIBUTION_LIMITATIONS = [*_BASE_LIMITATIONS, "parser_operator_approval_not_authorship"]
_ACCEPTED_LIMITATIONS = (_LIMITATIONS, _CURRENT_LIMITATIONS, _BASE_LIMITATIONS, _DISTRIBUTION_LIMITATIONS)

_SCHEMA = """
CREATE TABLE meta(key TEXT PRIMARY KEY, data BLOB NOT NULL, digest TEXT NOT NULL);
CREATE TABLE artifacts(id TEXT PRIMARY KEY, size INTEGER NOT NULL, data BLOB NOT NULL, digest TEXT NOT NULL);
CREATE TABLE acquisitions(id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES artifacts(id), data BLOB NOT NULL, digest TEXT NOT NULL);
CREATE TABLE records(id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES artifacts(id), ordinal INTEGER NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL, data BLOB NOT NULL, digest TEXT NOT NULL, UNIQUE(artifact_id,ordinal), UNIQUE(artifact_id,offset));
CREATE TABLE parse_runs(id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES artifacts(id), data BLOB NOT NULL, digest TEXT NOT NULL);
CREATE TABLE active_runs(artifact_id TEXT PRIMARY KEY REFERENCES artifacts(id), parse_run_id TEXT NOT NULL REFERENCES parse_runs(id), digest TEXT NOT NULL);
CREATE TABLE parse_records(parse_run_id TEXT NOT NULL REFERENCES parse_runs(id), record_id TEXT NOT NULL REFERENCES records(id), disposition TEXT NOT NULL, code TEXT, digest TEXT NOT NULL, PRIMARY KEY(parse_run_id,record_id));
CREATE TABLE events(id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES artifacts(id), parse_run_id TEXT NOT NULL REFERENCES parse_runs(id), ordinal INTEGER NOT NULL, low_us INTEGER, high_us INTEGER, kind TEXT NOT NULL, host TEXT, actor TEXT, search TEXT NOT NULL, data BLOB NOT NULL, digest TEXT NOT NULL);
CREATE TABLE objects(id TEXT PRIMARY KEY, kind TEXT NOT NULL, revision INTEGER NOT NULL, data BLOB NOT NULL, digest TEXT NOT NULL);
CREATE INDEX event_time ON events(low_us IS NULL,low_us,high_us,id);
CREATE INDEX event_source ON events(artifact_id,parse_run_id);
CREATE INDEX event_fields ON events(kind,host,actor);
CREATE INDEX record_source ON records(artifact_id,offset);
"""


def _error(code, exit_code=4):
    raise ProbentiumError(code, exit_code)


def _identifier(value):
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        _error("invalid_identifier", 2)
    return value


def _bounded(value, max_bytes=MAX_OBJECT_BYTES):
    """Structura ante serializationem terminatur."""
    pending, count, budget, ascii_keys = [(value, 0)], 0, 0, True
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 32 or count > 100_000:
            _error("object_structure_limit", 6)
        if isinstance(item, dict):
            if len(item) > 10_000:
                _error("invalid_object_structure", 2)
            budget += 2 + max(0, len(item) - 1) + len(item)
            for key, child in item.items():
                if not isinstance(key, str):
                    _error("invalid_object_structure", 2)
                if _SIMPLE_JSON_KEY.fullmatch(key):
                    # Claves ASCII simplices neque effugium neque ordinem novum postulant.
                    count += 1
                    budget += len(key) + 2
                    if depth >= 32 or count > 100_000:
                        _error("object_structure_limit", 6)
                else:
                    ascii_keys = ascii_keys and key.isascii()
                    pending.append((key, depth + 1))
                pending.append((child, depth + 1))
        elif isinstance(item, list):
            if len(item) > 100_000:
                _error("object_structure_limit", 6)
            budget += 2 + max(0, len(item) - 1)
            pending.extend((v, depth + 1) for v in item)
        elif isinstance(item, str):
            if len(item) > max_bytes:
                _error("object_size_limit", 6)
            try:
                budget += 2 + (len(item) if item.isascii() else len(item.encode("utf-8")))
            except UnicodeError:
                _error("invalid_object_text", 2)
            # Effugiorum expansio ante allocationem JSON numeratur.
            for match in _JSON_ESCAPES.finditer(item):
                budget += 1 if match.group() in '"\\\b\f\n\r\t' else 5
                if budget > max_bytes:
                    _error("object_size_limit", 6)
        elif item is None or type(item) is bool:
            budget += 5 if item is False else 4
        elif type(item) is int and abs(item) <= 9007199254740991:
            budget += len(str(item))
        else:
            _error("invalid_object_value", 2)
        if budget > max_bytes:
            _error("object_size_limit", 6)
    # Eadem probatio typorum, profunditatis et UTF-8 iam supra peracta est.
    data = _canonical_validated(value, ascii_keys)
    if len(data) > max_bytes:
        _error("object_size_limit", 6)
    return data


def _dump(value):
    raw = _bounded(value)
    return raw, hashlib.sha256(b"PROBENTIUM-OBJECT-V1\0" + raw).hexdigest()


def _load(raw, digest):
    try:
        value = strict_json(raw, MAX_OBJECT_BYTES)
        if _bounded(value) != raw or hashlib.sha256(b"PROBENTIUM-OBJECT-V1\0" + raw).hexdigest() != digest:
            _error("stored_object_digest_mismatch")
        return value
    except (TypeError, ValueError, OverflowError) as exc:
        if isinstance(exc, ProbentiumError) and exc.exit_code == 4:
            raise
        raise ProbentiumError("stored_object_invalid", 4) from None


def _checked_read(function):
    """Structura corrupta codicem fixum, non traceback, reddit."""
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ProbentiumError:
            raise
        except (sqlite3.Error, OSError, KeyError, IndexError, TypeError, ValueError, OverflowError):
            raise ProbentiumError("stored_structure_invalid", 4) from None
    return checked


@contextmanager
def _directory(path, private=False):
    """Omnis via per descriptores sine nexibus aperitur."""
    path = Path(os.path.abspath(path))
    fd = None
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if private and (stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid()):
            _error("case_directory_permissions", 2)
    except OSError as exc:
        if fd is not None:
            os.close(fd)
        raise ProbentiumError("storage_resource_limit" if exc.errno in (errno.ENOSPC, errno.EDQUOT) else "safe_directory_access_failed",
                              6 if exc.errno in (errno.ENOSPC, errno.EDQUOT) else 2) from None
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise
    try:
        yield fd
    finally:
        if fd is not None:
            os.close(fd)


def _private_file(directory, name, flags=os.O_RDONLY):
    try:
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            os.close(fd)
            _error("case_file_permissions", 2)
        return fd
    except OSError as exc:
        raise ProbentiumError("storage_resource_limit" if exc.errno in (errno.ENOSPC, errno.EDQUOT) else "safe_file_access_failed",
                              6 if exc.errno in (errno.ENOSPC, errno.EDQUOT) else 2) from None


def _schema_rows(db):
    return list(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"))


def _catalog_digest(db):
    """Catalogus absentiam membri deleti manifestat."""
    queries = {
        "artifacts": "SELECT id,digest FROM artifacts ORDER BY id",
        "acquisitions": "SELECT id,digest FROM acquisitions ORDER BY id",
        "records": "SELECT id,digest FROM records ORDER BY id",
        "parse_runs": "SELECT id,digest FROM parse_runs ORDER BY id",
        "active_runs": "SELECT artifact_id,parse_run_id,digest FROM active_runs ORDER BY artifact_id",
        "parse_records": "SELECT parse_run_id,record_id,digest FROM parse_records ORDER BY parse_run_id,record_id",
        "events": "SELECT id,digest FROM events ORDER BY id",
        "objects": "SELECT id,digest FROM objects ORDER BY id",
    }
    digest = hashlib.sha256(b"PROBENTIUM-CATALOG-V1\0")
    for table, sql in sorted(queries.items()):
        digest.update(canonical_bytes(table) + b"\n")
        for row in db.execute(sql):
            if any(not isinstance(value, str) or not _CATALOG_HEX.fullmatch(value) for value in row):
                _error("catalog_identity_invalid")
            # Hexadecimales sine effugio eandem formam JCS servant.
            digest.update(b'["' + b'","'.join(value.encode("ascii") for value in row) + b'"]\n')
    return digest.hexdigest()


def _parser_manifest():
    """Codicis manifestum distributio probata non dicitur."""
    from testifex import timeutil
    modules = {"parsers.py": Path(parsers.__file__), "timeutil.py": Path(timeutil.__file__),
               "store.py": Path(__file__), "contracts.py": Path(__file__).with_name("contracts.py"),
               "adapters.py": Path(__file__).with_name("adapters.py"), "worker.py": Path(__file__).with_name("worker.py"),
               "locators.py": Path(__file__).with_name("locators.py"), "limits.py": Path(__file__).with_name("limits.py")}
    members = {}
    for name, path in modules.items():
        with regular_reader(path, 4 * 1024 ** 2) as (stream, _):
            members[name] = hashlib.sha256(stream.read(4 * 1024 ** 2 + 1)).hexdigest()
    return {"schema": "probentium.parser-source-manifest.v1", "members": members}



def _validate_parser_manifest(manifest):
    if isinstance(manifest, dict) and manifest.get("schema") == "probentium.parser-distribution-manifest.v1":
        from .parser_artifact import validate_manifest
        return validate_manifest(manifest)
    if (not isinstance(manifest, dict) or set(manifest) != {"schema", "members"}
            or manifest["schema"] != "probentium.parser-source-manifest.v1" or not isinstance(manifest["members"], dict)
            or not 1 <= len(manifest["members"]) <= 64):
        _error("invalid_parser_manifest")
    for name, digest in manifest["members"].items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}\.py", name):
            _error("invalid_parser_manifest_member")
        _identifier(digest)
    return manifest

def _normalized(event):
    """Cellula relata non est tempus rei physicae."""
    value = dict(event)
    low, high = value["time_low_us"], value["time_high_us"]
    value["time_low_us"] = str(low) if low is not None else None
    value["time_high_us"] = str(high) if high is not None else None
    value["recorded_time"] = None if low is None else {"lo_us": str(low), "hi_us": str(high + 1), "lo_closed": True, "hi_closed": False}
    value["time_bounds_semantics"] = "legacy_inclusive_microsecond_cells"
    value["reference_time"] = None
    value["clock_alignment"] = "unknown"
    value["attributes"] = {k: str(v) if k.endswith("_us") else v for k, v in value["attributes"].items()}
    return value


def _record_id(value):
    return object_digest({k: value[k] for k in ("artifact_id", "offset", "length")}, "TESTIFEX-RECORD-V2")


def _run_id(value):
    return object_digest({k: value[k] for k in ("artifact_id", "adapter_id", "adapter_version", "parser_artifact_digest", "parser_config_digest")}, "TESTIFEX-PARSE-V2")


def _event_id(value):
    return object_digest({k: value[k] for k in ("parse_run_id", "record_refs", "output_index", "normalized_output_digest")}, "TESTIFEX-EVENT-V2")


def _assert_database_binding(path, directory, identity):
    """Nomen et inode post aperturam atque ante scripturam concordent."""
    try:
        with _directory(path, private=True) as current:
            old, new = os.fstat(directory), os.fstat(current)
            if (old.st_dev, old.st_ino) != (new.st_dev, new.st_ino):
                _error("database_path_changed", 4)
            fd = _private_file(current, "case.sqlite3")
            try:
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) != identity:
                    _error("database_path_changed", 4)
            finally:
                os.close(fd)
    except (OSError, CaseError, ProbentiumError):
        _error("database_path_changed", 4)


def _connect_checked(path, directory, readonly=False):
    """SQLite iterum nomen aperit; mutatio observata ante SQL reicitur."""
    anchor = _private_file(directory, "case.sqlite3")
    connection = None
    try:
        info = os.fstat(anchor)
        if info.st_size > MAX_DATABASE:
            _error("database_size_limit", 6)
        identity = (info.st_dev, info.st_ino)
        connection = sqlite3.connect((Path(path) / "case.sqlite3").as_uri() + ("?mode=ro" if readonly else "?mode=rw"),
                                     uri=True, isolation_level=None, timeout=0)
        _assert_database_binding(path, directory, identity)
        return connection, identity
    except BaseException:
        if connection is not None:
            connection.close()
        raise
    finally:
        os.close(anchor)


class CaseStore:
    """Lectio unam revisionem tenet; mutatio consensum exclusivum petit."""

    def __init__(self, path, *, resource_policy=None):
        self._resource_policy = resource_limits.validate(resource_policy) if resource_policy is not None else None
        self.path = Path(os.path.abspath(path))
        self.db = None
        self._dir = self._blobs = self._lock = None
        try:
            with _directory(self.path, private=True) as directory:
                self._dir = os.dup(directory)
            self._blobs = os.open("blobs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self._dir)
            info = os.fstat(self._blobs)
            if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
                _error("case_directory_permissions", 2)
            self._lock = _private_file(self._dir, "case.lock", os.O_RDWR)
            try:
                fcntl.flock(self._lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                _error("case_locked", 5)
            fd = _private_file(self._dir, "case.sqlite3")
            try:
                if os.fstat(fd).st_size > MAX_DATABASE:
                    _error("database_size_limit", 6)
            finally:
                os.close(fd)
            for extra in ("case.sqlite3-journal", "case.sqlite3-wal", "case.sqlite3-shm"):
                try:
                    os.stat(extra, dir_fd=self._dir, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                _error("database_recovery_required", 4)
            self.db, self._database_identity = _connect_checked(self.path, self._dir)
            self.db.enable_load_extension(False)
            self.db.execute("PRAGMA trusted_schema=OFF")
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA synchronous=FULL")
            page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
            self.db.execute(f"PRAGMA max_page_count={MAX_DATABASE // page_size}")
            if self.db.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID or self.db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                _error("unsupported_case_schema", 7)
            if self.db.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                _error("unsupported_journal_mode", 7)
            reference = sqlite3.connect(":memory:")
            try:
                reference.executescript(_SCHEMA)
                actual_rows, expected_rows = _schema_rows(self.db), _schema_rows(reference)
                legacy_index = "CREATE INDEX event_time ON events(low_us,high_us,id)"
                current_index = "CREATE INDEX event_time ON events(low_us IS NULL,low_us,high_us,id)"
                actual_rows = [(*row[:3], current_index) if row[:3] == ("index", "event_time", "events") and row[3] == legacy_index else row for row in actual_rows]
                old_event = next(row[3] for row in expected_rows if row[:3] == ("table", "events", "events")).replace("digest TEXT NOT NULL)", "digest TEXT NOT NULL, UNIQUE(parse_run_id,ordinal))")
                new_event = next(row[3] for row in expected_rows if row[:3] == ("table", "events", "events"))
                self._single_output_layout = any(row[:3] == ("table", "events", "events") and row[3] == old_event for row in actual_rows)
                actual_rows = [(*row[:3], new_event) if row[:3] == ("table", "events", "events") and row[3] == old_event else row for row in actual_rows]
                if actual_rows != expected_rows:
                    _error("case_schema_mismatch")
            finally:
                reference.close()
            self.db.execute("BEGIN")
            self._read_meta()
        except BaseException as exc:
            self.close()
            if isinstance(exc, (sqlite3.Error, OSError, CaseError)):
                raise ProbentiumError("case_open_failed", 4) from None
            raise

    @classmethod
    def create(cls, path, name="Untitled case", *, resource_policy=None):
        import tempfile
        from .maintenance import _publish_directory
        text_field(name)
        if resource_policy is not None:
            resource_policy = resource_limits.validate(resource_policy)
        path = Path(os.path.abspath(path))
        with _directory(path.parent) as parent:
            try:
                os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                _error("case_already_exists", 2)
        with tempfile.TemporaryDirectory(prefix=".case-", dir=path.parent) as staging:
            staged = Path(staging) / "case"
            with cls._create(staged, name):
                pass
            _publish_directory(staged, path)
        return cls(path, resource_policy=resource_policy)

    @classmethod
    def _create(cls, path, name="Untitled case"):
        text_field(name)
        path = Path(os.path.abspath(path))
        with _directory(path.parent) as parent:
            try:
                os.mkdir(path.name, 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                _error("case_already_exists", 2)
            except OSError:
                _error("case_create_failed", 2)
        with _directory(path, private=True) as directory:
            os.mkdir("blobs", 0o700, dir_fd=directory)
            for name_on_disk in ("case.lock", "case.sqlite3"):
                fd = os.open(name_on_disk, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                os.fsync(fd)
                os.close(fd)
            db, identity = _connect_checked(path, directory)
            try:
                db.execute("PRAGMA synchronous=FULL")
                db.executescript(_SCHEMA)
                db.execute(f"PRAGMA application_id={APPLICATION_ID}")
                db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                meta = {"schema_version": SCHEMA_VERSION, "case_id": uuid.uuid4().hex, "name": name,
                        "revision": 0, "limitations": _BASE_LIMITATIONS, "catalog_digest": _catalog_digest(db)}
                data, digest = _dump(meta)
                db.execute("INSERT INTO meta VALUES('case',?,?)", (data, digest))
                _assert_database_binding(path, directory, identity)
                db.commit()
            finally:
                db.close()
            os.fsync(directory)
        return cls(path)

    def __enter__(self):
        return self

    @property
    def resource_policy(self):
        return resource_limits.resolve(self._resource_policy, defaults={"max_source_bytes": MAX_ARTIFACT,
            "max_case_bytes": MAX_CASE_BYTES, "max_import_records": MAX_RECORDS, "max_case_events": MAX_EVENTS})

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        for key in ("_lock", "_blobs", "_dir"):
            fd = getattr(self, key, None)
            if fd is not None:
                os.close(fd)
                setattr(self, key, None)

    @_checked_read
    def _read_meta(self):
        rows = list(self.db.execute("SELECT key,data,digest FROM meta"))
        if len(rows) != 1 or rows[0][0] != "case":
            _error("case_metadata_invalid")
        value = _load(rows[0][1], rows[0][2])
        if (not isinstance(value, dict) or set(value) != {"schema_version", "case_id", "name", "revision", "limitations", "catalog_digest"}
                or value["schema_version"] != SCHEMA_VERSION or type(value["revision"]) is not int or not 0 <= value["revision"] < 9007199254740991
                or not isinstance(value["case_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", value["case_id"])
                or value["limitations"] not in _ACCEPTED_LIMITATIONS):
            _error("case_metadata_invalid")
        _identifier(value["catalog_digest"])
        try:
            text_field(value["name"])
        except ProbentiumError:
            _error("case_metadata_invalid")
        return value

    @property
    def meta(self):
        return self._read_meta()

    @property
    def revision(self):
        return self._read_meta()["revision"]

    def _expect(self, revision):
        if revision is not None and (type(revision) is not int or revision < 0):
            _error("invalid_expected_revision", 2)
        if revision is not None and revision != self.revision:
            _error("revision_conflict", 5)

    @contextmanager
    def _write(self, expected_revision=None):
        _assert_database_binding(self.path, self._dir, self._database_identity)
        self._expect(expected_revision)
        prior = self.revision
        self.db.execute("ROLLBACK")
        try:
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _error("case_locked", 5)
            self.db.execute("BEGIN IMMEDIATE")
            self._expect(prior if expected_revision is None else expected_revision)
            if self.meta["catalog_digest"] != _catalog_digest(self.db):
                _error("catalog_digest_mismatch")
            yield
            self._commit_checkpoint()
        except BaseException as exc:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            if isinstance(exc, sqlite3.Error) and getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL:
                raise ProbentiumError("storage_resource_limit", 6) from None
            if isinstance(exc, sqlite3.Error):
                raise ProbentiumError("database_operation_failed", 4) from None
            raise
        finally:
            try:
                fcntl.flock(self._lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                self.close()
                _error("case_locked", 5)
            self.db.execute("BEGIN")
            self._read_meta()

    def _commit_checkpoint(self, reopen=False):
        """Revisio et catalogus simul durabiles fiunt."""
        _assert_database_binding(self.path, self._dir, self._database_identity)
        meta = self._read_meta()
        meta["revision"] += 1
        meta["catalog_digest"] = _catalog_digest(self.db)
        data, digest = _dump(meta)
        self.db.execute("UPDATE meta SET data=?,digest=? WHERE key='case'", (data, digest))
        if self.db.execute("PRAGMA page_count").fetchone()[0] * self.db.execute("PRAGMA page_size").fetchone()[0] > MAX_DATABASE:
            _error("database_size_limit", 6)
        self.db.execute("COMMIT")
        os.fsync(self._dir)
        if reopen:
            self.db.execute("BEGIN IMMEDIATE")

    def _acquire(self, path):
        """Blob ante relationem SQL durabilis fit."""
        temporary = ".incoming-" + secrets.token_hex(16)
        fd = None
        policy = self.resource_policy
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self._blobs)
            h, size = hashlib.sha256(), 0
            with os.fdopen(fd, "wb") as output:
                fd = None
                with regular_reader(path, policy["max_source_bytes"]) as (stream, _):
                    stored_bytes = self._blob_inventory()[0]
                    if stored_bytes + os.fstat(stream.fileno()).st_size > policy["max_case_bytes"]:
                        _error("case_evidence_limit", 6)
                    capacity = os.fstatvfs(self._blobs)
                    if os.fstat(stream.fileno()).st_size + 32 * 1024 ** 2 > capacity.f_bavail * capacity.f_frsize:
                        _error("insufficient_disk_space", 6)
                    for chunk in iter(lambda: stream.read(1024 ** 2), b""):
                        size += len(chunk)
                        if size > policy["max_source_bytes"] or stored_bytes + size > policy["max_case_bytes"]:
                            _error("artifact_size_limit", 6)
                        h.update(chunk)
                        output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            digest = h.hexdigest()
            try:
                os.link(temporary, digest + ".bin", src_dir_fd=self._blobs, dst_dir_fd=self._blobs, follow_symlinks=False)
            except FileExistsError:
                with self._blob(digest, size):
                    pass
            os.unlink(temporary, dir_fd=self._blobs)
            temporary = None
            os.fsync(self._blobs)
            return digest, size
        except CaseError as exc:
            raise ProbentiumError("artifact_size_limit" if str(exc) == "input_size_limit" else "source_access_failed", 6 if str(exc) == "input_size_limit" else 2) from None
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                raise ProbentiumError("storage_resource_limit", 6) from None
            raise ProbentiumError("evidence_copy_failed", 4) from None
        finally:
            if fd is not None:
                os.close(fd)
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=self._blobs)
                except FileNotFoundError:
                    pass

    def _blob_inventory(self):
        """Orphana manent visibilia, numquam sponte deletur."""
        size, count, orphans = 0, 0, []
        with os.scandir(self._blobs) as entries:
            for entry in entries:
                count += 1
                if count > 2 * MAX_ARTIFACTS:
                    _error("blob_inventory_limit", 6)
                info = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                    _error("invalid_blob_entry")
                size += info.st_size
                if re.fullmatch(r"[0-9a-f]{64}\.bin", entry.name):
                    if self.db.execute("SELECT 1 FROM artifacts WHERE id=?", (entry.name[:-4],)).fetchone() is None:
                        orphans.append(entry.name)
                elif re.fullmatch(r"\.incoming-[0-9a-f]{32}", entry.name):
                    orphans.append(entry.name)
                else:
                    _error("unexpected_blob_entry")
        return size, sorted(orphans)

    def _blob_present(self, artifact_id):
        try:
            os.stat(artifact_id + ".bin", dir_fd=self._blobs, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    @contextmanager
    def _blob(self, artifact_id, size):
        _identifier(artifact_id)
        if not self._blob_present(artifact_id):
            from .retention import authorized_unavailable
            if artifact_id in authorized_unavailable(self):
                _error("artifact_authorized_unavailable", 3)
            _error("evidence_missing", 4)
        fd = _private_file(self._blobs, artifact_id + ".bin")
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if type(size) is not int or size < 0 or before.st_size != size or size > resource_limits.HARD_CAPS["max_source_bytes"]:
                _error("evidence_size_mismatch")
            h = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 ** 2), b""):
                h.update(chunk)
            if h.hexdigest() != artifact_id:
                _error("evidence_digest_mismatch")
            stream.seek(0)
            yield stream
            after = os.fstat(stream.fileno())
            current = os.stat(artifact_id + ".bin", dir_fd=self._blobs, follow_symlinks=False)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if identity(before) != identity(after) or identity(after) != identity(current):
                _error("evidence_changed_during_read")

    def ingest(self, path, format_name, label, expected_revision=None, expected_sha256=None, parser_approval_id=None):
        policy = self.resource_policy
        from .worker import require_strict_platform
        require_strict_platform()
        if format_name not in adapters.FORMATS:
            _error("format_unsupported", 7)
        text_field(label)
        if expected_sha256 is not None:
            _identifier(expected_sha256)
        selected_manifest = None
        if parser_approval_id is not None:
            from .parser_artifact import resolve_approval
            selected_manifest = resolve_approval(self, parser_approval_id)
        with self._write(expected_revision):
            if self.db.execute("SELECT count(*) FROM acquisitions").fetchone()[0] >= MAX_ACQUISITIONS:
                _error("acquisition_count_limit", 6)
            artifact_id, size = self._acquire(path)
            if expected_sha256 is not None and artifact_id != expected_sha256:
                _error("batch_source_changed", 4)
            old = self.db.execute("SELECT data,digest FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
            duplicate = old is not None
            if not duplicate:
                n, total = self.db.execute("SELECT count(*),coalesce(sum(size),0) FROM artifacts").fetchone()
                if n >= MAX_ARTIFACTS or total + size > policy["max_case_bytes"]:
                    _error("case_evidence_limit", 6)
                artifact = {"id": artifact_id, "sha256": artifact_id, "size": size, "content_type": "source.bytes"}
                data, digest = _dump(artifact)
                self.db.execute("INSERT INTO artifacts VALUES(?,?,?,?)", (artifact_id, size, data, digest))
            else:
                artifact = _load(*old)
                if artifact["size"] != size:
                    _error("artifact_identity_mismatch")
            manifest = selected_manifest if selected_manifest is not None else _parser_manifest()
            config = {"max_records": policy["max_import_records"], "max_line_bytes": MAX_LINE, "format": format_name}
            if self._resource_policy is not None:
                config["resource_policy"] = policy
            run = {"artifact_id": artifact_id, "adapter_id": format_name, "adapter_version": adapters.VERSION,
                   "parser_artifact_digest": object_digest(manifest, "TESTIFEX-PARSER-ARTIFACT-V2"),
                   "parser_manifest": manifest, "parser_config_digest": object_digest(config), "config": config}
            run["id"] = _run_id(run)
            existing = self.db.execute("SELECT data,digest FROM parse_runs WHERE id=?", (run["id"],)).fetchone()
            acquisition = {"id": uuid.uuid4().hex, "artifact_id": artifact_id, "label": label, "method": "copied_regular_file", "acquired_revision": self.revision + 1}
            if parser_approval_id is not None:
                acquisition["parser_approval_ref"] = parser_approval_id
                acquisition["parse_run_id"] = run["id"]
            data, digest = _dump(acquisition)
            self.db.execute("INSERT INTO acquisitions VALUES(?,?,?,?)", (acquisition["id"], artifact_id, data, digest))
            if existing is None:
                self._parse(artifact, run)
            else:
                _load(*existing)
                selection_digest = object_digest({"artifact_id": artifact_id, "parse_run_id": run["id"]})
                self.db.execute("INSERT INTO active_runs VALUES(?,?,?) ON CONFLICT(artifact_id) DO UPDATE SET parse_run_id=excluded.parse_run_id,digest=excluded.digest", (artifact_id, run["id"], selection_digest))
        result = next(item for item in self.sources() if item["id"] == artifact_id)
        return {**result, "duplicate_artifact": duplicate, "revision": self.revision}

    def _parse(self, artifact, run, resume=False):
        recorded_policy = resource_limits.parse_config(run["config"])
        policy = recorded_policy or self.resource_policy
        if not resume:
            run.update({"counters": dict.fromkeys(_DISPOSITIONS, 0), "records_total": 0, "events_total": 0, "cursor": 0,
                        "state": "pending", "coverage": "acquired_stream_only",
                        "limitations": _CURRENT_LIMITATIONS if run["parser_manifest"]["schema"] == "probentium.parser-source-manifest.v1" else _DISTRIBUTION_LIMITATIONS})
            data, digest = _dump(run)
            self.db.execute("INSERT INTO parse_runs VALUES(?,?,?,?)", (run["id"], artifact["id"], data, digest))
        selection_digest = object_digest({"artifact_id": artifact["id"], "parse_run_id": run["id"]})
        self.db.execute("INSERT INTO active_runs VALUES(?,?,?) ON CONFLICT(artifact_id) DO UPDATE SET parse_run_id=excluded.parse_run_id,digest=excluded.digest", (artifact["id"], run["id"], selection_digest))
        counters = run["counters"]
        starting_records = run["records_total"]
        existing_records = self.db.execute("SELECT count(*) FROM records").fetchone()[0]
        existing_dispositions = self.db.execute("SELECT count(*) FROM parse_records").fetchone()[0]
        existing_events = self.db.execute("SELECT count(*) FROM events WHERE parse_run_id != ?", (run["id"],)).fetchone()[0]
        with self._blob(artifact["id"], artifact["size"]) as stream, ParserWorker(artifact["size"], resource_policy=recorded_policy) as worker:
            stream.seek(run["cursor"])
            while run["cursor"] < artifact["size"] and run["records_total"] - starting_records < policy["max_import_records"]:
                if run["records_total"] % 256 == 0:
                    capacity = os.fstatvfs(self._dir)
                    if capacity.f_bavail * capacity.f_frsize < 32 * 1024 ** 2:
                        _error("insufficient_disk_space", 6)
                offset = stream.tell()
                raw = stream.readline(MAX_LINE + 1)
                if not raw:
                    _error("evidence_read_truncated")
                length, h = len(raw), hashlib.sha256(raw)
                oversize = length > MAX_LINE
                while oversize and not raw.endswith(b"\n"):
                    raw = stream.readline(MAX_LINE + 1)
                    if not raw:
                        break
                    length += len(raw)
                    h.update(raw)
                ordinal = run["records_total"] + 1
                record = {"artifact_id": artifact["id"], "ordinal": ordinal, "offset": offset, "length": length, "raw_digest": h.hexdigest()}
                record["id"] = _record_id(record)
                data, digest = _dump(record)
                previous = self.db.execute("SELECT data,digest FROM records WHERE id=?", (record["id"],)).fetchone()
                if previous is None:
                    if existing_records >= resource_limits.HARD_CAPS["max_import_records"]:
                        _error("case_record_limit", 6)
                    self.db.execute("INSERT INTO records VALUES(?,?,?,?,?,?,?)", (record["id"], artifact["id"], ordinal, offset, length, data, digest))
                    existing_records += 1
                elif _load(*previous) != record:
                    _error("record_identity_mismatch")
                event, code = None, None
                if oversize:
                    disposition, code = "oversize", "line_limit"
                elif run["adapter_id"] == "opaque":
                    disposition = "known_out_of_scope"
                elif not raw.strip(b" \t\r\n"):
                    disposition = "blank"
                else:
                    try:
                        event = worker.parse(raw, run["adapter_id"], ordinal)
                        disposition = "parsed" if event is not None else "unsupported"
                    except (parsers.ParseError, ProbentiumError) as exc:
                        if isinstance(exc, ProbentiumError) and exc.exit_code in (4, 6):
                            raise
                        disposition, code = ("unsupported" if isinstance(exc, ProbentiumError) and exc.exit_code == 7 else "malformed"), exc.code
                if event is not None:
                    if existing_events + run["events_total"] >= policy["max_case_events"]:
                        _error("case_event_limit", 6)
                    output = _normalized(event)
                    self._append_event(run, [record], output)
                    run["events_total"] += 1
                if existing_dispositions >= resource_limits.HARD_CAPS["max_import_records"]:
                    _error("case_disposition_limit", 6)
                existing_dispositions += 1
                disposition_digest = object_digest({"parse_run_id": run["id"], "record_id": record["id"], "disposition": disposition, "code": code})
                self.db.execute("INSERT INTO parse_records VALUES(?,?,?,?,?)", (run["id"], record["id"], disposition, code, disposition_digest))
                counters[disposition] += 1
                run["records_total"] += 1
                run["cursor"] = stream.tell()
                if run["records_total"] % CHECKPOINT_RECORDS == 0 and run["cursor"] < artifact["size"]:
                    self._save_run(artifact, run)
                    self._commit_checkpoint(reopen=True)
        self._save_run(artifact, run)

    def _append_event(self, run, records, output, output_index=0, primary_record_ref=None):
        """Parser probatus locos explicitos tradit; identitas immutabilis manet."""
        from .locators import event_records
        from .exchange import _normalized_output
        _normalized_output(output)
        if not isinstance(records, list) or not records:
            _error("event_record_count_invalid")
        primary = next((record for record in records if record["id"] == primary_record_ref), records[0])
        item = {**output, "artifact_id": run["artifact_id"], "source_id": run["artifact_id"], "parse_run_id": run["id"],
                "record_refs": [record["id"] for record in records], "primary_record_ref": primary_record_ref or primary["id"],
                "output_index": output_index, **{key: primary[key] for key in ("ordinal", "offset", "length", "raw_digest")},
                "normalized_output": output, "normalized_output_digest": object_digest(output)}
        event_records(item, {record["id"]: record for record in records}.get)
        if getattr(self, "_single_output_layout", False) and (len(records) != 1 or output_index != 0):
            _error("legacy_locator_layout_requires_copy", 7)
        item["id"] = _event_id(item)
        data, digest = _dump(item)
        search = canonical_bytes(output).decode("utf-8").casefold()
        self.db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (item["id"], run["artifact_id"], run["id"], primary["ordinal"],
                        None if output["time_low_us"] is None else int(output["time_low_us"]),
                        None if output["time_high_us"] is None else int(output["time_high_us"]), output["kind"], output["host"], output["actor"], search, data, digest))
        return item

    def _save_run(self, artifact, run):
        counters = run["counters"]
        run["state"] = "complete" if run["cursor"] == artifact["size"] else "incomplete"
        run["unprocessed_bytes"] = artifact["size"] - run["cursor"]
        run["unprocessed_records"] = 0 if run["state"] == "complete" else None
        run["interpretation_complete"] = run["state"] == "complete" and not any(counters[k] for k in ("known_out_of_scope", "unsupported", "malformed", "oversize"))
        data, digest = _dump(run)
        self.db.execute("UPDATE parse_runs SET data=?,digest=? WHERE id=?", (data, digest, run["id"]))

    @_checked_read
    def sources(self):
        result = []
        for aid, size, raw, digest, rid, rraw, rdigest, selection_digest in self.db.execute("SELECT a.id,a.size,a.data,a.digest,p.id,p.data,p.digest,x.digest FROM artifacts a JOIN active_runs x ON x.artifact_id=a.id JOIN parse_runs p ON p.id=x.parse_run_id ORDER BY a.id"):
            artifact, run = _load(raw, digest), _load(rraw, rdigest)
            if artifact["id"] != aid or artifact["size"] != size or run["id"] != rid or _run_id(run) != rid or run["artifact_id"] != aid or selection_digest != object_digest({"artifact_id": aid, "parse_run_id": rid}):
                _error("source_identity_mismatch")
            acquisitions = [_load(row[0], row[1]) for row in self.db.execute("SELECT data,digest FROM acquisitions WHERE artifact_id=? ORDER BY rowid", (aid,))]
            result.append({**artifact, "active_parse_run": rid, "parse_run_id": rid, "format": run["adapter_id"],
                           "label": acquisitions[-1]["label"] if acquisitions else "Unlabelled evidence", "acquisitions": acquisitions,
                           "status": run["state"], "state": run["state"], "counters": run["counters"], "records_total": run["records_total"],
                           "events_total": run["events_total"], "cursor": run["cursor"], "unprocessed_bytes": run["unprocessed_bytes"],
                           "unprocessed_records": run["unprocessed_records"], "interpretation_complete": run["interpretation_complete"],
                           "parser_artifact_digest": run["parser_artifact_digest"], "limitations": run["limitations"]})
        return result

    @_checked_read
    def _event(self, row):
        item = _load(row[10], row[11])
        output = item.get("normalized_output")
        normalized_bytes = canonical_bytes(output)
        if (item.get("id") != row[0] or _event_id(item) != row[0] or hashlib.sha256(b"PROBENTIUM-OBJECT-V1\0" + normalized_bytes).hexdigest() != item.get("normalized_output_digest")
                or item.get("artifact_id") != row[1] or item.get("source_id") != row[1] or item.get("parse_run_id") != row[2] or item.get("ordinal") != row[3]
                or output != {k: item[k] for k in output}
                or (None if item["time_low_us"] is None else int(item["time_low_us"])) != row[4]
                or (None if item["time_high_us"] is None else int(item["time_high_us"])) != row[5]
                or (item["kind"], item["host"], item["actor"]) != row[6:9]
                or normalized_bytes.decode("utf-8").casefold() != row[9]):
            _error("event_identity_mismatch")
        return item

    @_checked_read
    def query_events(self, query="", limit=100, offset=0, expected_revision=None):
        self._expect(expected_revision)
        if not isinstance(query, str) or len(query) > 4096 or type(limit) is not int or not 1 <= limit <= MAX_PAGE or type(offset) is not int or not 0 <= offset <= resource_limits.HARD_CAPS["max_case_events"]:
            _error("invalid_query", 2)
        where = "FROM events e JOIN active_runs a ON a.parse_run_id=e.parse_run_id AND a.artifact_id=e.artifact_id"
        folded = query.casefold()
        parameters = [folded] if folded else []
        if folded:
            where += " WHERE instr(e.search,?)>0"
        total = self.db.execute("SELECT count(*) " + where, parameters).fetchone()[0]
        rows = [self._event(row) for row in self.db.execute("SELECT e.* " + where + " ORDER BY e.low_us IS NULL,e.low_us,e.high_us,e.id LIMIT ? OFFSET ?", parameters + [limit, offset])]
        return {"rows": rows, "total": total, "revision": self.revision,
                "query_digest": object_digest({"query": query, "revision": self.revision}), "limit": limit, "offset": offset}

    @_checked_read
    def query_after(self, query="", limit=100, last_sort_key=None, expected_revision=None):
        self._expect(expected_revision)
        if not isinstance(query, str) or len(query) > 4096 or type(limit) is not int or not 1 <= limit <= MAX_PAGE:
            _error("invalid_query", 2)
        where = " FROM events e JOIN active_runs a ON a.parse_run_id=e.parse_run_id AND a.artifact_id=e.artifact_id WHERE "
        where += "instr(e.search,?)>0" if query else "1=1"
        parameters = [query.casefold()] if query else []
        total = self.db.execute("SELECT count(*)" + where, parameters).fetchone()[0]
        offset = 0
        if last_sort_key is not None:
            key = last_sort_key
            if not isinstance(key, list) or len(key) != 4 or type(key[0]) is not bool:
                _error("invalid_cursor_sort_key", 2)
            _identifier(key[3])
            if key[0]:
                if key[1:3] != [None, None]:
                    _error("invalid_cursor_sort_key", 2)
                values = [1, 0, 0, key[3]]
            else:
                if any(not isinstance(x, str) or not re.fullmatch(r"-?(0|[1-9][0-9]{0,17})", x) for x in key[1:3]):
                    _error("invalid_cursor_sort_key", 2)
                values = [0, int(key[1]), int(key[2]), key[3]]
                if values[1] > values[2]:
                    _error("invalid_cursor_sort_key", 2)
            expression = " AND (e.low_us IS NULL,coalesce(e.low_us,0),coalesce(e.high_us,0),e.id)"
            offset = self.db.execute("SELECT count(*)" + where + expression + "<=(?,?,?,?)", parameters + values).fetchone()[0]
            where += expression + ">(?,?,?,?)"
            parameters += values
        rows = [self._event(row) for row in self.db.execute("SELECT e.*" + where + " ORDER BY e.low_us IS NULL,e.low_us,e.high_us,e.id LIMIT ?", parameters + [limit])]
        return {"rows": rows, "total": total, "revision": self.revision, "limit": limit, "offset": offset,
                "query_digest": object_digest({"query": query, "case_id": self.meta["case_id"]})}

    @_checked_read
    def raw_records(self, event_id):
        """Segmenta separata limites et primarium locum conservant."""
        from .locators import event_records
        _identifier(event_id)
        row = self.db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        if row is None:
            _error("event_not_found", 2)
        event = self._event(row)
        records = event_records(event, self._record)
        source = self.db.execute("SELECT size FROM artifacts WHERE id=?", (event["artifact_id"],)).fetchone()
        if source is None or any(record["offset"] + record["length"] > source[0] for record in records):
            _error("record_range_invalid")
        segments = []
        with self._blob(event["artifact_id"], source[0]) as stream:
            for record in records:
                stream.seek(record["offset"])
                raw = stream.read(record["length"])
                if len(raw) != record["length"] or hashlib.sha256(raw).hexdigest() != record["raw_digest"]:
                    _error("record_digest_mismatch")
                segments.append({"record": record, "bytes": raw, "primary": record["id"] == event["primary_record_ref"]})
        return segments

    def raw(self, event_id):
        """Unus locus formam veterem servat; composita limites requirunt."""
        segments = self.raw_records(event_id)
        if len(segments) != 1:
            _error("composite_raw_requires_segments", 7)
        return segments[0]["bytes"]

    @_checked_read
    def _record(self, record_id):
        row = self.db.execute("SELECT * FROM records WHERE id=?", (_identifier(record_id),)).fetchone()
        if row is None:
            _error("record_not_found")
        value = _load(row[5], row[6])
        if value.get("id") != row[0] or _record_id(value) != row[0] or tuple(value[k] for k in ("artifact_id", "ordinal", "offset", "length")) != row[1:5] or type(value["offset"]) is not int or type(value["length"]) is not int or value["offset"] < 0 or value["length"] <= 0:
            _error("record_identity_mismatch")
        return value

    def put_object(self, kind, data, expected_revision=None):
        if not isinstance(kind, str) or not _KIND.fullmatch(kind) or not isinstance(data, dict):
            _error("invalid_object_schema", 2)
        raw = _bounded(data)
        value = strict_json(raw, MAX_OBJECT_BYTES)
        identity = object_digest({"kind": kind, "data": value}, "PROBENTIUM-STORED-OBJECT-V1")
        with self._write(expected_revision):
            existing = self.db.execute("SELECT id FROM objects WHERE id=?", (identity,)).fetchone()
            if existing is None:
                if self.db.execute("SELECT count(*) FROM objects").fetchone()[0] >= MAX_OBJECTS:
                    _error("object_count_limit", 6)
                created = self.revision + 1
                digest = object_digest({"kind": kind, "data": value, "revision": created})
                self.db.execute("INSERT INTO objects VALUES(?,?,?,?,?)", (identity, kind, created, raw, digest))
            else:
                self.get_object(identity)
        return self.get_object(identity)

    @_checked_read
    def get_object(self, identity):
        row = self.db.execute("SELECT id,kind,revision,data,digest FROM objects WHERE id=?", (_identifier(identity),)).fetchone()
        if row is None:
            _error("object_not_found", 2)
        try:
            value = strict_json(row[3], MAX_OBJECT_BYTES)
            if _bounded(value) != row[3] or object_digest({"kind": row[1], "data": value, "revision": row[2]}) != row[4]:
                _error("stored_object_digest_mismatch")
        except (TypeError, ValueError):
            _error("stored_object_invalid")
        if not isinstance(value, dict) or not _KIND.fullmatch(row[1]) or object_digest({"kind": row[1], "data": value}, "PROBENTIUM-STORED-OBJECT-V1") != row[0] or type(row[2]) is not int or not 1 <= row[2] <= self.revision:
            _error("object_identity_mismatch")
        return {"id": row[0], "kind": row[1], "data": value, "revision": row[2]}

    @_checked_read
    def objects(self, kind=None):
        if kind is not None and (not isinstance(kind, str) or not _KIND.fullmatch(kind)):
            _error("invalid_object_kind", 2)
        where, args = ("", ()) if kind is None else (" WHERE kind=?", (kind,))
        if self.db.execute("SELECT coalesce(sum(length(data)),0) FROM objects" + where, args).fetchone()[0] > MAX_LIST_BYTES:
            _error("object_listing_limit", 6)
        return [self.get_object(row[0]) for row in self.db.execute("SELECT id FROM objects" + where + " ORDER BY revision,id", args)]

    def export_snapshot(self, max_bytes=64 * 1024 ** 2):
        """SQL numquam transfertur; summa ante allocationem probatur."""
        if type(max_bytes) is not int or not 1 <= max_bytes <= 64 * 1024 ** 2:
            _error("snapshot_size_limit", 6)
        total = 0
        for table in ("meta", "artifacts", "acquisitions", "records", "parse_runs", "events", "objects"):
            total += self.db.execute("SELECT coalesce(sum(length(data)),0) FROM " + table).fetchone()[0]
        total += self.db.execute("SELECT count(*)*320 FROM parse_records").fetchone()[0]
        if total > max_bytes:
            _error("snapshot_size_limit", 6)
        check = self.verify()
        if not check["ok"]:
            _error("snapshot_integrity_failed", 4)
        result = {"schema": "probentium.case-snapshot.v1", "meta": self.meta}
        for table in ("artifacts", "acquisitions", "records", "parse_runs", "events"):
            result[table] = [_load(raw, digest) for raw, digest in self.db.execute("SELECT data,digest FROM " + table + " ORDER BY id")]
        result["objects"] = self.objects()
        result["active_runs"] = [dict(zip(("artifact_id", "parse_run_id", "digest"), row)) for row in self.db.execute("SELECT * FROM active_runs ORDER BY artifact_id")]
        result["parse_records"] = [dict(zip(("parse_run_id", "record_id", "disposition", "code", "digest"), row)) for row in self.db.execute("SELECT * FROM parse_records ORDER BY parse_run_id,record_id")]
        if len(canonical_bytes(result)) > max_bytes:
            _error("snapshot_size_limit", 6)
        return result

    def snapshot_header(self):
        """Caput parvum; tabulae singulatim leguntur."""
        check = self.verify()
        if not check["ok"]:
            _error("snapshot_integrity_failed", 4)
        tables = ("artifacts", "acquisitions", "records", "parse_runs", "active_runs", "parse_records", "events", "objects")
        return {"schema": "probentium.case-snapshot.v1", "meta": self.meta,
                "counts": {name: self.db.execute("SELECT count(*) FROM " + name).fetchone()[0] for name in tables}}

    def iter_snapshot_rows(self, table):
        """Nomen tabulae ex albo clauso venit; revisio manet fixa."""
        tables = {"artifacts", "acquisitions", "records", "parse_runs", "events", "objects", "active_runs", "parse_records"}
        if table not in tables:
            _error("invalid_snapshot_table", 2)
        if table == "objects":
            for identity, in self.db.execute("SELECT id FROM objects ORDER BY id"):
                yield self.get_object(identity)
        elif table == "events":
            for row in self.db.execute("SELECT * FROM events ORDER BY id"):
                yield self._event(row)
        elif table == "active_runs":
            for row in self.db.execute("SELECT * FROM active_runs ORDER BY artifact_id"):
                yield dict(zip(("artifact_id", "parse_run_id", "digest"), row))
        elif table == "parse_records":
            for row in self.db.execute("SELECT * FROM parse_records ORDER BY parse_run_id,record_id"):
                yield dict(zip(("parse_run_id", "record_id", "disposition", "code", "digest"), row))
        else:
            for raw, digest in self.db.execute("SELECT data,digest FROM " + table + " ORDER BY id"):
                yield _load(raw, digest)

    def resume(self, artifact_id, expected_revision=None, parser_approval_id=None):
        """Solum cursor probatus resumitur."""
        _identifier(artifact_id)
        if not self.verify()["ok"]:
            _error("resume_integrity_failed")
        with self._write(expected_revision):
            exact = self.db.execute("SELECT data,digest FROM parse_runs WHERE id=?", (artifact_id,)).fetchone()
            if exact is not None:
                selected = _load(*exact)
                active = self.db.execute("SELECT parse_run_id FROM active_runs WHERE artifact_id=?", (selected["artifact_id"],)).fetchone()
                if active is None or active[0] != selected["id"]:
                    _error("parse_run_not_active", 5)
                artifact_id = selected["artifact_id"]
            row = self.db.execute("SELECT p.data,p.digest FROM parse_runs p JOIN active_runs a ON p.id=a.parse_run_id WHERE a.artifact_id=?", (artifact_id,)).fetchone()
            if row is None:
                _error("source_not_found", 2)
            run = _load(*row)
            recorded_policy = resource_limits.parse_config(run["config"])
            if self._resource_policy is not None and self._resource_policy != recorded_policy:
                _error("resume_resource_policy_mismatch", 5)
            if parser_approval_id is not None:
                from .parser_artifact import resolve_approval
                selected_manifest = resolve_approval(self, parser_approval_id)
            else:
                selected_manifest = _parser_manifest()
            if run["parser_artifact_digest"] != object_digest(selected_manifest, "TESTIFEX-PARSER-ARTIFACT-V2"):
                _error("resume_parser_version_unavailable", 7)
            if run["state"] != "incomplete":
                _error("source_not_resumable", 2)
            artifact = _load(*self.db.execute("SELECT data,digest FROM artifacts WHERE id=?", (artifact_id,)).fetchone())
            self._parse(artifact, run, resume=True)
        return next(item for item in self.sources() if item["id"] == artifact_id)

    def issues(self, artifact_id=None, limit=1000):
        if type(limit) is not int or not 1 <= limit <= 1000:
            _error("invalid_query", 2)
        if artifact_id is not None:
            _identifier(artifact_id)
        query = "SELECT r.artifact_id,r.ordinal,r.offset,r.length,p.disposition,p.code FROM parse_records p JOIN records r ON r.id=p.record_id JOIN active_runs a ON a.parse_run_id=p.parse_run_id WHERE p.disposition IN ('unsupported','malformed','oversize')"
        args = []
        if artifact_id is not None:
            query += " AND r.artifact_id=?"
            args.append(artifact_id)
        count = self.db.execute("SELECT count(*) FROM (" + query + ")", args).fetchone()[0]
        return {"revision": self.revision, "total": count, "rows": [dict(zip(("artifact_id", "line", "offset", "length", "disposition", "code"), row)) for row in self.db.execute(query + " ORDER BY r.artifact_id,r.ordinal LIMIT ?", [*args, limit])]}

    def verify(self):
        checks, issues = [], []
        revision = None
        unreferenced_blobs, unavailable = [], []
        try:
            revision = self.revision
            if self.db.execute("PRAGMA integrity_check").fetchall() != [("ok",)] or self.db.execute("PRAGMA foreign_key_check").fetchone() is not None:
                _error("database_integrity_failed")
            checks.append("database_structure")
            if self.meta["catalog_digest"] != _catalog_digest(self.db):
                _error("catalog_digest_mismatch")
            checks.append("catalog_membership")
            from .retention import authorized_unavailable
            permitted = authorized_unavailable(self)
            if (self.db.execute("SELECT coalesce(sum(size),0) FROM artifacts").fetchone()[0] > resource_limits.HARD_CAPS["max_case_bytes"]
                    or self.db.execute("SELECT count(*) FROM events").fetchone()[0] > resource_limits.HARD_CAPS["max_case_events"]
                    or self.db.execute("SELECT count(*) FROM records").fetchone()[0] > resource_limits.HARD_CAPS["max_import_records"]
                    or self.db.execute("SELECT count(*) FROM parse_records").fetchone()[0] > resource_limits.HARD_CAPS["max_import_records"]):
                _error("stored_resource_hard_cap_exceeded", 6)
            for aid, size, raw, digest in self.db.execute("SELECT * FROM artifacts ORDER BY id"):
                value = _load(raw, digest)
                if value != {"id": aid, "sha256": aid, "size": size, "content_type": "source.bytes"}:
                    _error("artifact_identity_mismatch")
                missing_permitted = aid in permitted and not self._blob_present(aid)
                if missing_permitted:
                    unavailable.append({"artifact_id": aid, "tombstone_id": permitted[aid]})
                with (nullcontext(None) if missing_permitted else self._blob(aid, size)) as stream:
                    previous_end = 0
                    for rid, in self.db.execute("SELECT id FROM records WHERE artifact_id=? ORDER BY offset", (aid,)):
                        record = self._record(rid)
                        if record["offset"] != previous_end or record["offset"] + record["length"] > size:
                            _error("record_range_invalid")
                        if stream is not None:
                            stream.seek(record["offset"])
                            remain, h = record["length"], hashlib.sha256()
                            while remain:
                                chunk = stream.read(min(remain, MAX_LINE))
                                if not chunk:
                                    _error("record_range_invalid")
                                h.update(chunk)
                                remain -= len(chunk)
                            if h.hexdigest() != record["raw_digest"]:
                                _error("record_digest_mismatch")
                        previous_end += record["length"]
            checks.append("evidence_and_record_bytes")
            for rid, aid, raw, digest in self.db.execute("SELECT * FROM parse_runs"):
                run = _load(raw, digest)
                if run["id"] != rid or run["artifact_id"] != aid or _run_id(run) != rid or object_digest(run["config"]) != run["parser_config_digest"] or object_digest(run["parser_manifest"], "TESTIFEX-PARSER-ARTIFACT-V2") != run["parser_artifact_digest"]:
                    _error("parse_run_identity_mismatch")
                _validate_parser_manifest(run["parser_manifest"])
                recorded_policy = resource_limits.parse_config(run["config"])
                if recorded_policy is not None and self.db.execute("SELECT size FROM artifacts WHERE id=?", (aid,)).fetchone()[0] > recorded_policy["max_source_bytes"]:
                    _error("parse_source_policy_mismatch")
                counts = dict.fromkeys(_DISPOSITIONS, 0)
                cursor, ordinal = 0, 0
                for record_id, disposition, code, disposition_digest in self.db.execute("SELECT p.record_id,p.disposition,p.code,p.digest FROM parse_records p JOIN records r ON r.id=p.record_id WHERE p.parse_run_id=? ORDER BY r.offset", (rid,)):
                    record = self._record(record_id)
                    ordinal += 1
                    if record["artifact_id"] != aid or record["offset"] != cursor or record["ordinal"] != ordinal or disposition not in counts or (code is not None and (not isinstance(code, str) or not re.fullmatch(r"[a-z_]{1,64}", code))):
                        _error("parse_accounting_invalid")
                    if disposition_digest != object_digest({"parse_run_id": rid, "record_id": record_id, "disposition": disposition, "code": code}):
                        _error("parse_accounting_digest_mismatch")
                    cursor += record["length"]
                    counts[disposition] += 1
                size = self.db.execute("SELECT size FROM artifacts WHERE id=?", (aid,)).fetchone()[0]
                actual_events = self.db.execute("SELECT count(*) FROM events WHERE parse_run_id=?", (rid,)).fetchone()[0]
                complete = cursor == size
                if (counts != run["counters"] or ordinal != run["records_total"] or cursor != run["cursor"] or actual_events != run["events_total"]
                        or run["state"] != ("complete" if complete else "incomplete") or run["unprocessed_bytes"] != size - cursor
                        or run["unprocessed_records"] != (0 if complete else None)
                        or run["interpretation_complete"] != (complete and not any(counts[k] for k in ("known_out_of_scope", "unsupported", "malformed", "oversize")))):
                    _error("parse_accounting_invalid")
            if self.db.execute("SELECT count(*) FROM artifacts").fetchone()[0] != self.db.execute("SELECT count(*) FROM active_runs").fetchone()[0]:
                _error("active_parse_run_missing")
            self.sources()
            checks.append("parse_accounting_and_active_selection")
            from .locators import event_records, observation_key
            used, outputs = {}, set()
            for row in self.db.execute("SELECT * FROM events"):
                event = self._event(row)
                records = event_records(event, self._record)
                key = observation_key(event)
                if key in outputs:
                    _error("duplicate_normalized_observation")
                outputs.add(key)
                covered = used.setdefault(event["parse_run_id"], set())
                for record in records:
                    link = self.db.execute("SELECT disposition FROM parse_records WHERE parse_run_id=? AND record_id=?", (event["parse_run_id"], record["id"])).fetchone()
                    if link != ("parsed",):
                        _error("event_disposition_mismatch")
                    covered.add(bytes.fromhex(record["id"]))
            for rid, raw, digest in self.db.execute("SELECT id,data,digest FROM parse_runs"):
                if len(used.get(rid, ())) != _load(raw, digest)["counters"]["parsed"]:
                    _error("parse_accounting_invalid")
            checks.append("normalized_event_identity")
            for aid, artifact_id, raw, digest in self.db.execute("SELECT * FROM acquisitions"):
                acquisition = _load(raw, digest)
                fields = {"id", "artifact_id", "label", "method"}
                if not isinstance(acquisition, dict) or set(acquisition) not in (fields, fields | {"acquired_revision"}, fields | {"acquired_revision", "parser_approval_ref", "parse_run_id"}):
                    _error("acquisition_shape_invalid")
                if not isinstance(aid, str) or not re.fullmatch(r"[a-f0-9]{32}", aid) or self.db.execute("SELECT 1 FROM artifacts WHERE id=?", (artifact_id,)).fetchone() is None:
                    _error("acquisition_identity_mismatch")
                if acquisition.get("id") != aid or acquisition.get("artifact_id") != artifact_id or acquisition.get("method") != "copied_regular_file":
                    _error("acquisition_identity_mismatch")
                text_field(acquisition["label"])
                if "acquired_revision" in acquisition and (type(acquisition["acquired_revision"]) is not int or not 1 <= acquisition["acquired_revision"] <= self.revision):
                    _error("acquisition_revision_invalid")
                if "parser_approval_ref" in acquisition:
                    from .parser_artifact import validate_approval
                    approval = self.get_object(acquisition["parser_approval_ref"])
                    if approval["kind"] != "parser_approval":
                        _error("parser_approval_required")
                    validate_approval(approval["data"])
                    if approval["revision"] >= acquisition["acquired_revision"]:
                        _error("acquisition_revision_invalid")
                    selected = self.db.execute("SELECT data,digest FROM parse_runs WHERE id=?", (acquisition.get("parse_run_id"),)).fetchone()
                    if selected is None:
                        _error("parser_approval_binding_invalid")
                    selected = _load(*selected)
                    if selected["artifact_id"] != artifact_id or selected["parser_artifact_digest"] != approval["data"]["manifest_digest"]:
                        _error("parser_approval_binding_invalid")
            for identity, in self.db.execute("SELECT id FROM objects"):
                self.get_object(identity)
            checks.append("object_and_acquisition_identity")
            _, unreferenced_blobs = self._blob_inventory()
            checks.append("blob_inventory")
        except (ProbentiumError, sqlite3.Error, OSError, KeyError, TypeError, ValueError) as exc:
            issues.append({"code": exc.code if isinstance(exc, ProbentiumError) else "stored_structure_invalid", "exit_code": 4})
        return {"ok": not issues, "checks": checks, "issues": issues, "revision": revision,
                "unreferenced_blobs": unreferenced_blobs, "authorized_unavailable": unavailable,
                "completeness": "partial" if unavailable else "acquired_bytes_present", "exit_code": 4 if issues else 3 if unavailable else 0,
                "limitations": ["hashes_do_not_authenticate_authorship", "parser_reexecution_not_performed", "external_whole_history_rewrite_not_detectable_without_trusted_snapshot"]}
