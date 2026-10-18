"""Consilium ante acquisitionem; cursor eandem revisionem tenet."""
import base64
import hashlib
import os
import platform
import shutil
from pathlib import Path

from testifex.safeio import regular_reader
from testifex.model import CaseError
from . import adapters, __version__
from . import limits as resource_limits
from .contracts import ProbentiumError, canonical_bytes, object_digest, strict_json, text_field
from .store import MAX_ARTIFACT, MAX_LINE
from .worker import ParserWorker

MAX_SAMPLE_BYTES = 8 * 1024 ** 2


def _fingerprint(path, resource_policy=None):
    policy = resource_limits.resolve(resource_policy, defaults={"max_source_bytes": MAX_ARTIFACT})
    try:
        with regular_reader(Path(path), policy["max_source_bytes"]) as (stream, _):
            digest, size = hashlib.sha256(), 0
            for chunk in iter(lambda: stream.read(1024 ** 2), b""):
                digest.update(chunk)
                size += len(chunk)
                if size > policy["max_source_bytes"]:
                    raise ProbentiumError("artifact_size_limit", 6)
            return digest.hexdigest(), size
    except CaseError as exc:
        limited = str(exc) == "input_size_limit"
        raise ProbentiumError("artifact_size_limit" if limited else "source_access_failed", 6 if limited else 4) from None


def inspect_file(path, *, format_name=None, sample_lines=100, resource_policy=None):
    policy = resource_limits.resolve(resource_policy, defaults={"max_source_bytes": MAX_ARTIFACT})
    if type(sample_lines) is not int or not 1 <= sample_lines <= 1000:
        raise ProbentiumError("invalid_sample_limit")
    if format_name is not None and format_name not in adapters.FORMATS:
        raise ProbentiumError("format_unsupported", 7)
    try:
        with regular_reader(Path(path), policy["max_source_bytes"]) as (stream, _):
            size = os.fstat(stream.fileno()).st_size
            samples, consumed = [], 0
            for _ in range(sample_lines):
                raw = stream.readline(MAX_LINE + 1)
                if not raw:
                    break
                consumed += len(raw)
                if consumed > MAX_SAMPLE_BYTES:
                    raise ProbentiumError("sample_byte_limit", 6)
                if len(raw) > MAX_LINE:
                    raise ProbentiumError("sample_line_limit", 6)
                samples.append(raw)
    except CaseError as exc:
        limited = str(exc) == "input_size_limit"
        raise ProbentiumError("artifact_size_limit" if limited else "source_access_failed", 6 if limited else 4) from None
    formats = [format_name] if format_name else [f for f in adapters.FORMATS if f != "opaque"]
    candidates = []
    with ParserWorker(size, resource_policy=policy) as worker:
        for name in formats:
            parsed = malformed = unsupported = blank = 0
            for ordinal, raw in enumerate(samples, 1):
                if not raw.strip():
                    blank += 1
                    continue
                try:
                    event = worker.parse(raw, name, ordinal)
                    if event is None:
                        unsupported += 1
                    else:
                        parsed += 1
                except ProbentiumError as exc:
                    if exc.exit_code not in (2, 7):
                        raise
                    if exc.exit_code == 7:
                        unsupported += 1
                    else:
                        malformed += 1
            candidates.append({"format": name, "parsed": parsed, "malformed": malformed,
                               "unsupported": unsupported, "blank": blank})
    return {"schema": "probentium.inspect.v1", "size": size, "sampled_lines": len(samples),
            "sampled_bytes": consumed, "sample_only": consumed < size,
            "candidates": candidates, "format_requires_explicit_selection": True,
            "resource_policy": policy, "resource_policy_digest": resource_limits.digest(policy)}


def batch_plan(entries, *, resource_policy=None):
    policy = resource_limits.resolve(resource_policy, defaults={"max_source_bytes": MAX_ARTIFACT})
    if not isinstance(entries, list) or not 1 <= len(entries) <= 1000:
        raise ProbentiumError("invalid_batch_entries")
    planned = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "format", "label"}:
            raise ProbentiumError("invalid_batch_entry")
        if entry["format"] not in adapters.FORMATS:
            raise ProbentiumError("format_unsupported", 7)
        text_field(entry["label"])
        if not isinstance(entry["path"], str) or not entry["path"]:
            raise ProbentiumError("invalid_batch_path")
        identity, size = _fingerprint(entry["path"], policy)
        planned.append({**entry, "path": str(Path(entry["path"]).absolute()), "sha256": identity, "size": size})
    value = {"schema": "probentium.batch-plan.v1", "entries": planned,
             **({"resource_policy": policy} if resource_policy is not None else {})}
    return {**value, "digest": object_digest(value)}


def execute_batch(case, plan, *, expected_revision=None):
    if not isinstance(plan, dict) or set(plan) not in ({"schema", "entries", "digest"}, {"schema", "entries", "digest", "resource_policy"}) or plan["schema"] != "probentium.batch-plan.v1":
        raise ProbentiumError("invalid_batch_plan")
    if object_digest({k: v for k, v in plan.items() if k != "digest"}) != plan["digest"]:
        raise ProbentiumError("batch_plan_digest_mismatch", 4)
    policy = case.resource_policy
    if "resource_policy" in plan and resource_limits.validate(plan["resource_policy"]) != policy:
        raise ProbentiumError("batch_resource_policy_mismatch", 5)
    entries = plan["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 1000:
        raise ProbentiumError("invalid_batch_entries")
    case._expect(expected_revision)
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "format", "label", "sha256", "size"}:
            raise ProbentiumError("invalid_batch_entry")
        if _fingerprint(entry["path"], policy) != (entry["sha256"], entry["size"]):
            raise ProbentiumError("batch_source_changed", 4)
    completed = []
    for entry in entries:
        result = case.ingest(entry["path"], entry["format"], entry["label"], expected_revision=case.revision,
                             expected_sha256=entry["sha256"])
        completed.append({"artifact_id": result["id"], "parse_run_id": result["parse_run_id"], "state": result["state"]})
    return {"schema": "probentium.batch-result.v1", "plan_digest": plan["digest"], "completed": completed,
            "revision": case.revision, "atomicity": "per_artifact_with_checkpoints",
            "resource_policy": policy, "resource_policy_digest": resource_limits.digest(policy)}


def timeline_page(case, *, query="", limit=100, cursor=None):
    last_sort_key = None
    query_digest = object_digest({"query": query, "case_id": case.meta["case_id"]})
    if cursor is not None:
        if not isinstance(cursor, str) or len(cursor) > 1024:
            raise ProbentiumError("invalid_cursor")
        try:
            raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
            value = strict_json(raw, 1024)
        except (ValueError, TypeError):
            raise ProbentiumError("invalid_cursor") from None
        if (not isinstance(value, dict) or set(value) != {"version", "revision", "query_digest", "last_sort_key"}
                or type(value["version"]) is not int or value["version"] != 1
                or canonical_bytes(value) != raw or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != cursor):
            raise ProbentiumError("invalid_cursor")
        if value["query_digest"] != query_digest:
            raise ProbentiumError("cursor_query_mismatch")
        case._expect(value["revision"])
        last_sort_key = value["last_sort_key"]
    page = case.query_after(query=query, limit=limit, last_sort_key=last_sort_key)
    next_offset = page["offset"] + len(page["rows"])
    last = page["rows"][-1] if page["rows"] else None
    next_value = {"version": 1, "revision": case.revision, "query_digest": query_digest,
                  "last_sort_key": [last["time_low_us"] is None, last["time_low_us"], last["time_high_us"], last["id"]] if last else None}
    page["next_cursor"] = base64.urlsafe_b64encode(canonical_bytes(next_value)).rstrip(b"=").decode() if next_offset < page["total"] else None
    return page


def doctor():
    from importlib.metadata import version
    from .budgets import capabilities
    dependencies = {name: version(name) for name in ("rfc8785", "cryptography")}
    return {"schema": "probentium.doctor.v1", "version": __version__, "python": platform.python_version(),
            "platform": platform.system(), "dependencies": dependencies,
            "parser_process_isolation": True, "strict_resource_limits": platform.system() == "Linux",
            "analysis_resources": capabilities(),
            "parser_network_sandbox": False, "age_available": shutil.which("age") is not None,
            "offline_operation": True, "telemetry": False, "legal_profiles_verified": False}
