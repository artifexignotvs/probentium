"""Schema clausum; nullum tempus ex machina suppletur."""
import ipaddress
import re
from testifex import parsers
from testifex.timeutil import parse_time, TimeError, MIN_TIME_US, MAX_TIME_US
from .contracts import strict_json, ProbentiumError

FORMATS = (*parsers.FORMATS, "events-v2", "opaque")
VERSION = "probentium-adapters-2.1"
KINDS = {
    "auth.failure": {"service", "method", "reason"},
    "auth.success": {"service", "method"},
    "process.start": {"pid", "parent_pid", "executable", "command"},
    "process.command": {"pid", "parent_pid", "executable", "command"},
    "file.create": {"path", "digest_algorithm", "digest"},
    "file.modify": {"path", "digest_algorithm", "digest"},
    "file.delete": {"path", "digest_algorithm", "digest"},
    "network.connection": {"protocol", "local_ip", "remote_ip", "local_port", "remote_port", "direction"},
    "account.change": {"action", "target_account"},
}
REQUIRED_PAYLOAD = {
    "auth.failure": {"service"},
    "auth.success": {"service"},
    "process.start": {"pid", "executable"},
    "process.command": {"command"},
    "file.create": {"path"},
    "file.modify": {"path"},
    "file.delete": {"path"},
    "network.connection": {"protocol", "local_ip", "remote_ip", "local_port", "remote_port"},
    "account.change": {"action", "target_account"},
}


def _object(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise ProbentiumError("invalid_event_fields")
    return value


def _text(value):
    if value is not None and (not isinstance(value, str) or not value or len(value) > 4096):
        raise ProbentiumError("invalid_event_text")
    return value


def _ip(value):
    if value is not None:
        if not isinstance(value, str) or "%" in value:
            raise ProbentiumError("invalid_event_ip")
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ProbentiumError("invalid_event_ip") from exc
    return value


def parse_v2(raw):
    value = strict_json(raw, 1024 * 1024)
    _object(value, {"schema", "kind", "recorded_time", "origin", "host", "actor", "source_ip", "source_record_key", "payload", "timestamp_semantics"},
            {"schema", "kind", "recorded_time", "origin", "payload"})
    if value["schema"] != "testifex.events.v2":
        raise ProbentiumError("unsupported_event_schema", 7)
    kind = value["kind"]
    if not isinstance(kind, str) or kind not in KINDS:
        raise ProbentiumError("unsupported_event_kind", 7)
    # Clavis absens error est; null cognitio incerta manet.
    payload = _object(value["payload"], KINDS[kind], REQUIRED_PAYLOAD[kind])
    for key, item in payload.items():
        if key in {"pid", "parent_pid", "local_port", "remote_port"}:
            upper = 65535 if "port" in key else 2147483647
            if item is not None and (type(item) is not int or not 0 <= item <= upper):
                raise ProbentiumError("invalid_event_integer")
        elif key.endswith("_ip"):
            _ip(item)
        else:
            _text(item)
    if payload.get("direction") not in {None, "inbound", "outbound", "unknown"}:
        raise ProbentiumError("invalid_network_direction")
    if payload.get("digest_algorithm") is not None or payload.get("digest") is not None:
        sizes = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
        algorithm, digest = payload.get("digest_algorithm"), payload.get("digest")
        if algorithm not in sizes or not isinstance(digest, str) or not re.fullmatch("[a-f0-9]{%d}" % sizes[algorithm], digest):
            raise ProbentiumError("invalid_file_digest")
    origin = value["origin"]
    if origin is not None:
        _object(origin, {"export_tool", "export_version", "upstream_locator"}, {"export_tool", "export_version", "upstream_locator"})
        for item in origin.values():
            _text(item)
    for key in ("host", "actor", "source_record_key"):
        _text(value.get(key))
    _ip(value.get("source_ip"))
    semantics = value.get("timestamp_semantics", "unknown")
    if not isinstance(semantics, str) or semantics not in {"event_time", "log_write_time", "export_time", "unknown"}:
        raise ProbentiumError("invalid_timestamp_semantics")
    clock = value["recorded_time"]
    time = {"time_low_us": None, "time_high_us": None, "time_raw": None, "time_basis": "unknown"}
    if clock is not None:
        _object(clock, {"value", "encoding", "resolution_us"}, {"value", "encoding", "resolution_us"})
        resolution = clock["resolution_us"]
        if not isinstance(resolution, str) or not re.fullmatch(r"[1-9][0-9]{0,14}", resolution):
            raise ProbentiumError("invalid_recorded_resolution")
        if clock["encoding"] == "rfc3339":
            try:
                time = parse_time(clock["value"])
            except TimeError as exc:
                raise ProbentiumError(exc.code) from exc
        elif clock["encoding"] == "unix_us":
            if not isinstance(clock["value"], str) or not re.fullmatch(r"-?(0|[1-9][0-9]{0,17})", clock["value"]):
                raise ProbentiumError("invalid_recorded_timestamp")
            low = int(clock["value"])
            time = {"time_low_us": low, "time_high_us": low, "time_raw": clock["value"], "time_basis": "unix_microseconds"}
        else:
            raise ProbentiumError("unsupported_time_encoding", 7)
        time["time_high_us"] = time["time_low_us"] + max(int(resolution), time["time_high_us"] - time["time_low_us"] + 1) - 1
        if not MIN_TIME_US <= time["time_low_us"] <= time["time_high_us"] <= MAX_TIME_US:
            raise ProbentiumError("timestamp_out_of_range")
    return {**time, "kind": kind, "host": value.get("host"), "actor": value.get("actor"),
            "src_ip": value.get("source_ip"), "source_ip": value.get("source_ip"), "dst_ip": payload.get("remote_ip"),
            "path": payload.get("path") or payload.get("executable"), "action": payload.get("action"),
            "attributes": {}, "payload": payload, "origin": origin, "upstream_locator_status": "supplied_assertion",
            "source_record_key": value.get("source_record_key"), "timestamp_semantics": semantics}


def parse(raw, format_name, ordinal):
    if format_name == "opaque":
        return None
    if format_name == "events-v2":
        return parse_v2(raw)
    if format_name in ("events", "journal"):
        strict_json(raw, 1024 * 1024)
    if format_name not in parsers.FORMATS:
        raise ProbentiumError("unsupported_format", 7)
    return parsers.parse_line(raw, format_name, ordinal)


def formats():
    return {"schema": "probentium.formats.v1", "formats": [
        {"id": name, "explicit_selection_required": True, "max_record_bytes": 1048576,
         "opaque": name == "opaque", "schema": "testifex.events.v2" if name == "events-v2" else "legacy"}
        for name in FORMATS]}
