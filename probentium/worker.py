"""Processus finitus, ambitus secretorum non hereditatur."""
import base64
import os
import selectors
import struct
import subprocess
import sys
import tempfile
import time

from .contracts import canonical_bytes, strict_json, ProbentiumError
from . import limits as resource_limits

MAX_FRAME = 1024 * 1024

# Codices clausi cum exitu certo: processus alienus verba sua non transmittit.
_ERROR_EXITS = {
    **dict.fromkeys((
        "attributes_unsupported", "auth_header_unsupported", "auth_message_unsupported", "auth_method_unsupported",
        "duplicate_json_key", "event_fields_invalid", "event_kind_unsupported", "floating_point_not_supported",
        "format_unsupported", "input_bytes_required", "integer_out_of_range", "invalid_boot_id", "invalid_canonical_value",
        "invalid_event_fields", "invalid_event_integer", "invalid_event_ip", "invalid_event_text", "invalid_file_digest",
        "invalid_host", "invalid_integer", "invalid_ip", "invalid_json", "invalid_network_direction",
        "invalid_recorded_resolution", "invalid_recorded_timestamp", "invalid_text", "invalid_timestamp_semantics",
        "invalid_utf8", "invalid_worker_request", "journal_message_missing", "journal_message_unsupported",
        "journal_timestamp_invalid", "json_depth_limit", "json_duplicate_key", "json_float_unsupported", "json_nonfinite",
        "json_object_required", "json_structure_limit", "line_limit", "multiple_lines", "ordinal_invalid",
        "sudo_command_invalid", "sudo_message_unsupported", "text_limit", "timestamp_invalid", "timestamp_out_of_range",
        "timestamp_timezone_unknown", "timestamp_too_long", "unsupported_value_type",
    ), 2),
    "input_size_limit": 6, "worker_message_limit": 6,
    "unsupported_event_schema": 7, "unsupported_event_kind": 7, "unsupported_format": 7, "unsupported_time_encoding": 7,
}


def _limits(cpu):
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 ** 2, 512 * 1024 ** 2))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def require_strict_platform():
    if not sys.platform.startswith("linux"):
        raise ProbentiumError("strict_resource_mode_unsupported", 7)


class ParserWorker:
    def __init__(self, source_size=0, wall_seconds=900, strict=True, resource_policy=None):
        policy = resource_limits.resolve(resource_policy)
        if type(source_size) is not int or not 0 <= source_size <= policy["max_source_bytes"]:
            raise ProbentiumError("parser_source_size_limit", 6)
        if strict:
            require_strict_platform()
        self.directory = tempfile.TemporaryDirectory(prefix="probentium-parser-")
        self.deadline = time.monotonic() + wall_seconds
        cpu = max(120, min(900, ((source_size + 100 * 1024 ** 2 - 1) // (100 * 1024 ** 2)) * 120))
        try:
            self.process = subprocess.Popen([sys.executable, "-I", "-B", "-X", "pycache_prefix=" + os.path.join(self.directory.name, "bytecode"),
                                             "-m", "probentium.worker", "--child", str(cpu)],
                                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                            cwd=self.directory.name, env={"PATH": os.defpath, "LC_ALL": "C.UTF-8"},
                                            close_fds=True)
            os.set_blocking(self.process.stdin.fileno(), False)
            os.set_blocking(self.process.stdout.fileno(), False)
        except BaseException:
            self.directory.cleanup()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if getattr(self, "process", None):
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
            self.process.stdin.close()
            self.process.stdout.close()
        self.directory.cleanup()

    def _transfer(self, fd, data=None, count=None):
        result, offset = bytearray(), 0
        with selectors.DefaultSelector() as selector:
            selector.register(fd, selectors.EVENT_WRITE if data is not None else selectors.EVENT_READ)
            while offset < (len(data) if data is not None else count):
                remaining = self.deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ProbentiumError("parser_timeout", 6)
                try:
                    if data is not None:
                        size = os.write(fd, data[offset:])
                    else:
                        chunk = os.read(fd, count - offset)
                        size = len(chunk)
                        result.extend(chunk)
                except BlockingIOError:
                    continue
                except (BrokenPipeError, OSError) as exc:
                    raise ProbentiumError("parser_process_failed", 6) from exc
                if not size:
                    raise ProbentiumError("parser_process_failed", 6)
                offset += size
        return bytes(result)

    def request(self, value):
        raw = canonical_bytes(value)
        if len(raw) > MAX_FRAME:
            raise ProbentiumError("worker_message_limit", 6)
        self._transfer(self.process.stdin.fileno(), struct.pack(">I", len(raw)) + raw)
        size = struct.unpack(">I", self._transfer(self.process.stdout.fileno(), count=4))[0]
        if not 0 < size <= MAX_FRAME:
            raise ProbentiumError("worker_message_limit", 6)
        response = strict_json(self._transfer(self.process.stdout.fileno(), count=size), MAX_FRAME)
        if not isinstance(response, dict) or set(response) not in ({"event"}, {"error", "exit_code"}, {"ack"}):
            raise ProbentiumError("invalid_worker_protocol", 4)
        if "error" in response:
            code = response["error"]
            if not isinstance(code, str) or not code.isascii() or len(code) > 64 or code not in _ERROR_EXITS:
                raise ProbentiumError("invalid_worker_protocol", 4)
            if type(response["exit_code"]) is not int or response["exit_code"] != _ERROR_EXITS[code]:
                raise ProbentiumError("invalid_worker_protocol", 4)
            raise ProbentiumError(code, response["exit_code"])
        return response

    def parse(self, raw, format_name, ordinal):
        if len(raw) <= 512 * 1024:
            request = {"op": "parse", "format": format_name, "ordinal": ordinal, "raw": base64.b64encode(raw).decode("ascii")}
        else:
            self.request({"op": "start"})
            for offset in range(0, len(raw), 512 * 1024):
                self.request({"op": "append", "raw": base64.b64encode(raw[offset:offset + 512 * 1024]).decode("ascii")})
            request = {"op": "finish", "format": format_name, "ordinal": ordinal}
        response = self.request(request)
        if "event" not in response:
            raise ProbentiumError("invalid_worker_protocol", 4)
        event = response["event"]
        if event is not None:
            if not isinstance(event, dict) or not {"kind", "host", "actor", "attributes", "time_low_us", "time_high_us"} <= set(event):
                raise ProbentiumError("invalid_worker_protocol", 4)
            if not isinstance(event["attributes"], dict) or not isinstance(event["kind"], str):
                raise ProbentiumError("invalid_worker_protocol", 4)
            for key in ("time_low_us", "time_high_us"):
                value = event[key]
                if value is not None and (not isinstance(value, str) or len(value) > 19 or not value.lstrip("-").isdigit()):
                    raise ProbentiumError("invalid_worker_protocol", 4)
                event[key] = int(value) if value is not None else None
            if ((event["time_low_us"] is None) != (event["time_high_us"] is None)
                    or (event["time_low_us"] is not None and event["time_low_us"] > event["time_high_us"])):
                raise ProbentiumError("invalid_worker_protocol", 4)
        return event


def child(cpu):
    _limits(cpu)
    from . import adapters
    from testifex.parsers import ParseError
    buffered = bytearray()
    while True:
        header = sys.stdin.buffer.read(4)
        if not header:
            return
        if len(header) != 4:
            return
        size = struct.unpack(">I", header)[0]
        if not 0 < size <= MAX_FRAME:
            return
        raw_request = sys.stdin.buffer.read(size)
        if len(raw_request) != size:
            return
        try:
            request = strict_json(raw_request, MAX_FRAME)
            op = request["op"]
            if op == "start" and set(request) == {"op"}:
                buffered.clear()
                response = {"ack": True}
            elif op == "append" and set(request) == {"op", "raw"}:
                buffered.extend(base64.b64decode(request["raw"], validate=True))
                if len(buffered) > MAX_FRAME:
                    raise ProbentiumError("line_limit")
                response = {"ack": True}
            elif op in {"parse", "finish"}:
                expected = {"op", "format", "ordinal"} | ({"raw"} if op == "parse" else set())
                if set(request) != expected or type(request["ordinal"]) is not int or request["ordinal"] < 1:
                    raise ProbentiumError("invalid_worker_request")
                raw = base64.b64decode(request["raw"], validate=True) if op == "parse" else bytes(buffered)
                buffered.clear()
                if len(raw) > MAX_FRAME:
                    raise ProbentiumError("line_limit")
                event = adapters.parse(raw, request["format"], request["ordinal"])
                if event is not None:
                    event = dict(event)
                    for key in ("time_low_us", "time_high_us"):
                        event[key] = str(event[key]) if event[key] is not None else None
                response = {"event": event}
            else:
                raise ProbentiumError("invalid_worker_request")
        except (ProbentiumError, ParseError) as exc:
            response = {"error": exc.code, "exit_code": exc.exit_code if isinstance(exc, ProbentiumError) and exc.code != "json_depth_limit" else 2}
        except (ValueError, TypeError, KeyError):
            response = {"error": "invalid_worker_request", "exit_code": 2}
        raw_response = canonical_bytes(response)
        if len(raw_response) > MAX_FRAME:
            raw_response = b'{"error":"worker_message_limit","exit_code":6}'
        sys.stdout.buffer.write(struct.pack(">I", len(raw_response)) + raw_response)
        sys.stdout.buffer.flush()


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "--child":
    child(int(sys.argv[2]))
