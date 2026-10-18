"""Species novem, claves necessariae et ignorantia explicita probantur."""
import copy
import json
import unittest

from probentium import adapters
from probentium.contracts import ProbentiumError
from testifex.timeutil import MAX_TIME_US, MIN_TIME_US


PAYLOADS = {
    "auth.failure": {"service": "ssh", "method": "publickey", "reason": "Unknown key"},
    "auth.success": {"service": "ssh", "method": "publickey"},
    "process.start": {"pid": 41, "parent_pid": 1, "executable": "/usr/bin/example", "command": "example --check"},
    "process.command": {"command": "example --check", "pid": 42, "parent_pid": 41, "executable": "/usr/bin/example"},
    "file.create": {"path": "/synthetic/new.txt", "digest_algorithm": "sha256", "digest": "a" * 64},
    "file.modify": {"path": "/synthetic/changed.txt"},
    "file.delete": {"path": "/synthetic/deleted.txt"},
    "network.connection": {"protocol": "tcp", "local_ip": "192.0.2.10", "remote_ip": "2001:db8::20",
                           "local_port": 42000, "remote_port": 443, "direction": "outbound"},
    "account.change": {"action": "disable", "target_account": "synthetic-account"},
}
REQUIRED = {
    "auth.failure": ("service",), "auth.success": ("service",),
    "process.start": ("pid", "executable"), "process.command": ("command",),
    "file.create": ("path",), "file.modify": ("path",), "file.delete": ("path",),
    "network.connection": ("protocol", "local_ip", "remote_ip", "local_port", "remote_port"),
    "account.change": ("action", "target_account"),
}


def event(kind="auth.success", payload=None):
    return {"schema": "testifex.events.v2", "kind": kind, "recorded_time": None,
            "origin": None, "payload": copy.deepcopy(PAYLOADS[kind] if payload is None else payload)}


def wire(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")


def valid_fixtures():
    rows = []
    for kind, payload in PAYLOADS.items():
        rows.append((kind + "/complete", event(kind)))
        rows.append((kind + "/minimal", event(kind, {key: payload[key] for key in REQUIRED[kind]})))
        rows.append((kind + "/unknown", event(kind, {key: None for key in REQUIRED[kind]})))
        rows.append((kind + "/all-null", event(kind, dict.fromkeys(payload))))
    enriched = event()
    enriched.update({"host": "synthetic-host", "actor": "synthetic-account", "source_ip": "198.51.100.13",
                     "source_record_key": "row-7", "timestamp_semantics": "log_write_time",
                     "origin": {"export_tool": "synthetic-export", "export_version": "1", "upstream_locator": "row:7"}})
    rows.append(("top-level/all-optional", enriched))
    unknown = event()
    unknown.update(dict.fromkeys(("host", "actor", "source_ip", "source_record_key")))
    unknown["origin"] = dict.fromkeys(("export_tool", "export_version", "upstream_locator"))
    rows.append(("top-level/optional-null", unknown))
    for encoding, value in (("rfc3339", "2026-10-18T12:00:00.1234567Z"), ("rfc3339", "2026-10-18t14:00:00+02:00"),
                            ("unix_us", "9007199254740992"), ("unix_us", "-1"), ("unix_us", str(MIN_TIME_US)),
                            ("unix_us", str(MAX_TIME_US))):
        row = event()
        row["recorded_time"] = {"encoding": encoding, "value": value, "resolution_us": "1"}
        rows.append(("time/" + encoding + "/" + value, row))
    for key in ("pid", "parent_pid"):
        for value in (0, 2147483647):
            row = event("process.start")
            row["payload"][key] = value
            rows.append(("pid/" + key + "/" + str(value), row))
    for key in ("local_port", "remote_port"):
        for value in (0, 65535):
            row = event("network.connection")
            row["payload"][key] = value
            rows.append(("port/" + key + "/" + str(value), row))
    for algorithm, size in (("md5", 32), ("sha1", 40), ("sha256", 64), ("sha512", 128)):
        rows.append(("digest/" + algorithm, event("file.modify", {"path": None, "digest_algorithm": algorithm, "digest": "a" * size})))
    row = event("process.command", {"command": "x" * 4096})
    rows.append(("text/exact-length", row))
    return rows


def invalid_fixtures():
    rows = []
    for kind in PAYLOADS:
        for key in REQUIRED[kind]:
            absent = event(kind)
            del absent["payload"][key]
            rows.append((kind + "/absent/" + key, absent))
            wrong_type = event(kind)
            wrong_type["payload"][key] = {}
            rows.append((kind + "/wrong-type/" + key, wrong_type))
        extra = event(kind)
        extra["payload"]["unexpected"] = None
        rows.append((kind + "/unknown-key", extra))
    for key in ("schema", "kind", "recorded_time", "origin", "payload"):
        row = event()
        del row[key]
        rows.append(("top-level/absent/" + key, row))
    for key, values in {
        "schema": (None, "testifex.events.v99", [], True), "kind": (None, "auth.other", [], 1),
        "payload": (None, [], "ssh", True), "origin": ([], True, "tool", {}),
        "recorded_time": ([], True, "2026-10-18T12:00:00Z", {}),
        "host": (True, {}, "", "x" * 4097), "actor": (0, [], ""),
        "source_record_key": (False, {}, ""), "source_ip": (True, "host.example", "192.0.2.300", "fe80::1%eth0"),
        "timestamp_semantics": (None, [], {}, True, "acquisition_time"),
    }.items():
        for index, value in enumerate(values):
            row = event()
            row[key] = value
            rows.append(("top-level/type-or-value/" + key + "/" + str(index), row))
    row = event()
    row["unexpected"] = None
    rows.append(("top-level/unknown-key", row))
    for key in ("export_tool", "export_version", "upstream_locator"):
        row = event()
        row["origin"] = dict.fromkeys(("export_tool", "export_version", "upstream_locator"))
        del row["origin"][key]
        rows.append(("origin/absent/" + key, row))
        row = event()
        row["origin"] = dict.fromkeys(("export_tool", "export_version", "upstream_locator"))
        row["origin"][key] = 7
        rows.append(("origin/wrong-type/" + key, row))
    row = event()
    row["origin"] = dict.fromkeys(("export_tool", "export_version", "upstream_locator", "unexpected"))
    rows.append(("origin/unknown-key", row))
    for kind, key, values in (
        ("process.start", "pid", (-1, 2147483648, True, "1", 1.5)),
        ("process.command", "parent_pid", (-1, 2147483648, False, "1")),
        ("network.connection", "local_port", (-1, 65536, True, "443", 1.5)),
        ("network.connection", "remote_port", (-1, 65536, False, "443")),
        ("network.connection", "local_ip", ("256.0.0.1", "192.168.001.1", "fe80::1%lo", "hostname", 7)),
        ("network.connection", "remote_ip", ("2001:db8:::1", "", "192.0.2.1/24", False)),
        ("network.connection", "direction", ("sideways", True, [])),
        ("network.connection", "protocol", ("", 6)),
        ("auth.failure", "reason", (False, "", "x" * 4097)),
        ("process.command", "command", (False, "", "x" * 4097)),
    ):
        for index, value in enumerate(values):
            row = event(kind)
            row["payload"][key] = value
            rows.append((kind + "/boundary/" + key + "/" + str(index), row))
    for index, additions in enumerate((
        {"digest_algorithm": "sha256"}, {"digest": "a" * 64},
        {"digest_algorithm": "sha256", "digest": None}, {"digest_algorithm": None, "digest": "a" * 64},
        {"digest_algorithm": "sha256", "digest": "A" * 64}, {"digest_algorithm": "sha256", "digest": "a" * 63},
        {"digest_algorithm": "sha256", "digest": "a" * 65}, {"digest_algorithm": "crc32", "digest": "aaaaaaaa"},
        {"digest_algorithm": "sha256", "digest": "a" * 64 + "\n"},
    )):
        rows.append(("digest/invalid/" + str(index), event("file.create", {"path": None, **additions})))
    for key, values in {
        "encoding": (None, "unix_ms", [], 1), "resolution_us": (None, 1, "0", "01", "-1", "1.5", "1000000000000000", "1\n"),
        "value": (None, 1, [], "2026-10-18T12:00:00", "2026-10-18T12:00:00-00:00", "2026-10-18T12:00:00Z\n"),
    }.items():
        for index, value in enumerate(values):
            row = event()
            row["recorded_time"] = {"encoding": "rfc3339", "value": "2026-10-18T12:00:00Z", "resolution_us": "1"}
            row["recorded_time"][key] = value
            rows.append(("time/invalid/" + key + "/" + str(index), row))
    for key in ("encoding", "value", "resolution_us"):
        row = event()
        row["recorded_time"] = {"encoding": "unix_us", "value": "0", "resolution_us": "1"}
        del row["recorded_time"][key]
        rows.append(("time/absent/" + key, row))
    row = event()
    row["recorded_time"] = {"encoding": "unix_us", "value": "0", "resolution_us": "1", "unexpected": None}
    rows.append(("time/unknown-key", row))
    for value in ("01", "+1", "1.0", "1e3", "-01", "1000000000000000000", "0\n"):
        row = event()
        row["recorded_time"] = {"encoding": "unix_us", "value": value, "resolution_us": "1"}
        rows.append(("time/unix-syntax/" + value, row))
    return rows


def runtime_only_invalid_fixtures():
    rows = []
    for value in ("2026-02-30T00:00:00Z", "0000-01-01T00:00:00Z"):
        row = event()
        row["recorded_time"] = {"encoding": "rfc3339", "value": value, "resolution_us": "1"}
        rows.append(("calendar/" + value, wire(row)))
    for value, resolution in ((str(MAX_TIME_US + 1), "1"), (str(MIN_TIME_US - 1), "1"), (str(MAX_TIME_US), "2")):
        row = event()
        row["recorded_time"] = {"encoding": "unix_us", "value": value, "resolution_us": resolution}
        rows.append(("time/representable-interval/" + value + "/" + resolution, wire(row)))
    row = event("process.start")
    row["payload"]["pid"] = 1.0
    rows.append(("wire/floating-point-integer", wire(row)))
    rows.append(("wire/duplicate-key", wire(event()).replace(b'"service":"ssh"', b'"service":"ssh","service":null')))
    rows.append(("wire/invalid-utf8", wire(event()).replace(b"ssh", b"\xff")))
    return rows


class AdaptersV2Tests(unittest.TestCase):
    def test_all_valid_fixtures_preserve_declared_payload(self):
        for name, value in valid_fixtures():
            with self.subTest(name=name):
                result = adapters.parse_v2(wire(value))
                self.assertEqual(result["kind"], value["kind"])
                self.assertEqual(result["payload"], value["payload"])
                self.assertEqual(result["origin"], value["origin"])

    def test_all_structural_invalid_fixtures_fail_safely(self):
        for name, value in invalid_fixtures():
            with self.subTest(name=name):
                with self.assertRaises(ProbentiumError):
                    adapters.parse_v2(wire(value))

    def test_runtime_semantic_and_wire_limits_are_enforced(self):
        for name, raw in runtime_only_invalid_fixtures():
            with self.subTest(name=name):
                with self.assertRaises(ProbentiumError):
                    adapters.parse_v2(raw)

    def test_unknown_values_remain_unknown_and_absence_is_not_imputed(self):
        for kind, keys in REQUIRED.items():
            with self.subTest(kind=kind):
                payload = dict.fromkeys(keys)
                result = adapters.parse(wire(event(kind, payload)), "events-v2", 1)
                self.assertEqual(result["payload"], payload)
                self.assertIsNone(result["time_low_us"])
                self.assertIsNone(result["time_high_us"])
                self.assertIsNone(result["origin"])
                self.assertEqual(result["timestamp_semantics"], "unknown")
                self.assertEqual(result["upstream_locator_status"], "supplied_assertion")

    def test_unsupported_kind_and_version_have_specific_diagnostics(self):
        for key, value, code in (("kind", "auth.other", "unsupported_event_kind"),
                                 ("schema", "testifex.events.v99", "unsupported_event_schema")):
            row = event()
            row[key] = value
            with self.subTest(key=key), self.assertRaises(ProbentiumError) as caught:
                adapters.parse_v2(wire(row))
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.exit_code, 7)

    def test_resolution_encloses_input_precision_without_float_rounding(self):
        row = event()
        row["recorded_time"] = {"encoding": "unix_us", "value": "9007199254740992", "resolution_us": "1000"}
        result = adapters.parse_v2(wire(row))
        self.assertEqual(result["time_low_us"], 9007199254740992)
        self.assertEqual(result["time_high_us"], 9007199254741991)
        row["recorded_time"] = {"encoding": "rfc3339", "value": "2026-10-18T12:00:00Z", "resolution_us": "1"}
        result = adapters.parse_v2(wire(row))
        self.assertEqual(result["time_high_us"] - result["time_low_us"] + 1, 1000000)

    def test_registry_preserves_explicit_selection_and_version(self):
        self.assertEqual(adapters.VERSION, "probentium-adapters-2.1")
        row = next(item for item in adapters.formats()["formats"] if item["id"] == "events-v2")
        self.assertEqual(row["schema"], "testifex.events.v2")
        self.assertEqual(row["max_record_bytes"], 1048576)
        self.assertTrue(row["explicit_selection_required"])
        self.assertFalse(row["opaque"])
        with self.assertRaisesRegex(ProbentiumError, "unsupported_format") as caught:
            adapters.parse(wire(event()), "events-v3", 1)
        self.assertEqual(caught.exception.exit_code, 7)


if __name__ == "__main__":
    unittest.main()
