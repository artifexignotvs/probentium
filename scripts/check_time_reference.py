#!/usr/bin/env python3
"""Tempora ficta cum instrumento externo comparantur."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from testifex.timeutil import parse_time


def main():
    executable = shutil.which("date")
    if executable is None:
        raise SystemExit("GNU date is required for this optional reference check")
    version = subprocess.run([executable, "--version"], capture_output=True, text=True, check=False)
    if version.returncode != 0 or "GNU coreutils" not in version.stdout:
        raise SystemExit("GNU date is required for this optional reference check")
    timestamps = [
        "2026-01-01T00:00:00Z", "2026-01-01T01:30:00.125+01:30",
        "1960-01-01T00:00:00.250000Z", "2000-02-29T23:59:59.999999Z",
        "2038-01-19T03:14:08.123456Z", "2026-01-01T00:00:00.123456789Z",
        "2026-01-01T00:00:00-05:45", "2400-02-29T12:34:56.000001Z",
    ]
    results = []
    for timestamp in timestamps:
        output = subprocess.check_output([executable, "-u", "-d", timestamp, "+%s %N"], text=True).split()
        expected = int(output[0]) * 1000000 + int(output[1]) // 1000
        actual = parse_time(timestamp)["time_low_us"]
        results.append({"timestamp": timestamp, "reference_us": expected, "parsed_low_us": actual, "matches": expected == actual})
    result = {"schema": "testifex.time-reference.v1", "tool": version.stdout.splitlines()[0], "results": results,
              "scope": "UTC microsecond lower-bound conversion only; no artifact-parser validation or certification.",
              "ok": all(row["matches"] for row in results)}
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
