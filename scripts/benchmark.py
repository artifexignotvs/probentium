#!/usr/bin/env python3
"""Mensura repetibilis, non promissum universale."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
MAX_EVENTS = 100000
GROUP_PERIOD = 1000
SCHEMA = "testifex.benchmark.v1"


def rss_measurement():
    """Unitates systematis manifeste convertuntur."""
    try:
        import resource
        raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (ImportError, OSError):
        return {"peak_rss_bytes": None, "rss_source": "unavailable", "rss_native_unit": "unknown"}
    if sys.platform == "darwin":
        multiplier, unit = 1, "bytes"
    elif sys.platform.startswith("linux"):
        multiplier, unit = 1024, "KiB"
    else:
        return {"peak_rss_bytes": None, "rss_source": "resource.ru_maxrss", "rss_native_value": raw, "rss_native_unit": "unverified"}
    return {"peak_rss_bytes": int(raw * multiplier), "rss_source": "resource.ru_maxrss", "rss_native_value": raw, "rss_native_unit": unit}


def dataset(path, count):
    """Exempla ficta parva inter eventus communes inseruntur."""
    epoch = datetime(2026, 1, 1, tzinfo=timezone.utc)
    digest = hashlib.sha256()
    groups = 0
    kinds = {"generic": 0, "auth.failure": 0, "auth.success": 0, "process.exec": 0}
    with path.open("xb") as stream:
        for index in range(count):
            position, group = index % GROUP_PERIOD, index // GROUP_PERIOD
            stamp = (epoch + timedelta(seconds=index)).strftime("%Y-%m-%dT%H:%M:%SZ")
            event = {"timestamp": stamp, "kind": "generic"}
            if position < 8:
                event.update(host=f"host-demo-{group:03d}", actor=f"operator-demo-{group:03d}")
                if position < 6:
                    event.update(kind="auth.failure", src_ip="192.0.2.10")
                elif position == 6:
                    event.update(kind="auth.success", src_ip="192.0.2.10")
                else:
                    event.update(kind="process.exec", path="/usr/bin/id")
                    groups += 1
            kinds[event["kind"]] += 1
            line = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            digest.update(line)
            stream.write(line)
    return {"generator_version": "1", "events": count, "format": "events", "sha256": digest.hexdigest(),
            "bytes": path.stat().st_size, "kinds": kinds, "complete_groups": groups,
            "expected_findings": kinds["auth.success"] + kinds["process.exec"],
            "group_period_rows": GROUP_PERIOD,
            "description": "Six authentication failures, one success and one process record per sparse group; other records are generic. All data is synthetic."}


def implementation():
    """Versio et digestum fontis contextum mensurae servant."""
    from testifex import __version__
    digest = hashlib.sha256()
    for path in sorted((ROOT / "testifex").rglob("*.py")):
        digest.update(path.relative_to(ROOT).as_posix().encode("utf-8") + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return {"version": __version__, "source_tree_sha256": digest.hexdigest(),
            "fingerprint_method": "SHA-256 over sorted relative Python source paths and bytes, each followed by NUL"}


def environment(directory):
    cpu_model = "unavailable"
    if sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith("model name"):
                    cpu_model = line.split(":", 1)[1].strip()
                    break
        except OSError:
            pass
    elif sys.platform == "darwin":
        try:
            cpu_model = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True, timeout=5, stderr=subprocess.DEVNULL).strip()
        except (OSError, subprocess.SubprocessError):
            pass
    cpu_model = "".join(c for c in cpu_model if c.isprintable())[:256]
    filesystem = {"type": "unknown", "temporary_directory": True, "cache": "not flushed; later phases may use warm filesystem cache"}
    try:
        info = os.statvfs(directory)
        filesystem["block_size_bytes"] = info.f_frsize
    except (AttributeError, OSError):
        pass
    if sys.platform.startswith("linux"):
        try:
            best = 0
            for line in Path("/proc/self/mountinfo").read_text().splitlines():
                left, right = line.split(" - ", 1)
                mount = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), left.split()[4])
                if directory.is_relative_to(Path(mount)) and len(mount) >= best:
                    filesystem["type"], best = right.split()[0], len(mount)
        except (OSError, ValueError, IndexError):
            pass
    result = {"python_version": platform.python_version(), "python_implementation": platform.python_implementation(),
              "system": platform.system(), "release": platform.release(), "machine": platform.machine(),
              "cpu_model": cpu_model, "logical_cpus": os.cpu_count(), "filesystem": filesystem,
              "process_model": "Each measured phase runs in a new child process; peak RSS includes that process's imports and retained case state.",
              "wall_time_scope": "Case open/create, operation and case close; interpreter startup and input generation are excluded."}
    if hasattr(os, "sched_getaffinity"):
        result["available_cpu_affinity_count"] = len(os.sched_getaffinity(0))
    for file, field in (("/sys/fs/cgroup/memory.max", "cgroup_memory_limit_bytes"), ("/sys/fs/cgroup/cpu.max", "cgroup_cpu_quota")):
        try:
            value = Path(file).read_text().strip().split()
            if field == "cgroup_cpu_quota":
                result[field] = {"quota_us": None if value[0] == "max" else int(value[0]), "period_us": int(value[1])}
            else:
                result[field] = None if value[0] == "max" else int(value[0])
        except (OSError, ValueError, IndexError):
            pass
    return result


def worker(phase, directory, count):
    from testifex.case import Case
    from testifex.analysis import analyze
    started = time.perf_counter()
    result = {"status": "complete"}
    try:
        if phase == "ingest":
            with Case.create(directory / "case", "Synthetic benchmark") as case:
                source = case.ingest(directory / "input.jsonl", "events", "Synthetic dataset", max_records=count)
                result.update(parsed_events=source["parsed_count"], ignored_records=source["ignored_count"], error_records=source["error_count"])
                if source["status"] != "complete" or source["parsed_count"] != count:
                    raise ValueError("unexpected_ingest_result")
        elif phase == "analyze":
            with Case(directory / "case") as case:
                analysis = analyze(case.events(), case.sources(), window_us=300000000, threshold=5, max_events=count)
                result.update(events_analyzed=analysis["coverage"]["event_count"], findings=len(analysis["findings"]))
        elif phase == "verify":
            with Case(directory / "case") as case:
                verification = case.verify()
                result.update(verified=verification["ok"], events_checked=verification["events_checked"])
                if not verification["ok"] or verification["events_checked"] != count:
                    raise ValueError("unexpected_verification_result")
        else:
            raise ValueError("unknown_phase")
    except Exception as exc:
        code = str(exc)
        result.update(status="failed", error=code if re.fullmatch(r"[a-z0-9_]{1,120}", code) else "operation_failed")
    result["wall_seconds"] = round(time.perf_counter() - started, 6)
    result.update(rss_measurement())
    print(json.dumps(result, sort_keys=True))


def run_phase(phase, directory, count, timeout):
    try:
        completed = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--worker", phase,
                                    "--directory", str(directory), "--events", str(count)],
                                   capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "timeout_seconds": timeout, "wall_seconds": None, "peak_rss_bytes": None}
    if completed.returncode != 0:
        return {"status": "failed", "error": "worker_failed", "exit_code": completed.returncode, "wall_seconds": None, "peak_rss_bytes": None}
    try:
        return json.loads(completed.stdout)
    except (ValueError, UnicodeError):
        return {"status": "failed", "error": "invalid_worker_result", "wall_seconds": None, "peak_rss_bytes": None}


def benchmark(count, timeout):
    before = implementation()
    with tempfile.TemporaryDirectory(prefix="testifex-benchmark-") as temporary:
        directory = Path(temporary).resolve()
        inputs = dataset(directory / "input.jsonl", count)
        conditions = environment(directory)
        phases = {}
        for phase in ("ingest", "analyze", "verify"):
            if phase != "ingest" and phases["ingest"]["status"] != "complete":
                phases[phase] = {"status": "skipped", "reason": "ingest_not_complete"}
            else:
                phases[phase] = run_phase(phase, directory, count, timeout)
        analysis = phases["analyze"]
        if analysis["status"] == "complete" and analysis["findings"] != inputs["expected_findings"]:
            analysis.update(status="failed", error="unexpected_finding_count")
        case_size = sum(path.stat().st_size for path in (directory / "case").rglob("*") if path.is_file())
    after = implementation()
    changed = before != after
    return {"schema": SCHEMA, "measured_at_utc": datetime.now(timezone.utc).isoformat(),
            "command": f"python scripts/benchmark.py --events {count}", "implementation": before,
            "implementation_changed_during_measurement": changed,
            "environment": conditions, "input": inputs, "case_size_bytes": case_size, "phases": phases,
            "status": "complete" if not changed and all(p["status"] == "complete" for p in phases.values()) else "incomplete",
            "caveats": ["One local measurement, not a benchmark distribution or a cross-tool comparison.",
                        "Filesystem cache was not flushed. Verify follows ingest and analysis.",
                        "Sparse synthetic records do not represent all real formats, corrupt data, high correlation density or live acquisition.",
                        "Peak RSS is per-process high-water memory, not incremental allocation or total system memory.",
                        "Input generation and interpreter startup are excluded from phase wall times.",
                        "A failed phase's elapsed time is time until refusal or failure, not successful throughput.",
                        "Case size is logical file bytes, not allocated filesystem blocks. Temporary input and case are deleted after the run."]}


def main():
    parser = argparse.ArgumentParser(description="Measure synthetic local ingestion, analysis and verification without network access.")
    parser.add_argument("--events", type=int, default=10000, help="Synthetic record count, 1 to 100000")
    parser.add_argument("--timeout", type=int, default=600, help="Maximum seconds per phase, 1 to 3600")
    parser.add_argument("--output", type=Path, help="Create a new JSON results file; never overwrite")
    parser.add_argument("--worker", choices=("ingest", "analyze", "verify"), help=argparse.SUPPRESS)
    parser.add_argument("--directory", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not 1 <= args.events <= MAX_EVENTS or not 1 <= args.timeout <= 3600:
        parser.error("events must be 1..100000 and timeout must be 1..3600")
    if args.worker:
        if args.directory is None:
            parser.error("worker directory required")
        worker(args.worker, args.directory, args.events)
        return 0
    result = benchmark(args.events, args.timeout)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        try:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(encoded)
        except OSError:
            parser.exit(2, "error: cannot create results file; choose a new writable destination\n")
    else:
        sys.stdout.write(encoded)
    return 0 if result["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
