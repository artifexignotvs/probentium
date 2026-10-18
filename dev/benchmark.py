"""Mensurae observatae, non promissa, referuntur."""
import argparse
import hashlib
import json
import math
import os
import platform
import resource
import statistics
import tempfile
import time
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path

from probentium import __version__
from probentium.contracts import canonical_bytes, ProbentiumError
from probentium.store import CaseStore
from probentium import investigation, time_model
from probentium.budgets import normalize_analysis_limits


_SOURCE_FILES = (
    "dev/benchmark.py", "probentium/contracts.py", "probentium/store.py",
    "probentium/worker.py", "probentium/adapters.py", "probentium/claims.py",
    "probentium/time_model.py", "probentium/investigation.py",
    "probentium/budgets.py", "probentium/locators.py", "probentium/exchange.py",
    "probentium/maintenance.py", "probentium/parser_artifact.py",
    "probentium/limits.py", "probentium/dependency_graph.py",
    "probentium/retention.py", "probentium/__init__.py", "testifex/__init__.py",
    "testifex/model.py", "testifex/parsers.py", "testifex/timeutil.py", "testifex/safeio.py",
)


def _manifest():
    root = Path(__file__).resolve().parent.parent
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in _SOURCE_FILES}


def _rss_kib(who):
    maximum = resource.getrusage(who).ru_maxrss
    return math.ceil(maximum / 1024) if platform.system() == "Darwin" else maximum


def _timed(report, name, function):
    report["active_stage"] = name
    start = time.perf_counter_ns()
    result = function()
    report["measurements"][name + "_ms"] = (time.perf_counter_ns() - start + 500000) // 1000000
    print(name + " completed: " + str(report["measurements"][name + "_ms"]) + " ms", flush=True)
    return result


def _write_report(path, report):
    destination = Path(path)
    with tempfile.NamedTemporaryFile(prefix=".benchmark-", dir=destination.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(canonical_bytes(report) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=100000)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not 100 <= args.events <= 100000:
        parser.error("events must be between 100 and 100000")
    if hasattr(os, "sched_getaffinity"):
        available = sorted(os.sched_getaffinity(0))
        os.sched_setaffinity(0, available[:4])
    report = {
        "schema": "probentium.benchmark.v2", "tool_version": __version__,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.system(), "architecture": platform.machine(),
        "python": platform.python_version(), "dependencies": {name: version(name) for name in ("rfc8785", "cryptography")},
        "cpu_affinity_count": len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
        "memory_profile": "Host allocation; no 16 GiB reference-machine memory cap was applied.",
        "event_count": args.events, "run_count": 1,
        "cache_condition": "Fresh temporary case; operating-system caches were not evicted. Reads follow import and verification.",
        "environment_limitations": ["Linux host measurement; not a macOS reference measurement.",
                                   "CPU affinity limits eligible CPUs, not exclusive CPU availability.",
                                   "Other host workloads were not stopped; this is not an isolated performance laboratory."],
        "source_sha256_before": _manifest(), "measurements": {}, "analysis_outcomes": [],
        "analysis_limits": normalize_analysis_limits(),
        "analysis_execution_mode": "in_process_core_measurement_not_child_launch",
        "measurement_scope": {
            "import": "Production CaseStore.ingest including parser worker and checkpoints; source generation excluded.",
            "full_verify": "Production CaseStore.verify including full source hashing and stored integrity checks.",
            "clock_setup": "Production save_clock validation and immutable write for an explicitly synthetic clock assumption.",
            "load_data": "Production load_data, including its own mandatory verification, pagination and analytic projection.",
            "two_templates": "One correlate_many_data call over loaded data; includes validation, semantic digests and both templates. No source-file I/O.",
            "rss": "Process lifetime peak including generation, import, verification, setup and analysis. Child value is RUSAGE_CHILDREN maximum, not a sum of simultaneous workers.",
        },
    }
    failed = False
    try:
        with tempfile.TemporaryDirectory(prefix="probentium-benchmark-") as directory:
            root = Path(directory)
            source = root / "events.jsonl"
            start = datetime(2026, 1, 1, tzinfo=timezone.utc)
            corpus_hash = hashlib.sha256()
            with source.open("xb") as stream:
                for index in range(args.events):
                    kind = "auth.failure" if index < args.events - 2 else "auth.success" if index == args.events - 2 else "process.exec"
                    value = {"timestamp": (start + timedelta(seconds=index)).isoformat(), "kind": kind,
                             "host": "synthetic-host", "actor": "synthetic-operator", "action": "synthetic-observation"}
                    raw = canonical_bytes(value) + b"\n"
                    corpus_hash.update(raw)
                    stream.write(raw)
            report["corpus_sha256"] = corpus_hash.hexdigest()
            report["corpus_bytes"] = source.stat().st_size
            with CaseStore.create(root / "case", "Synthetic benchmark") as case:
                imported = _timed(report, "import", lambda: case.ingest(source, "events", "Synthetic generated records"))
                report["import_accounting"] = {key: imported[key] for key in ("state", "records_total", "events_total", "counters", "unprocessed_bytes", "interpretation_complete")}
                if imported["events_total"] != args.events or imported["records_total"] != args.events or not imported["interpretation_complete"]:
                    raise ProbentiumError("benchmark_import_accounting_failed", 4)
                check = _timed(report, "full_verify", case.verify)
                report["integrity_receipt"] = {key: check[key] for key in ("ok", "completeness", "exit_code", "checks", "limitations")}
                report["integrity_passed"] = (check.get("ok") is True
                                               and check.get("completeness") == "acquired_bytes_present"
                                               and check.get("exit_code") == 0
                                               and not check.get("issues")
                                               and not check.get("authorized_unavailable"))
                if not report["integrity_passed"]:
                    raise ProbentiumError("benchmark_integrity_failed", 4)
                report["active_stage"] = "paged_reads"
                latencies = []
                offsets = []
                for index in range(30):
                    offset = index * (args.events - 100) // 29
                    offsets.append(offset)
                    started = time.perf_counter_ns()
                    page = case.query_events(limit=100, offset=offset)
                    latencies.append((time.perf_counter_ns() - started + 500000) // 1000000)
                    if page["total"] != args.events or len(page["rows"]) != 100:
                        raise ProbentiumError("benchmark_pagination_failed", 4)
                report["page_sampling"] = {"samples": len(latencies), "page_size": 100, "offsets": offsets,
                                           "p95_method": "nearest rank: sorted samples[ceil(0.95*n)-1]", "latencies_ms": latencies,
                                           "condition": "Post-verification reads; the first sample is not a cold-cache measurement."}
                report["measurements"].update(page_first_ms=latencies[0], page_p95_ms=sorted(latencies)[math.ceil(0.95*len(latencies))-1],
                                               page_median_ms=round(statistics.median(latencies)))
                model = {"schema": "testifex.clock-model.v1", "id": "synthetic-benchmark-clock", "basis_refs": [],
                         "rationale": "Explicit zero-error assumption for generated benchmark timestamps only; not measured clock calibration.",
                         "assumption_id": "synthetic-benchmark-zero-error", "source_family_ids": [],
                         "segments": [{"validity": time_model.interval(time_model.MIN_TIME_US, time_model.MAX_TIME_US, True, False),
                                       "fixed_offset_us": "0", "local_error": time_model.interval(0, 0), "shared_errors": []}]}
                _timed(report, "clock_setup", lambda: investigation.save_clock(case, model, [imported["id"]], expected_revision=case.revision))
                report["clock_assumption"] = {"type": "explicit_synthetic_zero_error", "model_sha256": hashlib.sha256(canonical_bytes(model)).hexdigest(),
                                               "scope": "The generated benchmark artifact only; no real host calibration is asserted."}
                data = _timed(report, "load_data", lambda: investigation.load_data(case, analysis_limits={}))
                if len(data["events"]) != args.events or data["integrity"] != "verified":
                    raise ProbentiumError("benchmark_analysis_input_failed", 4)
                requests = [{"template": name, "window_us": "3600000000", "threshold": 5}
                            for name in ("auth_after_failures", "post_auth_process")]
                result = _timed(report, "two_templates", lambda: investigation.correlate_many_data(data, requests, analysis_limits={}))
                report["analysis_input_digest"] = result["analysis"]["input_digest"]
                for group in result["templates"]:
                    report["analysis_outcomes"].append({"template": group["template"], "execution_state": result["execution_state"],
                                                        "findings": len(group["findings"]), "verdicts": [item["verdict"] for item in group["findings"]],
                                                        "count_units": [item["count"]["unit"] for item in group["findings"] if item["count"] is not None]})
                report["analysis_expected_outcome"] = "Both conditional templates entailed; failure counts evaluated as observations and duplicate groups, not proven real-world attempts."
                if result["execution_state"] != "complete" or len(result["templates"]) != 2 or any(not row["verdicts"] or set(row["verdicts"]) != {"entailed"} for row in report["analysis_outcomes"]):
                    raise ProbentiumError("benchmark_analysis_outcome_failed", 4)
                report["database_bytes"] = (case.path / "case.sqlite3").stat().st_size
                report["case_revision"] = case.revision
            report["parent_peak_rss_kib"] = _rss_kib(resource.RUSAGE_SELF)
            report["worker_peak_rss_kib"] = _rss_kib(resource.RUSAGE_CHILDREN)
    except Exception as exc:
        failed = True
        report["failure"] = {"stage": report.get("active_stage", "setup"), "code": getattr(exc, "code", "benchmark_execution_failed")}
    report.pop("active_stage", None)
    report["source_sha256_after"] = _manifest()
    report["source_unchanged_during_run"] = report["source_sha256_before"] == report["source_sha256_after"]
    if not report["source_unchanged_during_run"] and "failure" not in report:
        report["failure"] = {"stage": "source_manifest", "code": "benchmark_source_changed_during_run"}
    failed = failed or not report["source_unchanged_during_run"]
    report["status"] = "failed" if failed else "complete"
    measurements = report["measurements"]
    report["observed_thresholds"] = {
        "import_under_60s": measurements["import_ms"] < 60000 if "import_ms" in measurements else None,
        "two_templates_under_15s": measurements["two_templates_ms"] < 15000 if "two_templates_ms" in measurements else None,
        "page_p95_under_250ms": measurements["page_p95_ms"] < 250 if "page_p95_ms" in measurements else None,
        "parent_under_512mib": report["parent_peak_rss_kib"] < 512*1024 if "parent_peak_rss_kib" in report else None,
    }
    report["threshold_interpretation"] = "These flags compare this single observed Linux run with numeric targets; they do not establish equivalent reference hardware, cold-cache performance or other-platform support."
    report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    _write_report(args.output, report)
    print(json.dumps(report, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
