#!/usr/bin/env python3
"""Quaestio ultra centum milia observationum ex veris importationibus probatur."""
import argparse
import hashlib
import json
import platform
import resource
import tempfile
import time
from pathlib import Path

from probentium import __version__
from probentium.contracts import canonical_bytes, ProbentiumError
from probentium.intake import timeline_page
from probentium.store import CaseStore


def require(value, code):
    if not value:
        raise ProbentiumError(code, 4)


def manifest():
    root = Path(__file__).resolve().parents[1]
    names = ("scripts/check_large_search.py", "probentium/store.py", "probentium/contracts.py",
             "probentium/worker.py", "probentium/adapters.py", "testifex/parsers.py", "testifex/timeutil.py")
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}


def measure(count):
    report = {"schema": "probentium.large-search-check.v1", "synthetic_only": True,
              "tool_version": __version__, "platform": platform.system(),
              "python": platform.python_version(), "event_count": count,
              "source_sha256_before": manifest(), "checks": []}
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="probentium-search-") as directory:
            root = Path(directory)
            source = root / "synthetic.jsonl"
            ordinary = canonical_bytes({"kind": "auth.failure", "timestamp": "2026-10-18T12:00:00Z",
                                         "actor": "synthetic-ordinary"}) + b"\n"
            special = canonical_bytes({"kind": "auth.success", "timestamp": "2026-10-18T12:00:01Z",
                                        "actor": "synthetic-Stra\u00dfe_%LAST"}) + b"\n"
            corpus = hashlib.sha256()
            with CaseStore.create(root / "case", "Synthetic whole-case search") as case:
                # Partes finitae eodem limite processus ac fontes ordinarii utuntur.
                remaining, imported = count, 0
                while remaining:
                    portion = min(100_001, remaining)
                    with source.open("wb") as stream:
                        for index in range(portion):
                            raw = special if remaining == portion and index == portion - 1 else ordinary
                            stream.write(raw)
                            corpus.update(raw)
                    row = case.ingest(source, "events", "Synthetic search part " + str(imported))
                    require(row["state"] == "complete" and row["events_total"] == portion,
                            "search_import_accounting_failed")
                    remaining -= portion
                    imported += portion
                report["imported_records"] = imported
                report["corpus_sha256"] = corpus.hexdigest()
                report["import_ms"] = round((time.monotonic() - started) * 1000)
                result = case.query_events("SYNTHETIC-STRASSE_%LAST", limit=1)
                require(result["total"] == 1 and len(result["rows"]) == 1, "late_record_search_failed")
                record = result["rows"][0]
                require(case.raw(record["id"]) == special, "late_record_raw_mismatch")
                require(record["ordinal"] == (count - 1) % 100_001 + 1, "late_record_ordinal_mismatch")
                report["checks"].append({"check": "literal_unicode_casefold_after_100000", "status": "passed",
                                          "global_import_position": count, "matched_records": 1})
                require(case.query_events("%LAST")["total"] == 1, "literal_percent_search_failed")
                require(case.query_events("%')[OR 1=1]")["total"] == 0, "literal_query_changed_semantics")
                page = timeline_page(case, query="SYNTHETIC-STRASSE_%LAST", limit=1)
                require(page["total"] == 1 and page["rows"][0]["id"] == record["id"], "cursor_filtered_search_failed")
                report["checks"].append({"check": "literal_query_and_cursor", "status": "passed"})
                positions = sorted({index * (count - 1) // 11 for index in range(12)})
                for offset in positions:
                    page = case.query_events(limit=1, offset=offset)
                    require(page["total"] == count and len(page["rows"]) == 1, "whole_case_pagination_failed")
                report["checks"].append({"check": "whole_case_pagination", "status": "passed", "positions": positions})
                proof = case.verify()
                require(proof["ok"] and proof["exit_code"] == 0, "large_search_integrity_failed")
                report["checks"].append({"check": "final_full_integrity", "status": "passed"})
        report["status"] = "passed"
    except (ProbentiumError, OSError, ValueError, KeyError, TypeError) as exc:
        report.update(status="failed", error=getattr(exc, "code", "large_search_check_failed"))
    report["source_sha256_after"] = manifest()
    report["source_unchanged"] = report["source_sha256_before"] == report["source_sha256_after"]
    if not report["source_unchanged"]:
        report.update(status="failed", error="check_source_changed")
    report["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    report["parent_peak_rss_kib"] = peak // 1024 if platform.system() == "Darwin" else peak
    report["limitations"] = ["Functional synthetic search check, not the cold/warm performance acceptance matrix.",
                             "Host workload and caches were not controlled; elapsed time is observational."]
    return report


def main():
    parser = argparse.ArgumentParser(description="Verify whole-case search using real bounded synthetic imports.")
    parser.add_argument("--events", type=int, default=100_001)
    parser.add_argument("--output", type=Path, required=True, help="New JSON receipt file")
    args = parser.parse_args()
    if not 100_001 <= args.events <= 1_000_000:
        parser.error("events must be between 100001 and 1000000")
    if args.output.exists():
        parser.error("output already exists")
    result = measure(args.events)
    with args.output.open("xb") as stream:
        stream.write(canonical_bytes(result) + b"\n")
    print(json.dumps({"status": result["status"], "events": args.events, "checks": len(result["checks"])}))
    return 0 if result["status"] == "passed" else 4


if __name__ == "__main__":
    raise SystemExit(main())
