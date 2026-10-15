"""Mandata clara, exitus probabiles."""
import argparse
import base64
import json
import os
import sqlite3
import sys
from itertools import islice
from pathlib import Path

from . import __version__
from .case import Case
from .model import CaseError, FORMATS, MAX_REPORT, MAX_SOURCE, canonical, safe_text, seconds_us, strict_json
from .safeio import bounded_read, read_key, write_new


def parser():
    p = argparse.ArgumentParser(prog="testifex", description="Offline evidence timelines with explicit time uncertainty.")
    p.add_argument("--version", action="version", version=__version__)
    commands = p.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create a private local case")
    init.add_argument("directory"); init.add_argument("--name", default="Untitled case")
    ingest = commands.add_parser("ingest", help="Copy, hash and parse one regular evidence file")
    ingest.add_argument("file"); ingest.add_argument("--case", required=True)
    ingest.add_argument("--format", choices=FORMATS, required=True)
    ingest.add_argument("--label", required=True)
    ingest.add_argument("--clock-offset", default="0", help="Seconds the source clock is ahead; corrected = recorded - offset")
    ingest.add_argument("--clock-error", default="0", help="Symmetric uncertainty in seconds")
    ingest.add_argument("--reason", default="")
    ingest.add_argument("--declared-start"); ingest.add_argument("--declared-end")
    ingest.add_argument("--max-bytes", type=int, default=MAX_SOURCE)
    ingest.add_argument("--max-records", type=int, default=1000000)
    resume = commands.add_parser("resume", help="Continue a verified evidence copy from a checkpoint")
    resume.add_argument("source"); resume.add_argument("--case", required=True)
    resume.add_argument("--max-records", type=int, default=1000000)
    for name in ("sources", "issues"):
        item = commands.add_parser(name); item.add_argument("--case", required=True)
    timeline = commands.add_parser("timeline", help="List timestamp intervals, not inferred total ordering")
    timeline.add_argument("--case", required=True)
    for field in ("source", "kind", "host", "actor", "after", "before"):
        timeline.add_argument("--" + field)
    timeline.add_argument("--limit", type=int, default=200)
    timeline.add_argument("--format", choices=("text", "json", "jsonl"), default="text")
    event = commands.add_parser("event", help="Inspect a record and its exact evidence locator")
    event.add_argument("id"); event.add_argument("--case", required=True)
    event.add_argument("--raw", action="store_true", help="Include original bytes as base64; sensitive")
    for name in ("analyze", "report", "snapshot", "share", "triage"):
        item = commands.add_parser(name)
        item.add_argument("--case", required=True)
        item.add_argument("--threshold", type=int, default=5)
        item.add_argument("--window", default="300")
        item.add_argument("--max-events", type=int, default=100000)
        if name == "triage":
            item.add_argument("--format", choices=("text", "json"), default="text")
            item.add_argument("--limit", type=int, default=10, help="Show at most this many findings (1 to 100)")
            item.add_argument("--output")
        elif name in ("analyze", "report"):
            item.add_argument("--format", choices=("json", "markdown"), default="json")
            item.add_argument("--output")
        elif name == "snapshot":
            item.add_argument("--label", required=True)
        else:
            item.add_argument("--key-file", required=True)
            item.add_argument("--output")
            item.add_argument("--public", action="store_true", help="Write a public-share candidate; otherwise preview to stdout")
    diff = commands.add_parser("diff", help="Compare two saved validated reports")
    diff.add_argument("before"); diff.add_argument("after")
    diff.add_argument("--output")
    verify = commands.add_parser("verify", help="Verify evidence bytes and replay normalization")
    verify.add_argument("--case", required=True)
    replay = commands.add_parser("replay", help="Rebuild another case from verified evidence copies")
    replay.add_argument("--case", required=True); replay.add_argument("--into", required=True)
    hypothesis = commands.add_parser("hypothesis", help="Record analyst hypotheses and counterevidence")
    hc = hypothesis.add_subparsers(dest="hypothesis_command", required=True)
    add = hc.add_parser("add"); add.add_argument("--title", required=True)
    add.add_argument("--assumption", action="append", default=[])
    link = hc.add_parser("link"); link.add_argument("id"); link.add_argument("--event", required=True)
    link.add_argument("--stance", choices=("supports", "contradicts", "context"), required=True)
    link.add_argument("--note", default="")
    state = hc.add_parser("status"); state.add_argument("id")
    state.add_argument("--state", choices=("open", "supported", "refuted", "inconclusive"), required=True)
    listing = hc.add_parser("list")
    for child in (add, link, state, listing):
        child.add_argument("--case", required=True)
    browse = commands.add_parser("browse", help="Read-only keyboard evidence browser")
    browse.add_argument("--case", required=True); browse.add_argument("--ascii", action="store_true")
    demo = commands.add_parser("demo", help="Create and run two synthetic offline investigations")
    demo.add_argument("--directory", required=True)
    return p


def emit(value, output=None, markdown=False):
    text = value if markdown else canonical(value) + "\n"
    if output:
        write_new(output, text.encode("utf-8"))
    else:
        sys.stdout.write(text)


def build_report(case, args):
    from .analysis import analyze
    from .report import make_report
    if not 1 <= args.max_events <= 100000:
        raise CaseError("event_limit_must_be_1_to_100000")
    events = list(islice(case.events(), args.max_events + 1))
    if len(events) > args.max_events:
        raise CaseError("analysis_event_limit_exceeded")
    sources = case.sources()
    if not case.verify()["ok"]:
        raise CaseError("case_verification_failed")
    result = analyze(events, sources, window_us=seconds_us(args.window, True), threshold=args.threshold, max_events=args.max_events)
    return make_report(case.metadata, sources, events, result, case.hypotheses())


def execute(args):
    from .timeutil import parse_time, format_time
    command = args.command
    if command == "init":
        with Case.create(args.directory, args.name) as case:
            emit(case.metadata)
        return 0
    if command == "diff":
        from .report import compare_reports
        before = strict_json(bounded_read(args.before, MAX_REPORT))
        after = strict_json(bounded_read(args.after, MAX_REPORT))
        emit(compare_reports(before, after), args.output)
        return 0
    if command == "demo":
        from .demo import run_demo
        emit(run_demo(args.directory))
        return 0
    with Case(args.case) as case:
        if command == "ingest":
            options = {"clock_offset_us": seconds_us(args.clock_offset), "clock_error_us": seconds_us(args.clock_error, True), "correction_reason": args.reason,
                       "declared_start_us": parse_time(args.declared_start)["time_low_us"] if args.declared_start else None,
                       "declared_end_us": parse_time(args.declared_end)["time_high_us"] if args.declared_end else None}
            source = case.ingest(args.file, args.format, args.label, options, args.max_bytes, args.max_records)
            emit(source)
            return 0 if source["status"] == "complete" else 3
        if command == "resume":
            source = case.resume(args.source, args.max_records); emit(source)
            return 0 if source["status"] == "complete" else 3
        if command == "sources":
            emit(case.sources()); return 0
        if command == "issues":
            for issue in case.issues():
                emit(issue)
            return 0
        if command == "timeline":
            if not 1 <= args.limit <= 100000:
                raise CaseError("timeline_limit_must_be_1_to_100000")
            after = parse_time(args.after)["time_low_us"] if args.after else None
            before = parse_time(args.before)["time_high_us"] if args.before else None
            if after is not None and before is not None and after > before:
                raise CaseError("invalid_timeline_interval")
            selected = []
            for event in case.events(args.source):
                if any(getattr(args, k) is not None and event[k] != getattr(args, k) for k in ("kind", "host", "actor")):
                    continue
                if (after is not None or before is not None) and event["time_low_us"] is None:
                    continue
                if after is not None and event["time_high_us"] < after:
                    continue
                if before is not None and event["time_low_us"] > before:
                    continue
                selected.append(event)
                if len(selected) > args.limit:
                    break
            truncated = len(selected) > args.limit
            selected = selected[:args.limit]
            if args.format == "json":
                emit({"schema": "testifex.timeline.v1", "events": selected, "truncated": truncated, "ordering": "interval_lower_bound_not_proven_chronology"})
            elif args.format == "jsonl":
                for event in selected:
                    emit(event)
            else:
                print("UTC INTERVAL (inclusive)                                  KIND             ACTOR / HOST")
                for event in selected:
                    low = format_time(event["time_low_us"]) or "unknown"
                    high = format_time(event["time_high_us"]) or "unknown"
                    print(safe_text(f"{low} .. {high}  {event['kind']}  {event['actor'] or '-'} / {event['host'] or '-'}"))
                    print("  " + event["id"])
            if truncated:
                print("timeline_truncated: increase --limit or narrow filters", file=sys.stderr)
            return 0
        if command == "event":
            event = case.event(args.id)
            if args.raw:
                event["raw_base64"] = base64.b64encode(case.raw_event(args.id)).decode()
            emit(event); return 0
        if command == "triage":
            from .triage import render_text, summarize_report, validate_limit
            validate_limit(args.limit)
            report = build_report(case, args)
            value = summarize_report(report, limit=args.limit) if args.format == "json" else render_text(report, limit=args.limit)
            emit(value, args.output, args.format == "text")
            return 0
        if command in ("analyze", "report", "snapshot", "share"):
            from .report import render_markdown, share_report
            report = build_report(case, args)
            if command == "snapshot":
                emit(case.snapshot(report, args.label)); return 0
            if command == "share":
                if args.output and not args.public:
                    raise CaseError("public_output_requires_explicit_public_flag")
                candidate = share_report(report, read_key(args.key_file))
                emit(candidate, args.output)
                print("share_candidate: free text withheld; timing and relationships may still identify a case. Review before publication.", file=sys.stderr)
                return 0
            value = report["analysis"] if command == "analyze" and args.format == "json" else report
            emit(render_markdown(report) if args.format == "markdown" else value, args.output, args.format == "markdown")
            return 0
        if command == "verify":
            result = case.verify(); emit(result)
            return 0 if result["ok"] else 4
        if command == "replay":
            proof = case.verify()
            if not proof["ok"] or any(s["status"] != "complete" for s in case.sources()):
                raise CaseError("replay_requires_complete_verified_sources")
            with Case.create(args.into, case.metadata["name"]) as target:
                for source in case.sources():
                    copied = target.ingest(case.path / "evidence" / (source["sha256"] + ".bin"), source["format"], source["label"], source["options"],
                                           max_bytes=4 * 1024 ** 3, max_records=max(1, source["lines_total"]))
                    if (copied["id"] != source["id"] or copied["status"] != "complete"
                            or copied["lines_total"] != source["lines_total"] or copied["parsed_count"] != source["parsed_count"]):
                        raise CaseError("replay_source_mismatch")
                for hypothesis in case.hypotheses():
                    target.db.execute("INSERT INTO hypotheses VALUES(?,?)", (hypothesis["id"], canonical({k: v for k, v in hypothesis.items() if k != "evidence"})))
                    for link in hypothesis["evidence"]:
                        target.db.execute("INSERT INTO hypothesis_evidence VALUES(?,?,?,?)", (hypothesis["id"], link["event_id"], link["stance"], link["note"]))
                target.db.commit()
                emit({"replayed": True, "sources": len(target.sources()), "events": target.db.execute("SELECT count(*) FROM events").fetchone()[0], "case_id": target.metadata["case_id"]})
            return 0
        if command == "hypothesis":
            if args.hypothesis_command == "add":
                emit(case.add_hypothesis(args.title, args.assumption))
            elif args.hypothesis_command == "link":
                case.link_hypothesis(args.id, args.event, args.stance, args.note); emit({"linked": True})
            elif args.hypothesis_command == "status":
                case.set_hypothesis_status(args.id, args.state); emit({"updated": True})
            else:
                emit(case.hypotheses())
            return 0
        if command == "browse":
            from .tui import run_tui
            run_tui(case, ascii_only=args.ascii)
            return 0
    raise CaseError("unknown_command")


def main(argv=None):
    try:
        return execute(parser().parse_args(argv))
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except BrokenPipeError:
            pass
        return 0
    except KeyboardInterrupt:
        print("interrupted: saved import checkpoints can be resumed", file=sys.stderr)
        return 130
    except (CaseError, ValueError) as exc:
        # Nuntius externus numquam sine examine redditur.
        code = str(exc)
        if not code or len(code) > 120 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_: -" for c in code):
            code = "invalid_input_or_configuration"
        print("error: " + code, file=sys.stderr)
        return 2
    except (OSError, sqlite3.Error, KeyError, TypeError, OverflowError):
        print("error: operation_failed; check file permissions, case schema and input format", file=sys.stderr)
        return 2
