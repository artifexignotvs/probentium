"""Mandata clara, errores sine secretis."""
import sys
from pathlib import Path

from . import __version__
from .contracts import strict_json, ProbentiumError, utc_now
from .store import CaseStore
from . import cli_contract as contract


def read_input(path):
    from testifex.safeio import regular_reader
    with regular_reader(Path(path), 16 * 1024 * 1024) as (stream, _):
        return strict_json(stream.read(16 * 1024 * 1024 + 1))


def parser():
    result = contract.SafeParser(prog="probentium", description="Offline evidence workbench. Development preview; draft regulatory profiles.")
    result.add_argument("--version", action="version", version=__version__)
    result.add_argument("--format", dest="transport_format", choices=("json",), help="Use the versioned result envelope; place before the command")
    sub = result.add_subparsers(dest="command", required=True)
    console = sub.add_parser("console", help="Start the native terminal console")
    console.add_argument("--case", help="Open an existing case after startup")
    console.add_argument("--ascii", action="store_true", help="Render non-ASCII text as visible escapes")
    console.add_argument("--no-banner", action="store_true", help="Hide the text logo")
    init = sub.add_parser("init", help="Create a private case")
    init.add_argument("directory")
    init.add_argument("--name", required=True)
    demo = sub.add_parser("demo", help="Create a synthetic investigation")
    demo.add_argument("directory")
    demo.add_argument("--basic", action="store_true", help="Create only the small intake/reporting exercise")
    for name in ("status", "sources", "verify", "browse"):
        command = sub.add_parser(name)
        command.add_argument("--case", required=True)
        if name == "browse":
            command.add_argument("--ascii", action="store_true", help="Render non-ASCII text as visible escapes")
    ingest = sub.add_parser("ingest", help="Acquire an evidence file and record byte provenance")
    ingest.add_argument("--case", required=True)
    ingest.add_argument("file")
    from .adapters import FORMATS
    ingest.add_argument("--format", choices=FORMATS, required=True)
    ingest.add_argument("--label", required=True)
    ingest.add_argument("--expect-revision", "--expected-revision", dest="expect_revision", type=int)
    ingest.add_argument("--resource-policy", help="Explicit versioned resource policy JSON for this operation")
    ingest.add_argument("--parser-artifact", help="Explicitly selected registered parser approval ID")
    timeline = sub.add_parser("timeline", help="Query the entire case with bounded pagination")
    timeline.add_argument("--case", required=True)
    timeline.add_argument("--filter", default="")
    timeline.add_argument("--limit", type=int, default=100)
    timeline.add_argument("--offset", type=int, default=0)
    timeline.add_argument("--cursor")
    event = sub.add_parser("event", help="Retrieve original record bytes without terminal control execution")
    event.add_argument("--case", required=True)
    event.add_argument("id")
    for name in ("control", "incident"):
        group = sub.add_parser(name)
        group.add_argument("--case", required=True)
        group.add_argument("--input", "--spec", dest="input", required=True, help="JSON input file")
        group.add_argument("--save", action="store_true", help="Persist the input as a new immutable object")
        group.add_argument("--expect-revision", "--expected-revision", dest="expect_revision", type=int)
        if name == "incident":
            group.add_argument("--as-of", default=None)
    filing = sub.add_parser("filing", help="Prepare a frozen draft; does not submit anything")
    filing.add_argument("--case", required=True)
    filing.add_argument("--track", required=True, help="Track JSON file")
    filing.add_argument("--fields", required=True, help="Fields JSON file")
    filing.add_argument("--cutoff", required=True)
    filing.add_argument("--expect-revision", "--expected-revision", dest="expect_revision", type=int)
    diff = sub.add_parser("diff", help="Compare two stored filing snapshots")
    diff.add_argument("--case", required=True)
    diff.add_argument("before")
    diff.add_argument("after")
    from .commands import register
    register(sub)
    contract.attach_help(result)
    return result


def run(args):
    if args.command not in {"demo", "init", "browse", "status", "sources", "verify", "ingest", "timeline", "event", "control", "incident", "filing", "diff"}:
        from .commands import dispatch
        return dispatch(args, read_input)
    if args.command == "demo":
        from .demo import make_demo
        return make_demo(args.directory, extended=not args.basic)
    if args.command == "init":
        with CaseStore.create(args.directory, args.name) as case, contract.observe_case(args, case):
            return {"case": case.meta, "revision": case.revision}
    if args.command == "browse":
        if args.transport_format == "json":
            raise ProbentiumError("interactive_json_not_supported", 7)
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise ProbentiumError("interactive_terminal_required")
        from .tui import browse
        browse(args.case, ascii_only=args.ascii)
        return None
    policy = read_input(args.resource_policy) if getattr(args, "resource_policy", None) else None
    with CaseStore(args.case, resource_policy=policy) as case, contract.observe_case(args, case):
        if args.command == "status":
            return {"case": case.meta, "revision": case.revision,
                    "sources": len(case.sources()), "events": case.query_events(limit=1)["total"],
                    "objects": len(case.objects()), "development_preview": True}
        if args.command == "sources":
            return {"sources": case.sources(), "revision": case.revision}
        if args.command == "verify":
            return case.verify()
        if args.command == "ingest":
            return case.ingest(args.file, args.format, args.label, expected_revision=args.expect_revision, parser_approval_id=args.parser_artifact)
        if args.command == "timeline":
            if args.cursor or not args.offset:
                from .intake import timeline_page
                return timeline_page(case, query=args.filter, limit=args.limit, cursor=args.cursor)
            return case.query_events(query=args.filter, limit=args.limit, offset=args.offset)
        if args.command == "event":
            import base64
            import hashlib
            segments = case.raw_records(args.id)
            if len(segments) > 1:
                return {"schema": "probentium.event-raw.v2", "event_id": args.id,
                        "segments": [{"locator": part["record"], "primary": part["primary"],
                                      "raw_base64": base64.b64encode(part["bytes"]).decode("ascii")} for part in segments],
                        "concatenation_performed": False}
            raw = segments[0]["bytes"]
            return {"event_id": args.id, "raw_base64": base64.b64encode(raw).decode("ascii"),
                    "raw_sha256": hashlib.sha256(raw).hexdigest(), "length": len(raw)}
        if args.command == "control":
            from .workbench import assess_control
            control = read_input(args.input)
            result = assess_control(case, control)
            if args.save:
                result["stored"] = case.put_object("control", control, expected_revision=args.expect_revision)
            return result
        if args.command == "incident":
            from .regulatory import evaluate_deadlines
            track = read_input(args.input)
            result = evaluate_deadlines(track, args.as_of or utc_now())
            if args.save:
                result["stored"] = case.put_object("track", track, expected_revision=args.expect_revision)
            return result
        if args.command == "filing":
            from .regulatory import prepare_filing
            from .workbench import validate_refs
            track, fields = read_input(args.track), read_input(args.fields)
            snapshot = prepare_filing(track, fields, case.revision, args.cutoff)
            validate_refs(case, snapshot["fields"])
            return case.put_object("filing", snapshot, expected_revision=args.expect_revision)
        if args.command == "diff":
            from .regulatory import compare_filings
            before, after = case.get_object(args.before), case.get_object(args.after)
            if before["kind"] != "filing" or after["kind"] != "filing":
                raise ProbentiumError("filing_object_required")
            return compare_filings(before["data"], after["data"])
    raise ProbentiumError("unknown_command")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv and sys.stdin.isatty() and sys.stdout.isatty():
        argv = ["console"]
    machine, args, information = contract.machine_requested(argv), None, []
    try:
        command_line = parser()
        if machine:
            contract.capture_information(command_line, information)
        args = command_line.parse_args(argv)
        if args.command == "console":
            if machine:
                raise ProbentiumError("interactive_json_not_supported", 7)
            from .terminal import launch
            return launch(args.case, ascii_only=args.ascii, no_banner=args.no_banner, command_runner=main)
        result = run(args)
        code = contract.exit_code(args, result)
        if result is not None or machine:
            contract.write_json(sys.stdout, contract.envelope(args, result, code) if machine else result)
        return code
    except contract.InformationExit:
        if machine:
            data = {"kind": "version" if "--version" in argv else "help", "text": "".join(information)}
            contract.write_json(sys.stdout, contract.envelope(None, data))
        return 0
    except ProbentiumError as exc:
        error = contract.envelope(args, None, exc.exit_code, exc.code)
        contract.write_json(sys.stderr, error if machine else {"error": error["errors"][0]["code"]})
        return exc.exit_code
    except MemoryError:
        contract.write_json(sys.stderr, contract.envelope(args, None, 6, "memory_resource_limit") if machine else {"error": "memory_resource_limit"})
        return 6
    except (OSError, ValueError, TypeError, KeyError):
        contract.write_json(sys.stderr, contract.envelope(args, None, 2, "operation_failed") if machine else {"error": "operation_failed"})
        return 2
    except KeyboardInterrupt:
        if machine:
            contract.write_json(sys.stderr, contract.envelope(args, None, 130, "interrupted"))
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
