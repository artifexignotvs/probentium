"""Exempla ficta, exitus veri."""
import json
from pathlib import Path
from types import SimpleNamespace

from .case import Case
from .cli import build_report
from .model import canonical
from .report import compare_reports, render_markdown
from .safeio import write_new


def run_demo(directory):
    root = Path(directory)
    root.mkdir(mode=0o700)
    auth = []
    for i in range(8):
        auth.append(f"2026-01-01T00:00:{i*5:02d}Z edge-demo sshd[1234]: Failed password for operator from 192.0.2.30 port 54321 ssh2")
    auth.append("2026-01-01T00:01:30Z edge-demo sshd[1234]: Accepted publickey for operator from 192.0.2.30 port 54321 ssh2")
    write_new(root / "auth.log", ("\n".join(auth) + "\n").encode())
    process = {"timestamp": "2026-01-01T00:01:45.000000Z", "kind": "process.exec", "host": "edge-demo", "actor": "operator", "path": "/usr/bin/id", "action": "execute"}
    write_new(root / "activity.jsonl", (canonical(process) + "\n").encode())
    options = SimpleNamespace(threshold=5, window="300", max_events=100000)
    reports = {}
    for name, correction in (("auth-case", {}), ("uncertain-case", {"clock_error_us": 30000000, "correction_reason": "Synthetic collector offset bounded to plus or minus 30 seconds"})):
        with Case.create(root / name, name) as case:
            case.ingest(root / "auth.log", "auth", "synthetic-auth")
            case.ingest(root / "activity.jsonl", "events", "synthetic-process", correction)
            events = list(case.events())
            hypothesis = case.add_hypothesis("Was the successful login followed by an unauthorized command?", ["The collector host and account labels refer to the same machine and account."])
            success = next(e for e in events if e["kind"] == "auth.success")
            proc = next(e for e in events if e["kind"] == "process.exec")
            case.link_hypothesis(hypothesis["id"], success["id"], "supports", "Authentication succeeded after failures; authorization remains unknown.")
            case.link_hypothesis(hypothesis["id"], proc["id"], "context", "A process record does not independently establish an SSH session link.")
            report = build_report(case, options)
            reports[name] = report
            write_new(root / (name + ".json"), (canonical(report) + "\n").encode())
            write_new(root / (name + ".md"), render_markdown(report).encode())
            case.snapshot(report, "synthetic-baseline")
            if not case.verify()["ok"]:
                raise ValueError("demo_verification_failed")
    delta = compare_reports(reports["auth-case"], reports["uncertain-case"])
    write_new(root / "comparison.json", (canonical(delta) + "\n").encode())
    return {"schema": "testifex.demo.v1", "network_requests": 0, "synthetic": True,
            "scenarios": [{"case": name, "events": len(report["events"]), "findings": len(report["analysis"]["findings"]), "report": name + ".md"} for name, report in reports.items()],
            "comparison": "comparison.json", "point": "Adding a declared clock error can change a certain temporal lead into an uncertain one; neither proves compromise."}
