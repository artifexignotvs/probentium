"""Una actio, una visio fixa."""
import json
import shlex

from . import __version__
from .contracts import ProbentiumError, safe_text, utc_now, object_digest
from .regulatory import evaluate_control, evaluate_deadlines, prepare_filing, compare_filings
from .screen import render, VIEWS
from .store import CaseStore

PAGE_SIZE = 100


def validate_refs(case, fields):
    """Relatio sine origine non fit probatio."""
    if not isinstance(fields, list) or not all(isinstance(field, dict) and isinstance(field.get("refs", []), list) and all(isinstance(ref, str) for ref in field.get("refs", [])) for field in fields):
        raise ProbentiumError("invalid_evidence_references")
    known = {source["id"] for source in case.sources()}
    known.update(item["id"] for item in case.objects())
    required = {ref for field in fields for ref in field.get("refs", [])}
    for ref in required - known:
        try:
            case.raw_records(ref)
        except ProbentiumError as exc:
            raise ProbentiumError("evidence_reference_missing") from exc


def assess_control(case, control):
    result = evaluate_control(control)
    refs = [{"refs": control.get("evidence_refs", [])}]
    refs.extend({"refs": row.get("evidence_refs", [])} for row in control.get("observations", []))
    validate_refs(case, refs)
    return result


def json_lines(value):
    return json.dumps(value, ensure_ascii=False, indent=2).splitlines()


def object_state(obj):
    """Exitus, fiducia et praesentia non confunduntur."""
    data = obj["data"]
    if obj["kind"] == "analysis_scenario":
        results = data.get("scenario_result", {}).get("evaluations", [])
        return ", ".join(sorted({row["verdict"] for row in results})) or data.get("execution_state", "recorded")
    if obj["kind"] == "review_decision":
        return data["decision"]["disposition"] + " / " + data["verification"]["key_trust"]
    return data.get("state", data.get("status", data.get("execution_state", "recorded")))


def deadline_row(row):
    target = row.get("operational_target")
    interval = row.get("operational_target_range")
    if interval:
        target = ("[" if interval.get("earliest_inclusive") else "(") + (interval.get("earliest") or "unbounded") + " .. " + (interval.get("latest") or "unbounded") + ("]" if interval.get("latest_inclusive") else ")")
    status = row.get("operational_status", "unknown")
    if status == "unknown":
        status = row.get("status", "unknown")
    return {"stage": row["stage"], "target": target or "not supplied", "status": status,
            "stage_display": row["stage"].replace("_", " "),
            "status_display": status.replace("_", " "),
            "basis": "; ".join(reason.replace("_", " ") for reason in row.get("reasons", [])) or "Operational planning only"}


class Workbench:
    def __init__(self, path):
        self.path = path
        self.state = {"view": "overview", "selected": 0, "scroll": 0, "filter": "", "detail": False,
                      "message": "Local evidence workbench. Press ? for keys and commands.", "prompt": None}
        self.offset = 0
        self.integrity = {"ok": None, "issues": []}
        self.verified_revision = None
        self.closed = False
        self.model = {}
        self.track_id = None
        self.command_detail = None
        self.analysis_revision = None
        self.analysis_fingerprint = None

    def refresh(self):
        with CaseStore(self.path) as case:
            objects = case.objects()
            by_kind = lambda kind: [item for item in objects if item["kind"] == kind]
            scenarios = by_kind("scenario")
            scenario = scenarios[-1]["data"] if scenarios else {}
            synthetic = (scenario.get("synthetic") is True
                         and scenario.get("artifacts") == sorted(item["id"] for item in case.sources())
                         and scenario.get("source_digest") == object_digest(case.sources())
                         and scenario.get("objects") == sorted(item["id"] for item in objects if item["kind"] != "scenario"))
            as_of = scenario.get("as_of") if synthetic else utc_now()
            controls = []
            for obj in by_kind("control"):
                control = obj["data"]
                result = assess_control(case, control)
                coverage = result.get("coverage", {})
                population = coverage.get("population")
                controls.append({**control, **result, "title": control.get("title", control.get("id")),
                                 "status_display": result["status"].replace("_", " "),
                                 "reason": "; ".join(result.get("reasons", [])), "object_id": obj["id"],
                                 "coverage_summary": str(coverage.get("assessed", 0)) + "/" + (str(population) if population is not None else "?") + " obs."})
            from .governance import assess_control_observation
            for obj in by_kind("eu.control_observation"):
                result = assess_control_observation(case, obj["id"])
                coverage = result["coverage"]
                controls.append({**result, "id": obj["id"], "object_id": obj["id"],
                                 "title": result["procedure_id"] + " / declared population",
                                 "status_display": result["status"].replace("_", " "),
                                 "reason": "; ".join(result["limitations"]),
                                 "coverage_summary": str(coverage["assessed"]) + "/" + (str(coverage["population"]) if coverage["population"] is not None else "?") + " obs.",
                                 "record": obj})
            tracks = by_kind("track")
            candidates = [item for item in tracks if self.track_id is None or item["data"].get("id") == self.track_id]
            track = candidates[-1]["data"] if candidates else None
            if track:
                self.track_id = track["id"]
            incident = {"id": None, "title": "No reporting track", "profile": None, "status": "not supplied", "deadline_rows": []}
            if track:
                deadlines = evaluate_deadlines(track, as_of)
                incident = {**track, "status": "DRAFT / legal currentness unverified",
                            "awareness": track.get("anchors", {}).get("awareness"),
                            "deadline_rows": [deadline_row(row) for row in deadlines["deadlines"]],
                            "limitations": ["No legal applicability determination or external submission.",
                                            "Draft rules; legal calendar and currentness are unverified.",
                                            ("Exercise clock: " if synthetic else "Evaluated at: ") + as_of]}
            filing_objects = [item for item in by_kind("filing") if item["data"].get("track", {}).get("id") == self.track_id]
            filings = [{"id": item["id"], "status": "prepared", "title": "Frozen incident draft", "cutoff": item["data"].get("cutoff"),
                        "fields_count": len(item["data"].get("fields", [])), "data": item["data"]} for item in filing_objects]
            diff = compare_filings(filing_objects[-2]["data"], filing_objects[-1]["data"]) if len(filing_objects) >= 2 else {"changes": []}
            changes = [{**change,
                        "before_summary": change["before"].get("value") if change.get("before") else "absent",
                        "after_summary": change["after"].get("value") if change.get("after") else "absent"}
                       for change in diff.get("changes", [])]
            total_events = case.query_events(limit=1)["total"]
            page = case.query_events(query=self.state["filter"], limit=PAGE_SIZE, offset=self.offset)
            if self.offset and not page["rows"]:
                self.offset = max(0, ((max(1, page["total"]) - 1) // PAGE_SIZE) * PAGE_SIZE)
                page = case.query_events(query=self.state["filter"], limit=PAGE_SIZE, offset=self.offset)
            page["offset"] = self.offset
            integrity = self.integrity if self.verified_revision == case.revision else {"ok": None, "issues": [], "state": "not_checked"}
            self.model = {"product": "PROBENTIUM", "version": __version__, "case_name": case.meta.get("name", "Unnamed case"),
                          "revision": case.revision, "synthetic": synthetic, "integrity": integrity,
                          "counts": {"sources": len(case.sources()), "events": total_events, "controls": len(controls), "filings": len(filings)},
                          "sources": [{**source, "parsed_count": source.get("counters", {}).get("parsed"),
                                       "status_summary": "read / gaps" if source.get("status") == "complete" and not source.get("interpretation_complete") else source.get("status")}
                                      for source in case.sources()], "events": page, "controls": controls, "incident": incident,
                          "filings": filings, "changes": changes, "detail_lines": [], "track": track}
            from .investigation import stale_status_many
            evaluations = by_kind("evaluation")
            claim_rows = []
            claim_objects = by_kind("claim")
            if claim_objects and self.analysis_revision != case.revision:
                try:
                    batch = stale_status_many(case, [row["id"] for row in evaluations])
                    self.analysis_currentness = {row["evaluation_id"]: row for row in batch["statuses"]}
                except ProbentiumError as exc:
                    if exc.exit_code != 6:
                        raise
                    self.analysis_currentness = {}
                self.analysis_revision = case.revision
            latest_claim = {obj["data"]["claim"]["id"]: obj["id"] for obj in claim_objects}
            for obj in claim_objects:
                latest = [row for row in evaluations if row["data"].get("claim_object_id") == obj["id"]]
                evaluation = latest[-1] if latest else None
                result = evaluation["data"]["result"]["evaluations"][0] if evaluation else {}
                state = result.get("verdict", "not evaluated")
                if evaluation and (getattr(self, "analysis_currentness", {}).get(evaluation["id"], {}).get("status") != "current" or latest_claim[obj["data"]["claim"]["id"]] != obj["id"]):
                    state = "stale / " + state
                claim_rows.append({"id": obj["id"], "kind": obj["data"]["claim"]["predicate"], "state": state,
                                   "summary": obj["data"]["claim"]["id"], "claim": obj, "evaluation": evaluation})
            self.model["claims"] = claim_rows
            groups = {"scenarios": {"analysis_scenario"}, "review": {"review", "review_decision", "review.import"},
                      "scope": {"eu.service", "eu.supplier", "eu.dependency", "eu.control_test", "eu.applicability", "eu.awareness", "eu.reporting_track", "eu.filing_snapshot", "eu.receipt", "eu.legal_pack", "eu.legal_review", "eu.legal_activation", "eu.control_population", "eu.control_observation", "eu.deadline_evaluation", "eu.obligation_anchor", "eu.requirement_catalogue", "eu.legal_coverage_audit", "unified_graph"},
                      "export": {"packet_export", "export_receipt", "migration"},
                      "retention": {"retention.plan", "retention.hold", "retention.approval", "retention.tombstone"}}
            for view, kinds in groups.items():
                self.model[view] = [{"id": obj["id"], "kind": obj["kind"],
                                     "state": object_state(obj),
                                     "summary": obj["data"].get("logical_id", obj["data"].get("title", obj["data"].get("scope", "revision " + str(obj["revision"])))),
                                     "record": obj} for obj in objects if obj["kind"] in kinds]
            if self.command_detail is not None and self.state["detail"]:
                self.model["detail_lines"] = json_lines(self.command_detail)
            rows = self.rows()
            self.state["selected"] = max(0, min(self.state["selected"], max(0, len(rows) - 1)))
            if self.state["detail"] and rows and self.command_detail is None:
                selected = rows[self.state["selected"]]
                if self.state["view"] == "timeline":
                    try:
                        segments = case.raw_records(selected["id"])
                        original = "\n\n".join(
                            ("" if len(segments) == 1 else "RECORD " + part["record"]["id"] + " / offset " + str(part["record"]["offset"]) + " / " + str(part["record"]["length"]) + " bytes\n")
                            + safe_text(part["bytes"].decode("utf-8", "replace")) for part in segments)
                    except ProbentiumError as exc:
                        if exc.exit_code != 3:
                            raise
                        original = "Unavailable under an approved retention decision. Derived records remain."
                    self.model["detail_lines"] = ["ORIGINAL RECORD / bytes escaped for display", original, "", "NORMALIZED EVENT"] + json_lines(selected)
                else:
                    self.model["detail_lines"] = json_lines(selected)
        return self.model

    def rows(self):
        view = self.state["view"]
        if view == "timeline":
            return self.model.get("events", {}).get("rows", [])
        if view == "evidence":
            return self.model.get("sources", [])
        if view == "incident":
            return [self.model["incident"]] if self.model.get("track") else []
        return self.model.get(view, []) if view in ("controls", "filings", "changes", "claims", "scenarios", "review", "scope", "export", "retention") else []

    def frame(self, width=120, height=36, ascii_only=False):
        self.refresh()
        frame = render(self.model, self.state, width, height, ascii_only=ascii_only)
        frame.update({"view": self.state["view"], "revision": self.model["revision"], "closed": self.closed})
        return frame

    def verify(self):
        with CaseStore(self.path) as case:
            self.integrity = case.verify()
            self.verified_revision = case.revision
        self.state["message"] = "Integrity verification: " + ("partial / authorized evidence unavailable." if self.integrity.get("authorized_unavailable") else "passed; this does not establish factual truth." if self.integrity["ok"] else "FAILED. Inspect case before use.")

    def command(self, value):
        try:
            args = shlex.split(value)
        except ValueError as exc:
            raise ProbentiumError("invalid_command") from exc
        if not args:
            return
        action = args[0]
        if action in VIEWS and len(args) == 1:
            self.navigate(action)
        elif action == "verify" and len(args) == 1:
            self.verify()
        elif action == "replay" and len(args) == 1:
            from .maintenance import replay_case
            with CaseStore(self.path) as case:
                self.command_detail = replay_case(case)
            self.state.update(detail=True, scroll=0)
        elif action == "explain" and len(args) == 2:
            from .investigation import explain
            with CaseStore(self.path) as case:
                self.command_detail = explain(case, args[1])
            self.state.update(detail=True, scroll=0)
        elif action == "witness" and len(args) == 3:
            from .investigation import witness
            with CaseStore(self.path) as case:
                self.command_detail = witness(case, args[1], args[2])
            self.state.update(detail=True, scroll=0)
        elif action == "evaluate" and len(args) == 2:
            from .budgets import run_case_analysis
            execution = run_case_analysis(self.path, "evaluate", {"claim_id": args[1], "expected_revision": self.model["revision"]})
            result = execution["result"]
            with CaseStore(self.path) as case:
                case._expect(execution["case_revision"])
                if self.model.get("synthetic"):
                    marker = case.objects("scenario")[-1]["data"]
                    marker["objects"] = sorted(set(marker["objects"] + [result["id"]]))
                    case.put_object("scenario", marker, expected_revision=case.revision)
            self.navigate("claims")
            self.state["message"] = "New evaluation recorded; previous results remain available."
        elif action == "filter":
            self.state["filter"] = " ".join(args[1:])[:200]
            self.offset = 0
            self.navigate("timeline")
        elif action == "track" and len(args) == 2:
            with CaseStore(self.path) as case:
                if not any(item["data"].get("id") == args[1] for item in case.objects("track")):
                    raise ProbentiumError("track_not_found")
            self.track_id = args[1]
            self.navigate("incident")
        elif action == "prepare" and len(args) == 1:
            with CaseStore(self.path) as case:
                filings = [item for item in case.objects("filing") if item["data"].get("track", {}).get("id") == self.track_id]
                tracks = [item for item in case.objects("track") if item["data"].get("id") == self.track_id]
                if not filings or not tracks:
                    raise ProbentiumError("filing_input_required")
                fields = [{key: value for key, value in field.items() if value is not None} for field in filings[-1]["data"]["fields"]]
                validate_refs(case, fields)
                snapshot = prepare_filing(tracks[-1]["data"], fields, case.revision, utc_now())
                stored = case.put_object("filing", snapshot, expected_revision=self.model["revision"])
                if self.model.get("synthetic"):
                    scenario = case.objects("scenario")[-1]["data"]
                    scenario["objects"] = sorted(set(scenario["objects"] + [stored["id"]]))
                    case.put_object("scenario", scenario, expected_revision=case.revision)
            self.navigate("filings")
            self.state["message"] = "New immutable draft prepared from the latest fields. Nothing submitted."
        else:
            raise ProbentiumError("unknown_command_use_help")

    def navigate(self, view):
        self.command_detail = None
        self.state.update(view=view, selected=0, scroll=0, detail=False)

    def key(self, key):
        if not isinstance(key, str) or len(key) > 64:
            raise ProbentiumError("invalid_key")
        try:
            prompt = self.state["prompt"]
            if prompt is not None:
                if key == "Escape":
                    self.state["prompt"] = None
                elif key == "Enter":
                    self.state["prompt"] = None
                    if prompt.startswith("/"):
                        self.state["filter"] = prompt[1:]
                        self.offset = 0
                        self.navigate("timeline")
                    else:
                        self.command(prompt[1:])
                elif key == "Backspace":
                    self.state["prompt"] = prompt[:-1] if len(prompt) > 1 else None
                elif len(key) == 1 and key.isprintable() and len(prompt) < 201:
                    self.state["prompt"] += key
                return
            if key in "1234567" and len(key) == 1:
                self.navigate(VIEWS[int(key) - 1])
            elif key in "890" and len(key) == 1:
                self.navigate({"8": "claims", "9": "scenarios", "0": "review"}[key])
            elif key in ("?", "F1"):
                self.navigate("help")
            elif key in ("/", ":"):
                self.state["prompt"] = key
            elif key in ("Escape", "Backspace"):
                self.state.update(detail=False, scroll=0)
            elif key == "Enter":
                self.state.update(detail=not self.state["detail"], scroll=0)
            elif key in ("j", "ArrowDown", "k", "ArrowUp"):
                delta = 1 if key in ("j", "ArrowDown") else -1
                if self.state["detail"] or self.state["view"] in ("incident", "help"):
                    self.state["scroll"] = max(0, min(10000, self.state["scroll"] + delta))
                else:
                    self.state["selected"] = max(0, min(len(self.rows()) - 1, self.state["selected"] + delta))
            elif key in ("PageDown", "PageUp", "]", "["):
                delta = 1 if key in ("PageDown", "]") else -1
                if self.state["detail"] or self.state["view"] in ("incident", "help"):
                    self.state["scroll"] = max(0, self.state["scroll"] + delta * 15)
                elif self.state["view"] == "timeline":
                    self.offset = max(0, self.offset + delta * PAGE_SIZE)
                    self.state.update(selected=0, scroll=0)
            elif key == "Home":
                self.state.update(selected=0, scroll=0)
                self.offset = 0
            elif key == "v":
                self.verify()
            elif key == "q":
                self.closed = True
        except ProbentiumError as exc:
            self.state["message"] = "Action stopped: " + exc.code
