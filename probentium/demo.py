"""Exempla ficta sunt; calculi tamen veri sunt."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .contracts import canonical_bytes, object_digest, ProbentiumError
from .regulatory import prepare_filing
from .store import CaseStore

DEMO_TIME = "2026-10-18T12:00:00Z"


def make_demo(directory, *, extended=False):
    root = Path(directory)
    if root.exists():
        raise ProbentiumError("demo_destination_exists")
    root.mkdir(mode=0o700, parents=True)
    start = datetime(2026, 10, 18, 9, 0, tzinfo=timezone.utc)
    events = []
    for index in range(126):
        events.append({"timestamp": (start + timedelta(seconds=index * 4)).isoformat().replace("+00:00", "Z"),
                       "kind": "auth.failure", "host": "cedar-07", "actor": "supplier-service",
                       "src_ip": "192.0.2.41", "action": "login", "attributes": {"service": "ssh"}})
    events.extend([
        {"timestamp": "2026-10-18T09:09:12Z", "kind": "auth.success", "host": "cedar-07", "actor": "supplier-service", "src_ip": "192.0.2.41", "action": "login"},
        {"timestamp": "2026-10-18T09:09:15Z", "kind": "process.exec", "host": "cedar-07", "actor": "supplier-service", "path": "/usr/bin/id", "action": "execute"},
        {"timestamp": "2026-10-18T09:12:00Z", "kind": "network.connect", "host": "cedar-07", "dst_ip": "198.51.100.17", "attributes": {"dst_port": 443, "protocol": "tcp"}},
        {"timestamp": None, "kind": "file.observed", "host": "cedar-07", "path": "/srv/archive/inventory.csv", "action": "observed"},
    ])
    source = root / "activity.jsonl"
    with source.open("xb") as stream:
        source.chmod(0o600)
        stream.write(b"\n".join(canonical_bytes(row) for row in events) + b"\n")
    with CaseStore.create(root / "case", "CEDAR / 007") as case:
        case.ingest(source, "events", "Synthetic supplier access records")
        rows = case.query_events(limit=200)["rows"]
        success = next(row["id"] for row in rows if row["kind"] == "auth.success")
        ref = [success]
        mfa_test = root / "mfa-exercise.jsonl"
        tests = [
            {"timestamp": "2026-10-18T10:20:00Z", "kind": "generic", "host": "cedar-07", "actor": "supplier-service", "action": "mfa-exercise",
             "attributes": {"service": "ssh", "result": "without_second_factor_allowed", "unit": "SYNTHETIC / MFA-01 v1: configured=true; enforced=false; attempt login without a second factor"}},
            {"timestamp": "2026-10-18T10:21:00Z", "kind": "generic", "host": "cedar-07", "actor": "operator", "action": "mfa-exercise",
             "attributes": {"service": "console", "result": "without_factor_denied_valid_factor_accepted", "unit": "SYNTHETIC / MFA-01 v1: configured=true; enforced=true; attempt login without a second factor, then with a valid factor"}},
        ]
        with mfa_test.open("xb") as stream:
            mfa_test.chmod(0o600)
            stream.write(b"\n".join(canonical_bytes(row) for row in tests) + b"\n")
        case.ingest(mfa_test, "events", "Synthetic MFA exercise observations")
        mfa_rows = case.query_events(query="mfa-exercise", limit=10)["rows"]
        mfa_refs = {row["actor"]: [row["id"]] for row in mfa_rows}
        case.put_object("control", {"id": "C-01", "title": "MFA on supplier access paths", "kind": "mfa", "population": 3,
                                   "evidence_refs": [], "observations": [
                                       {"id": "O-01", "subject": "supplier-service / ssh", "configured": True, "enforced": False, "evidence_refs": mfa_refs["supplier-service"]},
                                       {"id": "O-02", "subject": "operator / console", "configured": True, "enforced": True, "evidence_refs": mfa_refs["operator"]}]})
        case.put_object("control", {"id": "C-02", "title": "Restore exercise evidence", "kind": "restore", "population": 2,
                                   "rto_seconds": 3600, "rpo_seconds": 900, "evidence_refs": [], "observations": []})
        case.put_object("control", {"id": "C-03", "title": "Remediation retest coverage", "kind": "remediation", "population": None,
                                   "evidence_refs": [], "observations": []})
        track = {"id": "I-007", "title": "Supplier access investigation", "profile": "cz-nis2-higher", "ongoing": True,
                 "anchors": {"awareness": "2026-10-18T10:00:00Z", "submitted": None}}
        case.put_object("track", track)
        fields = [
            {"id": "summary", "value": "Supplier access under investigation; authorization is unresolved.", "basis": "human_attested", "refs": [], "reason": "Synthetic exercise statement, not a finding of compromise."},
            {"id": "successful_login", "value": "A successful login record is present.", "basis": "source_backed", "refs": ref},
            {"id": "affected_accounts", "value": 1, "basis": "human_attested", "refs": [], "reason": "Initial scope declared for the exercise."},
            {"id": "clock_alignment", "basis": "unknown", "refs": [], "reason": "No clock calibration evidence supplied."},
        ]
        first = prepare_filing(track, fields, case.revision, "2026-10-18T10:15:00Z")
        case.put_object("filing", first)
        fields[2] = {"id": "affected_accounts", "value": 2, "basis": "human_attested", "refs": [], "reason": "Revised scope declared by the exercise analyst; independent confirmation pending."}
        second = prepare_filing(track, fields, case.revision, "2026-10-18T11:30:00Z")
        case.put_object("filing", second)
        case.put_object("scenario", {"synthetic": True, "as_of": DEMO_TIME,
                                    "title": "Supplier access investigation",
                                    "artifacts": sorted(item["id"] for item in case.sources()),
                                    "source_digest": object_digest(case.sources()),
                                    "objects": sorted(item["id"] for item in case.objects()),
                                    "limits": ["Fictional evidence and organization.", "Clock alignment is unknown; recorded order is not a causal finding."]})
        demonstration = None
        if extended:
            from .investigation import build_demonstration
            demonstration = build_demonstration(case, expected_revision=case.revision)
            from .reporting import build_demonstration as build_reporting_demonstration
            demonstration["reporting"] = build_reporting_demonstration(case, acknowledged_synthetic=True, expected_revision=case.revision)
            from .governance import append_demo_control_observations
            demonstration["control_observations"] = append_demo_control_observations(
                case, demonstration["reporting"]["service_ref"], case.sources()[0]["id"],
                {"start": "2026-10-18T09:00:00Z", "end": "2026-10-18T12:00:00Z"})
            demonstration["review"] = _review_exercise(case, demonstration)
            from .dependency_graph import build_case_graph
            demonstration["dependency_graph"] = build_case_graph(case, expected_revision=case.revision)["id"]
            marker = case.objects("scenario")[-1]["data"]
            marker["objects"] = sorted(item["id"] for item in case.objects() if item["kind"] != "scenario")
            marker["source_digest"] = object_digest(case.sources())
            marker["limits"] = ["Fictional evidence and organization.", "Clock models are explicit exercise assumptions, not measured calibration."]
            case.put_object("scenario", marker, expected_revision=case.revision)
        check = case.verify()
        if not check["ok"]:
            raise ProbentiumError("demo_integrity_failure", 4)
        return {"case": str(root / "case"), "synthetic": True, "events": case.query_events(limit=1)["total"], "integrity": check, "demonstration": demonstration}


def _review_exercise(case, demonstration):
    """Signum verum est; persona ficta abstinet nec approbationem simulat."""
    import tempfile
    from . import reviews, signatures
    from .investigation import resolve_review_references
    text = "Synthetic exercise only. This generated test key represents no independent reviewer. Abstain: no approval or legal attestation is given."
    case.put_object("review_rationale", {"text": text}, expected_revision=case.revision)
    claim = case.get_object(demonstration["claim_id"])
    evaluation = case.get_object(demonstration["aligned_evaluation_id"])["data"]
    with tempfile.TemporaryDirectory(prefix="review-exercise-") as directory:
        key = Path(directory) / "seed.bin"
        public = signatures.generate_key(key)
        decision = reviews.create_decision(claim["id"], claim["revision"], evaluation["result"]["digest"],
                                           evaluation["data_fingerprint"], public["key_id"], "abstain", reviews.rationale_digest(text))
        receipt = reviews.import_review(case, decision, reviews.sign_review(decision, key),
                                        reference_resolver=resolve_review_references, expected_revision=case.revision)
    return {"review_object_id": receipt["stored"]["id"], "disposition": "abstain", "key_trust": receipt["verification"]["key_trust"],
            "approval_effect": receipt["approval_effect"], "synthetic": True, "independent_review": False}
