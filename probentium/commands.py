"""Mandata publica ad idem nucleum ducunt."""
from .contracts import ProbentiumError, utc_now
from .cli_contract import observe_case


def register(sub):
    for name in ("doctor", "formats"):
        sub.add_parser(name)
    schema = sub.add_parser("schema", help="Print the installed machine-readable input contract")
    schema.add_argument("name", choices=("events-v2", "control-observation.v1", "deadline-plan.v1",))
    inspect = sub.add_parser("inspect", help="Inspect a bounded sample without importing it")
    inspect.add_argument("file")
    inspect.add_argument("--format")
    inspect.add_argument("--resource-policy", help="Explicit versioned resource policy JSON")
    inspect.add_argument("--sample-lines", type=int, default=100)
    migrate = sub.add_parser("migrate", help="Migrate a schema-1 local case to a new directory")
    migrate.add_argument("source")
    migrate.add_argument("destination")
    migrate.add_argument("--resource-policy", help="Explicit versioned resource policy JSON")
    actions = {"issues": ("status",), "resume": ("status",), "replay": ("status",), "support": ("status",),
               "recover": ("plan", "apply", "copy"), "batch": ("plan", "execute"),
               "parser-artifact": ("register", "verify"),
               "claim": ("list", "add", "revise", "evaluate", "analyze", "explain", "stale", "witness"),
               "clock": ("add",), "family": ("add",), "duplicates": ("add",), "identity": ("add",),
               "scenario": ("run",), "sensitivity": ("run",), "correlate": ("run", "batch"),
               "analysis": ("compare",), "graph": ("save", "stale", "build", "impact"),
               "governance": ("status", "put", "get", "list", "assess", "impact", "observe", "observation-assess", "anchor-status", "anchor-replay"),
               "legal": ("status", "import", "review", "activate", "diff", "draft", "import-catalogue", "audit-coverage", "coverage-status", "coverage-replay"),
               "reporting": ("status", "track", "deadlines", "prepare", "approve", "submission", "receipt", "impact", "evaluate-deadline", "deadline-status", "deadline-replay"),
               "retention": ("status", "hold", "plan", "approve", "execute"), "review": ("create", "verify", "import", "rationale"),
               "packet": ("verify", "export", "restore", "encrypt", "decrypt"), "key": ("generate",)}
    for name in actions:
        p = sub.add_parser(name)
        p.add_argument("action", nargs="?", choices=actions[name], default=actions[name][0])
        p.add_argument("--case")
        p.add_argument("--input", "--spec", dest="input", help="Strict JSON command document")
        p.add_argument("--id", help="Stored object identifier")
        p.add_argument("--expect-revision", "--expected-revision", dest="expect_revision", type=int)
        p.add_argument("--output")
        p.add_argument("--key", help="Private signing key file")
        p.add_argument("--trust", help="Explicit trusted-key JSON file")
        p.add_argument("--profile", default="private_full")
        p.add_argument("--scope", choices=("structure", "replay"), default="structure")
        p.add_argument("--require-signature", action="store_true")
        p.add_argument("--require-trusted-key", action="store_true")
        if name in {"batch", "resume", "replay", "recover", "packet"}:
            p.add_argument("--resource-policy", help="Explicit versioned resource policy JSON for this operation")
        if name in {"resume", "replay"}:
            p.add_argument("--parser-artifact", help="Explicitly selected registered parser approval ID")
        if name == "legal":
            p.add_argument("--catalogue", help="Exact imported requirement catalogue ID")
            p.add_argument("--as-of", help="Explicit review instant in UTC")
        if name == "packet":
            p.add_argument("--parser-manifest", help="Explicit distribution manifest for local replay verification only")
        if name in {"claim", "correlate", "scenario", "sensitivity"}:
            p.add_argument("--resource-mode", choices=("strict", "monitored"), help="Analysis child process resource enforcement")
            p.add_argument("--analysis-limits", help="Strict versioned JSON analysis budget overrides")
            p.add_argument("--execution-receipt", action="store_true", help="Return the domain result together with measured process limits")


def dispatch(args, read_input):
    from .store import CaseStore
    from . import intake, maintenance
    resource_policy = read_input(args.resource_policy) if getattr(args, "resource_policy", None) else None
    if resource_policy is not None:
        from .limits import validate
        resource_policy = validate(resource_policy)
    if args.command == "doctor":
        return intake.doctor()
    if args.command == "formats":
        from .adapters import formats
        return formats()
    if args.command == "schema":
        import sys
        from pathlib import Path
        installed = Path(sys.prefix) / "share/probentium/schemas" / (args.name + ".schema.json")
        source = Path(__file__).resolve().parents[1] / "schemas" / (args.name + ".schema.json")
        return read_input(installed if installed.is_file() else source)
    if args.command == "inspect":
        return intake.inspect_file(args.file, format_name=args.format, sample_lines=args.sample_lines, resource_policy=resource_policy)
    if args.command == "migrate":
        return maintenance.migrate_v1(args.source, args.destination, resource_policy=resource_policy)
    binary_packet = args.command == "packet" and args.action in {"verify", "restore"}
    document = read_input(args.input) if args.input and not binary_packet else None
    action, command = args.action, args.command
    if (args.require_signature or args.require_trusted_key) and (command != "packet" or action not in {"verify", "restore", "decrypt"}):
        raise ProbentiumError("verification_options_require_packet_verification")
    if args.scope != "structure" and (command != "packet" or action != "verify"):
        raise ProbentiumError("replay_scope_requires_packet_verify")
    if document is not None and not isinstance(document, (dict, list)):
        raise ProbentiumError("command_document_required")
    if command == "key":
        from .signatures import generate_key
        if action != "generate" or not args.output:
            raise ProbentiumError("key_generate_output_required")
        return generate_key(args.output)
    if command == "batch" and action == "plan":
        return intake.batch_plan(document, resource_policy=resource_policy)
    if command == "packet":
        from . import exchange, signatures
        trust = signatures.load_trust_store(args.trust) if args.trust else None
        if action == "verify":
            if not args.input:
                raise ProbentiumError("packet_input_required")
            selected_manifest = read_input(args.parser_manifest) if args.parser_manifest else None
            if selected_manifest is not None:
                if args.scope != "replay":
                    raise ProbentiumError("parser_manifest_requires_replay_scope")
                from .parser_artifact import verify_manifest
                verify_manifest(selected_manifest)
            def selected_replay(manifest, snapshot, reader):
                return maintenance.replay_packet(manifest, snapshot, reader, approved_manifest=selected_manifest, resource_policy=resource_policy)
            return exchange.verify_packet(args.input, scope=args.scope, trust_store=trust,
                                          require_signature=args.require_signature, require_trusted_key=args.require_trusted_key,
                                          replay=selected_replay, resource_policy=resource_policy)
        if getattr(args, "parser_manifest", None):
            raise ProbentiumError("parser_manifest_requires_packet_verify")
        if action == "restore":
            if not args.input or not args.output:
                raise ProbentiumError("packet_input_output_required")
            return maintenance.restore_packet(args.input, args.output, trust_store=trust, require_signature=args.require_signature, require_trusted_key=args.require_trusted_key, resource_policy=resource_policy)
        if action == "encrypt":
            if not isinstance(document, dict) or set(document) != {"packet", "recipients"} or not args.output:
                raise ProbentiumError("packet_encrypt_document_required")
            return exchange.encrypt_packet(document["packet"], args.output, document["recipients"], trust_store=trust, resource_policy=resource_policy)
        if action == "decrypt":
            if not isinstance(document, dict) or set(document) != {"packet", "identity_file"} or not args.output:
                raise ProbentiumError("packet_decrypt_document_required")
            return exchange.decrypt_packet(document["packet"], args.output, document["identity_file"], trust_store=trust, require_trusted_key=args.require_trusted_key, resource_policy=resource_policy)
    if not args.case:
        raise ProbentiumError("case_required")
    if command == "recover" and action == "copy":
        if not args.output:
            raise ProbentiumError("recovery_output_required")
        return maintenance.recover_copy(args.case, args.output, resource_policy=resource_policy)
    analysis_action = (command == "claim" and action in {"evaluate", "analyze"}) or command in {"correlate", "scenario", "sensitivity"}
    if analysis_action:
        from .budgets import run_case_analysis
        if command == "claim":
            if document is not None:
                raise ProbentiumError("claim_evaluation_takes_no_document")
            operation, arguments = "evaluate", {"claim_id": args.id, "expected_revision": args.expect_revision}
        elif command == "correlate" and action == "batch":
            if not isinstance(document, list):
                raise ProbentiumError("correlation_request_list_required")
            operation, arguments = "correlate_many", {"requests": document, "expected_revision": args.expect_revision}
        elif command == "correlate":
            if not isinstance(document, dict) or not {"template", "window_us"} <= set(document) or set(document) - {"template", "window_us", "threshold"}:
                raise ProbentiumError("correlation_document_required")
            operation, arguments = "correlate", {**document, "expected_revision": args.expect_revision}
        elif command == "scenario":
            if not isinstance(document, dict) or set(document) != {"claim_ids", "scenario"}:
                raise ProbentiumError("scenario_document_required")
            operation, arguments = "scenario", {**document, "expected_revision": args.expect_revision}
        else:
            if not isinstance(document, dict) or "claim_ids" not in document or set(document) - {"claim_ids", "family_ids", "limit"}:
                raise ProbentiumError("sensitivity_document_required")
            operation, arguments = "sensitivity", {**document, "expected_revision": args.expect_revision}
        limits = read_input(args.analysis_limits) if args.analysis_limits else None
        receipt = run_case_analysis(args.case, operation, arguments, limits=limits, resource_mode=args.resource_mode or "monitored")
        args._observed_case_revision = receipt["case_revision"]
        args._analysis_resources = receipt["resources"]
        return receipt if args.execution_receipt else receipt["result"]
    if any(getattr(args, name, None) for name in ("resource_mode", "analysis_limits", "execution_receipt")):
        raise ProbentiumError("analysis_options_require_analysis_action")
    with CaseStore(args.case, resource_policy=resource_policy) as case, observe_case(args, case):
        kw = {"expected_revision": args.expect_revision}
        if command == "issues":
            return case.issues(args.id)
        if command == "resume":
            return case.resume(args.id, parser_approval_id=args.parser_artifact, **kw)
        if command == "replay":
            return maintenance.replay_case(case, parser_approval_id=args.parser_artifact, resource_policy=resource_policy)
        if command == "parser-artifact":
            from . import parser_artifact
            if action == "register":
                fields = {"product_wheel", "product_sha256", "dependency_wheels", "approved_by", "reason"}
                if not isinstance(document, dict) or set(document) != fields:
                    raise ProbentiumError("parser_registration_document_required")
                return parser_artifact.register(case, **document, **kw)
            if document is not None:
                raise ProbentiumError("parser_verification_takes_no_document")
            manifest = parser_artifact.resolve_approval(case, args.id)
            return parser_artifact.verify_manifest(manifest)
        if command == "support":
            check = case.verify()
            return {"schema": "probentium.support.v1", "runtime": intake.doctor(), "case_schema": case.meta["schema_version"],
                    "source_count": len(case.sources()), "event_count": case.query_events(limit=1)["total"],
                    "object_count": len(case.objects()), "integrity": "passed" if check["ok"] else "failed",
                    "availability": check.get("completeness", "complete"),
                    "authorized_unavailable_count": len(check.get("authorized_unavailable", [])),
                    "issue_codes": [row["code"] for row in check["issues"]], "evidence_included": False,
                    "paths_included": False, "environment_included": False, "identifiers_included": False}
        if command == "recover":
            return maintenance.apply_recovery(case, document, **kw) if action == "apply" else maintenance.recovery_plan(case)
        if command == "batch":
            if action != "execute":
                raise ProbentiumError("invalid_batch_action")
            return intake.execute_batch(case, document, **kw)
        if command == "packet":
            from .exchange import export_case
            if action != "export" or not args.output:
                raise ProbentiumError("packet_export_output_required")
            fields = document or {}
            if set(fields) - {"packet_schema", "object_ids", "field_allowlist", "purpose", "pseudonym_key_file"}:
                raise ProbentiumError("invalid_packet_export_options")
            return export_case(case, args.output, profile=args.profile, signing_key=args.key, resource_policy=resource_policy, **fields)
        if command in {"claim", "clock", "family", "duplicates", "identity", "scenario", "sensitivity", "correlate", "analysis", "graph"}:
            from . import investigation as inv
            if command == "claim":
                if action in {"list", "status"}:
                    return {"claims": inv.list_claims(case)}
                if action in {"add", "revise"}:
                    return inv.save_claim(case, document, previous_id=args.id if action == "revise" else None, **kw)
                if action in {"evaluate", "analyze"}:
                    return inv.evaluate(case, args.id, **kw)
                if action == "explain":
                    return inv.explain(case, args.id)
                if action == "stale":
                    return inv.stale_status(case, args.id)
                if action == "witness":
                    if not isinstance(document, dict) or set(document) != {"event_id"}:
                        raise ProbentiumError("witness_event_document_required")
                    return inv.witness(case, args.id, document["event_id"])
            if command == "clock" and action == "add":
                return inv.save_clock(case, document["model"], document["artifact_ids"], **kw)
            if command == "family" and action == "add":
                return inv.save_family(case, document["family_id"], document["artifact_ids"], document["basis_refs"], document["rationale"], **kw)
            if command == "duplicates" and action == "add":
                return inv.save_duplicates(case, document, **kw)
            if command == "identity" and action == "add":
                return inv.save_identity(case, document, **kw)
            if command == "scenario" and action == "run":
                return inv.run_scenario(case, document["claim_ids"], document["scenario"], **kw)
            if command == "sensitivity":
                return inv.sensitivity(case, document["claim_ids"], family_ids=document.get("family_ids"), limit=document.get("limit", 64))
            if command == "correlate":
                if action == "batch":
                    if not isinstance(document, list):
                        raise ProbentiumError("correlation_request_list_required")
                    return inv.correlate_many(case, document)
                return inv.correlate(case, document["template"], window_us=document["window_us"], threshold=document.get("threshold", 5))
            if command == "analysis":
                from .claims import compare_results
                if not isinstance(document, dict) or set(document) != {"before", "after"}:
                    raise ProbentiumError("analysis_comparison_document_required")
                before, after = (case.get_object(document[key]) for key in ("before", "after"))
                if before["kind"] != "evaluation" or after["kind"] != "evaluation":
                    raise ProbentiumError("evaluation_object_required")
                return compare_results(before["data"]["result"], after["data"]["result"])
            if command == "graph":
                if action in {"build", "impact"}:
                    from . import dependency_graph
                    if action == "build":
                        options = {} if document is None else document
                        if not isinstance(options, dict) or set(options) - {"artifact_ids", "object_ids"}:
                            raise ProbentiumError("case_graph_document_required")
                        return dependency_graph.build_case_graph(case, **options, **kw)
                    if not isinstance(document, dict) or set(document) != {"changed_ids"}:
                        raise ProbentiumError("case_graph_impact_document_required")
                    return dependency_graph.impact(case, args.id, document["changed_ids"], **kw)
                if action == "save":
                    if not isinstance(document, dict) or set(document) != {"nodes", "edges"}:
                        raise ProbentiumError("dependency_graph_document_required")
                    return inv.save_dependency_graph(case, document["nodes"], document["edges"], **kw)
                graph = case.get_object(args.id)
                if graph["kind"] != "dependency_graph" or not isinstance(document, dict) or set(document) != {"changed_ids"}:
                    raise ProbentiumError("dependency_graph_document_required")
                return {"stale_descendants": inv.stale_descendants(graph["data"]["nodes"], graph["data"]["edges"], document["changed_ids"])}
        if command == "governance":
            from . import governance as gov
            if action == "anchor-status":
                if not isinstance(document, dict) or set(document) != {"as_of"}:
                    raise ProbentiumError("anchor_status_document_required")
                return gov.obligation_anchor_status(case, args.id, document["as_of"])
            if action == "anchor-replay":
                if document is not None:
                    raise ProbentiumError("anchor_replay_takes_no_document")
                return gov.replay_obligation_anchor(case, args.id)
            if action == "observe":
                return gov.put_control_observation(case, document, **kw)
            if action == "observation-assess":
                if document is not None:
                    raise ProbentiumError("observation_assessment_takes_no_document")
                return gov.assess_control_observation(case, args.id)
            if action == "put":
                return gov.put_record(case, document["kind"], document["data"], **kw)
            if action == "get":
                return gov.get_record(case, args.id)
            if action == "list":
                return {"records": gov.list_records(case, kind=document.get("kind") if document else None)}
            if action == "assess":
                return gov.assess_scope(case, args.id, (document or {}).get("as_of", utc_now()))
            if action == "impact":
                return gov.dependency_impact(case, document["changed_refs"])
            if action == "status":
                return gov.dashboard(case, (document or {}).get("as_of", utc_now()))
        if command == "legal":
            from . import legalpacks as legal
            if action == "import-catalogue":
                return legal.import_catalogue(case, document, **kw)
            if action == "audit-coverage":
                if document is not None or not args.catalogue or not args.as_of:
                    raise ProbentiumError("coverage_audit_arguments_required")
                return legal.audit_coverage(case, args.id, args.catalogue, args.as_of, **kw)
            if action == "coverage-status":
                if document is not None or not args.as_of:
                    raise ProbentiumError("coverage_status_arguments_required")
                return legal.coverage_status(case, args.id, args.as_of)
            if action == "coverage-replay":
                if document is not None:
                    raise ProbentiumError("coverage_replay_takes_no_document")
                return legal.replay_coverage(case, args.id)
            if action == "import":
                return legal.import_pack(case, document, **kw)
            if action == "review":
                return legal.review_pack(case, args.id, document, **kw)
            if action == "activate":
                return legal.activate_pack(case, args.id, document, **kw)
            if action == "status":
                return legal.pack_status(case, args.id, (document or {}).get("as_of", utc_now()))
            if action == "diff":
                return legal.pack_diff(case.get_object(document["before"])["data"], case.get_object(document["after"])["data"])
            if action == "draft":
                return legal.draft_czech_pack(document["regime"])
        if command == "reporting":
            from . import reporting as rep
            if action == "evaluate-deadline":
                if (not isinstance(document, dict) or not {"rule_id", "calendar_id", "as_of"} <= set(document)
                        or set(document) - {"rule_id", "calendar_id", "as_of", "exception"}):
                    raise ProbentiumError("deadline_evaluation_document_required")
                return rep.evaluate_deadline(case, args.id, **document, **kw)
            if action == "deadline-status":
                if not isinstance(document, dict) or set(document) != {"as_of"}:
                    raise ProbentiumError("deadline_status_as_of_required")
                return rep.deadline_status(case, args.id, document["as_of"])
            if action == "deadline-replay":
                if document is not None:
                    raise ProbentiumError("deadline_replay_takes_no_document")
                return rep.replay_deadline(case, args.id)
            if action == "track":
                return rep.create_track(case, document, **kw)
            if action == "deadlines":
                return rep.deadlines(case, args.id, (document or {}).get("as_of", utc_now()))
            if action == "prepare":
                return rep.prepare(case, args.id, document["fields"], document["cutoff"], **kw)
            if action == "approve":
                return rep.approve(case, args.id, document, **kw)
            if action == "submission":
                return rep.record_submission(case, args.id, document, **kw)
            if action == "receipt":
                return rep.link_receipt(case, args.id, document, **kw)
            if action == "status":
                return rep.filing_status(case, args.id)
            if action == "impact":
                return rep.correction_impact(case, document["before"], document["after"], changed_refs=document.get("changed_refs", []), **kw)
        if command == "retention":
            from . import retention as ret
            if action == "hold":
                return ret.hold(case, document["artifact_ids"], document["actor"], document["rationale"], released_hold_id=document.get("released_hold_id"), **kw)
            if action == "plan":
                return ret.plan(case, document["artifact_ids"], document["actor"], document["rationale"], document["retain_until"], policy=document.get("policy"), **kw)
            if action == "approve":
                return ret.approve(case, args.id, document["actor"], document["rationale"], **kw)
            if action == "execute":
                return ret.execute(case, args.id, document["approval_id"], **kw)
            if action == "status":
                return ret.status(case)
        if command == "review":
            from . import reviews, signatures
            trust = signatures.load_trust_store(args.trust) if args.trust else None
            if action == "rationale":
                if not isinstance(document, dict) or set(document) != {"text"}:
                    raise ProbentiumError("review_rationale_document_required")
                digest = reviews.rationale_digest(document["text"])
                return {"rationale_digest": digest, "stored": case.put_object("review_rationale", document, **kw)}
            if action == "create":
                decision = reviews.create_decision(**document)
                return {"decision": decision, "envelope": reviews.sign_review(decision, args.key) if args.key else None}
            if action == "verify":
                return reviews.verify_review(document["decision"], document["envelope"], trust_store=trust)
            if action == "import":
                from .investigation import resolve_review_references
                return reviews.import_review(case, document["decision"], document["envelope"], trust_store=trust, reference_resolver=resolve_review_references, **kw)
    raise ProbentiumError("unsupported_command_action")
