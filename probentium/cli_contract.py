"""Exitus, documenta et transportus a sententia separantur."""
import argparse
from contextlib import contextmanager
import json
import re

from .contracts import ProbentiumError, canonical_bytes

SCHEMA = "probentium.cli-result.v1"
EXIT_CODES = {0: "Operation completed; inspect the domain verdict and limitations.",
              2: "Invalid input, usage or an operation that could not be performed.",
              3: "Explicit partial availability or incomplete verification scope.",
              4: "Integrity, signature or binding verification failed.",
              5: "Revision, lock, hold or conflicting-state refusal.",
              6: "Resource budget exceeded or work aborted by a limit.",
              7: "Requested implementation or platform is unsupported.",
              130: "Interrupted; inspect state before retrying a mutating operation."}
STATUSES = {0: "completed", 2: "invalid_input", 3: "partial", 4: "failed_integrity",
            5: "conflict", 6: "resource_limit", 7: "unsupported", 130: "interrupted"}

# Exempla nomina ficta continent; identificatores ex vero casu sumendi sunt.
_BASE = {
    "console": ("Start the native terminal console with a text logo.", "console --ascii", "Startup creates no case. Explicit commands may change case data. Requires a terminal; JSON envelope mode is unsupported."),
    "init": ("Create a private case.", "init CASE --name Synthetic", "Creates a new directory and database; refuses an existing destination."),
    "demo": ("Create a synthetic evidence and reporting exercise.", "demo EXERCISE", "Creates synthetic files and a case; does not submit reports."),
    "status": ("Read case metadata and counts.", "status --case CASE", "Reads the held case revision; does not perform full integrity verification."),
    "sources": ("List acquired artifacts and parse coverage.", "sources --case CASE", "Reads the case; no mutation."),
    "verify": ("Verify stored case integrity and disclose missing evidence.", "verify --case CASE", "Reads and hashes case evidence; no mutation."),
    "browse": ("Open the monochrome terminal workbench.", "browse --case CASE --ascii", "Interactive commands may change the case. Requires a terminal; JSON envelope mode is unsupported."),
    "ingest": ("Acquire a source and record byte provenance.", "ingest --case CASE SOURCE.jsonl --format events --label Synthetic", "Copies evidence and writes checkpointed parse results; interruption may leave resumable progress."),
    "timeline": ("Filter the whole case and return a bounded page.", "timeline --case CASE --limit 100", "Reads a held revision; cursor reuse across revisions is refused."),
    "event": ("Read verified original record bytes as base64.", "event --case CASE EVENT_ID", "Reads and hashes evidence; does not execute its content."),
    "control": ("Assess supplied control observations.", "control --case CASE --input control.json", "Read-only unless --save appends the supplied control. Does not authenticate observation truth."),
    "incident": ("Evaluate a draft operational deadline track.", "incident --case CASE --input track.json --as-of 2026-10-18T00:00:00Z", "Read-only unless --save appends the track; no legal certification or submission."),
    "filing": ("Store an immutable prepared filing snapshot.", "filing --case CASE --track track.json --fields fields.json --cutoff 2026-10-18T00:00:00Z", "Appends a prepared snapshot; never transmits it."),
    "diff": ("Compare two stored filing snapshots.", "diff --case CASE BEFORE_ID AFTER_ID", "Reads the case; no mutation or external correction."),
    "doctor": ("Report local runtime capabilities.", "doctor", "Reads runtime capabilities; does not configure or install dependencies."),
    "formats": ("List supported explicit input formats.", "formats", "No case access or mutation."),
    "schema": ("Print an installed machine-readable input schema.", "schema events-v2", "Reads a local schema; does not fetch a remote schema."),
    "inspect": ("Inspect a bounded source sample without acquisition.", "inspect SOURCE.jsonl --format events --sample-lines 10", "Reads the source sample; does not create or change a case."),
    "migrate": ("Copy a verified schema-1 case to a staged schema-2 case.", "migrate LEGACY_CASE NEW_CASE", "Reads the original and creates a new verified destination; does not overwrite it."),
}
_ACTIONS = {
    'graph build': ('Freeze a typed graph of explicit case dependencies.', '--case CASE', 'Appends a graph bound to a verified snapshot; unknown schemas and references remain visible gaps.'),
    'graph impact': ('Compare a frozen dependency graph with current premises.', '--case CASE --id GRAPH_ID --input changed-ids.json', 'Reads explicit paths and reports review impact; does not declare legal or analytical invalidity.'),
    'governance anchor-status': ('Read the currentness of a supplied obligation anchor.', '--case CASE --id ANCHOR_ID --input as-of.json', 'Reads typed supplied facts; does not infer statutory applicability or authenticate delivery.'),
    'governance anchor-replay': ('Recheck immutable obligation-anchor premises.', '--case CASE --id ANCHOR_ID', 'Reads references and integrity; does not create a legal decision.'),
    'legal import-catalogue': ('Import an explicit requirement and branch catalogue.', '--case CASE --input requirement-catalogue.json', 'Appends a bounded catalogue; an author completeness claim is not independent verification.'),
    'legal audit-coverage': ('Freeze exact structural coverage against a selected catalogue.', '--case CASE --id PACK_ID --catalogue CATALOGUE_ID --as-of 2026-10-19T00:00:00Z', 'Appends missing rules, evidence, branches and source mismatches; does not certify legal completeness.'),
    'legal coverage-status': ('Check the currentness of a frozen coverage audit.', '--case CASE --id AUDIT_ID --as-of 2026-10-19T00:00:00Z', 'Reads current references and preserves the historical result.'),
    'legal coverage-replay': ('Recompute structural coverage from frozen premises.', '--case CASE --id AUDIT_ID', 'Reads stored pack and catalogue; no legal interpretation or external update discovery.'),
    "parser-artifact register": ("Register an explicitly approved exact installed parser distribution and dependencies.", "--case CASE --input parser-registration.json", "Reads supplied wheels, checks installed bytes and stores the supplied operator attestation; does not install or execute wheel content."),
    "parser-artifact verify": ("Recheck locally selected parser distribution bytes.", "--case CASE --id PARSER_APPROVAL_ID", "Reads installed files and the stored manifest; byte equality grants no publisher authenticity or independent approval."),
    "issues status": ("Read parse issues.", "--case CASE", "Reads case issue records."),
    "resume status": ("Resume an interrupted parse run.", "--case CASE --id PARSE_RUN_ID", "Appends checkpointed parse progress."),
    "replay status": ("Replay supported parser and analytical steps.", "--case CASE", "Reads evidence and uses private temporary verification data; no case mutation."),
    "support status": ("Produce an allowlisted diagnostic summary.", "--case CASE", "Reads and verifies the case; output excludes raw evidence and source identifiers."),
    "recover plan": ("Plan removal of unreferenced blobs.", "--case CASE", "Reads and verifies; does not remove data."),
    "recover apply": ("Apply an exact revision-bound recovery plan.", "--case CASE --input recovery-plan.json", "Removes only the validated unreferenced blobs in the plan."),
    "recover copy": ("Recover an interrupted database into a new case.", "--case CASE --output RECOVERED_CASE", "Creates a verified copy; does not mutate the original."),
    "batch plan": ("Fingerprint an explicit list of source acquisitions.", "--input sources.json", "Reads source files; output includes local paths and hashes."),
    "batch execute": ("Execute an approved fingerprint-bound batch plan.", "--case CASE --input batch-plan.json", "Acquires files with per-artifact checkpoints; the batch is not globally atomic."),
    "claim list": ("List immutable claim revisions.", "--case CASE", "Reads the case."),
    "claim add": ("Store a scoped typed claim.", "--case CASE --input claim.json", "Appends a claim object."),
    "claim revise": ("Append a revision of an existing claim.", "--case CASE --id CLAIM_ID --input claim.json", "Appends a revision; preserves the previous claim."),
    "claim evaluate": ("Evaluate and store a claim result.", "--case CASE --id CLAIM_ID", "Appends a result conditional on the held evidence and assumptions."),
    "claim analyze": ("Evaluate and store a claim result.", "--case CASE --id CLAIM_ID", "Alias of claim evaluate; appends a result."),
    "claim explain": ("Explain saved evidence lineage and typed gaps.", "--case CASE --id EVALUATION_ID", "Reads and verifies available evidence; does not reexecute the saved evaluation."),
    "claim stale": ("Check whether a saved evaluation is current.", "--case CASE --id EVALUATION_ID", "Reads current premises without rewriting the historical result."),
    "claim witness": ("Read a verified witness from a saved excerpt.", "--case CASE --id EVALUATION_ID --input witness.json", "Reads original bytes and returns base64; does not execute them."),
    "clock add": ("Store an attributed clock model.", "--case CASE --input clock.json", "Appends a clock premise; does not change acquired bytes."),
    "family add": ("Declare source-family membership and its basis.", "--case CASE --input family.json", "Appends an attributed family assertion."),
    "duplicates add": ("Store explicit duplicate groups.", "--case CASE --input duplicates.json", "Appends declared groups; does not remove evidence."),
    "identity add": ("Store an explicit identity assertion.", "--case CASE --input identity.json", "Appends an assertion; does not identify a person automatically."),
    "scenario run": ("Evaluate an explicit counterfactual scenario.", "--case CASE --input scenario.json", "Stores scenario results; original evidence and premises remain."),
    "sensitivity run": ("Compare bounded source-family removals.", "--case CASE --input sensitivity.json", "Reads and evaluates; no case mutation."),
    "correlate run": ("Evaluate one supported correlation template.", "--case CASE --input correlation.json", "Reads and computes conditional findings; no automatic response."),
    "correlate batch": ("Evaluate a list of correlation templates together.", "--case CASE --input correlations.json", "Reads and computes bounded findings; no automatic response."),
    "analysis compare": ("Compare two saved evaluation results.", "--case CASE --input comparison.json", "Reads case results; no mutation."),
    "graph save": ("Store an explicit acyclic dependency graph.", "--case CASE --input graph.json", "Appends a validated graph object."),
    "graph stale": ("Find descendants of explicitly changed graph nodes.", "--case CASE --id GRAPH_ID --input changed-nodes.json", "Reads the graph; does not infer missing relationships."),
    "governance observe": ("Store an attributed control observation with explicit population.", "--case CASE --input observation.json", "Appends a strict control-observation.v1 record; does not perform or authenticate the real-world test."),
    "governance observation-assess": ("Assess observed results against the declared population and expectations.", "--case CASE --id OBSERVATION_ID", "Reads supplied evidence; missing observations remain unknown."),
    "reporting evaluate-deadline": ("Freeze a reproducible operational deadline calculation.", "--case CASE --id TRACK_ID --input deadline.json", "Stores rule, calendar, anchor and filing-state references; never certifies a legal deadline."),
    "reporting deadline-status": ("Check the currentness of a frozen deadline calculation.", "--case CASE --id DEADLINE_ID --input as-of.json", "Reads current premises; retains the original calculation and its limits."),
    "reporting deadline-replay": ("Recompute a frozen deadline from its recorded premises.", "--case CASE --id DEADLINE_ID", "Reads stored premises; does not submit a filing or approve legal interpretation."),
    "governance status": ("Summarize supplied governance evidence.", "--case CASE", "Reads records; does not certify effectiveness."),
    "governance put": ("Store a typed governance record.", "--case CASE --input governance.json", "Appends an immutable record after reference validation."),
    "governance get": ("Read a governance record.", "--case CASE --id RECORD_ID", "Reads the case."),
    "governance list": ("List governance records.", "--case CASE", "Reads the case; an input document may narrow the kind."),
    "governance assess": ("Assess a declared control-test scope.", "--case CASE --id SCOPE_ID", "Reads supplied observations; does not perform the real-world test."),
    "governance impact": ("Compute explicitly recorded dependency impact.", "--case CASE --input changed-refs.json", "Reads references; does not infer undocumented dependencies."),
    "legal status": ("Read a legal pack's supplied review/currentness state.", "--case CASE --id PACK_ID", "Reads the case; offline unseen amendments remain unknown."),
    "legal import": ("Import a strictly typed legal pack.", "--case CASE --input legal-pack.json", "Appends a pack; import alone grants no legal approval."),
    "legal review": ("Record an evidenced review attestation.", "--case CASE --id PACK_ID --input review-attestation.json", "Appends supplied review evidence; does not invent independent review."),
    "legal activate": ("Explicitly activate a permitted pack mode.", "--case CASE --id PACK_ID --input activation.json", "Appends activation history; draft mode remains unverified legally."),
    "legal diff": ("Compare exact versions of supplied packs.", "--case CASE --input pack-comparison.json", "Reads pack objects; does not fetch legal updates."),
    "legal draft": ("Return a bundled draft Czech source catalogue.", "--case CASE --input regime.json", "Reads draft definitions; no legal certification or case write."),
    "reporting status": ("Read preparation, approval and submission evidence separately.", "--case CASE --id FILING_ID", "Reads stored records; no external portal query."),
    "reporting track": ("Store a reporting track with explicit role and anchors.", "--case CASE --input reporting-track.json", "Appends a track; does not determine legal applicability automatically."),
    "reporting deadlines": ("Plan a track's operational deadlines.", "--case CASE --id TRACK_ID", "Reads the track; legal calendars remain explicitly unverified."),
    "reporting prepare": ("Freeze a recipient-template filing snapshot.", "--case CASE --id TRACK_ID --input filing-fields.json", "Appends a prepared snapshot; never transmits it."),
    "reporting approve": ("Record scoped approval of an exact snapshot.", "--case CASE --id FILING_ID --input filing-approval.json", "Appends a supplied approval; does not submit the filing."),
    "reporting submission": ("Record an attributable assertion of submission.", "--case CASE --id FILING_ID --input submission.json", "Appends evidence of an asserted external action; does not send anything."),
    "reporting receipt": ("Link receipt evidence with explicit strength.", "--case CASE --id SUBMISSION_ID --input receipt.json", "Appends supplied receipt evidence; does not authenticate a portal automatically."),
    "reporting impact": ("Record correction impact between exact snapshots.", "--case CASE --input filing-comparison.json", "Appends an impact record; does not amend external submissions."),
    "retention status": ("Read holds, plans and current evidence availability.", "--case CASE", "Reads current absence separately from historical removal authorizations."),
    "retention hold": ("Place or explicitly release a scoped hold.", "--case CASE --input hold.json", "Appends hold history; releasing a hold does not erase data."),
    "retention plan": ("Prepare a scoped source-byte removal plan.", "--case CASE --input retention-plan.json", "Appends a plan; does not remove evidence."),
    "retention approve": ("Record approval of an exact retention plan.", "--case CASE --id PLAN_ID --input retention-approval.json", "Appends approval acknowledging retained derived data."),
    "retention execute": ("Execute a due approved source-byte removal plan.", "--case CASE --id PLAN_ID --input approved-plan.json", "Removes approved raw source bytes; derived data remains and secure erasure is not promised."),
    "review rationale": ("Store the exact rationale for a signed opinion.", "--case CASE --input rationale.json", "Appends rationale text and returns its digest."),
    "review create": ("Create a revision-bound review and optional signature.", "--case CASE --input review-fields.json --key private-keys/reviewer.seed", "Reads an optional private key; returns a decision without importing it."),
    "review verify": ("Verify a review signature against explicit key trust.", "--case CASE --input signed-review.json --trust trust.json", "Reads supplied trust and signature; does not grant reviewer identity or authority."),
    "review import": ("Import a verified review against resolved dependencies.", "--case CASE --input signed-review.json --trust trust.json", "Appends the review and its current verification evidence."),
    "packet verify": ("Verify packet structure or supported replay.", "--input evidence.pbp --scope structure", "Reads a packet using private verification data; does not restore it."),
    "packet export": ("Export an explicit evidence profile.", "--case CASE --output evidence.pbp", "Creates a new packet; does not publish or send it. Default profile contains private evidence."),
    "packet restore": ("Restore verified packet data into a new case.", "--input evidence.pbp --output RESTORED_CASE", "Validates staging and publishes a new destination without overwrite."),
    "packet encrypt": ("Encrypt a verified packet for explicit age recipients.", "--input encryption.json --output evidence.pbp.age", "Runs locally installed age and creates ciphertext; does not encrypt the local case."),
    "packet decrypt": ("Authenticate and decrypt an age packet locally.", "--input decryption.json --output evidence.pbp", "Reads a private identity and creates verified plaintext; never overwrites the destination."),
    "key generate": ("Generate a local Ed25519 signing seed.", "--output private-keys/reviewer.seed", "Creates a private key file in an existing private directory; output contains public-key metadata only."),
}


def catalog():
    rows = {}
    for key, (purpose, example, effects) in _BASE.items():
        rows[key] = {"purpose": purpose, "example": "probentium " + example, "side_effects": effects}
    for key, (purpose, arguments, effects) in _ACTIONS.items():
        rows[key] = {"purpose": purpose, "example": "probentium " + key + " " + arguments, "side_effects": effects}
    for key, value in rows.items():
        value["output_sensitivity"] = ("Public contract metadata." if key in {"formats", "schema"} else
                                       "Local runtime details; inspect before sharing." if key in {"doctor", "support status"} else
                                       "May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.")
        value["exit_codes"] = dict(EXIT_CODES)
    return rows


class InformationExit(Exception):
    pass


class SafeParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)
        self.information = None

    def error(self, message):
        raise ProbentiumError("invalid_arguments", 2)

    def _print_message(self, message, file=None):
        if self.information is not None:
            self.information.append(message or "")
        elif message:
            super()._print_message(message.encode("ascii", "backslashreplace").decode("ascii"), file)

    def exit(self, status=0, message=None):
        if status:
            raise ProbentiumError("invalid_arguments", 2)
        if message:
            self._print_message(message)
        raise InformationExit()


def command_parsers(parser):
    return {name: child for action in parser._actions if isinstance(action, argparse._SubParsersAction)
            for name, child in action.choices.items()}


def registered_contracts(parser):
    result = set()
    for name, child in command_parsers(parser).items():
        actions = [action for action in child._actions if action.dest == "action"]
        result.update(name + " " + choice for choice in actions[0].choices) if actions else result.add(name)
    return result


def attach_help(parser):
    entries = catalog()
    if registered_contracts(parser) != set(entries):
        raise RuntimeError("cli_contract_coverage_mismatch")
    codes = "\n".join(str(code) + ": " + meaning for code, meaning in EXIT_CODES.items())
    parser.epilog = ("Example: probentium --format json formats\n"
                     "Output sensitivity: command-specific; see COMMAND --help.\n"
                     "Side effects: command-specific; nothing is published automatically.\n"
                     "Global --format json must precede the command. Ingest/inspect --format selects input syntax.\n"
                     "Exit-code meanings (only applicable outcomes are used):\n" + codes)
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    for name, child in command_parsers(parser).items():
        keys = [key for key in entries if key == name or key.startswith(name + " ")]
        child.description = entries[keys[0]]["purpose"] if len(keys) == 1 else "Local " + name + " operations. Each action is documented below."
        child.formatter_class = argparse.RawDescriptionHelpFormatter
        child.epilog = "\n\n".join(key + "\nPurpose: " + entries[key]["purpose"] + "\nExample: " + entries[key]["example"] +
                                  "\nOutput sensitivity: " + entries[key]["output_sensitivity"] +
                                  "\nSide effects: " + entries[key]["side_effects"] for key in keys)
        child.epilog += ("\n\nCASE and *_ID are placeholders for your existing case and returned identifiers. "
                         "Named JSON files must contain the documented typed input. See docs/cli-reference.md.\n"
                         "Exit-code meanings (only applicable outcomes are used):\n" + codes)


def machine_requested(argv):
    index = 0
    while index < len(argv):
        value = argv[index]
        if value == "--format":
            return index + 1 < len(argv) and argv[index + 1] == "json"
        if value.startswith("--format="):
            return value == "--format=json"
        if not value.startswith("-") or value == "--":
            return False
        index += 1
    return False


def capture_information(parser, messages):
    parser.information = messages
    for child in command_parsers(parser).values():
        child.information = messages


@contextmanager
def observe_case(args, case):
    yield
    if getattr(args, "transport_format", None) == "json":
        args._observed_case_revision = case.revision


def exit_code(args, result):
    if not isinstance(result, dict):
        return 0
    if result.get("schema") == "probentium.analysis-execution.v1":
        return exit_code(args, result.get("result"))
    if args.command == "verify" and not result.get("ok"):
        return 4
    if "exit_code" in result:
        code = result["exit_code"]
        if type(code) is not int or code not in STATUSES:
            raise ProbentiumError("invalid_result_exit_code", 4)
        return code
    if "normalization_replay" in result:
        states = {result.get("normalization_replay"), result.get("analysis_replay")}
        return 4 if "failed" in states else 7 if "unsupported" in states else 3 if states - {"passed"} else 0
    nested = result.get("data")
    candidates = [result, result.get("analysis"), nested.get("result") if isinstance(nested, dict) else None]
    return 6 if any(isinstance(value, dict) and value.get("execution_state") == "aborted_limit" for value in candidates) else 0


def envelope(args, data, code=0, error=None):
    verification = None
    command, action = getattr(args, "command", None), getattr(args, "action", None)
    scope = ("case_integrity" if command == "verify" else "case_replay" if command == "replay" else
             "packet_" + args.scope if command == "packet" and action == "verify" else
             "review_signature_and_supplied_trust" if command == "review" and action == "verify" else None)
    if scope and isinstance(data, dict) and error is None:
        verification = {"scope": scope, "result": data}
    errors = []
    if error:
        safe = error if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", error) else "operation_failed"
        errors.append({"code": safe, "exit_code": code})
    elif code:
        errors.append({"code": "operation_reported_nonzero", "exit_code": code})
    execution_limits = []
    observed_resources = getattr(args, "_analysis_resources", None)
    if isinstance(observed_resources, dict):
        execution_limits = ["analysis_memory_" + observed_resources["memory_mode"], "analysis_execution_is_not_a_security_sandbox"]
    return {"schema": SCHEMA, "status": STATUSES[code],
            "case_revision": getattr(args, "_observed_case_revision", None),
            "verification": verification, "data": data,
            "limitations": ["development_preview", "execution_status_is_not_a_domain_verdict",
                            "envelope_does_not_add_verification_or_identity_trust"] + execution_limits, "errors": errors}


def write_json(stream, value):
    canonical_bytes(value)
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    if hasattr(stream, "buffer"):
        stream.buffer.write(raw.encode("ascii"))
    else:
        stream.write(raw)


def reference_markdown():
    lines = ["# Command reference", "", "This reference is generated from the same closed command/action catalogue used by --help. "
             "Run each example with supplied synthetic inputs or replace CASE and *_ID with an existing private case and returned identifiers. "
             "Examples show real accepted arguments; placeholder identifiers do not claim to exist.", "",
             "## Output contract", "", "Default output retains the existing flat JSON contract. Put `--format json` before the command "
             "to select `probentium.cli-result.v1`, containing exactly `schema`, `status`, `case_revision`, `verification`, `data`, `limitations` and `errors`. "
             "Ingest/inspect's later `--format` still selects the source format.", "",
             "Command receipts go to stdout, including partial or failed verification receipts with their nonzero exit code. "
             "Usage errors, exceptions and interruptions produce an error envelope on stderr and no stdout. No progress messages mix with data. "
             "Help and version are informational data in JSON mode. Interactive browse rejects JSON mode before opening the terminal.", "",
             "Transport is ASCII-escaped JSON; decoding recovers the original Unicode values. Signature and object-identity canonicalization is unchanged. "
             "`status` describes execution, never the truth of a claim. `case_revision` is recorded only inside the actual operation's held case context, "
             "not copied from an arbitrary result object or obtained by reopening the case. Otherwise it is null. "
             "`verification` contains a scoped explicit verify/replay receipt only; otherwise it is null. Null is not a verification pass.", "",
             "`completed` maps to 0; `invalid_input` to 2; `partial` to 3; `failed_integrity` to 4; `conflict` to 5; "
             "`resource_limit` to 6; `unsupported` to 7; `interrupted` to 130. Error codes contain no input values or suggested commands containing secrets.", "",
             "## Input documents", "", "All named JSON files are operator-supplied, closed typed documents, not automatically generated facts. "
             "See [events v2](events-v2.md), [the development guide](development-preview.md) and "
             "[governance/reporting examples](r1-eu-status.md) for concrete schemas and workflows. "
             "`witness.json` contains an `event_id`; `comparison.json` contains `before`/`after` saved evaluation IDs; "
             "`changed-nodes.json` contains `changed_ids`; `changed-refs.json` contains `changed_refs`; "
             "`regime.json` contains `regime`; `rationale.json` contains `text`. "
             "Encryption input contains `packet` and `recipients`; decryption input contains `packet` and `identity_file`. "
             "Keep private-key material out of arguments and source evidence. The signing-key parent must already have private permissions.", ""]
    for key, item in catalog().items():
        lines.extend(["## " + key, "", item["purpose"], "", "```sh", item["example"], "```", "",
                      "Output sensitivity: " + item["output_sensitivity"], "", "Side effects: " + item["side_effects"], "",
                      "Exit codes (only applicable outcomes are used):", ""])
        lines.extend("- `" + str(code) + "`: " + meaning for code, meaning in EXIT_CODES.items())
        lines.append("")
    return "\n".join(lines)
