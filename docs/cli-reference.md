# Command reference

This reference is generated from the same closed command/action catalogue used by --help. Run each example with supplied synthetic inputs or replace CASE and *_ID with an existing private case and returned identifiers. Examples show real accepted arguments; placeholder identifiers do not claim to exist.

## Output contract

Default output retains the existing flat JSON contract. Put `--format json` before the command to select `probentium.cli-result.v1`, containing exactly `schema`, `status`, `case_revision`, `verification`, `data`, `limitations` and `errors`. Ingest/inspect's later `--format` still selects the source format.

Command receipts go to stdout, including partial or failed verification receipts with their nonzero exit code. Usage errors, exceptions and interruptions produce an error envelope on stderr and no stdout. No progress messages mix with data. Help and version are informational data in JSON mode. Interactive browse rejects JSON mode before opening the terminal.

Transport is ASCII-escaped JSON; decoding recovers the original Unicode values. Signature and object-identity canonicalization is unchanged. `status` describes execution, never the truth of a claim. `case_revision` is recorded only inside the actual operation's held case context, not copied from an arbitrary result object or obtained by reopening the case. Otherwise it is null. `verification` contains a scoped explicit verify/replay receipt only; otherwise it is null. Null is not a verification pass.

`completed` maps to 0; `invalid_input` to 2; `partial` to 3; `failed_integrity` to 4; `conflict` to 5; `resource_limit` to 6; `unsupported` to 7; `interrupted` to 130. Error codes contain no input values or suggested commands containing secrets.

## Input documents

All named JSON files are operator-supplied, closed typed documents, not automatically generated facts. See [events v2](events-v2.md), [the development guide](development-preview.md) and [governance/reporting examples](r1-eu-status.md) for concrete schemas and workflows. `witness.json` contains an `event_id`; `comparison.json` contains `before`/`after` saved evaluation IDs; `changed-nodes.json` contains `changed_ids`; `changed-refs.json` contains `changed_refs`; `regime.json` contains `regime`; `rationale.json` contains `text`. Encryption input contains `packet` and `recipients`; decryption input contains `packet` and `identity_file`. Keep private-key material out of arguments and source evidence. The signing-key parent must already have private permissions.

## console

Start the native terminal console with a text logo.

```sh
probentium console --ascii
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Startup creates no case. Explicit commands may change case data. Requires a terminal; JSON envelope mode is unsupported.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## init

Create a private case.

```sh
probentium init CASE --name Synthetic
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Creates a new directory and database; refuses an existing destination.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## demo

Create a synthetic evidence and reporting exercise.

```sh
probentium demo EXERCISE
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Creates synthetic files and a case; does not submit reports.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## status

Read case metadata and counts.

```sh
probentium status --case CASE
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads the held case revision; does not perform full integrity verification.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## sources

List acquired artifacts and parse coverage.

```sh
probentium sources --case CASE
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads the case; no mutation.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## verify

Verify stored case integrity and disclose missing evidence.

```sh
probentium verify --case CASE
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads and hashes case evidence; no mutation.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## browse

Open the monochrome terminal workbench.

```sh
probentium browse --case CASE --ascii
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Interactive commands may change the case. Requires a terminal; JSON envelope mode is unsupported.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## ingest

Acquire a source and record byte provenance.

```sh
probentium ingest --case CASE SOURCE.jsonl --format events --label Synthetic
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Copies evidence and writes checkpointed parse results; interruption may leave resumable progress.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## timeline

Filter the whole case and return a bounded page.

```sh
probentium timeline --case CASE --limit 100
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads a held revision; cursor reuse across revisions is refused.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## event

Read verified original record bytes as base64.

```sh
probentium event --case CASE EVENT_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads and hashes evidence; does not execute its content.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## control

Assess supplied control observations.

```sh
probentium control --case CASE --input control.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Read-only unless --save appends the supplied control. Does not authenticate observation truth.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## incident

Evaluate a draft operational deadline track.

```sh
probentium incident --case CASE --input track.json --as-of 2026-10-18T00:00:00Z
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Read-only unless --save appends the track; no legal certification or submission.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## filing

Store an immutable prepared filing snapshot.

```sh
probentium filing --case CASE --track track.json --fields fields.json --cutoff 2026-10-18T00:00:00Z
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends a prepared snapshot; never transmits it.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## diff

Compare two stored filing snapshots.

```sh
probentium diff --case CASE BEFORE_ID AFTER_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads the case; no mutation or external correction.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## doctor

Report local runtime capabilities.

```sh
probentium doctor
```

Output sensitivity: Local runtime details; inspect before sharing.

Side effects: Reads runtime capabilities; does not configure or install dependencies.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## formats

List supported explicit input formats.

```sh
probentium formats
```

Output sensitivity: Public contract metadata.

Side effects: No case access or mutation.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## schema

Print an installed machine-readable input schema.

```sh
probentium schema events-v2
```

Output sensitivity: Public contract metadata.

Side effects: Reads a local schema; does not fetch a remote schema.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## inspect

Inspect a bounded source sample without acquisition.

```sh
probentium inspect SOURCE.jsonl --format events --sample-lines 10
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads the source sample; does not create or change a case.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## migrate

Copy a verified schema-1 case to a staged schema-2 case.

```sh
probentium migrate LEGACY_CASE NEW_CASE
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads the original and creates a new verified destination; does not overwrite it.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## graph build

Freeze a typed graph of explicit case dependencies.

```sh
probentium graph build --case CASE
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends a graph bound to a verified snapshot; unknown schemas and references remain visible gaps.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## graph impact

Compare a frozen dependency graph with current premises.

```sh
probentium graph impact --case CASE --id GRAPH_ID --input changed-ids.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads explicit paths and reports review impact; does not declare legal or analytical invalidity.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## governance anchor-status

Read the currentness of a supplied obligation anchor.

```sh
probentium governance anchor-status --case CASE --id ANCHOR_ID --input as-of.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads typed supplied facts; does not infer statutory applicability or authenticate delivery.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## governance anchor-replay

Recheck immutable obligation-anchor premises.

```sh
probentium governance anchor-replay --case CASE --id ANCHOR_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads references and integrity; does not create a legal decision.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## legal import-catalogue

Import an explicit requirement and branch catalogue.

```sh
probentium legal import-catalogue --case CASE --input requirement-catalogue.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends a bounded catalogue; an author completeness claim is not independent verification.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## legal audit-coverage

Freeze exact structural coverage against a selected catalogue.

```sh
probentium legal audit-coverage --case CASE --id PACK_ID --catalogue CATALOGUE_ID --as-of 2026-10-19T00:00:00Z
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends missing rules, evidence, branches and source mismatches; does not certify legal completeness.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## legal coverage-status

Check the currentness of a frozen coverage audit.

```sh
probentium legal coverage-status --case CASE --id AUDIT_ID --as-of 2026-10-19T00:00:00Z
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads current references and preserves the historical result.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## legal coverage-replay

Recompute structural coverage from frozen premises.

```sh
probentium legal coverage-replay --case CASE --id AUDIT_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads stored pack and catalogue; no legal interpretation or external update discovery.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## parser-artifact register

Register an explicitly approved exact installed parser distribution and dependencies.

```sh
probentium parser-artifact register --case CASE --input parser-registration.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads supplied wheels, checks installed bytes and stores the supplied operator attestation; does not install or execute wheel content.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## parser-artifact verify

Recheck locally selected parser distribution bytes.

```sh
probentium parser-artifact verify --case CASE --id PARSER_APPROVAL_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads installed files and the stored manifest; byte equality grants no publisher authenticity or independent approval.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## issues status

Read parse issues.

```sh
probentium issues status --case CASE
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads case issue records.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## resume status

Resume an interrupted parse run.

```sh
probentium resume status --case CASE --id PARSE_RUN_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends checkpointed parse progress.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## replay status

Replay supported parser and analytical steps.

```sh
probentium replay status --case CASE
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads evidence and uses private temporary verification data; no case mutation.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## support status

Produce an allowlisted diagnostic summary.

```sh
probentium support status --case CASE
```

Output sensitivity: Local runtime details; inspect before sharing.

Side effects: Reads and verifies the case; output excludes raw evidence and source identifiers.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## recover plan

Plan removal of unreferenced blobs.

```sh
probentium recover plan --case CASE
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads and verifies; does not remove data.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## recover apply

Apply an exact revision-bound recovery plan.

```sh
probentium recover apply --case CASE --input recovery-plan.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Removes only the validated unreferenced blobs in the plan.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## recover copy

Recover an interrupted database into a new case.

```sh
probentium recover copy --case CASE --output RECOVERED_CASE
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Creates a verified copy; does not mutate the original.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## batch plan

Fingerprint an explicit list of source acquisitions.

```sh
probentium batch plan --input sources.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads source files; output includes local paths and hashes.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## batch execute

Execute an approved fingerprint-bound batch plan.

```sh
probentium batch execute --case CASE --input batch-plan.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Acquires files with per-artifact checkpoints; the batch is not globally atomic.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## claim list

List immutable claim revisions.

```sh
probentium claim list --case CASE
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads the case.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## claim add

Store a scoped typed claim.

```sh
probentium claim add --case CASE --input claim.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends a claim object.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## claim revise

Append a revision of an existing claim.

```sh
probentium claim revise --case CASE --id CLAIM_ID --input claim.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends a revision; preserves the previous claim.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## claim evaluate

Evaluate and store a claim result.

```sh
probentium claim evaluate --case CASE --id CLAIM_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends a result conditional on the held evidence and assumptions.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## claim analyze

Evaluate and store a claim result.

```sh
probentium claim analyze --case CASE --id CLAIM_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Alias of claim evaluate; appends a result.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## claim explain

Explain saved evidence lineage and typed gaps.

```sh
probentium claim explain --case CASE --id EVALUATION_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads and verifies available evidence; does not reexecute the saved evaluation.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## claim stale

Check whether a saved evaluation is current.

```sh
probentium claim stale --case CASE --id EVALUATION_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads current premises without rewriting the historical result.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## claim witness

Read a verified witness from a saved excerpt.

```sh
probentium claim witness --case CASE --id EVALUATION_ID --input witness.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads original bytes and returns base64; does not execute them.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## clock add

Store an attributed clock model.

```sh
probentium clock add --case CASE --input clock.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends a clock premise; does not change acquired bytes.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## family add

Declare source-family membership and its basis.

```sh
probentium family add --case CASE --input family.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends an attributed family assertion.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## duplicates add

Store explicit duplicate groups.

```sh
probentium duplicates add --case CASE --input duplicates.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends declared groups; does not remove evidence.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## identity add

Store an explicit identity assertion.

```sh
probentium identity add --case CASE --input identity.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends an assertion; does not identify a person automatically.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## scenario run

Evaluate an explicit counterfactual scenario.

```sh
probentium scenario run --case CASE --input scenario.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Stores scenario results; original evidence and premises remain.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## sensitivity run

Compare bounded source-family removals.

```sh
probentium sensitivity run --case CASE --input sensitivity.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads and evaluates; no case mutation.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## correlate run

Evaluate one supported correlation template.

```sh
probentium correlate run --case CASE --input correlation.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads and computes conditional findings; no automatic response.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## correlate batch

Evaluate a list of correlation templates together.

```sh
probentium correlate batch --case CASE --input correlations.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads and computes bounded findings; no automatic response.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## analysis compare

Compare two saved evaluation results.

```sh
probentium analysis compare --case CASE --input comparison.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads case results; no mutation.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## graph save

Store an explicit acyclic dependency graph.

```sh
probentium graph save --case CASE --input graph.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends a validated graph object.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## graph stale

Find descendants of explicitly changed graph nodes.

```sh
probentium graph stale --case CASE --id GRAPH_ID --input changed-nodes.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads the graph; does not infer missing relationships.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## governance observe

Store an attributed control observation with explicit population.

```sh
probentium governance observe --case CASE --input observation.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends a strict control-observation.v1 record; does not perform or authenticate the real-world test.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## governance observation-assess

Assess observed results against the declared population and expectations.

```sh
probentium governance observation-assess --case CASE --id OBSERVATION_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads supplied evidence; missing observations remain unknown.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## reporting evaluate-deadline

Freeze a reproducible operational deadline calculation.

```sh
probentium reporting evaluate-deadline --case CASE --id TRACK_ID --input deadline.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Stores rule, calendar, anchor and filing-state references; never certifies a legal deadline.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## reporting deadline-status

Check the currentness of a frozen deadline calculation.

```sh
probentium reporting deadline-status --case CASE --id DEADLINE_ID --input as-of.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads current premises; retains the original calculation and its limits.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## reporting deadline-replay

Recompute a frozen deadline from its recorded premises.

```sh
probentium reporting deadline-replay --case CASE --id DEADLINE_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads stored premises; does not submit a filing or approve legal interpretation.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## governance status

Summarize supplied governance evidence.

```sh
probentium governance status --case CASE
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads records; does not certify effectiveness.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## governance put

Store a typed governance record.

```sh
probentium governance put --case CASE --input governance.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends an immutable record after reference validation.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## governance get

Read a governance record.

```sh
probentium governance get --case CASE --id RECORD_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads the case.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## governance list

List governance records.

```sh
probentium governance list --case CASE
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads the case; an input document may narrow the kind.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## governance assess

Assess a declared control-test scope.

```sh
probentium governance assess --case CASE --id SCOPE_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads supplied observations; does not perform the real-world test.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## governance impact

Compute explicitly recorded dependency impact.

```sh
probentium governance impact --case CASE --input changed-refs.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads references; does not infer undocumented dependencies.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## legal status

Read a legal pack's supplied review/currentness state.

```sh
probentium legal status --case CASE --id PACK_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads the case; offline unseen amendments remain unknown.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## legal import

Import a strictly typed legal pack.

```sh
probentium legal import --case CASE --input legal-pack.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends a pack; import alone grants no legal approval.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## legal review

Record an evidenced review attestation.

```sh
probentium legal review --case CASE --id PACK_ID --input review-attestation.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends supplied review evidence; does not invent independent review.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## legal activate

Explicitly activate a permitted pack mode.

```sh
probentium legal activate --case CASE --id PACK_ID --input activation.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends activation history; draft mode remains unverified legally.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## legal diff

Compare exact versions of supplied packs.

```sh
probentium legal diff --case CASE --input pack-comparison.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads pack objects; does not fetch legal updates.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## legal draft

Return a bundled draft Czech source catalogue.

```sh
probentium legal draft --case CASE --input regime.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads draft definitions; no legal certification or case write.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## reporting status

Read preparation, approval and submission evidence separately.

```sh
probentium reporting status --case CASE --id FILING_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads stored records; no external portal query.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## reporting track

Store a reporting track with explicit role and anchors.

```sh
probentium reporting track --case CASE --input reporting-track.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends a track; does not determine legal applicability automatically.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## reporting deadlines

Plan a track's operational deadlines.

```sh
probentium reporting deadlines --case CASE --id TRACK_ID
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads the track; legal calendars remain explicitly unverified.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## reporting prepare

Freeze a recipient-template filing snapshot.

```sh
probentium reporting prepare --case CASE --id TRACK_ID --input filing-fields.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends a prepared snapshot; never transmits it.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## reporting approve

Record scoped approval of an exact snapshot.

```sh
probentium reporting approve --case CASE --id FILING_ID --input filing-approval.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends a supplied approval; does not submit the filing.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## reporting submission

Record an attributable assertion of submission.

```sh
probentium reporting submission --case CASE --id FILING_ID --input submission.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends evidence of an asserted external action; does not send anything.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## reporting receipt

Link receipt evidence with explicit strength.

```sh
probentium reporting receipt --case CASE --id SUBMISSION_ID --input receipt.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends supplied receipt evidence; does not authenticate a portal automatically.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## reporting impact

Record correction impact between exact snapshots.

```sh
probentium reporting impact --case CASE --input filing-comparison.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends an impact record; does not amend external submissions.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## retention status

Read holds, plans and current evidence availability.

```sh
probentium retention status --case CASE
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads current absence separately from historical removal authorizations.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## retention hold

Place or explicitly release a scoped hold.

```sh
probentium retention hold --case CASE --input hold.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends hold history; releasing a hold does not erase data.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## retention plan

Prepare a scoped source-byte removal plan.

```sh
probentium retention plan --case CASE --input retention-plan.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends a plan; does not remove evidence.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## retention approve

Record approval of an exact retention plan.

```sh
probentium retention approve --case CASE --id PLAN_ID --input retention-approval.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends approval acknowledging retained derived data.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## retention execute

Execute a due approved source-byte removal plan.

```sh
probentium retention execute --case CASE --id PLAN_ID --input approved-plan.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Removes approved raw source bytes; derived data remains and secure erasure is not promised.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## review rationale

Store the exact rationale for a signed opinion.

```sh
probentium review rationale --case CASE --input rationale.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends rationale text and returns its digest.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## review create

Create a revision-bound review and optional signature.

```sh
probentium review create --case CASE --input review-fields.json --key private-keys/reviewer.seed
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads an optional private key; returns a decision without importing it.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## review verify

Verify a review signature against explicit key trust.

```sh
probentium review verify --case CASE --input signed-review.json --trust trust.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads supplied trust and signature; does not grant reviewer identity or authority.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## review import

Import a verified review against resolved dependencies.

```sh
probentium review import --case CASE --input signed-review.json --trust trust.json
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Appends the review and its current verification evidence.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## packet verify

Verify packet structure or supported replay.

```sh
probentium packet verify --input evidence.pbp --scope structure
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads a packet using private verification data; does not restore it.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## packet export

Export an explicit evidence profile.

```sh
probentium packet export --case CASE --output evidence.pbp
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Creates a new packet; does not publish or send it. Default profile contains private evidence.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## packet restore

Restore verified packet data into a new case.

```sh
probentium packet restore --input evidence.pbp --output RESTORED_CASE
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Validates staging and publishes a new destination without overwrite.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## packet encrypt

Encrypt a verified packet for explicit age recipients.

```sh
probentium packet encrypt --input encryption.json --output evidence.pbp.age
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Runs locally installed age and creates ciphertext; does not encrypt the local case.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## packet decrypt

Authenticate and decrypt an age packet locally.

```sh
probentium packet decrypt --input decryption.json --output evidence.pbp
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Reads a private identity and creates verified plaintext; never overwrites the destination.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.

## key generate

Generate a local Ed25519 signing seed.

```sh
probentium key generate --output private-keys/reviewer.seed
```

Output sensitivity: May contain private case identifiers, paths, source bytes, claims or supplied personal data; inspect before sharing.

Side effects: Creates a private key file in an existing private directory; output contains public-key metadata only.

Exit codes (only applicable outcomes are used):

- `0`: Operation completed; inspect the domain verdict and limitations.
- `2`: Invalid input, usage or an operation that could not be performed.
- `3`: Explicit partial availability or incomplete verification scope.
- `4`: Integrity, signature or binding verification failed.
- `5`: Revision, lock, hold or conflicting-state refusal.
- `6`: Resource budget exceeded or work aborted by a limit.
- `7`: Requested implementation or platform is unsupported.
- `130`: Interrupted; inspect state before retrying a mutating operation.
