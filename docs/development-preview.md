# Technical preview: 0.2.0.dev3

The terminal application, CLI and synthetic development viewer use the same case and analysis code. This guide describes the new `probentium` command. The older `testifex` command uses a separate case format and different capabilities.

## Start and navigate

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/probentium doctor
.venv/bin/probentium demo exercise
.venv/bin/probentium browse --case exercise/case
```

The demo refuses an existing destination. Its 132 records and identities are synthetic. Documentation IP addresses are used. Clock calibration is explicitly an exercise assumption, not a measurement. A stored time-ordering claim moves from unknown to entailed under that assumption; widening the uncertainty produces an unresolved scenario. The EU exercise uses a fictional internal pack and never fabricates legal review, regulator submission or delivery receipts. A generated exercise key signs an explicit abstention; it is untrusted and represents no independent reviewer or approval. `demo --basic` creates the smaller original intake exercise.

Use `1`–`7` for Overview, Evidence, Timeline, Controls, Incident, Filings and Changes; `8`, `9`, `0` for Claims, Scenarios and Review. `browse --ascii` renders non-ASCII values as visible escapes before calculating columns. `j`/`k` or arrows move; `Enter` opens complete details; `Escape` returns. `/` filters the whole timeline. `PageUp`/`PageDown` paginate or scroll. `v` verifies; `?` shows help; `q` exits.

The `:` prompt accepts only internal commands. It cannot execute a shell. `:scope`, `:export`, `:retention`, `:evaluate ID`, `:explain ID`, `:witness EVALUATION EVENT` and `:replay` expose the new workflows. The existing `:prepare` prepares the selected legacy-style track's latest draft fields. The richer EU reporting workflow is available through the CLI; the view is not a form editor for every typed record.

## Acquire and verify evidence

```sh
probentium formats
probentium schema events-v2
probentium inspect copied-events.jsonl --format events-v2
probentium init private-case --name 'Investigation'
probentium ingest copied-events.jsonl --case private-case --format events-v2 --label 'Copied export'
probentium sources --case private-case
probentium issues --case private-case
probentium timeline --case private-case --filter auth.success --limit 100
probentium verify --case private-case
probentium replay --case private-case
```

`inspect` samples at most the requested number of bounded lines; it never declares the entire source valid. Ingest requires explicit format selection. Available adapters are listed by `formats`. `opaque` preserves bytes without claiming event interpretation. Unknown timestamp timezone/year remains unknown. The exact [events-v2 contract](events-v2.md) is stricter than the compatibility `events` format; a machine-readable schema is included in the distribution.

A batch plan binds path, format, label, size and SHA-256. Save a JSON list such as `[{"path":"copied-events.jsonl","format":"events-v2","label":"Copied export"}]`, then:

```sh
probentium batch plan --input entries.json > plan.json
probentium batch execute --case private-case --input plan.json
probentium resume --case private-case --id PARSE_RUN_ID
```

Execution checks all planned fingerprints before starting and checks the copied bytes again for each acquisition. A batch is not one all-or-nothing transaction: completed artifacts and committed parser checkpoints remain. Resume never reuses a checkpoint from a different parser identity.

Regular files and non-symlink parent paths are required. Record output in the JSON CLI is base64; all CLI JSON output escapes non-ASCII and control characters without changing decoded values. This transport encoding is separate from canonical identity and signature encoding. The TUI escapes control and directional characters. The parser runs in a separate process with a cleared environment, private working directory and Linux CPU/memory/file-descriptor/wall limits. This is not an OS network sandbox. No parser-supplied code or command is executed.

## Claims, clocks and review

All command inputs are strict UTF-8 JSON. Duplicate keys, floats and unknown schema fields are rejected where the corresponding typed contract applies. Microseconds use decimal strings; counts use integers. IDs in these examples are identifiers returned by earlier commands, not arbitrary names.

```sh
probentium claim add --case private-case --input claim.json
probentium clock add --case private-case --input clock-assignment.json
probentium family add --case private-case --input family.json
probentium duplicates add --case private-case --input duplicates.json
probentium identity add --case private-case --input identity.json
probentium claim evaluate --case private-case --id CLAIM_OBJECT_ID
probentium claim explain --case private-case --id EVALUATION_OBJECT_ID
probentium claim stale --case private-case --id EVALUATION_OBJECT_ID
probentium scenario run --case private-case --input scenario-request.json
probentium sensitivity run --case private-case --input sensitivity-request.json
probentium correlate batch --case private-case --input correlation-requests.json
probentium analysis compare --case private-case --input comparison.json
```

Clock assignment has `model` and `artifact_ids`. A family request has `family_id`, `artifact_ids`, `basis_refs`, `rationale`. A scenario request has `claim_ids`, `scenario`; sensitivity has `claim_ids` and optional `family_ids`, `limit`. A comparison has stored evaluation IDs `before`, `after`. Batch correlation accepts up to two distinct requests:

```json
[
  {"template":"auth_after_failures","window_us":"300000000","threshold":5},
  {"template":"post_auth_process","window_us":"60000000"}
]
```

Five predicates distinguish entailed, ruled_out, unresolved, unknown, invalid and not_evaluated results. Integrity, available coverage, review trust and execution state are separate. Empty explicit scope means empty scope; `all_at_revision` is frozen on save. Source-family assertions and identity links are declarations with basis, not automatically established real-world independence or identity. Witness displays are bounded with count, digest and completeness flags.

```sh
mkdir -m 700 private-keys
probentium key generate --output private-keys/signing-key.bin
probentium review rationale --case private-case --input rationale.json
probentium review create --case private-case --input decision-fields.json --key private-keys/signing-key.bin > signed-review.json
probentium review verify --case private-case --input signed-review.json --trust trusted-keys.json
probentium review import --case private-case --input signed-review.json --trust trusted-keys.json
```

The generated signing key is a raw 32-byte private seed, not a JSON document. Its parent must be mode 0700 and the key mode 0600. `rationale.json` is `{"text":"The reviewer's actual rationale."}`. Its returned digest binds the exact text. `decision-fields.json` contains claim ID/revision, evaluation digest, evidence-state digest, reviewer key ID, disposition, rationale digest and optional previous decision ID. A valid signature alone does not establish the reviewer's identity. Trust must be explicitly supplied. Missing references, altered inputs and historical approval remain distinct. Local signing keys are private files and are never included in evidence packets.

## Exchange and recovery

```sh
probentium packet export --case private-case --output evidence.pbp --key private-keys/signing-key.bin
probentium packet verify --input evidence.pbp --scope structure --trust trusted-keys.json --require-trusted-key
probentium packet verify --input evidence.pbp --scope replay --trust trusted-keys.json --require-trusted-key
probentium packet restore --input evidence.pbp --output restored-case --trust trusted-keys.json --require-trusted-key
probentium recover plan --case private-case > recovery-plan.json
probentium recover apply --case private-case --input recovery-plan.json
probentium recover copy --case interrupted-case --output recovered-copy
probentium migrate legacy-case new-case
```

Packets use a restricted uncompressed USTAR layout, a manifest, bounded canonical JSON and SHA-256-addressed blobs. Larger snapshots use validated chunk indexes and a private verifier-owned SQLite index; foreign databases are never opened as cases. Flat v1 packets remain readable. EU and retention records require `.pbp`; the compatibility `.tfp` namespace does not silently accept those extensions. Restores validate in a private staging directory and publish without replacing an existing destination.

Structural verification does not claim parser replay. Replay requires a supported local parser identity; it does not download executable dependencies from the packet. Development source identities remain distinct from the explicit [approved distribution workflow](parser-artifacts.md), which binds the product wheel, pinned runtime wheels and installed bytes to a supplied operator approval. A packet cannot select its own executable parser. Ordered composite record references and multiple output indexes are supported in storage, raw-byte inspection and transfer; unsupported composite parser reexecution is reported explicitly.

Profiles are `private_full`, `public_summary`, and `recipient_dossier`. `public_summary` uses the compatibility `.tfp` schema; the other profiles support `.pbp`. The public summary uses an explicit HMAC pseudonym key and withholds free text; it is not a guarantee of anonymity. Recipient dossiers use explicit object/field allowlists and preserve withheld-reference status. Full packets and local cases contain sensitive plaintext.

Encryption requires an independently installed `age` executable. `packet encrypt` takes `{"packet":"evidence.pbp","recipients":["age1..."]}`; `packet decrypt` takes `{"packet":"evidence.pbp.age","identity_file":"recipient-key.txt"}`. Use `--output` for the new destination. Actual age interoperability and tampering tests are part of validation; local case encryption is not implied.

## Analysis process receipts and dependency graphs

The CLI executes claim evaluation, correlation, scenarios and sensitivity in a
separate bounded process. `--analysis-limits FILE` supplies a closed
`probentium.analysis-limits.v1` document. Omitted fields use the declared defaults;
values above hard caps are rejected. Limits are included in the analytical
configuration and digest. `--execution-receipt` returns the domain result together
with the actual input/output revisions, effective limits and resource mechanism.
`--expect-revision` checks the held child revision for read-only analysis too.

```sh
probentium correlate batch --case private-case --input correlation-requests.json --execution-receipt --resource-mode strict
probentium graph build --case private-case
probentium graph impact --case private-case --id GRAPH_ID --input changed-ids.json
```

Strict analysis memory enforcement is currently supported on Linux. A monitored
platform is not relabeled hard-enforced. Process limits do not establish a
network or hostile-code sandbox. The parent is not subjected to the child's
memory limits. A late child failure can follow a completed immutable write;
inspect the case revision before retrying a mutating operation.

Graph build freezes typed explicit dependencies between original bytes, records,
parser versions, events, clock/identity premises, claims, review decisions and EU
objects. It stores bounded immutable chunks. A build input may select
`artifact_ids` and/or `object_ids`; an impact input contains `changed_ids`.
Unknown schemas or unresolved references create visible gaps. Structural impact
requests review; it does not automatically declare a legal or analytical
conclusion invalid. Existing selective claim-currentness checks retain their
own semantics. Historical objects and signatures remain unchanged.

## Governance, reporting and retention

The [EU requirement audit and examples](r1-eu-status.md) cover governance records, applicability, rule-pack import/review/activation, reporting tracks, frozen filings, approvals, submission assertions, receipts and corrections. Supplied European/Czech profiles are draft planning aids. Explicit human attestations are not independent legal certification; `legally_verified` remains false. A prepared or approved filing is not a transmitted filing.

Retention is explicitly `source_bytes_only`. It requires a plan, attributed approval, a due date and no active hold. An optional policy records purpose, data category, retention basis and review date; the v2 plan freezes shared-acquisition counts, affected records/events and known filing/export references. A changed acquisition inventory requires a new plan and approval. Reacquiring the same bytes invalidates the old authorization for any subsequent absence. Normalized events, metadata, indexes, objects, external exports and backups are retained or outside this operation. Their retention is acknowledged in the approval. Authorized absence is partial availability, not unexplained corruption; secure erasure is not promised.

## Limits, diagnostics and exit codes

Defaults include 1 GiB/source, 20 GiB source bytes/case, 1 MiB/line, 1 million case events and 100,000 events/analysis. Explicit [resource policies](resource-policies.md) bind selected acquisition/packet limits and their digests; a packet cannot raise the receiver's local limits. Analysis has a separate versioned policy and process receipt. Independent database, metadata, structure and disk-capacity limits still apply. Large numeric ceilings are not evidence of achieved maximum workload performance. No silent partial analysis is labeled complete.

Exit codes: `0` completed operation (which may report an unknown analytical verdict); `2` input/usage error; `3` partial availability or incomplete verification scope; `4` integrity failure; `5` revision/lock/hold conflict; `6` resource limit; `7` unsupported implementation; `130` interruption. JSON results retain more specific state. Inspect `execution_state` as well as verdict; never interpret a successful process exit as proof of a claim.

Use the global `--format json` before the command for the versioned machine envelope, for example `probentium --format json status --case private-case`. Each action's help and the [CLI reference](cli-reference.md) document its purpose, minimum example, output sensitivity, side effects and exit codes. Unobserved revision or verification is `null`; the wrapper does not imply an extra verification pass. The existing flat JSON output remains the default.

`probentium support --case private-case` emits an allowlisted diagnostic summary without source bytes, paths, identifiers or environment values. It is still a local candidate to inspect before sharing. `doctor` reports actual runtime capabilities, including the missing network sandbox and external age availability.

## Local development viewer

```sh
.venv/bin/python dev/livepreview/server.py --case exercise/case --port 5197
```

Open `http://127.0.0.1:5197`. The viewer renders the same frame model and accepts the same keys. It binds only to loopback, uses no external assets, rejects non-synthetic cases and has no file-upload, shell or submission endpoint. Host, Origin and per-session token checks are enforced. These four development fixture files are included in the source distribution so its preview tests are self-contained; the wheel does not install a production server.

The browser shell adds horizontal top navigation, live case totals and a compact integrity/revision summary around that shared frame. Narrow screens scroll the module strip and terminal independently. The summary is derived from the currently open synthetic case; there are no simulated host statistics.

## Validation and remaining gates

[Recorded validation](validation-terminal-kali.md) describes the installed-package checks, the synthetic scale tests and their limits. The pinned dependency wheelhouse can be prepared with `scripts/prepare_offline.py`; it reads already acquired wheels and makes no network request. Obtain matching platform/Python wheels separately, inspect their upstream licenses, and use the generated hash-locked requirements for offline installation. The project archive and external age binaries are separate inputs.

[Core audit](r1-core-status.md), [machine-readable status](r1-requirements-status.json) and [EU audit](r1-eu-status.md) are the requirement map. They record partial implementation and unfulfilled acceptance conditions explicitly. Internal tests and performance runs do not replace independent analyst/IR/GRC pilots, legal review, security assessment, macOS validation or the prescribed reference-machine cold/warm benchmarks. The product name remains provisional. Publication as a technical preview does not close the full-R1 acceptance gates.
