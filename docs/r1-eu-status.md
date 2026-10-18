# EU and governance implementation status

Local technical preview, reviewed against requirements R065–R096 on 2026-10-19.
This is an implementation inventory, not full R1 release approval or a legal opinion.
Publication of the 0.2.0.dev3 technical prerelease is explicitly authorized;
that permission does not complete any acceptance or legal-review gate.
The original requirements remain acceptance targets. A test written and run by
the implementer is not independent legal, security or usability review.

## Working technical contracts

`probentium/governance.py` stores closed-schema immutable records for services,
suppliers, dependencies, control implementations, evidence assertions, control
tests, exceptions, decisions, training, awareness and applicability. Revisions
explicitly supersede an existing object. References must exist; references do
not authenticate the meaning of a document or a supplied observation.

`probentium/legalpacks.py` imports bounded data-only packs, records separate
legal and technical review attestations, requires explicit activation and
reports version differences and expired review windows. A review requires
attached source artifacts matching the declared SHA-256 values, supporting
documents, a named actor, a review window and reference cases. Author self-review
cannot satisfy the separate review requirement. The program cannot authenticate
the reviewer’s professional status or independence from an actor name.

`probentium/reporting.py` separates immutable tracks, awareness assertions,
prepared snapshots, scoped approvals, asserted submissions, receipts and
correction impacts. A general delivery receipt does not establish which bytes
were submitted. A matching content digest remains a supplied binding assertion,
not automatic verification of a government receipt or legal acceptance.

`deadlines.py` and `deadline_records.py` calculate and persist versioned
operational evaluations with frozen rule/calendar/anchor digests, filing state,
review context and explicit `as_of`. Replay and currentness are separate.
`control_observation.py` implements the exact closed `control-observation.v1`
input, explicit population records, shared observation budgets and assessments.
`legalcoverage.py` audits actual pack mappings against an explicit immutable
requirement catalogue. It reports clause/branch, evidence, trigger, date and
source gaps without turning a supplied catalogue into complete law.

Every mutation uses `CaseStore.put_object` and accepts `expected_revision`.
All three modules expose `validate_stored(kind, data)` for typed transport.
Objects carry explicit draft or non-certification semantics. No function sends
a report to an authority or connects to a monitored system.

## Requirement-by-requirement assessment

“Technical base” means the named behavior works locally, within the stated
limits. It does not assert that the entire acceptance requirement has passed.

| Requirement | Current implementation | Remaining acceptance work |
| --- | --- | --- |
| R065 Applicability | Entity, service, jurisdiction, role, facts, exceptions, source references, reviewer and review date; unresolved facts cannot become an exemption by omission. | Human review is required. No automatic determination of enterprise size, group relationships, statutory scope or valid exemption. Registration delivery remains a supplied fact. |
| R066 Legal packs | Strict data contracts, separate effective/applicable dates, version, sources, origin, finite operator allowlist, calendars and templates. Proposals cannot execute or masquerade as enacted rules. | No arbitrary pack script execution. Import is not source authenticity or legal interpretation review. |
| R067 Czech regimes | Separate higher/lower/digital draft maps and fixed typed registration-condition/decision/delivery/effectivity/change/prior-review assertions. Immutable supersession, reference replay and currentness keep their meanings separate. Catalogue audit exposes missing trigger mappings. | **Partial:** no automatic legal applicability or start-of-duty decision. The section index still needs complete independently reviewed paragraph/branch content and transitional interpretation; supplied trigger assertions do not close that gate. |
| R068 Requirement links | Versioned requirement catalogues and saved coverage audits compare exact sources, provisions, conditional branches, evidence expectations, trigger tags and clause-level dates. Replay preserves historical mappings; later catalogue versions flag currentness. | **Partial:** structural matches are not legal sufficiency or a complete independent Czech mapping. Supplied catalogues may omit clauses. Reused evidence never implies equivalent obligations. |
| R069 Services and dependencies | Immutable service/supplier identity, unknown-dependency flag, typed relationships, declared periods and cycle rejection. | Declared references only. No automatic supplier identity inference, discovery or assertion of inventory completeness. |
| R070 Test scope | Population, sample, exclusions, procedure/version and period. Unknown denominator and incomplete inventory cannot produce full-scope effectiveness. | Observations and inventory completeness are supplied assertions. No independent inventory acquisition or authentication of observed outcomes. |
| R071 Document versus effectiveness | Evidence assertions distinguish policy, supplier statement, human attestation, observed test and derived result; approval preserves type. | A referenced policy can be incorrectly described by its author; software validates structure and references, not semantic truth. |
| R072 Freshness | Explicit internal/legal/none expiry origin, reason and review date; stale records appear in the dashboard. | No universal statutory expiry is inferred. Legal expiry policies require their own substantive review. |
| R073 Restore | Restore status, functional check, elapsed time, data age and declared RTO/RPO are evaluated within recorded scope. | No restoration executor or independent proof of functional recovery. Missing observation or target remains unknown. |
| R074 MFA | Configuration and enforcement are separate; tests bind the subject/access path, sample and declared population. Exceptions and uncovered population remain visible. | No directory connector, live enforcement test or guarantee that all emergency/service-account paths were supplied. |
| R075 Remediation | Applicability, remediation and retest are separate; ticket closure alone does not pass a test. | No automatic CVE applicability/exploitation determination, component inventory or authenticated patch validation. |
| R076 Suppliers | Supplier statements stay statements; documented dependencies identify affected services. Unknown branches are not invented. | Impact returns one representative causal path per affected object, not every possible route or an inferred real-world dependency map. |
| R077 Exceptions | Scope, owner, risk, compensating measures, review date, disposition and supporting references. Accepted risk never certifies legality. | Human decision and its supporting evidence must be supplied. |
| R078 Management decisions | Approval references a particular immutable target and scope; changed premises mark dependent decisions for review. | Identity/authority and signatures on uploaded management documents are not automatically authenticated. |
| R079 Training | Attendance and supplied assessment outcome remain separate. | Neither attendance nor a test result establishes universal professional competence. |
| R080 Awareness | Explicit actor, role, basis, rationale, event type and review decision; occurrence/detection are not substituted for awareness. Contested awareness loses its precise planning target. | A human must determine the relevant legal awareness threshold. Imported log timestamps do not do this. |
| R081 Deadlines | Stored `eu.deadline_evaluation` binds exact track/rule/calendar/anchor versions, `as_of`, case revision, filing state and result digest. Replay checks retained input bindings; relevant corrections, changed review context or filing states cause staleness. Unknown/waiting/time-unknown and open interval states remain separate. | Technical operational calculation/persistence is implemented. Legal deadlines remain `null`, calendar review unverified and legal countdown disabled. Native-case replay does not authenticate a foreign packet's original history or establish timely compliance. |
| R082 Deadline exceptions | Explicit timezone snapshots, hour/day/month policies, holiday coverage and DORA eligibility assertions drive bounded operational arithmetic. A closed 16-node calendar plan adds minimum-working-day floors, min/max targets and explicit policy/predecessor precedence with frozen replay traces. DORA role exclusions, late classification, CRA anchors, month-end, DST, holidays and unknowns have local regressions. | **Gate:** no independently reviewed legal vectors. Policy applicability, retroactive periods and legal-instrument precedence are supplied decisions rather than automatic legal conclusions. Local review attestations and passing vectors cannot enable a certified legal countdown. |
| R083 Frozen evidence | A snapshot binds the selected immutable track, pack, template, field bases/references, current case revision and explicit cutoff. Later revisions do not rewrite it. | The cutoff is operator supplied. It does not reconstruct everything the organization knew at that time or replay a historical database solely from a wall-clock timestamp. |
| R084 Separate tracks | Incident, role, qualification, recipient, profile and anchors remain separate per track; cross-track correction is rejected. | No automatic lex-specialis decision. DORA does not automatically suppress GDPR or unrelated tracks. Draft catalogues for all EU jurisdictions are not supplied. |
| R085 Filing fields | Closed field schema, explicit source-backed/human/derived/contested/unknown basis, calculation metadata and source references. Missing required facts create tasks, not zeroes. | Field content still needs human review and authority-form mapping. A count of parsed events is not a count of affected people. |
| R086 Submission evidence | Prepared, scoped approval, asserted submission and three receipt strengths are separate. Exact snapshot digest is retained. | No portal integration, automatic receipt authenticity check, government acceptance or submission on the operator’s behalf. |
| R087 Corrections | Immutable before/after snapshots, field/basis changes, explicit changed premises, dependency paths and old-submission references. | A responsible person decides whether and how to correct an external filing. No automatic legal correction obligation or external amendment. |
| R088 Retention | Scoped holds, inventory-bound plans, approvals and generation-aware source-byte tombstones; changed acquisitions require a fresh plan, and old removal authorization cannot hide loss after reacquisition. Retained derived data, known exports and unknown external copies are disclosed. | Implemented within the declared source-byte scope. Whole-case erasure and secure deletion of SSDs, journals, swap, backups and external copies are not claimed. |
| R089 Restricted transfer | Typed EU object envelopes and explicit recipient field projections are integrated with the packet module; public summary excludes EU records. | Recipient projections disclose withholding and are not full case replay. Third-party review of export policy and end-to-end recipient workflows remains a release gate. |
| R090 Rule updates | Version/content conflict rejection, pack diff, explicit activation, history-preserving replacement and review expiry. Offline unseen amendments remain unknown. | Source-update discovery and legal review are not automatic; a currently dated supplied review cannot prove no later amendment exists. |
| R091 Dependencies | A persisted unified graph binds explicit byte, parser, event, time/identity, claim, review and EU references to a verified revision. Impact preserves old snapshots and returns affected paths, structural changes and explicit gaps. | No inference from free text or real-world completeness. Structural impact requests review; selective analytical currentness retains its own domain checks. |
| R092 Contracts/limits | The exact closed `control-observation.v1` wire input and published JSON Schema now cover restore/MFA/remediation, decimal microseconds, explicit nulls, references, population scope and aggregate budgets shared with legacy control tests. Deadline evaluations, catalogues/audits and obligation assertions have closed typed validators and versioned identities. | Full combined interaction/resource/platform/UI acceptance remains broader than the focused module suite. Schema structure validation does not replace runtime scope/reference checks or independent security review. |
| R093 Incident exercise | `build_demonstration` creates fictional scope/awareness, two prepared snapshots, actual parsed-event count, correction impact and stored/replayable fictional follow-up evaluation. The control helper stores three explicit population/observation workflows with passing, unknown and failed results. No submission or external reviewer is invented. | This is an implementer-run synthetic exercise, not independent user validation. |
| R094 Profile review | Technical workflow requires separate legal/technical attestations and source documents before `review_attested` activation; expired attestations lose currentness. | **External gate:** no independently commissioned legal review or authenticated reviewer credentials are supplied. `legally_verified` remains false. `draft_operational` is explicitly not active legal certification. |
| R095 User utility | Synthetic examples and repeatable workflows exist. | **External gate:** three independent practitioner pairs, comprehension evidence, measured comparative utility and performance claims are not completed. |
| R096 Name/release | New namespace and preview naming coexist with preserved legacy identity domains. | **Full R1 release gate:** registry/trademark availability, exact final public-surface checks and reviewed release claims remain separate requirements. Publication of the 0.2.0.dev3 technical prerelease is explicitly authorized. GitHub private vulnerability reporting was enabled on 2026-10-19; monitored handling, response-time commitments and independent assessment remain open. Limited preview authorization does not pass this gate. |

## Source provenance and its limits

The bundled catalogues cite these official promulgated sources and pin the PDF
bytes retrieved on 2026-10-18. The PDF files themselves are not bundled. A source
URL is a citation; this product does not fetch it while evaluating a case.

| Official source | PDF SHA-256 |
| --- | --- |
| [Act 264/2025 Coll.](https://e-sbirka.gov.cz/sb/2025/264) | `ee72b72a3caaa5fb86b91588ed9ab5be3d60f2fa06fe1f23d01965e5b7a9de03` |
| [Decree 334/2025 Coll.](https://e-sbirka.gov.cz/sb/2025/334) | `6c489ae66bfa65c8aedecdfa3b660224762c32fa3794a8cb2f3ed5f888900cf9` |
| [Decree 408/2025 Coll.](https://e-sbirka.gov.cz/sb/2025/408) | `419392fc5e77c7f44046e15e717f68c2564c49da80c89ef05cc66e8d3e3bae07` |
| [Decree 409/2025 Coll.](https://e-sbirka.gov.cz/sb/2025/409) | `09aaa48213c7d37ae3740ada3c547cefbda8eafc44a852818d2fcd1f9756c302` |
| [Decree 410/2025 Coll.](https://e-sbirka.gov.cz/sb/2025/410) | `3fd120e8c0e9d852b35192e9d0fc41ff780a27a962095255e76f1519bb46bf70` |
| [Implementing Regulation 2024/2690, English OJ](https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj/eng) | `8799b1a7c352060c4f155ddc56241b0b2679e2204645361b134bbda3199d7199` |

These hashes are integrity anchors for exact files, not proof of a correct legal
interpretation, absence of amendments, applicability to an entity or sufficient
evidence. Currentness review, authentic source attachment and independent review
are separate. The Czech mapping indexes all higher/lower measure sections and
annexes, with registration/transition and the separate digital branch. It does
not expand every paragraph and annex subclause into a legally reviewed rule.

## Repeatable local CLI exercise

Run from a checkout with the documented environment installed and a new writable
working directory. All data below is fictional. The default demo creates a case
under `eu-example/case`; use a new directory for each run.

```sh
python -m probentium demo eu-example > demo-result.json
printf '%s\n' '{"as_of":"2026-10-18T14:00:00Z"}' > as-of.json
python -m probentium governance status --case eu-example/case --input as-of.json
printf '%s\n' '{"regime":"higher"}' > higher.json
python -m probentium legal draft --case eu-example/case --input higher.json > czech-draft.json
python -m probentium legal import --case eu-example/case --input czech-draft.json > imported-draft.json
```

Import does not activate the legal pack. It has no attached official source
documents or legal review. The following local preparation selects actual IDs
from the synthetic demo and writes strict JSON input files, so there are no
invented hashes to replace manually:

```python
import json
from pathlib import Path
from probentium.store import CaseStore

with CaseStore("eu-example/case") as case:
    track = [row for row in case.objects("eu.reporting_track")
             if row["data"]["id"] == "exercise-track"][-1]
    original = [row for row in case.objects("eu.filing_snapshot")
                if row["data"]["track_ref"] == track["id"]][-1]
    Path("track-id.txt").write_text(track["id"])
    Path("previous-filing-id.txt").write_text(original["id"])
    Path("prepare.json").write_text(json.dumps({
        "cutoff": "2026-10-18T14:00:00Z",
        "fields": [{"id": "scope", "basis": "human_attested",
                    "value": "Synthetic exercise only; impact not independently established.",
                    "refs": [], "reason": "Explicit fictional operator assessment."}]
    }))
```

Then prepare and inspect a new immutable snapshot:

```sh
python -m probentium reporting deadlines --case eu-example/case --id "$(cat track-id.txt)" --input as-of.json
python -m probentium reporting prepare --case eu-example/case --id "$(cat track-id.txt)" --input prepare.json > prepared.json
```

`prepared.json` is a stored-object wrapper with `id`, `kind`, `revision` and
`data`. Its field tasks include unknown values for omitted required facts. This
does not submit a report or approve the contents.

The governance `put` command takes this shape; reference arrays may be empty for
an explicitly unsubstantiated service assertion. It does not infer that the
inventory is complete:

```json
{
  "kind": "service",
  "data": {
    "logical_id": "additional-synthetic-service",
    "actor": "Synthetic operator",
    "recorded_at": "2026-10-18T14:00:00Z",
    "basis_refs": [],
    "rationale": "Fictional inventory entry; dependencies have not been established.",
    "supersedes": null,
    "name": "Additional synthetic service",
    "entity": "Fictional organization",
    "jurisdiction": "synthetic",
    "owner": "Synthetic owner",
    "criticality": "unknown",
    "unknown_dependencies": true
  }
}
```

Save it as `service.json`, then run:

```sh
python -m probentium governance put --case eu-example/case --input service.json
python -m probentium governance list --case eu-example/case
```

To update that logical service, supply its exact prior object ID in `supersedes`
and use `--expect-revision` to reject a stale case view. Arbitrary extra input
fields are rejected by the typed module. A list or get operation does not prove
that an assertion is accurate.

## Validation boundary

Run the focused technical suite with:

```sh
python -m unittest tests_r1.test_regulatory tests_r1.test_governance tests_r1.test_legalpacks tests_r1.test_reporting tests_r1.test_deadline_evaluations tests_r1.test_control_observations tests_r1.test_legalcoverage
```

It covers unknown scope, sample mismatch, explicit evidence types, aggregate
observation caps, dependency cycles and branch-specific impact, immutable review
binding, stale and cross-pack reviews, proposal execution rejection, exact
source-reference types, cross-track filings, missing facts, receipt strength,
historical preservation and the fictional demonstration. It includes the
operational DORA/CRA/Czech/GDPR boundary tests from the pure planner.

The additional input/schema, frozen-evaluation and catalogue workflows are
documented in [control observations](control-observations.md),
[deadline evaluations](deadline-evaluations.md) and
[legal coverage](legal-coverage.md). The structural observation schema was also
checked with jsonschema 4.25.1 against six valid and 30 invalid synthetic input
variants. That is a software-contract check, not independently reviewed legal
reference evidence. Current integrated execution is recorded in the
[native-terminal and Kali validation basis](validation-terminal-kali.md) and its
[hash-bound receipt](validation-terminal-kali.json). The corpus has 696 distinct
runtime tests: 549 current-interface and 147 compatibility-interface cases.
Both the native Kali build and separate installed-system-package runtime suite
passed all 696 without skips. Source Python 3.12 and interim-wheel Python 3.13
retain an initial stale test expectation and subsequent corrected nine-test
module pass; those executions are not relabeled as full corrected-suite passes.
The first installed Kali driver retained exit 4 for noncanonical trust JSON in
a test helper; the corrected six-check workflow driver separately exited 0.
Final artifact identities and acceptance remain separate release attachments.

The native console and 97-action CLI expose the same local governance and
reporting operations without a browser. These synthetic, implementer-run checks
do not authenticate control effectiveness, legal applicability, reviewer
independence or an external filing. Local Kali package tests do not establish
distribution inclusion. The original 80 implemented, 10 partial and six external
requirement statuses, and all 16 unpassed release gates, remain unchanged.

Passing this suite does not complete the broader R001–R064 core acceptance,
independent audit, platform/resource matrix, user research, or the legal and
release gates above. No percentage-complete or universal compliance claim is
derived from test counts.
