# Requirement-catalogue coverage audits

The coverage audit compares an immutable legal pack to an explicit supplied requirement catalogue. It reports concrete structural gaps: unmapped clause branches, absent rule IDs, different provision or condition text, missing evidence expectations, missing typed registration triggers, conflicting effectivity/applicability dates, and different source URLs/digests/origins. A catalogue with only section headings cannot establish that all paragraph, item and conditional branches were enumerated.

`legalpacks.import_catalogue(case, data)` stores a `eu.requirement_catalogue`. The closed input contains:

- `schema: "probentium.eu.v1"`, `kind: "requirement_catalogue"`, `id`, `version`, `jurisdiction`, `regime`, `author`, and `recorded_at`.
- Nonempty `document_refs`, `completeness_claim` (`partial` or `declared_complete`), and `review_status: "unverified"`.
- `sources`: up to 64 records with `id`, `url`, `sha256`, nullable `document_ref`, and `origin`. Attached source bytes must have the declared digest. An origin label is supplied metadata, not independent authentication.
- `requirements`: up to 5,000 records with `id`, `source_id`, `provision`, nullable `effective_from` and `applicable_from` calendar dates, and nonempty `branches`.
- Each branch has `id`, `condition`, `rule_ids`, `evidence`, and nullable `trigger_kind`. The complete catalogue is limited to 5,000 branches and 16 MiB.

The same catalogue ID/version cannot be re-imported with different content. A new version is a new immutable object. The catalogue's assertion of completeness is retained as a claim and is never verified merely because it exists.

`legalpacks.audit_coverage(case, pack_id, catalogue_id, as_of)` saves a `eu.legal_coverage_audit` with pinned input digests, case revision, explicit clock instant, review context, exact result and result digest. `replay_coverage` checks retained input bindings and recomputes the comparison. Corruption fails; authorized missing evidence is partial. `coverage_status` identifies newer supplied catalogues/packs and changed review or activation context without altering the historical audit.

The most positive result is `structural_match_only`. It remains `review_status: unverified`, `legally_verified: false`, and `evidence_reuse_implies_equivalence: false`. Internal guidance and proposals are explicitly identified as non-enacted sources. Matching evidence expectation names does not prove actual control effectiveness, independent corroboration or legal equivalence. There is no compliance percentage or automatic approval.

## Separate registration and effectivity assertions

Governance `put` supports `obligation_anchor` with the common immutable governance fields plus `service_ref`, `profile`, `trigger_kind`, `anchor` and `review_decision`. Profiles remain separate: `cz-nis2-higher`, `cz-nis2-lower`, and `cz-nis2-digital`. Fixed trigger kinds are:

- `registration_conditions_met`
- `registration_decision`
- `registration_delivery`
- `law_effective`
- `data_change`
- `prior_regulation_review`

The time anchor accepts the existing known, unknown, waiting, time-unknown and open/closed interval forms. A declaration needs evidence references when it says a trigger exists. A future published effectivity date can be recorded; it does not assert that duties have already started. An observed registration or delivery assertion cannot occur after its attestation. Revision of an assertion must preserve the service, profile and trigger kind; a decision date cannot silently replace a delivery date.

`governance.obligation_anchor_status(case, id, as_of)` reports supersession, supplied time state and human review decision. `replay_obligation_anchor` checks the immutable reference chain and case integrity. Neither determines whether the organization is regulated or when a particular legal duty begins.

The current Czech draft packs remain review starting points. Their section maps and source digests do not establish exhaustive, independently reviewed clause coverage. Registration/start-of-duty legal interpretation, transitional branches and a complete externally reviewed Czech requirement catalogue remain content and legal-review gates. The new audit makes omitted branches and missing trigger mappings visible instead of treating a partial index as complete law.

## CLI

Replace `CASE` and `*_ID` with the existing case directory and actual returned immutable IDs. `catalogue.json` is the direct catalogue input described above. Coverage audit and currentness use explicit `--as-of`, not an input document.

```sh
probentium legal import-catalogue --case CASE --input catalogue.json
probentium legal audit-coverage --case CASE --id PACK_ID --catalogue CATALOGUE_ID --as-of 2026-10-18T14:00:00Z
probentium legal coverage-status --case CASE --id AUDIT_ID --as-of 2026-10-18T15:00:00Z
probentium legal coverage-replay --case CASE --id AUDIT_ID
```

For an anchor, `anchor.json` is `{"kind":"obligation_anchor","data":{...}}` using the fields above; `as-of.json` contains only `{"as_of":"2026-10-18T14:00:00Z"}`.

```sh
probentium governance put --case CASE --input anchor.json
probentium governance anchor-status --case CASE --id ANCHOR_ID --input as-of.json
probentium governance anchor-replay --case CASE --id ANCHOR_ID
```

Import, audit and governance put append case objects and accept `--expect-revision`. Currentness and replay are read-only. Replay takes no input document. Outputs can reveal private applicability facts, source references, registered-service aliases and supplied review context.
