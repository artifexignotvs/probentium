# Analysis, provenance and uncertainty

TESTIFEX is an offline terminal workbench for a bounded set of imported records. It produces temporal leads with references to their source bytes. It does not determine whether a host was compromised, whether two records belong to one session, or whether a collection is complete.

*Ordo temporum indicium est, non causa.*

## What a finding means

The current rule version is `1`.

| Rule | Required match | Result |
| --- | --- | --- |
| `auth_after_failures` | Failure and success records have the same nonempty host, actor and source IP; enough failures can precede the success within the configured window | One finding anchored to the success record, with every matched failure reference |
| `post_auth_process` | An authentication success and a process or command record have the same nonempty host and actor and can occur in that order within the window | One temporal lead for each matching success/process pair |

Defaults are a 300-second window and five failure records. The second rule does not require the first rule to fire. It does not require a source IP on the success record: a local process record ordinarily cannot establish which remote address or authenticated session caused it.

Matching is exact after parser normalization. Host aliases, case differences, renamed accounts and account reuse are not resolved automatically. Missing identifiers prevent the corresponding link. A process record near two successful authentications can produce two separate leads; the program does not choose a session on the analyst's behalf.

Counts describe matching records. Overlapping collections can describe the same underlying attempt more than once. No cross-source semantic deduplication or independent attempt-count estimate is performed. A logged `sudo` command is represented as a command record, not proof that execution succeeded or completed.

## Intervals, not invented precision

Every known time has inclusive integer UTC microsecond bounds, `time_low_us` and `time_high_us`. The original text and the timestamp basis are retained in private reports.

For a timestamp at `00:01:30Z`, the representation cell runs from `00:01:30.000000Z` through `00:01:30.999999Z`. A three-digit fraction represents a 1,000-microsecond cell. Six or more fractional digits occupy the containing microsecond cell; longer raw fractions remain available without a false claim of nanosecond-resolution storage.

These cells describe representation resolution. They are not measured clock accuracy, confidence intervals or probabilities about when the physical event happened.

For predecessor interval `A`, successor interval `B` and positive window `W`:

- A relation is possible when `A.low <= B.high` and `B.low - A.high <= W`.
- It is certain **within the supplied interval model** only when `A.high < B.low` and `B.high - A.low <= W`.
- Intersecting intervals produce `overlapping_time_intervals`.
- An interval pair whose largest possible separation exceeds the window produces `uncertain_window_boundary`.

Equal timestamps do not establish order. Sorting by interval bounds and an identifier gives a deterministic display, not an evidentiary total ordering. A source whose consecutive timestamped records reverse their recorded order receives a `source_sequence_time_reversal` qualification.

An authentication finding exposes both `failure_count` and `certain_failure_count`. Its `threshold_status` is `certain` only if enough certainly preceding, within-window records meet the threshold. The overall `ordering` can still be `possible` when additional matched records are ambiguous. No certainty percentage is invented.

## Declared clock corrections

`--clock-offset` is the number of seconds the source clock is ahead. `--clock-error` is a nonnegative, symmetric declared uncertainty. For recorded bounds `[low, high]`, offset `O` and error `E`, corrected bounds are:

```text
[low - O - E, high - O + E]
```

Nonzero corrections require `--reason`. Original bounds, corrected bounds, offset and error remain distinct event fields. A declaration is not an independently measured calibration. Both CLI parameters must be exactly representable in microseconds and are bounded to 365 days in magnitude.

Identical file bytes cannot be imported into one case as conflicting format, parser or clock-option versions. Analysis also rejects duplicate source digests with `conflicting_source_versions`. This prevents one raw file from silently contributing the same record twice. Use separate cases to compare alternate assumptions, as the synthetic demo does.

## Coverage is always qualified

The report includes source status, parsed/ignored/error counters, included records, unknown times, observed spans and any declared spans. Possible source states are `pending`, `complete`, `incomplete` and `interrupted`.

`complete` describes completion of this import, not completeness of the original investigation or collection. A file may already be an incomplete, filtered or modified export. The report therefore retains `collection_completeness: "unknown"`, including for an empty input or a successful import.

Declared start/end bounds are analyst assertions. `within_declared_bounds` means the observed records fit inside them; it does not show that every event inside that interval was collected. Quiet intervals are not automatically labelled collection gaps or deletion evidence.

Unknown times, missing identifiers, parser errors, unfinished imports and included-event counts that differ from parser counts remain visible. A result with no matching leads is not a clean-state verdict.

## Source references and verification

Source identity incorporates the input SHA-256, format, parser version and interpretation options. Labels do not create a second independent source. Event identity incorporates source identity, physical line ordinal and raw-record SHA-256. Each event retains its byte offset and length.

Reports retain the source-copy digest, parser configuration, event references and original/corrected bounds. They omit acquisition filenames and filesystem stat metadata from `source_metadata`; an absolute source label is reduced to its final component. Internal labels, case names and analyst notes can still contain sensitive text. An ordinary report is not a public export.

Verification checks retained bytes and stored records against the parser and locators. A matching hash establishes consistency with a reference, assuming the reference is trusted. It does not establish authorship, an authentic acquisition time, complete custody, truthful log contents or complete collection.

## Reproducibility and report comparison

For fixed case metadata, evidence, hypotheses and configuration, report construction is deterministic. It does not add a new wall-clock generation timestamp. Canonical serialization sorts object keys and uses compact ASCII JSON.

Creating or replaying into a new case gives it a new case identifier. Whole-report bytes can therefore differ even when the normalized events and analysis are identical. Hypothesis identifiers and edits are also part of report content. Compare the relevant structures instead of assuming every new case must have the same report digest.

`testifex diff BEFORE AFTER` accepts full private `testifex.report.v1` reports. It validates their bounded schema and recomputes analysis from their contained events before comparison. Unknown fields, contradictory generated analysis, invalid references and malformed values fail explicitly.

The delta distinguishes added, removed and changed findings, sources, events and hypotheses. It separately reports analysis configuration changes and parser/source-option changes, including when the same input digest receives a different source identity. A finding removed after changing a window, parser, clock assumption or input is not proof that an incident was resolved. Added/removed lists and top-level reasons should be read together.

Finding identity is anchored to the rule and success record, or the success/process pair. Adding another failure to an existing success can change a finding without changing its ID. Changing a source's clock options changes source and event identities; the comparison then shows replacement evidence and findings rather than pretending the original interpretation was untouched.

## Bounds and failure behavior

Analysis accepts at most 100,000 events and 10,000 sources. Its default event cap is 100,000 and may be lowered. It allows at most 20,000 findings, 250,000 considered temporal relations, 250,000 finding evidence references and 250,000 ordering qualifications. The interval index prunes impossible ranges; it is not an unlimited streaming correlator.

The event representation, full report, report delta and public export each have explicit 64 MiB bounds. Dense matching, oversized inputs or exceeded limits fail rather than returning an apparently exhaustive partial analysis. Higher ingestion limits do not increase the analysis cap. See [formats.md](formats.md) for parser and ingestion limits.

## Public-share candidates

`testifex share` requires an external, owner-only file containing exactly 32 raw key bytes. The key is never a command-line value or a report field. Without `--public`, the candidate goes to standard output; providing `--output` without `--public` fails. The command does not publish anything to a service.

The public schema uses an allowlist. Case/source/event/finding/hypothesis identifiers, host/account/address/path/action values, parser-version identifiers and digests receive domain-separated HMAC-SHA256 pseudonyms. Equal values in the same domain stay linked with the same key; different domains do not share tokens. Original hashes are also replaced, since a known file hash can itself link a case to public evidence.

Case names, source labels, acquisition metadata, raw timestamp strings, event attributes, finding titles, hypothesis titles, assumptions, notes and correction-reason text are withheld. Counts, event kinds, parser-format enums, time bounds, clock adjustments, record locators, finding structure and evidence relationships remain visible. A withheld-field summary is included.

This is pseudonymization, not anonymity. Times, rare sequences, counts, known relationships and reuse of one key can enable correlation. Digest pseudonyms cannot independently verify the original bytes, and the export is not signed or authenticated as a whole. Review the candidate before sharing it and retain the private evidence separately. Public-report rendering checks structure and recomputes temporal semantics; it cannot verify the HMAC tokens without the secret key or establish authenticity of the underlying records.
