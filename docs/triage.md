# A compact local overview

`testifex triage --case CASE` provides a monochrome terminal summary of a case. It runs the same evidence-consistency verification and bounded report construction as `report`; changed evidence or invalid analysis stops the command before any overview is emitted.

```sh
testifex demo --directory ./temporal-demo
testifex triage --case ./temporal-demo/auth-case
testifex triage --case ./temporal-demo/uncertain-case --format json
```

The synthetic cases each contain ten events and two temporal leads. The first overview counts two certain leads. With the process source's declared 30-second clock error, the second counts one certain lead and one possible lead. These labels describe ordering and window membership under the supplied interval model. They are not incident-confidence scores or proof of a shared session.

## What is shown

- Source totals and complete, incomplete, interrupted and pending import counts.
- Records read, parsed, ignored and rejected; events with known or unknown time; events missing identifiers required by temporal rules.
- Unknown collection completeness, unfinished sources, sources with parsing errors and included-event subsets.
- Declared-span counts, sources extending outside a declaration and the number of ordering qualifications.
- Active threshold and time-window settings, total certain/possible leads, and a bounded list of finding identifiers, rule names, ordering and evidence-record counts.
- For authentication-after-failures leads, matching and certain failure-record counts plus the separate threshold qualification.

Import status and collection completeness mean different things. A complete import can still come from an incomplete collection. An interrupted source can pass verification of its retained prefix; the overview continues to show that unfinished status. Parse errors and unknown timestamps remain visible even when no rule produces a finding. No findings is not a clean-state verdict.

The overview withholds case names, source labels and filenames, raw records, host/account/IP/path values, attributes, timestamps and analyst free text. It is still a local overview, not a public-share export: counts and stable finding identifiers can reveal relationships. Use the separate `share` workflow for a reviewed pseudonymized candidate.

## Limits and output

```sh
testifex triage --case investigation --limit 5
testifex triage --case investigation --format json --limit 100
testifex triage --case investigation --threshold 8 --window 120 --output overview.txt
```

The default display limit is ten findings; accepted limits are 1 through 100. Every result records how many findings were shown and omitted. Findings retain the validated report's deterministic order by interval lower bound, upper bound and identifier. This display order does not establish physical chronology.

The display limit never shortens analysis. All supplied events must fit the existing analysis budgets. `--max-events` defaults to 100,000 and cannot exceed that value; a smaller value fails if the case contains more events. Existing source, report-byte, finding and relationship limits also apply. Use `report` to inspect findings beyond the compact display limit. Text output has at most three lines per shown finding plus a fixed-size overview and caveats; it does not emit a row for every source.

`--output` creates a private new file and never overwrites an existing path. The default format is `text`; `--format json` emits canonical JSON with schema `testifex.triage.v1`. JSON includes aggregate source/record/event/coverage counts, ordering-qualification counts by reason, rule configuration, finding totals, shown items, omitted count and limitations. It contains no per-event data or raw source digests. Finding IDs are the original stable report identifiers, not keyed pseudonyms.

Successful triage returns exit code 0 even when findings, errors or unfinished sources are present; inspect the summary. Invalid limits, failed verification, unsupported input and I/O errors return 2. This command neither changes a case nor sends anything over the network.
