# Command reference

Use `testifex COMMAND --help` for exact arguments. Commands never prompt. Results go to stdout; diagnostics go to stderr. JSON output uses a stable canonical serializer, JSONL emits one object per line, and Markdown is available for reports. Output files are exclusively created and never silently replaced.

| Command | Purpose |
| --- | --- |
| `init DIRECTORY --name NAME` | Create a private local case |
| `ingest FILE --case CASE --format auth\|journal\|events --label LABEL` | Copy/hash one regular file and parse records |
| `resume SOURCE_ID --case CASE` | Continue the same source after digest/version checks |
| `sources --case CASE` | Inventory, acquisition metadata, counters and status |
| `issues --case CASE` | Safe diagnostic codes and record locations, JSONL |
| `timeline --case CASE` | Chronological lower-bound display, optionally filtered |
| `event EVENT_ID --case CASE [--raw]` | Full normalized record; explicit raw bytes as base64 |
| `analyze --case CASE` | Verified deterministic analysis in JSON; Markdown uses the full report |
| `triage --case CASE [--format text\|json] [--limit 10]` | Verified bounded overview; see [triage](triage.md) |
| `report --case CASE --format json\|markdown [--output FILE]` | Verified complete bounded report |
| `snapshot --case CASE --label LABEL` | Content-addressed report saved in the case |
| `diff BEFORE.json AFTER.json` | Validate and compare two full reports |
| `verify --case CASE` | Rehash evidence, reparse records and check stored accounting/indexes |
| `replay --case CASE --into DIRECTORY` | Rebuild from verified complete source copies |
| `hypothesis add\|link\|status\|list ... --case CASE` | Analyst statements and evidence links |
| `share --case CASE --key-file FILE` | Preview a pseudonymized candidate on stdout |
| `browse --case CASE [--ascii]` | Monochrome read-only TUI, requires a terminal |
| `demo --directory DIRECTORY` | Create and run both synthetic scenarios |

## Time and limits

`ingest --clock-offset SECONDS` means the source clock is ahead by that amount: corrected time = recorded time − offset. `--clock-error SECONDS` widens each end by a declared nonnegative error bound. Either requires `--reason`. Bounds accept exact microsecond-resolution decimal seconds, not approximate floating-point conversion. The maximum adjustment is 365 days.

`--declared-start` and `--declared-end` must be supplied together as timestamps with a known timezone offset. They express the analyst's expected collection interval, not proof of completeness. `--max-bytes` defaults to 1 GiB. `--max-records` defaults to one million and remains a cumulative ceiling during resume: increase it to continue a source stopped at that limit.

Timeline filters include `--source`, `--kind`, `--host`, `--actor`, `--after`, `--before`, `--limit` and `--format text|json|jsonl`. A time filter selects intervals that intersect the window. Unknown-time records are excluded from time-filtered output; without a time filter they appear last. The JSON envelope explicitly reports truncation; text/JSONL truncation is reported on stderr. Ordering by interval lower bound does not prove physical chronology.

Analysis/triage/report/snapshot/share accept `--threshold` (default 5), `--window` seconds (default 300) and `--max-events` (default/max 100,000). Further byte, relationship and finding budgets apply. Exceeding any budget is an error rather than a silent partial result.

## Analyst hypotheses

```sh
testifex hypothesis add --case investigation \
  --title 'Was the login unauthorized?' --assumption 'Collector identity is reliable'
testifex hypothesis link HYPOTHESIS_ID --case investigation \
  --event EVENT_ID --stance contradicts --note 'A change ticket may explain the action'
testifex hypothesis status HYPOTHESIS_ID --case investigation --state inconclusive
testifex hypothesis list --case investigation
```

Replace identifiers with actual command results. `supports`, `contradicts` and `context` describe the analyst's relationship, not a machine-validated truth. Status values are `open`, `supported`, `refuted` and `inconclusive`. Preserve snapshots if earlier notes/status values matter; current notes are mutable.

## Share a reviewed candidate

Create a random key in a private directory; do not reuse an example key for real evidence.

```sh
python3 -c 'import os; f=os.open("share.key", os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600); os.write(f, os.urandom(32)); os.close(f)'
testifex share --case investigation --key-file share.key
testifex share --case investigation --key-file share.key --public --output share-candidate.json
```

The first command previews to stdout. A file output requires the explicit `--public` flag; this means “write a share candidate”, not “publish to a network”. The key must contain exactly 32 bytes, belong to the current user and be inaccessible to group/other users. Do not put it in the case or repository. Free-form fields and notes are withheld; timestamps and relationships remain. Treat the output as requiring human review.

## Keyboard controls

`j/k` or arrow keys move; Page Up/Down page; `/` starts a literal case-insensitive filter; Enter opens event details; `r` explicitly reads a digest-checked, escaped raw preview; `q` returns or quits. Details show original/corrected intervals and byte location. Raw previews are capped at 16 KiB. Below 70 columns × 18 rows, the browser shows a resize/CLI hint. `--ascii` replaces non-ASCII display characters; the source copy remains unchanged.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Operation completed; findings do not cause failure |
| 2 | Invalid input/configuration, unsupported operation or I/O failure |
| 3 | Import has parse issues or stopped at its record limit |
| 4 | Consistency verification found a mismatch |
| 130 | Interrupted; committed import checkpoints remain resumable |

An incomplete import can still be inspected and reported with its missing/failed coverage explicit. Replay currently requires every source to be complete. Broken output pipes are handled without printing a traceback.
