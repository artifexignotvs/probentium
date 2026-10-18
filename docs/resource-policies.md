# Explicit resource policies

Resource budgets belong to the operation. No environment variable raises them,
and creating a case does not silently install a new policy for later commands.
Omitting `--resource-policy` preserves the existing defaults. A supplied policy is
a closed, versioned JSON object; unknown fields, booleans used as counts and
values beyond hard caps are rejected before acquisition or packet processing.

| Budget | Default | Hard cap |
| --- | ---: | ---: |
| Source bytes | 1 GiB | 4 GiB |
| Acquired source bytes in a case | 20 GiB | 100 GiB |
| Records processed in one import/resume invocation | 1,000,000 | 10,000,000 |
| Events in a case | 1,000,000 | 10,000,000 |
| Packet bytes including archive padding | 8 GiB | 100 GiB |

Messages/lines remain capped at 1 MiB, JSON depth at 32, a packet blob at 4 GiB
and packet members at 20,000. The entire case's stored record index also has a
10-million-record hard ceiling. Independent SQLite-file and snapshot-metadata
ceilings remain 4 GiB. Temporary storage and filesystem capacity can stop work
earlier. These are safety ceilings, not a claim that the maximum-size workloads
have passed performance or platform acceptance.

This is a complete default policy document, suitable for saving as `policy.json`:

```json
{
  "schema": "probentium.resource-policy.v1",
  "max_source_bytes": 1073741824,
  "max_case_bytes": 21474836480,
  "max_import_records": 1000000,
  "max_case_events": 1000000,
  "max_packet_bytes": 8589934592,
  "max_message_bytes": 1048576,
  "max_json_depth": 32,
  "max_blob_bytes": 4294967296,
  "max_packet_members": 20000
}
```

```sh
probentium inspect SOURCE.jsonl --format events-v2 --resource-policy policy.json
probentium ingest SOURCE.jsonl --case CASE --format events-v2 --label 'Copied source' --resource-policy policy.json
probentium resume --case CASE --id PARSE_RUN_ID --resource-policy policy.json
probentium batch plan --input sources.json --resource-policy policy.json > batch-plan.json
probentium batch execute --case CASE --input batch-plan.json --resource-policy policy.json
probentium packet export --case CASE --output evidence.pbp --resource-policy policy.json
probentium packet verify --input evidence.pbp --resource-policy policy.json
probentium packet restore --input evidence.pbp --output RESTORED_CASE --resource-policy policy.json
```

An explicit import policy is frozen in the parse configuration and its digest.
Resume reuses the recorded policy and refuses a contradictory explicit selection.
`resume --id` accepts an active parse-run ID or its artifact ID. An inactive run
is refused rather than silently selecting another interpretation.
A record budget can leave an explicitly incomplete resumable run; its counters
and unprocessed bytes remain visible. A different policy requires a different
parse run, not rewriting the previous interpretation.

An explicitly configured packet binds its declared policy in the manifest.
The receiver separately selects a local policy. A packet can never raise the
receiver's limits by declaring a larger budget. A default reader retains the
historical default row ceilings; a larger packet requires both an explicit
sender policy and an explicit local receiving policy. Receipts report the
selected policy and digest. Restore, replay, recovery, migration and encrypted
packet transport accept the same policy option at their relevant boundary.

## Analysis is a separate budget

Acquiring a larger case does not silently widen analytical scope. Analyses remain
limited to 100,000 events, 20,000 findings, 250,000 relations/support references,
32 time variables per comparison and 64 scenarios. A closed
`probentium.analysis-limits.v1` document may lower limits or raise only the
explicitly allowed budgets, such as claims from 1,000 up to 10,000.

```json
{"schema":"probentium.analysis-limits.v1","max_claims":2000,"max_wall_seconds":300}
```

```sh
probentium claim evaluate --case CASE --id CLAIM_ID --analysis-limits analysis-limits.json --execution-receipt --resource-mode strict
```

The analysis receipt reports the actual held input and output revision, effective
limits and enforcement mechanism. On Linux, child address-space limits combine
with parent RSS/wall-time monitoring; the parent process is not given the child's
limit. Monitored RSS can miss brief peaks and is not a hard memory guarantee.
Strict unsupported-platform requests fail explicitly. Process resource limits
are not an operating-system network or hostile-code sandbox.
