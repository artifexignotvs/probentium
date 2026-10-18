# Scoped control observations

`control-observation.v1` is a strict supplied-data contract for restore, MFA and remediation observations. The structural schema is [control-observation.v1.schema.json](../schemas/control-observation.v1.schema.json). The runtime also enforces case references, scope, timestamps, safe text and budgets. It does not execute a restore, change authentication settings, scan a host or authenticate an analyst's declarations.

The required fields are `schema`, `procedure_id`, `service_ref`, `population_ref`, `period`, `expected`, `observed`, `source_refs`, and `attestation`. Unknown fields are rejected at every level. A required result key may contain `null` when unknown; omitting it is invalid. `period` has RFC3339 `start` and `end`; `attestation` has `actor`, `at`, and `statement`. The attestation cannot predate the observed period's end.

| Procedure | Expected fields | Fields on each observation, in addition to `subject` and `source_refs` |
| --- | --- | --- |
| `restore.v1` | `rto_us`, `rpo_us` | `restored`, `functional_check`, `elapsed_us`, `data_age_us` |
| `mfa.v1` | `configured: true`, `enforced: true` | `configured`, `enforced` |
| `remediation.v1` | `remediated: true`, `retest_passed: true` | `applicable`, `remediated`, `retest_passed` |

Durations are nonnegative canonical decimal strings containing microseconds, with at most 19 digits, or `null`. Booleans in observed results also accept `null`. Expected restore limits may be unknown; unknown limits cannot produce a passing restoration assessment. Expected MFA/remediation values must be `true`, so a failing desired outcome cannot be turned into a passing control.

A `eu.control_population` is created with the existing governance `put` action. It contains the common fields `logical_id`, `actor`, `recorded_at`, `basis_refs`, `rationale`, `supersedes`, plus `service_ref`, `unit`, `members`, `complete`, and `period`. Units are `service_restore`, `account_access_path`, and `asset_finding`, respectively. The observation must reference the same service, appropriate unit, listed members and a contained period. An incomplete population yields `population: null` and `missing: null`; known rows do not imply a complete denominator. A complete population can still have unobserved members, which count as missing.

`governance observe` takes this input document and stores an immutable `eu.control_observation`. Its domain-separated input digest and exact dependency references are checked on read. `governance observation-assess` returns counts for supplied rows, passed, failed, unknown and missing. A referenced document alone cannot establish effectiveness. Rows without source references are unknown, and a non-applicable or unknown remediation finding is not counted as a passing retest. An assessment is limited to the stored period and population; it is not a claim about present production state.

The case budget is 20,000 observation rows shared with the older `eu.control_test` format, with a 16 MiB input bound. Each reference list is limited to 64, subject and actor text to 256 characters, and an attestation statement to 4,096. Case revision conflicts reject a write. The case dependency graph includes population, service and source dependencies.

The API `governance.append_demo_control_observations(case, service_ref, source_ref, period)` creates three explicitly fictional populations and stored observation documents. Its restore result passes the supplied limits, MFA retains one unknown result, and remediation fails its retest. The helper is for a fresh synthetic demonstration case and does not claim an independent assessment.

## CLI

Use the existing case directory for `CASE` and an actual returned object ID for `OBSERVATION_ID`. `population.json` is a governance wrapper `{"kind":"control_population","data":{...}}`; `observation.json` is the direct closed observation input, with the returned population ID.

```sh
probentium schema control-observation.v1
probentium governance put --case CASE --input population.json
probentium governance observe --case CASE --input observation.json
probentium governance observation-assess --case CASE --id OBSERVATION_ID
```

The two writes accept `--expect-revision` to reject a stale case view. Assessment takes no input document. Output can contain private subject aliases, evidence IDs and declarations; inspect before sharing.
