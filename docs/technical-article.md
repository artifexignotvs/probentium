# Fifteen seconds apart is not necessarily fifteen seconds later

The two records look straightforward: an SSH authentication succeeds at `00:01:30`, and a process record appears at `00:01:45`. Put them in a sorted table and the second record looks like the next step.

There are two separate questions. Does the recorded time support that order? And, even if it does, did the authentication cause the process?

TESTIFEX is a small offline terminal workbench built around making that distinction visible. Its current technical preview keeps source-byte references, parser settings, time intervals, analyst hypotheses and coverage qualifications alongside a bounded set of temporal leads. The example below is entirely synthetic. It makes no network requests and does not describe a real intrusion.

*Ordo temporum indicium est, non causa.*

## A reproducible small case

From a local checkout with the preview installed:

```sh
python3 -m testifex demo --directory ./temporal-demo
```

Use a fresh destination; existing output files are not overwritten. The demo writes nine synthetic SSH records and one canonical process record. Eight failures occur between `00:00:00` and `00:00:35`; authentication succeeds at `00:01:30`. The process record names `/usr/bin/id` at `00:01:45.000000Z`, with the same synthetic host and account labels.

The example uses the documentation address `192.0.2.30`. It sends no traffic to that address.

Two cases are created from the same input bytes:

- `auth-case` uses the recorded timestamp cells without an additional clock-error declaration.
- `uncertain-case` declares a symmetric 30-second error for the process source and records the reason. The authentication source is unchanged.

Both contain ten events and two temporal leads. The authentication-after-failures lead is certain within the supplied interval model in both cases. The process lead changes:

| Observation | Baseline bounds, UTC | With process clock error, UTC |
| --- | --- | --- |
| Authentication success | `00:01:30.000000` through `00:01:30.999999` | Unchanged |
| Process record | `00:01:45.000000` through `00:01:45.000000` | `00:01:15.000000` through `00:02:15.000000` |
| Process lead's ordering/window membership | `certain` | `possible` |

The authentication log has second resolution. TESTIFEX retains a one-second representation cell instead of printing additional zeroes and implying that the log measured microseconds. That cell is a representation convention, not a measured error distribution.

The process source has a six-digit fraction. Adding a declared clock error expands its interval on both sides. The expanded interval overlaps authentication: the process record could be earlier or later within the supplied model. The chronological link is therefore possible, not certain. There is no invented confidence percentage.

## What the comparison actually says

The demo writes `auth-case.json`, `uncertain-case.json`, Markdown versions of both, and `comparison.json`. They can also be compared explicitly:

```sh
python3 -m testifex diff ./temporal-demo/auth-case.json ./temporal-demo/uncertain-case.json
python3 -m testifex verify --case ./temporal-demo/auth-case
python3 -m testifex verify --case ./temporal-demo/uncertain-case
```

The process input has the same SHA-256 in both cases. Its interpretation options differ. Source identity includes those options, so the process event and its anchored finding receive new identities. The delta records one removed and one added process lead, plus the source-option change. It does not silently overwrite the earlier interpretation or mislabel the removed finding as a resolved incident.

Case identifiers and analyst-hypothesis identifiers also differ because the demo creates two cases. That is visible in the comparison. Reproducibility here means being able to trace and recompute the result under each recorded set of assumptions, not expecting two independently created cases to have identical entire report files.

## The stronger conclusion is still unavailable

Even in the baseline, a certain ordering result proves no session relationship. Host and account labels can match while two activities are unrelated. A process record does not establish who initiated it, whether the activity was authorized or whether execution completed. A logged sudo command is especially easy to overread: the parser calls it a recorded command, not a confirmed outcome.

The same caution applies to the eight preceding failures. They are eight matching records. Another overlapping collection might contain copies of the same underlying attempts. Identical raw files cannot be counted again under a conflicting import configuration in one case, but broader semantic deduplication is not claimed.

## Check the record, then check the collection

Every normalized event carries a source identifier, physical line ordinal, byte offset, length and raw-record SHA-256. Source copies retain their own digests and parser configuration. Verification can check those bytes and reproduce normalization.

A matching hash answers a consistency question. It does not prove who wrote the source, whether collection was authentic, or whether a missing file should have been present. A fully consumed import can still originate from an incomplete export. TESTIFEX therefore leaves collection completeness unknown and shows parser errors, unfinished sources and unknown timestamps explicitly. A quiet interval is not labelled log deletion.

The terminal browser and Markdown reports are intended to make these qualifications easier to inspect, not to hide them behind a score.

## Sharing without copying the whole case

A separate public-share command replaces identifiers and evidence digests with typed HMAC-SHA256 pseudonyms using a private, 32-byte external key. It withholds source labels, case names, raw timestamp strings, event attributes and analyst free text. Evidence references remain linked within the candidate.

This does not make the case anonymous. Times, counts and rare event relationships remain visible, and reuse of one key links exports. The result is a candidate for review, not an automatic publication or an authenticated evidence package.

## A narrow preview, with narrow claims

Timeline analysis, provenance and analyst annotations are established practices. [Plaso documents processing metadata and parser counters](https://plaso.readthedocs.io/en/stable/sources/user/Using-pinfo.html), [Timesketch documents timelines and analyst context](https://timesketch.org/guides/user/basic-concepts/), and [Dissect offers terminal forensic queries](https://docs.dissect.tools/en/latest/tools/target-query.html). TESTIFEX does not claim to replace their acquisition or parser breadth, or to introduce timeline correlation as a new idea.

This preview supports selected SSH/sudo text, journal JSON and a small canonical event format. It uses explicit bounds and currently reports two rule types. No speed, detection-rate, novelty or superiority claim follows from this example.

The useful review question is concrete: given these two reports, can another analyst find the exact source record, explain why the ordering changed, and identify what still cannot be concluded? That is the workflow this preview is meant to make inspectable.

Source and reproducible examples: [TESTIFEX on GitHub](https://github.com/artifexignotvs/testifex). The complete current core is licensed under Apache-2.0.
