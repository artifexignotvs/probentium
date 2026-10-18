# Immutable operational deadline evaluations

`reporting evaluate-deadline` freezes a `eu.deadline_evaluation` for one stored reporting-track revision, one rule and one calendar from that track's immutable legal pack. The input document contains `rule_id`, `calendar_id`, `as_of` and optionally `exception`. `as_of` is a supplied RFC3339 instant, not a hidden reading of the system clock. The evaluation binds the case revision, rule/calendar/input/result digests, anchor object references, pack review/activation context and filing states. Rule arithmetic uses fixed named operators; legal packs cannot supply executable expressions.

`reporting deadline-replay` recomputes the result from its frozen inputs and checks those inputs against the referenced case records. It verifies current case integrity first. Corruption fails with exit 4. Authorized missing source bytes yield partial/exit 3 while separately reporting that the retained input computation replayed. This is a native-case history check; a transported object's structural validation does not alone prove its original case revision or dependencies.

`reporting deadline-status` reports whether later recorded anchor/track corrections, relevant pack activation/review expiry, or filing-state changes make the evaluation stale. Unrelated service records do not invalidate it. Later records cannot rewrite the historical result. A different `as_of` explicitly requires a new operational evaluation, even when the frozen inputs remain current. Prepared filings, approval records, asserted submissions and linked receipts remain separate references; preparation does not imply submission or legal acceptance.

Every current implementation result has `legal_deadline: null`, `legally_verified: false`, `legal_countdown_enabled: false`, and `reference_vectors_reviewed: false`. Local review attestations and passing software tests do not become independent legal review. The arithmetic does not decide reportability, jurisdiction, qualification, or whether a notification is due. Built-in draft profiles and these supplied policies remain operational planning aids.

## Explicit calendar input

Executable calendars are imported inside a legal pack and require this closed shape:

```json
{
  "schema": "probentium.calendar-policy.v1",
  "id": "exercise-utc",
  "version": "1",
  "timezone": "UTC",
  "timezone_data": null,
  "source_ids": ["synthetic-input"],
  "hour_rule": "elapsed_hours",
  "day_rule": "elapsed_days",
  "month_rule": "same_local_time_clamp",
  "nonworking_rule": "none",
  "weekend_days": [5, 6],
  "holidays": [],
  "holiday_coverage": {"start": "2026-01-01", "end": "2026-12-31"},
  "status": "unverified"
}
```

`source_ids` must refer to sources within the same legal pack. UTC requires no timezone payload. Other zones require a supplied base64 TZif snapshot of at most 65,536 decoded bytes, bound by the calendar digest; evaluation does not read an installed timezone database or fetch holidays. The zone label and supplied bytes are not independently authenticated. An ambiguous or nonexistent local target produces `calendar_unknown`, not a silently chosen clock fold. Holiday coverage is explicit; missing coverage needed for adjustment also produces `calendar_unknown`.

Supported hour rules are `elapsed_hours` and `exclude_started_hour`; day rules are `elapsed_days` and `exclude_start_day_end_of_day`; month rules are `same_local_time_clamp` and `exclude_start_day_end_of_day`. Calendar month arithmetic preserves the local date/time where it exists and clamps an absent month-end date. It is distinct from 30 elapsed days. End-of-day policies use the final representable microsecond of the specified local day.

Nonworking-day policy is explicitly `none`, `next_working_day_end`, or `dora_next_working_day_noon`. There are at most 1,000 supplied holiday dates and at most six configured weekend weekdays. A single end adjustment stops after 370 steps. The bounded plan below can apply a supplied minimum working-day rule and precedence order. Applicability of those conventions, retroactive periods and precedence between legal instruments is never inferred.

Elapsed interval shifts preserve open endpoints. Non-injective calendar shifts use a clearly labelled closed enclosure of possible targets while retaining the original input interval. Such an enclosure can be conservative; it is not presented as a newly precise awareness time. Unknown trigger, waiting trigger, known trigger with unknown time, an interval, and unresolved calendar time remain different states.

## Explicit DORA exception assertion

The optional exception is a closed object with `kind: "dora_nonworking"`, `stage` (`initial`, `intermediate`, `final`), `entity_class` (`credit_institution`, `central_counterparty`, `trading_venue`, `other`), nullable booleans `nis2_essential_or_important` and `authority_exclusion`, and `actor`, `at`, `rationale`, and nonempty `basis_refs`. It is accepted only for a DORA track, matching rule stage and explicit DORA calendar policy. Its attestation time cannot be later than the evaluation's `as_of`. Unknown eligibility preserves the unextended operational target.

The DORA named operator retains the four-hour classification/24-hour awareness constraint and its late-classification branch. Intermediate and final rules require distinct submitted/intermediate/latest-intermediate anchors. Weekend relief is excluded for initial/intermediate reports under the supplied excluded-entity or authority facts; the final-stage exception is treated separately. `authority_exclusion` is an analyst's incident-specific assertion: the software does not determine when an authority's notified decision became applicable. Failure to meet a target does not itself decide the separate duty to explain delay. These interpretations were checked against [Delegated Regulation (EU) 2025/301, Article 5](https://eur-lex.europa.eu/eli/reg_del/2025/301/oj/eng) on 2026-10-19.

General period conventions and Member State holiday context require their own applicability review; an hours-based period does not automatically inherit the general non-hours weekend rule. See [Regulation 1182/71, Articles 1–3](https://eur-lex.europa.eu/eli/reg/1971/1182/oj/eng). The calendar's operator selection remains explicit and unverified.

## Bounded calendar plans

A rule can use `operator: "calendar_plan"` with a `parameters` object conforming to [deadline-plan.v1.schema.json](../schemas/deadline-plan.v1.schema.json). The object has exactly `schema: "probentium.deadline-plan.v1"`, `nodes`, and `output`. It is an ordered finite graph, not executable source text. All node fields below are mandatory and unknown keys are rejected.

| Node `op` | Additional fields after `id` and `op` | Meaning |
| --- | --- | --- |
| `anchor` | `anchor` | One of awareness, classification, submitted, intermediate, latest_intermediate, measure_available, resolved. |
| `shift` | `input`, `unit`, `amount` | Shift a previous node by 1–366 hours, days or months under the frozen calendar. |
| `working_days` | `input`, `count`, `include_start_day`, `completion` | Find working day 1–366 from a previous node; explicit start-day inclusion and `local_end_of_day` or `same_local_time`. |
| `nonworking_adjust` | `input`, `mode` | Explicit `none`, `next_working_day_end`, or `dora_next_working_day_noon`; DORA eligibility assertions and role exclusions still apply. |
| `combine` | `inputs`, `mode` | Minimum or maximum of 2–8 previous nodes. Unknown required inputs do not disappear merely because another term is known. |
| `precedence` | `candidates` | Ordered 1–8 objects `{input, applies}`; `applies` is a supplied boolean or null. The first true candidate is selected. An earlier null blocks fallback; false explicitly excludes that policy. |
| `dora_initial` | `awareness`, `classification` | Two previous direct anchor nodes with the corresponding fixed meanings; apply the existing four/24-hour calculation including its late-classification branch. DORA profile only. |

IDs are unique ASCII identifiers of at most 64 characters. References must point backward; cycles and forward references are rejected. `output` must name the final node, and every node must be reachable from it. The maximum is 16 nodes and 64 KiB. Working-day enumeration stops after 3,700 examined dates. Missing supplied holiday coverage or ambiguous local time produces `calendar_unknown`. Input limits are validated before evaluation and result copies.

For example, this plan enforces a **supplied operational** minimum of two complete working days after the start date, keeps a longer nominal two-day period, then adjusts a nonworking end. This policy is not automatically selected for any jurisdiction:

```json
{
  "schema": "probentium.deadline-plan.v1",
  "nodes": [
    {"id":"start","op":"anchor","anchor":"awareness"},
    {"id":"nominal","op":"shift","input":"start","unit":"days","amount":2},
    {"id":"working","op":"working_days","input":"start","count":2,"include_start_day":false,"completion":"local_end_of_day"},
    {"id":"minimum_days","op":"combine","inputs":["nominal","working"],"mode":"maximum"},
    {"id":"adjusted","op":"nonworking_adjust","input":"minimum_days","mode":"next_working_day_end"}
  ],
  "output":"adjusted"
}
```

To express specific-policy precedence, calculate the candidate targets, then select them using explicit `applies` facts. Selection does not automatically apply the general calendar adjustment again. A chosen predecessor whose time is unknown remains unknown; the tool cannot silently substitute an earlier filing or awareness. `applies` is an operator-supplied assumption, not a legal conclusion or authenticated review.

Each persisted evaluation binds the complete plan and contains its digest and per-node trace, including input IDs, selected predecessor, target or interval, and reasons. Replay recomputes this trace. Interval combinations and non-injective calendar mappings use labelled conservative enclosures; original open endpoints remain visible in the anchor trace. Month-end, supplied DST transitions, holidays, minimum-working-day rules, precedence, unknowns, limits and trace tampering have local regression vectors. Those vectors are software tests, not independently reviewed legal evidence.

The synthetic reporting demonstration stores a fictional 24-hour follow-up rule, UTC calendar and a replayable evaluation alongside its two prepared filings. It activates no legal pack and sends no report.

## CLI

Replace `CASE`, `TRACK_ID` and `EVALUATION_ID` with the existing case and actual returned object IDs. For the synthetic reporting demonstration, save this as `deadline.json`:

```json
{"rule_id":"exercise-followup","calendar_id":"exercise-utc","as_of":"2026-10-18T12:00:00Z"}
```

Save `{"as_of":"2026-10-18T14:00:00Z"}` as `as-of.json`, then use:

```sh
probentium reporting evaluate-deadline --case CASE --id TRACK_ID --input deadline.json
probentium reporting deadline-status --case CASE --id EVALUATION_ID --input as-of.json
probentium reporting deadline-replay --case CASE --id EVALUATION_ID
```

Evaluation appends an immutable record and accepts `--expect-revision`. Status and replay are read-only. Replay takes no input document. These receipts may reveal private anchors, track identities, filing states and analyst reasoning; inspect before sharing.
