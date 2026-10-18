# Events v2 input contract

The `events-v2` adapter accepts UTF-8 JSON records with the discriminator
`"schema":"testifex.events.v2"`. Select the format explicitly during ingestion;
the file extension does not select it. Adapter implementation version
`probentium-adapters-2.1` supports the nine kinds below. It does not execute
commands, open event paths, resolve hosts or fetch upstream locators.

Each required key must be present. A required payload value may be `null` when
it is unknown; the adapter preserves that value. An absent required key is an
invalid record, not an instruction to infer its value. Optional keys may be
omitted. Objects are closed: unknown keys are rejected at the record, payload,
origin and recorded-time levels.

## Supported payloads

| Kind | Required payload keys | Additional permitted payload keys |
| --- | --- | --- |
| `auth.failure` | `service` | `method`, `reason` |
| `auth.success` | `service` | `method` |
| `process.start` | `pid`, `executable` | `parent_pid`, `command` |
| `process.command` | `command` | `pid`, `parent_pid`, `executable` |
| `file.create` | `path` | `digest_algorithm`, `digest` |
| `file.modify` | `path` | `digest_algorithm`, `digest` |
| `file.delete` | `path` | `digest_algorithm`, `digest` |
| `network.connection` | `protocol`, `local_ip`, `remote_ip`, `local_port`, `remote_port` | `direction` |
| `account.change` | `action`, `target_account` | None |

Text fields accept `null` or a nonempty string of at most 4,096 Unicode code
points. Empty strings are rejected. Text is a supplied assertion: a command is
not executed, a path is not acquired, and an account identifier is not resolved.
Protocol, service, action and method names are not restricted to a predefined
vocabulary or checked against a host. Unknown text should be `null`.

`pid` and `parent_pid` accept `null` or an integer from 0 through 2,147,483,647.
Ports accept `null` or an integer from 0 through 65,535. A Boolean, numeric
string or floating-point JSON token is not an integer for this adapter.
Port zero is preserved as supplied; the adapter does not interpret its meaning.

IP fields accept `null` or a syntactically valid IPv4/IPv6 address. Hostnames,
CIDR networks, IPv6 zone suffixes and IPv4 addresses with leading-zero octets
are rejected. Address syntax does not establish ownership or reachability.
`direction` may be `null`, `inbound`, `outbound` or `unknown`.

File digests may both be absent or `null`. When either is non-null, both must
be supplied: `digest_algorithm` must be `md5`, `sha1`, `sha256` or `sha512`, and
`digest` must contain respectively 32, 40, 64 or 128 lowercase hexadecimal
characters. These are reported source values, not a digest computed over a
file acquired by this event. Accepting a reported MD5/SHA-1 value does not
endorse it as an integrity primitive for case storage.

## Record envelope

Required top-level keys are `schema`, `kind`, `recorded_time`, `origin` and
`payload`. `payload` must always be an object, including when all its required
values are unknown.

Optional top-level keys are `host`, `actor`, `source_ip`, `source_record_key`
and `timestamp_semantics`. The first four accept `null`; their known values
follow the text/IP rules above. `timestamp_semantics` accepts `event_time`,
`log_write_time`, `export_time` or `unknown`. Omission means `unknown`; an
explicit `null` is rejected for this enumerated field.

`origin` must be `null` or an object containing exactly `export_tool`,
`export_version` and `upstream_locator`. Each of these three values may be
`null` or text. The normalized output labels the locator
`upstream_locator_status: supplied_assertion`. It does not claim independent
provenance or authentication of the upstream export.

An explicitly unknown process event is valid:

```json
{
  "schema": "testifex.events.v2",
  "kind": "process.start",
  "recorded_time": null,
  "origin": null,
  "payload": {"pid": null, "executable": null}
}
```

Deleting `pid` from this example makes it invalid. It is not replaced with
zero, and no process identity is invented.

## Time representation

`recorded_time` must be `null` or an object containing exactly `value`,
`encoding` and `resolution_us`. A null recorded time stays unknown; the
adapter does not substitute ingestion time or the machine's local timezone.

`encoding` is `rfc3339` or `unix_us`. Both `value` and `resolution_us` are
strings. `resolution_us` is a positive decimal integer without leading zeroes,
from `"1"` through `"999999999999999"`. The whole resulting interval must fit
the supported timestamp range.

- `rfc3339` requires an explicit `Z` or numeric UTC offset, a valid calendar
  date and time, and at most 96 characters. Lowercase `t`/`z` is accepted.
  `-00:00`, leap-second notation and timezone-free values are rejected.
  Fractional seconds may have more than six digits; the result encloses them
  within the applicable microsecond cell.
- `unix_us` is a signed decimal microsecond string matching
  `-?(0|[1-9][0-9]{0,17})`. Numeric JSON tokens, exponent notation, a leading
  plus sign and redundant leading zeroes are rejected. Exact integer parsing
  preserves values beyond JavaScript's safe integer range.

The result is a closed interval whose width is the larger of the explicitly
declared resolution and the precision implied by the original timestamp.
For example, an RFC3339 value ending in whole seconds retains a one-second
cell even if `resolution_us` is `"1"`. Resolution is not an assertion of
clock accuracy, timezone correctness or causal order. Runtime validation
rejects intervals outside UTC years 0001 through 9999, including intervals
whose lower bound fits but whose upper bound overflows.

## Validation scope and compatibility

The formal [JSON Schema](../schemas/events-v2.schema.json) uses Draft 2020-12.
Use a validator with IPv4/IPv6 format checking enabled; format annotations
alone need not reject an invalid address. The schema describes field presence,
closed objects, value types, lengths, ranges and conditional digest pairs.

The runtime parser remains authoritative for UTF-8, duplicate JSON keys,
floating-point tokens, Unicode validity, the 1 MiB raw-record limit, JSON depth,
calendar validity and timestamp-interval bounds. A JSON Schema validator may
consider `1.0` an integer after decoding, while the runtime deliberately rejects
that wire representation. Passing structural validation alone does not mean
that a record will pass ingestion or that its contents are true.

Version 2.1 rejects incomplete payloads that version 2.0 accepted. Supply
explicit null values when the required facts are genuinely unknown; do not
invent them to make an import pass. The wire discriminator remains
`testifex.events.v2`. Historical parser identities and results are not rewritten;
replay still requires a supported matching parser identity. This contract does
not widen or change the separate legacy `events` format.

The runtime suite includes valid and invalid cases for all nine kinds,
null-versus-absent checks, closed-object checks and adversarial value boundaries:

```sh
python -m unittest tests_r1.test_adapters_v2 -v
```

For a separate structural validator, install the development-only dependency
`jsonschema==4.25.1` and run:

```sh
python scripts/check_event_schema.py
```

The script checks the schema itself and the shared valid/invalid structural
fixtures with format checking enabled. It fails explicitly when its required
development dependency is absent or has another version. Runtime-only wire
and time-bound cases are counted separately and exercised by the unit suite.
This cross-check is not an independent security assessment or a claim that
every possible malformed input has been tested.
