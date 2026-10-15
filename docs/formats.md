# Formats and limits

This document describes the local TESTIFEX preview, package `testifex`, parser version `1`, analysis rule version `1`, and case schema version `1`.

Input consists of regular UTF-8 files. Select the parser explicitly with `--format auth`, `--format journal` or `--format events`; formats are not guessed. This preview does not parse disk images, packet captures, native journal files or native event-log databases. Other forensic tools' exports need an explicit conversion to one of the documented shapes; no universal export adapter is implied.

## Common line and JSON rules

- One physical line is one parsing unit. A final LF or CRLF is accepted. Embedded CR/LF characters are rejected. Blank or space/tab-only lines are ignored.
- A line is bounded to 1,048,576 bytes, including its terminator. Oversized lines become visible import errors; their tail is drained before the next physical line is parsed.
- Invalid UTF-8, duplicate JSON keys at any depth, floating-point JSON numbers, nonfinite constants and invalid Unicode/control characters are rejected.
- JSON must be an object. JSON traversal permits at most 4,096 value nodes and depth 8. An individual object or array has at most 128 entries. Keys have at most 128 characters; general text values have at most 4,096 characters.
- Parser errors use short diagnostic codes without echoing raw input. The original file remains in the private evidence copy. Ignored records and rejected records have separate counters.

The JSON reader checks the entire object, including journal fields that will not be retained. A malformed or oversized unused field can therefore reject the record.

## `events`: canonical JSON Lines

Each object requires `timestamp` and `kind`. These are the only allowed top-level fields:

| Field | Accepted value |
| --- | --- |
| `timestamp` | A nonempty RFC3339 string with an explicit timezone, or JSON `null` for an explicitly unknown time |
| `kind` | `auth.failure`, `auth.success`, `process.exec`, `file.observed`, `file.changed`, `network.connect`, or `generic` |
| `host` | Omitted, `null`, or a nonempty string of at most 253 characters without whitespace, `/` or `\`; `"-"` becomes an unknown host |
| `actor`, `path`, `action` | Omitted, `null`, or a nonempty string of at most 4,096 characters |
| `src_ip`, `dst_ip` | Omitted, `null`, or an IPv4/IPv6 address literal of at most 64 characters; hostnames, CIDR notation and scoped `%interface` suffixes are rejected |
| `attributes` | Omitted or an object containing only the typed fields below |

Unknown top-level fields and unknown attributes fail explicitly. Addresses are normalized using the standard-library IP parser. Empty strings do not stand in for unknown values. There is no automatic host or account alias resolution.

```json
{"timestamp":"2026-01-01T00:01:45.000000Z","kind":"process.exec","host":"edge-demo","actor":"operator","path":"/usr/bin/id","action":"execute"}
```

This is a synthetic record. A caller-supplied `kind` is a statement in the input, not independent proof that the described activity occurred.

Allowed integer attributes reject booleans and strings:

| Attribute | Inclusive range |
| --- | --- |
| `pid` | 1 through 2,147,483,647 |
| `parent_pid` | 0 through 2,147,483,647 |
| `uid`, `gid` | 0 through 4,294,967,295 |
| `port`, `dst_port` | 0 through 65,535 |
| `monotonic_us` | 0 through 9,223,372,036,854,775,807 |
| `source_realtime_us` | 0 through 253,402,300,799,999,999 |

Allowed nonempty text attributes are `protocol` (32 characters), `service` (64), `executable` (4,096), `result` (64), `unit` (256), and `boot_id` (exactly 32 hexadecimal characters, normalized to lowercase). Arbitrary nested attributes, raw messages and command argument arrays are not supported.

## `auth`: selected OpenSSH and sudo lines

The header accepts an RFC3339 timestamp or traditional month/day/time form, then a host and service with an optional PID. An optional syslog priority is 0 through 191.

```text
2026-01-01T00:00:00Z edge-demo sshd[1234]: Failed password for operator from 192.0.2.30 port 54321 ssh2
2026-01-01T00:01:30Z edge-demo sshd[1234]: Accepted publickey for operator from 192.0.2.30 port 54321 ssh2
```

Supported SSH services are `sshd` and `sshd-session`. Recognized outcomes are `Failed` and `Accepted`, including the `invalid user` failure form. Accepted method tokens are `password`, `publickey`, `keyboard-interactive`, `keyboard-interactive/pam`, `gssapi-with-mic`, `hostbased` and `none`. The parser records outcome, account, source IP, port, service and optional PID. The recognized line describes authentication; it does not establish a subsequently observed process's session membership.

Selected `sudo` denial forms become `auth.failure` without an invented source IP. A supported `COMMAND=` record becomes `process.exec` with action `sudo.command_recorded` and result `recorded`. The invoker is retained as actor. The first shell-parsed word is retained as executable; it becomes `path` only if absolute. Arguments are not copied into normalized attributes. This is a logged command request, not confirmation of successful execution or completion. Unsupported prefixes and malformed commands fail rather than being guessed.

A valid but irrelevant service/message is ignored. Recognized unsupported SSH authentication messages, unsupported methods and malformed headers produce errors. This parser does not claim coverage of every PAM, SSH or sudo message variant.

A traditional timestamp such as `Jan 1 00:00:00` has neither a year nor a timezone. Its raw text is retained with unknown bounds and basis `unknown_no_year_or_timezone`. The parser validates its calendar shape without borrowing the current year or local timezone.

## `journal`: one journal export object per line

Use JSON Lines as emitted by `journalctl -o json`, not binary journal files. `MESSAGE` must be a text string. Binary/repeated message representations are unsupported.

`__REALTIME_TIMESTAMP`, when present, is authoritative. It accepts a nonnegative integer or a decimal digit string in microseconds since the Unix epoch, bounded to the maximum supported calendar time. Zero is valid. A missing field yields unknown time with basis `unknown_journal_realtime_missing`; a present invalid or null value is an error.

| Input field | Retained interpretation |
| --- | --- |
| `_HOSTNAME` | Host, using the host rules above |
| `SYSLOG_IDENTIFIER`, falling back to `_COMM` | Service identifier used for supported message interpretation |
| `_PID`, falling back to `SYSLOG_PID` | PID |
| `_SOURCE_REALTIME_TIMESTAMP` | `source_realtime_us`; does not replace authoritative time |
| `__MONOTONIC_TIMESTAMP` | `monotonic_us`; not converted into UTC |
| `_BOOT_ID` | Validated `boot_id`; retained context, not automatic clock alignment |
| `_UID`, `_GID` | Numeric UID/GID attributes; not invented account names |
| `_SYSTEMD_UNIT` | `unit` attribute |
| `_EXE` | `executable` metadata; does not overwrite the command executable already derived from a sudo command record |

Supported SSH/sudo messages use the same interpretations as `auth`. Other messages become `generic` journal records; the raw message is not duplicated into normalized attributes. An executable field on a generic journal message alone does not promote it into a process-execution event. Other journal keys are ignored after structural validation.

## Timestamp rules

RFC3339 parsing requires a four-digit calendar year, full date and `HH:MM:SS`, a `T`/`t` separator, optional decimal fraction, and `Z`/`z` or an explicit numeric offset. Timestamp text is at most 96 characters. Offsets are applied using integer arithmetic. Parsed bounds must remain inside calendar years 1 through 9999.

| Representation | Stored inclusive cell width |
| --- | --- |
| No fractional digits | 1,000,000 microseconds |
| One fractional digit | 100,000 microseconds |
| Three fractional digits | 1,000 microseconds |
| Six fractional digits | 1 microsecond |
| More than six digits | The containing microsecond; original fraction preserved in `time_raw` |

Missing timezone, the unknown-offset notation `-00:00`, empty timestamps, invalid calendar dates, leap-second notation and `24:00:00` are rejected. Explicit timezone offsets are normalized; a timezone-less value is never silently treated as UTC. The parser retains basis strings describing seconds, fractional resolution or submicrosecond enclosure.

The resulting precision cell is not a measurement of physical clock error. Clock offset/error declarations are separate import options, explained in [analysis.md](analysis.md).

## Case and output structures

The private case stores copied input bytes, source records, normalized events, diagnostic issues, hypotheses and snapshots. Each normalized event includes source ID, physical line ordinal, byte offset/length, raw SHA-256, original timestamp text, original bounds, corrected bounds, clock parameters, kind, identifiers and bounded attributes. Unknown time uses `null` for both bounds.

Source records include parser version, options, digest, size, cursor, counters, observed bounds and import state. A source's declared start/end bounds must be supplied together. Declared coverage is an assertion, not verified acquisition completeness.

| Output | Schema |
| --- | --- |
| Analysis | `testifex.analysis.v1` |
| Full private report | `testifex.report.v1` |
| Report comparison | `testifex.report-delta.v1` |
| Public-share candidate | `testifex.public.v1` |
| JSON timeline | `testifex.timeline.v1` |
| Verification result | `testifex.verification.v1` |
| Synthetic demo summary | `testifex.demo.v1` |

Full reports contain `case`, `sources`, `events`, `analysis`, `hypotheses` and fixed limitations. Public candidates use a different allowlist and cannot be substituted for full reports in `diff`. The public form is pseudonymized and retains timing and structural information; it is not an anonymous or signed evidence package.

CLI JSON uses sorted keys, compact separators and ASCII escapes, followed by a newline. Report-comparison digests cover canonical JSON **without** that final newline. Snapshot file digests cover the stored canonical JSON **with** its newline. Source and record digests cover exact original bytes. These are distinct hash domains; compare the appropriate representation.

Unsupported case/schema versions fail. No automatic database migration or parser upgrade of stored evidence is performed. A source imported with a different parser version requires an explicit fresh interpretation workflow. Preserve the original case and compare another case instead of editing version fields in place.

## Operational bounds

Default ingestion limits are 1 GiB per file and 1,000,000 physical records. The file limit can be raised to 4 GiB; the record limit to 10,000,000. Reaching the record cap leaves an explicit resumable state. Parser errors remain in the issue stream. Analysis is separately bounded to 100,000 records and does not silently analyze only the first portion of a larger case.

Reports are bounded to 64 MiB. Source/event attributes and recursive JSON structures have additional bounds. Dense analyses can reach explicit relation/finding limits before reaching the event cap; see [analysis.md](analysis.md).

File operations require regular files and the POSIX safety primitives used by the implementation. Symlinks, including parent-directory symlinks, and special files are refused. Outputs are written without overwriting an existing path. A public-export key must contain exactly 32 raw bytes, have no group/world permissions and belong to the current user where ownership checking is available.

Operational success is exit code `0`; invalid input/configuration is `2`; an ingest/resume that is not complete is `3`; failed verification is `4`; interruption is `130`. A successful `diff` returns `0` whether reports are equal or different: inspect its `status` field. A JSON timeline reports `truncated`; text/JSONL modes also emit a truncation diagnostic to standard error when the requested result limit is exceeded.
