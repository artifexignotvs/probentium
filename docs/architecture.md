# Architecture and compatibility

The runtime has no network path or third-party dependency. Responsibility is separated into small modules:

| Layer | Responsibility |
| --- | --- |
| `safeio` | Bounded POSIX file access, immutable-by-convention copied evidence, stable descriptor verification and exclusive atomic output |
| `parsers`, `timeutil` | Selected record formats, strict input shapes and exact integer timestamp normalization |
| `case` | SQLite schema, source inventory, import checkpoints, byte locators, hypotheses and consistency verification |
| `analysis` | Bounded deterministic interval correlations, coverage and ordering conflicts |
| `report` | Validated reports, changes between reports, allowlisted pseudonymized schema and escaped Markdown |
| `cli`, `tui` | Scriptable commands and read-only keyboard browsing |
| `demo` | Reproducible synthetic end-to-end cases |

A case directory contains `case.sqlite3`, `evidence/<sha256>.bin` and `snapshots/<sha256>.json`. Copies are preserved byte-for-byte; evidence hashes are not a claim of immutable storage. The source inventory retains original basename, available file size/mode/mtime, acquisition method, parser version, transform options, progress and counters. It does not retain an absolute original path.

Source identity hashes the evidence digest, format, parser version and options. Changing a display label does not create independent evidence. Identical bytes with a different parser or correction are rejected within one case; create another case for that interpretation. Event identity hashes source identity, record ordinal and record digest. Repeated physical records remain separate occurrences; duplicate whole-file imports do not multiply findings.

Every normalized record carries exact byte offset and length in the imported copy, one-based record ordinal, raw-record hash, original time bounds, corrected bounds and time basis. An exported JSONL file is the imported source: this locator does not pretend to identify a byte location in an upstream database that was not acquired.

SQLite indexes support chronological iteration and actor/kind access. Imports stream bounded lines and commit every 256 records. Analysis materializes a bounded set, uses interval indexes for correlation and fails if its limits are exceeded. This is not a distributed engine. Use one writing process per case; concurrent interactive case editing and externally supplied databases are outside the supported workflow.

## Versions and reproduction

Case schema is version 1 (`PRAGMA user_version=1`); parser version is recorded per source; analysis includes rule version and configuration. Serialized report families carry explicit `.v1` schema identifiers. Unknown versions are refused rather than silently upgraded. A future migration must preserve original copies and produce a separately reviewable result; no fictitious migration command is shipped now.

Canonical JSON uses sorted keys, compact separators, ASCII escapes and finite values. Events and findings have deterministic identity and ordering. A replay reconstructs normalized events and analysis from verified complete source copies with the same recorded options and parser version. Case identity is intentionally new; full reports therefore are not byte-identical across newly created cases. Analyst hypothesis identifiers and links are copied. The original report's hash remains its own content identity.

Hypothesis status and notes are analyst-managed values. Updating a note replaces its current value; retain snapshots for earlier interpretations. The database is not an append-only audit ledger. Replay does not automatically recover previous notes, deleted sources or unavailable parser versions.

Plugins are not loaded in this preview. Any future executable extension must be treated as trusted code, explicitly installed and version recorded. A future documented adapter interface is a design direction, not a shipped capability.
