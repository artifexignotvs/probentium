# Threat model

## Assets and trust

Assets are source bytes, their recorded digests, normalized records, transformations, analyst notes and the confidentiality of case content. Input files can contain malformed encodings, oversized records, contradictory timestamps and terminal control sequences.

The host, filesystem, runtime, current user and case directory are trusted. Reference hashes stored alongside evidence are not independently authenticated. A same-user attacker or administrator can replace both. SQLite is not an untrusted-document sandbox: do not open a case database supplied by an adversary; import copied evidence into a newly created case instead.

## Boundaries and defenses

| Boundary | Implemented behavior | Remaining limit |
| --- | --- | --- |
| Input path | POSIX descriptor-based opening refuses symlinks in every component, non-regular files and files above the size limit. | Use canonical paths. This is not remote acquisition or a device write blocker. |
| Acquisition | Stream to an owner-only copy, calculate SHA-256, check file identity/size/mtime/ctime before and after reading, then install by content hash. | Reading a writable original may affect atime. Hostile same-user filesystem mutation is outside the authenticity boundary. |
| Parse/verify | Hash and parse the same opened descriptor; rehash before successful completion and check descriptor/directory-entry stability. | A failed operation can have earlier committed checkpoints, explicitly marked interrupted. Verification is still required before relying on them. |
| Stored paths | Exact source digest and source identity validation precede evidence-path construction. | Local metadata and analyst assertions are not signed by an independent authority. |
| Records | Bounded line reads, strict JSON duplicate-key/type/depth limits, visible parser issues. No shell evaluation. | Same-process parsers can consume CPU up to imposed limits. No hard CPU sandbox or archive handling. |
| Analysis | Event, serialized-size, finding and relationship limits fail visibly. | Bounds are not a universal RAM ceiling; object overhead varies. Large cases need partitioning or future streaming analysis. |
| Terminal | Untrusted controls and bidi controls escaped, literal filter, raw preview only on explicit request. | A raw preview intentionally reveals evidence content to the terminal user and terminal history. |
| Saved output | Owner-only temporary file, fsync, no-overwrite link to final name and directory sync. | Crash before finalization can leave a private temporary file; no incomplete final file should be exposed. Filesystem durability guarantees still apply. |
| Sharing | Separate schema and keyed HMAC pseudonyms; arbitrary/free fields withheld. | Timing, topology and known external facts can reidentify a case. Review every candidate. |

## Limits in this preview

Default source limit is 1 GiB; explicit `--max-bytes` accepts up to 4 GiB. A record can be at most 1 MiB. Default import limit is one million records; explicit `--max-records` accepts up to ten million. It is a cumulative per-source ceiling, including records already imported when resuming. An oversized record is drained in bounded chunks, recorded as an issue and not parsed.

Analysis accepts at most 100,000 events and also enforces a 64 MiB serialized-event/report budget, so the byte budget can bind earlier. Findings are limited to 20,000 and relation/evidence-reference work to 250,000. Exceeding these bounds is an error, never an apparently complete truncated report. The TUI displays at most 10,000 events with an explicit subset notice. Timeline output has an explicit limit and truncation diagnostic.

Storage grows with copied evidence and indexed normalized records. There is no global disk quota or hard memory/CPU enforcement. Monitor filesystem space and apply operating-system limits when needed. Parsers do not decompress archives, fetch linked artifacts or automatically load extensions.

## Handling and retention

New case directories use mode 0700 and evidence/output files mode 0600. Existing directory permissions are the owner's responsibility. The database, WAL/journal if any, snapshots, original copies and exported reports must all be treated as sensitive. No encryption, secure erasure, automatic retention policy or complete custody system is implemented.

Public sharing uses a random 32-byte secret kept separately with owner-only permissions. Reusing a key links pseudonyms across exports. Changing it prevents identifier equality but does not remove linkage through timestamps or event patterns. Secrets and original values are not included in the share schema. Protect backups and the key separately.

## Failure model

Imports commit at bounded checkpoints. Interruptions roll back the current transaction and retain an explicit interrupted status; resume verifies the same source copy and parser version. Parse failures produce an incomplete source with stable diagnostic codes, never copied raw secret text. Unsupported database schema versions are refused; this first schema has no previous version to migrate.

`verify` detects inconsistencies between stored evidence bytes, normalized records, indexes, record counts and parse diagnostics. It does not certify acquisition, validate analyst notes against reality or check a complete organizational custody trail. Reports run this consistency check before analysis. Existing snapshots are content addressed; external comparison still requires a trusted reference.
