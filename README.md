# TESTIFEX

**Trace a finding back to bytes. See when the clock cannot support the story.**

TESTIFEX is an offline terminal workbench for DFIR analysts reviewing small, portable evidence sets. It preserves imported files, locates every parsed record by byte offset, and makes time uncertainty visible in deterministic findings. No account, service, network request or model is needed.

**0.1.0a1 — public technical preview, Apache-2.0.** The complete current core is available for inspection and reuse. This is not a certified forensic suite or a replacement for established acquisition and artifact-parsing tools.

[![Checks](https://github.com/artifexignotvs/testifex/actions/workflows/ci.yml/badge.svg)](https://github.com/artifexignotvs/testifex/actions/workflows/ci.yml)
[Release and downloads](https://github.com/artifexignotvs/testifex/releases/tag/v0.1.0a1) · [License](LICENSE)

## Try the complete workflow

Python 3.11 or later on a POSIX system is required. Linux is locally tested; see [validation](docs/validation.md) for the exact environment. Use real, non-symlink paths, including parent directories.

```sh
git clone https://github.com/artifexignotvs/testifex.git
cd testifex
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/testifex demo --directory demo-output
.venv/bin/testifex triage --case demo-output/auth-case
.venv/bin/testifex browse --case demo-output/auth-case --ascii
.venv/bin/testifex verify --case demo-output/auth-case
.venv/bin/testifex diff demo-output/auth-case.json demo-output/uncertain-case.json
```

The first run observes eight failed SSH authentications, one success and a process record. The second uses the same two synthetic sources with a declared ±30-second clock error on the process collector. A temporal relationship that was certain under the original assumptions becomes possible. Neither result establishes that the command belonged to the SSH session, was unauthorized, or proved compromise.

`demo` creates both complete investigations, evidence copies, analyst hypotheses, JSON/Markdown reports and a comparison. It refuses an existing destination. All fixture identities are fictional; addresses are reserved for documentation.

![Recorded terminal evidence browser](assets/terminal.png)

[Authentic terminal recording](assets/demo.cast) · [How the recording was made](assets/README.md) · [Three-minute walkthrough](docs/walkthrough.md)

The release also includes a wheel for offline installation after download: `python3 -m pip install --no-index testifex-0.1.0a1-py3-none-any.whl`. This project is not currently distributed through a package registry.

## What works

- Copy and hash bounded input files; preserve their original bytes and acquisition metadata. Import OpenSSH/sudo text records, selected journal JSON records or a documented event JSONL schema.
- Resume interrupted imports from committed checkpoints. Reject changed evidence and conflicting interpretations of identical input in one case.
- Get a compact verified triage summary with coverage, uncertainty and finding references.
- Browse time intervals, filter events, inspect exact record locations and explicitly preview escaped raw content in a keyboard-operated monochrome TUI.
- Correlate repeated authentication failures with success, then identify nearby process/command records. Each result exposes input records, rule settings and assumptions.
- Record hypotheses with supporting, contradicting and contextual evidence. Analyst conclusions remain separate from rules and source observations.
- Reparse evidence to verify normalized records, counters, diagnostics and indexes. Save content-addressed reports and compare findings, sources, parser versions and settings.
- Produce a separate allowlisted share candidate using keyed pseudonyms. Free text is withheld; timestamps and relationships remain potentially identifying.

## Use your own copied evidence

```sh
testifex init investigation --name 'Authentication review'
testifex ingest copied-auth.log --case investigation --format auth --label auth-export
testifex ingest copied-events.jsonl --case investigation --format events --label process-export \
  --clock-error 30 --reason 'Collector calibration supplied a 30-second bound'
testifex sources --case investigation
testifex issues --case investigation
testifex timeline --case investigation --kind auth.success --format jsonl
testifex report --case investigation --format markdown --output investigation.md
testifex replay --case investigation --into replayed-investigation
```

Only specify a clock correction when you have a reason for it. The example does not estimate clock accuracy automatically. `report`, `analyze`, `snapshot` and `share` verify the imported copies and normalized records before generating results.

Runtime dependencies are Python's standard library. This is practical for the selected text/JSON formats; it does not justify a new home-grown parser for complex disk, memory or Windows artifacts.

## Boundaries that matter

A matching hash establishes consistency against a reference, not authorship, truth, collection completeness or acquisition time. Reading a file can update access metadata on a writable filesystem. Use appropriate evidence copies, read-only mounts or a write blocker for your acquisition procedure.

Cases and full reports contain **plaintext evidence**. Private file modes are not encryption. Keep them on storage appropriate to your environment. Public-share candidates are pseudonymized, not guaranteed anonymous.

Coverage describes records actually imported, parse failures, unknown times and analyst-declared intervals. Completeness remains unknown. Quiet periods are not labeled as missing evidence without an independently established expectation.

This preview does not acquire endpoints, parse raw EVTX, disk images, memory dumps, compressed archives or arbitrary vendor exports. It has two small correlation rules, not a general detection library. Unsupported formats are rejected or reported through parse diagnostics. See [formats](docs/formats.md), [analysis](docs/analysis.md) and [threat model](docs/threat-model.md).

## Review and extend

[CLI reference](docs/cli.md) · [Architecture and schemas](docs/architecture.md) · [Benchmark](docs/benchmark.md) · [Validation](docs/validation.md) · [Research](docs/research.md) · [Licensing and commercial scope](docs/licensing.md) · [Triage](docs/triage.md) · [Contributing](CONTRIBUTING.md)

```sh
python3 -m unittest discover -s tests -v
python3 scripts/benchmark.py --help
```

The useful question for a reviewer is concrete: can a second analyst find the original bytes, explain the uncertainty and reproduce the result? Adoption and productivity gains remain hypotheses to test with practitioners.

Artifex Ignotvs · *Ex indiciis, non ex fama.*
