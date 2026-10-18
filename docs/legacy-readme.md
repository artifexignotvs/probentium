# TESTIFEX / previous technical preview

**Did that process run after the SSH login? Check the clocks before drawing a conclusion.**

TESTIFEX helps incident responders review selected SSH/sudo logs, journal JSON and explicit process-event JSONL in the terminal. Follow a finding to its original source bytes, declare known clock error, and see whether the ordering still holds. Analysis runs locally without an account or network service.

In the included synthetic case, a login at `00:01:30` and a process record at `00:01:45` appear ordered. Give the process collector a declared ±30-second clock error and that ordering becomes **possible**, rather than certain within the interval model. The records do not establish that the process belonged to the SSH session or that an intrusion occurred.

**0.1.0a1 — public technical preview, Apache-2.0.** The complete current core is available for inspection and reuse. This is not a certified forensic suite or a replacement for established acquisition and artifact-parsing tools.

[![Checks](https://github.com/artifexignotvs/testifex/actions/workflows/ci.yml/badge.svg)](https://github.com/artifexignotvs/testifex/actions/workflows/ci.yml)
[Release and downloads](https://github.com/artifexignotvs/testifex/releases/tag/v0.1.0a1) · [License](../LICENSE)

## Help test one investigation workflow

We are looking for **five Linux or macOS incident responders** to try the synthetic example and tell us where it fails to help. Set aside ten minutes; stopping at a confusing step is useful feedback. There is no need to share incident data or contact details.

**[Start the field test](field-test.md)** · [Send structured feedback](https://github.com/artifexignotvs/testifex/issues/new?template=field-test.yml)

## Run the demo

Python 3.11 or later on a POSIX system is required. Installed packages have passed CI on Linux with Python 3.11/3.13 and macOS with Python 3.13; see [validation](validation.md) for the exact run and its limits. Use real, non-symlink paths, including parent directories.

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

![Recorded terminal evidence browser](../assets/terminal.png)

[Authentic terminal recording](../assets/demo.cast) · [How the recording was made](../assets/README.md) · [Three-minute walkthrough](walkthrough.md)

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

Check [supported formats](formats.md) first. Traditional syslog timestamps such as `Jan 1 00:00:00` have no year or timezone; TESTIFEX preserves them as unknown time. It will not infer those values from your machine. The canonical process JSONL is an explicit input schema, not an adapter for every endpoint product. Start with the synthetic field test before evaluating a private export locally.

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

This preview does not acquire endpoints, parse raw EVTX, disk images, memory dumps, compressed archives or arbitrary vendor exports. It has two small correlation rules, not a general detection library. Unsupported formats are rejected or reported through parse diagnostics. See [formats](formats.md), [analysis](analysis.md) and [threat model](threat-model.md).

## Review and extend

[CLI reference](cli.md) · [Architecture and schemas](architecture.md) · [Benchmark](benchmark.md) · [Validation](validation.md) · [Research](research.md) · [Licensing and commercial scope](licensing.md) · [Triage](triage.md) · [Contributing](../CONTRIBUTING.md)

```sh
python3 -m unittest discover -s tests -v
python3 scripts/benchmark.py --help
```

The useful question for a reviewer is concrete: can a second analyst find the original bytes, explain the uncertainty and reproduce the result? The [field test](field-test.md) checks that workflow. Adoption and productivity gains remain hypotheses to test with practitioners.

Artifex Ignotvs · *Ex indiciis, non ex fama.*
