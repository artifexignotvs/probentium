# Validation baseline before the native console extension

This receipt describes the earlier 0.2.0.dev3 source hashes, before the native
console and Debian packaging were added. The subsequent terminal and Kali work
has [separate validation evidence](validation-terminal-kali.md). Earlier results
and corrections below are retained as recorded; they are not relabelled as tests
of the later source.

This is implementer-run Linux validation. It does not certify legal compliance, forensic fitness or completion of the R1 release gates. The [machine-readable receipt](validation-preview.json) records the exact runtime, schema and test hashes, initial failures and targeted correction. The [requirement register](r1-requirements-status.json) separates implemented behavior from remaining acceptance.

## Regression coverage

| Environment | R1 full run | Legacy full run | Corrected module |
| --- | --- | --- | --- |
| clean_source_environment / Python 3.12.3 | 524 tests, 288.926 s; one fixture failure | 147 passed, 11.760 s | 4 passed, 23.017 s |
| installed_wheel_outside_checkout / Python 3.13.5 | 524 tests, 284.447 s; one fixture failure | 147 passed, 15.798 s | 4 passed, 18.410 s |

There are **671 distinct test cases**, not twice that count because two environments ran them. No test was skipped. Both initial full runs found the same invalid synthetic fixture: it omitted timestamp and actor fields while expecting two normalized events. The fixture was corrected, and all four tests in that module passed in both environments. Runtime code did not change. Initial logs and old/new test hashes remain recorded; the failed initial runs are not rewritten as successful runs.

The current corpus covers composite locators, duplicate outputs, unknown and malformed inputs, generation-aware retention, parser approval chronology, required-signature restoration, resource-policy negotiation, historical replay, typed observations, calendar-plan replay, unified dependency impacts and actual CLI revision/budget enforcement. Linux crash tests include interrupted checkpoints, disk/I/O faults and atomic recovery publication. These fixtures are not exhaustive power-loss, filesystem, continuous-fuzz or historical-format acceptance.

## Clean installed distributions

The interim wheel and source archive were installed separately into fresh Python 3.13.5 environments outside the checkout using hash-locked local dependency wheels. Both passed dependency checks. All **49 runtime Python files and 3 shipped schemas** match source and both archives exactly. Installed imports resolve inside the clean environment; the AST-only workbench fixture has no package initializer.

Each installed distribution passed the same **16-step workflow under inherited Linux network-syscall denial**: module origin and capabilities; the synthetic case and integrity; claim explanation/currentness; a revision-bound analysis child; typed control observations and frozen deadline replay; unified graph construction/impact; explicit trust and signed review; signed packet trust and semantic replay; restore/replay; real age encryption/decryption with tamper rejection; and legacy demonstration parity. Socket probes were denied before and after process execution. This confines the validation child and descendants; it does not claim a full hostile-code or filesystem sandbox.

A separate parser-distribution checkpoint verified **225 installed files**, including the three schemas, against the explicitly selected product and dependency wheels. Explicit approval, import and normalization replay succeeded; omission of the approval refused parser availability. A forged installed bytecode cache was ignored, and actual native-library byte tampering was rejected before the exact bytes were restored. That checkpoint had no stored evaluation, so it does not claim analysis replay for that case. It is separate from the network-denied workflow.

Reproduce the installed workflow with official age/age-keygen in the environment and Linux libseccomp available:

```sh
python scripts/validate_installed.py --python /absolute/environment/bin/python --output /absolute/new-validation
```

The output parent must exist. Dependency preparation is a separate step; runtime workflows require no service account or automatic network fetch. CI defines more environments, but unobserved hosted CI or macOS R1 results are not claimed here.

## Repeated 100,000-event measurements

| Run | Import | Full verify | Clock setup | Load analysis | Two templates | Paging p95 | Parent peak RSS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [Run 1](../dev/benchmark-linux-dev3-run1.json) | 73.693 s | 46.516 s | 84.916 s | 78.562 s | 13.018 s | 126 ms | 531.695 MiB |
| [Run 2](../dev/benchmark-linux-dev3-run2.json) | 75.339 s | 46.489 s | 85.644 s | 78.209 s | 13.001 s | 132 ms | 315.586 MiB |
| [Run 3](../dev/benchmark-linux-dev3-run3.json) | 76.599 s | 48.022 s | 86.215 s | 78.732 s | 13.025 s | 152 ms | 315.641 MiB |

Each run uses a fresh synthetic case and four-CPU affinity. CPUs are not exclusive; host RAM was not capped to the reference-machine size, and operating-system caches were not evicted. Reads follow import and verification. These are observed Linux host measurements, not promises or macOS acceptance. The analysis stage uses explicit current work limits in the in-process core; it does not measure child startup. Source generation and data loading are excluded from the two-template time and are disclosed separately.

The receipts preserve numeric target comparisons and outcomes, including any missed 60-second import, 15-second loaded-template, 250-ms paging or 512-MiB parent-memory target. They are not a full sparse/dense, cold/warm or supported-platform matrix. The retained dev2 benchmark and 100,001-record search receipts are historical measurements for different source hashes, not current dev3 results.

## Presentation and schema checks

The local synthetic viewer retains monochrome styling and top navigation. Actual button navigation showed six controls and their observations; case verification changed the integrity indicator to passed; keyboard Enter opened a stored claim. The fresh demo contains 132 events from two sources and two filing drafts. This is a local functional/visual check, not independent accessibility or practitioner acceptance.

The independent JSON Schema implementation accepted 57 positive events-v2 fixtures and rejected 167 structural negatives; eight additional wire/runtime cases are covered by parser tests. Three schemas are shipped: events-v2, control-observation.v1 and deadline-plan.v1. Package/runtime validators additionally enforce reference, chronology and cross-object invariants that JSON Schema alone cannot establish.

## Remaining release boundaries

Composite/multiple-output storage, explicit distribution approval, configurable bounded resource policies and persistent cross-domain dependency graphs are implemented within their documented limits. Built-in normalizers still do not promise arbitrary composite reexecution or arbitrary third-party plugins. Analysis remains bounded to 100,000 events; metadata/database and packet caps may stop larger cases earlier than nominal record limits.

Complete legally reviewed paragraph/annex mappings, active legal profiles/calendars, independent security/semantic review, practitioner pilots, broader platform and performance acceptance, name clearance and a working confidential security channel remain open. Hashes and signatures establish consistency against a reference, not truth or compliance. Filings are local drafts/records, not regulator submissions. Source-byte retention is not whole-case secure erasure.

Final documentation-bearing archive hashes, runtime/test parity and exact release-surface audit are separate sidecars, avoiding a self-referential archive hash. This candidate remains local and is not an R1 public release.
