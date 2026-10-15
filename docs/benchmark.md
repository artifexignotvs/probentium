# Reproducible local benchmark

The benchmark measures three separate operations on generated synthetic JSONL: import into a fresh case, temporal analysis, and verification against the retained evidence copy. It makes no comparison with other forensic tools.

From the source directory, run:

```sh
python scripts/benchmark.py --events 10000 --output benchmark-10000.json
python scripts/benchmark.py --events 100000 --output benchmark-100000.json
```

Use Python 3.11 or newer on a supported POSIX system. The script uses the standard library, creates a private temporary directory, and removes its input and case after the run. Output files must not already exist. The default count is 10,000; the maximum is 100,000. A phase has a 600-second default timeout, configurable through `--timeout` up to 3,600 seconds. A failed or refused operation is recorded and makes the command exit with status 1; it is not presented as completed throughput.

The input is deterministic. Each block of 1,000 rows starts with six authentication failure records, one success and one process record for a synthetic host and account. The remaining rows are generic observations. Timestamps are explicit UTC values one second apart, starting on 1 January 2026. Addresses use the documentation range. Groups have distinct identities, keeping correlation density bounded. This produces 20 expected temporal leads for 10,000 rows and 200 for 100,000 rows when analysis completes. The benchmark records the input hash and checks the observed finding count.

Each phase starts in its own child process. Wall time includes creating or opening the case, performing the operation, and closing the case. Interpreter startup and input generation are excluded. The analysis phase calls the Python `analyze` function directly: it reads and normalizes stored events and finds temporal relationships. Verification separately hashes the evidence copy and replays normalization with the current parser.

These are not timings for the complete `testifex analyze` or `testifex report` commands. Those commands also verify the case, construct a report, and recompute analysis to validate it; Markdown rendering and public export add further work. This benchmark does not measure those complete workflows. The analysis budget caps normalized event bytes at 64 MiB, while a full report must fit its events, sources, findings and other metadata into a separate 64 MiB serialized-report budget. Completing a 100,000-row sparse analysis does not establish that every 100,000-row report will fit or have the same runtime or memory peak.

Peak RSS is the process high-water mark, including imports and baseline process memory. Linux reports `resource.ru_maxrss` in KiB; the script multiplies it by 1,024. macOS reports bytes directly. For other systems, an unverified native value is retained without inventing a byte conversion. These are separate phase peaks, not quantities to add together. They are not incremental allocations or the memory consumed by the whole machine.

Results include Python and operating-system versions, CPU model and available CPU count, applicable container quotas, filesystem type and block size when detectable, input bytes, and logical case-file bytes. They exclude hostnames and local paths. The source fingerprint identifies the Python implementation measured; a change during measurement invalidates a complete-run claim.

Filesystem cache is not flushed. Verification runs after import and analysis and can benefit from warm cache. No attempt is made to control background load or virtual-machine scheduling. Repeat the commands several times on the intended deployment system before estimating capacity.

The checked-in [results](benchmark-results.json) are local observations with their exact conditions. Sparse synthetic rows do not measure parser diversity, corrupted records, dense correlation, image acquisition, multiple users or long-running collection. Count limits and byte limits both apply: a requested row count can be accepted by the benchmark while the analysis engine refuses the normalized dataset at a lower resource bound. Such a refusal is a useful limit observation, not a completed analysis measurement.

## Recorded observations

Measured on 15 October 2026 with TESTIFEX `0.1.0a1`, CPython 3.13.5, Linux x86_64, an Intel Core i7-10700KF and an ext4 temporary filesystem. Both runs used the same source fingerprint, with no source change detected during either run:

`1b1671adbe17ff9c2710decb0ade6fd6a4cd6180d71fae7604b2c78cd5559ef4`

| Rows | Import seconds / peak MiB | Direct analysis seconds / peak MiB | Verify seconds / peak MiB | Findings |
| --- | --- | --- | --- | --- |
| 10,000 | 1.607 / 23.4 | 0.376 / 41.1 | 0.743 / 23.7 | 20 |
| 100,000 | 21.235 / 25.1 | 3.823 / 200.7 | 7.773 / 25.0 | 200 |

All three measured operations completed for both sizes. Imports reported zero ignored or rejected records; verification checked every imported event. The input sizes were 546,230 and 5,462,300 bytes. Logical case sizes, including the retained input copy, were 11,797,942 and 117,618,972 bytes. MiB means 1,048,576 bytes. Raw measurements and environment details are retained in the results JSON.

These are two local observations, one per size. They are not estimates of full-report performance or a guarantee for other datasets or machines. No full 100,000-row report benchmark was performed.
