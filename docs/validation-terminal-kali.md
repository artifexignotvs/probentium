# Native terminal and Kali validation basis

Version **0.2.0.dev3** is a public technical preview. This receipt describes
measured work on the native-terminal runtime and Debian packaging. It does not
close the full-R1 acceptance register or establish Kali inclusion.
The [machine-readable receipt](validation-terminal-kali.json) binds the exact
50 runtime Python files, three schemas and test/development fixtures to these
results. Final downloadable artifacts have their own checksums and acceptance
receipt in the release: embedding an archive's own hash here would be circular.

## Tests and corrections

The runtime suite contains **696 distinct tests**: 549 current-interface tests
and 147 compatibility-interface tests. Repeating a suite in another environment
does not increase that count. Five archive-builder regression tests are separate.

| Environment and scope | Actual result |
| --- | --- |
| Linux, Python 3.12.3 source | 147 compatibility tests passed in 17.185 s; the initial 549-test run had one stale expected-command assertion in 346.897 s; all nine diagnostic tests passed after correcting it in 16.363 s |
| Linux, Python 3.13.5 installed interim wheel, outside checkout | 147 passed in 20.061 s; initial 549-test run had the same stale assertion in 347.907 s; corrected diagnostic module passed 9/9 in 12.550 s |
| Kali rolling amd64, Python 3.14.7, first native package build | Complete suites passed: 147 in 9.878 s and 549 in 262.685 s, with no skips |
| Separate clean Kali testbed, actual autopkgtest driver, installed system package | Runtime suite passed: 147 in 9.477 s and 549 in 259.973 s, with no skips |
| Archive-builder regressions | 5/5 passed in 1.407 s; includes real builds under umasks 022 and 077 |

The stale assertion omitted the newly registered `console` command. Only its
expected set changed; runtime bytes did not. The original failed logs are
retained by digest. The earlier source and wheel runs are not relabeled as
unqualified green full runs. A preliminary Kali setup attempt also failed
because an isolated parser could not import an unregistered source checkout;
that was a testbed preparation error, recorded separately from installed tests.

The first installed-workflow autopkgtest found a new fixture error: a supplied
trust document was not canonical JSON. The helper was corrected to use the
existing canonical serializer. No runtime change was needed. All six workflow
checks then passed under a separate invocation of the actual autopkgtest driver.
The first driver exit remains 4 because its workflow failed, even though its
complete runtime suite passed. The corrected workflow driver exited 0.

The workflows cover synthetic intake, machine output, all three installed
schemas, byte references, explicit signature trust, supported normalization and
analysis replay, restore, real age encryption and tampering refusal. Testbed
preparation used signed APT repositories; external networking was then
disconnected. Tests ran as an unprivileged user. A container is the measured
platform here, not every physical Kali installation.

## Installed bytes and isolation scope

The first Debian binary contains the same 50 Python files and three schemas as
the source. Its system runtime uses `python3-cryptography 49.0.0-2`; a separate
metadata patch preserves the upstream wheel's 50.0.2 pin. The final packaging
recipe additionally requires the fixed Debian revision explicitly. Full package
and library versions, the official container image digest, original failure
receipts and parity results are in the JSON receipt and
[Kali guide](kali-packaging.md).

The interim installed wheel also passed all 16 acceptance workflows with a
Linux seccomp policy denying network syscalls in the validation child and its
descendants. Before/after probes confirmed enforcement. This validation harness
does not change the host network policy and does not turn the application parser
into a complete hostile-code sandbox. The final wheel and source archive are
checked separately after documentation is frozen.

Explicit upstream-wheel parser approval verified 226 installed files and
rejected altered native dependency bytes. Operator approval and source-manifest
replay are different modes. Debian's system layout is not silently accepted as
the original wheel distribution. Signatures and matching bytes do not establish
the factual truth of collected evidence.

Lintian reported zero errors and one unsuppressed warning,
`initial-upload-closes-no-bugs`; no nonexistent tracker issue was invented.
The packaging still needs a working public maintainer mailbox before a Kali
request. No request has been submitted and no inclusion has been promised.

## Historical evidence and open limits

The [earlier dev3 baseline](validation-preview.md) and its JSON remain historical
records. Its three 100,000-event benchmark receipts still bind 22 unchanged
engine files. They met rule-timing and paging targets in all runs, missed the
import target in all runs, and exceeded the RSS target in one run. The new
console and packaging are outside that performance measurement. Those results
are not a new Kali benchmark or the complete prescribed reference-machine matrix.

Python 3.11 is declared but not newly measured by this receipt. Complete macOS,
historical migration and fault/resource matrices, independent analyst pilots,
security assessment and legal review remain open. GitHub private vulnerability
reporting is enabled; a monitored response process and response-time commitment
are not established by enabling a setting. Local cases remain plaintext and
reporting drafts are never submitted externally.

See the [core audit](r1-core-status.md), [EU audit](r1-eu-status.md) and
[security boundaries](../SECURITY.md) for the remaining acceptance conditions.
