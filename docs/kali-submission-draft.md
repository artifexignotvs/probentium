# Kali new-tool request — preparation only

Not submitted. Complete the open items in `kali-packaging.md` before adapting
this text for the official tracker. No Kali acceptance or team affiliation is
claimed.

**Name:** PROBENTIUM

**Version:** Public technical preview 0.2.0.dev3, frozen at commit
`4c59347334059b8ff83c46922884c362b6a359c5`. The standalone repository preserves
the original release files; the later project-link update does not rebuild them.
Do not submit a branch-head URL as a release.

**Homepage:** https://github.com/artifexignotvs/probentium

**Download:** [Immutable preview release](https://github.com/artifexignotvs/probentium/releases/tag/v0.2.0.dev3). Use its Debian bundle to retain the native filenames and verify its inner checksums. The release wheel retains the historical project URLs from the original build; current build metadata points to the standalone repository.

**Author:** Artifex Ignotvs.

**Licence:** Apache-2.0. NOTICE is retained. Independently installed dependencies
retain their respective licences.

**Description:** Terminal evidence workbench for conditional incident findings.
It preserves exact source-record references, models uncertain timestamps,
records analyst interpretations, shows the assumptions behind a finding and
compares findings after relevant assumptions change. Signed evidence packets
support offline byte verification and supported normalization/analysis replay.
Controls and incident-reporting drafts retain source basis and explicit unknowns;
they do not certify compliance or submit reports.

**Dependencies:** Python 3.11+, rfc8785 0.1.4 and cryptography 50.0.2 for the current
upstream package; age for encrypted transport. The distribution-only metadata patch allows the separately tested system
cryptography 49 family while preserving the upstream wheel pins. The exact
system package tested is 49.0.0-2; see the packaging compatibility table and
validation scope.

**Similar tools:** [Plaso/log2timeline](https://plaso.readthedocs.io/en/stable/sources/user/Using-log2timeline.html)
extracts events from files, directories and images into timeline storage, and
[Plaso is available in Kali](https://www.kali.org/tools/plaso/).
[Timesketch](https://timesketch.org/) supports collaborative timeline analysis.
[Velociraptor artifacts](https://docs.velociraptor.app/docs/vql/artifacts/)
package VQL queries for endpoint collection. PROBENTIUM currently focuses on
conditional claims, time uncertainty, exact witnesses and revision-bound offline
packets. Its accepted formats are deliberately narrow; it is not a fleet
collector and requires no browser. This is a scope comparison, not a claim
that the other tools lack every corresponding feature or that this tool is
unique or superior. Native imports from those tools are not promised.

**Activity:** The technical preview is public. A release does not establish a
mature maintenance history; supply issue-maintenance evidence before submission.

**How to install:** After downloading the release Debian bundle, extracting it
and checking its inner `SHA256SUMS` on the tested Kali rolling environment:

```sh
sudo apt install ./probentium_0.2.0~dev3-1_all.deb
```

This is a local installation example, not an official Kali repository package.
Do not bypass dependency checks or pipe downloaded scripts into a shell.

**How to use:** After a supported installation:

```sh
probentium demo exercise
probentium verify --case exercise/case
probentium console --case exercise/case --ascii
probentium --format json status --case exercise/case
```

The exercise is synthetic. Case databases remain plaintext. Strict parser and
analysis resource enforcement currently require Linux. Dependency review,
legal review, independent security review and broader platform/performance
acceptance remain separate gates.

**Packaged:** Local `debian/` draft, successfully built and installed in isolated
Kali rolling containers; not accepted or uploaded. The first build and actual
installed runtime autopkgtest each passed 147 earlier-interface and 549 current
tests. The installed workflow passed after a documented test-fixture correction.
Lintian has one unsuppressed initial-upload warning. See `kali-packaging.md` and
the exact artifact's validation receipt for the limits and retained failures.

**Maintainer contact:** A working public mailbox has not been supplied. The
existing GitHub noreply commit address is not a monitored support contact.

The eventual request belongs in the official
[Kali New Tool Requests process](https://www.kali.org/docs/tools/submitting-tools/).
This document does not create or authorize that request.
