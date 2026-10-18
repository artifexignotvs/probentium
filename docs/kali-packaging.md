# Kali packaging: local draft

The `debian/` directory is a local packaging draft, version `0.2.0~dev3-1`
with distribution `UNRELEASED`. It is not an accepted Kali or Debian package.
It does not change the product's development-preview status or release gates.
The application runs in the terminal; packaging adds no browser, desktop,
service, telemetry or root requirement to normal use.

## Current compatibility boundary

A fresh Kali rolling APT check on 19 October 2026 found the following amd64
candidates. Rolling repositories change; these versions describe that check.

| Component | Kali candidate | Current upstream requirement |
| --- | --- | --- |
| Python | 3.14.7-3 | Python 3.11 or newer; platform tests still required |
| python3-rfc8785 | 0.1.4-3 | rfc8785 0.1.4 |
| python3-cryptography | 49.0.0-2 | cryptography 50.0.2 |
| python3-cffi | 2.1.1-1 | wheel approval pins cffi 2.1.1 |
| python3-cffi-backend | 2.1.1-1+b1 | native bytes belong to the selected runtime |
| python3-pycparser | 3.0-1 | wheel approval pins pycparser 3.11 |
| age | 1.3.2-1 | independently installed transport executable |
| python3-setuptools | 84.0.0-2 | setuptools 77 or newer for the build |

The distribution-only quilt patch changes dependency metadata to
`cryptography>=49.0.0,<50.0.0`; the upstream wheel still pins 50.0.2. The exact
system version tested is 49.0.0-2. Other 49.x builds are not individually
validated by that result. `debian/py3dist-overrides` preserves both the bounded
cryptography requirement and the exact rfc8785 requirement in package metadata.
No runtime source is changed by the patch. Both build and runtime metadata also
require Debian revision `python3-cryptography (>= 49.0.0-2)`. Debian's
[security tracker for CVE-2026-69247](https://security-tracker.debian.org/tracker/CVE-2026-69247)
records the fix in that revision. The upstream 50.0.2 pin is retained. This
specific backport observation does not establish that every vulnerability is
absent; dependency security status needs continued review.

The existing wheel-distribution approval contract differs from Debian's system
package layout and dependencies. This package uses the existing source-manifest
mode, which records the selected runtime and dependency versions. It is not
independent distribution attestation. Original-wheel approval remains strict
and is unsupported for this different installation; no equivalent approval
scheme or automatic trust is introduced.

## Packaging contents

- Debhelper and the pybuild pyproject backend build system Python modules and
  entry points. Dependencies come from APT; build scripts do not fetch wheels.
- Both executable names have manual pages. `testifex` remains an earlier
  interface, not an alias for `probentium`.
- Schemas install below `/usr/share/probentium/schemas`. Documentation, copyright
  and NOTICE install below `/usr/share/doc/probentium`.
- The installed workflow exercises synthetic intake, machine output, byte
  references, explicit signing trust, semantic replay, restore and system age
  encryption including tamper refusal.
- The runtime-suite autopkgtest copies test fixtures into a temporary directory
  and imports the installed system modules. Its result is separate from the
  wheel/virtual-environment acceptance harness.

## Local validation procedure

Use an isolated Kali rolling VM or container. Prepare the APT build dependencies
first, then disconnect external networking for the actual build and tests.
Do not install dependencies into the host Python environment.

```sh
dpkg-buildpackage -us -uc -b
lintian ../probentium_0.2.0~dev3-1_all.deb
```

Do not use `--force-depends`, bypass dependency checks, disable the test suite
or relabel a failed install as a successful package. Use a matching immutable upstream archive for a source-package build.
Run autopkgtests against the built package in a fresh testbed; a help-only check
does not establish working analysis or encrypted transport.

## Validation evidence

The initial complete source run on Kali Python 3.14.7 exercised 549 current
cases and found one stale test expectation: a command registry assertion had
not yet included the new console. The runtime code was unchanged. After
synchronizing that test correction, all 9 diagnostic-module tests passed.
The 147 earlier-interface tests passed. The original failure is retained;
these results are not described as one unqualified green full run.
A preliminary testbed setup attempt also failed because isolated parser
children could not import an unregistered checkout. The subsequent source run
used an explicit registration of the copied source tree. This registration
must be removed for installed-package validation.

The first native binary build ran the corrected corpus from the pybuild output:
147 earlier-interface tests and 549 current tests passed, without skips. A
separate fresh container then installed the package through APT with dependency
checks enabled. No source-tree registration was present. Its actual autopkgtest
null-backend driver ran as an unprivileged test user with external networking
disconnected. The installed runtime suite passed the same 147 and 549 tests.

The first installed-workflow attempt failed because its test fixture wrote a
noncanonical trust document. After changing that fixture to the product's
canonical encoding, the actual driver passed all six workflow checks. The
initial failed driver result is retained, separately from the corrected result;
this correction changed no application code. All 50 Python module files and
three schemas matched the source bytes in the tested binary. Lintian reported
no errors and one unsuppressed warning: `initial-upload-closes-no-bugs`. There is
no issue number to claim or insert for this local draft.

These are local amd64 container results, not an independent review, acceptance
by Kali, or evidence for untested rolling versions. The final binary rebuild
incorporates the explicit Debian security-revision minimum and final
packaging documentation. Exact artifact hashes, input hashes, repeat-build
comparison and final-artifact checks belong in separate validation receipts;
they are not embedded into the binary they identify.

## Before requesting inclusion

1. Supply a working public maintainer mailbox that accepts automated package
   and bug mail. The current public GitHub noreply identity is retained only
   for this local draft and is not a support channel.
2. Retain system-library compatibility evidence and the strict original-wheel
   approval boundary. Record tested Python, library and architecture versions
   rather than claiming every rolling system is supported.
3. Produce a reproducible source package and installable binary package; retain
   build, lintian, installed workflow and autopkgtest results.
4. Publish a matching tag/release only after the separate public release gates
   pass. Record an exact download, supported examples and known limitations.
5. Explain the concrete analyst problem and how it differs from existing
   timeline, forensics and incident-response tooling. Do not promise adoption,
   certification, reach or inclusion.
6. Review the complete final public surface and arrange a monitored security
   reporting channel. No sensitive evidence belongs in a public issue.

## Primary references

Kali describes the required request fields and matching release in
[Submitting tools](https://www.kali.org/docs/tools/submitting-tools/), and the
selection factors in its
[tools policy](https://www.kali.org/docs/policy/penetration-testing-tools-policy/).
Packaging and isolated builds are documented in the
[packaging example](https://www.kali.org/docs/development/intro-to-packaging-example/)
and [environment guide](https://www.kali.org/docs/development/setting-up-packaging-system/).
Installed tests follow the scope described in
[Kali autopkgtest guidance](https://www.kali.org/docs/development/contributing-runtime-tests/).

Debian requires a working maintainer contact in
[Policy 3.3](https://www.debian.org/doc/debian-policy/ch-binary.html#the-maintainer-of-a-package).
Build restrictions are described in
[Policy 4.9](https://www.debian.org/doc/debian-policy/ch-source.html#main-building-script-debian-rules),
and manuals/copyright in
[Policy chapter 12](https://www.debian.org/doc/debian-policy/ch-docs.html).
The [Python policy](https://www.debian.org/doc/packaging-manuals/python-policy/),
[pybuild manual](https://manpages.debian.org/testing/dh-python/pybuild.1.en.html)
and [dh_python3 manual](https://manpages.debian.org/testing/dh-python/dh_python3.1.en.html)
describe the system layout, build backend and version-preserving dependency
translation used here.
