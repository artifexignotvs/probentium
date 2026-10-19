# PROBENTIUM

**0.2.0.dev3 — public technical preview.** An offline terminal workbench for evidence, time uncertainty, review and incident-reporting records. Test the implementation with synthetic evidence; it is not a certified forensic platform or a legal-compliance verdict.

*Ex indiciis, non ex fama.*

PROBENTIUM is a [standalone project](https://github.com/artifexignotvs/probentium). The original [TESTIFEX project](https://github.com/artifexignotvs/testifex) remains separate. This distribution retains the compatibility `testifex` command for existing schema-1 cases.

## Try a complete synthetic investigation

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/probentium demo exercise
.venv/bin/probentium browse --case exercise/case
```

Start `probentium` with no arguments in a terminal to enter the native console:

```text
[?]  P R O B E N T I U M
Offline evidence workbench
Development preview / 0.2.0.dev3
Ex indiciis, non ex fama.

probentium> open exercise/case
```

The console offers `open`, `create`, `demo`, `run`, `help` and `quit`.
`run` accepts any complete command, for example `run verify --case exercise/case`.
Use `probentium console --no-banner` to hide the mark, or `--ascii` for terminals
with limited character support. No browser, web server or graphical desktop is
required. [Terminal guide](docs/terminal.md).

The demonstration contains 132 records, a claim that starts with unknown clock accuracy, an explicit synthetic clock assumption, and a scenario that weakens the conclusion. It also contains control observations, a fictional reporting workflow and changed filing drafts. Nothing is submitted externally.

The native interface is monochrome and keyboard driven. `1`–`7` open the investigation views; `8`, `9`, `0` open claims, scenarios and review. `:scope`, `:export` and `:retention` open the remaining views. `?` shows the command reference. There is no account, hosted backend, telemetry or embedded network connector.

## What this preview does

- Acquire bounded evidence copies, preserve ordered byte locators and record parser/configuration identities. Optionally bind an explicit parser approval to exact installed distribution/dependency bytes. Inspect samples, execute fingerprinted batch plans, resume committed import checkpoints and migrate legacy cases to a new copy.
- Evaluate five predicates with explicit time uncertainty, shared clock errors, source families, duplicates and identity assertions. Inspect witnesses, change assumptions, assess sensitivity and compare stored results without rewriting history. Currentness follows the frozen scope and its dependency closure; unrelated artifacts outside that scope do not invalidate the conclusion.
- Correlate authentication bursts and process records as conditional investigation leads. A lead is not a finding of compromise or physical causality.
- Export and independently inspect restricted evidence packets; verify source hashes, reparse supported evidence and repeat stored analyses. Use Ed25519 signatures with explicit key trust and age-encrypted transport.
- Record signed review decisions bound to a claim revision, evaluation, evidence state and rationale. Historical or untrusted decisions do not silently become current approval.
- Keep service/supplier dependencies, declared control populations, typed restore/MFA/remediation observations, tests, exceptions, approvals and training records. Preserve unknown applicability and separate observations from claimed effectiveness.
- Prepare frozen reporting drafts, replay stored deadline calculations, record submission assertions and receipts, and trace changes to their dependencies. Legal rule packs are data, explicitly activated and versioned; the supplied packs remain drafts.
- Freeze unified dependency graphs and audit exact coverage against explicit legal requirement catalogues. Missing branches, sources and evidence stay visible; structural coverage is not legal certification.
- Plan and approve source-byte retention, honor holds, and distinguish authorized absence from unexplained evidence loss. Retained indexes and exported copies are disclosed; secure erasure is not promised.

## Inspect the implementation

[Development guide](docs/development-preview.md) · [CLI action reference](docs/cli-reference.md) · [Validation evidence](docs/validation-terminal-kali.md) · [Kali packaging](docs/kali-packaging.md) · [Core requirement audit](docs/r1-core-status.md) · [EU requirement audit](docs/r1-eu-status.md) · [Security boundaries](SECURITY.md) · [License](LICENSE)

Python 3.11+ is declared. Recorded validation covers Linux with Python 3.12, 3.13 and the Kali system interpreter; the validation receipt distinguishes each test scope. Parser resource enforcement and atomic restored-directory publication currently require Linux. Do not infer macOS support from the older command's validation. Runtime dependencies are pinned in `pyproject.toml`; encrypted transport additionally requires an independently installed age executable.

The `testifex` command remains available for separate schema-1 cases. `probentium migrate SOURCE DESTINATION` creates a new schema-2 copy; the original is not modified. Protocol namespaces needed for compatibility remain unchanged. [Earlier command documentation](docs/legacy-readme.md).

## Release status

[Release 0.2.0.dev3](https://github.com/artifexignotvs/probentium/releases/tag/v0.2.0.dev3) preserves the exact files built from commit `4c59347334059b8ff83c46922884c362b6a359c5`, before the repository separation. Its wheel retains the historical project URLs embedded in that build. The subsequent project-link update on `main` changes documentation and package metadata only: all 50 runtime files and three schemas remain unchanged, as do the release tag, archive bytes and recorded validation receipts. New builds use the standalone repository URLs and require their own hashes and validation; the existing release is not rebuilt.

The product name is provisional. The requirement audit distinguishes implemented behavior, partial requirements and external release gates. A successful hash check establishes consistency against a reference, not authorship, truth or collection completeness. Case storage remains plaintext; transport encryption does not encrypt the local database.

Independent analyst pilots, legal review, broader platform validation and the complete release security process remain required. No claim of universal artifact support, legal certification, independent accreditation or guaranteed adoption is made.
