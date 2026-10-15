# Ten-minute field test

This voluntary 14-day pilot seeks five Linux/macOS DFIR practitioners to try one narrow task: review temporal leads in selected authentication logs and trace a record back to its source bytes. Set a ten-minute timebox after installation; stopping at a blocker is useful feedback. No star, follow, employer name or real incident data is requested.

The pilot goals are three independent completions, two concrete feedback reports and one voluntary repeat use for a stated task. These are goals, not results or evidence of general adoption. Reading the answer check or receiving help before finishing is fine; report that assistance.

## Prepare

Use Python 3.11 or later on Linux or macOS and an ordinary terminal at least 70 columns by 18 rows. Native Windows is unsupported. Work without elevated privileges in a new directory whose path contains no symlinks. Keep installation time separate from exercise time.

Download the [0.1.0a1 wheel](https://github.com/artifexignotvs/testifex/releases/download/v0.1.0a1/testifex-0.1.0a1-py3-none-any.whl) into that directory. Then run:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --no-index ./testifex-0.1.0a1-py3-none-any.whl
.venv/bin/testifex --version
```

If Python or its virtual-environment support is unavailable, stop and report that blocker. The wheel has no runtime dependencies. The exercise below uses generated synthetic data only and makes no network requests.

## Interpret before opening the answer check

Create fresh fixtures and compare the two summaries. `field-demo` must not already exist. Leave `setup-summary.json` and the generated reports closed until you have written your own interpretation; they include explanatory results.

```sh
.venv/bin/testifex demo --directory field-demo > setup-summary.json
.venv/bin/testifex triage --case field-demo/auth-case
.venv/bin/testifex triage --case field-demo/uncertain-case
```

Write down locally: which lead changes, what “certain” and “possible” mean here, and one conclusion these records cannot support. Did the summaries make the distinction clear without help?

Now find the successful authentication and follow its provenance:

```sh
.venv/bin/testifex browse --case field-demo/auth-case --ascii
```

Use `j`/`k` or the arrow keys to select a record and Enter for details. Within details, use the same keys or PgUp/PgDn to scroll; the source digest and byte locator may be below the first screen. Note its original line number, byte offset/length, original timestamp and **source** SHA-256 locally. Press `r` to inspect the digest-checked raw record; `q` returns to the list, then `q` exits. If the interface blocks you, stop rather than troubleshooting past your timebox.

Independently hash the generated input file and compare it with the source digest you noted. The source digest and the individual record digest cover different bytes.

```sh
.venv/bin/python -c 'import hashlib; from pathlib import Path; print(hashlib.sha256(Path("field-demo/auth.log").read_bytes()).hexdigest())'
.venv/bin/testifex verify --case field-demo/auth-case
```

Record whether the raw record, source hash and verification agreed. What does that agreement establish, and what does it leave unproven? Then open the answer check below.

## Send minimal feedback

Use the [field-test form](https://github.com/artifexignotvs/testifex/issues/new?template=field-test.yml). A blocked attempt is as useful as a completion. Report approximate installation/exercise time, the first blocker or useful step, your interpretation and whether you would use it again for a specific task. A second voluntary attempt can be added to the same issue; label it as a repeat. GitHub associates an issue with your account; no additional identity is needed, and trying the tool does not require an account.

**Do not upload real incident data, case directories, reports, screenshots, logs or attachments.** Do not paste usernames, hostnames, addresses, private paths, evidence hashes, tokens or employer/client details. Short descriptions and fixed diagnostic codes are enough; any example must be synthetic.

## Optional fit check after the synthetic exercise

Consider whether your existing workflow has a suitable input: selected OpenSSH/sudo text, `journalctl -o json` exports, or the documented event JSON Lines format. Read [formats and limits](formats.md) before a further local trial. Binary journal files, raw event-log databases and disk images are unsupported. Traditional authentication timestamps without year/timezone remain unknown; do not invent missing time to obtain a lead.

Any further trial is optional and stays local. Use authorized lab-generated or already sanitized copies, keep original evidence separately, and treat sanitized material as a derivative: redaction changes hashes and can change identifier matches and analysis. Case storage and full reports are plaintext. Sanitization alone does not guarantee safe publication; no real incident material is requested. Tell us only whether the supported formats and results fit a task you already do.

<details>
<summary>Answer check — open after recording your interpretation</summary>

Both cases contain ten parsed events from two complete imports, with no ignored records or parser errors and two leads. Collection completeness still remains unknown. In `auth-case`, both leads are certain under the supplied time bounds. In `uncertain-case`, the authentication-after-failures lead stays certain, while the subsequent-process lead becomes possible because the process clock has a declared ±30-second error.

“Certain” describes ordering/window membership for all times allowed by the supplied bounds; “possible” allows an ordering without establishing it throughout those bounds. Recorded resolution and declared clock error are not measured confidence in an incident. Neither lead proves compromise, causality, authorization or membership in the same session.

The successful authentication is physical line **9**, at byte offset **832**, with length **107** including its newline. Its original timestamp is `2026-01-01T00:01:30Z`. The generated authentication source SHA-256 is `2858fd62508797a8efcc0454bc5ab918d71558ae1dabf7d94bc354beac3afd43`. These values describe this version's synthetic fixture, not arbitrary logs.

Verification should return `"ok":true`, `"reparsed":true`, two sources and ten checked events. Hash agreement and re-parsing support consistency with retained bytes; they do not independently prove authorship, acquisition time, authenticity or completeness. Record any discrepancy rather than changing your original answer.

</details>
