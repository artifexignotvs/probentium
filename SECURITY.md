# Security and evidence handling

This is an early technical preview. No independent forensic certification or comprehensive third-party security audit has been completed. The included tests and review record describe the checks actually performed.

Evidence may be hostile. TESTIFEX does not execute imported content, invoke evidence-provided commands, decompress archives, load plugins, retrieve URLs or send telemetry. It enforces file, record, event and relationship limits. Its Python parsers run in the same process: there is no operating-system sandbox claim.

The local user, operating system, Python runtime and private case directory are trusted. Use a dedicated unprivileged account and a read-only evidence source where appropriate. A hostile process with the same user's permissions can rewrite the case and its reference hashes; this tool cannot establish authenticity against that adversary.

Do not attach real evidence, secrets, personal identifiers or a whole case to a public issue. For a defect, preserve a minimal synthetic reproducer, expected/observed behavior, version and platform. A private reporting contact has not been established for this preview. Coordinate a private reporting channel with the maintainer before transmitting sensitive details.

See [threat model](docs/threat-model.md) for file-opening, output, resource and export boundaries.
