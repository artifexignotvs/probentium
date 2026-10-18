# Security and evidence handling

PROBENTIUM is a development candidate. No independent forensic certification, comprehensive external security audit or legal-compliance certification has been completed. The requirement audit records incomplete implementation and release gates.

The new command uses a separate parser process with a cleared environment, private working directory and Linux CPU, memory, descriptor and wall limits. This reduces accidental resource exposure; it is not a complete operating-system sandbox and does not enforce network isolation. The compatibility `testifex` command retains its original in-process parsers. Neither command executes evidence-provided commands, loads evidence-provided plugins, retrieves evidence URLs or sends telemetry.

CLI analysis also uses a child process with explicit count, byte, time and memory budgets. Effective limits and held revisions can be returned as an execution receipt. Linux hard enforcement and other-platform monitoring are reported separately. Explicit distribution approval verifies selected installed bytes; it does not authenticate a publisher or create a code sandbox.

The local user, operating system, interpreter, installed dependencies and private case directory are trusted. A hostile process with the same user's permissions can rewrite both evidence and local reference hashes. Hash verification establishes consistency against a reference; it cannot establish factual truth, authorship or completeness against that adversary. Use independently trusted signed references where the workflow requires them.

Local databases, indexes and source copies are plaintext. Private file modes are not encryption. Optional age transport encryption does not encrypt the local case. Public-summary pseudonyms do not guarantee anonymity. Retention removes approved source bytes only and discloses the retained derived data and out-of-scope copies; no secure-erasure guarantee is made.

Packet verification rejects links, traversal, unsupported archive extensions, duplicate or missing members and inconsistent identities. It builds its own fixed-schema index from validated JSON and does not open an imported database as a case. A valid signature, explicit key trust, current revision binding and actual reviewer identity are different properties.

Do not attach real evidence, secrets, personal identifiers or whole cases to public issues. Prepare a minimal synthetic reproducer, expected/observed behavior, version and platform. Use GitHub private vulnerability reporting from the repository Security tab for a confidential report. This channel was enabled for the technical preview; a monitored response process, response-time commitment and independent security review remain open R1 release requirements. Submit a synthetic reproducer first and agree on any sensitive evidence transfer separately.

The synthetic loopback development viewer is a test fixture included in the source distribution. It is not installed as a production case server by the wheel. See the [current guide](docs/development-preview.md) and [requirement audit](docs/r1-core-status.md). The older [threat model](docs/threat-model.md) applies to the compatibility command unless explicitly stated otherwise.
