# Three-minute review

Run `testifex demo --directory demo-output` in a directory without an existing `demo-output`. This writes synthetic fixtures and two cases. No input is downloaded.

1. Open `testifex browse --case demo-output/auth-case --ascii`. Locate the successful login. Enter shows its recorded UTC interval, source hash, record ordinal and byte offset. Press `r` to explicitly read the corresponding original record.
2. Read `demo-output/auth-case.md`. The failure cluster and nearby process record are leads, not a conclusion that the machine was compromised. Eight failures precede success under the recorded intervals.
3. Read `demo-output/uncertain-case.md`. The process timestamp is still preserved as recorded. Its normalized interval now includes the declared ±30-second error. The process/login ordering is possible rather than certain.
4. Run `testifex diff demo-output/auth-case.json demo-output/uncertain-case.json`. The process source identity changes because its transformation options changed. The difference records source/options changes rather than silently treating the new interpretation as the old one.
5. Run `testifex verify --case demo-output/auth-case`, then `testifex replay --case demo-output/auth-case --into replay-output`. Compare `testifex analyze` results for both cases: the normalized evidence and findings reproduce. A new case has a different case identifier, so full reports need not be byte-identical.

The two cases contain the same raw observations and different declared uncertainty. They do not model every incident, resolve causality, establish a complete acquisition or demonstrate a detector's real-world false-positive rate.
