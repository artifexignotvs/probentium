# Real terminal capture

`demo.cast` is an asciicast v2 recording of the unmodified TESTIFEX browser in a POSIX pseudo-terminal. `terminal.png`, `details.png` and `raw.png` are frames rendered from the recorded terminal output with a VT emulator. Text files preserve the corresponding visible screen contents. These are actual program results on synthetic data, not interface mockups.

Run `testifex demo --directory demo-output`, then reproduce the recording with:

```sh
python scripts/capture_demo.py --demo demo-output --output captured-assets
```

The optional capture utility needs `pyte` and `Pillow` and a monospaced font supplied through `--font` if its default DejaVu Sans Mono path is unavailable. These are documentation-production tools, not package runtime dependencies. The cast is playable with an asciicast-compatible player; no hosted player is required to use the forensic tool.

The recording opens the case, selects the successful authentication, opens details, explicitly reads the raw record and exits. `capture.json` records the command, input-generation command, terminal dimensions, key actions and a digest of captured output bytes. No shell prompt, hostname, account environment or real evidence is embedded. Only the documentation address `192.0.2.30` appears.
