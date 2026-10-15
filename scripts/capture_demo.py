#!/usr/bin/env python3
"""Terminalis verus in exemplis fictis describitur."""
import argparse
import codecs
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import sys
import termios
import time


def main():
    parser = argparse.ArgumentParser(description="Record the real evidence browser on synthetic demo cases.")
    parser.add_argument("--demo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--font", default="/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf")
    args = parser.parse_args()
    import pyte
    from PIL import Image, ImageDraw, ImageFont
    root = args.demo.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    cols, rows = 116, 40
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    command = [sys.executable, "-m", "testifex", "browse", "--case", "auth-case", "--ascii"]
    process = subprocess.Popen(command, cwd=root, stdin=slave, stdout=slave, stderr=slave,
                               env=dict(os.environ, TERM="xterm-256color"), start_new_session=True)
    os.close(slave)
    screen = pyte.Screen(cols, rows)
    stream = pyte.Stream(screen)
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    events, screens = [], {}
    raw = bytearray()
    actions = [(2.5, b"j" * 8), (4.5, b"\r"), (7.5, b"r"), (11.0, b"q"), (12.0, b"q")]
    captures = [(2.0, "timeline"), (6.5, "details"), (9.5, "raw")]
    started = time.monotonic()
    try:
        while time.monotonic() - started < 15:
            elapsed = time.monotonic() - started
            while actions and elapsed >= actions[0][0]:
                _, value = actions.pop(0)
                os.write(master, value)
                events.append([round(elapsed, 6), "i", value.decode("ascii")])
            ready, _, _ = select.select([master], [], [], 0.025)
            if ready:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                raw.extend(chunk)
                value = decoder.decode(chunk)
                events.append([round(time.monotonic() - started, 6), "o", value])
                stream.feed(value)
            while captures and elapsed >= captures[0][0]:
                _, name = captures.pop(0)
                screens[name] = [list(screen.buffer[y][x] for x in range(cols)) for y in range(rows)]
                (output / (name + ".txt")).write_text("\n".join(screen.display) + "\n")
            if process.poll() is not None:
                break
        process.wait(timeout=5)
        if process.returncode != 0 or set(screens) != {"timeline", "details", "raw"}:
            raise RuntimeError("terminal_capture_incomplete")
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        os.close(master)
    header = {"version": 2, "width": cols, "height": rows, "title": "TESTIFEX synthetic evidence review", "env": {"TERM": "xterm-256color"}}
    (output / "demo.cast").write_text("\n".join(json.dumps(item) for item in [header, *events]) + "\n")
    font = ImageFont.truetype(args.font, 17)
    cw, ch, border = round(font.getlength("M")), 22, 24
    for name, cells in screens.items():
        image = Image.new("RGB", (cols * cw + 2 * border, rows * ch + 2 * border), "#101010")
        draw = ImageDraw.Draw(image)
        for y, line in enumerate(cells):
            for x, cell in enumerate(line):
                left, top = border + x * cw, border + y * ch
                if cell.reverse:
                    draw.rectangle((left, top, left + cw, top + ch), fill="#ededed")
                if cell.data.strip():
                    draw.text((left, top), cell.data, font=font, fill="#101010" if cell.reverse else "#ededed", stroke_width=int(cell.bold))
        image.save(output / ("terminal.png" if name == "timeline" else name + ".png"))
    proof = {"schema": "testifex.capture.v1", "command": "testifex browse --case auth-case --ascii",
             "fixture_command": "testifex demo --directory demo-output", "terminal_dimensions": [cols, rows],
             "capture_method": "Unmodified program in a POSIX pseudo-terminal; actual terminal bytes replayed with a VT emulator. No substituted result text.",
             "keys": ["j x8", "Enter", "r", "q", "q"], "exit_code": process.returncode,
             "raw_terminal_sha256": hashlib.sha256(raw).hexdigest(),
             "scope": "Synthetic example only; process execution evidence is not proof of session linkage or compromise."}
    (output / "capture.json").write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps({"captured": True, "events": len(events), "screens": len(screens)}))


if __name__ == "__main__":
    main()
