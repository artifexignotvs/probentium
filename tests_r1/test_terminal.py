"""Terminalis verus cum limitibus et mandatis probatur."""
import errno
import fcntl
import io
import os
from pathlib import Path
import pty
import select
import signal
import struct
import sys
import tempfile
import termios
import time
import unittest
from unittest.mock import patch

from probentium.contracts import ProbentiumError
from probentium.screen import cell_width
from probentium.store import CaseStore
from probentium.terminal import _Console, _run, banner_lines, launch


class _TerminalProcess:
    def __init__(self, code="from probentium.terminal import launch; raise SystemExit(launch())", *, term="dumb", width=100):
        self.output = b""
        self.status = None
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            env = dict(os.environ, TERM=term, NO_COLOR="1", PYTHONDONTWRITEBYTECODE="1")
            os.execve(sys.executable, [sys.executable, "-c", code], env)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, width, 0, 0))

    def send(self, data):
        os.write(self.fd, data if isinstance(data, bytes) else data.encode())

    def until(self, marker, timeout=15):
        deadline = time.monotonic() + timeout
        while marker not in self.output:
            if time.monotonic() > deadline:
                raise AssertionError("terminal output timeout: " + repr(self.output[-1000:]))
            if select.select([self.fd], [], [], .1)[0]:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        chunk = b""
                    else:
                        raise
                if not chunk:
                    raise AssertionError("terminal ended before marker: " + repr(self.output[-1000:]))
                self.output += chunk
        return self.output

    def wait(self, timeout=15):
        deadline = time.monotonic() + timeout
        while self.status is None:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(status)
                return self.status
            if time.monotonic() > deadline:
                raise AssertionError("terminal exit timeout")
            if select.select([self.fd], [], [], .05)[0]:
                try:
                    self.output += os.read(self.fd, 65536)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
        return self.status

    def close(self):
        if self.status is None:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(self.pid, 0)
            except ChildProcessError:
                pass
        os.close(self.fd)


class TerminalTests(unittest.TestCase):
    def start(self, *args, **kwargs):
        process = _TerminalProcess(*args, **kwargs)
        self.addCleanup(process.close)
        return process

    def test_ascii_banner_is_cell_bounded_at_every_small_width(self):
        for width in range(1, 121):
            lines = banner_lines(width)
            self.assertTrue(all(line.isascii() and cell_width(line) <= width for line in lines))
            self.assertFalse(any("\x1b" in line for line in lines))
        self.assertIn("[?]", banner_lines(80)[0])
        for invalid in (True, 0, -1, 4097, "80"):
            with self.assertRaises(ProbentiumError):
                banner_lines(invalid)

    def test_noninteractive_refuses_without_output_or_case_creation(self):
        output = io.StringIO()
        with patch("sys.stdin", io.StringIO()), patch("sys.stdout", output):
            with self.assertRaises(ProbentiumError) as caught:
                launch()
        self.assertEqual(caught.exception.code, "interactive_terminal_required")
        self.assertEqual(output.getvalue(), "")

    def test_safe_case_text_escapes_controls_and_ascii_option(self):
        output = io.StringIO()
        with patch("sys.stdout", output):
            _Console(True).write("name\x1b[2J\u202eč界")
        text = output.getvalue()
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)
        self.assertTrue(text.isascii())
        self.assertIn("\\u202e", text)

    def test_real_pty_start_and_quit_no_automatic_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            before = set(Path(directory).iterdir())
            code = "import os; os.chdir(" + repr(directory) + "); from probentium.terminal import launch; raise SystemExit(launch())"
            process = self.start(code)
            data = process.until(b"probentium> ")
            self.assertIn(b"[?]", data)
            self.assertIn(b"Development preview", data)
            self.assertNotIn(b"\x1b", data)
            process.send("quit\n")
            self.assertEqual(process.wait(), 0)
            self.assertEqual(set(Path(directory).iterdir()), before)

    def test_real_pty_no_banner_narrow_dumb_and_help(self):
        process = self.start("from probentium.terminal import launch; raise SystemExit(launch(no_banner=True, ascii_only=True))", width=32)
        data = process.until(b"probentium> ")
        self.assertNotIn(b"[?]", data)
        process.send("help\n")
        data = process.until(b"open PATH")
        self.assertNotIn(b"\x1b", data)
        process.send("q\n")
        self.assertEqual(process.wait(), 0)
        for line in process.output.decode("ascii").splitlines():
            self.assertLessEqual(len(line), 32)

    def test_real_pty_create_then_open_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "case with spaces")
            process = self.start()
            process.until(b"probentium> ")
            process.send("create '" + path + "'\n")
            process.until(b"Case name: ")
            process.send("Synthetic terminal case\n")
            process.until(b"Created private case")
            process.send("open '" + path + "'\n")
            process.until(b"Plain terminal:")
            process.send("run status --case '" + path + "'\n")
            process.until(b'"development_preview":true')
            process.send("create '" + path + "'\nReplacement\n")
            process.until(b"case_already_exists")
            process.send("q\n")
            self.assertEqual(process.wait(), 0)
            with CaseStore(path) as case:
                self.assertEqual(case.meta["name"], "Synthetic terminal case")
                self.assertEqual(case.revision, 0)

    def test_real_pty_existing_cli_dispatch_and_no_shell_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / "must-not-exist"
            process = self.start()
            process.until(b"probentium> ")
            process.send("run --version\n")
            process.until(b"Command exit: 0")
            process.send("run formats ; touch " + str(sentinel) + "\n")
            process.until(b"invalid_arguments")
            process.send("q\n")
            self.assertEqual(process.wait(), 0)
            self.assertFalse(sentinel.exists())

    def test_real_pty_demo_is_explicit_and_synthetic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "exercise"
            process = self.start()
            process.until(b"probentium> ")
            self.assertFalse(path.exists())
            process.send("demo '" + str(path) + "'\n")
            process.until(b"Synthetic exercise created", timeout=45)
            process.send("q\n")
            self.assertEqual(process.wait(), 0)
            with CaseStore(path / "case") as case:
                self.assertGreater(case.query_events(limit=1)["total"], 0)
                self.assertTrue(case.objects("scenario")[-1]["data"]["synthetic"])

    def test_real_pty_eof_and_interrupt(self):
        process = self.start()
        process.until(b"probentium> ")
        process.send(b"\x04")
        self.assertEqual(process.wait(), 0)
        interrupted = self.start()
        interrupted.until(b"probentium> ")
        interrupted.send(b"\x03")
        self.assertEqual(interrupted.wait(), 130)
        self.assertIn(b"Interrupted", interrupted.output)

    def test_overlong_input_refuses_before_following_fragment(self):
        text = "x" * 4097 + "\ncreate must-not-exist\n"
        console = _Console(True)
        with patch("sys.stdin", io.StringIO(text)), patch("sys.stdout", io.StringIO()):
            with self.assertRaises(ProbentiumError) as caught:
                console.read("prompt> ")
        self.assertEqual((caught.exception.code, caught.exception.exit_code), ("terminal_input_limit", 6))

    def test_recursive_console_is_refused_before_callback(self):
        class Parsed:
            command = "console"
        with patch("probentium.cli.parser") as parser:
            parser.return_value.parse_args.return_value = Parsed()
            with patch("probentium.cli_contract.capture_information"):
                calls = []
                with self.assertRaises(ProbentiumError) as caught:
                    _run(["console"], calls.append)
        self.assertEqual(caught.exception.code, "recursive_console_not_supported")
        self.assertEqual(calls, [])

    def test_real_curses_case_view_returns_to_launcher(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "case")
            with CaseStore.create(path, "Synthetic native view"):
                pass
            process = self.start(term="xterm-256color")
            process.until(b"probentium> ")
            process.send("open " + path + "\n")
            process.until(b"OVERVIEW")
            process.send("q")
            process.until(b"Returned from the case view")
            process.send("q\n")
            self.assertEqual(process.wait(), 0)


if __name__ == "__main__":
    unittest.main()
