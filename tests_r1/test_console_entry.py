"""Ingressus publicus per terminalem verum probatur."""
import fcntl
import json
import os
from pathlib import Path
import pty
import struct
import subprocess
import sys
import tempfile
import termios
import unittest

from probentium.store import CaseStore
from tests_r1.test_terminal import _TerminalProcess


class _EntryProcess(_TerminalProcess):
    def __init__(self, *arguments, term="dumb", width=100):
        self.output = b""
        self.status = None
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            env = dict(os.environ, TERM=term, NO_COLOR="1", PYTHONDONTWRITEBYTECODE="1")
            os.execve(sys.executable, [sys.executable, "-m", "probentium", *arguments], env)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, width, 0, 0))


class ConsoleEntryTests(unittest.TestCase):
    def start(self, *arguments, **options):
        process = _EntryProcess(*arguments, **options)
        self.addCleanup(process.close)
        return process

    def invoke(self, *arguments):
        return subprocess.run([sys.executable, "-m", "probentium", *arguments],
                              input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=20, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))

    def test_no_arguments_real_tty_logo_help_formats_and_quit(self):
        process = self.start(term="xterm-256color")
        startup = process.until(b"probentium> ")
        self.assertIn(b"[?]", startup)
        self.assertIn(b"Development preview", startup)
        process.send("help\n")
        process.until(b"complete arguments")
        process.send("run formats\n")
        process.until(b'"schema":"probentium.formats.v1"')
        process.until(b"Command exit: 0")
        process.send("quit\n")
        self.assertEqual(process.wait(), 0)
        self.assertNotIn(b"Traceback", process.output)
        self.assertNotIn(b"\x1b", process.output)

    def test_explicit_console_no_banner_ascii_dumb_narrow(self):
        process = self.start("console", "--no-banner", "--ascii", width=32)
        startup = process.until(b"probentium> ")
        self.assertNotIn(b"[?]", startup)
        self.assertNotIn(b"P R O B", startup)
        process.send("q\n")
        self.assertEqual(process.wait(), 0)
        self.assertNotIn(b"\x1b", process.output)
        self.assertTrue(process.output.isascii())
        self.assertTrue(all(len(line) <= 32 for line in process.output.decode().splitlines()))

    def test_machine_console_refuses_with_only_one_json_error(self):
        result = self.invoke("--format", "json", "console", "--case", "missing-case")
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b"")
        error = json.loads(result.stderr)
        self.assertEqual(error["schema"], "probentium.cli-result.v1")
        self.assertEqual(error["errors"], [{"code": "interactive_json_not_supported", "exit_code": 7}])
        self.assertNotIn(b"[?]", result.stderr)
        self.assertNotIn(b"probentium> ", result.stderr)

    def test_non_tty_never_auto_launches_or_prints_a_banner(self):
        for arguments, code in (((), "invalid_arguments"), (("console",), "interactive_terminal_required")):
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(json.loads(result.stderr), {"error": code})
                self.assertNotIn(b"[?]", result.stderr)
        result = self.invoke("--format", "json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(json.loads(result.stderr)["errors"], [{"code": "invalid_arguments", "exit_code": 2}])

    def test_machine_console_refuses_even_on_real_tty_without_logo(self):
        process = self.start("--format", "json", "console")
        process.until(b'"interactive_json_not_supported"')
        self.assertEqual(process.wait(), 7)
        error = json.loads(process.output)
        self.assertEqual(error["status"], "unsupported")
        self.assertNotIn(b"[?]", process.output)
        self.assertNotIn(b"probentium> ", process.output)

    def test_dumb_case_entry_requires_complete_cli_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "case with spaces")
            with CaseStore.create(path, "Synthetic entry exercise"):
                pass
            process = self.start("console", "--case", path, term="dumb")
            startup = process.until(b"probentium> ")
            self.assertIn(b"Synthetic entry exercise", startup)
            self.assertIn(b"Plain terminal", startup)
            self.assertNotIn(b"\x1b", startup)
            process.send("run status\n")
            process.until(b"invalid_arguments")
            process.send("run status --case '" + path + "'\n")
            process.until(b'"development_preview":true')
            process.until(b"Command exit: 0")
            process.send("q\n")
            self.assertEqual(process.wait(), 0)
            with CaseStore(path) as case:
                self.assertEqual(case.revision, 0)

    def test_real_cli_interrupt_returns_130_and_eof_returns_zero(self):
        process = self.start()
        process.until(b"probentium> ")
        process.send(b"\x03")
        self.assertEqual(process.wait(), 130)
        self.assertIn(b"Interrupted", process.output)
        self.assertNotIn(b"Traceback", process.output)
        ended = self.start("console", "--no-banner")
        ended.until(b"probentium> ")
        ended.send(b"\x04")
        self.assertEqual(ended.wait(), 0)

    def test_public_console_recursion_is_rejected_and_help_remains_available(self):
        process = self.start("console")
        process.until(b"probentium> ")
        process.send("run --format json console\n")
        process.until(b"recursive_console_not_supported")
        process.send("run console --help\n")
        process.until(b"Hide the text logo")
        process.send("q\n")
        self.assertEqual(process.wait(), 0)

    def test_direct_help_and_machine_formats_remain_banner_free(self):
        help_result = self.invoke("console", "--help")
        self.assertEqual(help_result.returncode, 0)
        self.assertIn(b"probentium console --ascii", help_result.stdout)
        self.assertNotIn(b"[?]", help_result.stdout)
        self.assertEqual(help_result.stderr, b"")
        formats = self.invoke("--format", "json", "formats")
        self.assertEqual(formats.returncode, 0)
        self.assertEqual(formats.stderr, b"")
        self.assertEqual(json.loads(formats.stdout)["data"]["schema"], "probentium.formats.v1")
        self.assertNotIn(b"[?]", formats.stdout)


if __name__ == "__main__":
    unittest.main()
