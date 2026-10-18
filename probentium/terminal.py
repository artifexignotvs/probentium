"""Limen terminale; mandata numquam ad concham mittuntur."""
import os
import shlex
import sys

from . import __version__
from .contracts import ProbentiumError
from .screen import fit_text, safe_text

MAX_INPUT = 4096
_HELP = (
    "open PATH       Open an existing case in the terminal view.",
    "create PATH     Create a new private case; asks for its name.",
    "demo PATH       Create a synthetic exercise in a new directory.",
    "run COMMAND ... Run any existing command with its complete arguments.",
    "help            Show these commands.  quit / q: leave.",
    "Example: run status --case '/path/with spaces/case'",
    "Example: run --help",
    "No shell, pipes or automatic case creation. Quote paths with spaces.",
)


def banner_lines(width=80):
    """Signum breve est; angustiae numquam celantur."""
    if type(width) is not int or not 1 <= width <= 4096:
        raise ProbentiumError("invalid_terminal_width")
    mark = "[?]  P R O B E N T I U M" if width >= 24 else "[?] PROBENTIUM"
    return [fit_text(mark, width), fit_text("Offline evidence workbench", width),
            fit_text("Development preview / " + __version__, width),
            fit_text("Ex indiciis, non ex fama.", width)]


class _Console:
    def __init__(self, ascii_only):
        self.ascii_only = ascii_only
        self.selected = None

    def width(self):
        try:
            return min(4096, max(1, os.get_terminal_size(sys.stdout.fileno()).columns))
        except (OSError, ValueError, AttributeError):
            return 80

    def write(self, value=""):
        text = safe_text(value)
        if self.ascii_only:
            text = text.encode("ascii", "backslashreplace").decode("ascii")
        encoding = sys.stdout.encoding or "ascii"
        text = text.encode(encoding, "backslashreplace").decode(encoding)
        sys.stdout.write(fit_text(text, self.width()) + "\n")
        sys.stdout.flush()

    def read(self, prompt):
        sys.stdout.write(fit_text(prompt, self.width()))
        sys.stdout.flush()
        text = sys.stdin.readline(MAX_INPUT + 1)
        if text == "":
            return None
        if len(text) > MAX_INPUT or not text.endswith("\n"):
            # Residuum longum numquam novum mandatum fit.
            raise ProbentiumError("terminal_input_limit", 6)
        text = text[:-1]
        if any(ord(char) < 32 and char != "\t" or ord(char) == 127 for char in text):
            raise ProbentiumError("invalid_terminal_input")
        return text

    def select(self, path):
        from .store import CaseStore
        with CaseStore(path) as case:
            name, revision = case.meta["name"], case.revision
            events = case.query_events(limit=1)["total"]
        self.selected = path
        self.write("Case: " + name)
        self.write("Revision: " + str(revision) + " / Events: " + str(events))
        self.write("Integrity has not been checked by the launcher.")

    def open(self, path):
        self.select(path)
        if os.environ.get("TERM", "").lower() in {"", "dumb", "unknown"}:
            self.write("Plain terminal: use run with complete command arguments.")
            self.write("Example: run verify --case PATH")
            return
        try:
            from .tui import browse
            browse(path, ascii_only=self.ascii_only)
        except ImportError:
            raise ProbentiumError("terminal_view_unavailable", 7) from None
        except Exception as exc:
            import curses
            if not isinstance(exc, curses.error):
                raise
            raise ProbentiumError("terminal_view_unavailable", 7) from None
        self.write("Returned from the case view. Type help for launcher commands.")


def _run(arguments, command_runner):
    """Eadem grammatica adhibetur; recursio interdicitur."""
    from . import cli, cli_contract
    parser = cli.parser()
    cli_contract.capture_information(parser, [])
    try:
        parsed = parser.parse_args(arguments)
    except cli_contract.InformationExit:
        parsed = None
    if parsed is not None and parsed.command == "console":
        raise ProbentiumError("recursive_console_not_supported")
    return (command_runner or cli.main)(arguments)


def launch(case_path=None, *, ascii_only=False, no_banner=False, command_runner=None):
    """Nulla mutatio sine mandato manifesto incipit."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ProbentiumError("interactive_terminal_required")
    if type(ascii_only) is not bool or type(no_banner) is not bool:
        raise ProbentiumError("invalid_terminal_options")
    if case_path is not None and not isinstance(case_path, (str, os.PathLike)):
        raise ProbentiumError("invalid_terminal_case")
    if command_runner is not None and not callable(command_runner):
        raise ProbentiumError("invalid_terminal_runner")
    console = _Console(ascii_only)
    if not no_banner:
        for line in banner_lines(console.width()):
            console.write(line)
        console.write()
    console.write("Local console. Type help for commands; quit to leave.")
    try:
        if case_path is not None:
            console.open(os.fspath(case_path))
        while True:
            value = console.read("probentium> ")
            if value is None:
                console.write()
                return 0
            try:
                words = shlex.split(value)
            except ValueError:
                console.write("Error: invalid_terminal_command")
                continue
            if not words:
                continue
            action, *arguments = words
            if action in {"quit", "q", "exit"} and not arguments:
                return 0
            try:
                if action in {"help", "?"} and not arguments:
                    for line in _HELP:
                        console.write(line)
                elif action == "open" and len(arguments) == 1:
                    console.open(arguments[0])
                elif action == "create" and len(arguments) == 1:
                    from .store import CaseStore
                    name = console.read("Case name: ")
                    if name is None:
                        return 0
                    if not name.strip():
                        console.write("Cancelled: a case name is required.")
                        continue
                    with CaseStore.create(arguments[0], name):
                        pass
                    console.write("Created private case. Use open PATH to inspect it.")
                    console.select(arguments[0])
                elif action == "demo" and len(arguments) == 1:
                    from .demo import make_demo
                    console.write("Creating synthetic exercise; no real incident data is supplied.")
                    result = make_demo(arguments[0], extended=True)
                    console.write("Synthetic exercise created. Case path:")
                    console.write(result["case"])
                    console.select(result["case"])
                elif action == "run" and arguments:
                    code = _run(arguments, command_runner)
                    if type(code) is not int or not 0 <= code <= 255:
                        raise ProbentiumError("invalid_terminal_command_result", 4)
                    console.write("Command exit: " + str(code))
                else:
                    console.write("Error: invalid_terminal_command; type help.")
            except ProbentiumError as exc:
                console.write("Error: " + exc.code + " (exit " + str(exc.exit_code) + ")")
            except (OSError, ValueError, TypeError, KeyError):
                console.write("Error: terminal_operation_failed")
    except KeyboardInterrupt:
        console.write("Interrupted. Inspect case state before retrying a write.")
        return 130
