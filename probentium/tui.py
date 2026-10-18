"""Interfacies terminalis eandem tabulam ostendit."""
import curses

from .workbench import Workbench


def browse(path, ascii_only=False):
    workbench = Workbench(path)
    def loop(window):
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        window.keypad(True)
        styles = {"normal": curses.A_NORMAL, "strong": curses.A_BOLD,
                  "dim": curses.A_DIM, "inverse": curses.A_REVERSE}
        keys = {curses.KEY_UP: "ArrowUp", curses.KEY_DOWN: "ArrowDown", curses.KEY_NPAGE: "PageDown",
                curses.KEY_PPAGE: "PageUp", curses.KEY_HOME: "Home", curses.KEY_BACKSPACE: "Backspace",
                curses.KEY_ENTER: "Enter", curses.KEY_F1: "F1"}
        while not workbench.closed:
            height, width = window.getmaxyx()
            frame = workbench.frame(width, height, ascii_only=ascii_only)
            window.erase()
            for index, row in enumerate(frame["lines"]):
                try:
                    window.addstr(index, 0, row["text"], styles[row["style"]])
                except curses.error:
                    pass
            window.refresh()
            key = window.get_wch()
            if key == curses.KEY_RESIZE:
                continue
            if isinstance(key, int):
                key = keys.get(key, "")
            else:
                key = {"\n": "Enter", "\r": "Enter", "\x1b": "Escape", "\x7f": "Backspace"}.get(key, key)
            workbench.key(key)
    curses.wrapper(loop)
    return 0
