"""Tempus et origo sine ornatu apparent."""
import sys
import unicodedata
from dataclasses import dataclass
from itertools import islice

from .model import CaseError, canonical, safe_text
from .timeutil import format_time

MAX_EVENTS = 10000
MAX_FILTER = 128
MAX_RAW_PREVIEW = 16384
MIN_WIDTH = 70
MIN_HEIGHT = 18


def display_text(value, ascii_only=False):
    """Imperium occultum numquam ad terminalem transit."""
    text = safe_text(value)
    if ascii_only:
        text = text.encode("ascii", "backslashreplace").decode("ascii")
    return text


def cell_width(character):
    if unicodedata.combining(character):
        return 0
    return 2 if unicodedata.east_asian_width(character) in ("W", "F") else 1


def fit_text(value, width, ascii_only=False):
    """Latitudo cellularum, non numerus litterarum, terminum ponit."""
    if width <= 0:
        return ""
    result, used = [], 0
    for character in display_text(value, ascii_only):
        size = cell_width(character)
        if used + size > width:
            break
        result.append(character)
        used += size
    return "".join(result)


def wrap_text(value, width, ascii_only=False):
    text = display_text(value, ascii_only)
    if width <= 0:
        return []
    lines, current, used = [], [], 0
    for character in text:
        size = cell_width(character)
        if current and used + size > width:
            lines.append("".join(current))
            current, used = [], 0
        if size <= width:
            current.append(character)
            used += size
    if current or not lines:
        lines.append("".join(current))
    return lines


def time_interval(event, original=False):
    """Ordo ostensus causam non probat."""
    low = event.get("original_low_us" if original else "time_low_us")
    high = event.get("original_high_us" if original else "time_high_us")
    if low is None or high is None:
        return "[unknown time]"
    try:
        return "[" + format_time(low) + " .. " + format_time(high) + "]"
    except (ValueError, OverflowError, TypeError):
        return "[unrenderable time bounds]"


@dataclass
class Snapshot:
    events: list
    sources: list
    truncated: bool


def load_snapshot(case):
    """Finis memoriae palam declaratur."""
    iterator = iter(case.events())
    try:
        rows = list(islice(iterator, MAX_EVENTS + 1))
    finally:
        close = getattr(iterator, "close", None)
        if close is not None:
            close()
    return Snapshot(rows[:MAX_EVENTS], case.sources(), len(rows) > MAX_EVENTS)


def filter_events(events, query):
    """Quaestio simplex intra fenestram oneratum quaerit."""
    query = display_text(query).casefold()
    if not query:
        return list(events)
    fields = ("id", "source_id", "kind", "host", "actor", "src_ip", "dst_ip", "path", "action", "time_raw")
    return [event for event in events
            if query in " | ".join(display_text(event.get(field) or "") for field in fields).casefold()]


def coverage_lines(snapshot):
    totals = {field: sum(source.get(field, 0) for source in snapshot.sources)
              for field in ("parsed_count", "ignored_count", "error_count")}
    unfinished = sum(source.get("status") != "complete" for source in snapshot.sources)
    return [
        f"Sources {len(snapshot.sources)} | parsed {totals['parsed_count']} | ignored {totals['ignored_count']} | errors {totals['error_count']}",
        f"Sources not complete {unfinished} | Import counts do not prove collection completeness.",
    ]


def event_details(event, source, raw=None, raw_error=False):
    """Singula vestigia ad fontem suum referuntur."""
    lines = [
        "Event " + event["id"],
        "Kind: " + str(event.get("kind")),
        "UTC bounds: " + time_interval(event),
        "Bounds express recorded resolution and declared clock error, not confidence.",
        "Original bounds: " + time_interval(event, original=True),
        "Original time text: " + str(event.get("time_raw")),
        "Time basis: " + str(event.get("time_basis")),
        "Clock offset / error (us): " + str(event.get("clock_offset_us", 0)) + " / " + str(event.get("clock_error_us", 0)),
    ]
    for field in ("host", "actor", "src_ip", "dst_ip", "path", "action"):
        lines.append(field.replace("_", " ").capitalize() + ": " + str(event.get(field)))
    lines.extend([
        "Source ID: " + event["source_id"],
        "Source label: " + str(source.get("label", "unavailable")),
        "Source SHA-256: " + str(source.get("sha256", "unavailable")),
        "Parser: " + str(source.get("format", "unavailable")) + " / " + str(source.get("parser_version", "unavailable")),
        "Source status: " + str(source.get("status", "unavailable")),
        "Source parsed / ignored / errors: " + " / ".join(str(source.get(field, "?")) for field in ("parsed_count", "ignored_count", "error_count")),
        "Original line: " + str(event.get("ordinal")),
        "Byte offset / length: " + str(event.get("offset")) + " / " + str(event.get("length")),
        "Record SHA-256: " + str(event.get("raw_sha256")),
        "Source options: " + canonical(source.get("options", {})),
        "Attributes: " + canonical(event.get("attributes", {})),
        "Hash agreement is consistency evidence, not proof of acquisition or completeness.",
    ])
    if raw_error:
        lines.append("Raw record unavailable. Run case verification to inspect consistency.")
    elif raw is not None:
        preview = raw[:MAX_RAW_PREVIEW]
        if len(raw) > MAX_RAW_PREVIEW:
            lines.append(f"Escaped raw preview: first {MAX_RAW_PREVIEW} of {len(raw)} bytes; preview truncated.")
        else:
            lines.append(f"Escaped raw record: {len(raw)} bytes.")
        lines.append(preview.decode("utf-8", "backslashreplace"))
    else:
        lines.append("Press r to read the digest-checked raw record, escaped for display.")
    return lines


def layout_detail(event, source, width, ascii_only=False, raw=None, raw_error=False):
    return [line for value in event_details(event, source, raw, raw_error)
            for line in wrap_text(value, width, ascii_only)]


def viewport(selected, total, page_size):
    """Index semper intra terminos manet."""
    if total <= 0:
        return 0, 0
    selected = max(0, min(selected, total - 1))
    return selected, (selected // max(1, page_size)) * max(1, page_size)


def _paint(screen, y, value, ascii_only=False, attribute=0):
    import curses
    height, width = screen.getmaxyx()
    if not 0 <= y < height or width < 2:
        return
    try:
        screen.addstr(y, 0, fit_text(value, width - 1, ascii_only), attribute)
    except (curses.error, UnicodeError):
        pass


def _key(screen):
    import curses
    try:
        return screen.get_wch()
    except curses.error:
        return None


def _filter_prompt(screen, previous, ascii_only):
    import curses
    query = previous
    while True:
        height, _ = screen.getmaxyx()
        try:
            screen.move(max(0, height - 1), 0)
            screen.clrtoeol()
        except curses.error:
            pass
        _paint(screen, height - 1, "/" + query + "  [Enter apply; Esc cancel]", ascii_only)
        screen.refresh()
        key = _key(screen)
        if key in ("\n", "\r", curses.KEY_ENTER):
            return query
        if key == "\x1b":
            return previous
        if key in ("\x7f", "\b", curses.KEY_BACKSPACE):
            query = query[:-1]
        elif isinstance(key, str) and key.isprintable() and len(query) < MAX_FILTER:
            query += key


def _browse(screen, case, snapshot, ascii_only):
    import curses
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    screen.keypad(True)
    screen.timeout(250)
    sources = {source["id"]: source for source in snapshot.sources}
    rows, query, selected = list(snapshot.events), "", 0
    detail, scroll, raw, raw_error = False, 0, None, False
    while True:
        height, width = screen.getmaxyx()
        screen.erase()
        if width < MIN_WIDTH or height < MIN_HEIGHT:
            _paint(screen, 0, "TESTIFEX", ascii_only)
            _paint(screen, 1, "Resize terminal to 70 x 18.", ascii_only)
            _paint(screen, 2, "Or use the timeline command.", ascii_only)
            _paint(screen, 3, "q: exit", ascii_only)
            screen.refresh()
            if _key(screen) in ("q", "Q"):
                return
            continue
        content_height = height - 10
        _paint(screen, 0, "TESTIFEX | " + str(case.metadata.get("name", "Case")), ascii_only, curses.A_BOLD)
        for index, line in enumerate(coverage_lines(snapshot), 1):
            _paint(screen, index, line, ascii_only)
        limit = f"Showing first {MAX_EVENTS} events only; filter searches this loaded subset." if snapshot.truncated else "Loaded case snapshot; filter searches imported event fields."
        _paint(screen, 3, limit, ascii_only)
        _paint(screen, 4, "UTC bounds: resolution + declared clock error; ties do not imply causality.", ascii_only)
        _paint(screen, 5, f"Matches {len(rows)} / loaded {len(snapshot.events)} | Filter: {query or '(none)'}", ascii_only)
        _paint(screen, 6, "-" * (width - 1), ascii_only)
        if detail and rows:
            event = rows[selected]
            lines = layout_detail(event, sources.get(event["source_id"], {}), width - 1, ascii_only, raw, raw_error)
            scroll = min(max(0, scroll), max(0, len(lines) - content_height))
            for index, line in enumerate(lines[scroll:scroll + content_height], 7):
                _paint(screen, index, line, ascii_only)
            help_line = "j/k or arrows: scroll | PgUp/PgDn | r: raw record | q: back"
            position = f"Detail lines {scroll + 1}-{min(len(lines), scroll + content_height)} / {len(lines)}"
        else:
            page_size = max(1, content_height // 2)
            selected, first = viewport(selected, len(rows), page_size)
            for index, event in enumerate(rows[first:first + page_size]):
                number = first + index
                marker = "> " if number == selected else "  "
                text = marker + " | ".join(str(event.get(field) or "-") for field in ("kind", "host", "actor"))
                attribute = curses.A_REVERSE if number == selected else 0
                _paint(screen, 7 + index * 2, text, ascii_only, attribute)
                _paint(screen, 8 + index * 2, "  " + time_interval(event), ascii_only)
            if not rows:
                _paint(screen, 7, "No matching imported events. This does not establish absence of activity.", ascii_only)
            help_line = "j/k or arrows | PgUp/PgDn | / filter | Enter details | q exit"
            position = f"Event {selected + 1 if rows else 0} / {len(rows)} | Unknown time in loaded set: " + str(sum(e.get("time_low_us") is None for e in snapshot.events))
        _paint(screen, height - 3, "-" * (width - 1), ascii_only)
        _paint(screen, height - 2, position, ascii_only)
        _paint(screen, height - 1, help_line, ascii_only)
        screen.refresh()
        key = _key(screen)
        if key in ("q", "Q", "\x1b"):
            if detail:
                detail, scroll, raw, raw_error = False, 0, None, False
            else:
                return
        elif key == "/" and not detail:
            query = _filter_prompt(screen, query, ascii_only)
            rows, selected = filter_events(snapshot.events, query), 0
        elif key in ("\n", "\r", curses.KEY_ENTER) and rows and not detail:
            detail, scroll, raw, raw_error = True, 0, None, False
        elif key in ("r", "R") and detail and rows:
            try:
                raw = case.raw_event(rows[selected]["id"])
                raw_error = False
            except (CaseError, OSError):
                raw, raw_error = None, True
            lines = layout_detail(rows[selected], sources.get(rows[selected]["source_id"], {}), width - 1, ascii_only, raw, raw_error)
            scroll = max(0, len(lines) - content_height)
        elif key in ("j", curses.KEY_DOWN, "k", curses.KEY_UP, curses.KEY_NPAGE, curses.KEY_PPAGE):
            amount = content_height if detail else max(1, content_height // 2)
            delta = {"j": 1, curses.KEY_DOWN: 1, "k": -1, curses.KEY_UP: -1,
                     curses.KEY_NPAGE: amount, curses.KEY_PPAGE: -amount}[key]
            if detail:
                scroll = max(0, scroll + delta)
            else:
                selected, _ = viewport(selected + delta, len(rows), max(1, content_height // 2))


def run_tui(case, ascii_only=False):
    """Terminalis post exitum vel interruptionem restituitur."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise CaseError("interactive_terminal_required_use_timeline_command")
    try:
        import curses
    except ImportError as exc:
        raise CaseError("terminal_browser_unavailable_use_timeline_command") from exc
    snapshot = load_snapshot(case)
    try:
        curses.wrapper(_browse, case, snapshot, ascii_only)
    except KeyboardInterrupt:
        return
    except curses.error as exc:
        raise CaseError("terminal_browser_unavailable_use_timeline_command") from exc
