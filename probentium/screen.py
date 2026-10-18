"""Eadem tabula in terminali et imagine locali apparet."""

import json
import unicodedata

MIN_WIDTH = 80
MIN_HEIGHT = 24
MAX_WIDTH = 4096
MAX_HEIGHT = 2048
MAX_TEXT = 16384
VIEWS = ("overview", "evidence", "timeline", "controls", "incident", "filings", "changes", "claims", "scenarios", "review", "scope", "export", "retention", "help")
STYLES = frozenset(("normal", "dim", "strong", "inverse"))


def _escape(character):
    number = ord(character)
    if number < 256:
        return "\\x%02x" % number
    if number <= 65535:
        return "\\u%04x" % number
    return "\\U%08x" % number


def safe_text(value):
    """Imperium occultum fit textus visibilis."""
    if value is None:
        return "not supplied"
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bool, int, float)):
        text = str(value)
    elif isinstance(value, (dict, list, tuple)):
        try:
            text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError, RecursionError):
            return "[unsupported value]"
    else:
        return "[unsupported value]"
    result = []
    has_base = False
    marks = 0
    for character in text[:MAX_TEXT]:
        number = ord(character)
        category = unicodedata.category(character)
        combining = category in ("Mn", "Me")
        variation = (0xFE00 <= number <= 0xFE0F or 0xE0100 <= number <= 0xE01EF
                     or 0x1F3FB <= number <= 0x1F3FF or number == 0x20E3)
        jamo = 0x1160 <= number <= 0x11FF or 0xD7B0 <= number <= 0xD7FF
        if category in ("Cc", "Cf", "Cs", "Cn", "Zl", "Zp") or variation or jamo:
            result.append(_escape(character))
            has_base, marks = True, 0
        elif combining and (not has_base or marks >= 8):
            result.append(_escape(character))
            has_base, marks = True, 0
        else:
            result.append(character)
            if combining:
                marks += 1
            else:
                has_base, marks = True, 0
    if len(text) > MAX_TEXT:
        result.append(" [text limited]")
    return "".join(result)


def _character_width(character):
    if unicodedata.category(character) in ("Mn", "Me"):
        return 0
    return 2 if unicodedata.east_asian_width(character) in ("W", "F") else 1


def cell_width(text):
    """Cellulae latae duplicantur; accentus cellulas non addunt."""
    return sum(_character_width(character) for character in text)


def _take(text, width):
    result, used = [], 0
    for character in text:
        size = _character_width(character)
        if used + size > width:
            break
        result.append(character)
        used += size
    return "".join(result)


def fit_text(value, width, pad=False):
    """Textus limitatur ante picturam, non postea."""
    if width <= 0:
        return ""
    text = safe_text(value)
    if cell_width(text) > width:
        suffix = "..." if width >= 3 else "." * width
        text = _take(text, width - len(suffix)) + suffix
    if pad:
        text += " " * (width - cell_width(text))
    return text


def _line(text="", style="normal"):
    return {"text": text, "style": style}


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _rows(value):
    return value if isinstance(value, list) else []


def _integer(value, default=0):
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _value(row, *keys):
    for key in keys:
        if key in row and row[key] is not None:
            return safe_text(row[key])
    return "not supplied"


def _integrity(model):
    integrity = _mapping(model.get("integrity"))
    issues = _rows(integrity.get("issues"))
    if integrity.get("authorized_unavailable"):
        return "partial / authorized unavailable"
    if integrity.get("ok") is True and not issues:
        return "passed"
    if integrity.get("ok") is False or issues:
        return "issues reported"
    if integrity.get("state") == "not_checked":
        return "not checked at this revision"
    return "not supplied"


def _columns(values, widths):
    return "  ".join(fit_text(value, width, pad=True) for value, width in zip(values, widths))


def _table(title, headings, rows, fields, widths, state, capacity, context=""):
    """Index electus semper intra fenestram manet."""
    result = [_line(title + ("  |  " + context if context else ""), "strong"),
              _line(_columns(headings, widths), "dim")]
    available = max(0, capacity - 2)
    count = len(rows)
    if not count:
        result.append(_line("No rows supplied.", "dim"))
        return result
    selected = max(0, min(_integer(state.get("selected")), count - 1))
    start = max(0, min(_integer(state.get("scroll")), max(0, count - available)))
    if selected < start:
        start = selected
    elif selected >= start + available:
        start = max(0, selected - available + 1)
    for index in range(start, min(count, start + available)):
        row = _mapping(rows[index])
        values = [_value(row, *names) for names in fields]
        result.append(_line(_columns(values, widths), "inverse" if index == selected else "normal"))
    return result


def _overview(model):
    counts = _mapping(model.get("counts"))
    incident = _mapping(model.get("incident"))
    result = [_line("OVERVIEW", "strong"), _line(), _line("CASE INVENTORY", "strong")]
    for key, label in (("sources", "Sources"), ("events", "Events"), ("controls", "Controls"), ("filings", "Filings")):
        result.append(_line(f"  {label:<14}{_value(counts, key)}"))
    result.extend([_line(), _line("INTEGRITY", "strong"), _line("  " + _integrity(model))])
    for issue in _rows(_mapping(model.get("integrity")).get("issues"))[:4]:
        result.append(_line("  " + safe_text(issue)))
    result.extend([_line(), _line("INCIDENT", "strong"),
                   _line("  " + _value(incident, "title")),
                   _line("  Profile: " + _value(incident, "profile") + "  |  Status: " + _value(incident, "status")),
                   _line(), _line("Choose a view with 1-7. Enter opens the selected record.", "dim")])
    return result


def _incident(model):
    incident = _mapping(model.get("incident"))
    result = [_line("INCIDENT", "strong"), _line(_value(incident, "title")),
              _line("ID: " + _value(incident, "id")),
              _line("Profile: " + _value(incident, "profile") + "  |  Status: " + _value(incident, "status")),
              _line("Awareness: " + _value(incident, "awareness")), _line(), _line("DEADLINES", "strong")]
    deadlines = _rows(incident.get("deadline_rows"))
    if not deadlines:
        result.append(_line("No deadline rows supplied.", "dim"))
    for deadline in deadlines:
        row = _mapping(deadline)
        result.append(_line(_value(row, "stage_display", "stage") + "  |  " + _value(row, "target") + "  |  " + _value(row, "status_display", "status")))
        result.append(_line("  Basis: " + _value(row, "basis"), "dim"))
    limitations = _rows(incident.get("limitations"))
    if limitations:
        result.extend([_line(), _line("LIMITATIONS", "strong")])
        result.extend(_line(safe_text(value)) for value in limitations)
    return result


def _help():
    return [_line("HELP", "strong"), _line(),
            _line("1-7        Open Overview, Evidence, Timeline, Controls, Incident, Filings, Changes"),
            _line("8 / 9 / 0  Open Claims, Scenarios, Review"),
            _line("j / k      Move selection or scroll the detail view"),
            _line("Enter      Open or close the selected detail"),
            _line("/          Filter the entire timeline"),
            _line("PgUp/PgDn  Previous/next timeline page; scroll detail"),
            _line("v          Request verification"),
            _line(":          Open the command prompt"),
            _line("?          Open help"),
            _line("q          Quit"), _line(),
            _line("COMMANDS", "strong"),
            _line(":prepare   Freeze the selected track's latest fields as a new draft"),
            _line(":track ID  Select a reporting track; :filter TEXT searches all events"),
            _line(":verify    Verify bytes and stored identities; no external submission"),
            _line(":overview  Open a view by name (timeline, incident, filings, changes)"), _line(),
            _line(":claims / :scenarios / :review / :scope / :export / :retention"),
            _line(":evaluate ID   Evaluate a stored claim at the displayed revision"),
            _line(":explain ID    Show a stored evaluation, witness paths and evidence gaps"),
            _line(":witness EVALUATION EVENT   Open verified bytes of a listed witness"),
            _line(":replay        Repeat normalization and stored analyses offline"), _line(),
            _line("DISPLAY", "strong"),
            _line("The selected row uses inverse text. Long table values end with ..."),
            _line("Control characters and directional overrides are shown as escapes."),
            _line("Timeline counts distinguish supplied rows from the case total."),
            _line("Development interface. Displayed state comes from the open case.", "dim")]


def _detail(model, width, scroll, capacity):
    """Singula longa dividuntur; imperia in textu latentia non aguntur."""
    source = _rows(model.get("detail_lines"))
    if not source:
        return [_line("DETAIL", "strong"), _line("No detail supplied.", "dim")]
    result = [_line("DETAIL  |  Enter returns to the list", "strong")]
    wanted = max(0, scroll)
    position = 0
    for value in source:
        text = safe_text(value)
        while True:
            part = _take(text, width)
            if position >= wanted and len(result) < capacity:
                result.append(_line(part))
            position += 1
            text = text[len(part):]
            if not text or len(result) >= capacity:
                break
        if len(result) >= capacity:
            break
    if len(result) == 1:
        result.append(_line("End of supplied detail.", "dim"))
    return result


def _content(model, state, width, capacity):
    view = state.get("view", "overview")
    if state.get("detail") is True:
        return _detail(model, width, _integer(state.get("scroll")), capacity)
    if view == "overview":
        return _overview(model)
    if view == "incident":
        rows = _incident(model)
        offset = max(0, min(_integer(state.get("scroll")), max(0, len(rows) - capacity)))
        return rows[offset:offset + capacity]
    if view == "help":
        rows = _help()
        offset = max(0, min(_integer(state.get("scroll")), max(0, len(rows) - capacity)))
        return rows[offset:offset + capacity]
    if view == "evidence":
        return _table("EVIDENCE", ("SOURCE", "FORMAT", "STATUS", "PARSED"), _rows(model.get("sources")),
                      (("label", "name", "id", "source_id"), ("format", "adapter"), ("status_summary", "status"), ("parsed_count", "records", "events")),
                      (width - 45, 12, 19, 8), state, capacity)
    if view == "timeline":
        events = _mapping(model.get("events"))
        rows = _rows(events.get("rows"))
        context = f"loaded {len(rows)}  total {_value(events, 'total')}  offset {_value(events, 'offset')}"
        return _table("TIMELINE", ("RECORDED TIME", "KIND", "HOST", "ACTOR"), rows,
                      (("time", "time_raw", "recorded_time", "timestamp"), ("kind",), ("host",), ("actor", "id")),
                      (26, 18, 14, width - 64), state, capacity, context)
    if view == "controls":
        return _table("CONTROLS", ("ID", "CONTROL", "STATUS", "COVERAGE"), _rows(model.get("controls")),
                      (("id",), ("title",), ("status_display", "status"), ("coverage_summary", "coverage")),
                      (11, width - 48, 20, 11), state, capacity, "supplied declarations / references only")
    if view == "filings":
        return _table("FILINGS", ("ID", "STATUS", "TITLE", "CUTOFF"), _rows(model.get("filings")),
                      (("id",), ("status",), ("title",), ("cutoff",)),
                      (11, 19, width - 60, 24), state, capacity)
    if view == "changes":
        unit = (width - 6) // 4
        return _table("CHANGES", ("FIELD", "BEFORE", "AFTER", "REASON"), _rows(model.get("changes")),
                      (("field",), ("before_summary", "before"), ("after_summary", "after"), ("reason",)),
                      (unit, unit, unit, width - 6 - 3 * unit), state, capacity)
    if view in {"claims", "scenarios", "review", "scope", "export", "retention"}:
        return _table(view.upper(), ("ID", "TYPE", "STATE", "DETAIL"), _rows(model.get(view)),
                      (("id",), ("kind",), ("state",), ("summary",)),
                      (13, 20, 18, width - 57), state, capacity,
                      "Enter opens the complete stored record; :help lists actions")
    return [_line("Unknown view.", "strong"), _line("Use 1-7 or ? for help.")]


def _ascii_tree(value):
    """Litterae non ASCII ante mensuram columnae explicantur."""
    if isinstance(value, str):
        return value.encode("ascii", "backslashreplace").decode("ascii")
    if isinstance(value, dict):
        return {key: _ascii_tree(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_ascii_tree(item) for item in value]
    return value


def render(model, state, width=120, height=36, ascii_only=False):
    """Tabula pura dat longitudines certas nec statum mutat."""
    if type(width) is not int or type(height) is not int or not 1 <= width <= MAX_WIDTH or not 1 <= height <= MAX_HEIGHT:
        raise ValueError("screen dimensions out of bounds")
    model, state = _mapping(model), _mapping(state)
    if ascii_only:
        model, state = _ascii_tree(model), _ascii_tree(state)
    if width < MIN_WIDTH or height < MIN_HEIGHT:
        values = [_line("PROBENTIUM  |  development", "inverse"),
                  _line("Terminal too small.", "strong"),
                  _line(f"Resize to at least {MIN_WIDTH} columns x {MIN_HEIGHT} rows."),
                  _line(f"Current size: {width} x {height}."), _line("q quit", "dim")]
    else:
        product = fit_text(_value(model, "product"), 24)
        version = fit_text(_value(model, "version"), 24)
        origin = "synthetic case" if model.get("synthetic") is True else "local case" if model.get("synthetic") is False else "origin not supplied"
        counts = _mapping(model.get("counts"))
        case_suffix = "  |  revision " + fit_text(_value(model, "revision"), 12) + "  |  " + origin
        case_label = fit_text(_value(model, "case_name"), width - 6 - cell_width(case_suffix))
        values = [_line(f" {product} {version}  |  development", "inverse"),
                  _line("Case: " + case_label + case_suffix),
                  _line("Integrity: " + _integrity(model) + "  |  " + "  ".join(f"{key} {_value(counts, key)}" for key in ("sources", "events", "controls", "filings")), "dim"),
                  _line()]
        capacity = height - 7
        content = _content(model, state, width, capacity)
        values.extend(content[:capacity])
        values.extend(_line() for _ in range(height - 3 - len(values)))
        prompt = state.get("prompt")
        message = safe_text(prompt) if prompt is not None else safe_text(state.get("message", ""))
        query = safe_text(state.get("filter", ""))
        if prompt is None and query:
            message = "Timeline filter: " + query + ("  |  " + message if message else "")
        values.extend([_line(message, "strong" if prompt is not None else "dim"),
                       _line("1Overview 2Evidence 3Timeline 4Controls 5Incident 6Filings 7Changes", "strong"),
                       _line("8Claims 9Scenarios 0Review | j/k Enter /filter v verify :command ? help q quit", "dim")])
    values = values[:height]
    values.extend(_line() for _ in range(height - len(values)))
    return {"width": width, "height": height,
            "lines": [{"text": fit_text(line["text"], width, pad=True), "style": line["style"]} for line in values]}
