"""Forma certa, verba incerta separantur."""
import hashlib
import json
import re
from datetime import datetime, timezone

import rfc8785

_JSON_DELIMITERS = re.compile(rb'["\[\]{}]')


class ProbentiumError(ValueError):
    def __init__(self, code, exit_code=2):
        self.code = code
        self.exit_code = exit_code
        super().__init__(code)


def _check_value(value):
    ascii_keys = True
    def check(item, depth=0):
        nonlocal ascii_keys
        if depth > 32:
            raise ProbentiumError("json_depth_limit", 6)
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeError:
                raise ProbentiumError("invalid_canonical_value") from None
            return
        if item is None or isinstance(item, bool):
            return
        if type(item) is int:
            if abs(item) > 9007199254740991:
                raise ProbentiumError("integer_out_of_range")
            return
        if isinstance(item, list):
            for child in item:
                check(child, depth + 1)
            return
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ProbentiumError("unsupported_value_type")
                if depth >= 32:
                    raise ProbentiumError("json_depth_limit", 6)
                if not key.isascii():
                    check(key, depth + 1)
                    ascii_keys = False
                check(child, depth + 1)
            return
        raise ProbentiumError("unsupported_value_type")
    check(value)
    return ascii_keys


def canonical_bytes(value):
    ascii_keys = _check_value(value)
    return _canonical_validated(value, ascii_keys)


def _canonical_validated(value, ascii_keys):
    """Solum post integram validationem vocetur; nullum limitem hic removet."""
    try:
        # Sine numeris fractis, claves ASCII eundem ordinem UTF-16 servant.
        if ascii_keys:
            return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return rfc8785.dumps(value)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ProbentiumError("invalid_canonical_value") from exc


def object_digest(value, domain="PROBENTIUM-OBJECT-V1"):
    return hashlib.sha256(domain.encode("ascii") + b"\0" + canonical_bytes(value)).hexdigest()


def strict_json(raw, max_bytes=16 * 1024 * 1024):
    if isinstance(raw, str):
        try:
            raw = raw.encode("utf-8")
        except UnicodeError as exc:
            raise ProbentiumError("invalid_json") from exc
    if not isinstance(raw, bytes) or len(raw) > max_bytes:
        raise ProbentiumError("input_size_limit", 6)
    depth = 0
    quoted = False
    # Delimitatores tantum leguntur; series effugiorum paritatem servant.
    for token in _JSON_DELIMITERS.finditer(raw):
        ch = raw[token.start()]
        if ch == 34:
            position = token.start() - 1
            while position >= 0 and raw[position] == 92:
                position -= 1
            if (token.start() - position - 1) % 2 == 0:
                quoted = not quoted
        elif quoted:
            continue
        elif ch in (91, 123):
            depth += 1
            if depth > 32:
                raise ProbentiumError("json_depth_limit", 6)
        elif ch in (93, 125):
            depth -= 1
    def pairs(items):
        data = {}
        for key, value in items:
            if key in data:
                raise ProbentiumError("duplicate_json_key")
            data[key] = value
        return data
    def no_float(_):
        raise ProbentiumError("floating_point_not_supported")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=no_float, parse_constant=no_float)
        _check_value(value)
        return value
    except ProbentiumError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ProbentiumError("invalid_json") from exc


def safe_text(value):
    return "".join(c if c.isprintable() and c not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069" else "\\u%04x" % ord(c) for c in str(value))


def text_field(value, maximum=256):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or safe_text(value) != value:
        raise ProbentiumError("invalid_text")
    return value


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40 or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", value):
        raise ProbentiumError("timezone_required")
    if not value.endswith("Z") and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        raise ProbentiumError("invalid_timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ProbentiumError("invalid_timestamp") from exc


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
