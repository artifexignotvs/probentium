"""Forma certa, errores aperti."""
import hashlib
import json
import re
from decimal import Decimal, InvalidOperation

MAX_LINE = 1024 * 1024
MAX_SOURCE = 1024 * 1024 * 1024
MAX_REPORT = 64 * 1024 * 1024
FORMATS = ("auth", "journal", "events")


class CaseError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise CaseError("duplicate_json_key")
            result[key] = value
        return result
    def constant(_):
        raise CaseError("nonfinite_json_number")
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise CaseError("invalid_json") from exc


def safe_text(value):
    """Imperium terminalis a dato separatur."""
    return "".join(c if c.isprintable() and c not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069" else "\\u%04x" % ord(c) for c in str(value))


def label(value, name="label"):
    if not isinstance(value, str) or not value.strip() or len(value) > 256 or safe_text(value) != value:
        raise CaseError("invalid_" + name)
    return value


def seconds_us(value, nonnegative=False):
    try:
        number = Decimal(str(value))
        if not number.is_finite() or abs(number) > 86400 * 365:
            raise CaseError("invalid_seconds")
        micros = number * 1000000
        if micros != micros.to_integral_value() or (nonnegative and micros < 0):
            raise CaseError("invalid_seconds")
        return int(micros)
    except (InvalidOperation, ValueError) as exc:
        raise CaseError("invalid_seconds") from exc


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32,64}", value):
        raise CaseError("invalid_identifier")
    return value
