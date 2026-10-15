"""Tempora explicita servantur; resolutio horologii fiduciam non probat."""
from __future__ import annotations

from datetime import datetime, timedelta
import re

MAX_TIMESTAMP_CHARS = 96
SQLITE_MIN = -(1 << 63)
SQLITE_MAX = (1 << 63) - 1
_EPOCH = datetime(1970, 1, 1)
_MIN_DELTA = datetime.min - _EPOCH
_MAX_DELTA = datetime.max - _EPOCH
MIN_TIME_US = _MIN_DELTA.days * 86_400_000_000 + _MIN_DELTA.seconds * 1_000_000
MAX_TIME_US = _MAX_DELTA.days * 86_400_000_000 + _MAX_DELTA.seconds * 1_000_000 + 999_999
_RFC3339 = re.compile(
    r"(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})[Tt]"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]+))?(?P<zone>[Zz]|[+-][0-9]{2}:[0-9]{2})\Z"
)


class TimeError(ValueError):
    """Signum fixum tantum, numquam tempus secretum, redditur."""

    def __init__(self, code: str = "timestamp_invalid"):
        self.code = code
        super().__init__(code)


def parse_time(value: str) -> dict:
    """Cellam resolutionis UTC reddit; errorem horologii non aestimat."""
    if not isinstance(value, str) or not value:
        raise TimeError()
    if len(value) > MAX_TIMESTAMP_CHARS:
        raise TimeError("timestamp_too_long")
    match = _RFC3339.fullmatch(value)
    if match is None:
        raise TimeError()
    zone = match['zone']
    if zone == '-00:00':
        raise TimeError('timestamp_timezone_unknown')
    offset_seconds = 0
    if zone not in ('Z', 'z'):
        hour, minute = int(zone[1:3]), int(zone[4:6])
        if hour > 23 or minute > 59:
            raise TimeError()
        offset_seconds = (hour * 60 + minute) * 60 * (1 if zone[0] == '+' else -1)
    try:
        wall = datetime(*(int(match[field]) for field in ('year', 'month', 'day', 'hour', 'minute', 'second')))
    except ValueError:
        raise TimeError() from None
    fraction = match['fraction'] or ''
    delta = wall - _EPOCH
    low = delta.days * 86_400_000_000 + delta.seconds * 1_000_000
    low += int((fraction[:6] + '000000')[:6]) - offset_seconds * 1_000_000
    width = 10 ** (6 - min(6, len(fraction)))
    high = low + width - 1
    if not MIN_TIME_US <= low <= high <= MAX_TIME_US:
        raise TimeError('timestamp_out_of_range')
    basis = 'rfc3339_seconds' if not fraction else f'rfc3339_fraction_{len(fraction)}'
    if len(fraction) > 6:
        basis = f'rfc3339_submicrosecond_enclosure_{len(fraction)}'
    return {'time_low_us': low, 'time_high_us': high, 'time_basis': basis, 'time_raw': value}


def format_time(us: int | None) -> str | None:
    """Microssecunda integra sine conversione fluitante formantur."""
    if us is None:
        return None
    if type(us) is not int or not MIN_TIME_US <= us <= MAX_TIME_US:
        raise TimeError('timestamp_out_of_range')
    value = _EPOCH + timedelta(microseconds=us)
    return value.isoformat(timespec='microseconds') + 'Z'
