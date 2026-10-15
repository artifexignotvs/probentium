"""Eventus finiti ex indiciis leguntur; absentia numquam fingitur."""
from __future__ import annotations

from datetime import datetime
import ipaddress
import json
import re
import shlex
import unicodedata

from .timeutil import MAX_TIME_US, SQLITE_MAX, TimeError, parse_time

PARSER_VERSION = '1'
FORMATS = ('auth', 'journal', 'events')
MAX_LINE_BYTES = 1_048_576
MAX_TEXT_CHARS = 4096
MAX_JSON_NODES = 4096
MAX_JSON_DEPTH = 8
KINDS = frozenset(('auth.failure', 'auth.success', 'process.exec', 'file.observed', 'file.changed', 'network.connect', 'generic'))
_OPTIONAL = ('host', 'actor', 'src_ip', 'dst_ip', 'path', 'action')
_EVENT_FIELDS = {'timestamp', 'kind', 'attributes', *_OPTIONAL}
_INTEGER_ATTRIBUTES = {'pid': (1, 2**31 - 1), 'parent_pid': (0, 2**31 - 1), 'uid': (0, 2**32 - 1), 'gid': (0, 2**32 - 1), 'port': (0, 65535), 'dst_port': (0, 65535), 'monotonic_us': (0, SQLITE_MAX), 'source_realtime_us': (0, MAX_TIME_US)}
_TEXT_ATTRIBUTES = {'protocol': 32, 'service': 64, 'executable': MAX_TEXT_CHARS, 'result': 64, 'unit': 256, 'boot_id': 32}
_BOOT_ID = re.compile(r'[0-9a-fA-F]{32}\Z')
_HEADER = re.compile(r'(?:(?:<(?P<priority>[0-9]{1,3})>))?(?P<stamp>[0-9]{4}-\S+|[A-Z][a-z]{2} +[0-9]{1,2} +[0-9]{2}:[0-9]{2}:[0-9]{2})[ \t]+(?P<host>\S+)[ \t]+(?P<service>[A-Za-z0-9_./-]+)(?:\[(?P<pid>[0-9]+)\])?:[ \t]*(?P<message>.*)\Z')
_MONTHS = dict(zip(('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'), range(1, 13)))
_SSH = re.compile(r'(?P<outcome>Accepted|Failed) (?P<method>[A-Za-z0-9_/-]{1,64}) for (?P<invalid>invalid user )?(?P<actor>\S+) from (?P<address>\S+) port (?P<port>[0-9]+)(?: (?P<tail>.*))?\Z')
_SUDO = re.compile(r'(?P<actor>[^ :;]+)[ \t]*:[ \t]*(?P<fields>.*)\Z')


class ParseError(ValueError):
    """Signum diagnosticum materiam fontis numquam includit."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _text(value, limit=MAX_TEXT_CHARS, *, empty=False):
    if not isinstance(value, str) or (not value and not empty):
        raise ParseError('invalid_text')
    if len(value) > limit:
        raise ParseError('text_limit')
    if any(unicodedata.category(char).startswith('C') for char in value):
        raise ParseError('invalid_text')
    return value


def _integer(value, low=0, high=SQLITE_MAX):
    if type(value) is not int or not low <= value <= high:
        raise ParseError('invalid_integer')
    return value


def _decimal(value, low=0, high=SQLITE_MAX):
    if isinstance(value, str):
        if not re.fullmatch(r'[0-9]{1,19}', value):
            raise ParseError('invalid_integer')
        value = int(value)
    return _integer(value, low, high)


def _ip(value):
    value = _text(value, 64)
    try:
        if '%' in value:
            raise ValueError
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ParseError('invalid_ip') from None


def _host(value):
    value = _text(value, 253)
    if value == '-':
        return None
    if any(char.isspace() or char in '/\\' for char in value):
        raise ParseError('invalid_host')
    return value


def _unknown(raw=None, basis='unknown_explicit'):
    return {'time_raw': raw, 'time_low_us': None, 'time_high_us': None, 'time_basis': basis}


def _event(kind, time, **fields):
    return {'kind': kind, **time, **dict.fromkeys(_OPTIONAL), 'attributes': {}, **fields}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ParseError('json_duplicate_key')
        result[key] = value
    return result


def _nonfinite(_value):
    raise ParseError('json_nonfinite')


def _json(text):
    try:
        value = json.loads(text, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except ParseError:
        raise
    except (ValueError, RecursionError):
        raise ParseError('invalid_json') from None
    if not isinstance(value, dict):
        raise ParseError('json_object_required')
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ParseError('json_structure_limit')
        if isinstance(item, dict):
            if len(item) > 128:
                raise ParseError('json_structure_limit')
            for key, child in item.items():
                _text(key, 128)
                pending.append((child, depth + 1))
        elif isinstance(item, list):
            if len(item) > 128:
                raise ParseError('json_structure_limit')
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            _text(item, empty=True)
        elif type(item) is int:
            if not -(1 << 63) <= item <= SQLITE_MAX:
                raise ParseError('invalid_integer')
        elif isinstance(item, float):
            raise ParseError('json_float_unsupported')
    return value


def _attributes(value):
    if not isinstance(value, dict) or set(value) - (_INTEGER_ATTRIBUTES.keys() | _TEXT_ATTRIBUTES.keys()):
        raise ParseError('attributes_unsupported')
    result = {}
    for key, item in value.items():
        if key in _INTEGER_ATTRIBUTES:
            result[key] = _integer(item, *_INTEGER_ATTRIBUTES[key])
        else:
            result[key] = _text(item, _TEXT_ATTRIBUTES[key])
            if key == 'boot_id':
                if not _BOOT_ID.fullmatch(item):
                    raise ParseError('invalid_boot_id')
                result[key] = item.lower()
    return result


def _canonical(value):
    if set(value) - _EVENT_FIELDS or not {'timestamp', 'kind'} <= set(value):
        raise ParseError('event_fields_invalid')
    if not isinstance(value['kind'], str) or value['kind'] not in KINDS:
        raise ParseError('event_kind_unsupported')
    time = _unknown() if value['timestamp'] is None else parse_time(value['timestamp'])
    fields = {}
    for key in _OPTIONAL:
        item = value.get(key)
        if item is not None:
            fields[key] = _ip(item) if key in ('src_ip', 'dst_ip') else _host(item) if key == 'host' else _text(item)
    return _event(value['kind'], time, **fields, attributes=_attributes(value.get('attributes', {})))


def _auth_time(stamp):
    if stamp[0].isdigit():
        return parse_time(stamp)
    parts = stamp.split()
    try:
        hour, minute, second = map(int, parts[2].split(':'))
        datetime(2000, _MONTHS[parts[0]], int(parts[1]), hour, minute, second)
    except (ValueError, KeyError, IndexError):
        raise ParseError('timestamp_invalid') from None
    # Annus tantum ad formam probandam adhibetur, numquam ad tempus eventus.
    return _unknown(stamp, 'unknown_no_year_or_timezone')


def _message(message, service, time, host=None, pid=None):
    message = _text(message, empty=True)
    common = {'host': host}
    attributes = {'service': 'ssh' if service in ('sshd', 'sshd-session') else service}
    if pid is not None:
        attributes['pid'] = pid
    if service in ('sshd', 'sshd-session'):
        match = _SSH.fullmatch(message)
        if match is None:
            if message.startswith(('Accepted ', 'Failed ')) or 'authentication failure' in message.lower():
                raise ParseError('auth_message_unsupported')
            return None
        if match['method'] not in {'password', 'publickey', 'keyboard-interactive', 'keyboard-interactive/pam', 'gssapi-with-mic', 'hostbased', 'none'}:
            raise ParseError('auth_method_unsupported')
        port = _decimal(match['port'], 1, 65535)
        actor = _text(match['actor'])
        address = _ip(match['address'])
        outcome = 'success' if match['outcome'] == 'Accepted' else 'failure'
        attributes.update(port=port, result=outcome)
        return _event('auth.' + outcome, time, **common, actor=actor, src_ip=address, action='ssh.authentication', attributes=attributes)
    if service == 'sudo':
        match = _SUDO.fullmatch(message)
        if match is None:
            if 'COMMAND=' in message or 'authentication failure' in message.lower():
                raise ParseError('sudo_message_unsupported')
            return None
        actor = _text(match['actor'])
        fields = match['fields']
        if fields.startswith('user NOT in sudoers') or re.match(r'[0-9]+ incorrect password attempt', fields):
            attributes['result'] = 'denied'
            return _event('auth.failure', time, **common, actor=actor, action='sudo.authorization', attributes=attributes)
        marker = re.search(r'(?:^|;[ \t]*)COMMAND=', fields)
        if marker is None:
            return None
        preceding = fields[:marker.start()]
        if not re.fullmatch(r'(?:[ \t]*(?:TTY|PWD|USER|TSID|ENV)=[^;]*;?)*[ \t]*', preceding):
            raise ParseError('sudo_message_unsupported')
        command = fields[marker.end():]
        try:
            words = shlex.split(command, posix=True)
        except ValueError:
            raise ParseError('sudo_command_invalid') from None
        if not words:
            raise ParseError('sudo_command_invalid')
        executable = _text(words[0])
        attributes.update(executable=executable, result='recorded')
        return _event('process.exec', time, **common, actor=actor, path=executable if executable.startswith('/') else None, action='sudo.command_recorded', attributes=attributes)
    return None


def _auth(text):
    match = _HEADER.fullmatch(text)
    if match is None:
        raise ParseError('auth_header_unsupported')
    if match['priority'] is not None:
        _decimal(match['priority'], 0, 191)
    time = _auth_time(match['stamp'])
    host = _host(match['host'])
    pid = _decimal(match['pid'], 1, 2**31 - 1) if match['pid'] is not None else None
    return _message(match['message'], match['service'], time, host, pid)


def _journal(value):
    if 'MESSAGE' not in value:
        raise ParseError('journal_message_missing')
    if not isinstance(value['MESSAGE'], str):
        raise ParseError('journal_message_unsupported')
    raw = value.get('__REALTIME_TIMESTAMP')
    if raw is None:
        if '__REALTIME_TIMESTAMP' in value:
            raise ParseError('journal_timestamp_invalid')
        time = _unknown(basis='unknown_journal_realtime_missing')
    else:
        stamp = _decimal(raw, 0, MAX_TIME_US)
        time = {'time_raw': str(raw), 'time_low_us': stamp, 'time_high_us': stamp, 'time_basis': 'journal_realtime_microseconds'}
    host = _host(value['_HOSTNAME']) if '_HOSTNAME' in value else None
    service = value.get('SYSLOG_IDENTIFIER', value.get('_COMM', ''))
    service = _text(service, 64, empty=True)
    pid_key = '_PID' if '_PID' in value else 'SYSLOG_PID' if 'SYSLOG_PID' in value else None
    pid = _decimal(value[pid_key], 1, 2**31 - 1) if pid_key is not None else None
    event = _message(value['MESSAGE'], service, time, host, pid)
    if event is None:
        event = _event('generic', time, host=host, action='journal.record')
        if service:
            event['attributes']['service'] = service
        if pid is not None:
            event['attributes']['pid'] = pid
    mappings = {'_SOURCE_REALTIME_TIMESTAMP': 'source_realtime_us', '__MONOTONIC_TIMESTAMP': 'monotonic_us', '_UID': 'uid', '_GID': 'gid'}
    for source, target in mappings.items():
        if source in value:
            event['attributes'][target] = _decimal(value[source], *_INTEGER_ATTRIBUTES[target])
    for source, target in {'_BOOT_ID': 'boot_id', '_SYSTEMD_UNIT': 'unit', '_EXE': 'executable'}.items():
        if source in value:
            item = _attributes({target: value[source]})[target]
            if target == 'executable' and event['kind'] == 'process.exec':
                continue
            event['attributes'][target] = item
    return event


def parse_line(data: bytes, format_name: str, ordinal: int) -> dict | None:
    """Una linea finita unum eventum reddit; errores materiam celant."""
    if format_name not in FORMATS:
        raise ParseError('format_unsupported')
    if type(ordinal) is not int or not 1 <= ordinal <= SQLITE_MAX:
        raise ParseError('ordinal_invalid')
    if not isinstance(data, bytes):
        raise ParseError('input_bytes_required')
    if len(data) > MAX_LINE_BYTES:
        raise ParseError('line_limit')
    try:
        text = data.removesuffix(b'\n').removesuffix(b'\r').decode('utf-8', errors='strict')
    except UnicodeError:
        raise ParseError('invalid_utf8') from None
    if '\n' in text or '\r' in text:
        raise ParseError('multiple_lines')
    if not text.strip(' \t'):
        return None
    try:
        if format_name == 'auth':
            if any(unicodedata.category(c).startswith('C') and c != '\t' for c in text):
                raise ParseError('invalid_text')
            return _auth(text)
        value = _json(text)
        return _canonical(value) if format_name == 'events' else _journal(value)
    except TimeError as error:
        raise ParseError(error.code) from None
