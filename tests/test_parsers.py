"""Fontes adversi et imperfecti sine notitiis secretis probantur."""
import copy
import json
import unittest
from unittest.mock import patch

from testifex.parsers import MAX_LINE_BYTES, PARSER_VERSION, ParseError, parse_line
from testifex.timeutil import MAX_TIME_US, parse_time


def encoded(value):
    return json.dumps(value, ensure_ascii=True).encode()


class ParserTests(unittest.TestCase):
    def canonical(self, **changes):
        value = {'timestamp': '2026-10-15T12:34:56.123Z', 'kind': 'auth.failure', 'host': 'node', 'actor': 'analyst', 'src_ip': '192.0.2.10', 'attributes': {'service': 'ssh'}}
        value.update(changes)
        return value

    def journal(self, **changes):
        value = {'__REALTIME_TIMESTAMP': '1792067696123456', '_HOSTNAME': 'node', 'SYSLOG_IDENTIFIER': 'sshd', '_PID': '42', 'MESSAGE': 'Failed password for analyst from 192.0.2.10 port 40000 ssh2'}
        value.update(changes)
        return value

    def test_output_contract_is_complete_without_raw_duplication(self):
        result = parse_line(encoded(self.canonical()), 'events', 1)
        self.assertEqual(set(result), {'kind', 'time_raw', 'time_low_us', 'time_high_us', 'time_basis', 'host', 'actor', 'src_ip', 'dst_ip', 'path', 'action', 'attributes'})
        self.assertEqual(PARSER_VERSION, '1')
        self.assertIsNone(result['dst_ip'])
        self.assertNotIn('raw', result['attributes'])
        self.assertEqual(result['time_high_us'] - result['time_low_us'], 999)

    def test_all_supported_canonical_kinds_and_optional_nulls(self):
        for kind in ('auth.failure', 'auth.success', 'process.exec', 'file.observed', 'file.changed', 'network.connect', 'generic'):
            result = parse_line(encoded({'kind': kind, 'timestamp': None, 'host': None}), 'events', 1)
            self.assertEqual(result['kind'], kind)
            self.assertIsNone(result['time_low_us'])
            self.assertIsNone(result['time_high_us'])
            self.assertEqual(result['time_basis'], 'unknown_explicit')

    def test_canonical_missing_fields_unknown_fields_and_kind_are_errors(self):
        values = [{}, {'kind': 'generic'}, {'timestamp': None}, self.canonical(extra='PRIVATE-MARKER'), self.canonical(kind='alert'), self.canonical(kind=[]), self.canonical(timestamp=''), self.canonical(timestamp=123)]
        for value in values:
            with self.subTest(value=value), self.assertRaises(ParseError):
                parse_line(encoded(value), 'events', 1)

    def test_canonical_field_types_and_ip_literals_are_strict(self):
        for field in ('host', 'actor', 'path', 'action', 'src_ip', 'dst_ip'):
            for value in (True, [], {}, 123, ''):
                with self.subTest(field=field, value=value), self.assertRaises(ParseError):
                    parse_line(encoded(self.canonical(**{field: value})), 'events', 1)
        for address in ('256.0.0.1', 'host.example', 'fe80::1%eth0', '192.0.2.1/24'):
            with self.subTest(address=address), self.assertRaises(ParseError):
                parse_line(encoded(self.canonical(src_ip=address)), 'events', 1)
        result = parse_line(encoded(self.canonical(src_ip='2001:0db8::1')), 'events', 1)
        self.assertEqual(result['src_ip'], '2001:db8::1')

    def test_attributes_use_typed_allowlist_and_preserve_no_arbitrary_payload(self):
        attrs = {'pid': 4, 'parent_pid': 0, 'uid': 0, 'gid': 4294967295, 'port': 65535, 'dst_port': 443, 'protocol': 'tcp', 'service': 'ssh', 'executable': '/usr/bin/id', 'result': 'recorded', 'unit': 'sshd.service', 'boot_id': 'A' * 32, 'monotonic_us': 7, 'source_realtime_us': 8}
        result = parse_line(encoded(self.canonical(attributes=attrs)), 'events', 1)
        self.assertEqual(result['attributes'], attrs | {'boot_id': 'a' * 32})
        for attrs in (None, [], {'raw': 'PRIVATE-MARKER'}, {'pid': True}, {'pid': 0}, {'port': 65536}, {'uid': -1}, {'gid': 2**32}, {'unit': ['x']}, {'service': ''}, {'boot_id': 'x' * 32}, {'monotonic_us': 2**63}):
            with self.subTest(attrs=attrs), self.assertRaises(ParseError):
                parse_line(encoded(self.canonical(attributes=attrs)), 'events', 1)

    def test_json_rejects_duplicates_at_any_depth_and_constants(self):
        for raw in (b'{"timestamp":null,"kind":"generic","kind":"generic"}', b'{"timestamp":null,"kind":"generic","attributes":{"pid":2,"pid":3}}', b'{"timestamp":NaN,"kind":"generic"}', b'{"timestamp":Infinity,"kind":"generic"}', b'{"timestamp":-Infinity,"kind":"generic"}', b'{"timestamp":1e400,"kind":"generic"}'):
            with self.subTest(raw=raw), self.assertRaises(ParseError):
                parse_line(raw, 'events', 1)

    def test_invalid_unicode_controls_and_text_bounds_are_rejected(self):
        for text in ('\ud800', '\udfff', '\x00', '\x1b[31m', '\u202eabc', '\n', 'x' * 4097):
            with self.subTest(text=repr(text)), self.assertRaises(ParseError):
                parse_line(encoded(self.canonical(actor=text)), 'events', 1)
        for raw in (b'\xff', b'\xed\xa0\x80'):
            with self.assertRaises(ParseError):
                parse_line(raw, 'auth', 1)
        result = parse_line(encoded(self.canonical(actor='Žluťoučký')), 'events', 1)
        self.assertEqual(result['actor'], 'Žluťoučký')

    def test_line_depth_node_and_structure_limits(self):
        with self.assertRaisesRegex(ParseError, '^line_limit$'):
            parse_line(b' ' * (MAX_LINE_BYTES + 1), 'events', 1)
        nested = 1
        for _ in range(9):
            nested = {'a': nested}
        for raw in (b'[' * 2000 + b']' * 2000, encoded({'a': list(range(129))}), encoded({str(i): 'x' for i in range(129)}), encoded(nested)):
            with self.subTest(raw=raw[:40]), self.assertRaises(ParseError):
                parse_line(raw, 'journal', 1)
        with patch('testifex.parsers.MAX_JSON_NODES', 2), self.assertRaisesRegex(ParseError, 'json_structure_limit'):
            parse_line(encoded(self.canonical()), 'events', 1)

    def test_one_physical_line_only_blank_lines_and_crlf(self):
        for line in (b'', b'\n', b'\r\n', b' \t\n'):
            self.assertIsNone(parse_line(line, 'events', 1))
        value = encoded(self.canonical())
        self.assertEqual(parse_line(value + b'\r\n', 'events', 1), parse_line(value, 'events', 1))
        for raw in (b'{\n"timestamp":null,"kind":"generic"}', value + b'\n\n', value + b'\r\n' + value):
            with self.assertRaisesRegex(ParseError, '^multiple_lines$'):
                parse_line(raw, 'events', 1)

    def test_api_arguments_and_errors_do_not_echo_input(self):
        for data, fmt, ordinal in [('PRIVATE-MARKER', 'events', 1), (b'PRIVATE-MARKER', 'unsupported', 1), (b'PRIVATE-MARKER', 'auth', True), (b'PRIVATE-MARKER', 'auth', 0), (b'PRIVATE-MARKER', 'auth', 2**63)]:
            with self.assertRaises(ParseError) as caught:
                parse_line(data, fmt, ordinal)
            self.assertEqual(str(caught.exception), caught.exception.code)
            self.assertNotIn('PRIVATE-MARKER', str(caught.exception))
        for fmt in ('auth', 'journal', 'events'):
            with self.assertRaises(ParseError) as caught:
                parse_line(b'PRIVATE-MARKER-777', fmt, 1)
            self.assertNotIn('PRIVATE-MARKER', str(caught.exception))

    def test_ssh_failure_success_methods_and_source_port(self):
        for outcome, kind in (('Failed', 'auth.failure'), ('Accepted', 'auth.success')):
            for method in ('password', 'publickey', 'keyboard-interactive/pam', 'gssapi-with-mic', 'hostbased', 'none'):
                raw = f'2026-10-15T12:34:56.123456789Z node sshd[42]: {outcome} {method} for invalid user guest from 2001:db8::1 port 40000 ssh2: ED25519 SHA256:synthetic'
                result = parse_line(raw.encode(), 'auth', 1)
                self.assertEqual((result['kind'], result['host'], result['actor'], result['src_ip']), (kind, 'node', 'guest', '2001:db8::1'))
                self.assertEqual(result['attributes'], {'service': 'ssh', 'pid': 42, 'port': 40000, 'result': kind.split('.')[1]})
                self.assertEqual(result['time_raw'], '2026-10-15T12:34:56.123456789Z')

    def test_legacy_syslog_never_invents_year_or_timezone(self):
        for stamp in ('Oct 15 12:34:56', 'Feb 29 00:00:00', 'Jan  1 00:00:00'):
            result = parse_line(f'{stamp} node sshd: Accepted password for analyst from 192.0.2.10 port 22 ssh2'.encode(), 'auth', 1)
            self.assertEqual(result['time_raw'], stamp)
            self.assertIsNone(result['time_low_us'])
            self.assertIsNone(result['time_high_us'])
            self.assertEqual(result['time_basis'], 'unknown_no_year_or_timezone')
        for stamp in ('Feb 30 00:00:00', 'Bad 15 00:00:00', 'Jan 01 24:00:00'):
            with self.assertRaises(ParseError):
                parse_line(f'{stamp} node sshd: Accepted password for user from 192.0.2.10 port 22'.encode(), 'auth', 1)

    def test_auth_non_events_are_ignored_but_recognized_malformed_events_fail(self):
        for body in ('node sshd: Server listening on 0.0.0.0 port 22.', 'node cron[3]: periodic job', 'node sshd: Invalid user guest from 192.0.2.1 port 123'):
            self.assertIsNone(parse_line(('2026-10-15T12:34:56Z ' + body).encode(), 'auth', 1))
        for body in ('Failed password for guest', 'Accepted bananas for guest from 192.0.2.1 port 123', 'Failed password for guest from not-an-ip port 123', 'Failed password for guest from 192.0.2.1 port 65536', 'Accepted password for guest from 192.0.2.1 port 0'):
            with self.assertRaises(ParseError):
                parse_line(('2026-10-15T12:34:56Z node sshd: ' + body).encode(), 'auth', 1)
        for header in ('2026-10-15T12:34:56', '2026-10-15T12:34:56-00:00', '<999>2026-10-15T12:34:56Z'):
            with self.assertRaises(ParseError):
                parse_line((header + ' node sshd: Accepted password for user from 192.0.2.1 port 22').encode(), 'auth', 1)

    def test_sudo_command_preserves_invoker_and_executable_not_raw_arguments(self):
        raw = b'2026-10-15T12:34:56Z node sudo[15]: analyst : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/printf "private argument"'
        result = parse_line(raw, 'auth', 1)
        self.assertEqual(result['kind'], 'process.exec')
        self.assertEqual(result['actor'], 'analyst')
        self.assertEqual(result['path'], '/usr/bin/printf')
        self.assertEqual(result['action'], 'sudo.command_recorded')
        self.assertEqual(result['attributes']['result'], 'recorded')
        self.assertNotIn('private argument', json.dumps(result))
        raw = raw.replace(b'"private argument"', b'"user NOT in sudoers"')
        self.assertEqual(parse_line(raw, 'auth', 1)['kind'], 'process.exec')

    def test_sudo_denials_and_unsupported_commands_cannot_be_execution(self):
        for fields in ('user NOT in sudoers ; TTY=pts/0 ; COMMAND=/usr/bin/id', '3 incorrect password attempts ; TTY=pts/0 ; COMMAND=/usr/bin/id'):
            result = parse_line(('2026-10-15T12:34:56Z node sudo: analyst : ' + fields).encode(), 'auth', 1)
            self.assertEqual(result['kind'], 'auth.failure')
            self.assertEqual(result['attributes']['result'], 'denied')
            self.assertIsNone(result['path'])
        for fields in ('unknown refusal ; COMMAND=/usr/bin/id', 'TTY=pts/0 ; COMMAND=', 'TTY=pts/0 ; COMMAND="unterminated'):
            with self.assertRaises(ParseError):
                parse_line(('2026-10-15T12:34:56Z node sudo: analyst : ' + fields).encode(), 'auth', 1)
        self.assertIsNone(parse_line(b'2026-10-15T12:34:56Z node sudo: pam_unix(sudo:session): session closed for user root', 'auth', 1))

    def test_journal_authoritative_realtime_and_auxiliary_clocks_do_not_replace_it(self):
        value = self.journal(_SOURCE_REALTIME_TIMESTAMP='100', __MONOTONIC_TIMESTAMP='200', _BOOT_ID='A' * 32, _UID='1000', _GID=1000, _SYSTEMD_UNIT='sshd.service', _EXE='/usr/sbin/sshd')
        event = parse_line(encoded(value), 'journal', 1)
        self.assertEqual(event['time_low_us'], 1792067696123456)
        self.assertEqual(event['time_high_us'], 1792067696123456)
        self.assertEqual(event['time_raw'], value['__REALTIME_TIMESTAMP'])
        self.assertEqual(event['time_basis'], 'journal_realtime_microseconds')
        self.assertEqual(event['attributes']['source_realtime_us'], 100)
        self.assertEqual(event['attributes']['monotonic_us'], 200)
        self.assertEqual(event['attributes']['boot_id'], 'a' * 32)
        del value['__REALTIME_TIMESTAMP']
        event = parse_line(encoded(value), 'journal', 1)
        self.assertIsNone(event['time_low_us'])
        self.assertEqual(event['time_basis'], 'unknown_journal_realtime_missing')

    def test_journal_generic_retains_structure_without_duplication_or_inferred_execution(self):
        value = self.journal(SYSLOG_IDENTIFIER='worker', MESSAGE='PRIVATE-MARKER-777', _EXE='/usr/bin/worker', _UID='1000', CUSTOM_FIELD='private context')
        event = parse_line(encoded(value), 'journal', 1)
        self.assertEqual(event['kind'], 'generic')
        self.assertEqual(event['action'], 'journal.record')
        self.assertIsNone(event['actor'])
        self.assertIsNone(event['path'])
        self.assertNotIn('PRIVATE-MARKER', json.dumps(event))
        self.assertNotIn('private context', json.dumps(event))
        self.assertEqual(event['attributes']['uid'], 1000)

    def test_journal_sudo_logging_executable_does_not_overwrite_recorded_command(self):
        value = self.journal(SYSLOG_IDENTIFIER='sudo', MESSAGE='analyst : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id', _EXE='/usr/bin/sudo')
        event = parse_line(encoded(value), 'journal', 1)
        self.assertEqual(event['kind'], 'process.exec')
        self.assertEqual(event['attributes']['executable'], '/usr/bin/id')
        self.assertEqual(event['path'], '/usr/bin/id')

    def test_journal_missing_binary_or_repeated_fields_fail_without_raw_errors(self):
        mutations = [{'MESSAGE': None}, {'MESSAGE': [1, 2, 255]}, {'__REALTIME_TIMESTAMP': None}, {'__REALTIME_TIMESTAMP': -1}, {'__REALTIME_TIMESTAMP': '1.0'}, {'__REALTIME_TIMESTAMP': True}, {'__REALTIME_TIMESTAMP': MAX_TIME_US + 1}, {'_PID': None}, {'_PID': ['42']}, {'_SOURCE_REALTIME_TIMESTAMP': 'invalid'}, {'__MONOTONIC_TIMESTAMP': 2**63}, {'_BOOT_ID': 'private-machine-id'}, {'_HOSTNAME': 'host with space'}]
        for changes in mutations:
            with self.subTest(changes=changes), self.assertRaises(ParseError):
                parse_line(encoded(self.journal(**changes)), 'journal', 1)
        value = self.journal();del value['MESSAGE']
        with self.assertRaisesRegex(ParseError, '^journal_message_missing$'):
            parse_line(encoded(value), 'journal', 1)

    def test_journal_zero_realtime_and_integer_values_are_explicit(self):
        event = parse_line(encoded(self.journal(__REALTIME_TIMESTAMP=0)), 'journal', 1)
        self.assertEqual((event['time_raw'], event['time_low_us'], event['time_high_us']), ('0', 0, 0))
        self.assertEqual(parse_line(encoded(self.journal(_HOSTNAME='-')), 'journal', 1)['host'], None)

    def test_parsing_is_deterministic_does_not_mutate_or_open_network(self):
        source = self.canonical()
        original = copy.deepcopy(source)
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), patch('builtins.open', side_effect=AssertionError('file access forbidden')):
            first = parse_line(encoded(source), 'events', 1)
            second = parse_line(encoded(source), 'events', 999)
        self.assertEqual(first, second)
        self.assertEqual(source, original)
        self.assertEqual(first['time_low_us'], parse_time(source['timestamp'])['time_low_us'])


if __name__ == '__main__':
    unittest.main()
