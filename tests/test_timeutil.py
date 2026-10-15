"""Resolutio, zona et fines temporum sine coniectura probantur."""
import unittest

from testifex.timeutil import MAX_TIME_US, MIN_TIME_US, TimeError, format_time, parse_time


class TimeTests(unittest.TestCase):
    def test_epoch_and_negative_time_have_inclusive_precision_cells(self):
        epoch = parse_time('1970-01-01T00:00:00Z')
        self.assertEqual((epoch['time_low_us'], epoch['time_high_us']), (0, 999999))
        prior = parse_time('1969-12-31T23:59:59.999999Z')
        self.assertEqual((prior['time_low_us'], prior['time_high_us']), (-1, -1))
        self.assertEqual(format_time(-1), '1969-12-31T23:59:59.999999Z')

    def test_fractional_precision_is_not_promoted_to_clock_accuracy(self):
        for fraction, low, high in [('1', 100000, 199999), ('12', 120000, 129999), ('123', 123000, 123999), ('1234', 123400, 123499), ('12345', 123450, 123459), ('123456', 123456, 123456)]:
            with self.subTest(fraction=fraction):
                result = parse_time('1970-01-01T00:00:00.' + fraction + 'Z')
                self.assertEqual((result['time_low_us'], result['time_high_us']), (low, high))
                self.assertEqual(result['time_basis'], 'rfc3339_fraction_' + str(len(fraction)))

    def test_nanoseconds_keep_raw_text_and_use_containing_microsecond(self):
        for fraction in ('123456001', '123456999', '123456123456789123456789', '000000001'):
            raw = '1970-01-01T00:00:00.' + fraction + 'Z'
            event = parse_time(raw)
            expected = int(fraction[:6])
            self.assertEqual((event['time_low_us'], event['time_high_us']), (expected, expected))
            self.assertEqual(event['time_raw'], raw)
            self.assertIn('submicrosecond_enclosure', event['time_basis'])

    def test_offsets_are_integer_normalized_and_raw_is_unchanged(self):
        for raw in ('1970-01-01T01:30:00+01:30', '1969-12-31T22:30:00-01:30', '1970-01-01t00:00:00z', '1970-01-01T00:00:00+00:00'):
            with self.subTest(raw=raw):
                result = parse_time(raw)
                self.assertEqual(result['time_low_us'], 0)
                self.assertEqual(result['time_raw'], raw)
        self.assertEqual(parse_time('1970-01-01T23:59:00+23:59')['time_low_us'], 0)

    def test_calendar_dates_leap_days_and_seconds_are_strict(self):
        valid = parse_time('2000-02-29T23:59:59.999999Z')
        self.assertEqual(format_time(valid['time_low_us']), '2000-02-29T23:59:59.999999Z')
        for raw in ('1900-02-29T00:00:00Z', '2026-02-29T00:00:00Z', '2026-04-31T00:00:00Z', '2026-00-01T00:00:00Z', '2026-01-01T24:00:00Z', '2026-01-01T00:60:00Z', '2016-12-31T23:59:60Z'):
            with self.subTest(raw=raw), self.assertRaises(TimeError):
                parse_time(raw)

    def test_missing_timezone_and_unknown_offset_are_not_assumed_utc(self):
        for raw in ('2026-01-01', '2026-01-01T00:00:00', '2026-01-01T00:00:00 UTC'):
            with self.subTest(raw=raw), self.assertRaises(TimeError):
                parse_time(raw)
        with self.assertRaises(TimeError) as caught:
            parse_time('2026-01-01T00:00:00-00:00')
        self.assertEqual(caught.exception.code, 'timestamp_timezone_unknown')

    def test_format_and_type_variants_are_rejected(self):
        values = [None, 0, 1.0, True, '', ' 2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z\n', '2026-01-01 00:00:00Z', '2026-1-01T00:00:00Z', '2026-01-01T00:00:00,123Z', '2026-01-01T00:00:00.Z', '2026-01-01T00:00:00+24:00', '2026-01-01T00:00:00+00:60', '2026-01-01T00:00:00+0000', '２０２６-01-01T00:00:00Z', '2026-01-01T00:00:00\ud800Z']
        for value in values:
            with self.subTest(value=repr(value)), self.assertRaises(TimeError):
                parse_time(value)

    def test_bounds_account_for_offset_and_precision(self):
        self.assertEqual(parse_time('0001-01-01T00:00:00Z')['time_low_us'], MIN_TIME_US)
        self.assertEqual(parse_time('9999-12-31T23:59:59Z')['time_high_us'], MAX_TIME_US)
        self.assertEqual(format_time(MIN_TIME_US), '0001-01-01T00:00:00.000000Z')
        self.assertEqual(format_time(MAX_TIME_US), '9999-12-31T23:59:59.999999Z')
        for raw in ('0001-01-01T00:00:00+00:01', '9999-12-31T23:59:59-00:01', '0000-01-01T00:00:00Z'):
            with self.subTest(raw=raw), self.assertRaises(TimeError):
                parse_time(raw)

    def test_long_or_sensitive_error_input_is_never_echoed(self):
        for value in ('PRIVATE-MARKER-777', 'x' * 97):
            with self.assertRaises(TimeError) as caught:
                parse_time(value)
            self.assertNotIn(value, str(caught.exception))
            self.assertEqual(str(caught.exception), caught.exception.code)

    def test_format_none_rejects_noninteger_and_outside_calendar(self):
        self.assertIsNone(format_time(None))
        for value in (True, False, 1.0, '1', MIN_TIME_US - 1, MAX_TIME_US + 1, 2**63):
            with self.subTest(value=value), self.assertRaises(TimeError):
                format_time(value)

    def test_far_future_does_not_lose_microseconds_through_float(self):
        for raw in ('9000-02-03T04:05:06.123457Z', '9999-12-31T23:59:59.999998Z'):
            with self.subTest(raw=raw):
                self.assertEqual(format_time(parse_time(raw)['time_low_us']), raw)


if __name__ == '__main__':
    unittest.main()
