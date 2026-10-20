"""Shared CLI parsers for sizes, durations, and local times."""

from datetime import datetime
import unittest
from zoneinfo import ZoneInfo

from taema.cli.framework import _parser
from taema.cli.inputs import parse_duration, parse_size, parse_time


class HumanInputs(unittest.TestCase):
    def test_size_uses_binary_units_and_rounds_up_partial_bytes(self):
        self.assertEqual(parse_size("512M"), 512 * 1024**2)
        self.assertEqual(parse_size("1.5G"), 1536 * 1024**2)
        self.assertEqual(parse_size("2KiB"), 2048)
        self.assertEqual(parse_size("1.1B"), 2)
        self.assertEqual(parse_size(32), 32)

    def test_size_rejects_unknown_and_negative_units(self):
        for value in ("2Q", "-1M", "", float("inf"), -1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_size(value)

    def test_duration_accepts_seconds_and_compound_units(self):
        self.assertEqual(parse_duration("90s"), 90)
        self.assertEqual(parse_duration("2h30m"), 9000)
        self.assertEqual(parse_duration("7d"), 7 * 86400)
        self.assertEqual(parse_duration("250ms"), 0.25)
        self.assertEqual(parse_duration("1.5"), 1.5)

    def test_duration_rejects_malformed_and_negative_values(self):
        for value in ("", "2hours", "1h nope", "-3s", float("nan"), -1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_duration(value)

    def test_kill_timeout_uses_the_shared_duration_parser(self):
        args = _parser(selected="kill", include_all=False).parse_args(
            ["kill", "--timeout", "2h30m", "scope-demo"]
        )
        self.assertEqual(args.timeout, 9000)

    def test_time_understands_yesterday_and_the_most_recent_clock_time(self):
        zone = ZoneInfo("Asia/Kolkata")
        now = datetime(2026, 10, 20, 12, 15, tzinfo=zone)
        self.assertEqual(
            parse_time("yesterday", now), datetime(2026, 10, 19, 0, 0, tzinfo=zone)
        )
        self.assertEqual(
            parse_time("09:00", now), datetime(2026, 10, 20, 9, 0, tzinfo=zone)
        )
        early = datetime(2026, 10, 20, 8, 0, tzinfo=zone)
        self.assertEqual(
            parse_time("09:00", early), datetime(2026, 10, 19, 9, 0, tzinfo=zone)
        )
        self.assertEqual(
            parse_time("2026-10-18", now),
            datetime(2026, 10, 18, 0, 0, tzinfo=zone),
        )

    def test_time_rejects_invalid_values_and_keeps_explicit_offsets(self):
        for value in ("", "tomorrow", "25:99"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_time(value)
        parsed = parse_time("2026-10-20T09:00:00+00:00")
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)


if __name__ == "__main__":
    unittest.main()
