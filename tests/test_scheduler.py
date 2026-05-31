from datetime import UTC, datetime

from sentinel.scheduler import _seconds_until_next_midnight_utc


def test_seconds_until_next_midnight_utc():
    assert _seconds_until_next_midnight_utc(datetime(2026, 5, 31, 23, 59, 0, tzinfo=UTC)) == 60
