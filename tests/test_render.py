"""Display helpers for times and numbers (BSD 1: times shown in WIB)."""

from datetime import UTC, datetime, timedelta

from rajdoll.api.render import duration, num, wib


def test_wib_is_utc_plus_seven() -> None:
    moment = datetime(2026, 11, 4, 2, 12, 5, tzinfo=UTC)
    assert wib(moment) == "09:12"
    assert wib(moment, "%d-%m-%Y %H:%M:%S") == "04-11-2026 09:12:05"
    assert wib(None) == "—"


def test_duration() -> None:
    start = datetime(2026, 11, 4, 2, 0, tzinfo=UTC)
    assert duration(start, start + timedelta(seconds=42)) == "42 dtk"
    assert duration(start, start + timedelta(minutes=38, seconds=5)) == "38 mnt"
    assert duration(start, start + timedelta(hours=2, minutes=5)) == "2 j 5 mnt"
    assert duration(None) == "—"


def test_num_uses_indonesian_separators() -> None:
    assert num(10.0) == "10"
    assert num(2.5) == "2,5"
    assert num(18420) == "18.420"
    assert num(1234.5) == "1.234,5"
    assert num(None) == "—"
