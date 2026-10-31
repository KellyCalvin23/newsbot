"""Time helpers. Everything is stored in UTC and shown in the configured zone."""
from __future__ import annotations

from datetime import datetime, time, timezone
from zoneinfo import ZoneInfo


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def format_local(value: str | None, tz_name: str) -> str:
    dt = parse_iso(value)
    if dt is None:
        return "time unknown"
    return dt.astimezone(ZoneInfo(tz_name)).strftime("%d %b %H:%M %Z")


def in_quiet_hours(now: datetime, start: str, end: str, tz_name: str) -> bool:
    """True when `now` is inside [start, end); the window may cross midnight."""
    local = now.astimezone(ZoneInfo(tz_name)).time()
    begin = time.fromisoformat(start)
    finish = time.fromisoformat(end)
    if begin == finish:
        return False
    if begin < finish:
        return begin <= local < finish
    return local >= begin or local < finish
