"""UTC time helpers for Phase 4 detection runtime."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from edge.packet.pcap_naming import format_utc_iso


WINDOW_SECONDS = 10


def require_utc_whole_second(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use UTC offset")
    if value.microsecond != 0:
        raise ValueError(f"{field_name} must use whole-second precision")
    return value.astimezone(timezone.utc)


def require_utc_window_boundary(value: datetime, field_name: str) -> datetime:
    normalized = require_utc_whole_second(value, field_name)
    if normalized.second % WINDOW_SECONDS != 0:
        raise ValueError(f"{field_name} must align to a 10 second boundary")
    return normalized


def parse_db_utc(
    value: Any, field_name: str = "timestamp", *, allow_subseconds: bool = False
) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        else:
            text = text.replace(" ", "T")
        parsed = datetime.fromisoformat(text)

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    if parsed.microsecond != 0 and not allow_subseconds:
        raise ValueError(f"{field_name} must use whole-second precision")
    return parsed


def format_db_utc(value: datetime) -> str:
    return format_utc_iso(require_utc_whole_second(value, "value"))


def floor_window_start(value: datetime) -> datetime:
    normalized = require_utc_whole_second(value, "value")
    return normalized.replace(second=(normalized.second // WINDOW_SECONDS) * WINDOW_SECONDS)


def window_end_for(value: datetime) -> datetime:
    return floor_window_start(value) + timedelta(seconds=WINDOW_SECONDS)
