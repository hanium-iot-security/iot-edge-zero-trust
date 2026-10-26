"""Exact raw MQTT timestamp parsing; timezone-less historical rows are unknown."""
from datetime import datetime, timezone
import re

_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def mqtt_received_microseconds(value):
    if not isinstance(value, str) or not _PATTERN.fullmatch(value):
        return None
    if not value.endswith("Z"):
        zone = value[-6:]
        if int(zone[1:3]) > 23 or int(zone[4:6]) > 59:
            return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        return datetime_microseconds(parsed)
    except (ValueError, OverflowError):
        return None


def datetime_microseconds(value):
    delta = value - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def optional_utc(value, name):
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include timezone")
    try:
        return value.astimezone(timezone.utc)
    except OverflowError as exc:
        raise ValueError(f"{name} is outside the supported UTC range") from exc
