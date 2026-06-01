import json
from typing import Any


def payload_size(payload: str | bytes) -> int:
    if isinstance(payload, bytes):
        return len(payload)
    return len(payload.encode("utf-8"))


def parse_payload_json(payload: str | bytes) -> Any | None:
    try:
        return json.loads(payload.decode("utf-8") if isinstance(payload, bytes) else payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def is_malformed_json(payload: str | bytes) -> bool:
    return parse_payload_json(payload) is None


def is_malformed_payload(payload: str | bytes) -> bool:
    parsed = parse_payload_json(payload)
    if not isinstance(parsed, dict):
        return True

    device_id = parsed.get("device_id")
    return not isinstance(device_id, str) or not device_id.strip()
