import json


def payload_size(payload: str | bytes) -> int:
    if isinstance(payload, bytes):
        return len(payload)
    return len(payload.encode("utf-8"))


def is_malformed_json(payload: str | bytes) -> bool:
    try:
        json.loads(payload.decode("utf-8") if isinstance(payload, bytes) else payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return True
    return False
