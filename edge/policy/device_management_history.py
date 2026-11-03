"""Supplement SQL history checks with Python's accepted JSON constants.

SQLite's JSON view handles standard JSON. Ingestion also accepts NaN and
Infinity through json.loads; inspect only the rare payloads SQLite rejects.
Callers keep this check inside their existing snapshot or write transaction.
"""
import json
import sqlite3


class _ObjectPairs(list):
    """Retain duplicate object keys without mistaking JSON arrays for objects."""


def has_non_sqlite_json_device_history(connection: sqlite3.Connection, device_id: str) -> bool:
    for (payload,) in connection.execute("SELECT payload FROM mqtt_logs WHERE NOT json_valid(payload)"):
        try:
            parsed = json.loads(
                payload.decode("utf-8") if isinstance(payload, bytes) else payload,
                object_pairs_hook=_ObjectPairs,
            )
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            continue
        if isinstance(parsed, _ObjectPairs) and any(
            key == "device_id" and isinstance(value, str) and value.strip() == device_id
            for key, value in parsed
        ):
            return True
    return False
