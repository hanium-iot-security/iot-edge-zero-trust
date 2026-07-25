"""Isolation history query helpers used by FastAPI routers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.packet.pcap_naming import format_utc_iso


class IsolationHistoryDataError(RuntimeError):
    """Raised when stored isolation history rows violate the API contract."""


def _rows_to_dicts(rows) -> list[dict]:
    return [_isolation_item(dict(row)) for row in rows]


def list_isolation_history(
    db: Session,
    device_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    params: dict[str, str | int | None] = {
        "device_id": device_id,
        "limit": limit,
        "offset": offset,
    }
    columns = _column_names(db, "isolation_history")
    trust_history_column = (
        "trust_score_history_id"
        if "trust_score_history_id" in columns
        else "NULL AS trust_score_history_id"
    )

    total = db.execute(
        text(
            """
            SELECT COUNT(*)
            FROM isolation_history
            WHERE (:device_id IS NULL OR device_id = :device_id)
            """
        ),
        params,
    ).scalar_one()
    rows = db.execute(
        text(
            f"""
            SELECT
                id,
                device_id,
                action,
                reason,
                trust_score,
                trigger_event_id,
                {trust_history_column},
                created_at
            FROM isolation_history
            WHERE (:device_id IS NULL OR device_id = :device_id)
            ORDER BY created_at DESC, id DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).mappings().all()

    return {"items": _rows_to_dicts(rows), "total": int(total)}


def _column_names(db: Session, table_name: str) -> set[str]:
    rows = db.execute(text(f"PRAGMA table_info({table_name})")).mappings().all()
    return {str(row["name"]) for row in rows}


def _isolation_item(row: dict[str, Any]) -> dict[str, Any]:
    row["created_at"] = _format_optional_timestamp(row["created_at"], "created_at")
    return row


def _format_optional_timestamp(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text_value = str(value)
        text_value = text_value[:-1] + "+00:00" if text_value.endswith("Z") else text_value
        text_value = text_value.replace(" ", "T")
        try:
            parsed = datetime.fromisoformat(text_value)
        except ValueError as exc:
            raise IsolationHistoryDataError(
                f"{field_name} must be a valid timestamp"
            ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return format_utc_iso(parsed)
