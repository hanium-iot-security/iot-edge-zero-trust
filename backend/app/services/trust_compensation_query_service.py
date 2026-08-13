"""Trust Score compensation query helpers for FastAPI."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.packet.pcap_naming import format_utc_iso


class TrustCompensationDataError(RuntimeError):
    """Raised when stored compensation rows violate the API contract."""


def list_trust_compensations(
    db: Session,
    *,
    device_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    params = {"device_id": device_id, "limit": limit, "offset": offset}
    where_sql = "WHERE (:device_id IS NULL OR device_id = :device_id)"
    total = db.execute(
        text(
            f"""
            SELECT COUNT(*)
            FROM trust_score_compensations
            {where_sql}
            """
        ),
        params,
    ).scalar_one()
    rows = db.execute(
        text(
            f"""
            SELECT
                id,
                operation_id,
                device_id,
                source_event_id,
                source_trust_history_id,
                previous_score,
                compensation_delta,
                new_score,
                reason,
                approved_by,
                backup_path,
                backup_sha256,
                created_at
            FROM trust_score_compensations
            {where_sql}
            ORDER BY created_at DESC, id DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).mappings().all()
    return {
        "items": [_item(dict(row)) for row in rows],
        "total": int(total),
    }


def _item(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "operation_id": row["operation_id"],
        "device_id": row["device_id"],
        "source_event_id": int(row["source_event_id"]),
        "source_trust_history_id": int(row["source_trust_history_id"]),
        "previous_score": int(row["previous_score"]),
        "compensation_delta": int(row["compensation_delta"]),
        "new_score": int(row["new_score"]),
        "reason": row["reason"],
        "approved_by": row["approved_by"],
        "backup_reference": Path(str(row["backup_path"])).name,
        "backup_sha256": row["backup_sha256"],
        "created_at": _format_timestamp(row["created_at"], "created_at"),
    }


def _format_timestamp(value: Any, field_name: str) -> str:
    if isinstance(value, datetime):
        parsed = value
    else:
        text_value = str(value)
        text_value = text_value[:-1] + "+00:00" if text_value.endswith("Z") else text_value
        text_value = text_value.replace(" ", "T")
        try:
            parsed = datetime.fromisoformat(text_value)
        except ValueError as exc:
            raise TrustCompensationDataError(
                f"{field_name} must be a valid timestamp"
            ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return format_utc_iso(parsed)
