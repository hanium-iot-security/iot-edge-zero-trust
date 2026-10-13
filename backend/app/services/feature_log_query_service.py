"""FastAPI 계층에서 사용하는 feature log 조회 전용 도우미."""
from __future__ import annotations

from calendar import timegm
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.services.feature_read_snapshot import feature_read_snapshot


def list_feature_logs(
    db: Session,
    limit: int = 100,
    offset: int = 0,
    device_id: str | None = None,
    *,
    from_at: datetime | None = None,
    to_at: datetime | None = None,
    snapshot_max_id: int | None = None,
) -> dict[str, Any]:
    from_utc = _normalize_optional_utc(from_at, "from")
    to_utc = _normalize_optional_utc(to_at, "to")
    if from_utc is not None and to_utc is not None and from_utc > to_utc:
        raise ValueError("from must be before or equal to to")

    with feature_read_snapshot(db, "feature_logs", snapshot_max_id) as snapshot_max_id:
        filters: list[str] = ["id <= :snapshot_max_id"]
        params: dict[str, Any] = {"limit": limit, "offset": offset, "snapshot_max_id": snapshot_max_id}
        if device_id:
            filters.append("device_id = :device_id")
            params["device_id"] = device_id

        # Feature writers store whole-second UTC windows. Round query bounds inward
        # before SQLite comparison so fractional requests retain exact containment.
        if from_utc is not None:
            filters.append("CAST(strftime('%s', window_start) AS INTEGER) >= :from_epoch")
            params["from_epoch"] = timegm(from_utc.utctimetuple()) + (from_utc.microsecond > 0)
        if to_utc is not None:
            filters.append("CAST(strftime('%s', window_end) AS INTEGER) <= :to_epoch")
            params["to_epoch"] = timegm(to_utc.utctimetuple())

        where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
        total = db.execute(text(f"SELECT COUNT(*) FROM feature_logs {where_clause}"), params).scalar_one()
        rows = db.execute(
            text(
                f"""
                SELECT
                    id,
                    device_id,
                    window_start,
                    window_end,
                    publish_count,
                    avg_payload_size,
                    max_payload_size,
                    avg_message_interval,
                    min_message_interval,
                    topic_count,
                    abnormal_topic_count,
                    malformed_payload_count
                FROM feature_logs
                {where_clause}
                ORDER BY window_start DESC, id DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            params,
        ).mappings()

        return {"items": [dict(row) for row in rows], "total": total, "snapshot_max_id": snapshot_max_id}


def _normalize_optional_utc(value: datetime | None, field_name: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include timezone")
    try:
        return value.astimezone(timezone.utc)
    except OverflowError as exc:
        raise ValueError(f"{field_name} is outside the supported UTC range") from exc
