"""FastAPI 계층에서 사용하는 feature log 조회 전용 도우미."""
from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


def list_feature_logs(
    db: Session,
    limit: int = 100,
    offset: int = 0,
    device_id: str | None = None,
) -> dict[str, Any]:
    filters: list[str] = []
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if device_id:
        filters.append("device_id = :device_id")
        params["device_id"] = device_id

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

    return {"items": [dict(row) for row in rows], "total": total}
