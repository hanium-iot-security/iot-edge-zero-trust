"""FastAPI 계층에서 사용하는 MQTT log 조회 전용 도우미."""

from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


def list_mqtt_logs(
    db: Session,
    limit: int = 100,
    offset: int = 0,
    device_id: str | None = None,
    valid_only: bool = False,
) -> dict[str, Any]:
    filters: list[str] = []
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if device_id:
        filters.append("device_id = :device_id")
        params["device_id"] = device_id
    if valid_only:
        filters.append("is_json_valid = 1")
        filters.append("is_topic_valid = 1")

    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    total = db.execute(text(f"SELECT COUNT(*) FROM mqtt_logs {where_clause}"), params).scalar_one()
    rows = db.execute(
        text(
            f"""
            SELECT
                id,
                device_id,
                topic,
                payload,
                payload_size,
                received_at,
                is_json_valid,
                is_topic_valid,
                error_message
            FROM mqtt_logs
            {where_clause}
            ORDER BY id DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).mappings()

    return {"items": [dict(row) for row in rows], "total": total}
