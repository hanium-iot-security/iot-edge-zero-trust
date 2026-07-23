"""Trust Score query helpers used by FastAPI routers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.packet.pcap_naming import format_utc_iso


class TrustScoreDataError(RuntimeError):
    """Raised when stored Trust Score history rows violate the API contract."""


def _rows_to_dicts(rows) -> list[dict]:
    return [dict(row) for row in rows]


def list_trust_score_summary(
    db: Session,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    params = {"limit": limit, "offset": offset}
    total = db.execute(text("SELECT COUNT(*) FROM devices")).scalar_one()
    rows = db.execute(
        text(
            """
            SELECT
                device_id,
                status,
                trust_score,
                last_seen_at
            FROM devices
            ORDER BY trust_score ASC, device_id ASC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).mappings().all()

    return {"items": _rows_to_dicts(rows), "total": int(total)}


def list_trust_score_history(
    db: Session,
    device_id: str,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    device = db.execute(
        text(
            """
            SELECT trust_score, status
            FROM devices
            WHERE device_id = :device_id
            """
        ),
        {"device_id": device_id},
    ).mappings().one_or_none()
    if device is None:
        return {
            "device_id": device_id,
            "current_score": None,
            "current_status": None,
            "items": [],
            "total": 0,
        }

    if not _table_exists(db, "trust_score_history"):
        return _list_legacy_trust_score_history(
            db,
            device_id=device_id,
            current_score=int(device["trust_score"]),
            current_status=device["status"],
            limit=limit,
            offset=offset,
        )

    total = db.execute(
        text(
            """
            SELECT COUNT(*)
            FROM trust_score_history
            WHERE device_id = :device_id
            """
        ),
        {"device_id": device_id},
    ).scalar_one()
    if int(total) == 0 and _legacy_applied_event_count(db, device_id) > 0:
        return _list_legacy_trust_score_history(
            db,
            device_id=device_id,
            current_score=int(device["trust_score"]),
            current_status=device["status"],
            limit=limit,
            offset=offset,
        )
    rows = db.execute(
        text(
            """
            SELECT
                id,
                device_id,
                analysis_window_start,
                analysis_window_end,
                previous_score,
                calculated_delta,
                capped_delta,
                actual_delta,
                new_score,
                representative_event_ids_json,
                policy_version,
                created_at
            FROM trust_score_history
            WHERE device_id = :device_id
            ORDER BY analysis_window_end DESC, id DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        {"device_id": device_id, "limit": limit, "offset": offset},
    ).mappings().all()

    return {
        "device_id": device_id,
        "current_score": int(device["trust_score"]),
        "current_status": device["status"],
        "items": [_trust_history_item(dict(row)) for row in rows],
        "total": int(total),
    }


def _trust_history_item(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "device_id": row["device_id"],
        "analysis_window_start": _format_timestamp(
            row["analysis_window_start"],
            "analysis_window_start",
        ),
        "analysis_window_end": _format_timestamp(
            row["analysis_window_end"],
            "analysis_window_end",
        ),
        "previous_score": row["previous_score"],
        "calculated_delta": row["calculated_delta"],
        "capped_delta": row["capped_delta"],
        "actual_delta": row["actual_delta"],
        "new_score": row["new_score"],
        "representative_event_ids": _parse_representative_event_ids(
            row["representative_event_ids_json"]
        ),
        "policy_version": row["policy_version"],
        "created_at": _format_timestamp(row["created_at"], "created_at"),
    }


def _parse_representative_event_ids(value: str) -> list[int]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise TrustScoreDataError(
            "representative_event_ids_json must be valid JSON"
        ) from exc
    if not isinstance(parsed, list) or not all(isinstance(item, int) for item in parsed):
        raise TrustScoreDataError("representative_event_ids_json must be an integer array")
    return parsed


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
            raise TrustScoreDataError(f"{field_name} must be a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return format_utc_iso(parsed)


def _table_exists(db: Session, table_name: str) -> bool:
    row = db.execute(
        text(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table'
              AND name = :table_name
            """
        ),
        {"table_name": table_name},
    ).first()
    return row is not None


def _list_legacy_trust_score_history(
    db: Session,
    *,
    device_id: str,
    current_score: int,
    current_status: str,
    limit: int,
    offset: int,
) -> dict:
    rows = db.execute(
        text(
            """
            SELECT
                id AS event_id,
                event_type,
                detector_type,
                severity,
                score_delta,
                applied_to_score,
                detected_at,
                description
            FROM detection_events
            WHERE device_id = :device_id
              AND applied_to_score = 1
            ORDER BY detected_at ASC, id ASC
            """
        ),
        {"device_id": device_id},
    ).mappings().all()

    score = 100
    history: list[dict] = []
    for row in rows:
        item = dict(row)
        score_before = score
        score = max(0, score_before + int(item["score_delta"]))
        item["score_before"] = score_before
        item["score_after"] = score
        history.append(item)

    history.reverse()
    return {
        "device_id": device_id,
        "current_score": current_score,
        "current_status": current_status,
        "items": history[offset : offset + limit],
        "total": len(history),
    }


def _legacy_applied_event_count(db: Session, device_id: str) -> int:
    return int(
        db.execute(
            text(
                """
                SELECT COUNT(*)
                FROM detection_events
                WHERE device_id = :device_id
                  AND applied_to_score = 1
                """
            ),
            {"device_id": device_id},
        ).scalar_one()
    )
