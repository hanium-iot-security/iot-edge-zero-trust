"""Trust Score query helpers used by FastAPI routers."""

from sqlalchemy import text
from sqlalchemy.orm import Session


def _rows_to_dicts(rows) -> list[dict]:
    return [dict(row) for row in rows]


def list_trust_score_summary(
    db: Session,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    params = {"limit": limit, "offset": offset}
    count = db.execute(text("SELECT COUNT(*) FROM devices")).scalar_one()
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

    return {"items": _rows_to_dicts(rows), "count": int(count)}


def list_trust_score_history(
    db: Session,
    device_id: str,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    device_exists = db.execute(
        text("SELECT COUNT(*) FROM devices WHERE device_id = :device_id"),
        {"device_id": device_id},
    ).scalar_one()
    if int(device_exists) == 0:
        return {"device_id": device_id, "items": [], "count": 0}

    params = {
        "device_id": device_id,
        "limit": limit,
        "offset": offset,
    }
    count = db.execute(
        text(
            """
            SELECT COUNT(*)
            FROM detection_events
            WHERE device_id = :device_id
              AND applied_to_score = 1
            """
        ),
        params,
    ).scalar_one()
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
            ORDER BY detected_at DESC, id DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).mappings().all()

    return {"device_id": device_id, "items": _rows_to_dicts(rows), "count": int(count)}
