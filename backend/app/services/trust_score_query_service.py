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
    paginated_history = history[offset : offset + limit]

    return {
        "device_id": device_id,
        "current_score": int(device["trust_score"]),
        "current_status": device["status"],
        "items": paginated_history,
        "total": len(history),
    }
