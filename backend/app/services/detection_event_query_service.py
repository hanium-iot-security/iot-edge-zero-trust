"""Detection event query helpers used by FastAPI routers."""

from sqlalchemy import text
from sqlalchemy.orm import Session


def _rows_to_dicts(rows) -> list[dict]:
    return [dict(row) for row in rows]


def list_detection_events(
    db: Session,
    device_id: str | None = None,
    event_type: str | None = None,
    detector_type: str | None = None,
    applied_to_score: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    where_clauses: list[str] = []
    params: dict[str, str | int] = {
        "limit": limit,
        "offset": offset,
    }

    if device_id is not None:
        where_clauses.append("device_id = :device_id")
        params["device_id"] = device_id
    if event_type is not None:
        where_clauses.append("event_type = :event_type")
        params["event_type"] = event_type
    if detector_type is not None:
        where_clauses.append("detector_type = :detector_type")
        params["detector_type"] = detector_type
    if applied_to_score is not None:
        where_clauses.append("applied_to_score = :applied_to_score")
        params["applied_to_score"] = applied_to_score

    where_sql = f" WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    count = db.execute(
        text(f"SELECT COUNT(*) FROM detection_events{where_sql}"),
        params,
    ).scalar_one()
    rows = db.execute(
        text(
            f"""
            SELECT
                id,
                device_id,
                feature_log_id,
                mqtt_log_id,
                detector_type,
                event_type,
                severity,
                score_delta,
                applied_to_score,
                description,
                detected_at
            FROM detection_events
            {where_sql}
            ORDER BY detected_at DESC, id DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).mappings().all()

    return {"items": _rows_to_dicts(rows), "count": int(count)}
