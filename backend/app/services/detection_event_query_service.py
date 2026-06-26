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
    severity: str | None = None,
    applied_to_score: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    params: dict[str, str | int | None] = {
        "device_id": device_id,
        "event_type": event_type,
        "detector_type": detector_type,
        "severity": severity,
        "applied_to_score": applied_to_score,
        "limit": limit,
        "offset": offset,
    }

    total = db.execute(
        text(
            """
            SELECT COUNT(*)
            FROM detection_events
            WHERE (:device_id IS NULL OR device_id = :device_id)
              AND (:event_type IS NULL OR event_type = :event_type)
              AND (:detector_type IS NULL OR detector_type = :detector_type)
              AND (:severity IS NULL OR severity = :severity)
              AND (
                  :applied_to_score IS NULL
                  OR applied_to_score = :applied_to_score
              )
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
            WHERE (:device_id IS NULL OR device_id = :device_id)
              AND (:event_type IS NULL OR event_type = :event_type)
              AND (:detector_type IS NULL OR detector_type = :detector_type)
              AND (:severity IS NULL OR severity = :severity)
              AND (
                  :applied_to_score IS NULL
                  OR applied_to_score = :applied_to_score
              )
            ORDER BY detected_at DESC, id DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).mappings().all()

    return {"items": _rows_to_dicts(rows), "total": int(total)}
