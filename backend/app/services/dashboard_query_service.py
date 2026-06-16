"""Dashboard summary query helpers used by FastAPI routers."""

from sqlalchemy import text
from sqlalchemy.orm import Session


def _scalar_count(db: Session, query: str, params: dict | None = None) -> int:
    return int(db.execute(text(query), params or {}).scalar_one())


def _rows_to_dicts(rows) -> list[dict]:
    return [dict(row) for row in rows]


def get_dashboard_summary(db: Session) -> dict:
    status_counts = {
        "total_devices": _scalar_count(db, "SELECT COUNT(*) FROM devices"),
        "normal_devices": _scalar_count(
            db,
            "SELECT COUNT(*) FROM devices WHERE status = :status",
            {"status": "normal"},
        ),
        "warning_devices": _scalar_count(
            db,
            "SELECT COUNT(*) FROM devices WHERE status = :status",
            {"status": "warning"},
        ),
        "danger_devices": _scalar_count(
            db,
            "SELECT COUNT(*) FROM devices WHERE status = :status",
            {"status": "danger"},
        ),
        "isolated_devices": _scalar_count(
            db,
            "SELECT COUNT(*) FROM devices WHERE status = :status",
            {"status": "isolated"},
        ),
    }

    latest_detection_events = db.execute(
        text(
            """
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
            ORDER BY detected_at DESC, id DESC
            LIMIT 5
            """
        )
    ).mappings().all()
    latest_isolation_events = db.execute(
        text(
            """
            SELECT
                id,
                device_id,
                action,
                reason,
                trust_score,
                trigger_event_id,
                created_at
            FROM isolation_history
            ORDER BY created_at DESC, id DESC
            LIMIT 5
            """
        )
    ).mappings().all()

    return {
        **status_counts,
        "total_detection_events": _scalar_count(db, "SELECT COUNT(*) FROM detection_events"),
        "unapplied_detection_events": _scalar_count(
            db,
            "SELECT COUNT(*) FROM detection_events WHERE applied_to_score = :applied_to_score",
            {"applied_to_score": 0},
        ),
        "total_isolation_events": _scalar_count(db, "SELECT COUNT(*) FROM isolation_history"),
        "latest_detection_events": _rows_to_dicts(latest_detection_events),
        "latest_isolation_events": _rows_to_dicts(latest_isolation_events),
    }
