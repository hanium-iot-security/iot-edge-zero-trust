"""Dashboard summary query helpers used by FastAPI routers."""

from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.services.detection_event_query_service import list_detection_events


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

    recent_detections = list_detection_events(db, limit=5, offset=0)
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

    total_detection_events = recent_detections["total"]

    return {
        **status_counts,
        "total_detection_events": total_detection_events,
        "unapplied_detection_events": _scalar_count(
            db,
            "SELECT COUNT(*) FROM detection_events WHERE applied_to_score = :applied_to_score",
            {"applied_to_score": 0},
        ),
        "total_isolation_events": _scalar_count(db, "SELECT COUNT(*) FROM isolation_history"),
        "recent_events_count": min(total_detection_events, 10),
        "unknown_device_count": _scalar_count(
            db,
            "SELECT COUNT(*) FROM detection_events WHERE event_type = :event_type",
            {"event_type": "UNKNOWN_DEVICE"},
        ),
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "latest_detection_events": recent_detections["items"],
        "latest_isolation_events": _rows_to_dicts(latest_isolation_events),
    }
