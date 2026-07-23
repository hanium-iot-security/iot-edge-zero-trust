from datetime import datetime, timezone

from fastapi import APIRouter
from sqlalchemy import text

from backend.app.database import SessionLocal
from edge.packet.pcap_naming import format_utc_iso

router = APIRouter(tags=["health"])


@router.get("/health")
def health_check() -> dict[str, object]:
    server_time = format_utc_iso(datetime.now(timezone.utc))
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
    except Exception:
        return {
            "status": "degraded",
            "database": "error",
            "db_connected": False,
            "server_time": server_time,
        }

    return {
        "status": "ok",
        "database": "ok",
        "db_connected": True,
        "server_time": server_time,
    }
