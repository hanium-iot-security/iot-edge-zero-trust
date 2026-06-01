from datetime import datetime

from fastapi import APIRouter
from sqlalchemy import text

from backend.app.database import SessionLocal

router = APIRouter(tags=["health"])


@router.get("/health")
def health_check() -> dict[str, str | bool]:
    db_connected = False
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        db_connected = True
    except Exception:
        db_connected = False

    return {
        "status": "ok",
        "db_connected": db_connected,
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
