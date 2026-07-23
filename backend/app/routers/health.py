from fastapi import APIRouter
from sqlalchemy import text

from backend.app.database import SessionLocal

router = APIRouter(tags=["health"])


@router.get("/health")
def health_check() -> dict[str, str]:
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
    except Exception:
        return {
            "status": "degraded",
            "database": "error",
        }

    return {
        "status": "ok",
        "database": "ok",
    }
