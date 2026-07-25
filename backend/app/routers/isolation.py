from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.isolation_schema import IsolationHistoryListResponse
from backend.app.services.isolation_query_service import (
    IsolationHistoryDataError,
    list_isolation_history,
)


router = APIRouter(prefix="/isolation", tags=["isolation"])


@router.get("/history", response_model=IsolationHistoryListResponse)
def isolation_history(
    device_id: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return list_isolation_history(db, device_id=device_id, limit=limit, offset=offset)
    except IsolationHistoryDataError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
