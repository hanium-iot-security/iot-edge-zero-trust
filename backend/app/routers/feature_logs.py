from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.services.feature_log_query_service import list_feature_logs
from backend.app.services.feature_read_snapshot import SQLITE_MAX_ID

router = APIRouter(prefix="/feature-logs", tags=["feature-logs"])


@router.get("")
def get_feature_logs(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    snapshot_max_id: Annotated[int | None, Query(ge=0, le=SQLITE_MAX_ID)] = None,
    device_id: str | None = None,
    from_at: Annotated[datetime | None, Query(alias="from")] = None,
    to_at: Annotated[datetime | None, Query(alias="to")] = None,
    db: Session = Depends(get_db),
) -> dict:
    try:
        return list_feature_logs(
            db=db, limit=limit, offset=offset, device_id=device_id,
            from_at=from_at, to_at=to_at,
            snapshot_max_id=snapshot_max_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
