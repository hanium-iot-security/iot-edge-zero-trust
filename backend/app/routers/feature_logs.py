from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.services.feature_log_query_service import list_feature_logs

router = APIRouter(prefix="/feature-logs", tags=["feature-logs"])


@router.get("")
def get_feature_logs(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    device_id: str | None = None,
    db: Session = Depends(get_db),
) -> dict:
    return list_feature_logs(db=db, limit=limit, offset=offset, device_id=device_id)
