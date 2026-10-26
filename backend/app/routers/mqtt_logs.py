from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.services.feature_read_snapshot import SQLITE_MAX_ID
from backend.app.services.mqtt_log_query_service import MAX_MQTT_OFFSET, list_mqtt_logs

router = APIRouter(prefix="/mqtt-logs", tags=["mqtt-logs"])


@router.get("")
def get_mqtt_logs(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=MAX_MQTT_OFFSET)] = 0,
    device_id: str | None = None,
    valid_only: bool = False,
    from_at: Annotated[datetime | None, Query(alias="from")] = None,
    to_at: Annotated[datetime | None, Query(alias="to")] = None,
    snapshot_max_id: Annotated[int | None, Query(ge=0, le=SQLITE_MAX_ID)] = None,
    db: Session = Depends(get_db),
) -> dict:
    try:
        return list_mqtt_logs(
            db=db, limit=limit, offset=offset, device_id=device_id, valid_only=valid_only,
            from_at=from_at, to_at=to_at, snapshot_max_id=snapshot_max_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc