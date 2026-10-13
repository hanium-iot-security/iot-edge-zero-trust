from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.packet_feature_schema import PacketFeatureListResponse
from backend.app.services.packet_feature_query_service import (
    PacketFeatureDataError,
    list_packet_features,
)
from backend.app.services.feature_read_snapshot import SQLITE_MAX_ID


router = APIRouter(prefix="/packet-feature-logs", tags=["packet-feature-logs"])


@router.get("", response_model=PacketFeatureListResponse)
def get_packet_feature_logs(
    session_id: str | None = None,
    device_id: str | None = None,
    peer_ip: str | None = None,
    direction: Literal["INBOUND", "OUTBOUND"] | None = None,
    capture_eligible: bool | None = None,
    from_at: Annotated[datetime | None, Query(alias="from")] = None,
    to_at: Annotated[datetime | None, Query(alias="to")] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    snapshot_max_id: Annotated[int | None, Query(ge=0, le=SQLITE_MAX_ID)] = None,
    db: Session = Depends(get_db),
) -> dict:
    if capture_eligible is not None:
        raise HTTPException(
            status_code=422,
            detail="capture_eligible filtering is not supported by this endpoint",
        )
    try:
        return list_packet_features(
            db,
            session_id=session_id,
            device_id=device_id,
            peer_ip=peer_ip,
            direction=direction,
            from_at=from_at,
            to_at=to_at,
            limit=limit,
            offset=offset,
            snapshot_max_id=snapshot_max_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except PacketFeatureDataError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
