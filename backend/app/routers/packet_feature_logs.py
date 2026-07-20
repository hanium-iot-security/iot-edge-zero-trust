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


router = APIRouter(prefix="/packet-feature-logs", tags=["packet-feature-logs"])


@router.get("", response_model=PacketFeatureListResponse)
def get_packet_feature_logs(
    session_id: str | None = None,
    device_id: str | None = None,
    peer_ip: str | None = None,
    direction: Literal["INBOUND", "OUTBOUND"] | None = None,
    from_at: Annotated[datetime | None, Query(alias="from")] = None,
    to_at: Annotated[datetime | None, Query(alias="to")] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
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
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except PacketFeatureDataError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
