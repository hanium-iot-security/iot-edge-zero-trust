from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.detection_event_schema import DetectionEventListResponse
from backend.app.services.detection_event_query_service import (
    DetectionEventDataError,
    list_detection_events,
)


router = APIRouter(prefix="/detection-events", tags=["detection-events"])


@router.get("", response_model=DetectionEventListResponse)
def get_detection_events(
    device_id: str | None = None,
    event_type: str | None = None,
    detector_type: Literal["RULE", "AI"] | None = None,
    severity: Literal["low", "medium", "high"] | None = None,
    applied_to_score: int | None = Query(None, ge=0, le=1),
    incident_family: str | None = None,
    subject_ip: str | None = None,
    processing_reason: str | None = None,
    window_start_from: datetime | None = None,
    window_end_to: datetime | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return list_detection_events(
            db,
            device_id=device_id,
            event_type=event_type,
            detector_type=detector_type,
            severity=severity,
            applied_to_score=applied_to_score,
            incident_family=incident_family,
            subject_ip=subject_ip,
            processing_reason=processing_reason,
            window_start_from=window_start_from,
            window_end_to=window_end_to,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except DetectionEventDataError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
