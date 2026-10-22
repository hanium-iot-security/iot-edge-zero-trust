from datetime import datetime
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.ai_runtime_schema import AiWarningListResponse, RuntimeStatusResponse
from backend.app.services.ai_runtime_query_service import get_ai_warnings, get_runtime_status
from edge.detection.ai_runtime_repository import RuntimeEvidenceUnavailable
from edge.policy.device_policy import DevicePolicyError


router = APIRouter(tags=["ai-runtime"])
DeviceFilter = Annotated[str | None, Query(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")]
UNAVAILABLE_ERRORS = (RuntimeEvidenceUnavailable, DevicePolicyError, sqlite3.DatabaseError, SQLAlchemyError)


@router.get("/runtime-status", response_model=RuntimeStatusResponse)
def runtime_status(device_id: DeviceFilter = None, db: Session = Depends(get_db)) -> dict:
    try:
        return get_runtime_status(db, device_id=device_id)
    except UNAVAILABLE_ERRORS as exc:
        raise HTTPException(status_code=503, detail={"code": "RUNTIME_EVIDENCE_UNAVAILABLE"}) from exc


@router.get("/ai-warnings", response_model=AiWarningListResponse)
def ai_warnings(
    device_id: DeviceFilter = None,
    from_at: Annotated[datetime | None, Query(alias="from")] = None,
    to_at: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    db: Session = Depends(get_db),
) -> dict:
    try:
        return get_ai_warnings(db, device_id=device_id, from_at=from_at, to_at=to_at,
                               limit=limit, offset=offset)
    except UNAVAILABLE_ERRORS as exc:
        raise HTTPException(status_code=503, detail={"code": "AI_WARNING_DATA_UNAVAILABLE"}) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
