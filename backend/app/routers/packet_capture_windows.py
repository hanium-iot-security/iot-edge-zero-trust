"""Read one bounded capture interval without manufacturing Feature rows."""

from datetime import datetime
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import UUID4
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.services.packet_capture_query_service import (
    CaptureMetadataUnavailable, CaptureSessionNotFound, list_capture_windows,
)
from edge.policy.device_policy import DevicePolicyError


router = APIRouter(prefix="/packet-capture-windows", tags=["packet-feature-logs"])


@router.get("")
def get_packet_capture_windows(
    session_id: UUID4,
    from_at: Annotated[datetime, Query(alias="from")],
    to_at: Annotated[datetime, Query(alias="to")],
    db: Session = Depends(get_db),
) -> dict:
    try:
        return list_capture_windows(db, session_id=str(session_id), from_at=from_at, to_at=to_at)
    except CaptureSessionNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (sqlite3.Error, DevicePolicyError, CaptureMetadataUnavailable) as exc:
        raise HTTPException(status_code=503, detail={"code": "PACKET_CAPTURE_DATA_UNAVAILABLE"}) from exc
