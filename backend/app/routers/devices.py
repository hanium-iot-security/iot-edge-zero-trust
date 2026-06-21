from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.device_schema import DeviceItem, DeviceListResponse
from backend.app.services.device_query_service import get_device, list_devices


router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("", response_model=DeviceListResponse)
def get_devices(
    status: Literal["normal", "warning", "danger", "isolated"] | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    return list_devices(db, status=status, limit=limit, offset=offset)


@router.get("/{device_id}", response_model=DeviceItem)
def get_device_detail(
    device_id: str,
    db: Session = Depends(get_db),
) -> dict:
    device = get_device(db, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device
