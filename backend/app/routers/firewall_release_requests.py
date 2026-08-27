from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.firewall_release_schema import FirewallReleaseRequestResponse
from backend.app.security import RecoveryAdminContext, require_recovery_admin
from backend.app.services.firewall_release_request_service import (
    FirewallReleaseRequestDataError,
    FirewallReleaseRequestError,
    get_firewall_release_request,
)


router = APIRouter(
    prefix="/firewall-release-requests",
    tags=["firewall-release-requests"],
)


@router.get("/{request_id}", response_model=FirewallReleaseRequestResponse)
def get_release_request(
    request_id: int,
    db: Session = Depends(get_db),
    _admin: RecoveryAdminContext = Depends(require_recovery_admin),
) -> dict:
    try:
        return get_firewall_release_request(db, request_id=request_id)
    except FirewallReleaseRequestError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    except FirewallReleaseRequestDataError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
