from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.firewall_release_schema import (
    FirewallReleaseRequestCreate,
    FirewallReleaseRequestResponse,
)
from backend.app.schemas.firewall_rule_schema import FirewallRuleListResponse
from backend.app.security import RecoveryAdminContext, require_recovery_admin
from backend.app.services.firewall_release_request_service import (
    FirewallReleaseRequestDataError,
    FirewallReleaseRequestError,
    create_firewall_release_request,
)
from backend.app.services.firewall_rule_query_service import (
    FirewallRuleDataError,
    list_firewall_rules,
)


router = APIRouter(prefix="/firewall-rules", tags=["firewall-rules"])


@router.get("", response_model=FirewallRuleListResponse)
def get_firewall_rules(
    status: Literal["PENDING", "APPLIED", "FAILED", "REMOVED"] | None = None,
    device_id: str | None = None,
    source_ip: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return list_firewall_rules(
            db,
            status=status,
            device_id=device_id,
            source_ip=source_ip,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except FirewallRuleDataError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/{rule_id}/release-requests",
    response_model=FirewallReleaseRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
def post_firewall_release_request(
    rule_id: int,
    payload: FirewallReleaseRequestCreate,
    db: Session = Depends(get_db),
    admin: RecoveryAdminContext = Depends(require_recovery_admin),
) -> dict:
    try:
        return create_firewall_release_request(
            db,
            rule_id=rule_id,
            reason=payload.reason,
            confirm=payload.confirm,
            admin=admin,
        )
    except FirewallReleaseRequestError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    except FirewallReleaseRequestDataError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
