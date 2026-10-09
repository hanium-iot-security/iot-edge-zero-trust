from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.firewall_release_schema import (
    FirewallReleaseRequestCreate,
    FirewallReleaseRequestResponse,
)
from backend.app.schemas.firewall_rule_schema import (
    FirewallRuleListResponse, FirewallScopeExtensionCreate, FirewallScopeExtensionResponse,
)
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
from backend.app.services.firewall_scope_extension_service import (
    FirewallScopeExtensionError, create_firewall_scope_extension,
)
from edge.policy.device_policy import DevicePolicyError


class FirewallManagementRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def management_handler(request):
            try:
                return await handler(request)
            except RequestValidationError as error:
                return JSONResponse(status_code=422, content={"detail": [
                    {key: item[key] for key in ("type", "loc", "msg")} for item in error.errors()
                ]})
            except DevicePolicyError:
                return JSONResponse(status_code=422, content={"detail": "INVALID_SCOPE_EXTENSION_REQUEST"})

        return management_handler


router = APIRouter(prefix="/firewall-rules", tags=["firewall-rules"], route_class=FirewallManagementRoute)


@router.post("/{source_rule_id}/scope-extension-requests", response_model=FirewallScopeExtensionResponse,
             status_code=status.HTTP_201_CREATED)
def post_scope_extension(payload: FirewallScopeExtensionCreate, source_rule_id: int = Path(ge=1, le=9223372036854775807),
                         db: Session = Depends(get_db), admin: RecoveryAdminContext = Depends(require_recovery_admin)):
    try:
        return create_firewall_scope_extension(db, source_rule_id=source_rule_id,
                                               admin=admin, **payload.model_dump())
    except FirewallScopeExtensionError as error:
        raise HTTPException(status_code=error.status_code, detail=error.detail) from None


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
