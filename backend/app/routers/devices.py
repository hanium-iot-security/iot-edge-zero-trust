from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BeforeValidator
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.device_ai_policy_schema import AiPolicyRevisionRequest, AiPolicySnapshotResponse
from backend.app.schemas.device_schema import DeviceItem, DeviceListResponse
from backend.app.schemas.device_management_schema import (
    DeviceManagementRequest, DeviceManagementState, DeviceManagementResponse,
)
from backend.app.services.device_management_service import get_device_management, manage_device
from backend.app.schemas.device_policy_schema import (
    DeviceRegistrationRequest,
    DeviceRegistrationResponse,
    PolicyRevisionRequest,
    PolicySnapshotResponse,
)
from backend.app.security import RecoveryAdminContext, require_recovery_admin
from backend.app.services.device_ai_policy_service import get_device_ai_policy, revise_device_ai_policy
from backend.app.services.device_policy_service import (
    DevicePolicyConfigError, create_device, get_device_policy, revise_device_policy,
)
from backend.app.services.device_query_service import get_device, list_devices
from edge.policy.device_policy import (
    DeviceNotFoundError, DevicePolicyError, DevicePolicyValidationError, PolicyUnavailableError,
    validate_device_id,
)


DeviceIdPath = Annotated[str, Path(), BeforeValidator(validate_device_id)]


class DevicePolicyRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def management_handler(request):
            try:
                return await handler(request)
            except RequestValidationError as exc:
                # Keep the standard 422 array without echoing passwords/keys
                # from unsupported fields, or non-JSON NaN/Infinity inputs.
                return JSONResponse(status_code=422, content={"detail": [
                    {key: item[key] for key in ("type", "loc", "msg")}
                    for item in exc.errors()
                ]})
            except DevicePolicyValidationError as exc:
                return JSONResponse(status_code=422, content={"detail": [{
                    "type": "value_error", "loc": ["body", exc.field or "policy"],
                    "msg": str(exc),
                }]})
            except DevicePolicyError as exc:
                status_code = (404 if isinstance(exc, DeviceNotFoundError) else
                               503 if isinstance(exc, (PolicyUnavailableError, DevicePolicyConfigError))
                               else 409)
                detail = exc.to_detail()
                if exc.code in ("REVISION_CONFLICT", "PENDING_REVISION_EXISTS"):
                    detail["latest_revision"] = max(
                        (value for value in (detail["current_revision"], detail["pending_revision"])
                         if value is not None), default=None,
                    )
                raise HTTPException(status_code=status_code, detail=detail) from exc

        return management_handler


router = APIRouter(prefix="/devices", tags=["devices"], route_class=DevicePolicyRoute)


@router.post("", response_model=DeviceRegistrationResponse, status_code=201)
def register_device_command(
    request: DeviceRegistrationRequest,
    admin: RecoveryAdminContext = Depends(require_recovery_admin),
    db: Session = Depends(get_db),
) -> dict:
    return create_device(db, request, admin)


@router.get("/{device_id}/policy", response_model=PolicySnapshotResponse)
def get_device_policy_detail(device_id: DeviceIdPath, db: Session = Depends(get_db)) -> dict:
    return get_device_policy(db, device_id)


@router.post("/{device_id}/policy-revisions", response_model=PolicySnapshotResponse, status_code=201)
def revise_device_policy_command(
    device_id: DeviceIdPath,
    request: PolicyRevisionRequest,
    admin: RecoveryAdminContext = Depends(require_recovery_admin),
    db: Session = Depends(get_db),
) -> dict:
    return revise_device_policy(db, device_id, request, admin)


@router.get("/{device_id}/ai-policy", response_model=AiPolicySnapshotResponse)
def get_device_ai_policy_detail(device_id: DeviceIdPath, db: Session = Depends(get_db)) -> dict:
    return get_device_ai_policy(db, device_id)


@router.post("/{device_id}/ai-policy-revisions", response_model=AiPolicySnapshotResponse, status_code=201)
def revise_device_ai_policy_command(
    device_id: DeviceIdPath,
    request: AiPolicyRevisionRequest,
    admin: RecoveryAdminContext = Depends(require_recovery_admin),
    db: Session = Depends(get_db),
) -> dict:
    return revise_device_ai_policy(db, device_id, request, admin)


@router.get("", response_model=DeviceListResponse)
def get_devices(
    status: Literal["normal", "warning", "danger", "isolated"] | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    include_hidden: bool = False,
    db: Session = Depends(get_db),
) -> dict:
    return list_devices(db, status=status, limit=limit, offset=offset, include_hidden=include_hidden)


@router.get("/{device_id}/management", response_model=DeviceManagementState)
def get_management(device_id: DeviceIdPath, db: Session = Depends(get_db)) -> dict:
    return get_device_management(db, device_id)


@router.post("/{device_id}/management", response_model=DeviceManagementResponse)
def management_command(
    device_id: DeviceIdPath,
    request: DeviceManagementRequest,
    admin: RecoveryAdminContext = Depends(require_recovery_admin),
    db: Session = Depends(get_db),
) -> dict:
    return manage_device(db, device_id, request, admin)


@router.get("/{device_id}", response_model=DeviceItem)
def get_device_detail(
    device_id: str,
    db: Session = Depends(get_db),
) -> dict:
    device = get_device(db, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device
