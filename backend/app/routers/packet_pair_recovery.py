from fastapi import APIRouter, Depends, HTTPException

from backend.app.schemas.packet_pair_recovery_schema import PairPlanRequest, PairPlanResponse, PairStatusResponse
from backend.app.security import RecoveryAdminContext, require_recovery_admin
from backend.app.services import packet_pair_recovery_service as service


router = APIRouter(prefix="/recovery/packet-pair", tags=["packet-pair-recovery"])


def _call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except service.PairAPIError as error:
        raise HTTPException(status_code=error.status_code, detail={"code": error.code, "verification": "UNKNOWN"}) from error


@router.post("/plans", response_model=PairPlanResponse, status_code=201)
def create_plan(request: PairPlanRequest, admin: RecoveryAdminContext = Depends(require_recovery_admin)):
    return _call(service.create_plan, source_session_id=request.source_session_id,
                 target_session_id=request.target_session_id, reason=request.reason, principal=admin.principal)


@router.get("/{plan_id}", response_model=PairStatusResponse)
def get_plan(plan_id: str, _admin: RecoveryAdminContext = Depends(require_recovery_admin)):
    return _call(service.get_plan_status, plan_id)


@router.post("/{plan_id}/verify", response_model=PairStatusResponse)
def verify_plan(plan_id: str, _admin: RecoveryAdminContext = Depends(require_recovery_admin)):
    return _call(service.verify_plan, plan_id)
