from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.recovery_schema import (
    RecoveryAuditItem,
    RecoveryAuditListResponse,
    RecoveryExecuteRequest,
    RecoveryExecuteResponse,
    RecoveryPreflightRequest,
    RecoveryPreflightResponse,
)
from backend.app.security import RecoveryAdminContext, require_recovery_admin
from backend.app.services.recovery_command_service import (
    RecoveryCoreFailedError,
    RecoveryCommandError,
    RecoveryNotExecutableError,
    build_recovery_preflight,
    execute_recovery_command,
    get_recovery_audit,
    list_recovery_audits,
)


router = APIRouter(prefix="/recovery", tags=["recovery"])


@router.post("/preflight", response_model=RecoveryPreflightResponse)
def recovery_preflight(
    request: RecoveryPreflightRequest,
    _admin: RecoveryAdminContext = Depends(require_recovery_admin),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return build_recovery_preflight(
            db,
            device_id=request.device_id,
            expected_trust_score=request.expected_trust_score,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RecoveryCommandError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/execute", response_model=RecoveryExecuteResponse)
def recovery_execute(
    request: RecoveryExecuteRequest,
    admin: RecoveryAdminContext = Depends(require_recovery_admin),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return execute_recovery_command(
            db,
            device_id=request.device_id,
            expected_trust_score=request.expected_trust_score,
            reason=request.reason,
            confirm=request.confirm,
            admin=admin,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RecoveryNotExecutableError as exc:
        raise HTTPException(status_code=409, detail=exc.payload) from exc
    except RecoveryCoreFailedError as exc:
        raise HTTPException(status_code=500, detail=exc.payload) from exc
    except RecoveryCommandError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/history", response_model=RecoveryAuditListResponse)
def recovery_history(
    device_id: str | None = None,
    result: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _admin: RecoveryAdminContext = Depends(require_recovery_admin),
    db: Session = Depends(get_db),
) -> dict:
    return list_recovery_audits(
        db=db,
        device_id=device_id,
        result=result,
        limit=limit,
        offset=offset,
    )


@router.get("/history/{operation_id}", response_model=RecoveryAuditItem)
def recovery_history_item(
    operation_id: str,
    _admin: RecoveryAdminContext = Depends(require_recovery_admin),
    db: Session = Depends(get_db),
) -> dict:
    item = get_recovery_audit(operation_id, db=db)
    if item is None:
        raise HTTPException(status_code=404, detail="Recovery audit not found")
    return item
