from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.trust_score_schema import (
    TrustScoreHistoryResponse,
    TrustScoreSummaryResponse,
)
from backend.app.schemas.trust_compensation_schema import (
    TrustCompensationListResponse,
)
from backend.app.security import RecoveryAdminContext, require_recovery_admin
from backend.app.services.trust_compensation_query_service import (
    TrustCompensationDataError,
    list_trust_compensations,
)
from backend.app.services.trust_score_query_service import (
    TrustScoreDataError,
    list_trust_score_history,
    list_trust_score_summary,
)


router = APIRouter(prefix="/trust-score", tags=["trust-score"])


@router.get("/summary", response_model=TrustScoreSummaryResponse)
def trust_score_summary(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    return list_trust_score_summary(db, limit=limit, offset=offset)


@router.get("/compensations", response_model=TrustCompensationListResponse)
def trust_score_compensations(
    device_id: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _admin: RecoveryAdminContext = Depends(require_recovery_admin),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return list_trust_compensations(
            db,
            device_id=device_id,
            limit=limit,
            offset=offset,
        )
    except TrustCompensationDataError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/{device_id}/history", response_model=TrustScoreHistoryResponse)
def trust_score_history(
    device_id: str,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return list_trust_score_history(db, device_id=device_id, limit=limit, offset=offset)
    except TrustScoreDataError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
