from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.trust_score_schema import (
    TrustScoreHistoryResponse,
    TrustScoreSummaryResponse,
)
from backend.app.services.trust_score_query_service import (
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


@router.get("/{device_id}/history", response_model=TrustScoreHistoryResponse)
def trust_score_history(
    device_id: str,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    return list_trust_score_history(db, device_id=device_id, limit=limit, offset=offset)
