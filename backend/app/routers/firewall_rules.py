from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.firewall_rule_schema import FirewallRuleListResponse
from backend.app.services.firewall_rule_query_service import list_firewall_rules


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
