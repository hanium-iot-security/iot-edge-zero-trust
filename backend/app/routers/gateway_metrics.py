from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.gateway_metrics_schema import GatewayMetricListResponse
from backend.app.services.gateway_metrics_query_service import (
    GatewayMetricsDataError,
    list_gateway_metric_rows,
)


router = APIRouter(prefix="/gateway-metrics", tags=["gateway-metrics"])


@router.get("", response_model=GatewayMetricListResponse)
def get_gateway_metrics(
    from_at: Annotated[datetime | None, Query(alias="from")] = None,
    to_at: Annotated[datetime | None, Query(alias="to")] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return list_gateway_metric_rows(
            db,
            from_at=from_at,
            to_at=to_at,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except GatewayMetricsDataError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
