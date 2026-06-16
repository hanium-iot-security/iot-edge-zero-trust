"""Trust Score API response schemas."""

from pydantic import BaseModel


class TrustScoreSummaryItem(BaseModel):
    device_id: str
    status: str
    trust_score: int
    last_seen_at: str | None = None


class TrustScoreSummaryResponse(BaseModel):
    items: list[TrustScoreSummaryItem]
    count: int


class TrustScoreHistoryItem(BaseModel):
    event_id: int
    event_type: str
    detector_type: str
    severity: str | None = None
    score_delta: int
    applied_to_score: int
    detected_at: str | None = None
    description: str | None = None


class TrustScoreHistoryResponse(BaseModel):
    device_id: str
    items: list[TrustScoreHistoryItem]
    count: int
