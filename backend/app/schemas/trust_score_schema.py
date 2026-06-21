"""Trust Score API response schemas."""

from pydantic import BaseModel


class TrustScoreSummaryItem(BaseModel):
    device_id: str
    status: str
    trust_score: int
    last_seen_at: str | None = None


class TrustScoreSummaryResponse(BaseModel):
    items: list[TrustScoreSummaryItem]
    total: int


class TrustScoreHistoryItem(BaseModel):
    event_id: int
    event_type: str
    detector_type: str
    severity: str | None = None
    score_delta: int
    score_before: int
    score_after: int
    applied_to_score: int
    detected_at: str | None = None
    description: str | None = None


class TrustScoreHistoryResponse(BaseModel):
    device_id: str
    current_score: int | None
    current_status: str | None
    items: list[TrustScoreHistoryItem]
    total: int
