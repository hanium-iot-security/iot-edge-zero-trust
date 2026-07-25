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
    id: int | None = None
    device_id: str | None = None
    analysis_window_start: str | None = None
    analysis_window_end: str | None = None
    previous_score: int | None = None
    calculated_delta: int | None = None
    capped_delta: int | None = None
    actual_delta: int | None = None
    new_score: int | None = None
    representative_event_ids: list[int] | None = None
    policy_version: str | None = None
    created_at: str | None = None
    event_id: int | None = None
    event_type: str | None = None
    detector_type: str | None = None
    severity: str | None = None
    score_delta: int | None = None
    score_before: int | None = None
    score_after: int | None = None
    applied_to_score: int | None = None
    detected_at: str | None = None
    description: str | None = None


class TrustScoreHistoryResponse(BaseModel):
    device_id: str
    current_score: int | None
    current_status: str | None
    items: list[TrustScoreHistoryItem]
    total: int
