"""Isolation history API response schemas."""

from pydantic import BaseModel


class IsolationHistoryItem(BaseModel):
    id: int
    device_id: str
    action: str
    reason: str | None = None
    trust_score: int | None = None
    trigger_event_id: int | None = None
    trust_score_history_id: int | None = None
    created_at: str | None = None


class IsolationHistoryListResponse(BaseModel):
    items: list[IsolationHistoryItem]
    total: int
