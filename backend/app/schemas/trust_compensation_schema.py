"""Trust Score compensation read API schemas."""

from __future__ import annotations

from pydantic import BaseModel


class TrustCompensationItem(BaseModel):
    id: int
    operation_id: str
    device_id: str
    source_event_id: int
    source_trust_history_id: int
    previous_score: int
    compensation_delta: int
    new_score: int
    reason: str
    approved_by: str
    backup_reference: str
    backup_sha256: str
    created_at: str


class TrustCompensationListResponse(BaseModel):
    items: list[TrustCompensationItem]
    total: int
