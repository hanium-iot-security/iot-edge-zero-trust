"""Detection event API response schemas."""

from typing import Any

from pydantic import BaseModel


class DetectionEventItem(BaseModel):
    id: int
    device_id: str | None = None
    feature_log_id: int | None = None
    mqtt_log_id: int | None = None
    packet_feature_log_id: int | None = None
    detector_type: str
    event_type: str
    severity: str | None = None
    score_delta: int
    applied_to_score: int
    description: str | None = None
    detected_at: str | None = None
    analysis_window_start: str | None = None
    analysis_window_end: str | None = None
    incident_family: str | None = None
    subject_ip: str | None = None
    evidence: Any | None = None
    evidence_schema_version: int | None = None
    processing_reason: str | None = None
    processed_at: str | None = None
    policy_version: str | None = None


class DetectionEventListResponse(BaseModel):
    items: list[DetectionEventItem]
    total: int
