"""Detection event API response schemas."""

from pydantic import BaseModel


class DetectionEventItem(BaseModel):
    id: int
    device_id: str | None = None
    feature_log_id: int | None = None
    mqtt_log_id: int | None = None
    detector_type: str
    event_type: str
    severity: str | None = None
    score_delta: int
    applied_to_score: int
    description: str | None = None
    detected_at: str | None = None


class DetectionEventListResponse(BaseModel):
    items: list[DetectionEventItem]
    total: int
