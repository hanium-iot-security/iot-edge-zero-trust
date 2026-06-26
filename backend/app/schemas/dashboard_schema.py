"""Dashboard summary API response schemas."""

from pydantic import BaseModel

from backend.app.schemas.detection_event_schema import DetectionEventItem
from backend.app.schemas.isolation_schema import IsolationHistoryItem


class DashboardSummaryResponse(BaseModel):
    total_devices: int
    normal_devices: int
    warning_devices: int
    danger_devices: int
    isolated_devices: int
    total_detection_events: int
    unapplied_detection_events: int
    total_isolation_events: int
    recent_events_count: int
    unknown_device_count: int
    last_updated: str
    latest_detection_events: list[DetectionEventItem]
    latest_isolation_events: list[IsolationHistoryItem]
