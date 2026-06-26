"""Device API response schemas."""

from pydantic import BaseModel


class DeviceItem(BaseModel):
    device_id: str
    ip_address: str | None = None
    status: str
    trust_score: int
    last_seen_at: str | None = None
    created_at: str | None = None


class DeviceListResponse(BaseModel):
    items: list[DeviceItem]
    total: int
