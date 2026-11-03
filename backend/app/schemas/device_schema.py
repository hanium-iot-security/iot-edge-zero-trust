"""Device API response schemas."""

from pydantic import BaseModel


class DeviceItem(BaseModel):
    device_id: str
    ip_address: str | None = None
    status: str
    trust_score: int
    last_seen_at: str | None = None
    created_at: str | None = None
    hidden_at: str | None = None
    device_type: str | None = None
    mqtt_principal: str | None = None
    mqtt_topic: str | None = None
    registration_state: str | None = None
    registration_effective_from: str | None = None
    current_policy_revision: int | None = None
    pending_policy_revision: int | None = None
    auto_response_eligible: bool = False
    auto_response_exclusion_reason: str | None = "POLICY_UNAVAILABLE"


class DeviceListResponse(BaseModel):
    items: list[DeviceItem]
    total: int
