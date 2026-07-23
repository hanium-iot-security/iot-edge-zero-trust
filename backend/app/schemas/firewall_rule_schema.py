"""Firewall rule API response schemas."""

from pydantic import BaseModel


class FirewallRuleItem(BaseModel):
    id: int
    device_id: str | None = None
    source_ip: str
    protocol: str
    dest_port: int
    action: str
    status: str
    reason: str | None = None
    trigger_event_id: int | None = None
    retry_count: int
    last_error: str | None = None
    last_attempted_at: str | None = None
    next_retry_at: str | None = None
    applied_at: str | None = None
    released_at: str | None = None
    created_at: str
    updated_at: str


class FirewallRuleListResponse(BaseModel):
    items: list[FirewallRuleItem]
    total: int
