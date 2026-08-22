"""Firewall release request API schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


FirewallReleaseStatus = Literal["PENDING", "SUCCEEDED", "FAILED"]


class FirewallReleaseRequestCreate(BaseModel):
    reason: str = Field(..., min_length=1)
    confirm: str = Field(..., min_length=1)


class FirewallReleaseRequestItem(BaseModel):
    id: int
    firewall_rule_id: int
    status: FirewallReleaseStatus
    requested_by: str
    reason: str
    requested_at: str
    processed_at: str | None = None
    last_error: str | None = None
    created_at: str
    updated_at: str


class FirewallReleaseRequestResponse(BaseModel):
    item: FirewallReleaseRequestItem
