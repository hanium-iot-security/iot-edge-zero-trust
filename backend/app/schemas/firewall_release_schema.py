"""Firewall release request API schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


FirewallReleaseStatus = Literal["PENDING", "SUCCEEDED", "FAILED"]


class FirewallReleaseRequestCreate(BaseModel):
    reason: str = Field(..., min_length=1)
    confirm: str = Field(..., min_length=1)

    @field_validator("reason")
    @classmethod
    def reason_must_not_be_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("reason must not be blank")
        return normalized


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
