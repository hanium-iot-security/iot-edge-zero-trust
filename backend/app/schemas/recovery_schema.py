"""Recovery command and audit API schemas."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


RecoveryResult = Literal["SUCCESS", "DENIED", "HOLD", "FAILED"]


class RecoveryPreflightRequest(BaseModel):
    device_id: str = Field(..., min_length=1)
    expected_trust_score: int = Field(..., ge=0, le=100)


class RecoveryExecuteRequest(RecoveryPreflightRequest):
    reason: str = Field(..., min_length=1)
    confirm: str = Field(..., min_length=1)


class RecoveryPreflightResponse(BaseModel):
    device_id: str
    current_status: str | None
    current_trust_score: int | None
    can_execute: bool
    result: RecoveryResult
    firewall_db_state: dict[str, Any]
    firewall_release_request_state: dict[str, Any]
    firewall_runtime_verification: dict[str, Any]
    unprocessed_detection_count: int | None
    backup_check: dict[str, Any]
    failure_code: str | None = None
    failure_reason: str | None = None
    preflight_errors: list[str] = Field(default_factory=list)


class RecoveryExecuteResponse(BaseModel):
    operation_id: str
    result: RecoveryResult
    device_id: str
    reason: str
    requested_by: str
    approved_by: str
    requested_at: str
    before_status: str | None = None
    before_trust_score: int | None = None
    after_status: str | None = None
    after_trust_score: int | None = None
    firewall_release_status: str
    backup_reference: str | None = None
    backup_sha256: str | None = None
    failure_code: str | None = None
    failure_reason: str | None = None


class RecoveryAuditItem(RecoveryExecuteResponse):
    log_reference: str | None = None


class RecoveryAuditListResponse(BaseModel):
    items: list[RecoveryAuditItem]
    total: int
