"""Management-only inspection of a fixed, server-owned recovery plan."""
from typing import Any, Literal
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def canonical_uuid(value: str) -> str:
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("a canonical UUID string is required")
    return value


class PairPlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    source_session_id: str
    target_session_id: str
    reason: str = Field(min_length=1, max_length=1000)

    _sessions = field_validator("source_session_id", "target_session_id", mode="before")(canonical_uuid)

    @field_validator("reason")
    @classmethod
    def reason_required(cls, value: str) -> str:
        if not value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("a non-empty single-line reason is required")
        return value.strip()

    @model_validator(mode="after")
    def distinct_sessions(self):
        if self.source_session_id == self.target_session_id:
            raise ValueError("source and target sessions must differ")
        return self


class PairRuntime(BaseModel):
    status: Literal["UNKNOWN"] = "UNKNOWN"
    reason_code: str = "ORCHESTRATOR_PROCESS_CONFIGURATION_NOT_ATTESTED"


class PairPlanResponse(BaseModel):
    plan_id: str
    plan_sha256: str
    source_session_id: str
    target_session_id: str
    approved_by: str
    reason: str
    generated_at: str
    can_execute: bool
    blocking_reasons: list[str]
    skips_processable: bool
    boundary: str | None
    children: list[dict[str, Any]]
    apply_transport: Literal["ROOT_CLI"] = "ROOT_CLI"
    runtime: PairRuntime = Field(default_factory=PairRuntime)


class PairVerification(BaseModel):
    status: Literal["NOT_REQUESTED", "VERIFIED_AUDITS", "HOLD", "UNKNOWN"]
    error_code: str | None = None
    root_progress_verified: bool = False
    root_completion_recorded: bool = False
    root_progress_status: Literal["NOT_CHECKED", "UNAVAILABLE", "VERIFIED", "INVALID"] = "NOT_CHECKED"
    root_progress_observed_at: str | None = None
    root_progress_age_seconds: float | None = None
    root_progress_fresh: bool = False
    root_progress_max_age_seconds: int = 45
    root_completion_evidence_status: Literal["UNAVAILABLE", "NOT_COMPLETED", "RECORDED"] = "UNAVAILABLE"


class PairStatusResponse(BaseModel):
    plan_id: str
    plan_sha256: str
    observed_at: str
    operation_status: Literal[
        "PENDING", "COMMITTED_UNVERIFIED", "PARTIAL_HOLD", "HOLD", "APPLIED_VERIFY_REQUIRED",
    ]
    database_committed: bool | None
    children: dict[str, dict[str, Any]]
    verification: PairVerification
    runtime: PairRuntime = Field(default_factory=PairRuntime)
