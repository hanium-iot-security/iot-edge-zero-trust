"""HTTP contract for per-device OFF/OBSERVE settings, separate from Rule policy."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from edge.policy.device_policy import REVISION_MAX, validate_reason


class AiPolicyRevisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: Annotated[int, Field(ge=1, le=REVISION_MAX)]
    mode: Literal["OFF", "OBSERVE"]
    reason: str

    _reason = field_validator("reason", mode="before")(validate_reason)


class AiPolicyRevisionItem(BaseModel):
    device_id: str
    revision: int
    mode: Literal["OFF", "OBSERVE"]
    effective_from: str
    created_at: str
    created_by: str
    reason: str


class AiPolicySnapshotResponse(BaseModel):
    device_id: str
    server_time: str
    latest_revision: int
    current: AiPolicyRevisionItem | None
    pending: AiPolicyRevisionItem | None
