"""Explicit, optimistic-concurrency guarded device management commands."""
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from edge.policy.device_policy import REVISION_MAX, validate_reason


ManagementOperationId = Annotated[str, Field(min_length=1, max_length=128)]


class DeviceManagementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    action: Literal["DELETE_UNUSED", "HIDE", "RESTORE"]
    expected_revision: Annotated[int, Field(ge=1, le=REVISION_MAX)]
    expected_ai_revision: Annotated[int, Field(ge=1, le=REVISION_MAX)]
    expected_hidden_at: str | None
    expected_instance_id: str | None
    expected_management_operation_id: ManagementOperationId | None
    reason: str | None = None

    @field_validator("reason", mode="before")
    @classmethod
    def optional_reason(cls, value):
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        return validate_reason(value)


class DeviceManagementState(BaseModel):
    device_id: str
    expected_revision: int
    expected_ai_revision: int
    expected_instance_id: str | None
    expected_management_operation_id: ManagementOperationId | None
    hidden_at: str | None
    can_delete: bool
    can_hide: bool
    can_restore: bool
    delete_blockers: list[str]
    hide_blockers: list[str]


class DeviceManagementResponse(BaseModel):
    device_id: str
    action: Literal["DELETE_UNUSED", "HIDE", "RESTORE"]
    operation_id: str
    hidden_at: str | None
    deleted: bool
