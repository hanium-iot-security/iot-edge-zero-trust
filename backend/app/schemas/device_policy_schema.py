"""HTTP contract for administrator device registration and policy revisions."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.schemas.device_schema import DeviceItem
from edge.policy.device_policy import (
    BYTE_RATE_MAX_LIMIT_BYTES_PER_SECOND,
    EXPECTED_PUBLISH_INTERVAL_MAX_SECONDS,
    PACKET_RATE_MAX_LIMIT_PPS,
    PAYLOAD_SIZE_MAX_LIMIT_BYTES,
    PUBLISH_COUNT_MAX_LIMIT,
    REVISION_MAX,
    validate_device_id,
    validate_mqtt_principal,
    validate_reason,
)


class PolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)

    policy_profile: Literal["periodic-sensor-v1"]
    expected_publish_interval_seconds: Annotated[
        float, Field(gt=0, le=EXPECTED_PUBLISH_INTERVAL_MAX_SECONDS)
    ]
    publish_count_max: Annotated[int, Field(ge=1, le=PUBLISH_COUNT_MAX_LIMIT)]
    payload_size_max_bytes: Annotated[int, Field(ge=1, le=PAYLOAD_SIZE_MAX_LIMIT_BYTES)]
    packet_rate_max_pps: Annotated[float, Field(gt=0, le=PACKET_RATE_MAX_LIMIT_PPS)]
    byte_rate_max_bytes_per_second: Annotated[
        float, Field(gt=0, le=BYTE_RATE_MAX_LIMIT_BYTES_PER_SECOND)
    ]


class DeviceRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    device_id: str
    ip_address: str
    device_type: Literal["SENSOR", "CAMERA", "ACTUATOR", "OTHER"]
    mqtt_principal: str
    policy: PolicyInput
    reason: str

    _device_id = field_validator("device_id", mode="before")(validate_device_id)
    _principal = field_validator("mqtt_principal", mode="before")(validate_mqtt_principal)
    _reason = field_validator("reason", mode="before")(validate_reason)


class PolicyRevisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: Annotated[int, Field(ge=1, le=REVISION_MAX)]
    registration_state: Literal["PENDING", "ACTIVE", "DISABLED"]
    policy: PolicyInput
    reason: str

    _reason = field_validator("reason", mode="before")(validate_reason)


class PolicyRevisionItem(BaseModel):
    device_id: str
    revision: int
    effective_from: str
    registration_state: Literal["PENDING", "ACTIVE", "DISABLED"]
    policy: PolicyInput
    created_at: str
    created_by: str
    reason: str


class PolicySnapshotResponse(BaseModel):
    device_id: str
    server_time: str
    latest_revision: int
    current: PolicyRevisionItem | None
    pending: PolicyRevisionItem | None


class DeviceRegistrationResponse(BaseModel):
    device: DeviceItem
    policy: PolicySnapshotResponse
