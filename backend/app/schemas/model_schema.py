"""Artifact inspection is separate from evidence of a running model."""
from typing import Any, Literal

from pydantic import BaseModel, Field


class UnknownModelRuntime(BaseModel):
    status: Literal["UNKNOWN"] = "UNKNOWN"
    reason_code: str = "RUNTIME_MODEL_EVIDENCE_NOT_AVAILABLE"


class ModelChecks(BaseModel):
    bundle_sha256_verified: bool = False
    metadata_contract_verified: bool = False
    report_sha256_verified: bool = False
    report_json_object_verified: bool = False
    report_semantics_verified: Literal[False] = False
    model_deserialized: Literal[False] = False
    inference_verified: Literal[False] = False


class ModelInfoItem(BaseModel):
    detector: Literal["packet_if", "mqtt_if"]
    artifact_status: Literal[
        "BUNDLE_METADATA_VERIFIED", "UNCONFIGURED", "INVALID", "UNAVAILABLE",
        "LEGACY_CONTRACT_UNAVAILABLE",
    ]
    configured_model_version: str | None = None
    configured_bundle_sha256: str | None = None
    artifact: dict[str, Any] | None = None
    checks: ModelChecks = Field(default_factory=ModelChecks)
    runtime: UnknownModelRuntime = Field(default_factory=UnknownModelRuntime)
    error_code: str | None = None


class ModelInfoResponse(BaseModel):
    observed_at: str
    models: list[ModelInfoItem]
