"""Public runtime evidence; configured policy is not proof of inference."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


Count = Annotated[int, Field(ge=0)]
BundleHash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ObservationStatus = Literal["STARTING", "RUNNING", "FAILED", "STOPPED"]
Freshness = Literal["FRESH", "STALE", "MISSING", "FUTURE", "BOOT_MISMATCH", "BOOT_UNAVAILABLE"]


class EvidenceModel(BaseModel):
    # Whitelist public fields: publisher diagnostics must not leak through HTTP.
    model_config = ConfigDict(strict=True, extra="ignore")


class WarningPolicyInfo(EvidenceModel):
    version: Annotated[str, Field(min_length=1, max_length=128)]
    window_seconds: Annotated[int, Field(ge=10, multiple_of=10)]
    count_threshold: Annotated[int, Field(ge=1)]
    cooldown_seconds: Count


class RuntimeStage(EvidenceModel):
    name: str
    enabled: bool
    required: bool
    status: str
    observed_at: str | None = None
    trust_ai_mode: Literal["observe", "enforce"] | None = None
    ai_device_policy_enabled: bool | None = None
    model_version: str | None = None
    bundle_sha256: BundleHash | None = None
    last_completed_window_end: str | None = None
    last_processed_id: Count | None = None
    selected_count: Count | None = None
    created_event_count: Count | None = None
    error_code: str | None = None


class RuntimeObservation(EvidenceModel):
    run_id: str
    boot_id: str | None
    started_at: str
    observed_at: str
    status: ObservationStatus
    error_code: str | None = None
    warning_policy: WarningPolicyInfo | None = None
    stages: list[RuntimeStage]


class CompletionEvidence(EvidenceModel):
    run_id: str
    boot_id: str | None
    observed_at: str
    detector_name: Literal["mqtt_if", "packet_if"]
    device_id: str | None
    window_start: str | None
    completed_window_end: str
    input_count: Count
    inference_count: Count
    normal_count: Count
    anomaly_count: Count
    exclusion_counts: dict[str, Count]
    model_version: str | None
    bundle_sha256: BundleHash | None
    ai_revision: Annotated[int, Field(ge=1)] | None
    ai_mode: Literal["OFF", "OBSERVE"] | None


class CompletionItem(CompletionEvidence):
    evidence_status: Literal["CURRENT", "HISTORICAL"]
    freshness: Freshness
    age_seconds: float | None


class RuntimeStatusResponse(EvidenceModel):
    server_time: str
    observed_at: str | None
    run_id: str | None
    boot_id: str | None
    status: ObservationStatus | Literal["UNKNOWN"]
    last_observation_status: ObservationStatus | None
    freshness: Freshness
    age_seconds: float | None
    max_age_seconds: int
    reason_code: str | None
    error_code: str | None
    warning_policy: WarningPolicyInfo | None
    stages: list[RuntimeStage]
    completions: list[CompletionItem]


class AiWarningItem(EvidenceModel):
    id: Annotated[int, Field(ge=1)]
    device_id: str
    detector_name: Literal["mqtt_if", "packet_if"]
    event_type: Literal["AI_ANOMALY", "AI_PACKET_ANOMALY"]
    model_version: str
    warning_policy_version: str
    bucket_start: str
    bucket_end: str
    count: Count
    first_window: str | None
    latest_window: str | None
    notified_at: str | None
    suppressed_count: Count
    closed: bool
    last_decision: str
    updated_at: str
    event_ids: list[Annotated[int, Field(ge=1)]]
    analysis_windows: list[str]


class AiWarningListResponse(EvidenceModel):
    server_time: str
    observed_at: str | None
    source_status: Literal["AVAILABLE", "POLICY_UNCONFIGURED", "UNKNOWN"]
    reason_code: str | None
    items: list[AiWarningItem]
    total: Count
