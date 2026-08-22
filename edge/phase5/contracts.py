"""Shared Phase 5 Run Manifest contracts.

This module is intentionally pure Python: no DB, filesystem, network, or model
runtime access happens here. Scenario runners, run-manifest generators, and
evaluation exporters should import these dataclasses instead of redefining the
same fields.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
from ipaddress import ip_address
import json
import re
from typing import Any

from edge.trust.trust_policy import SCORE_DELTA_BY_EVENT


RUN_MANIFEST_SCHEMA_VERSION = "phase5-run-manifest-v1"
SUPPORTED_RUN_MANIFEST_SCHEMA_VERSIONS = (RUN_MANIFEST_SCHEMA_VERSION,)
RUN_MANIFEST_SHA256_SIDECAR_SUFFIX = ".sha256"

_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
_WINDOWS_DRIVE_PATTERN = re.compile(r"^[A-Za-z]:")


class ManifestStatus(str, Enum):
    """Phase 5 evaluation stage state.

    NOT_EVALUATED: The stage has not been evaluated yet.
    SUCCESS: The stage completed and matched the expected result.
    FAILED: The stage completed but did not match the expected result.
    HOLD: Evaluation is blocked by missing device/precondition readiness.
    NOT_APPLICABLE: The stage does not apply to this run.
    ENVIRONMENT_ERROR: Environment or infrastructure prevented evaluation.
    CAPTURE_INELIGIBLE: Packet capture evidence exists but is not eligible.
    """

    NOT_EVALUATED = "NOT_EVALUATED"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    HOLD = "HOLD"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ENVIRONMENT_ERROR = "ENVIRONMENT_ERROR"
    CAPTURE_INELIGIBLE = "CAPTURE_INELIGIBLE"


class EvaluationScope(str, Enum):
    FULL_E2E = "FULL_E2E"
    DETECTION_ONLY = "DETECTION_ONLY"
    TRUST_ONLY = "TRUST_ONLY"
    FIREWALL_ONLY = "FIREWALL_ONLY"
    BLOCK_ONLY = "BLOCK_ONLY"
    DATA_ONLY = "DATA_ONLY"


@dataclass(frozen=True)
class ManifestValidationIssue:
    code: str
    field_path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "field_path": self.field_path,
            "message": self.message,
        }


@dataclass(frozen=True)
class ManifestValidationResult:
    errors: tuple[ManifestValidationIssue, ...] = ()

    @property
    def is_valid(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "errors": [error.to_dict() for error in self.errors],
        }


class RunManifestValidationError(ValueError):
    def __init__(self, errors: Sequence[ManifestValidationIssue]) -> None:
        self.errors = tuple(errors)
        first = self.errors[0] if self.errors else None
        if first is None:
            message = "run manifest validation failed"
        else:
            message = (
                "run manifest validation failed: "
                f"{first.field_path}: {first.message}"
            )
        super().__init__(message)


@dataclass(frozen=True)
class ScenarioReference:
    scenario_id: str
    scenario_name: str | None = None
    scenario_version: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "scenario_id",
            _require_non_empty_string(self.scenario_id, "scenario.scenario_id"),
        )
        object.__setattr__(
            self,
            "scenario_name",
            _normalize_optional_string(self.scenario_name, "scenario.scenario_name"),
        )
        object.__setattr__(
            self,
            "scenario_version",
            _normalize_optional_string(
                self.scenario_version,
                "scenario.scenario_version",
            ),
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ScenarioReference":
        return cls(
            scenario_id=payload["scenario_id"],
            scenario_name=payload.get("scenario_name"),
            scenario_version=payload.get("scenario_version"),
        )

    def to_dict(self) -> dict[str, str | None]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "scenario_version": self.scenario_version,
        }


@dataclass(frozen=True)
class ExecutionNode:
    node_id: str
    registered: bool
    hostname: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "node_id",
            _require_non_empty_string(self.node_id, "execution_node.node_id"),
        )
        object.__setattr__(
            self,
            "registered",
            _require_bool(self.registered, "execution_node.registered"),
        )
        object.__setattr__(
            self,
            "hostname",
            _normalize_optional_string(self.hostname, "execution_node.hostname"),
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ExecutionNode":
        return cls(
            node_id=payload["node_id"],
            registered=payload["registered"],
            hostname=payload.get("hostname"),
        )

    def to_dict(self) -> dict[str, str | bool | None]:
        return {
            "node_id": self.node_id,
            "registered": self.registered,
            "hostname": self.hostname,
        }


@dataclass(frozen=True)
class ExpectedOutcome:
    expected_event_types: tuple[str, ...] = ()
    detection_expected: bool = False
    trust_score_change_expected: bool = False
    firewall_expected: bool = False
    block_expected: bool = False
    evaluation_scope: EvaluationScope = EvaluationScope.FULL_E2E

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "expected_event_types",
            _normalize_event_types(self.expected_event_types),
        )
        for field_name in (
            "detection_expected",
            "trust_score_change_expected",
            "firewall_expected",
            "block_expected",
        ):
            object.__setattr__(
                self,
                field_name,
                _require_bool(getattr(self, field_name), f"expected_outcome.{field_name}"),
            )
        object.__setattr__(
            self,
            "evaluation_scope",
            _coerce_enum(
                EvaluationScope,
                self.evaluation_scope,
                "expected_outcome.evaluation_scope",
            ),
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ExpectedOutcome":
        return cls(
            expected_event_types=tuple(payload.get("expected_event_types", ())),
            detection_expected=payload["detection_expected"],
            trust_score_change_expected=payload["trust_score_change_expected"],
            firewall_expected=payload["firewall_expected"],
            block_expected=payload["block_expected"],
            evaluation_scope=payload["evaluation_scope"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "expected_event_types": list(self.expected_event_types),
            "detection_expected": self.detection_expected,
            "trust_score_change_expected": self.trust_score_change_expected,
            "firewall_expected": self.firewall_expected,
            "block_expected": self.block_expected,
            "evaluation_scope": self.evaluation_scope.value,
        }


@dataclass(frozen=True)
class RunStageStatuses:
    scenario_status: ManifestStatus = ManifestStatus.NOT_EVALUATED
    detection_status: ManifestStatus = ManifestStatus.NOT_EVALUATED
    trust_status: ManifestStatus = ManifestStatus.NOT_EVALUATED
    firewall_status: ManifestStatus = ManifestStatus.NOT_EVALUATED
    block_status: ManifestStatus = ManifestStatus.NOT_EVALUATED
    data_status: ManifestStatus = ManifestStatus.NOT_EVALUATED
    final_status: ManifestStatus = ManifestStatus.NOT_EVALUATED

    def __post_init__(self) -> None:
        for field_name in _STATUS_FIELDS:
            object.__setattr__(
                self,
                field_name,
                _coerce_enum(
                    ManifestStatus,
                    getattr(self, field_name),
                    f"statuses.{field_name}",
                ),
            )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "RunStageStatuses":
        return cls(**{field_name: payload[field_name] for field_name in _STATUS_FIELDS})

    def to_dict(self) -> dict[str, str]:
        return {
            field_name: getattr(self, field_name).value
            for field_name in _STATUS_FIELDS
        }


@dataclass(frozen=True)
class MatchedResultIds:
    detection_event_ids: tuple[int, ...] | None = None
    trust_score_history_ids: tuple[int, ...] | None = None
    firewall_rule_ids: tuple[int, ...] | None = None
    firewall_release_request_ids: tuple[int, ...] | None = None
    trigger_event_ids: tuple[int, ...] | None = None

    def __post_init__(self) -> None:
        for field_name in _MATCHED_ID_FIELDS:
            object.__setattr__(
                self,
                field_name,
                _normalize_optional_ids(
                    getattr(self, field_name),
                    f"matched_ids.{field_name}",
                ),
            )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "MatchedResultIds":
        return cls(
            detection_event_ids=payload.get("detection_event_ids"),
            trust_score_history_ids=payload.get("trust_score_history_ids"),
            firewall_rule_ids=payload.get("firewall_rule_ids"),
            firewall_release_request_ids=payload.get("firewall_release_request_ids"),
            trigger_event_ids=payload.get("trigger_event_ids"),
        )

    def to_dict(self) -> dict[str, list[int] | None]:
        return {
            field_name: (
                None
                if getattr(self, field_name) is None
                else list(getattr(self, field_name))
            )
            for field_name in _MATCHED_ID_FIELDS
        }


@dataclass(frozen=True)
class RunArtifact:
    artifact_type: str
    relative_path: str
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "artifact_type",
            _require_non_empty_string(self.artifact_type, "artifacts[].artifact_type"),
        )
        object.__setattr__(
            self,
            "relative_path",
            _normalize_relative_path(self.relative_path, "artifacts[].relative_path"),
        )
        object.__setattr__(
            self,
            "size_bytes",
            _require_non_negative_int(self.size_bytes, "artifacts[].size_bytes"),
        )
        object.__setattr__(
            self,
            "sha256",
            _normalize_sha256(self.sha256, "artifacts[].sha256"),
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "RunArtifact":
        return cls(
            artifact_type=payload["artifact_type"],
            relative_path=payload["relative_path"],
            size_bytes=payload["size_bytes"],
            sha256=payload["sha256"],
        )

    def to_dict(self) -> dict[str, str | int]:
        return {
            "artifact_type": self.artifact_type,
            "relative_path": self.relative_path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class ManifestReference:
    relative_path: str
    schema_version: str
    sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "relative_path",
            _normalize_relative_path(
                self.relative_path,
                "session_manifest_ref.relative_path",
            ),
        )
        object.__setattr__(
            self,
            "schema_version",
            _require_non_empty_string(
                self.schema_version,
                "session_manifest_ref.schema_version",
            ),
        )
        object.__setattr__(
            self,
            "sha256",
            _normalize_sha256(self.sha256, "session_manifest_ref.sha256"),
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ManifestReference":
        return cls(
            relative_path=payload["relative_path"],
            schema_version=payload["schema_version"],
            sha256=payload["sha256"],
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "relative_path": self.relative_path,
            "schema_version": self.schema_version,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, kw_only=True)
class RunManifest:
    run_id: str
    session_id: str | None
    scenario: ScenarioReference
    target_device_id: str | None
    source_ip: str | None
    execution_node: ExecutionNode
    evaluation_scope: EvaluationScope
    is_active: bool
    started_at: datetime
    observation_deadline_at: datetime
    expected_outcome: ExpectedOutcome
    statuses: RunStageStatuses
    run_manifest_schema_version: str = RUN_MANIFEST_SCHEMA_VERSION
    attack_started_at: datetime | None = None
    ended_at: datetime | None = None
    external_observations: Mapping[str, datetime] = field(default_factory=dict)
    matched_ids: MatchedResultIds = field(default_factory=MatchedResultIds)
    artifacts: tuple[RunArtifact, ...] = ()
    session_manifest_ref: ManifestReference | None = None
    failure_stage: str | None = None
    failure_reason_code: str | None = None
    failure_reason: str | None = None

    def __post_init__(self) -> None:
        require_supported_run_manifest_schema_version(
            self.run_manifest_schema_version,
        )
        object.__setattr__(
            self,
            "run_id",
            _require_non_empty_string(self.run_id, "run_id"),
        )
        object.__setattr__(
            self,
            "session_id",
            _normalize_optional_string(self.session_id, "session_id"),
        )
        object.__setattr__(
            self,
            "target_device_id",
            _normalize_optional_string(self.target_device_id, "target_device_id"),
        )
        object.__setattr__(
            self,
            "source_ip",
            _normalize_optional_ip_address(self.source_ip, "source_ip"),
        )
        object.__setattr__(
            self,
            "evaluation_scope",
            _coerce_enum(EvaluationScope, self.evaluation_scope, "evaluation_scope"),
        )
        object.__setattr__(self, "is_active", _require_bool(self.is_active, "is_active"))

        scenario = self.scenario
        if isinstance(scenario, Mapping):
            scenario = ScenarioReference.from_dict(scenario)
        if not isinstance(scenario, ScenarioReference):
            raise ValueError("scenario must be a ScenarioReference")
        object.__setattr__(self, "scenario", scenario)

        execution_node = self.execution_node
        if isinstance(execution_node, Mapping):
            execution_node = ExecutionNode.from_dict(execution_node)
        if not isinstance(execution_node, ExecutionNode):
            raise ValueError("execution_node must be an ExecutionNode")
        object.__setattr__(self, "execution_node", execution_node)

        expected = self.expected_outcome
        if isinstance(expected, Mapping):
            expected = ExpectedOutcome.from_dict(expected)
        if not isinstance(expected, ExpectedOutcome):
            raise ValueError("expected_outcome must be an ExpectedOutcome")
        if expected.evaluation_scope != self.evaluation_scope:
            raise ValueError(
                "expected_outcome.evaluation_scope must match evaluation_scope"
            )
        object.__setattr__(self, "expected_outcome", expected)

        statuses = self.statuses
        if isinstance(statuses, Mapping):
            statuses = RunStageStatuses.from_dict(statuses)
        if not isinstance(statuses, RunStageStatuses):
            raise ValueError("statuses must be RunStageStatuses")
        object.__setattr__(self, "statuses", statuses)

        matched_ids = self.matched_ids
        if isinstance(matched_ids, Mapping):
            matched_ids = MatchedResultIds.from_dict(matched_ids)
        if not isinstance(matched_ids, MatchedResultIds):
            raise ValueError("matched_ids must be MatchedResultIds")
        object.__setattr__(self, "matched_ids", matched_ids)

        started_at = _require_utc_datetime(self.started_at, "started_at")
        attack_started_at = _normalize_optional_datetime(
            self.attack_started_at,
            "attack_started_at",
        )
        observation_deadline_at = _require_utc_datetime(
            self.observation_deadline_at,
            "observation_deadline_at",
        )
        ended_at = _normalize_optional_datetime(self.ended_at, "ended_at")
        if observation_deadline_at < started_at:
            raise ValueError("observation_deadline_at must not be earlier than started_at")
        if attack_started_at is not None and attack_started_at < started_at:
            raise ValueError("attack_started_at must not be earlier than started_at")
        if (
            attack_started_at is not None
            and attack_started_at > observation_deadline_at
        ):
            raise ValueError(
                "attack_started_at must not be later than observation_deadline_at"
            )
        if ended_at is not None and ended_at < started_at:
            raise ValueError("ended_at must not be earlier than started_at")
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "attack_started_at", attack_started_at)
        object.__setattr__(self, "observation_deadline_at", observation_deadline_at)
        object.__setattr__(self, "ended_at", ended_at)

        object.__setattr__(
            self,
            "external_observations",
            _normalize_observations(self.external_observations),
        )
        artifacts = tuple(
            sorted(
                [
                    artifact
                    if isinstance(artifact, RunArtifact)
                    else RunArtifact.from_dict(artifact)
                    for artifact in self.artifacts
                ],
                key=lambda artifact: (
                    artifact.artifact_type,
                    artifact.relative_path,
                    artifact.sha256,
                ),
            )
        )
        object.__setattr__(self, "artifacts", artifacts)
        session_manifest_ref = self.session_manifest_ref
        if isinstance(session_manifest_ref, Mapping):
            session_manifest_ref = ManifestReference.from_dict(session_manifest_ref)
        if session_manifest_ref is not None and not isinstance(
            session_manifest_ref,
            ManifestReference,
        ):
            raise ValueError("session_manifest_ref must be a ManifestReference")
        object.__setattr__(
            self,
            "session_manifest_ref",
            session_manifest_ref,
        )
        object.__setattr__(
            self,
            "failure_stage",
            _normalize_optional_string(self.failure_stage, "failure_stage"),
        )
        object.__setattr__(
            self,
            "failure_reason_code",
            _normalize_optional_string(
                self.failure_reason_code,
                "failure_reason_code",
            ),
        )
        object.__setattr__(
            self,
            "failure_reason",
            _normalize_optional_string(self.failure_reason, "failure_reason"),
        )
        _require_pre_capture_failure_invariant(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "RunManifest":
        result = validate_run_manifest_dict(payload)
        if not result.is_valid:
            raise RunManifestValidationError(result.errors)

        return cls(
            run_manifest_schema_version=payload["run_manifest_schema_version"],
            run_id=payload["run_id"],
            session_id=payload["session_id"],
            scenario=ScenarioReference.from_dict(payload["scenario"]),
            target_device_id=payload["target_device_id"],
            source_ip=payload["source_ip"],
            execution_node=ExecutionNode.from_dict(payload["execution_node"]),
            evaluation_scope=payload["evaluation_scope"],
            is_active=payload["is_active"],
            started_at=payload["started_at"],
            attack_started_at=payload.get("attack_started_at"),
            observation_deadline_at=payload["observation_deadline_at"],
            ended_at=payload.get("ended_at"),
            external_observations=payload.get("external_observations", {}),
            expected_outcome=ExpectedOutcome.from_dict(payload["expected_outcome"]),
            statuses=RunStageStatuses.from_dict(payload["statuses"]),
            matched_ids=MatchedResultIds.from_dict(payload.get("matched_ids", {})),
            artifacts=tuple(
                RunArtifact.from_dict(artifact)
                for artifact in payload.get("artifacts", ())
            ),
            session_manifest_ref=payload.get("session_manifest_ref"),
            failure_stage=payload.get("failure_stage"),
            failure_reason_code=payload.get("failure_reason_code"),
            failure_reason=payload.get("failure_reason"),
        )

    @classmethod
    def from_json(cls, payload: str) -> "RunManifest":
        data = json.loads(payload)
        if not isinstance(data, Mapping):
            issue = ManifestValidationIssue(
                code="INVALID_TYPE",
                field_path="$",
                message="run manifest JSON must be an object",
            )
            raise RunManifestValidationError((issue,))
        return cls.from_dict(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_manifest_schema_version": self.run_manifest_schema_version,
            "run_id": self.run_id,
            "session_id": self.session_id,
            "scenario": self.scenario.to_dict(),
            "target_device_id": self.target_device_id,
            "source_ip": self.source_ip,
            "execution_node": self.execution_node.to_dict(),
            "evaluation_scope": self.evaluation_scope.value,
            "is_active": self.is_active,
            "started_at": _format_utc_datetime(self.started_at),
            "attack_started_at": _format_optional_datetime(self.attack_started_at),
            "observation_deadline_at": _format_utc_datetime(
                self.observation_deadline_at,
            ),
            "ended_at": _format_optional_datetime(self.ended_at),
            "external_observations": {
                name: _format_utc_datetime(value)
                for name, value in self.external_observations.items()
            },
            "expected_outcome": self.expected_outcome.to_dict(),
            "statuses": self.statuses.to_dict(),
            "matched_ids": self.matched_ids.to_dict(),
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "session_manifest_ref": (
                None
                if self.session_manifest_ref is None
                else self.session_manifest_ref.to_dict()
            ),
            "failure_stage": self.failure_stage,
            "failure_reason_code": self.failure_reason_code,
            "failure_reason": self.failure_reason,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


def is_supported_run_manifest_schema_version(value: str) -> bool:
    return value in SUPPORTED_RUN_MANIFEST_SCHEMA_VERSIONS


def require_supported_run_manifest_schema_version(value: str) -> str:
    if not is_supported_run_manifest_schema_version(value):
        raise ValueError(f"unsupported run manifest schema version: {value!r}")
    return value


def run_manifest_sha256(manifest: RunManifest | Mapping[str, Any] | str) -> str:
    """Return the canonical digest used by run-manifest.json.sha256."""
    if isinstance(manifest, RunManifest):
        payload = manifest.to_json()
    elif isinstance(manifest, Mapping):
        payload = json.dumps(
            manifest,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    else:
        payload = manifest
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validate_run_manifest_dict(payload: Mapping[str, Any]) -> ManifestValidationResult:
    errors: list[ManifestValidationIssue] = []
    if not isinstance(payload, Mapping):
        return ManifestValidationResult(
            (
                ManifestValidationIssue(
                    code="INVALID_TYPE",
                    field_path="$",
                    message="run manifest must be a mapping",
                ),
            )
        )

    _validate_allowed_keys(payload, _RUN_MANIFEST_FIELDS, "$", errors)
    for field_name in _REQUIRED_RUN_MANIFEST_FIELDS:
        if field_name not in payload:
            _add_error(errors, "MISSING_FIELD", field_name, "field is required")

    _validate_schema_version(payload.get("run_manifest_schema_version"), errors)
    _validate_non_empty_string(payload.get("run_id"), "run_id", errors)
    _validate_optional_string(payload.get("session_id"), "session_id", errors)
    _validate_optional_string(
        payload.get("target_device_id"),
        "target_device_id",
        errors,
    )
    _validate_optional_ip_address(payload.get("source_ip"), "source_ip", errors)
    _validate_enum_value(
        EvaluationScope,
        payload.get("evaluation_scope"),
        "evaluation_scope",
        errors,
    )
    _validate_bool(payload.get("is_active"), "is_active", errors)

    _validate_scenario(payload.get("scenario"), errors)
    _validate_execution_node(payload.get("execution_node"), errors)
    _validate_expected_outcome(payload.get("expected_outcome"), errors)
    _validate_statuses(payload.get("statuses"), errors)
    _validate_matched_ids(payload.get("matched_ids"), errors)
    _validate_artifacts(payload.get("artifacts"), errors)
    _validate_observations(payload.get("external_observations"), errors)
    _validate_manifest_reference(
        payload.get("session_manifest_ref"),
        "session_manifest_ref",
        errors,
    )
    _validate_optional_string(payload.get("failure_stage"), "failure_stage", errors)
    _validate_optional_string(
        payload.get("failure_reason_code"),
        "failure_reason_code",
        errors,
    )
    _validate_optional_string(payload.get("failure_reason"), "failure_reason", errors)

    started_at = _validate_datetime(payload.get("started_at"), "started_at", errors)
    observation_deadline_at = _validate_datetime(
        payload.get("observation_deadline_at"),
        "observation_deadline_at",
        errors,
    )
    attack_started_at = _validate_optional_datetime(
        payload.get("attack_started_at"),
        "attack_started_at",
        errors,
    )
    ended_at = _validate_optional_datetime(payload.get("ended_at"), "ended_at", errors)
    if started_at is not None and observation_deadline_at is not None:
        if observation_deadline_at < started_at:
            _add_error(
                errors,
                "INVALID_TIME_ORDER",
                "observation_deadline_at",
                "must not be earlier than started_at",
            )
        if attack_started_at is not None and attack_started_at < started_at:
            _add_error(
                errors,
                "INVALID_TIME_ORDER",
                "attack_started_at",
                "must not be earlier than started_at",
            )
        if (
            attack_started_at is not None
            and attack_started_at > observation_deadline_at
        ):
            _add_error(
                errors,
                "INVALID_TIME_ORDER",
                "attack_started_at",
                "must not be later than observation_deadline_at",
            )
    if started_at is not None and ended_at is not None and ended_at < started_at:
        _add_error(
            errors,
            "INVALID_TIME_ORDER",
            "ended_at",
            "must not be earlier than started_at",
        )

    expected = payload.get("expected_outcome")
    if isinstance(expected, Mapping):
        if expected.get("evaluation_scope") != payload.get("evaluation_scope"):
            _add_error(
                errors,
                "EVALUATION_SCOPE_MISMATCH",
                "expected_outcome.evaluation_scope",
                "must match evaluation_scope",
            )

    _validate_pre_capture_failure_payload(payload, errors)

    return ManifestValidationResult(tuple(errors))


def validate_single_active_run(
    manifests: Iterable[RunManifest],
) -> ManifestValidationResult:
    active_run_ids = [manifest.run_id for manifest in manifests if manifest.is_active]
    if len(active_run_ids) <= 1:
        return ManifestValidationResult()
    return ManifestValidationResult(
        (
            ManifestValidationIssue(
                code="MULTIPLE_ACTIVE_RUNS",
                field_path="manifests",
                message=(
                    "at most one run may be active at a time: "
                    f"{sorted(active_run_ids)}"
                ),
            ),
        )
    )


def require_single_active_run(manifests: Iterable[RunManifest]) -> None:
    result = validate_single_active_run(manifests)
    if not result.is_valid:
        raise RunManifestValidationError(result.errors)


def _require_pre_capture_failure_invariant(manifest: RunManifest) -> None:
    identity_missing = (
        manifest.session_id is None
        or manifest.target_device_id is None
        or manifest.source_ip is None
    )
    if not identity_missing:
        return
    missing = [
        field_name
        for field_name in ("failure_stage", "failure_reason_code", "failure_reason")
        if getattr(manifest, field_name) is None
    ]
    if missing:
        raise ValueError(
            "pre-capture failure runs with null session/device/source fields "
            f"must include {', '.join(missing)}"
        )
    if manifest.is_active:
        raise ValueError("pre-capture failure runs must not be active")
    if manifest.statuses.final_status == ManifestStatus.SUCCESS:
        raise ValueError("pre-capture failure runs must not have SUCCESS final_status")


def _validate_pre_capture_failure_payload(
    payload: Mapping[str, Any],
    errors: list[ManifestValidationIssue],
) -> None:
    identity_missing = any(
        payload.get(field_name) is None
        for field_name in ("session_id", "target_device_id", "source_ip")
    )
    if not identity_missing:
        return
    for field_name in ("failure_stage", "failure_reason_code", "failure_reason"):
        if not isinstance(payload.get(field_name), str) or not payload[field_name].strip():
            _add_error(
                errors,
                "PRE_CAPTURE_FAILURE_REASON_REQUIRED",
                field_name,
                "pre-capture failure runs with null session/device/source fields "
                "must include failure stage, reason code, and reason",
            )
    if payload.get("is_active") is True:
        _add_error(
            errors,
            "PRE_CAPTURE_FAILURE_ACTIVE",
            "is_active",
            "pre-capture failure runs must not be active",
        )
    statuses = payload.get("statuses")
    if (
        isinstance(statuses, Mapping)
        and statuses.get("final_status") == ManifestStatus.SUCCESS.value
    ):
        _add_error(
            errors,
            "PRE_CAPTURE_FAILURE_SUCCESS",
            "statuses.final_status",
            "pre-capture failure runs must not have SUCCESS final_status",
        )


_STATUS_FIELDS = (
    "scenario_status",
    "detection_status",
    "trust_status",
    "firewall_status",
    "block_status",
    "data_status",
    "final_status",
)

_MATCHED_ID_FIELDS = (
    "detection_event_ids",
    "trust_score_history_ids",
    "firewall_rule_ids",
    "firewall_release_request_ids",
    "trigger_event_ids",
)

_RUN_MANIFEST_FIELDS = frozenset(
    {
        "run_manifest_schema_version",
        "run_id",
        "session_id",
        "scenario",
        "target_device_id",
        "source_ip",
        "execution_node",
        "evaluation_scope",
        "is_active",
        "started_at",
        "attack_started_at",
        "observation_deadline_at",
        "ended_at",
        "external_observations",
        "expected_outcome",
        "statuses",
        "matched_ids",
        "artifacts",
        "session_manifest_ref",
        "failure_stage",
        "failure_reason_code",
        "failure_reason",
    }
)

_REQUIRED_RUN_MANIFEST_FIELDS = frozenset(
    {
        "run_manifest_schema_version",
        "run_id",
        "session_id",
        "scenario",
        "target_device_id",
        "source_ip",
        "execution_node",
        "evaluation_scope",
        "is_active",
        "started_at",
        "observation_deadline_at",
        "expected_outcome",
        "statuses",
    }
)

_SCENARIO_FIELDS = frozenset(
    {
        "scenario_id",
        "scenario_name",
        "scenario_version",
    }
)
_EXECUTION_NODE_FIELDS = frozenset({"node_id", "registered", "hostname"})
_EXPECTED_OUTCOME_FIELDS = frozenset(
    {
        "expected_event_types",
        "detection_expected",
        "trust_score_change_expected",
        "firewall_expected",
        "block_expected",
        "evaluation_scope",
    }
)
_ARTIFACT_FIELDS = frozenset(
    {
        "artifact_type",
        "relative_path",
        "size_bytes",
        "sha256",
    }
)
_MANIFEST_REF_FIELDS = frozenset({"relative_path", "schema_version", "sha256"})


def _add_error(
    errors: list[ManifestValidationIssue],
    code: str,
    field_path: str,
    message: str,
) -> None:
    errors.append(ManifestValidationIssue(code, field_path, message))


def _validate_allowed_keys(
    payload: Mapping[str, Any],
    allowed: frozenset[str],
    field_path: str,
    errors: list[ManifestValidationIssue],
) -> None:
    for key in sorted(set(payload) - allowed):
        _add_error(errors, "UNKNOWN_FIELD", f"{field_path}.{key}", "unknown field")


def _validate_schema_version(
    value: Any,
    errors: list[ManifestValidationIssue],
) -> None:
    if not isinstance(value, str) or not value.strip():
        _add_error(
            errors,
            "INVALID_SCHEMA_VERSION",
            "run_manifest_schema_version",
            "must be a non-empty string",
        )
        return
    if not is_supported_run_manifest_schema_version(value):
        _add_error(
            errors,
            "UNSUPPORTED_SCHEMA_VERSION",
            "run_manifest_schema_version",
            f"unsupported schema version: {value!r}",
        )


def _validate_scenario(
    value: Any,
    errors: list[ManifestValidationIssue],
) -> None:
    if not isinstance(value, Mapping):
        _add_error(errors, "INVALID_TYPE", "scenario", "must be an object")
        return
    _validate_allowed_keys(value, _SCENARIO_FIELDS, "scenario", errors)
    _validate_non_empty_string(value.get("scenario_id"), "scenario.scenario_id", errors)
    _validate_optional_string(
        value.get("scenario_name"),
        "scenario.scenario_name",
        errors,
    )
    _validate_optional_string(
        value.get("scenario_version"),
        "scenario.scenario_version",
        errors,
    )


def _validate_execution_node(
    value: Any,
    errors: list[ManifestValidationIssue],
) -> None:
    if not isinstance(value, Mapping):
        _add_error(errors, "INVALID_TYPE", "execution_node", "must be an object")
        return
    _validate_allowed_keys(value, _EXECUTION_NODE_FIELDS, "execution_node", errors)
    _validate_non_empty_string(
        value.get("node_id"),
        "execution_node.node_id",
        errors,
    )
    _validate_bool(value.get("registered"), "execution_node.registered", errors)
    _validate_optional_string(
        value.get("hostname"),
        "execution_node.hostname",
        errors,
    )


def _validate_expected_outcome(
    value: Any,
    errors: list[ManifestValidationIssue],
) -> None:
    if not isinstance(value, Mapping):
        _add_error(errors, "INVALID_TYPE", "expected_outcome", "must be an object")
        return
    _validate_allowed_keys(
        value,
        _EXPECTED_OUTCOME_FIELDS,
        "expected_outcome",
        errors,
    )
    event_types = value.get("expected_event_types")
    if not isinstance(event_types, Sequence) or isinstance(event_types, (str, bytes)):
        _add_error(
            errors,
            "INVALID_TYPE",
            "expected_outcome.expected_event_types",
            "must be a list of event type strings",
        )
    else:
        for index, event_type in enumerate(event_types):
            field_path = f"expected_outcome.expected_event_types[{index}]"
            if not isinstance(event_type, str) or not event_type.strip():
                _add_error(
                    errors,
                    "INVALID_EVENT_TYPE",
                    field_path,
                    "must be a non-empty string",
                )
            elif event_type not in SCORE_DELTA_BY_EVENT:
                _add_error(
                    errors,
                    "UNKNOWN_EVENT_TYPE",
                    field_path,
                    f"unsupported event_type: {event_type!r}",
                )
    for field_name in (
        "detection_expected",
        "trust_score_change_expected",
        "firewall_expected",
        "block_expected",
    ):
        _validate_bool(
            value.get(field_name),
            f"expected_outcome.{field_name}",
            errors,
        )
    _validate_enum_value(
        EvaluationScope,
        value.get("evaluation_scope"),
        "expected_outcome.evaluation_scope",
        errors,
    )


def _validate_statuses(
    value: Any,
    errors: list[ManifestValidationIssue],
) -> None:
    if not isinstance(value, Mapping):
        _add_error(errors, "INVALID_TYPE", "statuses", "must be an object")
        return
    _validate_allowed_keys(value, frozenset(_STATUS_FIELDS), "statuses", errors)
    for field_name in _STATUS_FIELDS:
        _validate_enum_value(
            ManifestStatus,
            value.get(field_name),
            f"statuses.{field_name}",
            errors,
        )


def _validate_matched_ids(
    value: Any,
    errors: list[ManifestValidationIssue],
) -> None:
    if value is None:
        return
    if not isinstance(value, Mapping):
        _add_error(errors, "INVALID_TYPE", "matched_ids", "must be an object")
        return
    _validate_allowed_keys(value, frozenset(_MATCHED_ID_FIELDS), "matched_ids", errors)
    for field_name in _MATCHED_ID_FIELDS:
        if field_name in value:
            _validate_optional_ids(
                value[field_name],
                f"matched_ids.{field_name}",
                errors,
            )


def _validate_artifacts(
    value: Any,
    errors: list[ManifestValidationIssue],
) -> None:
    if value is None:
        return
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        _add_error(errors, "INVALID_TYPE", "artifacts", "must be a list")
        return
    for index, artifact in enumerate(value):
        prefix = f"artifacts[{index}]"
        if not isinstance(artifact, Mapping):
            _add_error(errors, "INVALID_TYPE", prefix, "must be an object")
            continue
        _validate_allowed_keys(artifact, _ARTIFACT_FIELDS, prefix, errors)
        _validate_non_empty_string(
            artifact.get("artifact_type"),
            f"{prefix}.artifact_type",
            errors,
        )
        _validate_relative_path(
            artifact.get("relative_path"),
            f"{prefix}.relative_path",
            errors,
        )
        _validate_non_negative_int(
            artifact.get("size_bytes"),
            f"{prefix}.size_bytes",
            errors,
        )
        _validate_sha256(artifact.get("sha256"), f"{prefix}.sha256", errors)


def _validate_manifest_reference(
    value: Any,
    field_path: str,
    errors: list[ManifestValidationIssue],
) -> None:
    if value is None:
        return
    if not isinstance(value, Mapping):
        _add_error(errors, "INVALID_TYPE", field_path, "must be an object")
        return
    _validate_allowed_keys(value, _MANIFEST_REF_FIELDS, field_path, errors)
    _validate_relative_path(
        value.get("relative_path"),
        f"{field_path}.relative_path",
        errors,
    )
    _validate_non_empty_string(
        value.get("schema_version"),
        f"{field_path}.schema_version",
        errors,
    )
    _validate_sha256(value.get("sha256"), f"{field_path}.sha256", errors)


def _validate_observations(
    value: Any,
    errors: list[ManifestValidationIssue],
) -> None:
    if value is None:
        return
    if not isinstance(value, Mapping):
        _add_error(
            errors,
            "INVALID_TYPE",
            "external_observations",
            "must be an object",
        )
        return
    for name, timestamp in value.items():
        if not isinstance(name, str) or not name.strip():
            _add_error(
                errors,
                "INVALID_FIELD_NAME",
                "external_observations",
                "observation names must be non-empty strings",
            )
            continue
        _validate_datetime(
            timestamp,
            f"external_observations.{name.strip()}",
            errors,
        )


def _validate_optional_ids(
    value: Any,
    field_path: str,
    errors: list[ManifestValidationIssue],
) -> None:
    if value is None:
        return
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        _add_error(errors, "INVALID_TYPE", field_path, "must be null or a list")
        return
    for index, row_id in enumerate(value):
        if isinstance(row_id, bool) or not isinstance(row_id, int) or row_id <= 0:
            _add_error(
                errors,
                "INVALID_ID",
                f"{field_path}[{index}]",
                "must be a positive integer",
            )


def _validate_non_empty_string(
    value: Any,
    field_path: str,
    errors: list[ManifestValidationIssue],
) -> None:
    if not isinstance(value, str) or not value.strip():
        _add_error(errors, "INVALID_STRING", field_path, "must be a non-empty string")


def _validate_optional_string(
    value: Any,
    field_path: str,
    errors: list[ManifestValidationIssue],
) -> None:
    if value is None:
        return
    _validate_non_empty_string(value, field_path, errors)


def _validate_bool(
    value: Any,
    field_path: str,
    errors: list[ManifestValidationIssue],
) -> None:
    if not isinstance(value, bool):
        _add_error(errors, "INVALID_BOOL", field_path, "must be a boolean")


def _validate_ip_address(
    value: Any,
    field_path: str,
    errors: list[ManifestValidationIssue],
) -> None:
    if not isinstance(value, str) or not value.strip():
        _add_error(errors, "INVALID_IP", field_path, "must be a non-empty IP address")
        return
    try:
        ip_address(value.strip())
    except ValueError:
        _add_error(errors, "INVALID_IP", field_path, "must be a valid IP address")


def _validate_optional_ip_address(
    value: Any,
    field_path: str,
    errors: list[ManifestValidationIssue],
) -> None:
    if value is None:
        return
    _validate_ip_address(value, field_path, errors)


def _validate_enum_value(
    enum_type: type[Enum],
    value: Any,
    field_path: str,
    errors: list[ManifestValidationIssue],
) -> None:
    actual = value.value if isinstance(value, enum_type) else value
    if actual not in {member.value for member in enum_type}:
        _add_error(
            errors,
            "INVALID_ENUM",
            field_path,
            f"must be one of {[member.value for member in enum_type]}",
        )


def _validate_datetime(
    value: Any,
    field_path: str,
    errors: list[ManifestValidationIssue],
) -> datetime | None:
    try:
        return _require_utc_datetime(value, field_path)
    except (TypeError, ValueError) as exc:
        _add_error(errors, "INVALID_TIMESTAMP", field_path, str(exc))
        return None


def _validate_optional_datetime(
    value: Any,
    field_path: str,
    errors: list[ManifestValidationIssue],
) -> datetime | None:
    if value is None:
        return None
    return _validate_datetime(value, field_path, errors)


def _validate_sha256(
    value: Any,
    field_path: str,
    errors: list[ManifestValidationIssue],
) -> None:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        _add_error(
            errors,
            "INVALID_SHA256",
            field_path,
            "must be a 64-character hexadecimal string",
        )


def _validate_relative_path(
    value: Any,
    field_path: str,
    errors: list[ManifestValidationIssue],
) -> None:
    try:
        _normalize_relative_path(value, field_path)
    except ValueError as exc:
        _add_error(errors, "INVALID_RELATIVE_PATH", field_path, str(exc))


def _validate_non_negative_int(
    value: Any,
    field_path: str,
    errors: list[ManifestValidationIssue],
) -> None:
    try:
        _require_non_negative_int(value, field_path)
    except ValueError as exc:
        _add_error(errors, "INVALID_SIZE", field_path, str(exc))


def _require_non_empty_string(value: Any, field_path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_path} must be a non-empty string")
    return value.strip()


def _normalize_optional_string(value: Any, field_path: str) -> str | None:
    if value is None:
        return None
    return _require_non_empty_string(value, field_path)


def _require_bool(value: Any, field_path: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_path} must be a boolean")
    return value


def _normalize_ip_address(value: Any, field_path: str) -> str:
    text = _require_non_empty_string(value, field_path)
    try:
        return str(ip_address(text))
    except ValueError as exc:
        raise ValueError(f"{field_path} must be a valid IP address") from exc


def _normalize_optional_ip_address(value: Any, field_path: str) -> str | None:
    if value is None:
        return None
    return _normalize_ip_address(value, field_path)


def _coerce_enum(enum_type: type[Enum], value: Any, field_path: str) -> Any:
    if isinstance(value, enum_type):
        return value
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ValueError(
            f"{field_path} must be one of {[member.value for member in enum_type]}"
        ) from exc


def _require_utc_datetime(value: Any, field_path: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(f"{field_path} must be an RFC 3339 timestamp") from exc
    else:
        raise ValueError(f"{field_path} must be a datetime or timestamp string")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_path} must be timezone-aware UTC")
    if parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{field_path} must use UTC offset")
    return parsed.astimezone(timezone.utc)


def _normalize_optional_datetime(value: Any, field_path: str) -> datetime | None:
    if value is None:
        return None
    return _require_utc_datetime(value, field_path)


def _format_utc_datetime(value: datetime) -> str:
    normalized = _require_utc_datetime(value, "timestamp")
    timespec = "microseconds" if normalized.microsecond else "seconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def _format_optional_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _format_utc_datetime(value)


def _normalize_observations(
    value: Mapping[str, datetime] | None,
) -> dict[str, datetime]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("external_observations must be a mapping")
    normalized: dict[str, datetime] = {}
    for name, timestamp in value.items():
        key = _require_non_empty_string(name, "external_observations key")
        normalized[key] = _require_utc_datetime(
            timestamp,
            f"external_observations.{key}",
        )
    return {key: normalized[key] for key in sorted(normalized)}


def _normalize_event_types(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError("expected_event_types must be a sequence of strings")
    event_types: set[str] = set()
    for event_type in values:
        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("expected_event_types must contain non-empty strings")
        event_type = event_type.strip()
        if event_type not in SCORE_DELTA_BY_EVENT:
            raise ValueError(f"unsupported event_type: {event_type!r}")
        event_types.add(event_type)
    return tuple(sorted(event_types))


def _normalize_optional_ids(
    values: Sequence[int] | None,
    field_path: str,
) -> tuple[int, ...] | None:
    if values is None:
        return None
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{field_path} must be null or a sequence of integer IDs")
    normalized: set[int] = set()
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{field_path} must contain positive integer IDs")
        normalized.add(value)
    return tuple(sorted(normalized))


def _require_non_negative_int(value: Any, field_path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_path} must be a non-negative integer")
    if value < 0:
        raise ValueError(f"{field_path} must be non-negative")
    return value


def _normalize_sha256(value: Any, field_path: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_path} must be a 64-character hexadecimal string")
    return value.lower()


def _normalize_relative_path(value: Any, field_path: str) -> str:
    text = _require_non_empty_string(value, field_path).replace("\\", "/")
    if text.startswith("/") or text.startswith("//") or _WINDOWS_DRIVE_PATTERN.match(text):
        raise ValueError(f"{field_path} must be a relative path")
    raw_parts = text.split("/")
    if any(part == ".." for part in raw_parts):
        raise ValueError(f"{field_path} must not contain '..'")
    parts = [part for part in raw_parts if part not in {"", "."}]
    if not parts:
        raise ValueError(f"{field_path} must point to a file")
    return "/".join(parts)
