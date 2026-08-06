"""Phase 5 Verified Collection Manifest contract.

This module expresses one fact and nothing more:

    수집 당시 자동 Run Manifest는 생성되지 않았지만, 보존된 DB Snapshot·PCAP·QC·
    Split·Firmware·Source 증적을 이후 읽기 전용으로 검증해 Dataset Provenance로
    이관했다.

It deliberately does NOT claim that a Scenario Runner executed, that an attack was
launched automatically, or that a Run Manifest existed at capture time. Those
claims would be false for the 16 normal Sessions and Session 53, which were
collected manually with ESP32 hardware before the Dataset v2 contract landed.

The module is pure: no database, no filesystem writes, no network. It only reads
the Collection Manifest and the Evidence files it references, so it can be reused
by the importer, by the Dataset v2 loader, and by tests without side effects.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
from ipaddress import IPv4Address, ip_address
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any
from uuid import UUID


VERIFIED_COLLECTION_SCHEMA_VERSION = "phase5-verified-collection-v1"
VERIFIED_COLLECTION_SHA256_SIDECAR_SUFFIX = ".sha256"
VERIFIED_COLLECTION_MANIFEST_FILENAME = "verified-collection-manifest.json"

# 정상 Profile은 Scenario Runner Registry 대상이 아니므로 Registry로 조회하지
# 않는다. Verified Collection 전용 허용 목록만 사용한다 (설계 9.1 절).
NORMAL_COLLECTION_SCENARIOS = (
    "normal_stable",
    "normal_interval_jitter",
    "normal_payload_variation",
    "normal_combined_variation",
)
ATTACK_COLLECTION_SCENARIOS = ("packet_rate_flood",)
ALLOWED_COLLECTION_SCENARIOS = frozenset(
    NORMAL_COLLECTION_SCENARIOS + ATTACK_COLLECTION_SCENARIOS
)

NORMAL_LABEL = "normal"
ATTACK_LABEL = "attack"
VALID_TRAFFIC_LABELS = frozenset({NORMAL_LABEL, ATTACK_LABEL})
VALID_SPLITS = frozenset({"train", "validation", "test"})

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PORTABLE_PATH_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_WINDOWS_RESERVED_PATH_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }
)


class ProvenanceMode(str, Enum):
    """How this Session's provenance was established."""

    VERIFIED_RETROSPECTIVE_IMPORT = "VERIFIED_RETROSPECTIVE_IMPORT"


class CollectionMethod(str, Enum):
    """How the Session was actually collected."""

    MANUAL_HARDWARE = "MANUAL_HARDWARE"


class PayloadSchemaProvenance(str, Enum):
    """Where the recorded Payload Schema Version came from.

    FIRMWARE_REPORTED: the collecting Firmware itself logged this version.
    RETROSPECTIVE_SOURCE_AND_PCAP_VERIFICATION: the version string was assigned
        afterwards by verifying Firmware source and captured PCAP bytes. The
        Firmware never emitted it. Session 53 uses this.
    """

    FIRMWARE_REPORTED = "FIRMWARE_REPORTED"
    RETROSPECTIVE_SOURCE_AND_PCAP_VERIFICATION = (
        "RETROSPECTIVE_SOURCE_AND_PCAP_VERIFICATION"
    )


@dataclass(frozen=True)
class VerifiedCollectionArtifact:
    """One Evidence file recorded with its exact byte size and SHA256."""

    relative_path: str
    artifact_type: str
    size_bytes: int
    sha256: str

    _FIELDS = ("relative_path", "artifact_type", "size_bytes", "sha256")

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "relative_path",
            normalize_relative_path(self.relative_path, "artifacts[].relative_path"),
        )
        object.__setattr__(
            self,
            "artifact_type",
            require_identifier(self.artifact_type, "artifacts[].artifact_type"),
        )
        object.__setattr__(
            self,
            "size_bytes",
            require_non_negative_int(self.size_bytes, "artifacts[].size_bytes"),
        )
        object.__setattr__(
            self,
            "sha256",
            normalize_sha256(self.sha256, "artifacts[].sha256"),
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "VerifiedCollectionArtifact":
        _require_exact_fields(payload, cls._FIELDS, "artifacts[]")
        return cls(
            relative_path=payload["relative_path"],
            artifact_type=payload["artifact_type"],
            size_bytes=payload["size_bytes"],
            sha256=payload["sha256"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "artifact_type": self.artifact_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class VerifiedCollectionObservation:
    """Packet counts observed at each layer, kept separate on purpose.

    `sender_reported_packets` is what the ESP32 counted as successful
    `udp.endPacket()` calls. That is not a receive acknowledgement, so it may
    legitimately exceed what the Gateway captured. The Dataset Ground Truth is
    `gateway_observed_packets`, which must equal `feature_packet_count`.
    """

    feature_packet_count: int
    gateway_observed_packets: int | None = None
    sender_reported_packets: int | None = None
    observation_gap_packets: int | None = None
    observation_gap_cause: str | None = None
    gateway_first_attack_packet_at: datetime | None = None

    _FIELDS = (
        "feature_packet_count",
        "gateway_observed_packets",
        "sender_reported_packets",
        "observation_gap_packets",
        "observation_gap_cause",
        "gateway_first_attack_packet_at",
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "feature_packet_count",
            require_non_negative_int(
                self.feature_packet_count,
                "observation.feature_packet_count",
            ),
        )
        for field_name in ("gateway_observed_packets", "sender_reported_packets"):
            object.__setattr__(
                self,
                field_name,
                require_optional_non_negative_int(
                    getattr(self, field_name),
                    f"observation.{field_name}",
                ),
            )
        object.__setattr__(
            self,
            "observation_gap_packets",
            require_optional_non_negative_int(
                self.observation_gap_packets,
                "observation.observation_gap_packets",
            ),
        )
        object.__setattr__(
            self,
            "observation_gap_cause",
            None
            if self.observation_gap_cause is None
            else require_identifier(
                self.observation_gap_cause,
                "observation.observation_gap_cause",
            ),
        )
        object.__setattr__(
            self,
            "gateway_first_attack_packet_at",
            normalize_optional_utc(
                self.gateway_first_attack_packet_at,
                "observation.gateway_first_attack_packet_at",
            ),
        )

        # Dataset Ground Truth는 Gateway가 실제 관측하고 Feature와 일치한 수다.
        if (
            self.gateway_observed_packets is not None
            and self.gateway_observed_packets != self.feature_packet_count
        ):
            raise ValueError(
                "observation.feature_packet_count must equal "
                "observation.gateway_observed_packets: "
                f"gateway={self.gateway_observed_packets}, "
                f"feature={self.feature_packet_count}"
            )
        if self.observation_gap_packets is not None:
            if (
                self.sender_reported_packets is None
                or self.gateway_observed_packets is None
            ):
                raise ValueError(
                    "observation.observation_gap_packets requires both "
                    "sender_reported_packets and gateway_observed_packets"
                )
            expected_gap = (
                self.sender_reported_packets - self.gateway_observed_packets
            )
            if self.observation_gap_packets != expected_gap:
                raise ValueError(
                    "observation.observation_gap_packets must equal "
                    "sender_reported_packets - gateway_observed_packets: "
                    f"expected={expected_gap}, "
                    f"actual={self.observation_gap_packets}"
                )
            if self.observation_gap_packets and self.observation_gap_cause is None:
                # 원인을 단정하지 않더라도 UNRESOLVED로 명시해야 한다.
                raise ValueError(
                    "observation.observation_gap_cause is required when "
                    "observation_gap_packets is non-zero"
                )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "VerifiedCollectionObservation":
        _require_exact_fields(payload, cls._FIELDS, "observation")
        return cls(
            feature_packet_count=payload["feature_packet_count"],
            gateway_observed_packets=payload["gateway_observed_packets"],
            sender_reported_packets=payload["sender_reported_packets"],
            observation_gap_packets=payload["observation_gap_packets"],
            observation_gap_cause=payload["observation_gap_cause"],
            gateway_first_attack_packet_at=payload["gateway_first_attack_packet_at"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature_packet_count": self.feature_packet_count,
            "gateway_observed_packets": self.gateway_observed_packets,
            "sender_reported_packets": self.sender_reported_packets,
            "observation_gap_packets": self.observation_gap_packets,
            "observation_gap_cause": self.observation_gap_cause,
            "gateway_first_attack_packet_at": format_optional_utc(
                self.gateway_first_attack_packet_at
            ),
        }


@dataclass(frozen=True, kw_only=True)
class VerifiedCollectionManifest:
    """Retrospectively verified provenance for one manual Capture Session."""

    run_id: str
    session_id: str
    collection_slot_id: str
    source_capture_group_id: str
    split: str
    traffic_label: str
    scenario: str
    collection_device_id: str
    target_device_id: str | None
    target_source_ip: str | None
    included_device_ids: tuple[str, ...]
    background_traffic_present: bool
    firmware_version: str
    payload_schema_version: str
    payload_schema_provenance: PayloadSchemaProvenance
    firmware_reported_payload_schema_version: str | None
    normal_policy_version: str
    capture_source_commit_sha: str
    verification_commit_sha: str
    capture_interface: str
    capture_filter: str
    started_at: datetime
    first_window_start: datetime
    ended_at: datetime
    verified_at: datetime
    segment_count: int
    processed_segment_count: int
    empty_segment_count: int
    eligible_feature_row_count: int
    db_snapshot_sha256: str
    observation: VerifiedCollectionObservation
    artifacts: tuple[VerifiedCollectionArtifact, ...]
    schema_version: str = VERIFIED_COLLECTION_SCHEMA_VERSION
    provenance_mode: ProvenanceMode = ProvenanceMode.VERIFIED_RETROSPECTIVE_IMPORT
    collection_method: CollectionMethod = CollectionMethod.MANUAL_HARDWARE

    _FIELDS = (
        "schema_version",
        "provenance_mode",
        "collection_method",
        "run_id",
        "session_id",
        "collection_slot_id",
        "source_capture_group_id",
        "split",
        "traffic_label",
        "scenario",
        "collection_device_id",
        "target_device_id",
        "target_source_ip",
        "included_device_ids",
        "background_traffic_present",
        "firmware_version",
        "payload_schema_version",
        "payload_schema_provenance",
        "firmware_reported_payload_schema_version",
        "normal_policy_version",
        "capture_source_commit_sha",
        "verification_commit_sha",
        "capture_interface",
        "capture_filter",
        "started_at",
        "first_window_start",
        "ended_at",
        "verified_at",
        "segment_count",
        "processed_segment_count",
        "empty_segment_count",
        "eligible_feature_row_count",
        "db_snapshot_sha256",
        "observation",
        "artifacts",
    )

    def __post_init__(self) -> None:
        if self.schema_version != VERIFIED_COLLECTION_SCHEMA_VERSION:
            raise ValueError(
                "unsupported Verified Collection schema_version: "
                f"{self.schema_version!r}"
            )
        object.__setattr__(
            self,
            "provenance_mode",
            coerce_enum(ProvenanceMode, self.provenance_mode, "provenance_mode"),
        )
        object.__setattr__(
            self,
            "collection_method",
            coerce_enum(CollectionMethod, self.collection_method, "collection_method"),
        )
        for field_name in (
            "run_id",
            "collection_slot_id",
            "collection_device_id",
            "firmware_version",
            "payload_schema_version",
            "normal_policy_version",
            "capture_interface",
        ):
            object.__setattr__(
                self,
                field_name,
                require_identifier(getattr(self, field_name), field_name),
            )
        object.__setattr__(
            self,
            "session_id",
            require_canonical_uuid4(self.session_id, "session_id"),
        )
        object.__setattr__(
            self,
            "source_capture_group_id",
            require_canonical_uuid4(
                self.source_capture_group_id,
                "source_capture_group_id",
            ),
        )
        object.__setattr__(
            self,
            "capture_filter",
            require_non_empty_string(self.capture_filter, "capture_filter"),
        )
        split = require_non_empty_string(self.split, "split")
        if split not in VALID_SPLITS:
            raise ValueError(f"invalid split: {split!r}")
        object.__setattr__(self, "split", split)
        traffic_label = require_non_empty_string(self.traffic_label, "traffic_label")
        if traffic_label not in VALID_TRAFFIC_LABELS:
            raise ValueError(f"invalid traffic_label: {traffic_label!r}")
        object.__setattr__(self, "traffic_label", traffic_label)
        scenario = require_identifier(self.scenario, "scenario")
        if scenario not in ALLOWED_COLLECTION_SCENARIOS:
            raise ValueError(
                "scenario is not an allowed Verified Collection scenario: "
                f"{scenario!r}"
            )
        object.__setattr__(self, "scenario", scenario)
        object.__setattr__(
            self,
            "target_device_id",
            None
            if self.target_device_id is None
            else require_identifier(self.target_device_id, "target_device_id"),
        )
        object.__setattr__(
            self,
            "target_source_ip",
            normalize_optional_ipv4(self.target_source_ip, "target_source_ip"),
        )
        object.__setattr__(
            self,
            "included_device_ids",
            normalize_device_ids(self.included_device_ids, "included_device_ids"),
        )
        object.__setattr__(
            self,
            "background_traffic_present",
            require_bool(
                self.background_traffic_present,
                "background_traffic_present",
            ),
        )
        object.__setattr__(
            self,
            "payload_schema_provenance",
            coerce_enum(
                PayloadSchemaProvenance,
                self.payload_schema_provenance,
                "payload_schema_provenance",
            ),
        )
        object.__setattr__(
            self,
            "firmware_reported_payload_schema_version",
            None
            if self.firmware_reported_payload_schema_version is None
            else require_identifier(
                self.firmware_reported_payload_schema_version,
                "firmware_reported_payload_schema_version",
            ),
        )
        for field_name in ("capture_source_commit_sha", "verification_commit_sha"):
            object.__setattr__(
                self,
                field_name,
                normalize_sha1(getattr(self, field_name), field_name),
            )
        object.__setattr__(
            self,
            "db_snapshot_sha256",
            normalize_sha256(self.db_snapshot_sha256, "db_snapshot_sha256"),
        )
        for field_name in (
            "started_at",
            "first_window_start",
            "ended_at",
            "verified_at",
        ):
            object.__setattr__(
                self,
                field_name,
                require_utc(getattr(self, field_name), field_name),
            )
        for field_name in (
            "segment_count",
            "processed_segment_count",
            "empty_segment_count",
            "eligible_feature_row_count",
        ):
            object.__setattr__(
                self,
                field_name,
                require_non_negative_int(getattr(self, field_name), field_name),
            )

        observation = self.observation
        if isinstance(observation, Mapping):
            observation = VerifiedCollectionObservation.from_dict(observation)
        if not isinstance(observation, VerifiedCollectionObservation):
            raise ValueError("observation must be a VerifiedCollectionObservation")
        object.__setattr__(self, "observation", observation)

        artifacts = tuple(
            VerifiedCollectionArtifact.from_dict(item)
            if isinstance(item, Mapping)
            else item
            for item in self.artifacts
        )
        if not artifacts:
            raise ValueError("artifacts must be a non-empty array")
        if any(
            not isinstance(item, VerifiedCollectionArtifact) for item in artifacts
        ):
            raise ValueError("artifacts must contain VerifiedCollectionArtifact values")
        paths = [item.relative_path for item in artifacts]
        if len(set(paths)) != len(paths):
            raise ValueError("artifacts must not contain duplicate relative_path values")
        object.__setattr__(
            self,
            "artifacts",
            tuple(sorted(artifacts, key=lambda item: item.relative_path)),
        )

        self._validate_cross_fields()

    def _validate_cross_fields(self) -> None:
        if self.collection_device_id not in self.included_device_ids:
            raise ValueError(
                "collection_device_id must appear in included_device_ids: "
                f"{self.collection_device_id!r}"
            )
        if self.traffic_label == NORMAL_LABEL:
            if self.scenario not in NORMAL_COLLECTION_SCENARIOS:
                raise ValueError(
                    f"normal Session scenario must be a normal profile: {self.scenario!r}"
                )
            if self.target_device_id is not None:
                raise ValueError(
                    "normal Session must not declare target_device_id"
                )
            if self.target_source_ip is not None:
                raise ValueError(
                    "normal Session must not declare target_source_ip"
                )
        else:
            if self.scenario not in ATTACK_COLLECTION_SCENARIOS:
                raise ValueError(
                    f"attack Session scenario must be an attack profile: {self.scenario!r}"
                )
            if self.split != "test":
                raise ValueError("attack Session must use the test split")
            if self.target_device_id is None:
                raise ValueError("attack Session must declare target_device_id")
            if self.target_source_ip is None:
                raise ValueError("attack Session must declare target_source_ip")
            if self.target_device_id not in self.included_device_ids:
                raise ValueError(
                    "attack target_device_id must appear in included_device_ids"
                )

        if self.payload_schema_provenance is PayloadSchemaProvenance.FIRMWARE_REPORTED:
            if self.firmware_reported_payload_schema_version is None:
                raise ValueError(
                    "FIRMWARE_REPORTED provenance requires "
                    "firmware_reported_payload_schema_version"
                )
            if (
                self.firmware_reported_payload_schema_version
                != self.payload_schema_version
            ):
                raise ValueError(
                    "firmware_reported_payload_schema_version must match "
                    "payload_schema_version for FIRMWARE_REPORTED provenance"
                )
        elif self.firmware_reported_payload_schema_version is not None:
            # 과거 Firmware가 출력하지 않은 Version을 출력했다고 기록하지 않는다.
            raise ValueError(
                "firmware_reported_payload_schema_version must be null for "
                "RETROSPECTIVE_SOURCE_AND_PCAP_VERIFICATION provenance"
            )

        if self.first_window_start < self.started_at:
            raise ValueError("first_window_start must not be earlier than started_at")
        if self.ended_at < self.first_window_start:
            raise ValueError("ended_at must not be earlier than first_window_start")
        if self.verified_at < self.ended_at:
            raise ValueError("verified_at must not be earlier than ended_at")

        if self.segment_count != (
            self.processed_segment_count + self.empty_segment_count
        ):
            raise ValueError(
                "segment_count must equal processed_segment_count + "
                f"empty_segment_count: segment_count={self.segment_count}"
            )
        if self.segment_count == 0:
            raise ValueError("segment_count must be greater than zero")
        if self.eligible_feature_row_count == 0:
            raise ValueError("eligible_feature_row_count must be greater than zero")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "VerifiedCollectionManifest":
        _require_exact_fields(payload, cls._FIELDS, "verified_collection_manifest")
        return cls(
            schema_version=payload["schema_version"],
            provenance_mode=payload["provenance_mode"],
            collection_method=payload["collection_method"],
            run_id=payload["run_id"],
            session_id=payload["session_id"],
            collection_slot_id=payload["collection_slot_id"],
            source_capture_group_id=payload["source_capture_group_id"],
            split=payload["split"],
            traffic_label=payload["traffic_label"],
            scenario=payload["scenario"],
            collection_device_id=payload["collection_device_id"],
            target_device_id=payload["target_device_id"],
            target_source_ip=payload["target_source_ip"],
            included_device_ids=tuple(payload["included_device_ids"]),
            background_traffic_present=payload["background_traffic_present"],
            firmware_version=payload["firmware_version"],
            payload_schema_version=payload["payload_schema_version"],
            payload_schema_provenance=payload["payload_schema_provenance"],
            firmware_reported_payload_schema_version=payload[
                "firmware_reported_payload_schema_version"
            ],
            normal_policy_version=payload["normal_policy_version"],
            capture_source_commit_sha=payload["capture_source_commit_sha"],
            verification_commit_sha=payload["verification_commit_sha"],
            capture_interface=payload["capture_interface"],
            capture_filter=payload["capture_filter"],
            started_at=payload["started_at"],
            first_window_start=payload["first_window_start"],
            ended_at=payload["ended_at"],
            verified_at=payload["verified_at"],
            segment_count=payload["segment_count"],
            processed_segment_count=payload["processed_segment_count"],
            empty_segment_count=payload["empty_segment_count"],
            eligible_feature_row_count=payload["eligible_feature_row_count"],
            db_snapshot_sha256=payload["db_snapshot_sha256"],
            observation=payload["observation"],
            artifacts=tuple(payload["artifacts"]),
        )

    @classmethod
    def from_json(cls, text: str) -> "VerifiedCollectionManifest":
        payload = json.loads(text)
        if not isinstance(payload, dict):
            raise ValueError("Verified Collection Manifest must be a JSON object")
        return cls.from_dict(payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "provenance_mode": self.provenance_mode.value,
            "collection_method": self.collection_method.value,
            "run_id": self.run_id,
            "session_id": self.session_id,
            "collection_slot_id": self.collection_slot_id,
            "source_capture_group_id": self.source_capture_group_id,
            "split": self.split,
            "traffic_label": self.traffic_label,
            "scenario": self.scenario,
            "collection_device_id": self.collection_device_id,
            "target_device_id": self.target_device_id,
            "target_source_ip": self.target_source_ip,
            "included_device_ids": list(self.included_device_ids),
            "background_traffic_present": self.background_traffic_present,
            "firmware_version": self.firmware_version,
            "payload_schema_version": self.payload_schema_version,
            "payload_schema_provenance": self.payload_schema_provenance.value,
            "firmware_reported_payload_schema_version": (
                self.firmware_reported_payload_schema_version
            ),
            "normal_policy_version": self.normal_policy_version,
            "capture_source_commit_sha": self.capture_source_commit_sha,
            "verification_commit_sha": self.verification_commit_sha,
            "capture_interface": self.capture_interface,
            "capture_filter": self.capture_filter,
            "started_at": format_utc(self.started_at),
            "first_window_start": format_utc(self.first_window_start),
            "ended_at": format_utc(self.ended_at),
            "verified_at": format_utc(self.verified_at),
            "segment_count": self.segment_count,
            "processed_segment_count": self.processed_segment_count,
            "empty_segment_count": self.empty_segment_count,
            "eligible_feature_row_count": self.eligible_feature_row_count,
            "db_snapshot_sha256": self.db_snapshot_sha256,
            "observation": self.observation.to_dict(),
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


def canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def verified_collection_sha256(
    manifest: VerifiedCollectionManifest | Mapping[str, Any] | str,
) -> str:
    """Hash the canonical JSON form, never the raw file bytes.

    The file on disk may be pretty-printed; the contract hash must not change
    because of whitespace.
    """
    if isinstance(manifest, VerifiedCollectionManifest):
        text = manifest.to_json()
    elif isinstance(manifest, str):
        text = VerifiedCollectionManifest.from_json(manifest).to_json()
    else:
        text = VerifiedCollectionManifest.from_dict(manifest).to_json()
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_verified_collection_manifest(
    path: Path,
    *,
    expected_sha256: str,
    verify_artifacts: bool = True,
) -> VerifiedCollectionManifest:
    """Load a Collection Manifest only after the full hash chain verifies."""
    expected = normalize_sha256(expected_sha256, "expected_collection_sha256")
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"unable to read Verified Collection Manifest: {path}") from exc

    try:
        manifest = VerifiedCollectionManifest.from_json(raw)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"invalid Verified Collection Manifest: {path}: {exc}"
        ) from exc

    actual = verified_collection_sha256(manifest)
    if actual != expected:
        raise ValueError(
            "Verified Collection Manifest SHA256 mismatch: "
            f"expected={expected}, actual={actual}"
        )

    sidecar_path = Path(f"{path}{VERIFIED_COLLECTION_SHA256_SIDECAR_SUFFIX}")
    sidecar = _read_sha256_sidecar(sidecar_path)
    if sidecar != expected:
        raise ValueError(
            "Verified Collection Manifest sidecar SHA256 mismatch: "
            f"expected={expected}, actual={sidecar}"
        )

    if verify_artifacts:
        verify_collection_artifacts(manifest, base_directory=path.parent)
    return manifest


def verify_collection_artifacts(
    manifest: VerifiedCollectionManifest,
    *,
    base_directory: Path,
) -> None:
    """Confirm every referenced Evidence file matches its recorded size and hash."""
    base = base_directory.resolve()
    for artifact in manifest.artifacts:
        artifact_path = (base / artifact.relative_path).resolve()
        if base not in artifact_path.parents:
            raise ValueError(
                "Collection Manifest artifact escapes its directory: "
                f"{artifact.relative_path}"
            )
        if not artifact_path.is_file():
            raise ValueError(
                f"Collection Manifest artifact is missing: {artifact.relative_path}"
            )
        actual_size = artifact_path.stat().st_size
        if actual_size != artifact.size_bytes:
            raise ValueError(
                "Collection Manifest artifact size mismatch: "
                f"{artifact.relative_path}: expected={artifact.size_bytes}, "
                f"actual={actual_size}"
            )
        actual_sha256 = file_sha256(artifact_path)
        if actual_sha256 != artifact.sha256:
            raise ValueError(
                "Collection Manifest artifact SHA256 mismatch: "
                f"{artifact.relative_path}: expected={artifact.sha256}, "
                f"actual={actual_sha256}"
            )


def validate_verified_collection_identity(
    manifest: VerifiedCollectionManifest,
    *,
    run_manifest: Any,
    session_id: str,
    scenario: str,
    target_device_id: str | None,
    target_source_ip: str | None,
    included_device_ips: Mapping[str, str],
) -> None:
    """Confirm Collection, Run, and Dataset all describe the same Session.

    `target_device_id` and `target_source_ip` are the *Dataset Annotation*
    values, which are null for normal Sessions. The Run Manifest always carries
    a concrete Device because Dataset v2 requires it to identify the exported
    registered Device.
    """
    if manifest.run_id != run_manifest.run_id:
        raise ValueError(
            "Collection Manifest run_id mismatch: "
            f"expected={run_manifest.run_id!r}, actual={manifest.run_id!r}"
        )
    if manifest.session_id != session_id:
        raise ValueError(
            "Collection Manifest session_id mismatch: "
            f"expected={session_id!r}, actual={manifest.session_id!r}"
        )
    if run_manifest.session_id != session_id:
        raise ValueError(
            "Run Manifest session_id does not match the Dataset Session: "
            f"expected={session_id!r}, actual={run_manifest.session_id!r}"
        )
    if manifest.scenario != scenario:
        raise ValueError(
            "Collection Manifest scenario mismatch: "
            f"expected={scenario!r}, actual={manifest.scenario!r}"
        )
    if manifest.scenario != run_manifest.scenario.scenario_id:
        raise ValueError(
            "Collection Manifest scenario does not match the Run Manifest: "
            f"run={run_manifest.scenario.scenario_id!r}, "
            f"collection={manifest.scenario!r}"
        )

    exported_devices = dict(included_device_ips)
    if set(manifest.included_device_ids) != set(exported_devices):
        raise ValueError(
            "Collection Manifest included_device_ids does not match the exported "
            f"Devices: collection={sorted(manifest.included_device_ids)}, "
            f"exported={sorted(exported_devices)}"
        )

    if target_device_id is None:
        # 정상 Session: Dataset Annotation은 Target이 없고, Run Manifest는 실제
        # Export된 등록 Device를 식별한다.
        if manifest.collection_device_id != run_manifest.target_device_id:
            raise ValueError(
                "Collection Manifest collection_device_id must match the normal "
                f"Run Manifest Device: run={run_manifest.target_device_id!r}, "
                f"collection={manifest.collection_device_id!r}"
            )
        expected_ip = exported_devices.get(manifest.collection_device_id)
        if expected_ip != run_manifest.source_ip:
            raise ValueError(
                "normal Run Manifest source_ip must match the collection Device: "
                f"expected={expected_ip!r}, actual={run_manifest.source_ip!r}"
            )
        return

    if manifest.target_device_id != target_device_id:
        raise ValueError(
            "Collection Manifest target_device_id mismatch: "
            f"expected={target_device_id!r}, actual={manifest.target_device_id!r}"
        )
    if manifest.target_source_ip != target_source_ip:
        raise ValueError(
            "Collection Manifest target_source_ip mismatch: "
            f"expected={target_source_ip!r}, actual={manifest.target_source_ip!r}"
        )
    if manifest.target_device_id != run_manifest.target_device_id:
        raise ValueError(
            "Collection Manifest target_device_id does not match the Run Manifest: "
            f"run={run_manifest.target_device_id!r}, "
            f"collection={manifest.target_device_id!r}"
        )
    if manifest.target_source_ip != run_manifest.source_ip:
        raise ValueError(
            "Collection Manifest target_source_ip does not match the Run Manifest: "
            f"run={run_manifest.source_ip!r}, collection={manifest.target_source_ip!r}"
        )


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --- Field helpers -----------------------------------------------------------


def _require_exact_fields(
    payload: Mapping[str, Any],
    allowed: Sequence[str],
    label: str,
) -> None:
    allowed_set = set(allowed)
    unknown = sorted(set(payload) - allowed_set)
    if unknown:
        raise ValueError(f"{label} contains unknown fields: {unknown}")
    missing = sorted(allowed_set - set(payload))
    if missing:
        raise ValueError(f"{label} is missing fields: {missing}")


def require_non_empty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    text = value.strip()
    if any(ord(character) < 32 for character in text):
        raise ValueError(f"{field_name} must not contain control characters")
    if len(text) > 256:
        raise ValueError(f"{field_name} must be at most 256 characters")
    return text


def require_identifier(value: Any, field_name: str) -> str:
    text = require_non_empty_string(value, field_name)
    if _IDENTIFIER_RE.fullmatch(text) is None:
        raise ValueError(
            f"{field_name} must use letters, numbers, '.', '_', ':', or '-'"
        )
    return text


def require_canonical_uuid4(value: Any, field_name: str) -> str:
    text = require_non_empty_string(value, field_name)
    try:
        parsed = UUID(text)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a canonical UUID4") from exc
    if parsed.version != 4 or str(parsed) != text:
        raise ValueError(f"{field_name} must be a canonical UUID4")
    return text


def normalize_sha256(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value.lower()) is None:
        raise ValueError(f"{field_name} must be a 64-character hexadecimal string")
    return value.lower()


def normalize_sha1(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or _SHA1_RE.fullmatch(value) is None:
        raise ValueError(
            f"{field_name} must be a lowercase 40-character SHA1"
        )
    return value


def normalize_optional_ipv4(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    text = require_non_empty_string(value, field_name)
    try:
        parsed = ip_address(text)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid IPv4 address") from exc
    if not isinstance(parsed, IPv4Address):
        raise ValueError(f"{field_name} must be a valid IPv4 address")
    return str(parsed)


def normalize_device_ids(value: Any, field_name: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{field_name} must be a non-empty array")
    normalized = tuple(require_identifier(item, f"{field_name}[]") for item in value)
    if not normalized:
        raise ValueError(f"{field_name} must be a non-empty array")
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field_name} must not contain duplicates")
    return tuple(sorted(normalized))


def require_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean")
    return value


def require_non_negative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def require_optional_non_negative_int(value: Any, field_name: str) -> int | None:
    if value is None:
        return None
    return require_non_negative_int(value, field_name)


def require_utc(value: Any, field_name: str) -> datetime:
    if isinstance(value, str):
        value = _parse_utc_text(value, field_name)
    if not isinstance(value, datetime):
        raise ValueError(f"{field_name} must be a UTC datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC")
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        raise ValueError(f"{field_name} must use whole-second precision")
    return normalized


def normalize_optional_utc(value: Any, field_name: str) -> datetime | None:
    if value is None:
        return None
    return require_utc(value, field_name)


def _parse_utc_text(value: str, field_name: str) -> datetime:
    text = value.strip()
    if not text:
        raise ValueError(f"{field_name} must be a non-empty string")
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed


def format_utc(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def format_optional_utc(value: datetime | None) -> str | None:
    return None if value is None else format_utc(value)


def coerce_enum(enum_type: type[Enum], value: Any, field_name: str) -> Any:
    if isinstance(value, enum_type):
        return value
    try:
        return enum_type(value)
    except ValueError as exc:
        allowed = sorted(member.value for member in enum_type)
        raise ValueError(f"{field_name} must be one of {allowed}") from exc


def normalize_relative_path(value: Any, field_name: str) -> str:
    text = require_non_empty_string(value, field_name).replace("\\", "/")
    if text.startswith(("/", "//")) or _WINDOWS_DRIVE_RE.match(text):
        raise ValueError(f"{field_name} must be a relative path")
    parts = PurePosixPath(text).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"{field_name} must not contain '.', '..', or empty parts")
    for part in parts:
        if (
            _PORTABLE_PATH_PART_RE.fullmatch(part) is None
            or part.endswith(".")
            or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED_PATH_NAMES
        ):
            raise ValueError(
                f"{field_name} contains a non-portable path component: {part!r}"
            )
    return "/".join(parts)


def _read_sha256_sidecar(path: Path) -> str:
    try:
        content = path.read_text(encoding="ascii")
    except FileNotFoundError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ValueError(
            f"unable to read Verified Collection SHA256 sidecar: {path}"
        ) from exc
    lines = content.splitlines()
    if len(lines) != 1:
        raise ValueError(
            "Verified Collection SHA256 sidecar must contain exactly one line"
        )
    tokens = lines[0].split()
    if not tokens or len(tokens) > 2:
        raise ValueError("invalid Verified Collection SHA256 sidecar format")
    if len(tokens) == 2:
        referenced_name = tokens[1].removeprefix("*")
        expected_name = path.name.removesuffix(
            VERIFIED_COLLECTION_SHA256_SIDECAR_SUFFIX
        )
        if referenced_name != expected_name:
            raise ValueError(
                "Verified Collection SHA256 sidecar references the wrong file: "
                f"expected={expected_name!r}, actual={referenced_name!r}"
            )
    return normalize_sha256(tokens[0], "collection_sidecar_sha256")
