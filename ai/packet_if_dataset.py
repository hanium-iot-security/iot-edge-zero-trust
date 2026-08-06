"""Packet Isolation Forest용 Session 기반 Dataset을 읽고 검증합니다."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from math import isclose, isfinite
from numbers import Integral
from numbers import Real
from pathlib import Path
import re
from typing import Any
from uuid import UUID

import pandas as pd

from ai.packet_if_contract import (
    PACKET_IF_NOMINAL_WINDOW_SECONDS,
    PACKET_IF_RAW_FEATURES,
    packet_feature_matrix,
)
from ai.packet_if_phase5_manifest import (
    PACKET_IF_DATASET_VERSION_V2,
    SUPPORTED_PACKET_IF_DATASET_VERSIONS,
    PacketIFRunManifestReference,
    assert_run_manifest_complete,
    load_verified_run_manifest,
    load_verified_session_manifest,
    normalize_device_ids,
    normalize_optional_ipv4,
    require_bool,
    require_canonical_uuid4,
    require_identifier,
    require_non_empty_string,
    validate_run_manifest_identity,
)
from edge.packet.capture_policy import (
    CaptureEligibilitySegment,
    CapturePolicy,
    is_capture_eligible,
)
from edge.phase5.verified_collection_contract import DatasetSessionIdentity

_UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


PACKET_IF_DATASET_VERSION = PACKET_IF_DATASET_VERSION_V2

TRAIN_SPLIT = "train"
VALIDATION_SPLIT = "validation"
TEST_SPLIT = "test"
VALID_SPLITS = frozenset({TRAIN_SPLIT, VALIDATION_SPLIT, TEST_SPLIT})

NORMAL_LABEL = "normal"
ATTACK_LABEL = "attack"
VALID_TRAFFIC_LABELS = frozenset({NORMAL_LABEL, ATTACK_LABEL})

DATASET_REQUIRED_COLUMNS = (
    "packet_feature_log_id",
    "session_id",
    "device_id",
    "direction",
    "window_start",
    "window_end",
    "peer_ip",
    "segment_window_start",
    "segment_window_end",
    "segment_status",
    "segment_error_code",
    "start_delay_seconds",
    "registered_device_id",
    "registered_ip_address",
    *PACKET_IF_RAW_FEATURES,
)


@dataclass(frozen=True)
class PacketIFSessionDevice:
    device_id: str
    peer_ip: str


@dataclass(frozen=True)
class PacketIFSessionSpec:
    session_id: str
    split: str
    traffic_label: str
    scenario: str
    target_device_id: str | None = None
    status: str = "COMPLETED"
    capture_interface: str = ""
    capture_filter: str = ""
    source_commit_sha: str = ""
    started_at: datetime | None = None
    first_window_start: datetime | None = None
    ended_at: datetime | None = None
    capture_gap_start: datetime | None = None
    capture_gap_end: datetime | None = None
    devices: tuple[PacketIFSessionDevice, ...] = ()
    data_sha256: str = ""
    collection_slot_id: str | None = None
    source_capture_group_id: str | None = None
    run_manifest_ref: PacketIFRunManifestReference | None = None
    normal_policy_version: str | None = None
    firmware_version: str | None = None
    payload_schema_version: str | None = None
    target_source_ip: str | None = None
    included_device_ids: tuple[str, ...] = ()
    background_traffic_present: bool | None = None


@dataclass(frozen=True)
class PacketIFDatasetManifest:
    dataset_version: str
    capture_policy: CapturePolicy
    dataset_sha256: str
    sessions: tuple[PacketIFSessionSpec, ...]

    @property
    def capture_policy_version(self) -> str:
        return self.capture_policy.version

    @property
    def normal_policy_version(self) -> str | None:
        versions = {
            session.normal_policy_version
            for session in self.sessions
            if session.normal_policy_version is not None
        }
        if self.dataset_version == PACKET_IF_DATASET_VERSION_V2:
            if len(versions) != 1:
                raise ValueError(
                    "Packet IF Dataset v2 must contain exactly one "
                    "normal_policy_version"
                )
            return next(iter(versions))
        if len(versions) > 1:
            raise ValueError(
                "Packet IF Dataset must not contain multiple "
                "normal_policy_version values"
            )
        return next(iter(versions), None)


@dataclass(frozen=True)
class PacketIFDataset:
    train: pd.DataFrame
    validation: pd.DataFrame
    test: pd.DataFrame
    manifest: PacketIFDatasetManifest

    def session_ids(self, split: str) -> tuple[str, ...]:
        if split not in VALID_SPLITS:
            raise ValueError(f"invalid packet dataset split: {split!r}")
        return tuple(
            spec.session_id
            for spec in self.manifest.sessions
            if spec.split == split
        )


def load_packet_if_dataset(
    dataset_path: Path,
    manifest_path: Path,
) -> PacketIFDataset:
    """변경되지 않는 CSV와 Session 단위 Split Manifest를 읽습니다."""
    manifest = load_packet_if_manifest(manifest_path)
    actual_sha256 = file_sha256(dataset_path)
    if actual_sha256 != manifest.dataset_sha256:
        raise ValueError(
            "packet dataset SHA256 mismatch: "
            f"expected={manifest.dataset_sha256}, actual={actual_sha256}"
        )

    session_sha256s = session_data_sha256s(dataset_path)
    frame = pd.read_csv(dataset_path)
    _validate_dataset_columns(frame)
    _validate_dataset_rows(
        frame,
        manifest,
        session_sha256s=session_sha256s,
    )

    session_map = {spec.session_id: spec for spec in manifest.sessions}
    enriched = frame.copy(deep=True)
    enriched["split"] = enriched["session_id"].map(
        lambda session_id: session_map[str(session_id)].split
    )
    enriched["traffic_label"] = enriched["session_id"].map(
        lambda session_id: session_map[str(session_id)].traffic_label
    )
    enriched["scenario"] = enriched["session_id"].map(
        lambda session_id: session_map[str(session_id)].scenario
    )
    enriched = enriched.sort_values(
        ["session_id", "window_start", "packet_feature_log_id"],
        kind="stable",
    ).reset_index(drop=True)

    return PacketIFDataset(
        train=_split_frame(enriched, TRAIN_SPLIT),
        validation=_split_frame(enriched, VALIDATION_SPLIT),
        test=_split_frame(enriched, TEST_SPLIT),
        manifest=manifest,
    )


def load_packet_if_manifest(
    path: Path,
) -> PacketIFDatasetManifest:
    if not path.exists():
        raise FileNotFoundError(f"packet dataset manifest not found: {path}")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid packet dataset manifest JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("packet dataset manifest must be a JSON object")

    dataset_version = _required_non_empty_string(payload, "dataset_version")
    if dataset_version not in SUPPORTED_PACKET_IF_DATASET_VERSIONS:
        raise ValueError(
            "unsupported packet dataset version: "
            f"supported={sorted(SUPPORTED_PACKET_IF_DATASET_VERSIONS)!r}, "
            f"actual={dataset_version!r}"
        )

    capture_policy = _parse_capture_policy(payload)
    dataset_sha256 = _validate_sha256(
        _required_non_empty_string(payload, "dataset_sha256"),
        "dataset_sha256",
    )

    raw_sessions = payload.get("sessions")
    if not isinstance(raw_sessions, list) or not raw_sessions:
        raise ValueError("packet dataset manifest sessions must be a non-empty list")

    sessions = tuple(
        _parse_session_spec(item, dataset_version=dataset_version)
        for item in raw_sessions
    )
    _validate_manifest_sessions(sessions, dataset_version=dataset_version)
    manifest = PacketIFDatasetManifest(
        dataset_version=dataset_version,
        capture_policy=capture_policy,
        dataset_sha256=dataset_sha256,
        sessions=sessions,
    )
    if dataset_version == PACKET_IF_DATASET_VERSION_V2:
        _validate_run_manifest_references(path, manifest)
    return manifest


def file_sha256(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"file not found: {path}")

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def session_data_sha256s(path: Path) -> dict[str, str]:
    """Hash each Session's canonical CSV rows without pandas type coercion."""
    if not path.is_file():
        raise FileNotFoundError(f"packet dataset not found: {path}")

    digests: dict[str, Any] = {}
    with path.open(newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        fieldnames = tuple(reader.fieldnames or ())
        missing = [
            column
            for column in DATASET_REQUIRED_COLUMNS
            if column not in fieldnames
        ]
        if missing:
            raise ValueError(
                f"packet dataset is missing required columns: {missing}"
            )
        for row in reader:
            session_id = str(row.get("session_id", "")).strip()
            if not session_id:
                raise ValueError("packet dataset session_id must not be empty")
            digest = digests.setdefault(session_id, hashlib.sha256())
            canonical_row = {
                column: row.get(column, "")
                for column in DATASET_REQUIRED_COLUMNS
            }
            digest.update(
                (
                    json.dumps(
                        canonical_row,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
            )
    return {
        session_id: digest.hexdigest()
        for session_id, digest in digests.items()
    }


def _parse_capture_policy(payload: dict[str, Any]) -> CapturePolicy:
    policy_version = _required_non_empty_string(
        payload,
        "capture_policy_version",
    )
    raw_policy = payload.get("capture_policy")
    if not isinstance(raw_policy, dict):
        raise ValueError("packet dataset capture_policy must be an object")
    nested_version = _required_non_empty_string(raw_policy, "version")
    if nested_version != policy_version:
        raise ValueError(
            "packet dataset Capture Policy version mismatch: "
            f"expected={policy_version!r}, actual={nested_version!r}"
        )

    nominal_window_seconds = _required_finite_real(
        raw_policy,
        "nominal_window_seconds",
    )
    if not isclose(
        nominal_window_seconds,
        PACKET_IF_NOMINAL_WINDOW_SECONDS,
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise ValueError(
            "packet dataset nominal_window_seconds must match "
            f"{PACKET_IF_NOMINAL_WINDOW_SECONDS}"
        )

    policy = CapturePolicy(
        max_start_delay_seconds=_required_finite_real(
            raw_policy,
            "max_start_delay_seconds",
        ),
        minimum_duration_seconds=_required_finite_real(
            raw_policy,
            "minimum_duration_seconds",
        ),
        epsilon_seconds=_required_finite_real(
            raw_policy,
            "epsilon_seconds",
        ),
        version=nested_version,
    )
    coverage_ratio = _required_finite_real(
        raw_policy,
        "minimum_coverage_ratio",
    )
    expected_coverage_ratio = (
        policy.minimum_duration_seconds / PACKET_IF_NOMINAL_WINDOW_SECONDS
    )
    if not isclose(
        coverage_ratio,
        expected_coverage_ratio,
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise ValueError(
            "packet dataset minimum_coverage_ratio does not match "
            "minimum_duration_seconds"
        )
    return policy


def _parse_session_device(payload: Any) -> PacketIFSessionDevice:
    if not isinstance(payload, dict):
        raise ValueError("each session device must be a JSON object")
    device_id = _required_non_empty_string(payload, "device_id")
    peer_ip = _required_non_empty_string(payload, "peer_ip")
    _validate_ipv4(peer_ip)
    return PacketIFSessionDevice(device_id=device_id, peer_ip=peer_ip)


def _parse_session_spec(
    payload: Any,
    *,
    dataset_version: str,
) -> PacketIFSessionSpec:
    if not isinstance(payload, dict):
        raise ValueError("each packet dataset session must be a JSON object")

    session_id = _required_non_empty_string(payload, "session_id")
    try:
        parsed_uuid = UUID(session_id)
    except ValueError as exc:
        raise ValueError(f"invalid packet dataset session_id: {session_id!r}") from exc
    if parsed_uuid.version != 4 or str(parsed_uuid) != session_id:
        raise ValueError(f"packet dataset session_id must be a canonical UUID4: {session_id!r}")

    split = _required_non_empty_string(payload, "split")
    if split not in VALID_SPLITS:
        raise ValueError(f"invalid packet dataset split: {split!r}")

    traffic_label = _required_non_empty_string(payload, "traffic_label")
    if traffic_label not in VALID_TRAFFIC_LABELS:
        raise ValueError(f"invalid packet traffic label: {traffic_label!r}")

    scenario = _required_non_empty_string(payload, "scenario")

    raw_target = payload.get("target_device_id")
    if raw_target is None:
        target_device_id = None
    elif isinstance(raw_target, str) and raw_target.strip():
        target_device_id = raw_target.strip()
    else:
        raise ValueError(
            f"target_device_id must be a non-empty string or omitted: {raw_target!r}"
        )

    status = _required_non_empty_string(payload, "status")
    if status != "COMPLETED":
        raise ValueError(
            f"packet dataset session must be COMPLETED: {session_id}"
        )
    capture_interface = _required_non_empty_string(
        payload,
        "capture_interface",
    )
    capture_filter = payload.get("capture_filter")
    if not isinstance(capture_filter, str):
        raise ValueError("capture_filter must be a string")
    source_commit_sha = _validate_sha1(
        _required_non_empty_string(payload, "source_commit_sha"),
        "source_commit_sha",
    )
    started_at = _required_utc_timestamp(payload, "started_at")
    first_window_start = _required_canonical_utc_timestamp(
        payload,
        "first_window_start",
    )
    ended_at = _required_utc_timestamp(payload, "ended_at")
    if not started_at <= first_window_start < ended_at:
        raise ValueError(
            "packet dataset session timestamps must satisfy "
            "started_at <= first_window_start < ended_at"
        )

    capture_gap_start = _optional_canonical_utc_timestamp(
        payload,
        "capture_gap_start",
    )
    capture_gap_end = _optional_canonical_utc_timestamp(
        payload,
        "capture_gap_end",
    )
    if (capture_gap_start is None) != (capture_gap_end is None):
        raise ValueError(
            "capture_gap_start and capture_gap_end must both be set or null"
        )
    if capture_gap_start is not None and capture_gap_end is not None:
        if not capture_gap_start < capture_gap_end <= first_window_start:
            raise ValueError(
                "Capture Gap must end no later than first_window_start"
            )

    raw_devices = payload.get("devices")
    if not isinstance(raw_devices, list) or not raw_devices:
        raise ValueError("packet dataset session devices must be a non-empty list")
    devices = tuple(_parse_session_device(item) for item in raw_devices)
    data_sha256 = _validate_sha256(
        _required_non_empty_string(payload, "data_sha256"),
        "data_sha256",
    )

    phase5_fields: dict[str, Any] = {}
    if dataset_version == PACKET_IF_DATASET_VERSION_V2:
        run_manifest_payload = payload.get("run_manifest_ref")
        if not isinstance(run_manifest_payload, dict):
            raise ValueError("run_manifest_ref must be a JSON object")
        phase5_fields = {
            "collection_slot_id": require_identifier(
                payload.get("collection_slot_id"),
                "collection_slot_id",
            ),
            "source_capture_group_id": require_canonical_uuid4(
                payload.get("source_capture_group_id"),
                "source_capture_group_id",
            ),
            "run_manifest_ref": PacketIFRunManifestReference.from_dict(
                run_manifest_payload
            ),
            "normal_policy_version": require_non_empty_string(
                payload.get("normal_policy_version"),
                "normal_policy_version",
            ),
            "firmware_version": require_non_empty_string(
                payload.get("firmware_version"),
                "firmware_version",
            ),
            "payload_schema_version": require_non_empty_string(
                payload.get("payload_schema_version"),
                "payload_schema_version",
            ),
            "target_source_ip": normalize_optional_ipv4(
                payload.get("target_source_ip"),
                "target_source_ip",
            ),
            "included_device_ids": normalize_device_ids(
                payload.get("included_device_ids"),
                "included_device_ids",
            ),
            "background_traffic_present": require_bool(
                payload.get("background_traffic_present"),
                "background_traffic_present",
            ),
        }

    return PacketIFSessionSpec(
        session_id=session_id,
        split=split,
        traffic_label=traffic_label,
        scenario=scenario,
        target_device_id=target_device_id,
        status=status,
        capture_interface=capture_interface,
        capture_filter=capture_filter,
        source_commit_sha=source_commit_sha,
        started_at=started_at,
        first_window_start=first_window_start,
        ended_at=ended_at,
        capture_gap_start=capture_gap_start,
        capture_gap_end=capture_gap_end,
        devices=devices,
        data_sha256=data_sha256,
        **phase5_fields,
    )


def _validate_manifest_sessions(
    sessions: tuple[PacketIFSessionSpec, ...],
    *,
    dataset_version: str,
) -> None:
    session_ids = [spec.session_id for spec in sessions]
    if len(set(session_ids)) != len(session_ids):
        raise ValueError("packet dataset manifest contains duplicate session_id values")

    if dataset_version == PACKET_IF_DATASET_VERSION_V2:
        _validate_phase5_manifest_sessions(sessions)

    split_values = {spec.split for spec in sessions}
    missing_splits = VALID_SPLITS - split_values
    if missing_splits:
        raise ValueError(
            f"packet dataset manifest is missing splits: {sorted(missing_splits)}"
        )

    for spec in sessions:
        if spec.split in {TRAIN_SPLIT, VALIDATION_SPLIT}:
            if spec.traffic_label != NORMAL_LABEL:
                raise ValueError(
                    f"{spec.split} session must be normal: {spec.session_id}"
                )
            if spec.scenario == "normal_management_traffic":
                raise ValueError(
                    "normal_management_traffic is reserved for Rule allowlist "
                    f"and false-positive evaluation: {spec.session_id}"
                )

    test_labels = {
        spec.traffic_label
        for spec in sessions
        if spec.split == TEST_SPLIT
    }
    missing_test_labels = VALID_TRAFFIC_LABELS - test_labels
    if missing_test_labels:
        raise ValueError(
            "test split must contain separate normal and attack sessions: "
            f"missing={sorted(missing_test_labels)}"
        )

    for spec in sessions:
        if spec.traffic_label == ATTACK_LABEL and not spec.target_device_id:
            raise ValueError(
                f"attack session must specify target_device_id: {spec.session_id}"
            )
        if spec.traffic_label == NORMAL_LABEL and spec.target_device_id is not None:
            raise ValueError(
                f"normal session must not have target_device_id: {spec.session_id}"
            )
        if dataset_version == PACKET_IF_DATASET_VERSION_V2:
            if spec.traffic_label == ATTACK_LABEL and not spec.target_source_ip:
                raise ValueError(
                    "attack session must specify target_source_ip: "
                    f"{spec.session_id}"
                )
            if (
                spec.traffic_label == NORMAL_LABEL
                and spec.target_source_ip is not None
            ):
                raise ValueError(
                    "normal session must not have target_source_ip: "
                    f"{spec.session_id}"
                )
        device_ids = [device.device_id for device in spec.devices]
        peer_ips = [device.peer_ip for device in spec.devices]
        if len(set(device_ids)) != len(device_ids):
            raise ValueError(
                f"packet dataset session has duplicate device_id: {spec.session_id}"
            )
        if len(set(peer_ips)) != len(peer_ips):
            raise ValueError(
                f"packet dataset session has duplicate peer_ip: {spec.session_id}"
            )
        if (
            spec.target_device_id is not None
            and spec.target_device_id not in device_ids
        ):
            raise ValueError(
                "attack target_device_id is missing from session devices: "
                f"{spec.session_id}"
            )
        if dataset_version == PACKET_IF_DATASET_VERSION_V2:
            _validate_phase5_session_devices(spec)


def _validate_phase5_manifest_sessions(
    sessions: tuple[PacketIFSessionSpec, ...],
) -> None:
    collection_slot_ids = [spec.collection_slot_id for spec in sessions]
    if len(set(collection_slot_ids)) != len(collection_slot_ids):
        raise ValueError(
            "packet dataset manifest contains duplicate "
            "collection_slot_id values"
        )

    run_ids = [
        spec.run_manifest_ref.run_id
        for spec in sessions
        if spec.run_manifest_ref is not None
    ]
    if len(set(run_ids)) != len(run_ids):
        raise ValueError("packet dataset manifest contains duplicate run_id values")

    group_splits: dict[str, str] = {}
    for spec in sessions:
        group_id = spec.source_capture_group_id
        if group_id is None:
            raise ValueError("source_capture_group_id is required for Dataset v2")
        previous_split = group_splits.setdefault(group_id, spec.split)
        if previous_split != spec.split:
            raise ValueError(
                "source_capture_group_id must not cross Dataset splits: "
                f"group={group_id}, splits={sorted({previous_split, spec.split})}"
            )

    policy_versions = {spec.normal_policy_version for spec in sessions}
    if len(policy_versions) != 1:
        raise ValueError(
            "Packet IF Dataset v2 must use one normal_policy_version: "
            f"{sorted(str(value) for value in policy_versions)}"
        )


def _validate_phase5_session_devices(spec: PacketIFSessionSpec) -> None:
    included = set(spec.included_device_ids)
    exported = {device.device_id for device in spec.devices}
    if not exported.issubset(included):
        raise ValueError(
            "packet dataset devices must be included in included_device_ids: "
            f"session_id={spec.session_id}, missing={sorted(exported - included)}"
        )
    if spec.target_device_id is None:
        return
    if spec.target_device_id not in included:
        raise ValueError(
            "attack target_device_id is missing from included_device_ids: "
            f"{spec.session_id}"
        )
    target_devices = [
        device
        for device in spec.devices
        if device.device_id == spec.target_device_id
    ]
    if (
        len(target_devices) != 1
        or target_devices[0].peer_ip != spec.target_source_ip
    ):
        raise ValueError(
            "attack target_source_ip must match the exported target device: "
            f"{spec.session_id}"
        )


def _dataset_session_identity(spec: PacketIFSessionSpec) -> DatasetSessionIdentity:
    """Collect the Dataset Session fields a Collection Manifest must reproduce."""
    return DatasetSessionIdentity(
        split=spec.split,
        traffic_label=spec.traffic_label,
        collection_slot_id=spec.collection_slot_id or "",
        source_capture_group_id=spec.source_capture_group_id or "",
        normal_policy_version=spec.normal_policy_version or "",
        firmware_version=spec.firmware_version or "",
        payload_schema_version=spec.payload_schema_version or "",
        background_traffic_present=bool(spec.background_traffic_present),
        source_commit_sha=spec.source_commit_sha,
        capture_filter=spec.capture_filter,
    )


def _validate_run_manifest_references(
    manifest_path: Path,
    manifest: PacketIFDatasetManifest,
) -> None:
    base_directory = manifest_path.parent.resolve()
    for spec in manifest.sessions:
        reference = spec.run_manifest_ref
        if reference is None:
            raise ValueError("run_manifest_ref is required for Dataset v2")
        run_manifest_path = (base_directory / reference.relative_path).resolve()
        if base_directory not in run_manifest_path.parents:
            raise ValueError(
                "run_manifest_ref escapes the Dataset Manifest directory"
            )
        run_manifest = load_verified_run_manifest(
            run_manifest_path,
            expected_sha256=reference.sha256,
        )
        included_device_ips = {
            device.device_id: device.peer_ip
            for device in spec.devices
        }
        validate_run_manifest_identity(
            run_manifest,
            reference,
            session_id=spec.session_id,
            scenario=spec.scenario,
            target_device_id=spec.target_device_id,
            target_source_ip=spec.target_source_ip,
            included_device_ips=included_device_ips,
        )
        # Verified Collection Run은 session_manifest_ref까지 연쇄 검증한다.
        # 기존 Scenario Runner Run은 참조가 없으므로 그대로 통과한다.
        load_verified_session_manifest(
            run_manifest_path,
            run_manifest,
            session_id=spec.session_id,
            scenario=spec.scenario,
            target_device_id=spec.target_device_id,
            target_source_ip=spec.target_source_ip,
            included_device_ips=included_device_ips,
            dataset_identity=_dataset_session_identity(spec),
            required=False,
        )
        assert_run_manifest_complete(run_manifest, reference.run_id)


def _validate_dataset_columns(frame: pd.DataFrame) -> None:
    missing = [
        column
        for column in DATASET_REQUIRED_COLUMNS
        if column not in frame.columns
    ]
    if missing:
        raise ValueError(f"packet dataset is missing required columns: {missing}")
    if frame.empty:
        raise ValueError("packet dataset must contain at least one row")


def _validate_dataset_rows(
    frame: pd.DataFrame,
    manifest: PacketIFDatasetManifest,
    *,
    session_sha256s: dict[str, str],
) -> None:
    ids = frame["packet_feature_log_id"]
    if ids.isna().any():
        raise ValueError("packet_feature_log_id must not be null")
    if ids.duplicated().any():
        raise ValueError("packet dataset contains duplicate packet_feature_log_id values")
    for value in ids:
        if (
            isinstance(value, bool)
            or not isinstance(value, Integral)
            or value < 0
        ):
            raise ValueError(
                "packet_feature_log_id must be a non-negative integer"
            )

    if frame["session_id"].isna().any():
        raise ValueError("packet dataset session_id must not be null")
    dataset_session_ids = {str(value) for value in frame["session_id"]}
    manifest_session_ids = {spec.session_id for spec in manifest.sessions}
    unknown_sessions = dataset_session_ids - manifest_session_ids
    if unknown_sessions:
        raise ValueError(
            f"packet dataset contains sessions missing from manifest: {sorted(unknown_sessions)}"
        )
    missing_sessions = manifest_session_ids - dataset_session_ids
    if missing_sessions:
        raise ValueError(
            f"packet dataset has no rows for manifest sessions: {sorted(missing_sessions)}"
        )
    for spec in manifest.sessions:
        actual_session_sha256 = session_sha256s.get(spec.session_id)
        if actual_session_sha256 != spec.data_sha256:
            raise ValueError(
                "packet dataset Session SHA256 mismatch: "
                f"session_id={spec.session_id}, "
                f"expected={spec.data_sha256}, actual={actual_session_sha256}"
            )

    if frame["device_id"].isna().any() or frame["device_id"].astype(str).str.strip().eq("").any():
        raise ValueError("packet dataset requires mapped device_id values")
    invalid_directions = set(frame["direction"].dropna().astype(str)) - {"INBOUND"}
    if frame["direction"].isna().any() or invalid_directions:
        raise ValueError(
            "packet dataset only accepts INBOUND rows: "
            f"invalid={sorted(invalid_directions)}"
        )

    if (
        frame["peer_ip"].isna().any()
        or frame["peer_ip"].astype(str).str.strip().eq("").any()
    ):
        raise ValueError("packet dataset requires non-empty peer_ip values")
    for raw_ip in frame["peer_ip"].astype(str):
        _validate_ipv4(raw_ip)

    _validate_window_timestamps(frame["window_start"], frame["window_end"])
    _validate_window_timestamps(
        frame["segment_window_start"],
        frame["segment_window_end"],
    )

    session_map = {spec.session_id: spec for spec in manifest.sessions}
    for session_id, group in frame.groupby("session_id"):
        spec = session_map.get(str(session_id))
        if spec is None:
            continue

        expected_devices = {
            (device.device_id, device.peer_ip)
            for device in spec.devices
        }
        for row in group.to_dict(orient="records"):
            _validate_dataset_source_row(
                row,
                capture_policy=manifest.capture_policy,
            )
            device_mapping = (
                str(row["device_id"]),
                str(row["peer_ip"]),
            )
            if device_mapping not in expected_devices:
                raise ValueError(
                    "packet dataset row is missing from Session device provenance: "
                    f"session_id={session_id}, device={device_mapping!r}"
                )
            window_start = _parse_canonical_utc(
                row["window_start"],
                "window_start",
            )
            window_end = _parse_canonical_utc(
                row["window_end"],
                "window_end",
            )
            if (
                spec.first_window_start is None
                or spec.ended_at is None
                or window_start < spec.first_window_start
                or window_end > spec.ended_at
            ):
                raise ValueError(
                    "packet dataset row falls outside Session timing provenance: "
                    f"session_id={session_id}"
                )

        if spec.target_device_id is not None:
            mismatched = group[
                group["device_id"].astype(str) != spec.target_device_id
            ]
            if not mismatched.empty:
                raise ValueError(
                    f"attack session {session_id!r} contains rows with device_id "
                    f"not matching target_device_id {spec.target_device_id!r}"
                )

    packet_feature_matrix(frame.to_dict(orient="records"))


def _validate_dataset_source_row(
    row: dict[str, Any],
    *,
    capture_policy: CapturePolicy,
) -> None:
    feature_start = _parse_canonical_utc(row["window_start"], "window_start")
    feature_end = _parse_canonical_utc(row["window_end"], "window_end")
    segment_start = _parse_canonical_utc(
        row["segment_window_start"],
        "segment_window_start",
    )
    segment_end = _parse_canonical_utc(
        row["segment_window_end"],
        "segment_window_end",
    )
    if feature_start != segment_start or feature_end != segment_end:
        raise ValueError(
            "Packet Feature window must match its Capture Segment window"
        )

    registered_device_id = _required_dataframe_string(
        row,
        "registered_device_id",
    )
    registered_ip_address = _required_dataframe_string(
        row,
        "registered_ip_address",
    )
    _validate_ipv4(registered_ip_address)
    if registered_device_id != str(row["device_id"]):
        raise ValueError(
            "packet dataset device_id does not match registered_device_id"
        )
    if registered_ip_address != str(row["peer_ip"]):
        raise ValueError(
            "packet dataset peer_ip does not match registered_ip_address"
        )

    eligibility = is_capture_eligible(
        CaptureEligibilitySegment(
            status=_required_dataframe_string(row, "segment_status"),
            error_code=_optional_dataframe_string(
                row.get("segment_error_code"),
            ),
            start_delay_seconds=_optional_dataframe_float(
                row.get("start_delay_seconds"),
                "start_delay_seconds",
            ),
            captured_duration_seconds=_optional_dataframe_float(
                row.get("captured_duration_seconds"),
                "captured_duration_seconds",
            ),
        ),
        capture_policy,
    )
    if not eligibility.eligible:
        raise ValueError(
            "packet dataset row is not Capture Policy eligible: "
            f"{eligibility.exclusion_reason}"
        )


def _split_frame(frame: pd.DataFrame, split: str) -> pd.DataFrame:
    result = frame.loc[frame["split"] == split].copy()
    if result.empty:
        raise ValueError(f"packet dataset split has no rows: {split}")
    return result.reset_index(drop=True)


def _validate_window_timestamps(
    start_series: pd.Series,
    end_series: pd.Series,
) -> None:
    for raw_start, raw_end in zip(start_series, end_series, strict=True):
        start = _parse_canonical_utc(raw_start, "window_start")
        end = _parse_canonical_utc(raw_end, "window_end")
        if start.second % 10 != 0:
            raise ValueError(
                f"window_start must be on a 10-second boundary: {raw_start!r}"
            )
        if end - start != timedelta(seconds=10):
            raise ValueError("packet dataset windows must be exact 10-second intervals")


def _parse_canonical_utc(raw_value: Any, field_name: str) -> datetime:
    if not isinstance(raw_value, str) or not _UTC_TIMESTAMP_RE.match(raw_value):
        raise ValueError(
            f"{field_name} must be in YYYY-MM-DDTHH:MM:SSZ format: {raw_value!r}"
        )
    try:
        parsed = datetime.strptime(raw_value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError(
            f"{field_name} is not a valid UTC datetime: {raw_value!r}"
        ) from exc
    return parsed.replace(tzinfo=timezone.utc)


def _validate_ipv4(ip_str: str) -> None:
    try:
        ipaddress.IPv4Address(ip_str)
    except ValueError as exc:
        raise ValueError(
            f"peer_ip must be a valid IPv4 address: {ip_str!r}"
        ) from exc


def _required_dataframe_string(
    row: dict[str, Any],
    field_name: str,
) -> str:
    value = row.get(field_name)
    if pd.isna(value) or not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _optional_dataframe_string(value: Any) -> str | None:
    if value is None or pd.isna(value):
        return None
    if not isinstance(value, str):
        raise ValueError("segment_error_code must be a string or null")
    return value or None


def _optional_dataframe_float(
    value: Any,
    field_name: str,
) -> float | None:
    if value is None or pd.isna(value):
        return None
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{field_name} must be a real number or null")
    result = float(value)
    if not isfinite(result):
        raise ValueError(f"{field_name} must be finite")
    return result


def _required_non_empty_string(payload: dict[str, Any], field_name: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _required_finite_real(payload: dict[str, Any], field_name: str) -> float:
    value = payload.get(field_name)
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{field_name} must be a real number")
    result = float(value)
    if not isfinite(result):
        raise ValueError(f"{field_name} must be finite")
    return result


def _required_utc_timestamp(
    payload: dict[str, Any],
    field_name: str,
) -> datetime:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field_name} must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must be an ISO-8601 UTC timestamp"
        ) from exc
    if parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use UTC")
    return parsed


def _required_canonical_utc_timestamp(
    payload: dict[str, Any],
    field_name: str,
) -> datetime:
    if field_name not in payload:
        raise ValueError(f"{field_name} is required")
    return _parse_canonical_utc(payload[field_name], field_name)


def _optional_canonical_utc_timestamp(
    payload: dict[str, Any],
    field_name: str,
) -> datetime | None:
    value = payload.get(field_name)
    if value is None:
        return None
    return _parse_canonical_utc(value, field_name)


def _validate_sha256(value: str, field_name: str) -> str:
    normalized = value.lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef"
        for character in normalized
    ):
        raise ValueError(f"{field_name} must be a 64-character SHA256 hex digest")
    return normalized


def _validate_sha1(value: str, field_name: str) -> str:
    if len(value) != 40 or any(
        character not in "0123456789abcdef"
        for character in value
    ):
        raise ValueError(f"{field_name} must be a lowercase 40-character SHA1")
    return value
