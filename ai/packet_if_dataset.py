"""Packet Isolation Forest용 Session 기반 Dataset을 읽고 검증합니다."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import UUID

import pandas as pd

from ai.packet_if_contract import PACKET_IF_RAW_FEATURES, packet_feature_matrix


PACKET_IF_DATASET_VERSION = "packet-if-dataset-v1"

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
    *PACKET_IF_RAW_FEATURES,
)


@dataclass(frozen=True)
class PacketIFSessionSpec:
    session_id: str
    split: str
    traffic_label: str
    scenario: str


@dataclass(frozen=True)
class PacketIFDatasetManifest:
    dataset_version: str
    capture_policy_version: str
    dataset_sha256: str
    sessions: tuple[PacketIFSessionSpec, ...]


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

    frame = pd.read_csv(dataset_path)
    _validate_dataset_columns(frame)
    _validate_dataset_rows(frame, manifest)

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


def load_packet_if_manifest(path: Path) -> PacketIFDatasetManifest:
    if not path.exists():
        raise FileNotFoundError(f"packet dataset manifest not found: {path}")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid packet dataset manifest JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("packet dataset manifest must be a JSON object")

    dataset_version = _required_non_empty_string(payload, "dataset_version")
    if dataset_version != PACKET_IF_DATASET_VERSION:
        raise ValueError(
            "unsupported packet dataset version: "
            f"expected={PACKET_IF_DATASET_VERSION!r}, actual={dataset_version!r}"
        )

    capture_policy_version = _required_non_empty_string(
        payload,
        "capture_policy_version",
    )
    dataset_sha256 = _validate_sha256(
        _required_non_empty_string(payload, "dataset_sha256"),
        "dataset_sha256",
    )

    raw_sessions = payload.get("sessions")
    if not isinstance(raw_sessions, list) or not raw_sessions:
        raise ValueError("packet dataset manifest sessions must be a non-empty list")

    sessions = tuple(_parse_session_spec(item) for item in raw_sessions)
    _validate_manifest_sessions(sessions)
    return PacketIFDatasetManifest(
        dataset_version=dataset_version,
        capture_policy_version=capture_policy_version,
        dataset_sha256=dataset_sha256,
        sessions=sessions,
    )


def file_sha256(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"file not found: {path}")

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_session_spec(payload: Any) -> PacketIFSessionSpec:
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
    return PacketIFSessionSpec(
        session_id=session_id,
        split=split,
        traffic_label=traffic_label,
        scenario=scenario,
    )


def _validate_manifest_sessions(
    sessions: tuple[PacketIFSessionSpec, ...],
) -> None:
    session_ids = [spec.session_id for spec in sessions]
    if len(set(session_ids)) != len(session_ids):
        raise ValueError("packet dataset manifest contains duplicate session_id values")

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
) -> None:
    if frame["packet_feature_log_id"].isna().any():
        raise ValueError("packet_feature_log_id must not be null")
    if frame["packet_feature_log_id"].duplicated().any():
        raise ValueError("packet dataset contains duplicate packet_feature_log_id values")

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

    if frame["device_id"].isna().any() or frame["device_id"].astype(str).str.strip().eq("").any():
        raise ValueError("packet dataset requires mapped device_id values")
    invalid_directions = set(frame["direction"].dropna().astype(str)) - {"INBOUND"}
    if frame["direction"].isna().any() or invalid_directions:
        raise ValueError(
            "packet dataset only accepts INBOUND rows: "
            f"invalid={sorted(invalid_directions)}"
        )

    window_start = pd.to_datetime(frame["window_start"], utc=True, errors="raise")
    window_end = pd.to_datetime(frame["window_end"], utc=True, errors="raise")
    durations = (window_end - window_start).dt.total_seconds()
    if not durations.eq(10.0).all():
        raise ValueError("packet dataset windows must be exact 10-second intervals")

    packet_feature_matrix(frame.to_dict(orient="records"))


def _split_frame(frame: pd.DataFrame, split: str) -> pd.DataFrame:
    result = frame.loc[frame["split"] == split].copy()
    if result.empty:
        raise ValueError(f"packet dataset split has no rows: {split}")
    return result.reset_index(drop=True)


def _required_non_empty_string(payload: dict[str, Any], field_name: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _validate_sha256(value: str, field_name: str) -> str:
    normalized = value.lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef"
        for character in normalized
    ):
        raise ValueError(f"{field_name} must be a 64-character SHA256 hex digest")
    return normalized
