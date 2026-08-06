"""Read-only import of already-collected Phase 5 Packet Capture Sessions.

The 16 normal Sessions and attack Session 53 were collected manually with ESP32
hardware before the Dataset v2 Run Manifest contract existed. Re-collecting them
is not an option, and fabricating Scenario Runner Runs for them would be false.

This module verifies the preserved evidence instead: a consistent SQLite
Snapshot, the processed PCAP files, the Packet Features, and the QC/Split
decisions from the official handover. Nothing is written to the operational
database and no PCAP is touched.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import logging
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
from typing import Any

from edge.packet.capture_policy import (
    CaptureEligibilitySegment,
    CapturePolicy,
    is_capture_eligible,
)
from edge.packet.pcap_naming import parse_pcap_filename
from edge.phase5.contracts import (
    RUN_MANIFEST_SCHEMA_VERSION,
    RUN_MANIFEST_SHA256_SIDECAR_SUFFIX,
    EvaluationScope,
    ExecutionNode,
    ExpectedOutcome,
    ManifestReference,
    ManifestStatus,
    RunArtifact,
    RunManifest,
    RunStageStatuses,
    ScenarioReference,
    run_manifest_sha256,
)
from edge.phase5.verified_collection_contract import (
    ALLOWED_COLLECTION_SCENARIOS,
    ATTACK_COLLECTION_SCENARIOS,
    ATTACK_LABEL,
    NORMAL_COLLECTION_SCENARIOS,
    NORMAL_LABEL,
    VALID_SPLITS,
    VALID_TRAFFIC_LABELS,
    VERIFIED_COLLECTION_MANIFEST_FILENAME,
    VERIFIED_COLLECTION_SCHEMA_VERSION,
    VERIFIED_COLLECTION_SHA256_SIDECAR_SUFFIX,
    PayloadSchemaProvenance,
    VerifiedCollectionArtifact,
    VerifiedCollectionManifest,
    VerifiedCollectionObservation,
    file_sha256,
    format_utc,
    load_verified_collection_manifest,
    normalize_optional_ipv4,
    normalize_sha1,
    require_canonical_uuid4,
    require_identifier,
    require_non_empty_string,
    verified_collection_sha256,
)


logger = logging.getLogger(__name__)


IMPORT_SPEC_SCHEMA_VERSION = "phase5-verified-collection-import-spec-v1"

# 설계 2.2 절에서 확정한 재사용 대상. 이 목록 밖의 공격 Session은 Dataset에
# 넣지 않는다 (Session 51·52와 Holdout은 별도 목적으로 보존한다).
VERIFIED_ATTACK_SESSION_IDS = frozenset({"23d5dc5b-1e73-44e4-80ed-1d0c12bda7f9"})
NORMAL_COLLECTION_DEVICE_ID = "esp32_01"
ATTACK_COLLECTION_DEVICE_ID = "esp32_02"
ATTACK_TARGET_SOURCE_IP = "192.168.0.5"

NORMAL_FIRMWARE_VERSION = "phase5-normal-pilot-v1"
NORMAL_PAYLOAD_SCHEMA_VERSION = "phase5-normal-payload-v1"
ATTACK_FIRMWARE_VERSION = "phase5-packet-rate-sender-v2"
ATTACK_PAYLOAD_SCHEMA_VERSION = "phase5-packet-rate-udp-payload-v1"

# Dataset 전체가 하나의 정상 정책과 하나의 Capture Filter를 써야 한다.
REQUIRED_NORMAL_POLICY_VERSION = "phase5-normal-policy-v1.1"
REQUIRED_CAPTURE_FILTER = "tcp or udp"

# 설계 12절이 고정한 Session 53의 실측 증적. ESP32의 udp.endPacket()==1은 수신
# ACK가 아니므로 960과 880의 차이를 원인으로 단정하지 않고 UNRESOLVED로 남긴다.
SESSION_53_SENDER_REPORTED_PACKETS = 960
SESSION_53_GATEWAY_OBSERVED_PACKETS = 880
SESSION_53_OBSERVATION_GAP_PACKETS = 80
SESSION_53_OBSERVATION_GAP_CAUSE = "UNRESOLVED"

ELIGIBLE_SEGMENT_STATUSES = frozenset({"PROCESSED", "EMPTY"})
NOMINAL_WINDOW_SECONDS = 10
_RUN_ID_PREFIX = "verified-"


class VerifiedCollectionImportError(RuntimeError):
    """A preserved Session failed read-only verification."""


@dataclass(frozen=True)
class VerifiedCollectionSessionSpec:
    """One operator-declared Session from the Import Spec."""

    session_id: str
    collection_slot_id: str
    split: str
    traffic_label: str
    scenario: str
    collection_device_id: str
    firmware_version: str
    payload_schema_version: str
    payload_schema_provenance: PayloadSchemaProvenance
    capture_source_commit_sha: str
    target_device_id: str | None
    target_source_ip: str | None
    source_capture_group_id: str
    # DB에서 유도할 수 없어 운영자가 인계 자료에서 확정해야 하는 값들이다.
    # sender_reported_packets는 ESP32 Serial 로그, gateway_first_attack_packet_at은
    # Gateway 관측 기록에서 온다. 둘 다 없으면 null로 남긴다.
    sender_reported_packets: int | None
    observation_gap_cause: str | None
    gateway_first_attack_packet_at: datetime | None

    _ALLOWED = frozenset(
        {
            "session_id",
            "collection_slot_id",
            "split",
            "traffic_label",
            "scenario",
            "collection_device_id",
            "firmware_version",
            "payload_schema_version",
            "payload_schema_provenance",
            "capture_source_commit_sha",
            "target_device_id",
            "target_source_ip",
            "source_capture_group_id",
            "sender_reported_packets",
            "observation_gap_cause",
            "gateway_first_attack_packet_at",
        }
    )
    _REQUIRED = frozenset(
        {
            "session_id",
            "collection_slot_id",
            "split",
            "traffic_label",
            "scenario",
            "collection_device_id",
            "firmware_version",
            "payload_schema_version",
            "payload_schema_provenance",
            "capture_source_commit_sha",
        }
    )

    @property
    def run_id(self) -> str:
        return f"{_RUN_ID_PREFIX}{self.collection_slot_id}"

    @property
    def is_attack(self) -> bool:
        return self.traffic_label == ATTACK_LABEL

    @property
    def firmware_reported_payload_schema_version(self) -> str | None:
        if self.payload_schema_provenance is PayloadSchemaProvenance.FIRMWARE_REPORTED:
            return self.payload_schema_version
        return None

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "VerifiedCollectionSessionSpec":
        if not isinstance(payload, Mapping):
            raise ValueError("each Import Spec Session must be a JSON object")
        unknown = sorted(set(payload) - cls._ALLOWED)
        if unknown:
            raise ValueError(f"Import Spec Session contains unknown fields: {unknown}")
        missing = sorted(cls._REQUIRED - set(payload))
        if missing:
            raise ValueError(f"Import Spec Session is missing fields: {missing}")

        session_id = require_canonical_uuid4(payload["session_id"], "session_id")
        split = require_non_empty_string(payload["split"], "split")
        if split not in VALID_SPLITS:
            raise ValueError(f"invalid split: {split!r}")
        traffic_label = require_non_empty_string(
            payload["traffic_label"],
            "traffic_label",
        )
        if traffic_label not in VALID_TRAFFIC_LABELS:
            raise ValueError(f"invalid traffic_label: {traffic_label!r}")
        scenario = require_identifier(payload["scenario"], "scenario")
        if scenario not in ALLOWED_COLLECTION_SCENARIOS:
            raise ValueError(
                f"scenario is not an allowed Verified Collection scenario: {scenario!r}"
            )
        collection_device_id = require_identifier(
            payload["collection_device_id"],
            "collection_device_id",
        )
        firmware_version = require_identifier(
            payload["firmware_version"],
            "firmware_version",
        )
        payload_schema_version = require_identifier(
            payload["payload_schema_version"],
            "payload_schema_version",
        )
        provenance = payload["payload_schema_provenance"]
        if isinstance(provenance, str):
            try:
                provenance = PayloadSchemaProvenance(provenance)
            except ValueError as exc:
                raise ValueError(
                    "payload_schema_provenance must be one of "
                    f"{sorted(item.value for item in PayloadSchemaProvenance)}"
                ) from exc
        if not isinstance(provenance, PayloadSchemaProvenance):
            raise ValueError("payload_schema_provenance must be a known value")
        capture_commit = normalize_sha1(
            payload["capture_source_commit_sha"],
            "capture_source_commit_sha",
        )
        target_device_id = payload.get("target_device_id")
        if target_device_id is not None:
            target_device_id = require_identifier(target_device_id, "target_device_id")
        target_source_ip = normalize_optional_ipv4(
            payload.get("target_source_ip"),
            "target_source_ip",
        )
        raw_group = payload.get("source_capture_group_id")
        source_capture_group_id = (
            session_id
            if raw_group is None
            else require_canonical_uuid4(raw_group, "source_capture_group_id")
        )
        sender_reported_packets = payload.get("sender_reported_packets")
        if sender_reported_packets is not None:
            if (
                isinstance(sender_reported_packets, bool)
                or not isinstance(sender_reported_packets, int)
                or sender_reported_packets < 0
            ):
                raise ValueError(
                    "sender_reported_packets must be a non-negative integer"
                )
        observation_gap_cause = payload.get("observation_gap_cause")
        if observation_gap_cause is not None:
            observation_gap_cause = require_identifier(
                observation_gap_cause,
                "observation_gap_cause",
            )
        gateway_first_attack_packet_at = payload.get("gateway_first_attack_packet_at")
        if gateway_first_attack_packet_at is not None:
            gateway_first_attack_packet_at = _parse_utc(
                gateway_first_attack_packet_at,
                "gateway_first_attack_packet_at",
            )

        spec = cls(
            session_id=session_id,
            collection_slot_id=require_identifier(
                payload["collection_slot_id"],
                "collection_slot_id",
            ),
            split=split,
            traffic_label=traffic_label,
            scenario=scenario,
            collection_device_id=collection_device_id,
            firmware_version=firmware_version,
            payload_schema_version=payload_schema_version,
            payload_schema_provenance=provenance,
            capture_source_commit_sha=capture_commit,
            target_device_id=target_device_id,
            target_source_ip=target_source_ip,
            source_capture_group_id=source_capture_group_id,
            sender_reported_packets=sender_reported_packets,
            observation_gap_cause=observation_gap_cause,
            gateway_first_attack_packet_at=gateway_first_attack_packet_at,
        )
        spec._validate_profile()
        return spec

    def _validate_profile(self) -> None:
        if self.traffic_label == NORMAL_LABEL:
            if self.scenario not in NORMAL_COLLECTION_SCENARIOS:
                raise ValueError(
                    f"normal Session scenario must be a normal profile: {self.scenario!r}"
                )
            if self.collection_device_id != NORMAL_COLLECTION_DEVICE_ID:
                raise ValueError(
                    "normal Session collection_device_id must be "
                    f"{NORMAL_COLLECTION_DEVICE_ID!r}: "
                    f"{self.collection_device_id!r}"
                )
            if self.target_device_id is not None:
                raise ValueError("normal Session must not declare target_device_id")
            if self.target_source_ip is not None:
                raise ValueError("normal Session must not declare target_source_ip")
            if (
                self.firmware_version != NORMAL_FIRMWARE_VERSION
                or self.payload_schema_version != NORMAL_PAYLOAD_SCHEMA_VERSION
            ):
                raise ValueError(
                    "normal Session firmware_version/payload_schema_version must be "
                    f"{NORMAL_FIRMWARE_VERSION!r}/{NORMAL_PAYLOAD_SCHEMA_VERSION!r}"
                )
            if (
                self.payload_schema_provenance
                is not PayloadSchemaProvenance.FIRMWARE_REPORTED
            ):
                raise ValueError(
                    "normal Session payload_schema_provenance must be FIRMWARE_REPORTED"
                )
            return

        if self.session_id not in VERIFIED_ATTACK_SESSION_IDS:
            raise ValueError(
                "unknown attack session for Verified Collection import: "
                f"{self.session_id!r}"
            )
        if self.scenario not in ATTACK_COLLECTION_SCENARIOS:
            raise ValueError(
                f"attack Session scenario must be an attack profile: {self.scenario!r}"
            )
        if self.split != "test":
            raise ValueError("attack Session must use the test split")
        if self.collection_device_id != ATTACK_COLLECTION_DEVICE_ID:
            raise ValueError(
                "attack Session collection_device_id must be "
                f"{ATTACK_COLLECTION_DEVICE_ID!r}"
            )
        if self.target_device_id != ATTACK_COLLECTION_DEVICE_ID:
            raise ValueError(
                f"attack Session target_device_id must be {ATTACK_COLLECTION_DEVICE_ID!r}"
            )
        if self.target_source_ip != ATTACK_TARGET_SOURCE_IP:
            raise ValueError(
                f"attack Session target_source_ip must be {ATTACK_TARGET_SOURCE_IP!r}"
            )
        if (
            self.firmware_version != ATTACK_FIRMWARE_VERSION
            or self.payload_schema_version != ATTACK_PAYLOAD_SCHEMA_VERSION
        ):
            raise ValueError(
                "attack Session firmware_version/payload_schema_version must be "
                f"{ATTACK_FIRMWARE_VERSION!r}/{ATTACK_PAYLOAD_SCHEMA_VERSION!r}"
            )
        if (
            self.payload_schema_provenance
            is not PayloadSchemaProvenance.RETROSPECTIVE_OPERATOR_ATTESTED_WITH_PCAP_INVENTORY
        ):
            # 수집 당시 Firmware는 Payload Schema Version을 출력하지 않았다.
            raise ValueError(
                "attack Session payload_schema_provenance must be "
                "RETROSPECTIVE_OPERATOR_ATTESTED_WITH_PCAP_INVENTORY"
            )
        # 설계 12절의 실측 증적을 필수로 강제한다. 값이 다르면 다른 수집분이거나
        # 인계 자료를 잘못 옮긴 것이므로 Batch 전체를 멈춘다.
        if self.sender_reported_packets != SESSION_53_SENDER_REPORTED_PACKETS:
            raise ValueError(
                "attack Session sender_reported_packets must be "
                f"{SESSION_53_SENDER_REPORTED_PACKETS}: "
                f"{self.sender_reported_packets!r}"
            )
        if self.observation_gap_cause not in (None, SESSION_53_OBSERVATION_GAP_CAUSE):
            raise ValueError(
                "attack Session observation_gap_cause must be "
                f"{SESSION_53_OBSERVATION_GAP_CAUSE!r}: "
                f"{self.observation_gap_cause!r}"
            )


@dataclass(frozen=True)
class VerifiedCollectionImportSpec:
    dataset_package_id: str
    normal_policy_version: str
    capture_filter: str
    sessions: tuple[VerifiedCollectionSessionSpec, ...]
    schema_version: str = IMPORT_SPEC_SCHEMA_VERSION

    _ALLOWED = frozenset(
        {
            "schema_version",
            "dataset_package_id",
            "normal_policy_version",
            "capture_filter",
            "sessions",
        }
    )

    @classmethod
    def from_json(cls, text: str) -> "VerifiedCollectionImportSpec":
        payload = json.loads(text)
        if not isinstance(payload, dict):
            raise ValueError("Import Spec must be a JSON object")
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "VerifiedCollectionImportSpec":
        unknown = sorted(set(payload) - cls._ALLOWED)
        if unknown:
            raise ValueError(f"Import Spec contains unknown fields: {unknown}")
        missing = sorted(cls._ALLOWED - set(payload))
        if missing:
            raise ValueError(f"Import Spec is missing fields: {missing}")

        schema_version = require_non_empty_string(
            payload["schema_version"],
            "schema_version",
        )
        if schema_version != IMPORT_SPEC_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported Import Spec schema_version: {schema_version!r}"
            )
        raw_sessions = payload["sessions"]
        if not isinstance(raw_sessions, list) or not raw_sessions:
            raise ValueError("Import Spec sessions must be a non-empty list")

        normal_policy_version = require_identifier(
            payload["normal_policy_version"],
            "normal_policy_version",
        )
        if normal_policy_version != REQUIRED_NORMAL_POLICY_VERSION:
            raise ValueError(
                "normal_policy_version must be "
                f"{REQUIRED_NORMAL_POLICY_VERSION!r}: {normal_policy_version!r}"
            )
        capture_filter = require_non_empty_string(
            payload["capture_filter"],
            "capture_filter",
        )
        if capture_filter != REQUIRED_CAPTURE_FILTER:
            raise ValueError(
                f"capture_filter must be {REQUIRED_CAPTURE_FILTER!r}: "
                f"{capture_filter!r}"
            )

        spec = cls(
            schema_version=schema_version,
            dataset_package_id=require_identifier(
                payload["dataset_package_id"],
                "dataset_package_id",
            ),
            normal_policy_version=normal_policy_version,
            capture_filter=capture_filter,
            sessions=tuple(
                VerifiedCollectionSessionSpec.from_dict(item)
                for item in raw_sessions
            ),
        )
        spec._validate_batch()
        return spec

    def _validate_batch(self) -> None:
        session_ids = [session.session_id for session in self.sessions]
        if len(set(session_ids)) != len(session_ids):
            raise ValueError("Import Spec contains a duplicate session_id")
        slot_ids = [session.collection_slot_id for session in self.sessions]
        if len(set(slot_ids)) != len(slot_ids):
            raise ValueError("Import Spec contains a duplicate collection_slot_id")
        run_ids = [session.run_id for session in self.sessions]
        if len(set(run_ids)) != len(run_ids):
            raise ValueError("Import Spec contains a duplicate run_id")

        group_splits: dict[str, str] = {}
        for session in self.sessions:
            previous = group_splits.setdefault(
                session.source_capture_group_id,
                session.split,
            )
            if previous != session.split:
                raise ValueError(
                    "source_capture_group_id must not cross Dataset splits: "
                    f"{session.source_capture_group_id}"
                )

        present_splits = {session.split for session in self.sessions}
        missing_splits = VALID_SPLITS - present_splits
        if missing_splits:
            raise ValueError(
                f"Import Spec is missing Dataset splits: {sorted(missing_splits)}"
            )
        test_labels = {
            session.traffic_label
            for session in self.sessions
            if session.split == "test"
        }
        missing_labels = VALID_TRAFFIC_LABELS - test_labels
        if missing_labels:
            raise ValueError(
                "test split must contain both normal and attack Sessions: "
                f"missing={sorted(missing_labels)}"
            )
        for session in self.sessions:
            if session.split in {"train", "validation"} and session.is_attack:
                raise ValueError(
                    "train and validation splits accept normal Sessions only"
                )

    def session_by_id(self, session_id: str) -> VerifiedCollectionSessionSpec:
        for session in self.sessions:
            if session.session_id == session_id:
                return session
        raise KeyError(session_id)


@dataclass(frozen=True)
class PcapEvidence:
    relative_path: str
    file_name: str
    size_bytes: int
    sha256: str
    segment_id: int
    window_start: datetime
    window_end: datetime


@dataclass(frozen=True)
class SegmentEvidence:
    segment_id: int
    status: str
    file_name: str | None
    window_start: datetime
    window_end: datetime
    packet_count: int
    start_delay_seconds: float | None
    captured_duration_seconds: float | None
    error_code: str | None


@dataclass(frozen=True)
class VerifiedCollectionSessionPlan:
    """Everything verified about one Session, ready to be written out."""

    spec: VerifiedCollectionSessionSpec
    capture_interface: str
    started_at: datetime
    first_window_start: datetime
    ended_at: datetime
    segments: tuple[SegmentEvidence, ...]
    processed_segment_count: int
    empty_segment_count: int
    eligible_row_count: int
    feature_packet_count: int
    included_device_ids: tuple[str, ...]
    background_traffic_present: bool
    device_ips: Mapping[str, str]
    pcap_files: tuple[PcapEvidence, ...]
    feature_ready_through: datetime

    @property
    def session_id(self) -> str:
        return self.spec.session_id

    @property
    def traffic_label(self) -> str:
        return self.spec.traffic_label

    @property
    def target_source_ip(self) -> str | None:
        return self.spec.target_source_ip

    @property
    def segment_count(self) -> int:
        return len(self.segments)

    @property
    def gateway_observed_packets(self) -> int:
        return self.feature_packet_count


@dataclass(frozen=True)
class VerifiedCollectionBatchPlan:
    spec: VerifiedCollectionImportSpec
    sessions: tuple[VerifiedCollectionSessionPlan, ...]
    verification_commit_sha: str
    db_snapshot_sha256: str
    capture_policy: CapturePolicy

    def session_by_id(self, session_id: str) -> VerifiedCollectionSessionPlan:
        for session in self.sessions:
            if session.session_id == session_id:
                return session
        raise KeyError(session_id)


def assert_standalone_snapshot(path: Path) -> None:
    """Refuse a database file whose content still lives in a WAL sidecar.

    A live WAL-mode database can be a few kilobytes on disk while every table
    sits in `<db>-wal`. Copying only the main file would produce a package that
    verifies cleanly and contains nothing. The Runbook requires a consistent
    standalone snapshot made with the SQLite Backup API, which has no WAL.
    """
    wal_path = Path(f"{path}-wal")
    if wal_path.is_file() and wal_path.stat().st_size > 0:
        raise VerifiedCollectionImportError(
            "DB snapshot still has a non-empty WAL sidecar, so it is not a "
            "consistent standalone snapshot. Create it with the SQLite Backup "
            f"API (or checkpoint and close all writers) first: {wal_path}"
        )


def connect_snapshot_read_only(path: Path) -> sqlite3.Connection:
    """Open an absolute SQLite Snapshot in a mode that cannot write.

    The absolute-path check runs before any `resolve()` so a relative path is
    rejected as given, rather than being silently completed against the current
    working directory.
    """
    if not path.is_absolute():
        raise ValueError(f"DB snapshot path must be absolute: {path}")
    path = path.resolve()
    if not path.is_file():
        raise ValueError(f"DB snapshot is not a file: {path}")
    assert_standalone_snapshot(path)
    uri = f"file:{path.as_posix()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    return connection


def preflight_verified_collection(
    *,
    db_snapshot: Path,
    processed_pcap_dir: Path,
    spec: VerifiedCollectionImportSpec,
    verification_commit_sha: str,
    capture_policy: CapturePolicy | None = None,
) -> VerifiedCollectionBatchPlan:
    """Verify every declared Session read-only and return the batch plan."""
    commit_sha = normalize_sha1(verification_commit_sha, "verification_commit_sha")
    policy = capture_policy or CapturePolicy.from_env()
    # 상대경로는 resolve 전에 거부한다. resolve 후에 검사하면 CWD 기준으로
    # 완성된 경로가 절대경로로 보여 통과해버린다.
    if not db_snapshot.is_absolute():
        raise ValueError(f"DB snapshot path must be absolute: {db_snapshot}")
    snapshot_path = db_snapshot.resolve()
    pcap_dir = processed_pcap_dir.resolve()
    if not pcap_dir.is_dir():
        raise VerifiedCollectionImportError(
            f"processed PCAP directory not found: {pcap_dir}"
        )

    connection = connect_snapshot_read_only(snapshot_path)
    try:
        _assert_snapshot_integrity(connection, snapshot_path)
        device_ips = _load_device_ips(connection)
        plans = tuple(
            _build_session_plan(
                connection,
                session_spec=session_spec,
                device_ips=device_ips,
                pcap_dir=pcap_dir,
                capture_policy=policy,
            )
            for session_spec in spec.sessions
        )
    finally:
        connection.close()

    return VerifiedCollectionBatchPlan(
        spec=spec,
        sessions=plans,
        verification_commit_sha=commit_sha,
        db_snapshot_sha256=file_sha256(snapshot_path),
        capture_policy=policy,
    )


def _assert_snapshot_integrity(
    connection: sqlite3.Connection,
    snapshot_path: Path,
) -> None:
    integrity = connection.execute("PRAGMA integrity_check").fetchone()
    if integrity is None or str(integrity[0]).lower() != "ok":
        raise VerifiedCollectionImportError(
            f"DB snapshot failed integrity_check: {snapshot_path}"
        )
    violations = connection.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise VerifiedCollectionImportError(
            f"DB snapshot has {len(violations)} foreign key violations: {snapshot_path}"
        )


def _load_device_ips(connection: sqlite3.Connection) -> dict[str, str]:
    rows = connection.execute(
        "SELECT device_id, ip_address FROM devices"
    ).fetchall()
    return {str(row["device_id"]): str(row["ip_address"]) for row in rows}


def _build_session_plan(
    connection: sqlite3.Connection,
    *,
    session_spec: VerifiedCollectionSessionSpec,
    device_ips: Mapping[str, str],
    pcap_dir: Path,
    capture_policy: CapturePolicy,
) -> VerifiedCollectionSessionPlan:
    session_row = connection.execute(
        """
        SELECT id, session_id, capture_interface, started_at,
               first_window_start, ended_at, status
        FROM packet_capture_sessions
        WHERE session_id = ?
        """,
        (session_spec.session_id,),
    ).fetchone()
    if session_row is None:
        raise VerifiedCollectionImportError(
            f"Capture Session not found in snapshot: {session_spec.session_id}"
        )
    status = str(session_row["status"])
    if status != "COMPLETED":
        raise VerifiedCollectionImportError(
            f"Capture Session must be COMPLETED: {session_spec.session_id} "
            f"(status={status})"
        )
    for column in ("started_at", "first_window_start", "ended_at"):
        if session_row[column] is None:
            raise VerifiedCollectionImportError(
                f"Capture Session is missing {column}: {session_spec.session_id}"
            )

    started_at = _parse_utc(session_row["started_at"], "started_at")
    first_window_start = _parse_utc(
        session_row["first_window_start"],
        "first_window_start",
    )
    ended_at = _parse_utc(session_row["ended_at"], "ended_at")

    segments = _load_segments(connection, int(session_row["id"]))
    if not segments:
        raise VerifiedCollectionImportError(
            f"Capture Session has no Segments: {session_spec.session_id}"
        )
    _validate_segment_statuses(session_spec.session_id, segments)
    _validate_contiguous_windows(session_spec.session_id, segments)
    _validate_session_window_bounds(
        session_spec.session_id,
        segments,
        first_window_start=first_window_start,
        ended_at=ended_at,
    )

    features = _load_features(connection, int(session_row["id"]))
    _validate_segment_feature_invariants(session_spec.session_id, segments, features)

    eligible_rows = _eligible_rows(
        segments=segments,
        features=features,
        device_ips=device_ips,
        capture_policy=capture_policy,
    )
    if not eligible_rows:
        raise VerifiedCollectionImportError(
            "Capture Session has no eligible registered INBOUND rows: "
            f"{session_spec.session_id}"
        )

    # Export Row는 정상·공격 모두 하나의 Device와 그 Source IP로 좁힌다. 정상
    # Session도 다른 등록 Device의 적격 Row가 섞여 있을 수 있고, 그것까지
    # Export하면 Dataset이 선언한 기기 범위와 어긋난다.
    export_device_id = session_spec.target_device_id or session_spec.collection_device_id
    export_source_ip = session_spec.target_source_ip or device_ips.get(export_device_id)
    if export_source_ip is None:
        raise VerifiedCollectionImportError(
            "export Device is not registered in the snapshot: "
            f"{session_spec.session_id} (device_id={export_device_id!r})"
        )
    exported_rows = [
        row
        for row in eligible_rows
        if str(row["device_id"]) == export_device_id
        and str(row["peer_ip"]) == export_source_ip
    ]
    if not exported_rows:
        raise VerifiedCollectionImportError(
            "Session has no eligible rows for the declared export Device and "
            f"Source IP: {session_spec.session_id} "
            f"(device_id={export_device_id!r}, source_ip={export_source_ip!r})"
        )

    # background_traffic_present는 정상·공격 모두 Export 필터 적용 **전** 전체
    # 적격 Row 기준으로 계산한다.
    all_eligible_devices = {str(row["device_id"]) for row in eligible_rows}
    exported_devices = {export_device_id}
    background_traffic_present = bool(all_eligible_devices - exported_devices)
    pcap_files = _verify_pcap_files(
        session_spec.session_id,
        segments=segments,
        pcap_dir=pcap_dir,
        capture_interface=str(session_row["capture_interface"]),
    )
    feature_ready_through = segments[-1].window_end

    return VerifiedCollectionSessionPlan(
        spec=session_spec,
        capture_interface=str(session_row["capture_interface"]),
        started_at=started_at,
        first_window_start=first_window_start,
        ended_at=ended_at,
        segments=segments,
        processed_segment_count=sum(
            1 for segment in segments if segment.status == "PROCESSED"
        ),
        empty_segment_count=sum(
            1 for segment in segments if segment.status == "EMPTY"
        ),
        eligible_row_count=len(exported_rows),
        feature_packet_count=sum(int(row["packet_count"]) for row in exported_rows),
        included_device_ids=tuple(sorted(exported_devices)),
        background_traffic_present=background_traffic_present,
        device_ips={export_device_id: export_source_ip},
        pcap_files=pcap_files,
        feature_ready_through=feature_ready_through,
    )


def _load_segments(
    connection: sqlite3.Connection,
    session_pk: int,
) -> tuple[SegmentEvidence, ...]:
    rows = connection.execute(
        """
        SELECT id, status, file_name, window_start, window_end, packet_count,
               start_delay_seconds, captured_duration_seconds, error_code
        FROM packet_capture_segments
        WHERE capture_session_id = ?
        ORDER BY window_start, id
        """,
        (session_pk,),
    ).fetchall()
    return tuple(
        SegmentEvidence(
            segment_id=int(row["id"]),
            status=str(row["status"]),
            file_name=None if row["file_name"] is None else str(row["file_name"]),
            window_start=_parse_utc(row["window_start"], "segment.window_start"),
            window_end=_parse_utc(row["window_end"], "segment.window_end"),
            packet_count=int(row["packet_count"] or 0),
            start_delay_seconds=(
                None
                if row["start_delay_seconds"] is None
                else float(row["start_delay_seconds"])
            ),
            captured_duration_seconds=(
                None
                if row["captured_duration_seconds"] is None
                else float(row["captured_duration_seconds"])
            ),
            error_code=None if row["error_code"] is None else str(row["error_code"]),
        )
        for row in rows
    )


def _load_features(
    connection: sqlite3.Connection,
    session_pk: int,
) -> list[sqlite3.Row]:
    return connection.execute(
        """
        SELECT pfl.id, pfl.capture_segment_id, pfl.device_id, pfl.peer_ip,
               pfl.direction, pfl.window_start, pfl.window_end, pfl.packet_count
        FROM packet_feature_logs pfl
        JOIN packet_capture_segments pcs ON pfl.capture_segment_id = pcs.id
        WHERE pcs.capture_session_id = ?
        ORDER BY pfl.window_start, pfl.id
        """,
        (session_pk,),
    ).fetchall()


def _validate_segment_statuses(
    session_id: str,
    segments: Sequence[SegmentEvidence],
) -> None:
    for segment in segments:
        if segment.status == "READY":
            raise VerifiedCollectionImportError(
                "Capture Session still has a READY Segment; run the Packet Feature "
                f"extractor before importing: {session_id} (segment={segment.segment_id})"
            )
        if segment.status == "FAILED":
            raise VerifiedCollectionImportError(
                "Capture Session has a FAILED Segment: "
                f"{session_id} (segment={segment.segment_id})"
            )
        if segment.status not in ELIGIBLE_SEGMENT_STATUSES:
            raise VerifiedCollectionImportError(
                f"unknown Segment status {segment.status!r}: {session_id}"
            )


def _validate_session_window_bounds(
    session_id: str,
    segments: Sequence[SegmentEvidence],
    *,
    first_window_start: datetime,
    ended_at: datetime,
) -> None:
    """Tie the Segment range to the Session's own recorded boundaries.

    Contiguity alone does not prove the Segments belong to this Session's
    declared span: a shifted-but-contiguous run would still pass. The first
    Segment must start exactly at `first_window_start`, and the last Segment
    must finish no later than `ended_at`.
    """
    if segments[0].window_start != first_window_start:
        raise VerifiedCollectionImportError(
            "first Segment window_start must equal the Session first_window_start: "
            f"{session_id} (session={format_utc(first_window_start)}, "
            f"segment={format_utc(segments[0].window_start)})"
        )
    if segments[-1].window_end > ended_at:
        raise VerifiedCollectionImportError(
            "last Segment window_end must not be later than the Session ended_at: "
            f"{session_id} (session={format_utc(ended_at)}, "
            f"segment={format_utc(segments[-1].window_end)})"
        )


def _validate_contiguous_windows(
    session_id: str,
    segments: Sequence[SegmentEvidence],
) -> None:
    expected_start = segments[0].window_start
    for segment in segments:
        if segment.window_end - segment.window_start != timedelta(
            seconds=NOMINAL_WINDOW_SECONDS
        ):
            raise VerifiedCollectionImportError(
                "Segment window must span exactly 10 seconds: "
                f"{session_id} (segment={segment.segment_id})"
            )
        if segment.window_start != expected_start:
            raise VerifiedCollectionImportError(
                "Capture Session windows must be contiguous: "
                f"{session_id} (expected={expected_start.isoformat()}, "
                f"actual={segment.window_start.isoformat()})"
            )
        expected_start = segment.window_end


def _validate_segment_feature_invariants(
    session_id: str,
    segments: Sequence[SegmentEvidence],
    features: Sequence[sqlite3.Row],
) -> None:
    features_by_segment: dict[int, list[sqlite3.Row]] = {}
    for row in features:
        features_by_segment.setdefault(int(row["capture_segment_id"]), []).append(row)

    for segment in segments:
        segment_features = features_by_segment.get(segment.segment_id, [])
        if segment.status == "PROCESSED" and not segment_features:
            raise VerifiedCollectionImportError(
                "PROCESSED Segment must have at least one Packet Feature row: "
                f"{session_id} (segment={segment.segment_id})"
            )
        if segment.status == "EMPTY" and segment_features:
            raise VerifiedCollectionImportError(
                "EMPTY Segment must not have Packet Feature rows: "
                f"{session_id} (segment={segment.segment_id})"
            )
        for row in segment_features:
            feature_start = _parse_utc(row["window_start"], "feature.window_start")
            feature_end = _parse_utc(row["window_end"], "feature.window_end")
            if (
                feature_start != segment.window_start
                or feature_end != segment.window_end
            ):
                raise VerifiedCollectionImportError(
                    "Packet Feature window must match its Segment window: "
                    f"{session_id} (segment={segment.segment_id}, "
                    f"feature={int(row['id'])})"
                )


def _eligible_rows(
    *,
    segments: Sequence[SegmentEvidence],
    features: Sequence[sqlite3.Row],
    device_ips: Mapping[str, str],
    capture_policy: CapturePolicy,
) -> list[sqlite3.Row]:
    eligible_segment_ids = {
        segment.segment_id
        for segment in segments
        if is_capture_eligible(
            CaptureEligibilitySegment(
                status=segment.status,
                error_code=segment.error_code,
                start_delay_seconds=segment.start_delay_seconds,
                captured_duration_seconds=segment.captured_duration_seconds,
            ),
            capture_policy,
        ).eligible
    }
    rows: list[sqlite3.Row] = []
    for row in features:
        if int(row["capture_segment_id"]) not in eligible_segment_ids:
            continue
        if str(row["direction"]) != "INBOUND":
            continue
        device_id = row["device_id"]
        if device_id is None:
            continue
        device_id = str(device_id)
        registered_ip = device_ips.get(device_id)
        if registered_ip is None or registered_ip != str(row["peer_ip"]):
            continue
        rows.append(row)
    return rows


def _verify_pcap_files(
    session_id: str,
    *,
    segments: Sequence[SegmentEvidence],
    pcap_dir: Path,
    capture_interface: str,
) -> tuple[PcapEvidence, ...]:
    evidence: list[PcapEvidence] = []
    for segment in segments:
        if segment.file_name is None:
            raise VerifiedCollectionImportError(
                "Segment has no PCAP file_name: "
                f"{session_id} (segment={segment.segment_id})"
            )
        parsed = parse_pcap_filename(segment.file_name)
        if parsed is None:
            raise VerifiedCollectionImportError(
                "PCAP file name is not a canonical capture name: "
                f"{session_id} ({segment.file_name})"
            )
        if (
            parsed.session_id != session_id
            or parsed.interface != capture_interface
            or parsed.window_start != segment.window_start
            or parsed.window_end != segment.window_end
            or parsed.is_tmp
        ):
            raise VerifiedCollectionImportError(
                "PCAP file name does not match its Segment metadata: "
                f"{session_id} ({segment.file_name})"
            )
        path = pcap_dir / segment.file_name
        if not path.is_file():
            raise VerifiedCollectionImportError(
                f"PCAP file is missing: {session_id} ({segment.file_name})"
            )
        evidence.append(
            PcapEvidence(
                relative_path=segment.file_name,
                file_name=segment.file_name,
                size_bytes=path.stat().st_size,
                sha256=file_sha256(path),
                segment_id=segment.segment_id,
                window_start=segment.window_start,
                window_end=segment.window_end,
            )
        )
    return tuple(evidence)


def _parse_utc(value: Any, field_name: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise VerifiedCollectionImportError(
                f"{field_name} is not an ISO-8601 timestamp: {value!r}"
            ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# --- Package publication -----------------------------------------------------

DEFAULT_OBSERVATION_GAP_CAUSE = "UNRESOLVED"
_EVIDENCE_DIRNAME = "evidence"
_RUNS_DIRNAME = "runs"
_DB_SNAPSHOT_FILENAME = "db-snapshot.db"
_DB_SNAPSHOT_METADATA_FILENAME = "db-snapshot-metadata.json"
_EXPORT_SPEC_FILENAME = "packet-if-export-spec-v2.json"
_IMPORT_SUMMARY_FILENAME = "import-summary.json"
_RUN_MANIFEST_FILENAME = "run-manifest.json"
_EVIDENCE_FILES = (
    ("session_snapshot", "session-snapshot.json"),
    ("feature_qc", "feature-qc.json"),
    ("pcap_inventory", "pcap-inventory.json"),
    ("source_evidence", "source-evidence.json"),
)


def write_verified_collection_package(
    plan: VerifiedCollectionBatchPlan,
    *,
    db_snapshot: Path,
    processed_pcap_dir: Path,
    output_root: Path,
    verified_at: datetime,
) -> Path:
    """Publish the whole batch atomically, or publish nothing at all.

    Every file is written into a temporary directory on the same filesystem and
    only renamed into place once all 17 Sessions succeeded and every hash chain
    reloaded. A partially verified batch must never become a Dataset input.
    """
    output_root = output_root.resolve()
    final_path = output_root / plan.spec.dataset_package_id
    if os.path.lexists(final_path):
        raise FileExistsError(
            f"Verified Collection package already exists: {final_path}"
        )
    output_root.mkdir(parents=True, exist_ok=True)
    snapshot_path = db_snapshot.resolve()
    pcap_dir = processed_pcap_dir.resolve()

    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{plan.spec.dataset_package_id}.",
            suffix=".tmp",
            dir=output_root,
        )
    )
    try:
        _copy_snapshot(plan, snapshot_path, staging)
        export_sessions: list[dict[str, Any]] = []
        for session_plan in plan.sessions:
            export_sessions.append(
                _write_run_directory(
                    plan,
                    session_plan,
                    staging=staging,
                    pcap_dir=pcap_dir,
                    verified_at=verified_at,
                )
            )
        _write_export_spec(plan, staging, export_sessions)
        _write_import_summary(plan, staging, verified_at, export_sessions)
        _reverify_package(staging, export_sessions)
        _fsync_tree(staging)
        if os.path.lexists(final_path):
            raise FileExistsError(
                "Verified Collection package appeared during publication; "
                f"refusing to replace it: {final_path}"
            )
        os.rename(staging, final_path)
        staging = None  # type: ignore[assignment]
        _fsync_directory(output_root)
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
    return final_path


def _copy_snapshot(
    plan: VerifiedCollectionBatchPlan,
    snapshot_path: Path,
    staging: Path,
) -> None:
    destination = staging / _DB_SNAPSHOT_FILENAME
    shutil.copyfile(snapshot_path, destination)
    copied_sha256 = file_sha256(destination)
    if copied_sha256 != plan.db_snapshot_sha256:
        raise VerifiedCollectionImportError(
            "copied DB snapshot SHA256 does not match the verified source: "
            f"expected={plan.db_snapshot_sha256}, actual={copied_sha256}"
        )
    connection = connect_snapshot_read_only(destination.resolve())
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
    finally:
        connection.close()
    _write_json(
        staging / _DB_SNAPSHOT_METADATA_FILENAME,
        {
            "source_path_name": snapshot_path.name,
            "sha256": copied_sha256,
            "size_bytes": destination.stat().st_size,
            "integrity_check": str(integrity[0]) if integrity else "unknown",
            "foreign_key_violations": len(violations),
            "opened_with": "mode=ro, PRAGMA query_only=ON",
        },
    )


def _write_run_directory(
    plan: VerifiedCollectionBatchPlan,
    session_plan: VerifiedCollectionSessionPlan,
    *,
    staging: Path,
    pcap_dir: Path,
    verified_at: datetime,
) -> dict[str, Any]:
    spec = session_plan.spec
    run_dir = staging / _RUNS_DIRNAME / spec.run_id
    (run_dir / _EVIDENCE_DIRNAME).mkdir(parents=True, exist_ok=True)

    evidence_payloads = {
        "session-snapshot.json": _session_snapshot_evidence(plan, session_plan),
        "feature-qc.json": _feature_qc_evidence(plan, session_plan),
        "pcap-inventory.json": _pcap_inventory_evidence(session_plan, pcap_dir),
        "source-evidence.json": _source_evidence(plan, session_plan),
    }
    for filename, payload in evidence_payloads.items():
        _write_json(run_dir / _EVIDENCE_DIRNAME / filename, payload)

    artifacts = tuple(
        VerifiedCollectionArtifact(
            relative_path=f"{_EVIDENCE_DIRNAME}/{filename}",
            artifact_type=artifact_type,
            size_bytes=(run_dir / _EVIDENCE_DIRNAME / filename).stat().st_size,
            sha256=file_sha256(run_dir / _EVIDENCE_DIRNAME / filename),
        )
        for artifact_type, filename in _EVIDENCE_FILES
    )

    collection = VerifiedCollectionManifest(
        run_id=spec.run_id,
        session_id=spec.session_id,
        collection_slot_id=spec.collection_slot_id,
        source_capture_group_id=spec.source_capture_group_id,
        split=spec.split,
        traffic_label=spec.traffic_label,
        scenario=spec.scenario,
        collection_device_id=spec.collection_device_id,
        target_device_id=spec.target_device_id,
        target_source_ip=spec.target_source_ip,
        included_device_ids=session_plan.included_device_ids,
        background_traffic_present=session_plan.background_traffic_present,
        firmware_version=spec.firmware_version,
        payload_schema_version=spec.payload_schema_version,
        payload_schema_provenance=spec.payload_schema_provenance,
        firmware_reported_payload_schema_version=(
            spec.firmware_reported_payload_schema_version
        ),
        normal_policy_version=plan.spec.normal_policy_version,
        capture_source_commit_sha=spec.capture_source_commit_sha,
        verification_commit_sha=plan.verification_commit_sha,
        capture_interface=session_plan.capture_interface,
        capture_filter=plan.spec.capture_filter,
        started_at=session_plan.started_at,
        first_window_start=session_plan.first_window_start,
        ended_at=session_plan.ended_at,
        verified_at=verified_at,
        segment_count=session_plan.segment_count,
        processed_segment_count=session_plan.processed_segment_count,
        empty_segment_count=session_plan.empty_segment_count,
        eligible_feature_row_count=session_plan.eligible_row_count,
        db_snapshot_sha256=plan.db_snapshot_sha256,
        observation=_build_observation(session_plan),
        artifacts=artifacts,
    )
    collection_path = run_dir / VERIFIED_COLLECTION_MANIFEST_FILENAME
    collection_path.write_text(collection.to_json(), encoding="utf-8")
    collection_sha256 = verified_collection_sha256(collection)
    _write_sidecar(
        Path(f"{collection_path}{VERIFIED_COLLECTION_SHA256_SIDECAR_SUFFIX}"),
        collection_sha256,
    )

    run_manifest = _build_run_manifest(
        plan,
        session_plan,
        collection_sha256=collection_sha256,
        collection_artifacts=artifacts,
        collection_path=collection_path,
    )
    run_path = run_dir / _RUN_MANIFEST_FILENAME
    run_path.write_text(run_manifest.to_json(), encoding="utf-8")
    run_sha256 = run_manifest_sha256(run_manifest)
    _write_sidecar(
        Path(f"{run_path}{RUN_MANIFEST_SHA256_SIDECAR_SUFFIX}"),
        run_sha256,
    )

    run_relative_path = f"{_RUNS_DIRNAME}/{spec.run_id}/{_RUN_MANIFEST_FILENAME}"
    return {
        "session_id": spec.session_id,
        "split": spec.split,
        "traffic_label": spec.traffic_label,
        "scenario": spec.scenario,
        "target_device_id": spec.target_device_id,
        "target_source_ip": spec.target_source_ip,
        "collection_slot_id": spec.collection_slot_id,
        "source_capture_group_id": spec.source_capture_group_id,
        "run_manifest_path": run_relative_path,
        "run_manifest_ref": {
            "run_id": spec.run_id,
            "relative_path": run_relative_path,
            "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
            "sha256": run_sha256,
        },
        "normal_policy_version": plan.spec.normal_policy_version,
        "firmware_version": spec.firmware_version,
        "payload_schema_version": spec.payload_schema_version,
        "included_device_ids": list(session_plan.included_device_ids),
        "background_traffic_present": session_plan.background_traffic_present,
        "source_commit_sha": spec.capture_source_commit_sha,
        "device_ips": dict(session_plan.device_ips),
    }


def _build_observation(
    session_plan: VerifiedCollectionSessionPlan,
) -> VerifiedCollectionObservation:
    spec = session_plan.spec
    sender = spec.sender_reported_packets
    gateway = session_plan.gateway_observed_packets
    gap = None if sender is None else sender - gateway
    cause = spec.observation_gap_cause
    if gap:
        # 원인을 단정하지 않는다. ESP32의 endPacket()==1은 수신 ACK가 아니므로
        # Wi-Fi 손실·ESP32 실패·Pi Drop 중 무엇인지 확정할 수 없다.
        cause = cause or DEFAULT_OBSERVATION_GAP_CAUSE

    if spec.is_attack:
        _require_session_53_observation(
            session_id=spec.session_id,
            sender=sender,
            gateway=gateway,
            feature=session_plan.feature_packet_count,
            gap=gap,
            cause=cause,
        )

    return VerifiedCollectionObservation(
        feature_packet_count=session_plan.feature_packet_count,
        gateway_observed_packets=gateway,
        sender_reported_packets=sender,
        observation_gap_packets=gap,
        observation_gap_cause=cause if gap else None,
        gateway_first_attack_packet_at=spec.gateway_first_attack_packet_at,
    )


def _require_session_53_observation(
    *,
    session_id: str,
    sender: int | None,
    gateway: int,
    feature: int,
    gap: int | None,
    cause: str | None,
) -> None:
    """Pin Session 53 to the counts recorded in the design.

    These are the only verified attack numbers we have. If the snapshot yields
    anything else, the input is not the Session the design describes and the
    whole batch must stop rather than publish a differently-shaped attack set.
    """
    expected = {
        "sender_reported_packets": (sender, SESSION_53_SENDER_REPORTED_PACKETS),
        "gateway_observed_packets": (gateway, SESSION_53_GATEWAY_OBSERVED_PACKETS),
        "feature_packet_count": (feature, SESSION_53_GATEWAY_OBSERVED_PACKETS),
        "observation_gap_packets": (gap, SESSION_53_OBSERVATION_GAP_PACKETS),
        "observation_gap_cause": (cause, SESSION_53_OBSERVATION_GAP_CAUSE),
    }
    mismatched = {
        field_name: (actual, wanted)
        for field_name, (actual, wanted) in expected.items()
        if actual != wanted
    }
    if mismatched:
        details = ", ".join(
            f"{field_name}: expected={wanted!r}, actual={actual!r}"
            for field_name, (actual, wanted) in sorted(mismatched.items())
        )
        raise VerifiedCollectionImportError(
            f"attack Session observation does not match the verified Session 53 "
            f"evidence: {session_id} ({details})"
        )


def _build_run_manifest(
    plan: VerifiedCollectionBatchPlan,
    session_plan: VerifiedCollectionSessionPlan,
    *,
    collection_sha256: str,
    collection_artifacts: Sequence[VerifiedCollectionArtifact],
    collection_path: Path,
) -> RunManifest:
    """Build the DATA_ONLY Run Manifest for one retrospective Session.

    The Run describes the original Capture, not this import: `started_at` and
    `ended_at` come from `packet_capture_sessions`. Detection, Trust, Firewall,
    and Block are NOT_APPLICABLE because no such evaluation ever ran.
    """
    spec = session_plan.spec
    # Dataset v2는 정상 Run도 실제 Export된 등록 Device를 식별하도록 요구한다.
    run_device_id = spec.target_device_id or spec.collection_device_id
    run_source_ip = spec.target_source_ip or session_plan.device_ips[run_device_id]

    external_observations: dict[str, datetime] = {}
    if spec.gateway_first_attack_packet_at is not None:
        external_observations["gateway_first_attack_packet_at"] = (
            spec.gateway_first_attack_packet_at
        )

    artifacts = [
        RunArtifact(
            artifact_type="verified_collection_manifest",
            relative_path=collection_path.name,
            size_bytes=collection_path.stat().st_size,
            sha256=file_sha256(collection_path),
        )
    ]
    artifacts.extend(
        RunArtifact(
            artifact_type=artifact.artifact_type,
            relative_path=artifact.relative_path,
            size_bytes=artifact.size_bytes,
            sha256=artifact.sha256,
        )
        for artifact in collection_artifacts
    )

    return RunManifest(
        run_id=spec.run_id,
        session_id=spec.session_id,
        scenario=ScenarioReference(scenario_id=spec.scenario),
        target_device_id=run_device_id,
        source_ip=run_source_ip,
        execution_node=ExecutionNode(node_id=spec.collection_device_id, registered=True),
        evaluation_scope=EvaluationScope.DATA_ONLY,
        is_active=False,
        started_at=session_plan.started_at,
        # 절대 UTC 공격 시작 증거가 확정되지 않았으므로 null로 둔다. ESP32의
        # started_at_ms는 부팅 후 경과시간이라 UTC로 변환하지 않는다.
        attack_started_at=None,
        observation_deadline_at=session_plan.ended_at,
        ended_at=session_plan.ended_at,
        expected_outcome=ExpectedOutcome(
            expected_event_types=(),
            detection_expected=False,
            trust_score_change_expected=False,
            firewall_expected=False,
            block_expected=False,
            evaluation_scope=EvaluationScope.DATA_ONLY,
        ),
        statuses=RunStageStatuses(
            scenario_status=ManifestStatus.SUCCESS,
            detection_status=ManifestStatus.NOT_APPLICABLE,
            trust_status=ManifestStatus.NOT_APPLICABLE,
            firewall_status=ManifestStatus.NOT_APPLICABLE,
            block_status=ManifestStatus.NOT_APPLICABLE,
            data_status=ManifestStatus.SUCCESS,
            final_status=ManifestStatus.SUCCESS,
        ),
        external_observations=external_observations,
        artifacts=tuple(artifacts),
        session_manifest_ref=ManifestReference(
            relative_path=VERIFIED_COLLECTION_MANIFEST_FILENAME,
            schema_version=VERIFIED_COLLECTION_SCHEMA_VERSION,
            sha256=collection_sha256,
        ),
    )


def _session_snapshot_evidence(
    plan: VerifiedCollectionBatchPlan,
    session_plan: VerifiedCollectionSessionPlan,
) -> dict[str, Any]:
    return {
        "session_id": session_plan.session_id,
        "capture_interface": session_plan.capture_interface,
        "status": "COMPLETED",
        "started_at": format_utc(session_plan.started_at),
        "first_window_start": format_utc(session_plan.first_window_start),
        "ended_at": format_utc(session_plan.ended_at),
        "feature_ready_through": format_utc(session_plan.feature_ready_through),
        "db_snapshot_sha256": plan.db_snapshot_sha256,
        "segments": [
            {
                "segment_id": segment.segment_id,
                "status": segment.status,
                "window_start": format_utc(segment.window_start),
                "window_end": format_utc(segment.window_end),
                "packet_count": segment.packet_count,
                "start_delay_seconds": segment.start_delay_seconds,
                "captured_duration_seconds": segment.captured_duration_seconds,
            }
            for segment in session_plan.segments
        ],
    }


def _feature_qc_evidence(
    plan: VerifiedCollectionBatchPlan,
    session_plan: VerifiedCollectionSessionPlan,
) -> dict[str, Any]:
    return {
        "session_id": session_plan.session_id,
        "segment_count": session_plan.segment_count,
        "processed_segment_count": session_plan.processed_segment_count,
        "empty_segment_count": session_plan.empty_segment_count,
        "eligible_feature_row_count": session_plan.eligible_row_count,
        "feature_packet_count": session_plan.feature_packet_count,
        "included_device_ids": list(session_plan.included_device_ids),
        "device_ips": dict(session_plan.device_ips),
        "background_traffic_present": session_plan.background_traffic_present,
        "capture_policy_version": plan.capture_policy.version,
        "feature_ready_through": format_utc(session_plan.feature_ready_through),
    }


def _pcap_inventory_evidence(
    session_plan: VerifiedCollectionSessionPlan,
    pcap_dir: Path,
) -> dict[str, Any]:
    return {
        "session_id": session_plan.session_id,
        "processed_pcap_dir_name": pcap_dir.name,
        "file_count": len(session_plan.pcap_files),
        "total_size_bytes": sum(item.size_bytes for item in session_plan.pcap_files),
        "note": (
            "PCAP originals are verified in place and never copied, moved, or "
            "deleted by this importer."
        ),
        "files": [
            {
                "file_name": item.file_name,
                "segment_id": item.segment_id,
                "window_start": format_utc(item.window_start),
                "window_end": format_utc(item.window_end),
                "size_bytes": item.size_bytes,
                "sha256": item.sha256,
            }
            for item in session_plan.pcap_files
        ],
    }


def _source_evidence(
    plan: VerifiedCollectionBatchPlan,
    session_plan: VerifiedCollectionSessionPlan,
) -> dict[str, Any]:
    spec = session_plan.spec
    return {
        "session_id": spec.session_id,
        "provenance_mode": "VERIFIED_RETROSPECTIVE_IMPORT",
        "collection_method": "MANUAL_HARDWARE",
        "collection_device_id": spec.collection_device_id,
        "firmware_version": spec.firmware_version,
        "payload_schema_version": spec.payload_schema_version,
        "payload_schema_provenance": spec.payload_schema_provenance.value,
        "firmware_reported_payload_schema_version": (
            spec.firmware_reported_payload_schema_version
        ),
        "capture_source_commit_sha": spec.capture_source_commit_sha,
        "verification_commit_sha": plan.verification_commit_sha,
        "normal_policy_version": plan.spec.normal_policy_version,
        "capture_policy": {
            "version": plan.capture_policy.version,
            "max_start_delay_seconds": plan.capture_policy.max_start_delay_seconds,
            "minimum_duration_seconds": plan.capture_policy.minimum_duration_seconds,
            "epsilon_seconds": plan.capture_policy.epsilon_seconds,
        },
        "scenario_runner_executed": False,
        "pcap_payload_bytes_parsed": False,
        "note": (
            "This Session was collected manually with ESP32 hardware before the "
            "Dataset v2 Run Manifest contract existed. No Scenario Runner ran and "
            "no Run Manifest was generated at capture time; the preserved DB "
            "snapshot, Packet Features, and PCAP file inventory were verified "
            "afterwards."
        ),
        "payload_schema_note": (
            "The importer does not parse PCAP payload bytes and does not check "
            "that any packet matches the declared payload schema. PCAP files are "
            "verified only for existence, size, SHA256, and filename metadata. A "
            "RETROSPECTIVE_OPERATOR_ATTESTED_WITH_PCAP_INVENTORY payload schema "
            "version is an operator attestation backed by that inventory, not an "
            "automated verification of payload content."
        ),
    }


def _write_export_spec(
    plan: VerifiedCollectionBatchPlan,
    staging: Path,
    export_sessions: Sequence[Mapping[str, Any]],
) -> None:
    """Emit the Dataset v2 Export Spec so nobody retypes verified values."""
    _write_json(
        staging / _EXPORT_SPEC_FILENAME,
        {
            "capture_filter": plan.spec.capture_filter,
            # 최상위 값은 기존 호출자 호환용 fallback이다. 공식 Session은 모두
            # 자기 Capture Commit을 갖는다.
            "source_commit_sha": plan.verification_commit_sha,
            # Export가 반드시 이 Package의 Snapshot을 읽었음을 코드로 강제한다.
            "db_snapshot_sha256": plan.db_snapshot_sha256,
            "sessions": [dict(entry) for entry in export_sessions],
        },
    )


def _write_import_summary(
    plan: VerifiedCollectionBatchPlan,
    staging: Path,
    verified_at: datetime,
    export_sessions: Sequence[Mapping[str, Any]],
) -> None:
    summary_path = staging / _IMPORT_SUMMARY_FILENAME
    _write_json(
        summary_path,
        {
            "dataset_package_id": plan.spec.dataset_package_id,
            "import_spec_schema_version": plan.spec.schema_version,
            "collection_manifest_schema_version": VERIFIED_COLLECTION_SCHEMA_VERSION,
            "run_manifest_schema_version": RUN_MANIFEST_SCHEMA_VERSION,
            "verified_at": format_utc(verified_at),
            "verification_commit_sha": plan.verification_commit_sha,
            "normal_policy_version": plan.spec.normal_policy_version,
            "db_snapshot_sha256": plan.db_snapshot_sha256,
            "capture_policy_version": plan.capture_policy.version,
            "session_count": len(plan.sessions),
            "split_counts": _split_counts(plan),
            "sessions": [
                {
                    "session_id": session.session_id,
                    "run_id": session.spec.run_id,
                    "split": session.spec.split,
                    "traffic_label": session.spec.traffic_label,
                    "scenario": session.spec.scenario,
                    "eligible_feature_row_count": session.eligible_row_count,
                    "segment_count": session.segment_count,
                    "pcap_file_count": len(session.pcap_files),
                    "capture_source_commit_sha": (
                        session.spec.capture_source_commit_sha
                    ),
                }
                for session in plan.sessions
            ],
            "export_spec_session_count": len(export_sessions),
        },
    )
    _write_sidecar(
        Path(f"{summary_path}.sha256"),
        file_sha256(summary_path),
    )


def _split_counts(plan: VerifiedCollectionBatchPlan) -> dict[str, int]:
    counts: dict[str, int] = {}
    for session in plan.sessions:
        counts[session.spec.split] = counts.get(session.spec.split, 0) + 1
    return dict(sorted(counts.items()))


def _reverify_package(
    staging: Path,
    export_sessions: Sequence[Mapping[str, Any]],
) -> None:
    """Reload every manifest from disk before the batch is published."""
    for entry in export_sessions:
        run_path = staging / entry["run_manifest_path"]
        raw_run = run_path.read_text(encoding="utf-8")
        run_manifest = RunManifest.from_json(raw_run)
        actual_run_sha256 = run_manifest_sha256(run_manifest)
        if actual_run_sha256 != entry["run_manifest_ref"]["sha256"]:
            raise VerifiedCollectionImportError(
                "Run Manifest SHA256 changed during packaging: "
                f"{entry['run_manifest_path']}"
            )
        reference = run_manifest.session_manifest_ref
        if reference is None:
            raise VerifiedCollectionImportError(
                "Verified Collection Run Manifest lost its session_manifest_ref: "
                f"{entry['run_manifest_path']}"
            )
        load_verified_collection_manifest(
            run_path.parent / reference.relative_path,
            expected_sha256=reference.sha256,
        )


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_sidecar(path: Path, digest: str) -> None:
    path.write_text(f"{digest}\n", encoding="ascii")


def _fsync_tree(root: Path) -> None:
    if os.name != "posix":  # pragma: no cover - platform dependent
        return
    for path in sorted(root.rglob("*")):
        if path.is_file():
            with path.open("rb") as handle:
                os.fsync(handle.fileno())
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            _fsync_directory(path)
    _fsync_directory(root)


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":  # pragma: no cover - platform dependent
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


# --- CLI ---------------------------------------------------------------------


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "이미 수집·QC가 끝난 Phase 5 Capture Session을 읽기 전용으로 검증해 "
            "Dataset v2 입력 Package로 이관합니다."
        )
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--db-snapshot", type=Path, required=True)
    parser.add_argument("--processed-pcap-dir", type=Path, required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--verification-commit-sha", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-only", action="store_true")
    mode.add_argument("--write", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        spec = VerifiedCollectionImportSpec.from_json(
            args.spec.read_text(encoding="utf-8")
        )
        plan = preflight_verified_collection(
            db_snapshot=args.db_snapshot,
            processed_pcap_dir=args.processed_pcap_dir,
            spec=spec,
            verification_commit_sha=args.verification_commit_sha,
        )
        summary: dict[str, Any] = {
            "status": "PASS",
            "mode": "check-only" if args.check_only else "write",
            "dataset_package_id": spec.dataset_package_id,
            "session_count": len(plan.sessions),
            "split_counts": _split_counts(plan),
            "db_snapshot_sha256": plan.db_snapshot_sha256,
            "capture_policy_version": plan.capture_policy.version,
            "sessions": [
                {
                    "session_id": session.session_id,
                    "run_id": session.spec.run_id,
                    "split": session.spec.split,
                    "traffic_label": session.spec.traffic_label,
                    "scenario": session.spec.scenario,
                    "eligible_feature_row_count": session.eligible_row_count,
                    "segment_count": session.segment_count,
                    "pcap_file_count": len(session.pcap_files),
                    "included_device_ids": list(session.included_device_ids),
                    "background_traffic_present": session.background_traffic_present,
                    "capture_source_commit_sha": (
                        session.spec.capture_source_commit_sha
                    ),
                }
                for session in plan.sessions
            ],
        }
        if args.write:
            package_path = write_verified_collection_package(
                plan,
                db_snapshot=args.db_snapshot,
                processed_pcap_dir=args.processed_pcap_dir,
                output_root=args.output_root,
                verified_at=datetime.now(timezone.utc).replace(microsecond=0),
            )
            summary["package_path_name"] = package_path.name
        print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (
        VerifiedCollectionImportError,
        FileExistsError,
        FileNotFoundError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {"status": "FAIL", "error": str(exc)},
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
