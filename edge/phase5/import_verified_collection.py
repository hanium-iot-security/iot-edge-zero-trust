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

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any

from edge.packet.capture_policy import (
    CaptureEligibilitySegment,
    CapturePolicy,
    is_capture_eligible,
)
from edge.packet.pcap_naming import parse_pcap_filename
from edge.phase5.verified_collection_contract import (
    ALLOWED_COLLECTION_SCENARIOS,
    ATTACK_COLLECTION_SCENARIOS,
    ATTACK_LABEL,
    NORMAL_COLLECTION_SCENARIOS,
    NORMAL_LABEL,
    VALID_SPLITS,
    VALID_TRAFFIC_LABELS,
    PayloadSchemaProvenance,
    file_sha256,
    normalize_optional_ipv4,
    normalize_sha1,
    require_canonical_uuid4,
    require_identifier,
    require_non_empty_string,
)


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
            is not PayloadSchemaProvenance.RETROSPECTIVE_SOURCE_AND_PCAP_VERIFICATION
        ):
            # 수집 당시 Firmware는 Payload Schema Version을 출력하지 않았다.
            raise ValueError(
                "attack Session payload_schema_provenance must be "
                "RETROSPECTIVE_SOURCE_AND_PCAP_VERIFICATION"
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

        spec = cls(
            schema_version=schema_version,
            dataset_package_id=require_identifier(
                payload["dataset_package_id"],
                "dataset_package_id",
            ),
            normal_policy_version=require_identifier(
                payload["normal_policy_version"],
                "normal_policy_version",
            ),
            capture_filter=require_non_empty_string(
                payload["capture_filter"],
                "capture_filter",
            ),
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


def connect_snapshot_read_only(path: Path) -> sqlite3.Connection:
    """Open an absolute SQLite Snapshot in a mode that cannot write."""
    if not path.is_absolute():
        raise ValueError(f"DB snapshot path must be absolute: {path}")
    if not path.is_file():
        raise ValueError(f"DB snapshot is not a file: {path}")
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

    segments = _load_segments(connection, int(session_row["id"]))
    if not segments:
        raise VerifiedCollectionImportError(
            f"Capture Session has no Segments: {session_spec.session_id}"
        )
    _validate_segment_statuses(session_spec.session_id, segments)
    _validate_contiguous_windows(session_spec.session_id, segments)

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

    # background_traffic_present는 Target 필터 적용 전 적격 Row 기준으로 계산한다.
    all_eligible_devices = {str(row["device_id"]) for row in eligible_rows}
    if session_spec.is_attack:
        exported_rows = [
            row
            for row in eligible_rows
            if str(row["device_id"]) == session_spec.target_device_id
        ]
        if not exported_rows:
            raise VerifiedCollectionImportError(
                "attack Session has no eligible rows for target_device_id: "
                f"{session_spec.session_id}"
            )
    else:
        exported_rows = list(eligible_rows)

    exported_devices = {str(row["device_id"]) for row in exported_rows}
    if session_spec.collection_device_id not in exported_devices:
        raise VerifiedCollectionImportError(
            "collection_device_id has no eligible rows in this Session: "
            f"{session_spec.session_id} "
            f"(collection_device_id={session_spec.collection_device_id!r}, "
            f"observed={sorted(exported_devices)})"
        )
    if not session_spec.is_attack and exported_devices != {
        session_spec.collection_device_id
    }:
        raise VerifiedCollectionImportError(
            "normal Session must export exactly its collection_device_id rows: "
            f"{session_spec.session_id} (observed={sorted(exported_devices)})"
        )

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
        started_at=_parse_utc(session_row["started_at"], "started_at"),
        first_window_start=_parse_utc(
            session_row["first_window_start"],
            "first_window_start",
        ),
        ended_at=_parse_utc(session_row["ended_at"], "ended_at"),
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
        device_ips={
            device_id: device_ips[device_id] for device_id in sorted(exported_devices)
        },
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
