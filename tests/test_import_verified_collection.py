"""Read-only Verified Collection preflight tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from ai import export_packet_if_dataset as exporter
from ai.export_packet_if_dataset import (
    PacketIFSessionAnnotation,
    export_packet_if_dataset,
)
from ai.packet_if_dataset import load_packet_if_dataset, load_packet_if_manifest
from ai.packet_if_phase5_manifest import (
    PacketIFRunManifestReference,
    load_verified_run_manifest,
    load_verified_session_manifest,
)
from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.packet.capture_policy import CapturePolicy
from edge.packet.pcap_naming import build_pcap_filename
from edge.phase5 import import_verified_collection as importer
from edge.phase5.contracts import (
    EvaluationScope,
    ManifestStatus,
    RunManifest,
)
from edge.phase5.import_verified_collection import (
    VerifiedCollectionImportError,
    VerifiedCollectionImportSpec,
    connect_snapshot_read_only,
    main,
    preflight_verified_collection,
    write_verified_collection_package,
)
from edge.phase5.verified_collection_contract import (
    VerifiedCollectionManifest,
    file_sha256,
)


ATTACK_TEST_SESSION = "23d5dc5b-1e73-44e4-80ed-1d0c12bda7f9"
HOLDOUT_SESSION = "44444444-4444-4444-8444-444444444444"

NORMAL_PROFILES = (
    "normal_stable",
    "normal_interval_jitter",
    "normal_payload_variation",
    "normal_combined_variation",
)
# 공식 구성: Profile 4종 × (Train 2 / Validation 1 / Test 1) + 공격 Test 1 = 17
PROFILE_SPLIT_LAYOUT = (("train", 2), ("validation", 1), ("test", 1))


def _normal_session_id(index: int) -> str:
    """Build a canonical UUID4 that is stable and readable in failures."""
    return f"{index:08x}-1111-4111-8111-111111111111"


def _official_normal_sessions() -> tuple[dict, ...]:
    """Enumerate the 16 normal Sessions of the official composition."""
    sessions: list[dict] = []
    index = 0x11111111
    for profile in NORMAL_PROFILES:
        for split, count in PROFILE_SPLIT_LAYOUT:
            for ordinal in range(1, count + 1):
                sessions.append(
                    {
                        "session_id": _normal_session_id(index),
                        "scenario": profile,
                        "split": split,
                        "slot": f"{profile.replace('_', '-')}-{split}-{ordinal:02d}",
                    }
                )
                index += 1
    return tuple(sessions)


OFFICIAL_NORMAL_SESSIONS = _official_normal_sessions()

# 대표 Session 3개. 기존 테스트가 이 이름으로 특정 Session을 가리킨다.
NORMAL_TRAIN_SESSION = OFFICIAL_NORMAL_SESSIONS[0]["session_id"]
NORMAL_VALIDATION_SESSION = next(
    item["session_id"]
    for item in OFFICIAL_NORMAL_SESSIONS
    if item["scenario"] == "normal_stable" and item["split"] == "validation"
)
NORMAL_TEST_SESSION = next(
    item["session_id"]
    for item in OFFICIAL_NORMAL_SESSIONS
    if item["scenario"] == "normal_stable" and item["split"] == "test"
)

CAPTURE_COMMIT = "a" * 40
ATTACK_COMMIT = "a4b0be29a8353f3b516808e2ed945b6cb251ac61"
VERIFICATION_COMMIT = "b" * 40
INTERFACE = "eth0"
BASE_TIME = datetime(2026, 8, 3, 10, 0, 0, tzinfo=timezone.utc)

PHASE6B_PACKAGE_ID = "packet-if-v2-calib-002"
PHASE6B_CAPTURE_COMMIT = "5c0de2d6f19332d07ab5d966d247e7735689eebc"
PHASE6B_NORMAL_SESSIONS = (
    {
        "session_id": "7134d811-df72-4b63-8cd6-b88ca769173f",
        "source_capture_group_id": "60e14996-6ecb-46ab-85a8-12cb74ffbb92",
        "slot": "phase6b-normal-stable-train-01",
        "split": "train",
        "scenario": "normal_stable",
    },
    {
        "session_id": "e95d0562-05b9-4e95-87d3-a466eac9dfc4",
        "source_capture_group_id": "bcd636dc-8b25-4070-95b6-d3c44c41429d",
        "slot": "phase6b-normal-combined-variation-train-01",
        "split": "train",
        "scenario": "normal_combined_variation",
    },
    {
        "session_id": "c326fdfe-35eb-49f7-bb4b-e6341d9223a4",
        "source_capture_group_id": "590f851d-1af1-4f72-9144-fddd2ee12cb3",
        "slot": "phase6b-normal-stable-validation-01",
        "split": "validation",
        "scenario": "normal_stable",
    },
    {
        "session_id": "078b8a30-f6cb-4835-9798-8ad7ca39326c",
        "source_capture_group_id": "dda7807c-9158-49b1-a18f-c788b2b5b562",
        "slot": "phase6b-normal-combined-variation-validation-01",
        "split": "validation",
        "scenario": "normal_combined_variation",
    },
    {
        "session_id": "2915ca75-c95d-41aa-a560-f3fb11287bd7",
        "source_capture_group_id": "8b884392-60f4-4b43-8029-db0c8be077c3",
        "slot": "phase6b-normal-stable-holdout-01",
        "split": "test",
        "scenario": "normal_stable",
    },
    {
        "session_id": "186b4f63-e62e-4cba-9f32-2d0ccc2cc9af",
        "source_capture_group_id": "0a60c148-1cf2-4fe5-8c78-c77472b5016d",
        "slot": "phase6b-normal-combined-variation-holdout-01",
        "split": "test",
        "scenario": "normal_combined_variation",
    },
)
LEGACY_17_SESSIONS_CANONICAL_SHA256 = (
    "0a64ae5a735a7383e7c0f4d45a1f83299a1a198b8769a3ec80287266d8650b56"
)


def _iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class SnapshotBuilder:
    """Builds a migrated SQLite snapshot plus its processed PCAP directory."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._working_db = (root / "iot_security.db").resolve()
        self._snapshot_db = (root / "iot_security.snapshot.db").resolve()
        self.pcap_dir = root / "pcap" / "processed"
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        apply_migrations(self._working_db, MIGRATIONS_DIR)
        self._engine = create_engine(f"sqlite:///{self._working_db}")
        self._SessionLocal = sessionmaker(bind=self._engine)
        self._segment_id = 0
        self._feature_id = 0
        self._window_cursor = 0
        self._dirty = True
        with self._SessionLocal() as db:
            for device_id, ip in (
                ("esp32_01", "192.168.0.4"),
                ("esp32_02", "192.168.0.5"),
            ):
                db.execute(
                    text(
                        """
                        INSERT INTO devices (device_id, ip_address, status, trust_score)
                        VALUES (:device_id, :ip, 'normal', 100)
                        """
                    ),
                    {"device_id": device_id, "ip": ip},
                )
            db.commit()

    @property
    def db_path(self) -> Path:
        """Return a consistent standalone snapshot of the seeded database.

        The working database runs in WAL mode, so its main file can be nearly
        empty while the data sits in `<db>-wal`. The Runbook requires operators
        to hand the importer a SQLite Backup API snapshot, and this fixture
        performs exactly that step so tests exercise the real input shape.
        """
        if self._dirty:
            self._engine.dispose()
            source = sqlite3.connect(self._working_db)
            try:
                destination = sqlite3.connect(self._snapshot_db)
                try:
                    source.backup(destination)
                finally:
                    destination.close()
            finally:
                source.close()
            self._dirty = False
        return self._snapshot_db

    def dispose(self) -> None:
        self._engine.dispose()

    def set_device_ip(self, device_id: str, ip_address: str) -> None:
        self._dirty = True
        with self._SessionLocal() as db:
            db.execute(
                text(
                    "UPDATE devices SET ip_address = :ip_address "
                    "WHERE device_id = :device_id"
                ),
                {"device_id": device_id, "ip_address": ip_address},
            )
            db.commit()

    def add_session(
        self,
        session_id: str,
        *,
        device_id: str = "esp32_01",
        peer_ip: str = "192.168.0.4",
        segments: int = 2,
        status: str = "COMPLETED",
        segment_statuses: tuple[str, ...] | None = None,
        start_delay: float = 0.2,
        duration: float = 9.8,
        window_gap_after: int | None = None,
        write_pcap: bool = True,
        pcap_filename_override: str | None = None,
        feature_direction: str = "INBOUND",
        feature_peer_ip: str | None = None,
        extra_device: tuple[str, str] | None = None,
        omit_feature_for_processed: bool = False,
        feature_for_empty: bool = False,
        feature_window_shift_seconds: int = 0,
        packet_count: int = 10,
    ) -> None:
        self._dirty = True
        statuses = segment_statuses or tuple("PROCESSED" for _ in range(segments))
        first_start = BASE_TIME + timedelta(seconds=10 * self._window_cursor)
        ended_at = first_start + timedelta(seconds=10 * len(statuses))
        with self._SessionLocal() as db:
            result = db.execute(
                text(
                    """
                    INSERT INTO packet_capture_sessions (
                        session_id, capture_interface, started_at,
                        first_window_start, ended_at, status
                    )
                    VALUES (
                        :session_id, :interface, :started_at,
                        :first_window_start, :ended_at, :status
                    )
                    """
                ),
                {
                    "session_id": session_id,
                    "interface": INTERFACE,
                    "started_at": _iso(first_start),
                    "first_window_start": _iso(first_start),
                    "ended_at": None if status == "RUNNING" else _iso(ended_at),
                    "status": status,
                },
            )
            session_pk = int(result.lastrowid)

            offset = 0
            for index, segment_status in enumerate(statuses):
                if window_gap_after is not None and index == window_gap_after:
                    offset += 1
                window_start = first_start + timedelta(seconds=10 * (index + offset))
                window_end = window_start + timedelta(seconds=10)
                self._segment_id += 1
                segment_id = self._segment_id
                file_name = (
                    None
                    if segment_status == "FAILED"
                    else (
                        pcap_filename_override
                        if pcap_filename_override and index == 0
                        else build_pcap_filename(
                            session_id=session_id,
                            interface=INTERFACE,
                            window_start=window_start,
                            window_end=window_end,
                            tmp=False,
                        )
                    )
                )
                db.execute(
                    text(
                        """
                        INSERT INTO packet_capture_segments (
                            id, capture_session_id, file_name, capture_interface,
                            window_start, window_end, status, packet_count,
                            processed_at, start_delay_seconds,
                            captured_duration_seconds
                        )
                        VALUES (
                            :segment_id, :session_pk, :file_name, :interface,
                            :window_start, :window_end, :status, :packet_count,
                            :processed_at, :start_delay, :duration
                        )
                        """
                    ),
                    {
                        "segment_id": segment_id,
                        "session_pk": session_pk,
                        "file_name": file_name,
                        "interface": INTERFACE,
                        "window_start": _iso(window_start),
                        "window_end": _iso(window_end),
                        "status": segment_status,
                        "packet_count": (
                            0 if segment_status == "EMPTY" else packet_count
                        ),
                        "processed_at": (
                            None
                            if segment_status in {"READY", "FAILED"}
                            else _iso(window_end)
                        ),
                        "start_delay": start_delay,
                        "duration": duration,
                    },
                )
                if file_name and write_pcap:
                    (self.pcap_dir / file_name).write_bytes(
                        f"pcap:{segment_id}".encode("ascii")
                    )

                needs_feature = segment_status == "PROCESSED" and not (
                    omit_feature_for_processed and index == 0
                )
                if segment_status == "EMPTY" and feature_for_empty:
                    needs_feature = True
                if not needs_feature:
                    continue

                feature_start = window_start + timedelta(
                    seconds=feature_window_shift_seconds
                )
                self._feature_id += 1
                self._insert_feature(
                    db,
                    feature_id=self._feature_id,
                    segment_id=segment_id,
                    device_id=device_id,
                    peer_ip=feature_peer_ip or peer_ip,
                    direction=feature_direction,
                    window_start=feature_start,
                    packet_count=packet_count,
                )
                if extra_device is not None:
                    self._feature_id += 1
                    self._insert_feature(
                        db,
                        feature_id=self._feature_id,
                        segment_id=segment_id,
                        device_id=extra_device[0],
                        peer_ip=extra_device[1],
                        direction="INBOUND",
                        window_start=feature_start,
                        packet_count=packet_count,
                    )
            db.commit()
        self._window_cursor += len(statuses) + 2

    def _insert_feature(
        self,
        db,
        *,
        feature_id: int,
        segment_id: int,
        device_id: str | None,
        peer_ip: str,
        direction: str,
        window_start: datetime,
        packet_count: int,
    ) -> None:
        db.execute(
            text(
                """
                INSERT INTO packet_feature_logs (
                    id, capture_segment_id, device_id, peer_ip, direction,
                    window_start, window_end, packet_count, total_bytes,
                    avg_packet_size, max_packet_size, mean_inter_arrival_time,
                    distinct_dest_port_count, tcp_syn_count,
                    mqtt_related_packet_count, non_mqtt_tcp_udp_packet_count,
                    capture_scope
                )
                VALUES (
                    :feature_id, :segment_id, :device_id, :peer_ip, :direction,
                    :window_start, :window_end, :packet_count, 1000,
                    100.0, 120, 0.5, 2, 1, 8, 2, 'gateway'
                )
                """
            ),
            {
                "feature_id": feature_id,
                "segment_id": segment_id,
                "device_id": device_id,
                "peer_ip": peer_ip,
                "direction": direction,
                "window_start": _iso(window_start),
                "window_end": _iso(window_start + timedelta(seconds=10)),
                "packet_count": packet_count,
            },
        )


@pytest.fixture
def snapshot(tmp_path: Path):
    builder = SnapshotBuilder(tmp_path / "snapshot")
    try:
        yield builder
    finally:
        builder.dispose()


def _session_entry(
    session_id: str,
    *,
    slot: str,
    split: str,
    label: str = "normal",
    scenario: str = "normal_stable",
    device: str = "esp32_01",
    firmware: str = "phase5-normal-pilot-v1",
    payload: str = "phase5-normal-payload-v1",
    provenance: str = "FIRMWARE_REPORTED",
    commit: str = CAPTURE_COMMIT,
    **extra,
) -> dict:
    entry = {
        "session_id": session_id,
        "collection_slot_id": slot,
        "split": split,
        "traffic_label": label,
        "scenario": scenario,
        "collection_device_id": device,
        "firmware_version": firmware,
        "payload_schema_version": payload,
        "payload_schema_provenance": provenance,
        "capture_source_commit_sha": commit,
    }
    entry.update(extra)
    return entry


# 설계 12절이 고정한 Session 53 실측 증적.
SESSION_53_SENDER_PACKETS = 960
SESSION_53_GATEWAY_PACKETS = 880
SESSION_53_SEGMENTS = 2
SESSION_53_PACKETS_PER_SEGMENT = SESSION_53_GATEWAY_PACKETS // SESSION_53_SEGMENTS


def _attack_entry(**overrides) -> dict:
    entry = _session_entry(
        ATTACK_TEST_SESSION,
        slot="packet-rate-flood-test-01",
        split="test",
        label="attack",
        scenario="packet_rate_flood",
        device="esp32_02",
        firmware="phase5-packet-rate-sender-v2",
        payload="phase5-packet-rate-udp-payload-v1",
        provenance="RETROSPECTIVE_OPERATOR_ATTESTED_WITH_PCAP_INVENTORY",
        commit=ATTACK_COMMIT,
        target_device_id="esp32_02",
        target_source_ip="192.168.0.5",
        sender_reported_packets=SESSION_53_SENDER_PACKETS,
    )
    entry.update(overrides)
    return entry


def _phase6b_normal_entry(item: dict, **overrides) -> dict:
    entry = _session_entry(
        item["session_id"],
        slot=item["slot"],
        split=item["split"],
        scenario=item["scenario"],
        device="esp32_02",
        commit=PHASE6B_CAPTURE_COMMIT,
        source_capture_group_id=item["source_capture_group_id"],
    )
    entry.update(overrides)
    return entry


def _phase6b_normal_entries() -> list[dict]:
    return [_phase6b_normal_entry(item) for item in PHASE6B_NORMAL_SESSIONS]


def _phase6b_23_session_spec() -> dict:
    return _spec_payload(
        [
            *_official_normal_entries(),
            _attack_entry(),
            *_phase6b_normal_entries(),
        ],
        dataset_package_id=PHASE6B_PACKAGE_ID,
    )


def _add_attack_session(snapshot: SnapshotBuilder, **overrides) -> None:
    """Seed Session 53 with the gateway packet count the design pins."""
    kwargs = {
        "device_id": "esp32_02",
        "peer_ip": "192.168.0.5",
        "segments": SESSION_53_SEGMENTS,
        "packet_count": SESSION_53_PACKETS_PER_SEGMENT,
    }
    kwargs.update(overrides)
    snapshot.add_session(ATTACK_TEST_SESSION, **kwargs)


def _seed_phase6b_23_session_batch(snapshot: SnapshotBuilder) -> None:
    for item in OFFICIAL_NORMAL_SESSIONS:
        snapshot.add_session(item["session_id"])
    _add_attack_session(snapshot)
    for item in PHASE6B_NORMAL_SESSIONS:
        snapshot.add_session(
            item["session_id"],
            device_id="esp32_02",
            peer_ip="192.168.0.5",
        )


def _spec_payload(sessions: list[dict], **overrides) -> dict:
    payload = {
        "schema_version": "phase5-verified-collection-import-spec-v1",
        "dataset_package_id": "packet-if-v2-verified-001",
        "normal_policy_version": "phase5-normal-policy-v1.1",
        "capture_filter": "tcp or udp",
        "sessions": sessions,
    }
    payload.update(overrides)
    return payload


def _official_normal_entries(
    *,
    skip_session_ids: frozenset[str] = frozenset(),
) -> list[dict]:
    return [
        _session_entry(
            item["session_id"],
            slot=item["slot"],
            split=item["split"],
            scenario=item["scenario"],
        )
        for item in OFFICIAL_NORMAL_SESSIONS
        if item["session_id"] not in skip_session_ids
    ]


def _full_spec(**overrides) -> dict:
    """Build the smallest Import Spec that satisfies every safety rule.

    The importer does not require a particular Dataset composition, so the
    default fixture is the minimum valid batch: one normal Session per Split
    plus the attack Test Session. The real 17-Session operating composition is
    exercised separately in the official-composition end-to-end test.
    """
    return _spec_payload(
        [
            _session_entry(
                NORMAL_TRAIN_SESSION,
                slot="normal-stable-train-01",
                split="train",
            ),
            _session_entry(
                NORMAL_VALIDATION_SESSION,
                slot="normal-stable-validation-01",
                split="validation",
            ),
            _session_entry(
                NORMAL_TEST_SESSION,
                slot="normal-stable-test-01",
                split="test",
            ),
            _attack_entry(),
        ],
        **overrides,
    )


def _seed_full_batch(
    snapshot: SnapshotBuilder,
    *,
    skip_session_ids: frozenset[str] = frozenset(),
    attack_overrides: dict | None = None,
    **first_session_overrides,
) -> None:
    """Seed the minimum valid batch that `_full_spec()` declares.

    `first_session_overrides` apply to the first normal Session only, which is
    how the negative tests inject a single malformed Session into an otherwise
    valid batch. `attack_overrides` does the same for Session 53.
    """
    minimal = (
        NORMAL_TRAIN_SESSION,
        NORMAL_VALIDATION_SESSION,
        NORMAL_TEST_SESSION,
    )
    for index, session_id in enumerate(minimal):
        if session_id in skip_session_ids:
            continue
        overrides = first_session_overrides if index == 0 else {}
        snapshot.add_session(session_id, **overrides)
    if ATTACK_TEST_SESSION not in skip_session_ids:
        _add_attack_session(snapshot, **(attack_overrides or {}))


def _preflight(snapshot: SnapshotBuilder, spec_payload: dict):
    return preflight_verified_collection(
        db_snapshot=snapshot.db_path,
        processed_pcap_dir=snapshot.pcap_dir,
        spec=VerifiedCollectionImportSpec.from_json(json.dumps(spec_payload)),
        verification_commit_sha=VERIFICATION_COMMIT,
        capture_policy=CapturePolicy(),
    )


# --- Import Spec parsing -----------------------------------------------------


def test_spec_parses_normal_and_attack_sessions() -> None:
    spec = VerifiedCollectionImportSpec.from_json(json.dumps(_full_spec()))

    assert spec.dataset_package_id == "packet-if-v2-verified-001"
    assert len(spec.sessions) == 4
    attack = spec.sessions[-1]
    assert attack.run_id == "verified-packet-rate-flood-test-01"
    assert attack.source_capture_group_id == ATTACK_TEST_SESSION
    assert attack.target_source_ip == "192.168.0.5"


def test_spec_rejects_unknown_schema_version() -> None:
    payload = _spec_payload([], schema_version="phase5-import-spec-v2")

    with pytest.raises(ValueError, match="schema_version"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_spec_rejects_unknown_scenario() -> None:
    payload = _spec_payload(
        [
            _session_entry(
                NORMAL_TRAIN_SESSION,
                slot="slot-01",
                split="train",
                scenario="mqtt_flood",
            )
        ]
    )

    with pytest.raises(ValueError, match="scenario"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_spec_rejects_normal_session_with_target_fields() -> None:
    payload = _spec_payload(
        [
            _session_entry(
                NORMAL_TRAIN_SESSION,
                slot="slot-01",
                split="train",
                target_device_id="esp32_01",
            )
        ]
    )

    with pytest.raises(ValueError, match="target_device_id"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_spec_rejects_attack_session_outside_test_split() -> None:
    payload = _spec_payload([_attack_entry(split="train")])

    with pytest.raises(ValueError, match="test split"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_spec_rejects_mismatched_normal_firmware_pair() -> None:
    payload = _spec_payload(
        [
            _session_entry(
                NORMAL_TRAIN_SESSION,
                slot="slot-01",
                split="train",
                firmware="phase5-packet-rate-sender-v2",
            )
        ]
    )

    with pytest.raises(ValueError, match="firmware_version"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_spec_rejects_attack_payload_claiming_firmware_reported() -> None:
    payload = _spec_payload(
        [_attack_entry(payload_schema_provenance="FIRMWARE_REPORTED")]
    )

    with pytest.raises(ValueError, match="payload_schema_provenance"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_spec_rejects_invalid_capture_commit() -> None:
    payload = _spec_payload(
        [
            _session_entry(
                NORMAL_TRAIN_SESSION,
                slot="slot-01",
                split="train",
                commit="A" * 40,
            )
        ]
    )

    with pytest.raises(ValueError, match="capture_source_commit_sha"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_spec_rejects_duplicate_collection_slot() -> None:
    payload = _spec_payload(
        [
            _session_entry(NORMAL_TRAIN_SESSION, slot="dup", split="train"),
            _session_entry(NORMAL_VALIDATION_SESSION, slot="dup", split="validation"),
        ]
    )

    with pytest.raises(ValueError, match="collection_slot_id"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_spec_rejects_duplicate_session_id() -> None:
    payload = _spec_payload(
        [
            _session_entry(NORMAL_TRAIN_SESSION, slot="slot-01", split="train"),
            _session_entry(NORMAL_TRAIN_SESSION, slot="slot-02", split="validation"),
        ]
    )

    with pytest.raises(ValueError, match="session_id"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_spec_rejects_missing_test_attack_label() -> None:
    payload = _spec_payload(
        [
            _session_entry(NORMAL_TRAIN_SESSION, slot="slot-01", split="train"),
            _session_entry(
                NORMAL_VALIDATION_SESSION,
                slot="slot-02",
                split="validation",
            ),
            _session_entry(NORMAL_TEST_SESSION, slot="slot-03", split="test"),
        ]
    )

    with pytest.raises(ValueError, match="attack"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_spec_rejects_missing_split() -> None:
    payload = _spec_payload(
        [
            _session_entry(NORMAL_TRAIN_SESSION, slot="slot-01", split="train"),
            _session_entry(NORMAL_TEST_SESSION, slot="slot-03", split="test"),
            _attack_entry(),
        ]
    )

    with pytest.raises(ValueError, match="validation"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_spec_rejects_source_capture_group_crossing_splits() -> None:
    payload = _spec_payload(
        [
            _session_entry(
                NORMAL_TRAIN_SESSION,
                slot="slot-01",
                split="train",
                source_capture_group_id=NORMAL_TRAIN_SESSION,
            ),
            _session_entry(
                NORMAL_VALIDATION_SESSION,
                slot="slot-02",
                split="validation",
                source_capture_group_id=NORMAL_TRAIN_SESSION,
            ),
            _session_entry(NORMAL_TEST_SESSION, slot="slot-03", split="test"),
            _attack_entry(),
        ]
    )

    with pytest.raises(ValueError, match="source_capture_group_id"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


# --- Read-only snapshot access ----------------------------------------------


def test_connect_snapshot_rejects_relative_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="absolute"):
        connect_snapshot_read_only(Path("relative/iot.db"))


def test_connect_snapshot_is_query_only(snapshot: SnapshotBuilder) -> None:
    connection = connect_snapshot_read_only(snapshot.db_path)
    try:
        assert connection.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("UPDATE devices SET trust_score = 1")
    finally:
        connection.close()


def test_preflight_reads_snapshot_without_modifying_it(
    snapshot: SnapshotBuilder,
) -> None:
    _seed_full_batch(snapshot)
    before = file_sha256(snapshot.db_path)

    plan = _preflight(snapshot, _full_spec())

    assert file_sha256(snapshot.db_path) == before
    assert len(plan.sessions) == 4
    train = plan.session_by_id(NORMAL_TRAIN_SESSION)
    assert train.eligible_row_count == 2
    assert train.included_device_ids == ("esp32_01",)
    assert train.background_traffic_present is False
    assert train.processed_segment_count == 2
    assert train.empty_segment_count == 0
    assert train.capture_interface == INTERFACE
    assert train.pcap_files and all(item.sha256 for item in train.pcap_files)


def test_preflight_records_attack_session_target_rows_only(
    snapshot: SnapshotBuilder,
) -> None:
    _seed_full_batch(snapshot)

    plan = _preflight(snapshot, _full_spec())
    attack = plan.session_by_id(ATTACK_TEST_SESSION)

    assert attack.traffic_label == "attack"
    assert attack.included_device_ids == ("esp32_02",)
    assert attack.target_source_ip == "192.168.0.5"
    assert attack.gateway_observed_packets == attack.feature_packet_count


def test_preflight_detects_background_traffic(snapshot: SnapshotBuilder) -> None:
    _seed_full_batch(
        snapshot,
        attack_overrides={"extra_device": ("esp32_01", "192.168.0.4")},
    )

    plan = _preflight(snapshot, _full_spec())
    attack = plan.session_by_id(ATTACK_TEST_SESSION)

    assert attack.background_traffic_present is True
    assert attack.included_device_ids == ("esp32_02",)


# --- Session validation ------------------------------------------------------


def test_preflight_rejects_missing_session(snapshot: SnapshotBuilder) -> None:
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    _add_attack_session(snapshot)

    with pytest.raises(VerifiedCollectionImportError, match="not found"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_non_completed_session(snapshot: SnapshotBuilder) -> None:
    _seed_full_batch(snapshot, status="RUNNING")

    with pytest.raises(VerifiedCollectionImportError, match="COMPLETED"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_ready_segment(snapshot: SnapshotBuilder) -> None:
    _seed_full_batch(
        snapshot,
        segment_statuses=("PROCESSED", "READY"),
    )

    with pytest.raises(VerifiedCollectionImportError, match="READY"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_failed_segment(snapshot: SnapshotBuilder) -> None:
    _seed_full_batch(
        snapshot,
        segment_statuses=("PROCESSED", "FAILED"),
    )

    with pytest.raises(VerifiedCollectionImportError, match="FAILED"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_processed_segment_without_feature(
    snapshot: SnapshotBuilder,
) -> None:
    _seed_full_batch(snapshot, omit_feature_for_processed=True)

    with pytest.raises(VerifiedCollectionImportError, match="PROCESSED"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_empty_segment_with_feature(
    snapshot: SnapshotBuilder,
) -> None:
    _seed_full_batch(
        snapshot,
        segment_statuses=("PROCESSED", "EMPTY"),
        feature_for_empty=True,
    )

    with pytest.raises(VerifiedCollectionImportError, match="EMPTY"):
        _preflight(snapshot, _full_spec())


def test_preflight_accepts_empty_segment_without_feature(
    snapshot: SnapshotBuilder,
) -> None:
    _seed_full_batch(
        snapshot,
        segment_statuses=("PROCESSED", "EMPTY"),
    )

    plan = _preflight(snapshot, _full_spec())
    train = plan.session_by_id(NORMAL_TRAIN_SESSION)

    assert train.processed_segment_count == 1
    assert train.empty_segment_count == 1
    assert train.eligible_row_count == 1


def test_preflight_rejects_window_gap(snapshot: SnapshotBuilder) -> None:
    _seed_full_batch(
        snapshot,
        segments=3,
        segment_statuses=("PROCESSED", "PROCESSED", "PROCESSED"),
        window_gap_after=1,
    )

    with pytest.raises(VerifiedCollectionImportError, match="contiguous"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_feature_segment_window_mismatch(
    snapshot: SnapshotBuilder,
) -> None:
    _seed_full_batch(snapshot, feature_window_shift_seconds=10)

    with pytest.raises(VerifiedCollectionImportError, match="window"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_no_eligible_rows(snapshot: SnapshotBuilder) -> None:
    _seed_full_batch(snapshot, feature_direction="OUTBOUND")

    with pytest.raises(VerifiedCollectionImportError, match="eligible"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_ineligible_capture_timing(
    snapshot: SnapshotBuilder,
) -> None:
    _seed_full_batch(snapshot, duration=7.5)

    with pytest.raises(VerifiedCollectionImportError, match="eligible"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_device_ip_mismatch(snapshot: SnapshotBuilder) -> None:
    _seed_full_batch(snapshot, feature_peer_ip="192.168.0.99")

    with pytest.raises(VerifiedCollectionImportError, match="eligible"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_collection_device_not_matching_rows(
    snapshot: SnapshotBuilder,
) -> None:
    _seed_full_batch(
        snapshot,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

    with pytest.raises(
        VerifiedCollectionImportError,
        match="no eligible rows for the declared export Device",
    ):
        _preflight(snapshot, _full_spec())


# --- PCAP --------------------------------------------------------------------


def test_preflight_rejects_missing_pcap(snapshot: SnapshotBuilder) -> None:
    _seed_full_batch(snapshot, write_pcap=False)

    with pytest.raises(VerifiedCollectionImportError, match="PCAP"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_pcap_filename_metadata_mismatch(
    snapshot: SnapshotBuilder,
) -> None:
    other_window = BASE_TIME + timedelta(days=1)
    bogus = build_pcap_filename(
        session_id=NORMAL_VALIDATION_SESSION,
        interface=INTERFACE,
        window_start=other_window,
        window_end=other_window + timedelta(seconds=10),
        tmp=False,
    )
    _seed_full_batch(snapshot, pcap_filename_override=bogus)

    with pytest.raises(VerifiedCollectionImportError, match="PCAP"):
        _preflight(snapshot, _full_spec())


def test_preflight_does_not_mutate_pcap_files(snapshot: SnapshotBuilder) -> None:
    _seed_full_batch(snapshot)
    before = {
        path.name: file_sha256(path)
        for path in sorted(snapshot.pcap_dir.iterdir())
    }

    _preflight(snapshot, _full_spec())

    after = {
        path.name: file_sha256(path)
        for path in sorted(snapshot.pcap_dir.iterdir())
    }
    assert after == before


# --- Holdout protection ------------------------------------------------------


def test_spec_rejects_normal_session_from_esp32_02() -> None:
    """The esp32_02 normal Holdout must never enter the official Dataset.

    Official normal Sessions were collected from esp32_01 only, so an esp32_02
    normal entry is rejected at spec-parse time rather than relying on the
    operator to remember the exclusion.
    """
    payload = _spec_payload(
        [
            _session_entry(
                HOLDOUT_SESSION,
                slot="normal-holdout-01",
                split="train",
                device="esp32_02",
            )
        ]
    )

    with pytest.raises(ValueError, match="collection_device_id"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_spec_accepts_only_the_complete_phase6b_normal_session_approval_set() -> None:
    spec = VerifiedCollectionImportSpec.from_json(
        json.dumps(_phase6b_23_session_spec())
    )

    phase6b_sessions = [
        session
        for session in spec.sessions
        if session.session_id
        in {item["session_id"] for item in PHASE6B_NORMAL_SESSIONS}
    ]
    assert len(phase6b_sessions) == 6
    assert {session.collection_device_id for session in phase6b_sessions} == {
        "esp32_02"
    }


def test_spec_rejects_partial_phase6b_normal_session_approval_set() -> None:
    payload = _phase6b_23_session_spec()
    payload["sessions"].pop()

    with pytest.raises(ValueError, match="all six approved Sessions"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_spec_rejects_phase6b_normal_sessions_in_another_package() -> None:
    payload = _phase6b_23_session_spec()
    payload["dataset_package_id"] = "packet-if-v2-verified-002"

    with pytest.raises(ValueError, match=PHASE6B_PACKAGE_ID):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("split", "validation"),
        ("scenario", "normal_combined_variation"),
        ("collection_slot_id", "phase6b-normal-stable-train-99"),
        ("source_capture_group_id", "55555555-5555-4555-8555-555555555555"),
        ("capture_source_commit_sha", "f" * 40),
    ],
)
def test_spec_rejects_tampered_phase6b_normal_session_contract(
    field: str,
    value: str,
) -> None:
    payload = _phase6b_23_session_spec()
    phase6b_entry = next(
        session
        for session in payload["sessions"]
        if session["session_id"] == PHASE6B_NORMAL_SESSIONS[0]["session_id"]
    )
    phase6b_entry[field] = value

    with pytest.raises(ValueError, match="approved Phase 6-B normal Session"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_preflight_exports_only_the_approved_phase6b_device_rows(
    snapshot: SnapshotBuilder,
) -> None:
    _seed_phase6b_23_session_batch(snapshot)

    plan = _preflight(snapshot, _phase6b_23_session_spec())

    for item in PHASE6B_NORMAL_SESSIONS:
        session = plan.session_by_id(item["session_id"])
        assert session.included_device_ids == ("esp32_02",)
        assert session.device_ips == {"esp32_02": "192.168.0.5"}
        assert session.eligible_row_count == 2


def test_preflight_rejects_phase6b_device_registration_ip_mismatch(
    snapshot: SnapshotBuilder,
) -> None:
    _seed_phase6b_23_session_batch(snapshot)
    snapshot.set_device_ip("esp32_02", "192.168.0.6")

    with pytest.raises(
        VerifiedCollectionImportError,
        match="Phase 6-B normal collection Device registration mismatch",
    ):
        _preflight(snapshot, _phase6b_23_session_spec())


def test_spec_rejects_attack_session_other_than_the_verified_one() -> None:
    """Only the verified packet_rate_flood attack Session may be imported.

    Session 51 and 52 were collected for Rule/Window analysis, not as Dataset
    attack material, so an unknown attack Session ID is refused.
    """
    payload = _spec_payload(
        [
            _session_entry(NORMAL_TRAIN_SESSION, slot="slot-01", split="train"),
            _session_entry(
                NORMAL_VALIDATION_SESSION,
                slot="slot-02",
                split="validation",
            ),
            _session_entry(NORMAL_TEST_SESSION, slot="slot-03", split="test"),
            _attack_entry(session_id=HOLDOUT_SESSION),
        ]
    )

    with pytest.raises(ValueError, match="attack session"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


# --- Package writing ---------------------------------------------------------


def _write_package(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
    spec_payload: dict | None = None,
    *,
    output_root: Path | None = None,
    verified_at: datetime | None = None,
):
    plan = _preflight(snapshot, spec_payload or _full_spec())
    return write_verified_collection_package(
        plan,
        db_snapshot=snapshot.db_path,
        processed_pcap_dir=snapshot.pcap_dir,
        output_root=output_root or (tmp_path / "exports"),
        verified_at=verified_at or (BASE_TIME + timedelta(days=3)),
    )


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_package_writes_expected_tree(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)

    package = _write_package(snapshot, tmp_path)

    assert package.name == "packet-if-v2-verified-001"
    assert (package / "import-summary.json").is_file()
    assert (package / "import-summary.json.sha256").is_file()
    assert (package / "db-snapshot.db").is_file()
    assert (package / "db-snapshot-metadata.json").is_file()
    assert (package / "packet-if-export-spec-v2.json").is_file()

    run_dir = package / "runs" / "verified-normal-stable-train-01"
    for name in (
        "verified-collection-manifest.json",
        "verified-collection-manifest.json.sha256",
        "run-manifest.json",
        "run-manifest.json.sha256",
    ):
        assert (run_dir / name).is_file(), name
    for name in (
        "session-snapshot.json",
        "feature-qc.json",
        "pcap-inventory.json",
        "source-evidence.json",
    ):
        assert (run_dir / "evidence" / name).is_file(), name


def test_package_copies_snapshot_with_matching_hash(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    source_sha256 = file_sha256(snapshot.db_path)

    package = _write_package(snapshot, tmp_path)

    assert file_sha256(package / "db-snapshot.db") == source_sha256
    metadata = _read_json(package / "db-snapshot-metadata.json")
    assert metadata["sha256"] == source_sha256
    assert metadata["integrity_check"] == "ok"
    assert metadata["foreign_key_violations"] == 0


def test_package_run_manifest_is_data_only(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)

    package = _write_package(snapshot, tmp_path)
    run_path = (
        package / "runs" / "verified-normal-stable-train-01" / "run-manifest.json"
    )
    run_manifest = RunManifest.from_json(run_path.read_text(encoding="utf-8"))

    assert run_manifest.session_manifest_ref.relative_path == (
        "verified-collection-manifest.json"
    )
    assert run_manifest.evaluation_scope is EvaluationScope.DATA_ONLY
    assert run_manifest.is_active is False
    assert run_manifest.statuses.scenario_status is ManifestStatus.SUCCESS
    assert run_manifest.statuses.data_status is ManifestStatus.SUCCESS
    assert run_manifest.statuses.detection_status is ManifestStatus.NOT_APPLICABLE
    assert run_manifest.statuses.trust_status is ManifestStatus.NOT_APPLICABLE
    assert run_manifest.statuses.firewall_status is ManifestStatus.NOT_APPLICABLE
    assert run_manifest.statuses.block_status is ManifestStatus.NOT_APPLICABLE
    assert run_manifest.statuses.final_status is ManifestStatus.SUCCESS
    assert run_manifest.expected_outcome.expected_event_types == ()
    assert run_manifest.expected_outcome.detection_expected is False
    assert run_manifest.expected_outcome.block_expected is False
    # 정상 Session의 Run Manifest는 실제 Export된 등록 Device를 식별한다.
    assert run_manifest.target_device_id == "esp32_01"
    assert run_manifest.source_ip == "192.168.0.4"


def test_package_run_times_describe_original_capture(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)

    package = _write_package(snapshot, tmp_path)
    run_path = (
        package / "runs" / "verified-normal-stable-train-01" / "run-manifest.json"
    )
    run_manifest = RunManifest.from_json(run_path.read_text(encoding="utf-8"))

    assert run_manifest.started_at == BASE_TIME
    assert run_manifest.ended_at == BASE_TIME + timedelta(seconds=20)
    assert run_manifest.observation_deadline_at == run_manifest.ended_at
    # 정상 Session에는 공격 시작 시각이 없다.
    assert run_manifest.attack_started_at is None


def test_attack_run_leaves_attack_started_at_null_without_absolute_evidence(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)

    package = _write_package(snapshot, tmp_path)
    run_path = (
        package / "runs" / "verified-packet-rate-flood-test-01" / "run-manifest.json"
    )
    run_manifest = RunManifest.from_json(run_path.read_text(encoding="utf-8"))

    assert run_manifest.attack_started_at is None
    assert run_manifest.target_device_id == "esp32_02"
    assert run_manifest.source_ip == "192.168.0.5"


def test_attack_gateway_first_packet_goes_to_external_observations(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    observed_at = BASE_TIME + timedelta(seconds=61)
    payload = _full_spec()
    payload["sessions"][-1]["gateway_first_attack_packet_at"] = _iso(observed_at)

    package = _write_package(snapshot, tmp_path, payload)
    run_path = (
        package / "runs" / "verified-packet-rate-flood-test-01" / "run-manifest.json"
    )
    run_manifest = RunManifest.from_json(run_path.read_text(encoding="utf-8"))

    assert run_manifest.attack_started_at is None
    assert (
        run_manifest.external_observations["gateway_first_attack_packet_at"]
        == observed_at
    )


def test_session_53_observation_is_recorded_without_claiming_a_cause(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    payload = _full_spec()
    payload["sessions"][-1]["sender_reported_packets"] = 960

    package = _write_package(snapshot, tmp_path, payload)
    collection_path = (
        package
        / "runs"
        / "verified-packet-rate-flood-test-01"
        / "verified-collection-manifest.json"
    )
    collection = VerifiedCollectionManifest.from_json(
        collection_path.read_text(encoding="utf-8")
    )
    observation = collection.observation

    assert observation.sender_reported_packets == 960
    assert observation.gateway_observed_packets == 880
    assert observation.feature_packet_count == 880
    assert observation.observation_gap_packets == 80
    assert observation.observation_gap_cause == "UNRESOLVED"


def test_collection_manifest_records_retrospective_payload_provenance(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)

    package = _write_package(snapshot, tmp_path)
    collection_path = (
        package
        / "runs"
        / "verified-packet-rate-flood-test-01"
        / "verified-collection-manifest.json"
    )
    collection = VerifiedCollectionManifest.from_json(
        collection_path.read_text(encoding="utf-8")
    )

    assert collection.payload_schema_provenance.value == (
        "RETROSPECTIVE_OPERATOR_ATTESTED_WITH_PCAP_INVENTORY"
    )
    assert collection.firmware_reported_payload_schema_version is None
    assert collection.provenance_mode.value == "VERIFIED_RETROSPECTIVE_IMPORT"
    assert collection.collection_method.value == "MANUAL_HARDWARE"


def test_package_manifests_reload_after_publication(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)

    package = _write_package(snapshot, tmp_path)
    export_spec = _read_json(package / "packet-if-export-spec-v2.json")

    for entry in export_spec["sessions"]:
        run_path = package / entry["run_manifest_path"]
        run_manifest = load_verified_run_manifest(
            run_path,
            expected_sha256=entry["run_manifest_ref"]["sha256"],
        )
        collection = load_verified_session_manifest(
            run_path,
            run_manifest,
            session_id=entry["session_id"],
            scenario=entry["scenario"],
            target_device_id=entry["target_device_id"],
            target_source_ip=entry["target_source_ip"],
            included_device_ips={
                device_id: ip
                for device_id, ip in entry["device_ips"].items()
            },
            required=True,
        )
        assert collection is not None


def test_export_spec_carries_per_session_capture_commits(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)

    package = _write_package(snapshot, tmp_path)
    export_spec = _read_json(package / "packet-if-export-spec-v2.json")
    commits = {
        entry["session_id"]: entry["source_commit_sha"]
        for entry in export_spec["sessions"]
    }

    assert commits[NORMAL_TRAIN_SESSION] == CAPTURE_COMMIT
    assert commits[ATTACK_TEST_SESSION] == ATTACK_COMMIT
    # 최상위 값은 호환용 검증 Commit이며 Session별 값이 우선한다.
    assert export_spec["source_commit_sha"] == VERIFICATION_COMMIT


def test_export_spec_uses_package_relative_run_manifest_paths(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)

    package = _write_package(snapshot, tmp_path)
    export_spec = _read_json(package / "packet-if-export-spec-v2.json")
    entry = next(
        item
        for item in export_spec["sessions"]
        if item["session_id"] == NORMAL_TRAIN_SESSION
    )

    assert entry["run_manifest_path"] == (
        "runs/verified-normal-stable-train-01/run-manifest.json"
    )
    assert entry["run_manifest_ref"]["relative_path"] == entry["run_manifest_path"]
    assert entry["source_capture_group_id"] == NORMAL_TRAIN_SESSION
    assert entry["included_device_ids"] == ["esp32_01"]
    assert entry["background_traffic_present"] is False


def test_pcap_inventory_records_hashes_without_copying_pcap(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)

    package = _write_package(snapshot, tmp_path)
    inventory = _read_json(
        package
        / "runs"
        / "verified-normal-stable-train-01"
        / "evidence"
        / "pcap-inventory.json"
    )

    assert inventory["file_count"] == 2
    for item in inventory["files"]:
        source = snapshot.pcap_dir / item["file_name"]
        assert source.is_file()
        assert item["sha256"] == file_sha256(source)
        assert not (package / item["file_name"]).exists()


def test_check_only_leaves_no_output(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    spec_path = tmp_path / "import-spec.json"
    spec_path.write_text(json.dumps(_full_spec()), encoding="utf-8")
    output_root = tmp_path / "exports"

    exit_code = main(
        [
            "--project-root",
            str(tmp_path),
            "--db-snapshot",
            str(snapshot.db_path),
            "--processed-pcap-dir",
            str(snapshot.pcap_dir),
            "--spec",
            str(spec_path),
            "--output-root",
            str(output_root),
            "--verification-commit-sha",
            VERIFICATION_COMMIT,
            "--check-only",
        ]
    )

    assert exit_code == 0
    assert not (output_root / "packet-if-v2-verified-001").exists()


def test_cli_write_publishes_package(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
    capsys,
) -> None:
    _seed_full_batch(snapshot)
    spec_path = tmp_path / "import-spec.json"
    spec_path.write_text(json.dumps(_full_spec()), encoding="utf-8")
    output_root = tmp_path / "exports"

    exit_code = main(
        [
            "--project-root",
            str(tmp_path),
            "--db-snapshot",
            str(snapshot.db_path),
            "--processed-pcap-dir",
            str(snapshot.pcap_dir),
            "--spec",
            str(spec_path),
            "--output-root",
            str(output_root),
            "--verification-commit-sha",
            VERIFICATION_COMMIT,
            "--write",
        ]
    )

    assert exit_code == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "PASS"
    assert summary["session_count"] == 4
    assert (output_root / "packet-if-v2-verified-001").is_dir()


def test_cli_requires_exactly_one_mode(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    spec_path = tmp_path / "import-spec.json"
    spec_path.write_text(json.dumps(_full_spec()), encoding="utf-8")

    with pytest.raises(SystemExit):
        main(
            [
                "--project-root",
                str(tmp_path),
                "--db-snapshot",
                str(snapshot.db_path),
                "--processed-pcap-dir",
                str(snapshot.pcap_dir),
                "--spec",
                str(spec_path),
                "--output-root",
                str(tmp_path / "exports"),
                "--verification-commit-sha",
                VERIFICATION_COMMIT,
            ]
        )


def test_package_refuses_to_overwrite_existing_directory(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    output_root = tmp_path / "exports"
    _write_package(snapshot, tmp_path, output_root=output_root)

    with pytest.raises(FileExistsError):
        _write_package(snapshot, tmp_path, output_root=output_root)


def test_failed_batch_leaves_no_final_package(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
    monkeypatch,
) -> None:
    _seed_full_batch(snapshot)
    output_root = tmp_path / "exports"
    plan = _preflight(snapshot, _full_spec())

    calls = {"count": 0}
    real_writer = importer._write_run_directory

    def failing_writer(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 3:
            raise RuntimeError("simulated failure on the third Session")
        return real_writer(*args, **kwargs)

    monkeypatch.setattr(importer, "_write_run_directory", failing_writer)

    with pytest.raises(RuntimeError, match="third Session"):
        write_verified_collection_package(
            plan,
            db_snapshot=snapshot.db_path,
            processed_pcap_dir=snapshot.pcap_dir,
            output_root=output_root,
            verified_at=BASE_TIME + timedelta(days=3),
        )

    assert not (output_root / "packet-if-v2-verified-001").exists()
    assert list(output_root.glob("*")) == []


def test_package_does_not_modify_snapshot_or_pcap(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    snapshot_before = file_sha256(snapshot.db_path)
    pcap_before = {
        path.name: file_sha256(path)
        for path in sorted(snapshot.pcap_dir.iterdir())
    }

    _write_package(snapshot, tmp_path)

    assert file_sha256(snapshot.db_path) == snapshot_before
    assert {
        path.name: file_sha256(path)
        for path in sorted(snapshot.pcap_dir.iterdir())
    } == pcap_before


# --- Dataset v2 integration --------------------------------------------------


def _export_from_package(
    package: Path,
    snapshot: SnapshotBuilder,
    tmp_path: Path,
    *,
    bind_snapshot: bool = True,
):
    """Run the real Dataset v2 exporter against the Package snapshot.

    `bind_snapshot=False` omits db_snapshot_sha256 so the resulting Dataset
    exercises the pre-Verified-Collection contract that has no snapshot hash.
    """
    spec_payload = _read_json(package / "packet-if-export-spec-v2.json")
    annotations = []
    for entry in spec_payload["sessions"]:
        annotations.append(
            PacketIFSessionAnnotation(
                session_id=entry["session_id"],
                split=entry["split"],
                traffic_label=entry["traffic_label"],
                scenario=entry["scenario"],
                target_device_id=entry["target_device_id"],
                collection_slot_id=entry["collection_slot_id"],
                source_capture_group_id=entry["source_capture_group_id"],
                run_manifest_ref=PacketIFRunManifestReference.from_dict(
                    entry["run_manifest_ref"]
                ),
                run_manifest_path=(package / entry["run_manifest_path"]).resolve(),
                normal_policy_version=entry["normal_policy_version"],
                firmware_version=entry["firmware_version"],
                payload_schema_version=entry["payload_schema_version"],
                target_source_ip=entry["target_source_ip"],
                included_device_ids=tuple(entry["included_device_ids"]),
                background_traffic_present=entry["background_traffic_present"],
                source_commit_sha=entry["source_commit_sha"],
            )
        )

    snapshot_path = (package / "db-snapshot.db").resolve()
    engine, session_factory = exporter._snapshot_session_factory(snapshot_path)
    try:
        with session_factory() as db:
            return export_packet_if_dataset(
                db,
                output_path=package / "packet-if-dataset-v2.csv",
                manifest_path=package / "packet-if-dataset-v2-manifest.json",
                session_annotations=annotations,
                capture_filter=spec_payload["capture_filter"],
                source_commit_sha=spec_payload["source_commit_sha"],
                capture_policy=CapturePolicy(),
                db_snapshot_sha256=(
                    spec_payload["db_snapshot_sha256"] if bind_snapshot else None
                ),
            )
    finally:
        engine.dispose()


def test_package_export_spec_drives_dataset_v2_end_to_end(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)

    result = _export_from_package(package, snapshot, tmp_path)
    dataset = load_packet_if_dataset(result.output_path, result.manifest_path)

    assert set(dataset.session_ids("train")) == {NORMAL_TRAIN_SESSION}
    assert set(dataset.session_ids("validation")) == {NORMAL_VALIDATION_SESSION}
    assert set(dataset.session_ids("test")) == {
        NORMAL_TEST_SESSION,
        ATTACK_TEST_SESSION,
    }
    commits = {
        session.session_id: session.source_commit_sha
        for session in dataset.manifest.sessions
    }
    assert commits[NORMAL_TRAIN_SESSION] == CAPTURE_COMMIT
    assert commits[ATTACK_TEST_SESSION] == ATTACK_COMMIT
    assert dataset.manifest.normal_policy_version == "phase5-normal-policy-v1.1"


def test_dataset_load_fails_when_collection_evidence_is_tampered(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)
    result = _export_from_package(package, snapshot, tmp_path)

    evidence_path = (
        package
        / "runs"
        / "verified-normal-stable-train-01"
        / "evidence"
        / "session-snapshot.json"
    )
    payload = _read_json(evidence_path)
    payload["capture_interface"] = "eth1"
    evidence_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="artifact"):
        load_packet_if_dataset(result.output_path, result.manifest_path)


def test_dataset_load_fails_when_collection_manifest_is_tampered(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)
    result = _export_from_package(package, snapshot, tmp_path)

    collection_path = (
        package
        / "runs"
        / "verified-normal-stable-train-01"
        / "verified-collection-manifest.json"
    )
    payload = _read_json(collection_path)
    payload["capture_source_commit_sha"] = "f" * 40
    collection_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="SHA256 mismatch"):
        load_packet_if_dataset(result.output_path, result.manifest_path)


def test_dataset_load_fails_when_collection_sidecar_is_tampered(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)
    result = _export_from_package(package, snapshot, tmp_path)

    sidecar = (
        package
        / "runs"
        / "verified-normal-stable-train-01"
        / "verified-collection-manifest.json.sha256"
    )
    sidecar.write_text(f"{'0' * 64}\n", encoding="ascii")

    with pytest.raises(ValueError, match="sidecar SHA256 mismatch"):
        load_packet_if_dataset(result.output_path, result.manifest_path)


def test_connect_snapshot_rejects_live_wal_database(tmp_path: Path) -> None:
    """A WAL-mode database is not a consistent standalone snapshot.

    Its main file can be a few kilobytes while every table lives in `<db>-wal`,
    so copying it alone would silently produce an empty package.
    """
    live_db = (tmp_path / "live.db").resolve()
    connection = sqlite3.connect(live_db)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE devices (device_id TEXT)")
        connection.execute("INSERT INTO devices VALUES ('esp32_01')")
        connection.commit()
        assert Path(f"{live_db}-wal").stat().st_size > 0

        with pytest.raises(VerifiedCollectionImportError, match="WAL"):
            connect_snapshot_read_only(live_db)
    finally:
        connection.close()


def test_backup_api_snapshot_is_accepted(tmp_path: Path) -> None:
    """The Runbook's SQLite Backup API output passes the standalone check."""
    live_db = (tmp_path / "live.db").resolve()
    snapshot_db = (tmp_path / "snapshot.db").resolve()
    source = sqlite3.connect(live_db)
    try:
        source.execute("PRAGMA journal_mode=WAL")
        source.execute("CREATE TABLE devices (device_id TEXT)")
        source.execute("INSERT INTO devices VALUES ('esp32_01')")
        source.commit()
        destination = sqlite3.connect(snapshot_db)
        try:
            source.backup(destination)
        finally:
            destination.close()
    finally:
        source.close()

    connection = connect_snapshot_read_only(snapshot_db)
    try:
        assert connection.execute("SELECT count(*) FROM devices").fetchone()[0] == 1
    finally:
        connection.close()


# --- Fix 5: window bounds, background, and export row filtering ---------------


def test_normal_session_background_traffic_is_detected_and_excluded(
    snapshot: SnapshotBuilder,
) -> None:
    """A normal Session with another registered Device present is not rejected.

    The extra Device's rows must stay out of the export while still marking
    background_traffic_present, exactly like the attack case.
    """
    _seed_full_batch(
        snapshot,
        extra_device=("esp32_02", "192.168.0.5"),
    )

    plan = _preflight(snapshot, _full_spec())
    train = plan.session_by_id(NORMAL_TRAIN_SESSION)

    assert train.background_traffic_present is True
    assert train.included_device_ids == ("esp32_01",)
    assert train.device_ips == {"esp32_01": "192.168.0.4"}
    # 2 Segment × esp32_01 Row 1개. esp32_02 Row는 Export되지 않는다.
    assert train.eligible_row_count == 2


def test_attack_session_without_rows_for_the_declared_target_ip_is_rejected(
    snapshot: SnapshotBuilder,
) -> None:
    """Eligible rows alone are not enough; they must be the declared target's.

    Here the attack Session carries only eligible esp32_01/192.168.0.4 rows, so
    the declared esp32_02/192.168.0.5 target has nothing to export and the
    Session must not be silently published with someone else's traffic.
    """
    _seed_full_batch(
        snapshot,
        attack_overrides={"device_id": "esp32_01", "peer_ip": "192.168.0.4"},
    )

    with pytest.raises(
        VerifiedCollectionImportError,
        match="no eligible rows for the declared export Device",
    ):
        _preflight(snapshot, _full_spec())


def test_attack_export_excludes_background_rows_from_other_devices(
    snapshot: SnapshotBuilder,
) -> None:
    """Background esp32_01 rows are counted for the flag but never exported."""
    _seed_full_batch(
        snapshot,
        attack_overrides={"extra_device": ("esp32_01", "192.168.0.4")},
    )

    plan = _preflight(snapshot, _full_spec())
    attack = plan.session_by_id(ATTACK_TEST_SESSION)

    assert attack.background_traffic_present is True
    assert attack.included_device_ids == ("esp32_02",)
    assert attack.device_ips == {"esp32_02": "192.168.0.5"}
    # Gateway 관측 880개만 집계되고 esp32_01 Background는 제외된다.
    assert attack.feature_packet_count == SESSION_53_GATEWAY_PACKETS


def test_preflight_rejects_first_segment_not_matching_first_window_start(
    snapshot: SnapshotBuilder,
) -> None:
    _seed_full_batch(snapshot)
    engine = create_engine(f"sqlite:///{snapshot._working_db}")
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                UPDATE packet_capture_sessions
                SET first_window_start = :shifted
                WHERE session_id = :session_id
                """
            ),
            {
                "shifted": _iso(BASE_TIME + timedelta(seconds=10)),
                "session_id": NORMAL_TRAIN_SESSION,
            },
        )
    engine.dispose()
    snapshot._dirty = True

    with pytest.raises(
        VerifiedCollectionImportError,
        match="first Segment window_start must equal",
    ):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_last_segment_after_session_ended_at(
    snapshot: SnapshotBuilder,
) -> None:
    _seed_full_batch(snapshot)
    engine = create_engine(f"sqlite:///{snapshot._working_db}")
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                UPDATE packet_capture_sessions
                SET ended_at = :early
                WHERE session_id = :session_id
                """
            ),
            {
                "early": _iso(BASE_TIME + timedelta(seconds=10)),
                "session_id": NORMAL_TRAIN_SESSION,
            },
        )
    engine.dispose()
    snapshot._dirty = True

    with pytest.raises(
        VerifiedCollectionImportError,
        match="last Segment window_end must not be later",
    ):
        _preflight(snapshot, _full_spec())


# --- Fix 4 and 6: pinned Session 53 evidence and batch constants --------------


def test_attack_spec_requires_pinned_sender_reported_packets() -> None:
    payload = _spec_payload(
        [
            _session_entry(NORMAL_TRAIN_SESSION, slot="slot-01", split="train"),
            _session_entry(
                NORMAL_VALIDATION_SESSION,
                slot="slot-02",
                split="validation",
            ),
            _session_entry(NORMAL_TEST_SESSION, slot="slot-03", split="test"),
            _attack_entry(sender_reported_packets=900),
        ]
    )

    with pytest.raises(ValueError, match="sender_reported_packets must be 960"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_attack_spec_requires_unresolved_gap_cause() -> None:
    payload = _spec_payload(
        [
            _session_entry(NORMAL_TRAIN_SESSION, slot="slot-01", split="train"),
            _session_entry(
                NORMAL_VALIDATION_SESSION,
                slot="slot-02",
                split="validation",
            ),
            _session_entry(NORMAL_TEST_SESSION, slot="slot-03", split="test"),
            _attack_entry(observation_gap_cause="WIFI_LOSS"),
        ]
    )

    with pytest.raises(ValueError, match="observation_gap_cause"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_preflight_rejects_attack_gateway_count_other_than_880(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot, attack_overrides={"packet_count": 100})

    plan = _preflight(snapshot, _full_spec())

    with pytest.raises(
        VerifiedCollectionImportError,
        match="verified Session 53 evidence",
    ):
        write_verified_collection_package(
            plan,
            db_snapshot=snapshot.db_path,
            processed_pcap_dir=snapshot.pcap_dir,
            output_root=tmp_path / "exports",
            verified_at=BASE_TIME + timedelta(days=3),
        )


def test_session_53_pinned_counts_are_published(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)

    package = _write_package(snapshot, tmp_path)
    collection = VerifiedCollectionManifest.from_json(
        (
            package
            / "runs"
            / "verified-packet-rate-flood-test-01"
            / "verified-collection-manifest.json"
        ).read_text(encoding="utf-8")
    )

    assert collection.observation.sender_reported_packets == 960
    assert collection.observation.gateway_observed_packets == 880
    assert collection.observation.feature_packet_count == 880
    assert collection.observation.observation_gap_packets == 80
    assert collection.observation.observation_gap_cause == "UNRESOLVED"


def test_spec_rejects_other_normal_policy_version() -> None:
    payload = _spec_payload(
        [_session_entry(NORMAL_TRAIN_SESSION, slot="slot-01", split="train")],
        normal_policy_version="phase5-normal-policy-v1.0",
    )

    with pytest.raises(ValueError, match="normal_policy_version"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_spec_rejects_other_capture_filter() -> None:
    payload = _spec_payload(
        [_session_entry(NORMAL_TRAIN_SESSION, slot="slot-01", split="train")],
        capture_filter="tcp",
    )

    with pytest.raises(ValueError, match="capture_filter"):
        VerifiedCollectionImportSpec.from_json(json.dumps(payload))


def test_preflight_rejects_relative_db_snapshot_before_resolving(
    snapshot: SnapshotBuilder,
) -> None:
    """A relative path must be refused as given, not completed against CWD."""
    with pytest.raises(ValueError, match="absolute"):
        preflight_verified_collection(
            db_snapshot=Path("relative/iot_security.snapshot.db"),
            processed_pcap_dir=snapshot.pcap_dir,
            spec=VerifiedCollectionImportSpec.from_json(json.dumps(_full_spec())),
            verification_commit_sha=VERIFICATION_COMMIT,
            capture_policy=CapturePolicy(),
        )


# --- Fix 1: full Dataset/Collection field comparison -------------------------

# 아래 9개는 Collection Manifest 내부 계약을 깨지 않고 단독으로 바꿀 수 있다.
# traffic_label은 단독 변경이 불가능하다 (attack은 test Split·Target·공격
# Scenario를 함께 요구한다). 그래서 아래에서 결합 변경으로 따로 검증한다.
_TAMPERABLE_COLLECTION_FIELDS = (
    ("split", "validation"),
    ("collection_slot_id", "normal-stable-train-99"),
    ("source_capture_group_id", "55555555-5555-4555-8555-555555555555"),
    ("normal_policy_version", "phase5-normal-policy-v9.9"),
    ("firmware_version", "phase5-normal-pilot-v9"),
    ("payload_schema_version", "phase5-normal-payload-v9"),
    ("background_traffic_present", True),
    ("capture_source_commit_sha", "f" * 40),
    ("capture_filter", "tcp"),
)


def _train_collection_path(package: Path) -> Path:
    return (
        package
        / "runs"
        / "verified-normal-stable-train-01"
        / "verified-collection-manifest.json"
    )


def _retamper_collection(
    package: Path,
    changes: dict,
    *,
    dataset_manifest_path: Path | None = None,
) -> None:
    """Rewrite Collection Manifest fields and refresh the whole hash chain.

    The Manifest, its sidecar, the Run Manifest reference, the Export Spec, and
    optionally the already-written Dataset Manifest are all updated so every
    SHA256 still verifies. That leaves the field-by-field Dataset comparison as
    the only thing that can catch the change, which is the point of these tests.
    """
    collection_path = _train_collection_path(package)
    payload = json.loads(collection_path.read_text(encoding="utf-8"))
    payload.update(changes)
    if "payload_schema_version" in changes:
        # FIRMWARE_REPORTED provenance는 두 값이 같아야 한다.
        payload["firmware_reported_payload_schema_version"] = changes[
            "payload_schema_version"
        ]
    collection = VerifiedCollectionManifest.from_dict(payload)
    collection_path.write_text(collection.to_json(), encoding="utf-8")
    digest = importer.verified_collection_sha256(collection)
    Path(f"{collection_path}.sha256").write_text(f"{digest}\n", encoding="ascii")

    run_path = collection_path.parent / "run-manifest.json"
    run_payload = json.loads(run_path.read_text(encoding="utf-8"))
    run_payload["session_manifest_ref"]["sha256"] = digest
    run_manifest = RunManifest.from_json(json.dumps(run_payload))
    run_path.write_text(run_manifest.to_json(), encoding="utf-8")
    run_digest = importer.run_manifest_sha256(run_manifest)
    Path(f"{run_path}.sha256").write_text(f"{run_digest}\n", encoding="ascii")

    spec_path = package / "packet-if-export-spec-v2.json"
    spec_payload = json.loads(spec_path.read_text(encoding="utf-8"))
    for entry in spec_payload["sessions"]:
        if entry["session_id"] == NORMAL_TRAIN_SESSION:
            entry["run_manifest_ref"]["sha256"] = run_digest
    spec_path.write_text(json.dumps(spec_payload, indent=2), encoding="utf-8")

    if dataset_manifest_path is not None:
        dataset_payload = json.loads(
            dataset_manifest_path.read_text(encoding="utf-8")
        )
        for entry in dataset_payload["sessions"]:
            if entry["session_id"] == NORMAL_TRAIN_SESSION:
                entry["run_manifest_ref"]["sha256"] = run_digest
        dataset_manifest_path.write_text(
            json.dumps(dataset_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        # Dataset Manifest를 고쳤으므로 Dataset CSV Hash는 그대로 두고
        # Manifest 자체만 갱신된다. Loader는 CSV Hash를 Manifest에서 읽는다.


@pytest.mark.parametrize("field_name,value", _TAMPERABLE_COLLECTION_FIELDS)
def test_export_rejects_collection_field_mismatch(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
    field_name: str,
    value,
) -> None:
    """Every compared field must fail the Export path when it disagrees."""
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)
    _retamper_collection(package, {field_name: value})

    with pytest.raises(ValueError, match="does not match the Dataset Session"):
        _export_from_package(package, snapshot, tmp_path)


@pytest.mark.parametrize("field_name,value", _TAMPERABLE_COLLECTION_FIELDS)
def test_dataset_load_rejects_collection_field_mismatch(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
    field_name: str,
    value,
) -> None:
    """The same comparison must also run when the Dataset is loaded."""
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)
    result = _export_from_package(package, snapshot, tmp_path)
    _retamper_collection(
        package,
        {field_name: value},
        dataset_manifest_path=result.manifest_path,
    )

    with pytest.raises(ValueError, match="does not match the Dataset Session"):
        load_packet_if_dataset(result.output_path, result.manifest_path)


def test_export_rejects_collection_traffic_label_mismatch(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    """traffic_label cannot be forged alone, so it is checked as a coupled change.

    Declaring `attack` in the Collection Manifest drags along the test Split,
    the attack Scenario, and the Target fields. The Dataset Session still says
    normal/train, so the comparison must reject it.
    """
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)
    _retamper_collection(
        package,
        {
            "traffic_label": "attack",
            "split": "test",
            "scenario": "packet_rate_flood",
            "collection_device_id": "esp32_02",
            "target_device_id": "esp32_02",
            "target_source_ip": "192.168.0.5",
            "included_device_ids": ["esp32_02"],
        },
    )

    with pytest.raises(ValueError):
        _export_from_package(package, snapshot, tmp_path)


def test_matching_collection_passes_all_compared_fields(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)

    result = _export_from_package(package, snapshot, tmp_path)
    dataset = load_packet_if_dataset(result.output_path, result.manifest_path)

    assert len(dataset.manifest.sessions) == 4


# --- Fix 2: Dataset Export bound to the Package Snapshot ---------------------


def test_export_spec_declares_package_snapshot_sha256(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)

    package = _write_package(snapshot, tmp_path)
    spec_payload = _read_json(package / "packet-if-export-spec-v2.json")

    assert spec_payload["db_snapshot_sha256"] == file_sha256(
        package / "db-snapshot.db"
    )


def test_dataset_manifest_preserves_db_snapshot_sha256(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)

    result = _export_from_package(package, snapshot, tmp_path)
    manifest = _read_json(result.manifest_path)

    assert manifest["db_snapshot_sha256"] == file_sha256(
        package / "db-snapshot.db"
    )


def test_export_rejects_snapshot_that_differs_from_collection_manifest(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    """Exporting from a Snapshot the Collection Manifest never saw is refused."""
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)

    with pytest.raises(
        ValueError,
        match="db_snapshot_sha256 does not match the Snapshot this Export read",
    ):
        _export_from_package_with_snapshot_sha256(package, "f" * 64)


def _export_from_package_with_snapshot_sha256(package: Path, sha256: str):
    spec_payload = _read_json(package / "packet-if-export-spec-v2.json")
    annotations = []
    for entry in spec_payload["sessions"]:
        annotations.append(
            PacketIFSessionAnnotation(
                session_id=entry["session_id"],
                split=entry["split"],
                traffic_label=entry["traffic_label"],
                scenario=entry["scenario"],
                target_device_id=entry["target_device_id"],
                collection_slot_id=entry["collection_slot_id"],
                source_capture_group_id=entry["source_capture_group_id"],
                run_manifest_ref=PacketIFRunManifestReference.from_dict(
                    entry["run_manifest_ref"]
                ),
                run_manifest_path=(package / entry["run_manifest_path"]).resolve(),
                normal_policy_version=entry["normal_policy_version"],
                firmware_version=entry["firmware_version"],
                payload_schema_version=entry["payload_schema_version"],
                target_source_ip=entry["target_source_ip"],
                included_device_ids=tuple(entry["included_device_ids"]),
                background_traffic_present=entry["background_traffic_present"],
                source_commit_sha=entry["source_commit_sha"],
            )
        )
    snapshot_path = (package / "db-snapshot.db").resolve()
    engine, session_factory = exporter._snapshot_session_factory(snapshot_path)
    try:
        with session_factory() as db:
            return export_packet_if_dataset(
                db,
                output_path=package / "mismatch.csv",
                manifest_path=package / "mismatch-manifest.json",
                session_annotations=annotations,
                capture_filter=spec_payload["capture_filter"],
                source_commit_sha=spec_payload["source_commit_sha"],
                capture_policy=CapturePolicy(),
                db_snapshot_sha256=sha256,
            )
    finally:
        engine.dispose()


def test_snapshot_session_factory_rejects_relative_path() -> None:
    with pytest.raises(ValueError, match="absolute"):
        exporter._snapshot_session_factory(Path("relative/db-snapshot.db"))


def test_snapshot_session_factory_is_query_only(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)

    engine, session_factory = exporter._snapshot_session_factory(
        (package / "db-snapshot.db").resolve()
    )
    try:
        with session_factory() as db:
            assert db.execute(text("PRAGMA query_only")).scalar() == 1
            with pytest.raises(Exception):
                db.execute(text("UPDATE devices SET trust_score = 1"))
    finally:
        engine.dispose()


def test_export_cli_requires_db_snapshot_when_spec_declares_one(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)

    with pytest.raises(ValueError, match="--db-snapshot is required"):
        exporter.main(
            [
                "--output",
                str(tmp_path / "out.csv"),
                "--manifest-output",
                str(tmp_path / "out-manifest.json"),
                "--spec",
                str(package / "packet-if-export-spec-v2.json"),
            ]
        )


def test_export_cli_rejects_snapshot_not_matching_spec(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)
    other = tmp_path / "other-snapshot.db"
    other.write_bytes((package / "db-snapshot.db").read_bytes() + b"\x00")

    with pytest.raises(ValueError, match="does not match the Export Spec"):
        exporter.main(
            [
                "--output",
                str(tmp_path / "out.csv"),
                "--manifest-output",
                str(tmp_path / "out-manifest.json"),
                "--spec",
                str(package / "packet-if-export-spec-v2.json"),
                "--db-snapshot",
                str(other.resolve()),
            ]
        )


def test_export_cli_exports_from_package_snapshot(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
    capsys,
) -> None:
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)
    # Dataset Manifest는 Package Root에 둔다. run_manifest_ref.relative_path가
    # Manifest Directory 기준이라 Runbook도 같은 위치를 지정한다.
    output = package / "cli-dataset.csv"
    manifest_output = package / "cli-dataset-manifest.json"

    exit_code = exporter.main(
        [
            "--output",
            str(output),
            "--manifest-output",
            str(manifest_output),
            "--spec",
            str(package / "packet-if-export-spec-v2.json"),
            "--db-snapshot",
            str((package / "db-snapshot.db").resolve()),
        ]
    )

    assert exit_code == 0
    manifest = _read_json(manifest_output)
    assert manifest["db_snapshot_sha256"] == file_sha256(package / "db-snapshot.db")
    dataset = load_packet_if_dataset(output, manifest_output)
    assert len(dataset.manifest.sessions) == 4


# --- Dataset Manifest db_snapshot_sha256 contract ----------------------------


def test_dataset_manifest_without_snapshot_hash_stays_backward_compatible(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    """A Dataset with no db_snapshot_sha256 keeps the old, looser contract."""
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)
    result = _export_from_package(package, snapshot, tmp_path, bind_snapshot=False)

    manifest = load_packet_if_manifest(result.manifest_path)

    assert manifest.db_snapshot_sha256 is None
    assert manifest.is_verified_collection_dataset is False
    dataset = load_packet_if_dataset(result.output_path, result.manifest_path)
    assert len(dataset.manifest.sessions) == 4


def test_official_dataset_requires_session_manifest_ref(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    """With a snapshot hash present, a missing Collection reference is fatal."""
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)
    result = _export_from_package(package, snapshot, tmp_path)

    # Collection 참조만 지우고 Hash 연쇄는 그대로 맞춰 둔다.
    run_path = (
        package / "runs" / "verified-normal-stable-train-01" / "run-manifest.json"
    )
    run_payload = json.loads(run_path.read_text(encoding="utf-8"))
    run_payload["session_manifest_ref"] = None
    run_manifest = RunManifest.from_json(json.dumps(run_payload))
    run_path.write_text(run_manifest.to_json(), encoding="utf-8")
    run_digest = importer.run_manifest_sha256(run_manifest)
    Path(f"{run_path}.sha256").write_text(f"{run_digest}\n", encoding="ascii")

    dataset_payload = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    for entry in dataset_payload["sessions"]:
        if entry["session_id"] == NORMAL_TRAIN_SESSION:
            entry["run_manifest_ref"]["sha256"] = run_digest
    result.manifest_path.write_text(
        json.dumps(dataset_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must declare session_manifest_ref"):
        load_packet_if_dataset(result.output_path, result.manifest_path)


def test_dataset_load_rejects_snapshot_hash_mismatch(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    """The Dataset's snapshot hash must equal every Collection Manifest's."""
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)
    result = _export_from_package(package, snapshot, tmp_path)

    dataset_payload = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    dataset_payload["db_snapshot_sha256"] = "f" * 64
    result.manifest_path.write_text(
        json.dumps(dataset_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="db_snapshot_sha256 does not match the Dataset Manifest",
    ):
        load_packet_if_dataset(result.output_path, result.manifest_path)


def test_dataset_load_accepts_matching_snapshot_hash(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)
    result = _export_from_package(package, snapshot, tmp_path)

    dataset = load_packet_if_dataset(result.output_path, result.manifest_path)

    assert dataset.manifest.is_verified_collection_dataset is True
    assert dataset.manifest.db_snapshot_sha256 == file_sha256(
        package / "db-snapshot.db"
    )


def test_dataset_manifest_rejects_invalid_snapshot_hash(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_full_batch(snapshot)
    package = _write_package(snapshot, tmp_path)
    result = _export_from_package(package, snapshot, tmp_path)

    dataset_payload = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    dataset_payload["db_snapshot_sha256"] = "not-a-hash"
    result.manifest_path.write_text(
        json.dumps(dataset_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="db_snapshot_sha256"):
        load_packet_if_manifest(result.manifest_path)








# --- Official operating composition (accepted, not enforced) -----------------


def test_importer_accepts_the_official_17_session_composition(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    """The real operating shape must import cleanly end to end.

    The importer does not require this composition — it is the Phase 5 operating
    plan, not a property of Verified Collection — but the official batch has to
    work, so it is exercised here in full.
    """
    for item in OFFICIAL_NORMAL_SESSIONS:
        snapshot.add_session(item["session_id"])
    _add_attack_session(snapshot)
    spec_payload = _spec_payload([*_official_normal_entries(), _attack_entry()])

    package = _write_package(snapshot, tmp_path, spec_payload)
    result = _export_from_package(package, snapshot, tmp_path)
    dataset = load_packet_if_dataset(result.output_path, result.manifest_path)

    assert len(dataset.manifest.sessions) == 17
    assert len(dataset.session_ids("train")) == 8
    assert len(dataset.session_ids("validation")) == 4
    assert len(dataset.session_ids("test")) == 5
    for split in ("train", "validation", "test"):
        scenarios = {
            spec.scenario
            for spec in dataset.manifest.sessions
            if spec.split == split and spec.traffic_label == "normal"
        }
        assert scenarios == set(NORMAL_PROFILES), split


def test_phase6b_import_spec_reuses_the_existing_17_sessions_exactly() -> None:
    spec_path = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "specs"
        / "packet-if-v2-calib-002-import-spec.json"
    )
    payload = json.loads(spec_path.read_text(encoding="utf-8"))
    legacy_sessions = json.dumps(
        payload["sessions"][:17],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    assert payload["dataset_package_id"] == PHASE6B_PACKAGE_ID
    assert len(payload["sessions"]) == 23
    assert hashlib.sha256(legacy_sessions).hexdigest() == (
        LEGACY_17_SESSIONS_CANONICAL_SHA256
    )
    spec = VerifiedCollectionImportSpec.from_json(json.dumps(payload))
    assert len(spec.sessions) == 23
    assert {session.session_id for session in spec.sessions[-6:]} == {
        item["session_id"] for item in PHASE6B_NORMAL_SESSIONS
    }


def test_importer_accepts_the_phase6b_23_session_composition_end_to_end(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    _seed_phase6b_23_session_batch(snapshot)

    package = _write_package(snapshot, tmp_path, _phase6b_23_session_spec())
    result = _export_from_package(package, snapshot, tmp_path)
    dataset = load_packet_if_dataset(result.output_path, result.manifest_path)

    assert package.name == PHASE6B_PACKAGE_ID
    assert len(dataset.manifest.sessions) == 23
    assert len(dataset.session_ids("train")) == 10
    assert len(dataset.session_ids("validation")) == 6
    assert len(dataset.session_ids("test")) == 7

    export_spec = _read_json(package / "packet-if-export-spec-v2.json")
    expected_snapshot_sha256 = file_sha256(snapshot.db_path)
    assert export_spec["db_snapshot_sha256"] == expected_snapshot_sha256
    for entry in export_spec["sessions"]:
        run_dir = package / Path(entry["run_manifest_path"]).parent
        for filename in (
            "run-manifest.json",
            "run-manifest.json.sha256",
            "verified-collection-manifest.json",
            "verified-collection-manifest.json.sha256",
        ):
            assert (run_dir / filename).is_file()
        collection = VerifiedCollectionManifest.from_json(
            (run_dir / "verified-collection-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        assert collection.db_snapshot_sha256 == expected_snapshot_sha256


def test_phase6b_check_only_reports_the_23_session_candidate_shape(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
    capsys,
) -> None:
    _seed_phase6b_23_session_batch(snapshot)
    spec_path = tmp_path / "packet-if-v2-calib-002-import-spec.json"
    spec_path.write_text(
        json.dumps(_phase6b_23_session_spec()),
        encoding="utf-8",
    )
    output_root = tmp_path / "exports"

    exit_code = main(
        [
            "--project-root",
            str(tmp_path),
            "--db-snapshot",
            str(snapshot.db_path),
            "--processed-pcap-dir",
            str(snapshot.pcap_dir),
            "--spec",
            str(spec_path),
            "--output-root",
            str(output_root),
            "--verification-commit-sha",
            VERIFICATION_COMMIT,
            "--check-only",
        ]
    )

    assert exit_code == 0
    assert not output_root.exists()
    summary = json.loads(capsys.readouterr().out)
    assert summary["dataset_package_id"] == PHASE6B_PACKAGE_ID
    assert summary["session_count"] == 23
    assert summary["split_counts"] == {
        "test": 7,
        "train": 10,
        "validation": 6,
    }
    assert summary["scenario_split_counts"] == {
        "normal_combined_variation": {
            "test": 2,
            "train": 3,
            "validation": 2,
        },
        "normal_interval_jitter": {"test": 1, "train": 2, "validation": 1},
        "normal_payload_variation": {
            "test": 1,
            "train": 2,
            "validation": 1,
        },
        "normal_stable": {"test": 2, "train": 3, "validation": 2},
        "packet_rate_flood": {"test": 1},
    }


def test_check_only_reports_scenario_split_breakdown_for_review(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
    capsys,
) -> None:
    """`--check-only` must surface the composition so an operator can verify it."""
    for item in OFFICIAL_NORMAL_SESSIONS:
        snapshot.add_session(item["session_id"])
    _add_attack_session(snapshot)
    spec_path = tmp_path / "import-spec.json"
    spec_path.write_text(
        json.dumps(_spec_payload([*_official_normal_entries(), _attack_entry()])),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "--project-root",
            str(tmp_path),
            "--db-snapshot",
            str(snapshot.db_path),
            "--processed-pcap-dir",
            str(snapshot.pcap_dir),
            "--spec",
            str(spec_path),
            "--output-root",
            str(tmp_path / "exports"),
            "--verification-commit-sha",
            VERIFICATION_COMMIT,
            "--check-only",
        ]
    )

    assert exit_code == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["session_count"] == 17
    assert summary["split_counts"] == {"test": 5, "train": 8, "validation": 4}
    assert summary["scenario_split_counts"] == {
        "normal_combined_variation": {"test": 1, "train": 2, "validation": 1},
        "normal_interval_jitter": {"test": 1, "train": 2, "validation": 1},
        "normal_payload_variation": {"test": 1, "train": 2, "validation": 1},
        "normal_stable": {"test": 1, "train": 2, "validation": 1},
        "packet_rate_flood": {"test": 1},
    }


def test_importer_accepts_a_different_valid_composition(
    snapshot: SnapshotBuilder,
    tmp_path: Path,
) -> None:
    """A batch that satisfies the safety rules but not the 17-Session plan works.

    This is the point of not hardcoding the composition: a future re-collection
    with a different Profile mix must not require code changes.
    """
    snapshot.add_session(NORMAL_TRAIN_SESSION)
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    _add_attack_session(snapshot)
    spec_payload = _spec_payload(
        [
            _session_entry(
                NORMAL_TRAIN_SESSION,
                slot="normal-jitter-train-01",
                split="train",
                scenario="normal_interval_jitter",
            ),
            _session_entry(
                NORMAL_VALIDATION_SESSION,
                slot="normal-jitter-validation-01",
                split="validation",
                scenario="normal_interval_jitter",
            ),
            _session_entry(
                NORMAL_TEST_SESSION,
                slot="normal-jitter-test-01",
                split="test",
                scenario="normal_interval_jitter",
            ),
            _attack_entry(),
        ]
    )

    plan = _preflight(snapshot, spec_payload)

    assert len(plan.sessions) == 4
