"""Read-only Verified Collection preflight tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from ai.packet_if_phase5_manifest import (
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


NORMAL_TRAIN_SESSION = "11111111-1111-4111-8111-111111111111"
NORMAL_VALIDATION_SESSION = "22222222-2222-4222-8222-222222222222"
NORMAL_TEST_SESSION = "33333333-3333-4333-8333-333333333333"
ATTACK_TEST_SESSION = "23d5dc5b-1e73-44e4-80ed-1d0c12bda7f9"
HOLDOUT_SESSION = "44444444-4444-4444-8444-444444444444"

CAPTURE_COMMIT = "a" * 40
ATTACK_COMMIT = "a4b0be29a8353f3b516808e2ed945b6cb251ac61"
VERIFICATION_COMMIT = "b" * 40
INTERFACE = "eth0"
BASE_TIME = datetime(2026, 8, 3, 10, 0, 0, tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class SnapshotBuilder:
    """Builds a migrated SQLite snapshot plus its processed PCAP directory."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.db_path = (root / "iot_security.snapshot.db").resolve()
        self.pcap_dir = root / "pcap" / "processed"
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        apply_migrations(self.db_path, MIGRATIONS_DIR)
        self._engine = create_engine(f"sqlite:///{self.db_path}")
        self._SessionLocal = sessionmaker(bind=self._engine)
        self._segment_id = 0
        self._feature_id = 0
        self._window_cursor = 0
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

    def dispose(self) -> None:
        self._engine.dispose()

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
        provenance="RETROSPECTIVE_SOURCE_AND_PCAP_VERIFICATION",
        commit=ATTACK_COMMIT,
        target_device_id="esp32_02",
        target_source_ip="192.168.0.5",
    )
    entry.update(overrides)
    return entry


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


def _full_spec() -> dict:
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
        ]
    )


def _seed_full_batch(snapshot: SnapshotBuilder) -> None:
    snapshot.add_session(NORMAL_TRAIN_SESSION)
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )


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
    snapshot.add_session(NORMAL_TRAIN_SESSION)
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
        extra_device=("esp32_01", "192.168.0.4"),
    )

    plan = _preflight(snapshot, _full_spec())
    attack = plan.session_by_id(ATTACK_TEST_SESSION)

    assert attack.background_traffic_present is True
    assert attack.included_device_ids == ("esp32_02",)


# --- Session validation ------------------------------------------------------


def test_preflight_rejects_missing_session(snapshot: SnapshotBuilder) -> None:
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

    with pytest.raises(VerifiedCollectionImportError, match="not found"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_non_completed_session(snapshot: SnapshotBuilder) -> None:
    snapshot.add_session(NORMAL_TRAIN_SESSION, status="RUNNING")
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

    with pytest.raises(VerifiedCollectionImportError, match="COMPLETED"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_ready_segment(snapshot: SnapshotBuilder) -> None:
    snapshot.add_session(
        NORMAL_TRAIN_SESSION,
        segment_statuses=("PROCESSED", "READY"),
    )
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

    with pytest.raises(VerifiedCollectionImportError, match="READY"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_failed_segment(snapshot: SnapshotBuilder) -> None:
    snapshot.add_session(
        NORMAL_TRAIN_SESSION,
        segment_statuses=("PROCESSED", "FAILED"),
    )
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

    with pytest.raises(VerifiedCollectionImportError, match="FAILED"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_processed_segment_without_feature(
    snapshot: SnapshotBuilder,
) -> None:
    snapshot.add_session(NORMAL_TRAIN_SESSION, omit_feature_for_processed=True)
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

    with pytest.raises(VerifiedCollectionImportError, match="PROCESSED"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_empty_segment_with_feature(
    snapshot: SnapshotBuilder,
) -> None:
    snapshot.add_session(
        NORMAL_TRAIN_SESSION,
        segment_statuses=("PROCESSED", "EMPTY"),
        feature_for_empty=True,
    )
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

    with pytest.raises(VerifiedCollectionImportError, match="EMPTY"):
        _preflight(snapshot, _full_spec())


def test_preflight_accepts_empty_segment_without_feature(
    snapshot: SnapshotBuilder,
) -> None:
    snapshot.add_session(
        NORMAL_TRAIN_SESSION,
        segment_statuses=("PROCESSED", "EMPTY"),
    )
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

    plan = _preflight(snapshot, _full_spec())
    train = plan.session_by_id(NORMAL_TRAIN_SESSION)

    assert train.processed_segment_count == 1
    assert train.empty_segment_count == 1
    assert train.eligible_row_count == 1


def test_preflight_rejects_window_gap(snapshot: SnapshotBuilder) -> None:
    snapshot.add_session(
        NORMAL_TRAIN_SESSION,
        segments=3,
        segment_statuses=("PROCESSED", "PROCESSED", "PROCESSED"),
        window_gap_after=1,
    )
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

    with pytest.raises(VerifiedCollectionImportError, match="contiguous"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_feature_segment_window_mismatch(
    snapshot: SnapshotBuilder,
) -> None:
    snapshot.add_session(NORMAL_TRAIN_SESSION, feature_window_shift_seconds=10)
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

    with pytest.raises(VerifiedCollectionImportError, match="window"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_no_eligible_rows(snapshot: SnapshotBuilder) -> None:
    snapshot.add_session(NORMAL_TRAIN_SESSION, feature_direction="OUTBOUND")
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

    with pytest.raises(VerifiedCollectionImportError, match="eligible"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_ineligible_capture_timing(
    snapshot: SnapshotBuilder,
) -> None:
    snapshot.add_session(NORMAL_TRAIN_SESSION, duration=7.5)
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

    with pytest.raises(VerifiedCollectionImportError, match="eligible"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_device_ip_mismatch(snapshot: SnapshotBuilder) -> None:
    snapshot.add_session(NORMAL_TRAIN_SESSION, feature_peer_ip="192.168.0.99")
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

    with pytest.raises(VerifiedCollectionImportError, match="eligible"):
        _preflight(snapshot, _full_spec())


def test_preflight_rejects_collection_device_not_matching_rows(
    snapshot: SnapshotBuilder,
) -> None:
    snapshot.add_session(
        NORMAL_TRAIN_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

    with pytest.raises(VerifiedCollectionImportError, match="collection_device_id"):
        _preflight(snapshot, _full_spec())


# --- PCAP --------------------------------------------------------------------


def test_preflight_rejects_missing_pcap(snapshot: SnapshotBuilder) -> None:
    snapshot.add_session(NORMAL_TRAIN_SESSION, write_pcap=False)
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

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
    snapshot.add_session(NORMAL_TRAIN_SESSION, pcap_filename_override=bogus)
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
    )

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
    snapshot.add_session(NORMAL_TRAIN_SESSION)
    snapshot.add_session(NORMAL_VALIDATION_SESSION)
    snapshot.add_session(NORMAL_TEST_SESSION)
    snapshot.add_session(
        ATTACK_TEST_SESSION,
        device_id="esp32_02",
        peer_ip="192.168.0.5",
        segments=2,
        packet_count=440,
    )
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
        "RETROSPECTIVE_SOURCE_AND_PCAP_VERIFICATION"
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
