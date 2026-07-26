from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from ai.predict_packet_isolation_forest import PacketIFArtifact
from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.detection import packet_ai_detector
from edge.detection.packet_ai_detector import PacketIsolationForestStage
from edge.detection.runtime_checkpoint_repository import get_detector_checkpoint
from edge.packet.capture_policy import CapturePolicy


RANGE_START = datetime(2026, 7, 26, 10, 0, 0, tzinfo=timezone.utc)
CUTOFF = datetime(2026, 7, 26, 10, 0, 10, tzinfo=timezone.utc)
NEXT_CUTOFF = datetime(2026, 7, 26, 10, 0, 20, tzinfo=timezone.utc)
THIRD_CUTOFF = datetime(2026, 7, 26, 10, 0, 30, tzinfo=timezone.utc)
SESSION_ID = "11111111-1111-4111-8111-111111111111"
SECOND_SESSION_ID = "22222222-2222-4222-8222-222222222222"


class FakeIsolationForest:
    def __init__(self, raw_scores: list[float]) -> None:
        self.raw_scores = raw_scores
        self.call_count = 0

    def decision_function(self, matrix: np.ndarray) -> np.ndarray:
        self.call_count += 1
        if len(self.raw_scores) != matrix.shape[0]:
            raise AssertionError("unexpected prediction row count")
        return np.asarray(self.raw_scores, dtype=float)


class FailingIsolationForest:
    def decision_function(self, matrix: np.ndarray) -> np.ndarray:
        raise RuntimeError("model inference failed")


@pytest.fixture
def SessionLocal(tmp_path: Path):
    db_path = tmp_path / "packet-if-runtime.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    session_factory = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )
    try:
        yield session_factory
    finally:
        engine.dispose()


def test_packet_if_stage_writes_anomaly_and_checkpoint_in_one_transaction(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        _insert_device(db)
        session_pk = _insert_capture_session(db)
        _insert_packet_source(
            db,
            session_pk=session_pk,
            feature_id=1,
            segment_id=1,
        )
        db.commit()

    stage = _stage(raw_scores=[-0.2], threshold=0.1)
    with SessionLocal() as db:
        with db.begin():
            result = stage.run_until(
                db,
                cycle_range_start=RANGE_START,
                cycle_cutoff=CUTOFF,
            )

    assert result.selected_count == 1
    assert result.created_event_count == 1
    assert result.last_processed_id_before is None
    assert result.last_processed_id_after == 1
    assert result.completed_window_end_after == CUTOFF

    with SessionLocal() as db:
        event = db.execute(
            text(
                """
                SELECT device_id, packet_feature_log_id, detector_type,
                       event_type, severity, score_delta, applied_to_score,
                       incident_family, subject_ip, evidence_json,
                       policy_version
                FROM detection_events
                """
            )
        ).mappings().one()
        assert event["device_id"] == "esp32_01"
        assert event["packet_feature_log_id"] == 1
        assert event["detector_type"] == "AI"
        assert event["event_type"] == "AI_PACKET_ANOMALY"
        assert event["severity"] == "medium"
        assert event["score_delta"] == -15
        assert event["applied_to_score"] == 0
        assert event["incident_family"] == "AI_ONLY"
        assert event["subject_ip"] == "192.168.0.4"
        assert event["policy_version"] == (
            "packet-if-runtime-v1:packet-if-test-v1:dddddddddddd"
        )

        evidence = json.loads(event["evidence_json"])
        assert evidence["capture_session_id"] == SESSION_ID
        assert evidence["model"]["anomaly_score"] == pytest.approx(0.2)
        assert evidence["model"]["bundle_sha256"] == "d" * 64
        assert evidence["model"]["threshold_operator"] == ">"
        assert evidence["capture_policy"]["version"] == "packet-capture-policy-v1"

        checkpoint = get_detector_checkpoint(
            db,
            detector_name="packet_if",
            source_table="packet_feature_logs",
        )
        assert checkpoint["last_processed_id"] == 1
        assert checkpoint["last_completed_window_end"] == "2026-07-26T10:00:10Z"


def test_packet_if_stage_keeps_normal_rows_as_evidence_only_in_source(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        _insert_device(db)
        session_pk = _insert_capture_session(db)
        _insert_packet_source(
            db,
            session_pk=session_pk,
            feature_id=1,
            segment_id=1,
        )
        db.commit()

    stage = _stage(raw_scores=[0.2], threshold=0.1)
    with SessionLocal() as db:
        with db.begin():
            result = stage.run_until(
                db,
                cycle_range_start=RANGE_START,
                cycle_cutoff=CUTOFF,
            )
        assert result.created_event_count == 0
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 0
        checkpoint = get_detector_checkpoint(
            db,
            detector_name="packet_if",
            source_table="packet_feature_logs",
        )
        assert checkpoint["last_processed_id"] == 1


def test_packet_if_stage_keeps_isolated_registered_device_in_scope(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, status="isolated")
        session_pk = _insert_capture_session(db)
        _insert_packet_source(
            db,
            session_pk=session_pk,
            feature_id=1,
            segment_id=1,
        )
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = _stage(raw_scores=[-0.2]).run_until(
                db,
                cycle_range_start=RANGE_START,
                cycle_cutoff=CUTOFF,
            )
        assert result.created_event_count == 1
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 1


def test_packet_if_stage_consumes_ineligible_rows_without_inference(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        _insert_device(db)
        session_pk = _insert_capture_session(db)
        _insert_packet_source(
            db,
            session_pk=session_pk,
            feature_id=1,
            segment_id=1,
            direction="OUTBOUND",
        )
        _insert_packet_source(
            db,
            session_pk=session_pk,
            feature_id=2,
            segment_id=2,
            device_id=None,
            peer_ip="192.168.0.99",
            window_start="2026-07-26T10:00:10Z",
            window_end="2026-07-26T10:00:20Z",
        )
        _insert_packet_source(
            db,
            session_pk=session_pk,
            feature_id=3,
            segment_id=3,
            duration=8.0,
            window_start="2026-07-26T10:00:20Z",
            window_end="2026-07-26T10:00:30Z",
        )
        db.commit()

    model = FakeIsolationForest([])
    stage = _stage(model=model)
    with SessionLocal() as db:
        with db.begin():
            result = stage.run_until(
                db,
                cycle_range_start=RANGE_START,
                cycle_cutoff=THIRD_CUTOFF,
            )

        assert result.selected_count == 3
        assert result.created_event_count == 0
        assert result.last_processed_id_after == 3
        assert model.call_count == 0
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 0


def test_packet_if_stage_is_idempotent_for_the_same_range(SessionLocal) -> None:
    with SessionLocal() as db:
        _insert_device(db)
        session_pk = _insert_capture_session(db)
        _insert_packet_source(
            db,
            session_pk=session_pk,
            feature_id=1,
            segment_id=1,
        )
        db.commit()

    stage = _stage(raw_scores=[-0.2], threshold=0.1)
    with SessionLocal() as db:
        with db.begin():
            first = stage.run_until(
                db,
                cycle_range_start=RANGE_START,
                cycle_cutoff=CUTOFF,
            )
        with db.begin():
            second = stage.run_until(
                db,
                cycle_range_start=RANGE_START,
                cycle_cutoff=CUTOFF,
            )

        assert first.created_event_count == 1
        assert second.created_event_count == 0
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 1


def test_packet_if_stage_processes_lower_id_in_a_future_window(SessionLocal) -> None:
    with SessionLocal() as db:
        _insert_device(db)
        session_pk = _insert_capture_session(db)
        _insert_packet_source(
            db,
            session_pk=session_pk,
            feature_id=10,
            segment_id=1,
        )
        _insert_packet_source(
            db,
            session_pk=session_pk,
            feature_id=5,
            segment_id=2,
            window_start="2026-07-26T10:00:10Z",
            window_end="2026-07-26T10:00:20Z",
        )
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            first = _stage(raw_scores=[0.2]).run_until(
                db,
                cycle_range_start=RANGE_START,
                cycle_cutoff=CUTOFF,
            )
        with db.begin():
            second = _stage(raw_scores=[-0.2]).run_until(
                db,
                cycle_range_start=CUTOFF,
                cycle_cutoff=NEXT_CUTOFF,
            )

        assert first.last_processed_id_after == 10
        assert second.selected_count == 1
        assert second.created_event_count == 1
        assert second.last_processed_id_after == 10
        event_source = db.execute(
            text("SELECT packet_feature_log_id FROM detection_events")
        ).scalar_one()
        assert event_source == 5


def test_packet_if_stage_rejects_mixed_capture_sessions_without_db_changes(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        _insert_device(db)
        first_session = _insert_capture_session(db)
        second_session = _insert_capture_session(
            db,
            session_id=SECOND_SESSION_ID,
        )
        _insert_packet_source(
            db,
            session_pk=first_session,
            feature_id=1,
            segment_id=1,
        )
        _insert_packet_source(
            db,
            session_pk=second_session,
            feature_id=2,
            segment_id=2,
            window_start="2026-07-26T10:00:10Z",
            window_end="2026-07-26T10:00:20Z",
        )
        db.commit()

    with SessionLocal() as db:
        with pytest.raises(RuntimeError, match="must not mix Capture Sessions"):
            with db.begin():
                _stage(raw_scores=[-0.2, -0.2]).run_until(
                    db,
                    cycle_range_start=RANGE_START,
                    cycle_cutoff=NEXT_CUTOFF,
                )

    with SessionLocal() as db:
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 0
        assert get_detector_checkpoint(
            db,
            detector_name="packet_if",
            source_table="packet_feature_logs",
        ) is None


def test_packet_if_stage_rolls_back_event_and_checkpoint_on_writer_failure(
    SessionLocal,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SessionLocal() as db:
        _insert_device(db)
        session_pk = _insert_capture_session(db)
        _insert_packet_source(
            db,
            session_pk=session_pk,
            feature_id=1,
            segment_id=1,
        )
        db.commit()

    real_writer = packet_ai_detector.write_detection_event

    def fail_after_insert(*args: Any, **kwargs: Any):
        real_writer(*args, **kwargs)
        raise RuntimeError("writer failed")

    monkeypatch.setattr(
        packet_ai_detector,
        "write_detection_event",
        fail_after_insert,
    )
    with SessionLocal() as db:
        with pytest.raises(RuntimeError, match="writer failed"):
            with db.begin():
                _stage(raw_scores=[-0.2]).run_until(
                    db,
                    cycle_range_start=RANGE_START,
                    cycle_cutoff=CUTOFF,
                )

    with SessionLocal() as db:
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 0
        assert get_detector_checkpoint(
            db,
            detector_name="packet_if",
            source_table="packet_feature_logs",
        ) is None


def test_packet_if_stage_model_failure_leaves_database_unchanged(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        _insert_device(db)
        session_pk = _insert_capture_session(db)
        _insert_packet_source(
            db,
            session_pk=session_pk,
            feature_id=1,
            segment_id=1,
        )
        db.commit()

    with SessionLocal() as db:
        with pytest.raises(RuntimeError, match="model inference failed"):
            with db.begin():
                _stage(model=FailingIsolationForest()).run_until(
                    db,
                    cycle_range_start=RANGE_START,
                    cycle_cutoff=CUTOFF,
                )

    with SessionLocal() as db:
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 0
        assert get_detector_checkpoint(
            db,
            detector_name="packet_if",
            source_table="packet_feature_logs",
        ) is None


def test_packet_if_stage_empty_range_advances_only_completed_window(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        with db.begin():
            result = _stage(raw_scores=[]).run_until(
                db,
                cycle_range_start=RANGE_START,
                cycle_cutoff=CUTOFF,
            )
        assert result.selected_count == 0
        assert result.last_processed_id_after is None
        checkpoint = get_detector_checkpoint(
            db,
            detector_name="packet_if",
            source_table="packet_feature_logs",
        )
        assert checkpoint["last_processed_id"] is None
        assert checkpoint["last_completed_window_end"] == "2026-07-26T10:00:10Z"


def test_packet_if_stage_rejects_model_and_capture_policy_mismatch() -> None:
    with pytest.raises(ValueError, match="model version mismatch"):
        PacketIsolationForestStage(
            artifact=_artifact(model=FakeIsolationForest([])),
            expected_model_version="other-model",
            capture_policy=CapturePolicy(),
        )

    with pytest.raises(ValueError, match="Capture Policy mismatch"):
        PacketIsolationForestStage(
            artifact=_artifact(model=FakeIsolationForest([])),
            expected_model_version="packet-if-test-v1",
            capture_policy=CapturePolicy(version="other-policy"),
        )

    with pytest.raises(ValueError, match="Capture Policy mismatch"):
        PacketIsolationForestStage(
            artifact=_artifact(model=FakeIsolationForest([])),
            expected_model_version="packet-if-test-v1",
            capture_policy=CapturePolicy(minimum_duration_seconds=8.0),
        )


def test_packet_if_stage_from_settings_requires_runtime_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        packet_ai_detector.settings,
        "packet_if_artifact_dir",
        "",
    )
    monkeypatch.setattr(
        packet_ai_detector.settings,
        "packet_if_expected_model_version",
        "",
    )
    monkeypatch.setattr(
        packet_ai_detector.settings,
        "packet_if_expected_bundle_sha256",
        "",
    )
    with pytest.raises(ValueError, match="PACKET_IF_ARTIFACT_DIR"):
        PacketIsolationForestStage.from_settings()

    monkeypatch.setattr(
        packet_ai_detector.settings,
        "packet_if_artifact_dir",
        "ai/models/packet_if/packet-if-test-v1",
    )
    monkeypatch.setattr(
        packet_ai_detector,
        "load_packet_if_artifact",
        lambda *_args, **_kwargs: _artifact(model=FakeIsolationForest([])),
    )
    with pytest.raises(ValueError, match="PACKET_IF_EXPECTED_MODEL_VERSION"):
        PacketIsolationForestStage.from_settings()

    monkeypatch.setattr(
        packet_ai_detector.settings,
        "packet_if_expected_model_version",
        "packet-if-test-v1",
    )
    with pytest.raises(ValueError, match="PACKET_IF_EXPECTED_BUNDLE_SHA256"):
        PacketIsolationForestStage.from_settings()


def _stage(
    *,
    raw_scores: list[float] | None = None,
    threshold: float = 0.1,
    model: FakeIsolationForest | FailingIsolationForest | None = None,
) -> PacketIsolationForestStage:
    resolved_model = model or FakeIsolationForest(raw_scores or [])
    return PacketIsolationForestStage(
        artifact=_artifact(
            model=resolved_model,
            threshold=threshold,
        ),
        expected_model_version="packet-if-test-v1",
        capture_policy=CapturePolicy(),
    )


def _artifact(
    *,
    model: FakeIsolationForest | FailingIsolationForest,
    threshold: float = 0.1,
) -> PacketIFArtifact:
    return PacketIFArtifact(
        model=model,  # type: ignore[arg-type]
        model_path=Path("model.joblib"),
        metadata_path=Path("metadata.json"),
        training_report_path=Path("training_report.json"),
        model_version="packet-if-test-v1",
        threshold=threshold,
        bundle_sha256="d" * 64,
        capture_policy=CapturePolicy(),
        metadata={"capture_policy_version": "packet-capture-policy-v1"},
    )


def _insert_device(db, *, status: str = "normal") -> None:
    db.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES ('esp32_01', '192.168.0.4', :status, 100)
            """
        ),
        {"status": status},
    )


def _insert_capture_session(
    db,
    *,
    session_id: str = SESSION_ID,
) -> int:
    result = db.execute(
        text(
            """
            INSERT INTO packet_capture_sessions (
                session_id,
                capture_interface,
                started_at,
                first_window_start,
                ended_at,
                status
            )
            VALUES (
                :session_id,
                'eth0',
                '2026-07-26T10:00:00Z',
                '2026-07-26T10:00:00Z',
                '2026-07-26T10:01:00Z',
                'COMPLETED'
            )
            """
        ),
        {"session_id": session_id},
    )
    return int(result.lastrowid)


def _insert_packet_source(
    db,
    *,
    session_pk: int,
    feature_id: int,
    segment_id: int,
    device_id: str | None = "esp32_01",
    peer_ip: str = "192.168.0.4",
    direction: str = "INBOUND",
    window_start: str = "2026-07-26T10:00:00Z",
    window_end: str = "2026-07-26T10:00:10Z",
    duration: float = 9.8,
) -> None:
    db.execute(
        text(
            """
            INSERT INTO packet_capture_segments (
                id,
                capture_session_id,
                file_name,
                capture_interface,
                window_start,
                window_end,
                status,
                packet_count,
                processed_at,
                start_delay_seconds,
                captured_duration_seconds
            )
            VALUES (
                :segment_id,
                :session_pk,
                :file_name,
                'eth0',
                :window_start,
                :window_end,
                'PROCESSED',
                10,
                :window_end,
                0.2,
                :duration
            )
            """
        ),
        {
            "segment_id": segment_id,
            "session_pk": session_pk,
            "file_name": f"segment-{segment_id}.pcap",
            "window_start": window_start,
            "window_end": window_end,
            "duration": duration,
        },
    )
    db.execute(
        text(
            """
            INSERT INTO packet_feature_logs (
                id,
                capture_segment_id,
                device_id,
                peer_ip,
                direction,
                window_start,
                window_end,
                packet_count,
                total_bytes,
                avg_packet_size,
                max_packet_size,
                mean_inter_arrival_time,
                distinct_dest_port_count,
                tcp_syn_count,
                mqtt_related_packet_count,
                non_mqtt_tcp_udp_packet_count,
                capture_scope
            )
            VALUES (
                :feature_id,
                :segment_id,
                :device_id,
                :peer_ip,
                :direction,
                :window_start,
                :window_end,
                10,
                1000,
                100.0,
                120,
                0.5,
                2,
                1,
                8,
                2,
                'gateway'
            )
            """
        ),
        {
            "feature_id": feature_id,
            "segment_id": segment_id,
            "device_id": device_id,
            "peer_ip": peer_ip,
            "direction": direction,
            "window_start": window_start,
            "window_end": window_end,
        },
    )
