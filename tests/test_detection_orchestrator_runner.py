"""Detection Orchestrator Runner(P4-4-01) 테스트.

Runner의 책임은 Stage 구성·cutoff 확정·Barrier·Lock·주기이며, Stage 내부 판정과 Trust
정책은 각자의 테스트가 담당합니다. 마지막 테스트는 Feature Producer부터 Firewall
PENDING까지 한 흐름으로 이어지는지 확인합니다.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from ai.predict_packet_isolation_forest import PacketIFArtifact, PacketIFPrediction
from backend.app.config import Settings
from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.detection.packet_ai_detector import PacketIsolationForestStage
from edge.detection.packet_rule_detector import PacketRuleDetectorStage
from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.detection_event_writer import write_detection_event
from edge.detection.detector_contract import DetectorRunResult
from edge.detection.phase4_time import format_db_utc
from edge.detection.rule_detector import (
    ABNORMAL_PUBLISH_RATE,
    DETECTOR_RULE,
)
from edge.features.collect_feature_logs import MQTT_FEATURE_BUILDER, MQTT_LOGS_SOURCE
from edge.features.run_mqtt_feature_builder import (
    bootstrap_producer_checkpoint,
    run_producer_cycle,
)
from edge.orchestration.run_detection_orchestrator import (
    CYCLE_COMPLETED,
    CYCLE_SKIPPED_NO_NEW_WINDOW,
    CYCLE_SKIPPED_PACKET_NOT_READY,
    CYCLE_SKIPPED_NO_WATERMARK,
    GracefulShutdown,
    resolve_cycle_cutoff,
    resolve_cycle_range_start,
    print_checkpoint_status,
    run_orchestration_cycle,
    run_orchestrator_loop,
)
from edge.orchestration.packet_stage_readiness import PacketFeatureReadyStage
from edge.packet.capture_policy import CapturePolicy
from edge.runtime_lock import RuntimeLockError, single_instance_lock as _lock
from edge.orchestration.stage_registry import (
    ConfiguredStage,
    MQTT_FEATURE_RULE,
    MQTT_MESSAGE_RULE,
    PACKET_IF,
    PACKET_RULE,
    StageRegistry,
    StageConfigurationError,
    build_stage_registry,
    parse_stage_names,
)
from edge.trust.trust_score_v2 import TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE
from edge.packet import capture_session_repository as capture_sessions


DEVICE_ID = "esp32_02"
DEVICE_IP = "192.168.0.5"
BASE = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
PACKET_SESSION_ID = "33333333-3333-4333-8333-333333333333"


@pytest.fixture
def SessionLocal(tmp_path: Path):
    db_path = tmp_path / "phase4-orchestrator-runner.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    with TestingSessionLocal() as db:
        db.execute(
            text(
                """
                INSERT INTO devices (device_id, ip_address, trust_score, status)
                VALUES (:device_id, :ip_address, 100, 'normal')
                """
            ),
            {"device_id": DEVICE_ID, "ip_address": DEVICE_IP},
        )
        db.commit()
        # Producer Runtime은 Checkpoint 없이 실행을 거부한다. Orchestrator 테스트도
        # 실제 운영과 같은 순서(Bootstrap → Producer → Orchestrator)를 따른다.
        with db.begin():
            bootstrap_producer_checkpoint(db, now=BASE)
    try:
        yield TestingSessionLocal
    finally:
        engine.dispose()


@pytest.fixture
def registry():
    return build_stage_registry(
        enabled=[MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE],
        required=[MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE],
    )


def _insert_mqtt_log(db, *, received_at: datetime, device_id: str = DEVICE_ID) -> None:
    db.execute(
        text(
            """
            INSERT INTO mqtt_logs (
                device_id, topic, payload, payload_size,
                received_at, is_json_valid, is_topic_valid
            )
            VALUES (
                :device_id, :topic, '{"device_id":"esp32_02"}', 26,
                :received_at, 1, 1
            )
            """
        ),
        {
            "device_id": device_id,
            "topic": f"iot/{device_id}/sensor",
            "received_at": format_db_utc(received_at),
        },
    )


def _flood_window(db, *, window_index: int, messages: int = 20) -> None:
    """한 10초 Window 안에 publish_count > 15가 되도록 메시지를 넣습니다.

    `mqtt_logs.received_at`은 정수 초 UTC 문자열이므로 초당 여러 건을 넣어 Window당
    20건을 만듭니다.
    """
    window_start = BASE + timedelta(seconds=10 * window_index)
    for offset in range(messages):
        _insert_mqtt_log(
            db,
            received_at=window_start + timedelta(seconds=offset % 10),
        )
    db.commit()


def _completed(db, detector_name: str, source_table: str):
    return checkpoints.get_completed_window_end(
        db, detector_name=detector_name, source_table=source_table
    )


def _scalar(db, sql: str):
    return db.execute(text(sql)).scalar()


def _insert_processed_packet_window(
    db,
    *,
    session_id: str = PACKET_SESSION_ID,
    packet_count: int = 980,
    total_bytes: int = 9800,
) -> int:
    session_result = db.execute(
        text(
            """
            INSERT INTO packet_capture_sessions (
                session_id, capture_interface, started_at,
                first_window_start, ended_at, status
            )
            VALUES (
                :session_id, 'eth0', :window_start,
                :window_start, :window_end, 'COMPLETED'
            )
            """
        ),
        {
            "session_id": session_id,
            "window_start": format_db_utc(BASE),
            "window_end": format_db_utc(BASE + timedelta(seconds=10)),
        },
    )
    session_pk = int(session_result.lastrowid)
    segment_result = db.execute(
        text(
            """
            INSERT INTO packet_capture_segments (
                capture_session_id, file_name, capture_interface,
                window_start, window_end, status, packet_count, processed_at,
                actual_capture_started_at, capture_stop_requested_at,
                capture_process_exited_at, start_delay_seconds,
                captured_duration_seconds
            )
            VALUES (
                :session_pk, :file_name, 'eth0',
                :window_start, :window_end, 'PROCESSED', :packet_count, :window_end,
                :actual_start, :stop_requested_at,
                :process_exited_at, 0.2, 9.8
            )
            """
        ),
        {
            "session_pk": session_pk,
            "file_name": f"capture_{session_id}_eth0_packet-stage-e2e.pcap",
            "window_start": format_db_utc(BASE),
            "window_end": format_db_utc(BASE + timedelta(seconds=10)),
            "packet_count": packet_count,
            "actual_start": "2026-07-25T12:00:00.200000Z",
            "stop_requested_at": "2026-07-25T12:00:10.000000Z",
            "process_exited_at": "2026-07-25T12:00:10.050000Z",
        },
    )
    segment_id = int(segment_result.lastrowid)
    feature_result = db.execute(
        text(
            """
            INSERT INTO packet_feature_logs (
                capture_segment_id, device_id, peer_ip, direction,
                window_start, window_end, packet_count, total_bytes,
                avg_packet_size, max_packet_size, mean_inter_arrival_time,
                distinct_dest_port_count, tcp_syn_count,
                mqtt_related_packet_count, non_mqtt_tcp_udp_packet_count,
                capture_scope
            )
            VALUES (
                :segment_id, :device_id, :peer_ip, 'INBOUND',
                :window_start, :window_end, :packet_count, :total_bytes,
                10.0, 20, 0.01,
                1, 0, 10, 0,
                'gateway'
            )
            """
        ),
        {
            "segment_id": segment_id,
            "device_id": DEVICE_ID,
            "peer_ip": DEVICE_IP,
            "window_start": format_db_utc(BASE),
            "window_end": format_db_utc(BASE + timedelta(seconds=10)),
            "packet_count": packet_count,
            "total_bytes": total_bytes,
        },
    )
    return int(feature_result.lastrowid)


# --- Stage 구성 ------------------------------------------------------------


def test_parse_stage_names_keeps_order_and_drops_duplicates():
    assert parse_stage_names(" mqtt_feature_rule, mqtt_message_rule ,mqtt_feature_rule ") == (
        MQTT_FEATURE_RULE,
        MQTT_MESSAGE_RULE,
    )


def test_parse_stage_names_rejects_unknown_stage():
    with pytest.raises(StageConfigurationError, match="unknown stage"):
        parse_stage_names("mqtt_feature_rule,packet_fusion")


def test_required_stage_must_be_enabled():
    with pytest.raises(StageConfigurationError, match="must also be enabled"):
        build_stage_registry(enabled=[MQTT_FEATURE_RULE], required=[MQTT_MESSAGE_RULE])


def test_packet_rule_stage_can_be_enabled_and_required():
    app_settings = Settings(
        _env_file=None,
        packet_rule_packet_rate_threshold=321.0,
        packet_rule_policy_version="packet-rule-registry-test",
        pcap_max_start_delay_seconds=0.5,
        packet_min_capture_duration_seconds=9.5,
    )

    built = build_stage_registry(
        enabled=[MQTT_FEATURE_RULE, PACKET_RULE],
        required=[PACKET_RULE],
        app_settings=app_settings,
    )

    assert built.enabled_names == (MQTT_FEATURE_RULE, PACKET_RULE)
    assert built.required_names == (PACKET_RULE,)
    assert isinstance(built.stages[1].stage, PacketFeatureReadyStage)
    packet_rule = built.stages[1].stage.delegate
    assert isinstance(packet_rule, PacketRuleDetectorStage)
    assert packet_rule.rule_policy.packet_rate_threshold == 321.0
    assert (
        packet_rule.rule_policy.version
        == "packet-rule-registry-test"
    )
    assert packet_rule.capture_policy.max_start_delay_seconds == 0.5
    assert built.packet_layer_enabled is True
    assert built.packet_layer_required is True


def test_disabled_packet_if_does_not_require_artifact_configuration():
    app_settings = Settings(
        _env_file=None,
        packet_if_artifact_dir="",
        packet_if_expected_model_version="",
        packet_if_expected_bundle_sha256="",
    )

    built = build_stage_registry(
        enabled=[MQTT_FEATURE_RULE, PACKET_RULE],
        required=[MQTT_FEATURE_RULE],
        app_settings=app_settings,
    )

    assert PACKET_IF not in built.enabled_names


def test_enabled_packet_if_requires_artifact_configuration():
    app_settings = Settings(
        _env_file=None,
        packet_if_artifact_dir="",
        packet_if_expected_model_version="",
        packet_if_expected_bundle_sha256="",
    )

    with pytest.raises(
        StageConfigurationError,
        match=r"packet_if.*PACKET_IF_ARTIFACT_DIR",
    ):
        build_stage_registry(
            enabled=[PACKET_IF],
            required=[PACKET_IF],
            app_settings=app_settings,
        )


def test_packet_if_builder_uses_explicit_settings(monkeypatch):
    app_settings = Settings(
        _env_file=None,
        packet_if_artifact_dir="ai/models/packet_if/test-model",
        packet_if_expected_model_version="packet-if-test",
        packet_if_expected_bundle_sha256="a" * 64,
    )
    stage = object()
    captured = {}

    def fake_from_settings(cls, **kwargs):
        captured.update(kwargs)
        return stage

    monkeypatch.setattr(
        PacketIsolationForestStage,
        "from_settings",
        classmethod(fake_from_settings),
    )

    built = build_stage_registry(
        enabled=[PACKET_IF],
        required=[],
        app_settings=app_settings,
    )

    assert isinstance(built.stages[0].stage, PacketFeatureReadyStage)
    assert built.stages[0].stage.delegate is stage
    assert captured["app_settings"] is app_settings


def test_empty_stage_list_is_rejected():
    with pytest.raises(StageConfigurationError, match="at least one stage"):
        build_stage_registry(enabled=[], required=[])


def test_registry_reports_optional_and_required_stages():
    built = build_stage_registry(
        enabled=[MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE],
        required=[MQTT_FEATURE_RULE],
    )
    assert built.enabled_names == (MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE)
    assert built.required_names == (MQTT_FEATURE_RULE,)
    assert built.packet_layer_enabled is False
    assert built.packet_layer_required is False


# --- cutoff·range_start ----------------------------------------------------


def test_cycle_is_skipped_without_producer_watermark(SessionLocal, registry):
    """Producer가 아직 한 번도 돌지 않은 상태에서는 cutoff를 만들지 않는다."""
    with SessionLocal() as db:
        db.execute(
            text(
                """
                DELETE FROM detector_checkpoints
                WHERE detector_name = :detector_name AND source_table = :source_table
                """
            ),
            {"detector_name": MQTT_FEATURE_BUILDER, "source_table": MQTT_LOGS_SOURCE},
        )
        db.commit()

    outcome = run_orchestration_cycle(session_factory=SessionLocal, registry=registry)
    assert outcome.status == CYCLE_SKIPPED_NO_WATERMARK
    assert outcome.cutoff is None


def test_cutoff_comes_from_producer_checkpoint_only(SessionLocal, registry):
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))

    with SessionLocal() as db:
        assert resolve_cycle_cutoff(db) == BASE + timedelta(seconds=10)


def test_range_start_uses_earliest_source_on_first_run(SessionLocal, registry):
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))

    with SessionLocal() as db:
        cutoff = resolve_cycle_cutoff(db)
        assert resolve_cycle_range_start(db, registry=registry, cutoff=cutoff) == BASE


def test_second_cycle_without_new_window_is_skipped(SessionLocal, registry):
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))
    first = run_orchestration_cycle(session_factory=SessionLocal, registry=registry)
    assert first.status == CYCLE_COMPLETED

    second = run_orchestration_cycle(session_factory=SessionLocal, registry=registry)
    assert second.status == CYCLE_SKIPPED_NO_NEW_WINDOW


def test_required_packet_stage_skips_when_capture_session_is_not_ready(SessionLocal):
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))
    packet_registry = build_stage_registry(
        enabled=[PACKET_RULE],
        required=[PACKET_RULE],
    )

    outcome = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=packet_registry,
    )

    assert outcome.status == CYCLE_SKIPPED_PACKET_NOT_READY
    assert outcome.range_start == BASE
    assert outcome.cutoff == BASE + timedelta(seconds=10)
    with SessionLocal() as db:
        assert _completed(db, "packet_rule", "packet_feature_logs") is None
        assert _completed(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE) is None


def test_required_packet_stage_blocks_failed_packet_segment(SessionLocal):
    session_id = "12345678-1234-4234-8234-1234567890af"
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
        session_pk = capture_sessions.create_session(
            db,
            session_id=session_id,
            capture_interface="eth0",
            started_at=BASE,
        )
        capture_sessions.set_first_window_start(db, session_pk, BASE)
        segment_id = capture_sessions.insert_ready_segment(
            db,
            capture_session_pk=session_pk,
            file_name=f"capture_{session_id}_eth0_failed.pcap",
            capture_interface="eth0",
            window_start=BASE,
            window_end=BASE + timedelta(seconds=10),
        )
        db.execute(
            text(
                """
                UPDATE packet_capture_segments
                SET status = 'FAILED'
                WHERE id = :segment_id
                """
            ),
            {"segment_id": segment_id},
        )
        db.commit()

    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))
    packet_registry = build_stage_registry(
        enabled=[PACKET_RULE],
        required=[PACKET_RULE],
    )

    outcome = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=packet_registry,
    )

    assert outcome.status == CYCLE_SKIPPED_PACKET_NOT_READY
    with SessionLocal() as db:
        assert _completed(db, "packet_rule", "packet_feature_logs") is None
        assert _completed(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE) is None


def test_required_packet_stage_retries_after_ready_prefix_is_completed(SessionLocal):
    session_id = "12345678-1234-4234-8234-1234567890aa"
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
        session_pk = capture_sessions.create_session(
            db,
            session_id=session_id,
            capture_interface="eth0",
            started_at=BASE,
        )
        capture_sessions.set_first_window_start(db, session_pk, BASE)
        segment_id = capture_sessions.insert_ready_segment(
            db,
            capture_session_pk=session_pk,
            file_name=f"capture_{session_id}_eth0_ready.pcap",
            capture_interface="eth0",
            window_start=BASE,
            window_end=BASE + timedelta(seconds=10),
        )
        db.commit()

    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))
    packet_registry = build_stage_registry(
        enabled=[PACKET_RULE],
        required=[PACKET_RULE],
    )

    waiting = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=packet_registry,
    )
    assert waiting.status == CYCLE_SKIPPED_PACKET_NOT_READY

    with SessionLocal() as db:
        db.execute(
            text(
                """
                UPDATE packet_capture_segments
                SET status = 'EMPTY', packet_count = 0, processed_at = :processed_at
                WHERE id = :segment_id
                """
            ),
            {
                "segment_id": segment_id,
                "processed_at": format_db_utc(BASE + timedelta(seconds=10)),
            },
        )
        db.commit()

    completed = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=packet_registry,
    )
    assert completed.status == CYCLE_COMPLETED
    with SessionLocal() as db:
        assert _completed(
            db,
            "packet_rule",
            "packet_feature_logs",
        ) == BASE + timedelta(seconds=10)
        assert _completed(
            db,
            TRUST_DETECTOR_NAME,
            TRUST_SOURCE_TABLE,
        ) == BASE + timedelta(seconds=10)


def test_initial_packet_activation_catches_up_mqtt_before_first_capture(SessionLocal):
    session_id = "12345678-1234-4234-8234-1234567890ad"
    first_capture_start = BASE + timedelta(seconds=10)
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
        _flood_window(db, window_index=1)
        session_pk = capture_sessions.create_session(
            db,
            session_id=session_id,
            capture_interface="eth0",
            started_at=first_capture_start,
        )
        capture_sessions.set_first_window_start(db, session_pk, first_capture_start)
        segment_id = capture_sessions.insert_ready_segment(
            db,
            capture_session_pk=session_pk,
            file_name=f"capture_{session_id}_eth0_ready.pcap",
            capture_interface="eth0",
            window_start=first_capture_start,
            window_end=first_capture_start + timedelta(seconds=10),
        )
        db.commit()

    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=21))
    packet_registry = build_stage_registry(
        enabled=[MQTT_FEATURE_RULE, PACKET_RULE],
        required=[MQTT_FEATURE_RULE, PACKET_RULE],
    )

    activation = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=packet_registry,
    )

    assert activation.status == CYCLE_COMPLETED
    assert activation.range_start == BASE
    assert activation.cutoff == first_capture_start
    with SessionLocal() as db:
        assert _completed(
            db,
            MQTT_FEATURE_RULE,
            "feature_logs",
        ) == first_capture_start
        assert _completed(
            db,
            "packet_rule",
            "packet_feature_logs",
        ) == first_capture_start
        assert _completed(
            db,
            TRUST_DETECTOR_NAME,
            TRUST_SOURCE_TABLE,
        ) == first_capture_start
        assert _scalar(
            db,
            """
            SELECT COUNT(*)
            FROM detection_events
            WHERE event_type = 'ABNORMAL_PUBLISH_RATE'
              AND analysis_window_start = '2026-07-25T12:00:00Z'
              AND processed_at IS NOT NULL
            """,
        ) == 1

        db.execute(
            text(
                """
                UPDATE packet_capture_segments
                SET status = 'EMPTY', packet_count = 0, processed_at = :processed_at
                WHERE id = :segment_id
                """
            ),
            {
                "segment_id": segment_id,
                "processed_at": format_db_utc(
                    first_capture_start + timedelta(seconds=10)
                ),
            },
        )
        db.commit()

    resumed = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=packet_registry,
    )

    assert resumed.status == CYCLE_COMPLETED
    assert resumed.range_start == first_capture_start
    assert resumed.cutoff == first_capture_start + timedelta(seconds=10)
    with SessionLocal() as db:
        assert _completed(
            db,
            "packet_rule",
            "packet_feature_logs",
        ) == first_capture_start + timedelta(seconds=10)


def test_packet_activation_does_not_bridge_a_later_capture_session_gap(SessionLocal):
    first_session_id = "12345678-1234-4234-8234-1234567890ae"
    second_session_id = "12345678-1234-4234-8234-1234567890af"
    first_capture_start = BASE + timedelta(seconds=10)
    with SessionLocal() as db:
        for window_index in range(4):
            _flood_window(db, window_index=window_index)
        first_session_pk = capture_sessions.create_session(
            db,
            session_id=first_session_id,
            capture_interface="eth0",
            started_at=first_capture_start,
        )
        capture_sessions.set_first_window_start(
            db,
            first_session_pk,
            first_capture_start,
        )
        first_segment_id = capture_sessions.insert_ready_segment(
            db,
            capture_session_pk=first_session_pk,
            file_name=f"capture_{first_session_id}_eth0_empty.pcap",
            capture_interface="eth0",
            window_start=first_capture_start,
            window_end=first_capture_start + timedelta(seconds=10),
        )
        db.execute(
            text(
                """
                UPDATE packet_capture_segments
                SET status = 'EMPTY', packet_count = 0, processed_at = :processed_at
                WHERE id = :segment_id
                """
            ),
            {
                "segment_id": first_segment_id,
                "processed_at": format_db_utc(
                    first_capture_start + timedelta(seconds=10)
                ),
            },
        )

        second_capture_start = BASE + timedelta(seconds=30)
        second_session_pk = capture_sessions.create_session(
            db,
            session_id=second_session_id,
            capture_interface="eth0",
            started_at=second_capture_start,
        )
        capture_sessions.set_first_window_start(
            db,
            second_session_pk,
            second_capture_start,
        )
        second_segment_id = capture_sessions.insert_ready_segment(
            db,
            capture_session_pk=second_session_pk,
            file_name=f"capture_{second_session_id}_eth0_empty.pcap",
            capture_interface="eth0",
            window_start=second_capture_start,
            window_end=second_capture_start + timedelta(seconds=10),
        )
        db.execute(
            text(
                """
                UPDATE packet_capture_segments
                SET status = 'EMPTY', packet_count = 0, processed_at = :processed_at
                WHERE id = :segment_id
                """
            ),
            {
                "segment_id": second_segment_id,
                "processed_at": format_db_utc(
                    second_capture_start + timedelta(seconds=10)
                ),
            },
        )
        db.commit()

    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=41))
    packet_registry = build_stage_registry(
        enabled=[MQTT_FEATURE_RULE, PACKET_RULE],
        required=[MQTT_FEATURE_RULE, PACKET_RULE],
    )

    activation = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=packet_registry,
    )
    first_packet_cycle = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=packet_registry,
    )
    blocked_at_gap = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=packet_registry,
    )

    assert activation.status == CYCLE_COMPLETED
    assert activation.cutoff == first_capture_start
    assert first_packet_cycle.status == CYCLE_COMPLETED
    assert first_packet_cycle.cutoff == first_capture_start + timedelta(seconds=10)
    assert blocked_at_gap.status == CYCLE_SKIPPED_NO_NEW_WINDOW
    with SessionLocal() as db:
        assert _completed(
            db,
            "packet_rule",
            "packet_feature_logs",
        ) == first_capture_start + timedelta(seconds=10)
        assert _completed(
            db,
            TRUST_DETECTOR_NAME,
            TRUST_SOURCE_TABLE,
        ) == first_capture_start + timedelta(seconds=10)


def test_required_packet_stage_accepts_contiguous_empty_prefix(SessionLocal):
    session_id = "12345678-1234-4234-8234-1234567890ab"
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
        session_pk = capture_sessions.create_session(
            db,
            session_id=session_id,
            capture_interface="eth0",
            started_at=BASE,
        )
        capture_sessions.set_first_window_start(db, session_pk, BASE)
        segment_id = capture_sessions.insert_ready_segment(
            db,
            capture_session_pk=session_pk,
            file_name=f"capture_{session_id}_eth0_empty.pcap",
            capture_interface="eth0",
            window_start=BASE,
            window_end=BASE + timedelta(seconds=10),
        )
        db.execute(
            text(
                """
                UPDATE packet_capture_segments
                SET status = 'EMPTY', packet_count = 0, processed_at = :processed_at
                WHERE id = :segment_id
                """
            ),
            {
                "segment_id": segment_id,
                "processed_at": format_db_utc(BASE + timedelta(seconds=10)),
            },
        )
        db.commit()

    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))
    packet_registry = build_stage_registry(
        enabled=[PACKET_RULE],
        required=[PACKET_RULE],
    )

    outcome = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=packet_registry,
    )

    assert outcome.status == CYCLE_COMPLETED
    with SessionLocal() as db:
        assert _completed(
            db,
            "packet_rule",
            "packet_feature_logs",
        ) == BASE + timedelta(seconds=10)


def test_required_packet_stage_limits_cutoff_to_ready_prefix(SessionLocal):
    session_id = "12345678-1234-4234-8234-1234567890ac"
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
        _flood_window(db, window_index=1)
        session_pk = capture_sessions.create_session(
            db,
            session_id=session_id,
            capture_interface="eth0",
            started_at=BASE,
        )
        capture_sessions.set_first_window_start(db, session_pk, BASE)
        segment_id = capture_sessions.insert_ready_segment(
            db,
            capture_session_pk=session_pk,
            file_name=f"capture_{session_id}_eth0_empty.pcap",
            capture_interface="eth0",
            window_start=BASE,
            window_end=BASE + timedelta(seconds=10),
        )
        db.execute(
            text(
                """
                UPDATE packet_capture_segments
                SET status = 'EMPTY', packet_count = 0, processed_at = :processed_at
                WHERE id = :segment_id
                """
            ),
            {
                "segment_id": segment_id,
                "processed_at": format_db_utc(BASE + timedelta(seconds=10)),
            },
        )
        db.commit()

    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=21))
    packet_registry = build_stage_registry(
        enabled=[PACKET_RULE],
        required=[PACKET_RULE],
    )

    outcome = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=packet_registry,
    )

    assert outcome.status == CYCLE_COMPLETED
    assert outcome.cutoff == BASE + timedelta(seconds=10)
    with SessionLocal() as db:
        assert _completed(
            db,
            "packet_rule",
            "packet_feature_logs",
        ) == BASE + timedelta(seconds=10)
        assert _completed(
            db,
            TRUST_DETECTOR_NAME,
            TRUST_SOURCE_TABLE,
        ) == BASE + timedelta(seconds=10)


# --- Barrier ---------------------------------------------------------------


@dataclass
class StallingStage:
    """Checkpoint를 전진시키지 않는 Stage. Barrier 위반을 재현합니다."""

    detector_name: str = "mqtt_if"
    source_table: str = "feature_logs"

    def run_until(self, db, *, cycle_range_start, cycle_cutoff) -> DetectorRunResult:
        return DetectorRunResult(
            detector_name=self.detector_name,
            source_table=self.source_table,
            range_start=cycle_range_start,
            cutoff=cycle_cutoff,
            selected_count=0,
            created_event_count=0,
            last_processed_id_before=None,
            last_processed_id_after=None,
            completed_window_end_before=None,
            completed_window_end_after=cycle_cutoff,
        )


@dataclass
class FailingOptionalStage:
    detector_name: str = "mqtt_if"
    source_table: str = "feature_logs"

    def run_until(self, db, *, cycle_range_start, cycle_cutoff) -> DetectorRunResult:
        raise RuntimeError("optional stage failed")


@dataclass
class LateEventStage:
    detector_name: str = "mqtt_if"
    source_table: str = "feature_logs"

    def run_until(self, db, *, cycle_range_start, cycle_cutoff) -> DetectorRunResult:
        feature = db.execute(
            text(
                """
                SELECT id, device_id, window_start, window_end
                FROM feature_logs
                ORDER BY id
                LIMIT 1
                """
            )
        ).mappings().one()
        write_detection_event(
            db,
            device_id=feature["device_id"],
            detector_name=self.detector_name,
            source_table=self.source_table,
            source_id=int(feature["id"]),
            detector_type=DETECTOR_RULE,
            event_type=ABNORMAL_PUBLISH_RATE,
            severity="high",
            description="late optional evidence",
            policy_version="late-optional-test-v1",
            detected_at=cycle_cutoff,
            analysis_window_start=BASE,
            analysis_window_end=BASE + timedelta(seconds=10),
            subject_ip=DEVICE_IP,
            feature_log_id=int(feature["id"]),
        )
        checkpoints.upsert_detector_checkpoint(
            db,
            detector_name=self.detector_name,
            source_table=self.source_table,
            last_processed_id=int(feature["id"]),
            last_completed_window_end=cycle_cutoff,
            updated_at=cycle_cutoff,
        )
        return DetectorRunResult(
            detector_name=self.detector_name,
            source_table=self.source_table,
            range_start=cycle_range_start,
            cutoff=cycle_cutoff,
            selected_count=1,
            created_event_count=1,
            last_processed_id_before=None,
            last_processed_id_after=int(feature["id"]),
            completed_window_end_before=None,
            completed_window_end_after=cycle_cutoff,
        )


def test_trust_is_not_called_when_required_stage_has_not_reached_cutoff(SessionLocal):
    from edge.orchestration.stage_registry import ConfiguredStage, StageRegistry

    stalling = StageRegistry(
        stages=(ConfiguredStage(name="mqtt_if", stage=StallingStage(), required=True),)
    )
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))

    with pytest.raises(RuntimeError, match="required checkpoint"):
        run_orchestration_cycle(session_factory=SessionLocal, registry=stalling)

    with SessionLocal() as db:
        assert _completed(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE) is None


def test_optional_stage_that_stalls_does_not_block_trust(SessionLocal):
    from edge.orchestration.stage_registry import ConfiguredStage, StageRegistry

    built = build_stage_registry(
        enabled=[MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE],
        required=[MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE],
    )
    mixed = StageRegistry(
        stages=built.stages
        + (ConfiguredStage(name="mqtt_if", stage=StallingStage(), required=False),)
    )

    with SessionLocal() as db:
        _flood_window(db, window_index=0)
    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))

    outcome = run_orchestration_cycle(session_factory=SessionLocal, registry=mixed)

    assert outcome.status == CYCLE_COMPLETED
    with SessionLocal() as db:
        assert _completed(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE) == outcome.cutoff


def test_optional_stage_exception_does_not_block_trust_or_rewind_next_cycle(
    SessionLocal,
    caplog,
):
    from edge.orchestration.stage_registry import ConfiguredStage, StageRegistry

    built = build_stage_registry(
        enabled=[MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE],
        required=[MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE],
    )
    mixed = StageRegistry(
        stages=built.stages
        + (
            ConfiguredStage(
                name="mqtt_if",
                stage=FailingOptionalStage(),
                required=False,
            ),
        )
    )
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))

    with caplog.at_level("ERROR"):
        outcome = run_orchestration_cycle(session_factory=SessionLocal, registry=mixed)

    assert outcome.status == CYCLE_COMPLETED
    assert [result.detector_name for result in outcome.stage_results] == [
        MQTT_FEATURE_RULE,
        MQTT_MESSAGE_RULE,
    ]
    assert "event=STAGE_FAILED" in caplog.text
    assert "detector_name=mqtt_if" in caplog.text
    assert "source_table=feature_logs" in caplog.text
    assert "cycle_range_start=2026-07-25T12:00:00Z" in caplog.text
    assert "cycle_cutoff=2026-07-25T12:00:10Z" in caplog.text

    with SessionLocal() as db:
        assert (
            resolve_cycle_range_start(
                db,
                registry=mixed,
                cutoff=BASE + timedelta(seconds=20),
            )
            == BASE + timedelta(seconds=10)
        )


def test_late_optional_event_after_completed_trust_is_not_scored_twice(SessionLocal):
    from edge.orchestration.stage_registry import ConfiguredStage, StageRegistry

    required = build_stage_registry(
        enabled=[MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE],
        required=[MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE],
    )
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))
    first = run_orchestration_cycle(session_factory=SessionLocal, registry=required)
    assert first.status == CYCLE_COMPLETED

    with SessionLocal() as db:
        _insert_mqtt_log(db, received_at=BASE + timedelta(seconds=11))
        db.commit()
    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=21))

    with_late_optional = StageRegistry(
        stages=required.stages
        + (
            ConfiguredStage(
                name="mqtt_if",
                stage=LateEventStage(),
                required=False,
            ),
        )
    )
    second = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=with_late_optional,
    )
    assert second.status == CYCLE_COMPLETED

    with SessionLocal() as db:
        assert _scalar(db, "SELECT COUNT(*) FROM trust_score_history") == 1
        assert (
            _scalar(
                db,
                """
                SELECT COUNT(*)
                FROM detection_events
                WHERE description = 'late optional evidence'
                  AND processing_reason = 'LATE_EVENT'
                  AND applied_to_score = 0
                """,
            )
            == 1
        )


def test_all_stages_receive_the_same_cycle_window(SessionLocal, registry):
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))

    outcome = run_orchestration_cycle(session_factory=SessionLocal, registry=registry)

    assert len(outcome.stage_results) == 2
    assert {result.range_start for result in outcome.stage_results} == {outcome.range_start}
    assert {result.cutoff for result in outcome.stage_results} == {outcome.cutoff}


def test_trust_checkpoint_advances_with_empty_detection(SessionLocal, registry):
    # 메시지가 없는 구간이라 Event가 하나도 없지만 완료 Window는 전진해야 한다.
    with SessionLocal() as db:
        _insert_mqtt_log(db, received_at=BASE + timedelta(seconds=1))
        db.commit()
    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))

    outcome = run_orchestration_cycle(session_factory=SessionLocal, registry=registry)

    assert outcome.status == CYCLE_COMPLETED
    assert outcome.trust_result.created_history_count == 0
    with SessionLocal() as db:
        assert _completed(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE) == outcome.cutoff


# --- Lock ------------------------------------------------------------------


def test_single_instance_lock_blocks_second_holder(tmp_path: Path):
    lock_path = tmp_path / "orchestrator.lock"
    with _lock(lock_path):
        with pytest.raises(RuntimeLockError, match="another process holds the lock"):
            with _lock(lock_path):
                pass


def test_single_instance_lock_is_reusable_after_release(tmp_path: Path):
    lock_path = tmp_path / "orchestrator.lock"
    with _lock(lock_path):
        pass
    with _lock(lock_path):
        pass


# --- Loop ------------------------------------------------------------------


def test_loop_stops_after_max_cycles(SessionLocal, registry):
    completed = run_orchestrator_loop(
        registry=registry,
        shutdown=GracefulShutdown(),
        interval_seconds=0.01,
        session_factory=SessionLocal,
        max_cycles=2,
    )
    assert completed == 2


def test_loop_exits_immediately_on_shutdown(SessionLocal, registry):
    shutdown = GracefulShutdown()
    shutdown.request(15, None)
    completed = run_orchestrator_loop(
        registry=registry,
        shutdown=shutdown,
        interval_seconds=0.01,
        session_factory=SessionLocal,
        max_cycles=3,
    )
    assert completed == 0


@pytest.mark.parametrize("invalid", [0, -1])
def test_loop_rejects_invalid_max_cycles(SessionLocal, registry, invalid):
    with pytest.raises(ValueError):
        run_orchestrator_loop(
            registry=registry,
            shutdown=GracefulShutdown(),
            interval_seconds=1.0,
            session_factory=SessionLocal,
            max_cycles=invalid,
        )


def test_status_prints_all_checkpoint_keys_and_real_updated_at(
    SessionLocal,
    capsys,
):
    print_checkpoint_status(SessionLocal)

    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 7
    assert any(
        line.startswith("mqtt_feature_builder+mqtt_logs: status=PRESENT")
        and "updated_at=2026-07-25T12:00:00Z" in line
        for line in lines
    )
    assert any(
        line.startswith("mqtt_if+feature_logs: status=MISSING")
        and "updated_at=None" in line
        for line in lines
    )


# --- 전체 흐름 -------------------------------------------------------------


def test_flooding_drives_detection_trust_and_firewall_pending(SessionLocal, registry):
    """MQTT Flooding 4개 Window로 Trust 100 → 20까지 떨어지고 격리·Firewall PENDING까지 이어진다.

    ABNORMAL_PUBLISH_RATE는 publish_count > 15에서 -20이므로 4개 Window면 격리
    Threshold(30) 아래로 내려간다.
    """
    for window_index in range(4):
        with SessionLocal() as db:
            _flood_window(db, window_index=window_index)
        run_producer_cycle(
            session_factory=SessionLocal,
            now=BASE + timedelta(seconds=10 * window_index + 11),
        )
        run_orchestration_cycle(session_factory=SessionLocal, registry=registry)

    with SessionLocal() as db:
        assert _scalar(db, "SELECT COUNT(*) FROM feature_logs") == 4
        assert (
            _scalar(
                db,
                "SELECT COUNT(*) FROM detection_events "
                "WHERE event_type = 'ABNORMAL_PUBLISH_RATE'",
            )
            == 4
        )
        assert _scalar(db, "SELECT COUNT(*) FROM trust_score_history") == 4
        assert _scalar(db, f"SELECT trust_score FROM devices WHERE device_id = '{DEVICE_ID}'") == 20
        assert _scalar(db, f"SELECT status FROM devices WHERE device_id = '{DEVICE_ID}'") == "isolated"
        assert _scalar(db, "SELECT COUNT(*) FROM isolation_history") == 1
        firewall = db.execute(
            text("SELECT source_ip, protocol, dest_port, action, status FROM firewall_rules")
        ).mappings().all()

    assert len(firewall) == 1
    assert dict(firewall[0]) == {
        "source_ip": DEVICE_IP,
        "protocol": "tcp",
        "dest_port": 1883,
        "action": "DROP",
        "status": "PENDING",
    }


def test_repeated_cycles_do_not_duplicate_trust_history(SessionLocal, registry):
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))

    run_orchestration_cycle(session_factory=SessionLocal, registry=registry)
    run_orchestration_cycle(session_factory=SessionLocal, registry=registry)
    run_orchestration_cycle(session_factory=SessionLocal, registry=registry)

    with SessionLocal() as db:
        assert _scalar(db, "SELECT COUNT(*) FROM trust_score_history") == 1
        assert _scalar(db, "SELECT COUNT(*) FROM firewall_rules") == 0
        assert _scalar(db, f"SELECT trust_score FROM devices WHERE device_id = '{DEVICE_ID}'") == 80


def test_packet_rule_and_if_share_ready_session_and_reach_trust_once(
    SessionLocal,
    tmp_path: Path,
):
    capture_policy = CapturePolicy()
    model_version = "packet-if-orchestrator-e2e-v1"
    artifact = PacketIFArtifact(
        model=object(),
        model_path=tmp_path / "model.joblib",
        metadata_path=tmp_path / "metadata.json",
        training_report_path=tmp_path / "training-report.json",
        model_version=model_version,
        threshold=0.1,
        bundle_sha256="d" * 64,
        capture_policy=capture_policy,
        metadata={},
    )

    def predict_anomaly(
        _artifact: PacketIFArtifact,
        rows: list[dict],
    ) -> tuple[PacketIFPrediction, ...]:
        return tuple(
            PacketIFPrediction(
                model_version=model_version,
                raw_decision_score=-0.2,
                anomaly_score=0.2,
                threshold=0.1,
                is_anomaly=True,
                feature_values=(
                    float(row["packet_count"]),
                    float(row["total_bytes"]),
                    float(row["avg_packet_size"]),
                    float(row["max_packet_size"]),
                    float(row["mean_inter_arrival_time"]),
                    float(row["distinct_dest_port_count"]),
                ),
            )
            for row in rows
        )

    rule_registry = build_stage_registry(
        enabled=[PACKET_RULE],
        required=[PACKET_RULE],
        app_settings=Settings(_env_file=None),
    )
    packet_if_stage = PacketFeatureReadyStage(
        PacketIsolationForestStage(
            artifact=artifact,
            expected_model_version=model_version,
            capture_policy=capture_policy,
            predict_rows=predict_anomaly,
        )
    )
    packet_registry = StageRegistry(
        stages=rule_registry.stages
        + (
            ConfiguredStage(
                name=PACKET_IF,
                stage=packet_if_stage,
                required=True,
            ),
        )
    )

    with SessionLocal() as db:
        _insert_mqtt_log(db, received_at=BASE + timedelta(seconds=1))
        packet_feature_id = _insert_processed_packet_window(db)
        db.commit()
    run_producer_cycle(
        session_factory=SessionLocal,
        now=BASE + timedelta(seconds=11),
    )

    first = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=packet_registry,
    )
    second = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=packet_registry,
    )

    assert first.status == CYCLE_COMPLETED
    assert second.status == CYCLE_SKIPPED_NO_NEW_WINDOW
    assert {result.detector_name for result in first.stage_results} == {
        PACKET_RULE,
        PACKET_IF,
    }
    assert {
        result.capture_session_id for result in first.stage_results
    } == {PACKET_SESSION_ID}

    with SessionLocal() as db:
        events = db.execute(
            text(
                """
                SELECT dedupe_key, event_type, packet_feature_log_id
                FROM detection_events
                WHERE dedupe_key LIKE 'packet_rule:%'
                   OR dedupe_key LIKE 'packet_if:%'
                ORDER BY dedupe_key
                """
            )
        ).mappings().all()
        assert len(events) == 2
        packet_if_event, packet_rule_event = events
        assert packet_if_event["dedupe_key"].startswith(
            f"packet_if:packet_feature_logs:{packet_feature_id}:"
            "AI_PACKET_ANOMALY:"
        )
        assert packet_if_event["event_type"] == "AI_PACKET_ANOMALY"
        assert packet_if_event["packet_feature_log_id"] == packet_feature_id
        assert packet_rule_event["dedupe_key"].startswith(
            f"packet_rule:packet_feature_logs:{packet_feature_id}:"
            "PACKET_RATE_ANOMALY:"
        )
        assert packet_rule_event["event_type"] == "PACKET_RATE_ANOMALY"
        assert packet_rule_event["packet_feature_log_id"] == packet_feature_id
        assert _completed(
            db,
            PACKET_RULE,
            "packet_feature_logs",
        ) == BASE + timedelta(seconds=10)
        assert _completed(
            db,
            PACKET_IF,
            "packet_feature_logs",
        ) == BASE + timedelta(seconds=10)
        assert _completed(
            db,
            TRUST_DETECTOR_NAME,
            TRUST_SOURCE_TABLE,
        ) == BASE + timedelta(seconds=10)
        assert _scalar(db, "SELECT COUNT(*) FROM trust_score_history") == 1
        assert _scalar(
            db,
            f"SELECT trust_score FROM devices WHERE device_id = '{DEVICE_ID}'",
        ) == 80


def test_producer_and_orchestrator_checkpoints_stay_consistent(SessionLocal, registry):
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
        _flood_window(db, window_index=1)
    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=21))
    outcome = run_orchestration_cycle(session_factory=SessionLocal, registry=registry)

    with SessionLocal() as db:
        producer = _completed(db, MQTT_FEATURE_BUILDER, MQTT_LOGS_SOURCE)
        assert producer == outcome.cutoff
        for configured in registry.stages:
            assert (
                _completed(
                    db,
                    configured.stage.detector_name,
                    configured.stage.source_table,
                )
                == outcome.cutoff
            )
        assert _completed(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE) == outcome.cutoff
