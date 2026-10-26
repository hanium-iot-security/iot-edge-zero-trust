"""Detection Orchestrator Runner(P4-4-01) 테스트.

Runner의 책임은 Stage 구성·cutoff 확정·Barrier·Lock·주기이며, Stage 내부 판정과 Trust
정책은 각자의 테스트가 담당합니다. 마지막 테스트는 Feature Producer부터 Firewall
PENDING까지 한 흐름으로 이어지는지 확인합니다.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from shutil import copyfile
import signal
from threading import Event

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
from edge.orchestration import run_detection_orchestrator as runner
from edge.orchestration.run_detection_orchestrator import (
    CYCLE_COMPLETED,
    CYCLE_SKIPPED_NO_NEW_WINDOW,
    CYCLE_SKIPPED_PACKET_NOT_READY,
    CYCLE_SKIPPED_NO_WATERMARK,
    GracefulShutdown,
    resolve_cycle_cutoff,
    resolve_cycle_range_start,
    resolve_packet_live_resume_transition,
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
    legacy_migrations = tmp_path / "migrations-v2"
    legacy_migrations.mkdir()
    for source in MIGRATIONS_DIR.glob("[0-9][0-9][0-9]_*.sql"):
        if int(source.name[:3]) <= 6:
            copyfile(source, legacy_migrations / source.name)
    apply_migrations(db_path, legacy_migrations)
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
    window_start: datetime = BASE,
    session_status: str = "COMPLETED",
    terminal_end_offset: timedelta = timedelta(0),
    packet_count: int = 980,
    total_bytes: int = 9800,
) -> int:
    window_end = window_start + timedelta(seconds=10)
    session_result = db.execute(
        text(
            """
            INSERT INTO packet_capture_sessions (
                session_id, capture_interface, started_at,
                first_window_start, ended_at, status
            )
            VALUES (
                :session_id, 'eth0', :window_start,
                :window_start, :ended_at, :status
            )
            """
        ),
        {
            "session_id": session_id,
            "window_start": format_db_utc(window_start),
            "ended_at": (
                format_db_utc(window_end + terminal_end_offset)
                if session_status != "RUNNING"
                else None
            ),
            "status": session_status,
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
            "window_start": format_db_utc(window_start),
            "window_end": format_db_utc(window_end),
            "packet_count": packet_count,
            "actual_start": (
                window_start + timedelta(milliseconds=200)
            ).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "stop_requested_at": window_end.isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z"),
            "process_exited_at": (
                window_end + timedelta(milliseconds=50)
            ).isoformat(timespec="microseconds").replace("+00:00", "Z"),
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
            "window_start": format_db_utc(window_start),
            "window_end": format_db_utc(window_end),
            "packet_count": packet_count,
            "total_bytes": total_bytes,
        },
    )
    return int(feature_result.lastrowid)


LIVE_RESUME_TARGET_SESSION_ID = "44444444-4444-4444-8444-444444444444"


def _insert_live_resume_recovery_audit(
    db,
    *,
    current_session_id: str,
    target_session_id: str,
    last_processed_id: int,
    boundary_before: datetime,
    boundary_after: datetime,
    detector_name: str = "packet_rule",
    mode: str = "live-resume",
    plan_sha_matches: bool = True,
) -> None:
    plan_sha256 = "a" * 64
    plan = {
        "mode": mode,
        "plan_sha256": plan_sha256 if plan_sha_matches else "d" * 64,
    }
    db.execute(
        text(
            """
            INSERT INTO packet_checkpoint_recoveries (
                operation_id, detector_name, source_table,
                current_capture_session_id, target_capture_session_id,
                last_processed_id_before, last_processed_id_after,
                last_completed_window_end_before,
                last_completed_window_end_after,
                updated_at_before, updated_at_after,
                plan_sha256, plan_json,
                skipped_session_count, skipped_processable_session_count,
                approved_by, reason, repository_commit, database_path,
                backup_path, backup_sha256
            )
            VALUES (
                :operation_id, :detector_name, 'packet_feature_logs',
                :current_session_id, :target_session_id,
                :last_processed_id, :last_processed_id,
                :boundary_before, :boundary_after,
                :boundary_before, :boundary_after,
                :plan_sha256, :plan_json, 0, 0,
                'operator@example.com', 'approved live resume',
                :repository_commit, 'test.db', 'test.backup.db', :backup_sha256
            )
            """
        ),
        {
            "operation_id": f"orchestrator-live-resume-test-{detector_name}",
            "detector_name": detector_name,
            "current_session_id": current_session_id,
            "target_session_id": target_session_id,
            "last_processed_id": last_processed_id,
            "boundary_before": format_db_utc(boundary_before),
            "boundary_after": format_db_utc(boundary_after),
            "plan_sha256": plan_sha256,
            "plan_json": json.dumps(plan, sort_keys=True),
            "repository_commit": "b" * 40,
            "backup_sha256": "c" * 64,
        },
    )


def _seed_live_resume_orchestrator_state(
    SessionLocal,
    *,
    audit_kind: str = "matching",
    target_status: str = "RUNNING",
    include_packet_if_checkpoint: bool = False,
) -> dict[str, object]:
    boundary_before = BASE + timedelta(seconds=10)
    resume_boundary = BASE + timedelta(seconds=30)
    producer_cutoff = resume_boundary + timedelta(seconds=10)
    registry = build_stage_registry(
        enabled=[MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE, PACKET_RULE],
        required=[MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE, PACKET_RULE],
    )

    with SessionLocal() as db:
        for window_index in range(4):
            _insert_mqtt_log(
                db,
                received_at=BASE + timedelta(seconds=10 * window_index + 1),
            )
        previous_feature_id = _insert_processed_packet_window(
            db,
            packet_count=10,
            total_bytes=100,
        )
        target_feature_id = _insert_processed_packet_window(
            db,
            session_id=LIVE_RESUME_TARGET_SESSION_ID,
            window_start=resume_boundary,
            session_status=target_status,
            terminal_end_offset=(
                timedelta(seconds=1)
                if target_status == "COMPLETED"
                else timedelta(0)
            ),
            packet_count=980,
            total_bytes=9800,
        )
        db.commit()

    run_producer_cycle(
        session_factory=SessionLocal,
        now=producer_cutoff + timedelta(seconds=1),
    )
    initial = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=registry,
    )
    assert initial.status == CYCLE_COMPLETED
    assert initial.cutoff == boundary_before

    with SessionLocal() as db:
        packet_checkpoint = checkpoints.get_detector_checkpoint(
            db,
            detector_name=PACKET_RULE,
            source_table="packet_feature_logs",
        )
        assert packet_checkpoint is not None
        assert packet_checkpoint["last_processed_id"] == previous_feature_id
        checkpoints.upsert_detector_checkpoint(
            db,
            detector_name=PACKET_RULE,
            source_table="packet_feature_logs",
            last_processed_id=previous_feature_id,
            last_completed_window_end=resume_boundary,
            updated_at=resume_boundary,
        )
        if include_packet_if_checkpoint:
            checkpoints.upsert_detector_checkpoint(
                db,
                detector_name=PACKET_IF,
                source_table="packet_feature_logs",
                last_processed_id=previous_feature_id,
                last_completed_window_end=boundary_before,
                updated_at=boundary_before,
            )

        if audit_kind != "missing":
            audit_target = (
                PACKET_SESSION_ID
                if audit_kind == "target_mismatch"
                else LIVE_RESUME_TARGET_SESSION_ID
            )
            audit_boundary = (
                resume_boundary + timedelta(seconds=10)
                if audit_kind == "boundary_mismatch"
                else resume_boundary
            )
            audit_mode = "gap-recovery" if audit_kind == "mode_mismatch" else "live-resume"
            _insert_live_resume_recovery_audit(
                db,
                current_session_id=PACKET_SESSION_ID,
                target_session_id=audit_target,
                last_processed_id=(
                    previous_feature_id + 100
                    if audit_kind == "id_mismatch"
                    else previous_feature_id
                ),
                boundary_before=boundary_before,
                boundary_after=audit_boundary,
                mode=audit_mode,
                plan_sha_matches=audit_kind != "plan_sha_mismatch",
            )
        db.commit()

    return {
        "registry": registry,
        "boundary_before": boundary_before,
        "resume_boundary": resume_boundary,
        "producer_cutoff": producer_cutoff,
        "previous_feature_id": previous_feature_id,
        "target_feature_id": target_feature_id,
    }


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


@pytest.mark.parametrize("target_status", ("RUNNING", "COMPLETED"))
def test_live_resume_transition_catches_up_non_packet_and_trust_before_target_packet_session(
    SessionLocal,
    target_status: str,
):
    state = _seed_live_resume_orchestrator_state(
        SessionLocal,
        target_status=target_status,
    )
    registry = state["registry"]
    resume_boundary = state["resume_boundary"]

    catch_up = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=registry,
    )

    assert catch_up.status == CYCLE_COMPLETED
    assert catch_up.cutoff == resume_boundary
    assert {result.detector_name for result in catch_up.stage_results} == {
        MQTT_FEATURE_RULE,
        MQTT_MESSAGE_RULE,
    }
    with SessionLocal() as db:
        packet_after_catch_up = checkpoints.get_detector_checkpoint(
            db,
            detector_name=PACKET_RULE,
            source_table="packet_feature_logs",
        )
        assert packet_after_catch_up is not None
        assert packet_after_catch_up["last_processed_id"] == state["previous_feature_id"]
        assert packet_after_catch_up["last_completed_window_end"] == format_db_utc(
            resume_boundary
        )
        assert _completed(db, MQTT_FEATURE_RULE, "feature_logs") == resume_boundary
        assert _completed(db, MQTT_MESSAGE_RULE, "mqtt_logs") == resume_boundary
        assert _completed(
            db,
            TRUST_DETECTOR_NAME,
            TRUST_SOURCE_TABLE,
        ) == resume_boundary

    resumed = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=registry,
    )

    assert resumed.status == CYCLE_COMPLETED
    assert resumed.range_start == resume_boundary
    packet_result = next(
        result
        for result in resumed.stage_results
        if result.detector_name == PACKET_RULE
    )
    assert packet_result.capture_session_id == LIVE_RESUME_TARGET_SESSION_ID
    with SessionLocal() as db:
        packet_after_resume = checkpoints.get_detector_checkpoint(
            db,
            detector_name=PACKET_RULE,
            source_table="packet_feature_logs",
        )
        assert packet_after_resume is not None
        assert packet_after_resume["last_processed_id"] == state["target_feature_id"]
        assert _completed(
            db,
            PACKET_RULE,
            "packet_feature_logs",
        ) > resume_boundary


def test_live_resume_transition_requires_matching_recovery_audit(SessionLocal):
    state = _seed_live_resume_orchestrator_state(
        SessionLocal,
        audit_kind="missing",
    )

    outcome = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=state["registry"],
    )

    assert outcome.status == CYCLE_SKIPPED_NO_NEW_WINDOW
    with SessionLocal() as db:
        assert _completed(db, MQTT_FEATURE_RULE, "feature_logs") == state[
            "boundary_before"
        ]
        assert _completed(
            db,
            TRUST_DETECTOR_NAME,
            TRUST_SOURCE_TABLE,
        ) == state["boundary_before"]


@pytest.mark.parametrize(
    "audit_kind",
    (
        "target_mismatch",
        "boundary_mismatch",
        "mode_mismatch",
        "id_mismatch",
        "plan_sha_mismatch",
    ),
)
def test_live_resume_transition_rejects_mismatched_recovery_audit(
    SessionLocal,
    audit_kind: str,
):
    state = _seed_live_resume_orchestrator_state(
        SessionLocal,
        audit_kind=audit_kind,
    )

    outcome = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=state["registry"],
    )

    assert outcome.status == CYCLE_SKIPPED_NO_NEW_WINDOW
    with SessionLocal() as db:
        assert _completed(db, MQTT_FEATURE_RULE, "feature_logs") == state[
            "boundary_before"
        ]
        assert _completed(
            db,
            TRUST_DETECTOR_NAME,
            TRUST_SOURCE_TABLE,
        ) == state["boundary_before"]


@dataclass(frozen=True)
class PacketIfMustNotRunStage:
    detector_name: str = PACKET_IF
    source_table: str = "packet_feature_logs"

    def run_until(self, db, *, cycle_range_start, cycle_cutoff):
        raise AssertionError("mismatched required Packet IF must not run")


def _with_required_packet_if(registry: StageRegistry) -> StageRegistry:
    return StageRegistry(
        stages=registry.stages
        + (
            ConfiguredStage(
                name=PACKET_IF,
                stage=PacketIfMustNotRunStage(),
                required=True,
            ),
        )
    )


def _with_only_required_packet_if() -> StageRegistry:
    return StageRegistry(
        stages=(
            ConfiguredStage(
                name=PACKET_IF,
                stage=PacketIfMustNotRunStage(),
                required=True,
            ),
        )
    )


def _align_packet_if_and_add_audit(
    db,
    *,
    state: dict[str, object],
    audit_target: str = LIVE_RESUME_TARGET_SESSION_ID,
    audit_boundary: datetime | None = None,
) -> None:
    resume_boundary = state["resume_boundary"]
    previous_feature_id = state["previous_feature_id"]
    assert isinstance(resume_boundary, datetime)
    assert isinstance(previous_feature_id, int)
    checkpoints.upsert_detector_checkpoint(
        db,
        detector_name=PACKET_IF,
        source_table="packet_feature_logs",
        last_processed_id=previous_feature_id,
        last_completed_window_end=resume_boundary,
        updated_at=resume_boundary,
    )
    _insert_live_resume_recovery_audit(
        db,
        detector_name=PACKET_IF,
        current_session_id=PACKET_SESSION_ID,
        target_session_id=audit_target,
        last_processed_id=previous_feature_id,
        boundary_before=state["boundary_before"],
        boundary_after=audit_boundary or resume_boundary,
    )


def test_live_resume_transition_accepts_matching_audits_for_all_required_packet_stages(
    SessionLocal,
):
    state = _seed_live_resume_orchestrator_state(
        SessionLocal,
        include_packet_if_checkpoint=True,
    )
    registry = _with_required_packet_if(state["registry"])
    with SessionLocal() as db:
        _align_packet_if_and_add_audit(db, state=state)
        db.commit()

        transition = resolve_packet_live_resume_transition(
            db,
            registry=registry,
            range_start=state["boundary_before"],
            cutoff=state["producer_cutoff"],
        )

    assert transition is not None
    assert transition.boundary == state["resume_boundary"]
    assert transition.target_session_id == LIVE_RESUME_TARGET_SESSION_ID


def test_live_resume_transition_accepts_matching_packet_if_only_audit(SessionLocal):
    state = _seed_live_resume_orchestrator_state(
        SessionLocal,
        include_packet_if_checkpoint=True,
    )
    registry = _with_only_required_packet_if()
    with SessionLocal() as db:
        _align_packet_if_and_add_audit(db, state=state)
        db.commit()

        transition = resolve_packet_live_resume_transition(
            db,
            registry=registry,
            range_start=state["boundary_before"],
            cutoff=state["producer_cutoff"],
        )

    assert transition is not None
    assert transition.boundary == state["resume_boundary"]
    assert transition.target_session_id == LIVE_RESUME_TARGET_SESSION_ID


def test_live_resume_transition_rejects_missing_packet_if_audit(SessionLocal):
    state = _seed_live_resume_orchestrator_state(
        SessionLocal,
        include_packet_if_checkpoint=True,
    )
    registry = _with_required_packet_if(state["registry"])
    with SessionLocal() as db:
        resume_boundary = state["resume_boundary"]
        previous_feature_id = state["previous_feature_id"]
        checkpoints.upsert_detector_checkpoint(
            db,
            detector_name=PACKET_IF,
            source_table="packet_feature_logs",
            last_processed_id=previous_feature_id,
            last_completed_window_end=resume_boundary,
            updated_at=resume_boundary,
        )
        db.commit()

        transition = resolve_packet_live_resume_transition(
            db,
            registry=registry,
            range_start=state["boundary_before"],
            cutoff=state["producer_cutoff"],
        )

    assert transition is None


def test_live_resume_transition_rejects_packet_if_audit_target_mismatch(
    SessionLocal,
):
    state = _seed_live_resume_orchestrator_state(
        SessionLocal,
        include_packet_if_checkpoint=True,
    )
    registry = _with_required_packet_if(state["registry"])
    with SessionLocal() as db:
        _align_packet_if_and_add_audit(
            db,
            state=state,
            audit_target=PACKET_SESSION_ID,
        )
        db.commit()

        transition = resolve_packet_live_resume_transition(
            db,
            registry=registry,
            range_start=state["boundary_before"],
            cutoff=state["producer_cutoff"],
        )

    assert transition is None


def test_live_resume_transition_rejects_packet_if_audit_boundary_mismatch(
    SessionLocal,
):
    state = _seed_live_resume_orchestrator_state(
        SessionLocal,
        include_packet_if_checkpoint=True,
    )
    registry = _with_required_packet_if(state["registry"])
    with SessionLocal() as db:
        _align_packet_if_and_add_audit(
            db,
            state=state,
            audit_boundary=state["resume_boundary"] + timedelta(seconds=10),
        )
        db.commit()

        transition = resolve_packet_live_resume_transition(
            db,
            registry=registry,
            range_start=state["boundary_before"],
            cutoff=state["producer_cutoff"],
        )

    assert transition is None


def test_live_resume_transition_rejects_required_packet_boundary_mismatch(SessionLocal):
    state = _seed_live_resume_orchestrator_state(
        SessionLocal,
        include_packet_if_checkpoint=True,
    )
    base_registry = state["registry"]
    mismatched_registry = StageRegistry(
        stages=base_registry.stages
        + (
            ConfiguredStage(
                name=PACKET_IF,
                stage=PacketIfMustNotRunStage(),
                required=True,
            ),
        )
    )

    outcome = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=mismatched_registry,
    )

    assert outcome.status == CYCLE_SKIPPED_NO_NEW_WINDOW
    with SessionLocal() as db:
        assert _completed(db, PACKET_RULE, "packet_feature_logs") == state[
            "resume_boundary"
        ]
        assert _completed(db, PACKET_IF, "packet_feature_logs") == state[
            "boundary_before"
        ]
        assert _completed(db, MQTT_FEATURE_RULE, "feature_logs") == state[
            "boundary_before"
        ]


def test_live_resume_transition_rejects_failed_target_session(SessionLocal):
    state = _seed_live_resume_orchestrator_state(
        SessionLocal,
        target_status="FAILED",
    )

    outcome = run_orchestration_cycle(
        session_factory=SessionLocal,
        registry=state["registry"],
    )

    assert outcome.status == CYCLE_SKIPPED_NO_NEW_WINDOW
    with SessionLocal() as db:
        assert _completed(db, MQTT_FEATURE_RULE, "feature_logs") == state[
            "boundary_before"
        ]
        assert _completed(
            db,
            TRUST_DETECTOR_NAME,
            TRUST_SOURCE_TABLE,
        ) == state["boundary_before"]


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


@pytest.fixture
def restore_shutdown_handlers():
    previous = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT)}
    try:
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def test_shutdown_handler_avoids_logging_and_event_locks(
    monkeypatch, restore_shutdown_handlers,
):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("signal handlers must not acquire logging or Event locks")

    monkeypatch.setattr(runner.logger, "info", forbidden)
    monkeypatch.setattr(Event, "set", forbidden)
    shutdown = GracefulShutdown()
    shutdown.install()

    signal.raise_signal(signal.SIGTERM)

    assert shutdown.requested


def test_shutdown_wait_handles_signal_with_bounded_polling(
    monkeypatch, restore_shutdown_handlers,
):
    elapsed = [0.0]
    sleeps = []
    shutdown = GracefulShutdown()
    shutdown.install()

    def sleep(seconds):
        sleeps.append(seconds)
        elapsed[0] += seconds
        signal.raise_signal(signal.SIGTERM)

    monkeypatch.setattr(runner.time, "monotonic", lambda: elapsed[0])
    monkeypatch.setattr(runner.time, "sleep", sleep)

    assert shutdown.wait(60)
    assert sleeps == [0.1]


def test_shutdown_wait_respects_deadline_without_signal(monkeypatch):
    elapsed = [0.0]
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        elapsed[0] += seconds

    monkeypatch.setattr(runner.time, "monotonic", lambda: elapsed[0])
    monkeypatch.setattr(runner.time, "sleep", sleep)
    shutdown = GracefulShutdown()

    assert not shutdown.wait(0.25)
    assert sleeps == pytest.approx([0.1, 0.1, 0.05])
    assert not shutdown.wait(0)
    assert not shutdown.wait(-1)
    shutdown.request(signal.SIGTERM, None)
    assert shutdown.wait(0)


@pytest.mark.parametrize("signal_during", ["registry", "lock"])
def test_loop_sigterm_during_initialization_exits_cleanly_without_cycle(
    monkeypatch, registry, restore_shutdown_handlers, signal_during,
):
    events = []

    def unhandled_shutdown(_signum, _frame):
        raise AssertionError("loop shutdown handler must exist before initialization")

    signal.signal(signal.SIGTERM, unhandled_shutdown)

    def load_registry():
        events.append("registry")
        if signal_during == "registry":
            signal.raise_signal(signal.SIGTERM)
        return registry

    @contextmanager
    def acquire_lock(_path):
        events.append("locked")
        if signal_during == "lock":
            signal.raise_signal(signal.SIGTERM)
        try:
            yield
        finally:
            events.append("released")

    monkeypatch.setattr(runner, "configure_logging", lambda: None)
    monkeypatch.setattr(runner, "load_stage_registry", load_registry)
    monkeypatch.setattr(runner, "single_instance_lock", acquire_lock)
    monkeypatch.setattr(runner, "run_orchestration_cycle", lambda **_kwargs: events.append("cycle"))

    assert runner.main(["--loop", "--interval", "0.01"]) == 0
    assert events == ["registry", "locked", "released"]


def test_loop_sigterm_drains_current_cycle_and_returns_zero(
    monkeypatch, SessionLocal, registry, restore_shutdown_handlers,
):
    with SessionLocal() as db:
        _flood_window(db, window_index=0)
    run_producer_cycle(session_factory=SessionLocal, now=BASE + timedelta(seconds=11))
    calls = []
    feature_rule = registry.stages[0].stage
    original_stage = feature_rule.run_until

    def signal_in_stage(db, **kwargs):
        calls.append("feature-rule")
        signal.raise_signal(signal.SIGTERM)
        return original_stage(db, **kwargs)

    def run_cycle(**kwargs):
        calls.append("cycle")
        kwargs["session_factory"] = SessionLocal
        return run_orchestration_cycle(**kwargs)

    @contextmanager
    def acquire_lock(_path, **kwargs):
        if kwargs:
            with _lock(_path, **kwargs):
                yield
            return
        try:
            yield
        finally:
            calls.append("released")

    monkeypatch.setattr(feature_rule, "run_until", signal_in_stage)
    monkeypatch.setattr(runner, "configure_logging", lambda: None)
    monkeypatch.setattr(runner, "load_stage_registry", lambda: registry)
    monkeypatch.setattr(runner, "single_instance_lock", acquire_lock)
    monkeypatch.setattr(runner, "run_orchestration_cycle", run_cycle)

    assert runner.main(["--loop", "--interval", "60"]) == 0
    assert calls == ["cycle", "feature-rule", "released"]
    with SessionLocal() as db:
        cutoff = BASE + timedelta(seconds=10)
        assert _completed(db, MQTT_FEATURE_RULE, "feature_logs") == cutoff
        assert _completed(db, MQTT_MESSAGE_RULE, "mqtt_logs") == cutoff
        assert _completed(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE) == cutoff
        assert _scalar(db, "SELECT COUNT(*) FROM detection_events WHERE processed_at IS NULL") == 0
        assert _scalar(db, "SELECT trust_score FROM devices WHERE device_id='esp32_02'") == 80


@pytest.mark.parametrize("mode", ["--once", "--status"])
def test_non_loop_cli_does_not_install_shutdown_handlers(monkeypatch, registry, mode):
    calls = []

    def unexpected_install(_self):
        raise AssertionError("only the service loop owns shutdown handlers")

    @contextmanager
    def acquire_lock(_path):
        yield

    monkeypatch.setattr(GracefulShutdown, "install", unexpected_install)
    monkeypatch.setattr(runner, "configure_logging", lambda: None)
    monkeypatch.setattr(runner, "load_stage_registry", lambda: registry)
    monkeypatch.setattr(runner, "single_instance_lock", acquire_lock)
    monkeypatch.setattr(runner, "run_orchestration_cycle", lambda **_kwargs: calls.append("once"))
    monkeypatch.setattr(runner, "print_checkpoint_status", lambda: calls.append("status"))

    assert runner.main([mode]) == 0
    assert calls == [mode.removeprefix("--")]


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
    assert lines[0] == "trust_ai_mode=enforce"
    assert len(lines) == 8
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


@pytest.mark.parametrize("ai_mode", ["enforce", "observe"])
@pytest.mark.parametrize("packet_count", [2, 980])
def test_packet_rule_and_if_share_ready_session_and_reach_trust_once(
    SessionLocal,
    tmp_path: Path,
    monkeypatch,
    ai_mode,
    packet_count,
):
    from backend.app.config import settings
    monkeypatch.setattr(settings, "trust_ai_mode", ai_mode)
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
        packet_feature_id = _insert_processed_packet_window(db, packet_count=packet_count)
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
                SELECT dedupe_key, event_type, packet_feature_log_id,
                       applied_to_score, processing_reason, score_delta, processed_at, evidence_json
                FROM detection_events
                WHERE dedupe_key LIKE 'packet_rule:%'
                   OR dedupe_key LIKE 'packet_if:%'
                ORDER BY dedupe_key
                """
            )
        ).mappings().all()
        assert len(events) == (2 if packet_count == 980 else 1)
        packet_if_event = events[0]
        assert packet_if_event["dedupe_key"].startswith(
            f"packet_if:packet_feature_logs:{packet_feature_id}:"
            "AI_PACKET_ANOMALY:"
        )
        assert packet_if_event["event_type"] == "AI_PACKET_ANOMALY"
        assert packet_if_event["packet_feature_log_id"] == packet_feature_id
        assert packet_if_event["processed_at"] is not None
        if ai_mode == "observe":
            assert packet_if_event["processing_reason"] == "AI_OBSERVATION_ONLY"
            assert packet_if_event["applied_to_score"] == 0
            assert packet_if_event["score_delta"] == -15
            assert json.loads(packet_if_event["evidence_json"])["trust_decision"]["actual_delta"] == 0
        if packet_count == 980:
            packet_rule_event = events[1]
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
        expected_score = 80 if packet_count == 980 else (85 if ai_mode == "enforce" else 100)
        assert _scalar(db, "SELECT COUNT(*) FROM trust_score_history") == int(expected_score < 100)
        assert _scalar(
            db,
            f"SELECT trust_score FROM devices WHERE device_id = '{DEVICE_ID}'",
        ) == expected_score


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



def _sign_bounded_orchestrator_audit(SessionLocal, state, *, allow_failed_target=False):
    from edge.detection.packet_checkpoint_recovery import attach_plan_sha256
    from edge.detection.packet_checkpoint_recovery_repository import bounded_replay_target_evidence

    with SessionLocal() as db:
        target = db.execute(text("SELECT * FROM packet_capture_sessions WHERE session_id=:id"),
                            {"id": LIVE_RESUME_TARGET_SESSION_ID}).mappings().one()
        segments = list(db.execute(text("SELECT * FROM packet_capture_segments WHERE capture_session_id=:id ORDER BY window_start,id"),
                                   {"id": target["id"]}).mappings())
        features = list(db.execute(text("SELECT f.* FROM packet_feature_logs f JOIN packet_capture_segments g ON g.id=f.capture_segment_id "
                                       "WHERE g.capture_session_id=:id ORDER BY f.id"), {"id": target["id"]}).mappings())
        bound = bounded_replay_target_evidence(target, segments, features,
                                               allow_failed_target_session=allow_failed_target)
        bound["later_running_session"] = None
        plan = attach_plan_sha256({"mode": "bounded-replay", "bounded_replay": bound,
            **({"allow_failed_target_session": True, "failed_target_tail": bound["failed_target_tail"]}
               if allow_failed_target else {}),
            "detector_name": PACKET_RULE, "source_table": "packet_feature_logs",
            "current_session_id": PACKET_SESSION_ID, "target_session_id": LIVE_RESUME_TARGET_SESSION_ID,
            "sessions_between": [], "checkpoint": {
                "before": {"last_processed_id": state["previous_feature_id"], "last_completed_window_end": format_db_utc(state["boundary_before"])},
                "after": {"last_processed_id": state["previous_feature_id"], "last_completed_window_end": format_db_utc(state["resume_boundary"])}}}, generated_at=BASE)
        db.execute(text("UPDATE packet_checkpoint_recoveries SET plan_json=:plan,plan_sha256=:sha WHERE detector_name='packet_rule'"),
                   {"plan": json.dumps(plan, sort_keys=True), "sha": plan["plan_sha256"]})
        db.commit()
    return plan


def test_bounded_replay_audit_catches_up_then_consumes_closed_target_and_stops_before_later_session(SessionLocal):
    state = _seed_live_resume_orchestrator_state(SessionLocal, target_status="COMPLETED")
    _sign_bounded_orchestrator_audit(SessionLocal, state)
    with SessionLocal() as db:
        _insert_processed_packet_window(db, session_id="99999999-9999-4999-8999-999999999999",
                                       window_start=state["producer_cutoff"] + timedelta(days=1), session_status="RUNNING",
                                       packet_count=500, total_bytes=5000)
        db.commit()
    catchup = run_orchestration_cycle(session_factory=SessionLocal, registry=state["registry"])
    assert catchup.status == CYCLE_COMPLETED and catchup.cutoff == state["resume_boundary"]
    assert all(row.detector_name != PACKET_RULE for row in catchup.stage_results)
    replay = run_orchestration_cycle(session_factory=SessionLocal, registry=state["registry"])
    assert replay.status == CYCLE_COMPLETED and replay.cutoff == state["producer_cutoff"]
    packet = next(row for row in replay.stage_results if row.detector_name == PACKET_RULE)
    assert packet.capture_session_id == LIVE_RESUME_TARGET_SESSION_ID and packet.selected_count == 1
    with SessionLocal() as db:
        row = checkpoints.get_detector_checkpoint(db, detector_name=PACKET_RULE, source_table="packet_feature_logs")
        assert row["last_processed_id"] == state["target_feature_id"]
        assert _completed(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE) == state["producer_cutoff"]
    stopped = run_orchestration_cycle(session_factory=SessionLocal, registry=state["registry"])
    assert stopped.status == CYCLE_SKIPPED_NO_NEW_WINDOW


@pytest.mark.parametrize("mutation", ["unsigned", "wrong_end", "target_value", "missing_bound", "skipped_count"])
def test_bounded_replay_catchup_rejects_unsigned_changed_or_incomplete_closed_target_audit(SessionLocal, mutation):
    from edge.detection.packet_checkpoint_recovery import attach_plan_sha256
    state = _seed_live_resume_orchestrator_state(SessionLocal, target_status="COMPLETED")
    plan = _sign_bounded_orchestrator_audit(SessionLocal, state)
    with SessionLocal() as db:
        if mutation == "target_value":
            db.execute(text("UPDATE packet_feature_logs SET total_bytes=999 WHERE id=:id"), {"id": state["target_feature_id"]})
        elif mutation == "skipped_count":
            db.execute(text("UPDATE packet_checkpoint_recoveries SET skipped_session_count=1"))
        else:
            if mutation == "missing_bound":
                plan.pop("bounded_replay")
            else:
                plan["bounded_replay"]["replay_end"] = format_db_utc(state["producer_cutoff"] + timedelta(seconds=10))
            if mutation != "unsigned":
                plan = attach_plan_sha256(plan, generated_at=BASE)
            db.execute(text("UPDATE packet_checkpoint_recoveries SET plan_json=:plan,plan_sha256=:sha"),
                       {"plan": json.dumps(plan, sort_keys=True), "sha": plan["plan_sha256"]})
        db.commit()
    result = run_orchestration_cycle(session_factory=SessionLocal, registry=state["registry"])
    assert result.status == CYCLE_SKIPPED_NO_NEW_WINDOW
    with SessionLocal() as db:
        assert _completed(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE) == state["boundary_before"]



def test_bounded_replay_catchup_does_not_adopt_an_older_unapproved_range(SessionLocal):
    state = _seed_live_resume_orchestrator_state(SessionLocal, target_status="COMPLETED")
    _sign_bounded_orchestrator_audit(SessionLocal, state)
    with SessionLocal() as db:
        db.execute(text("UPDATE detector_checkpoints SET last_processed_id=NULL,last_completed_window_end=:start,updated_at=:start "
                        "WHERE detector_name=:detector AND source_table=:source"),
                   {"start": format_db_utc(BASE), "detector": TRUST_DETECTOR_NAME, "source": TRUST_SOURCE_TABLE})
        db.commit()
        transition = resolve_packet_live_resume_transition(db, registry=state["registry"], range_start=BASE,
                                                           cutoff=state["producer_cutoff"])
    assert transition is None


def _append_uncaptured_target_tail(SessionLocal, state):
    start = state["producer_cutoff"]
    end = start + timedelta(seconds=10)
    with SessionLocal() as db:
        db.execute(text("UPDATE packet_capture_sessions SET status='FAILED',ended_at=:ended WHERE session_id=:id"),
                   {"ended": format_db_utc(start + timedelta(seconds=1)), "id": LIVE_RESUME_TARGET_SESSION_ID})
        tail = db.execute(text("INSERT INTO packet_capture_segments (capture_session_id,file_name,capture_interface,"
                               "window_start,window_end,status,error_code,start_delay_seconds,captured_duration_seconds) "
                               "SELECT id,NULL,'eth0',:start,:end,'FAILED','LATE_CAPTURE',1.2,0 "
                               "FROM packet_capture_sessions WHERE session_id=:id"),
                          {"start": format_db_utc(start), "end": format_db_utc(end), "id": LIVE_RESUME_TARGET_SESSION_ID})
        db.commit()
        return int(tail.lastrowid)


def test_bounded_failed_target_prefix_consumes_actual_rows_and_keeps_tail_unapproved(SessionLocal):
    state = _seed_live_resume_orchestrator_state(SessionLocal, target_status="COMPLETED")
    tail_id = _append_uncaptured_target_tail(SessionLocal, state)
    _sign_bounded_orchestrator_audit(SessionLocal, state, allow_failed_target=True)
    with SessionLocal() as db:
        _insert_processed_packet_window(db, session_id="99999999-9999-4999-8999-999999999999",
                                       window_start=state["producer_cutoff"] + timedelta(seconds=10), session_status="RUNNING",
                                       packet_count=500, total_bytes=5000)
        tail_before = dict(db.execute(text("SELECT * FROM packet_capture_segments WHERE id=:id"), {"id": tail_id}).mappings().one())
        db.commit()
    catchup = run_orchestration_cycle(session_factory=SessionLocal, registry=state["registry"])
    assert catchup.status == CYCLE_COMPLETED and catchup.cutoff == state["resume_boundary"]
    replay = run_orchestration_cycle(session_factory=SessionLocal, registry=state["registry"])
    assert replay.status == CYCLE_COMPLETED and replay.cutoff == state["producer_cutoff"]
    packet = next(row for row in replay.stage_results if row.detector_name == PACKET_RULE)
    assert packet.selected_count == 1 and packet.capture_session_id == LIVE_RESUME_TARGET_SESSION_ID
    stopped = run_orchestration_cycle(session_factory=SessionLocal, registry=state["registry"])
    assert stopped.status == CYCLE_SKIPPED_NO_NEW_WINDOW
    with SessionLocal() as db:
        assert _completed(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE) == state["producer_cutoff"]
        assert dict(db.execute(text("SELECT * FROM packet_capture_segments WHERE id=:id"), {"id": tail_id}).mappings().one()) == tail_before
        assert db.execute(text("SELECT status FROM packet_capture_sessions WHERE session_id=:id"), {"id": LIVE_RESUME_TARGET_SESSION_ID}).scalar() == "FAILED"
        assert checkpoints.get_detector_checkpoint(db, detector_name=PACKET_RULE, source_table="packet_feature_logs")["last_processed_id"] == state["target_feature_id"]


@pytest.mark.parametrize("mutation", ["default", "unsigned", "nonbool", "outer_tail", "tail_captured", "prefix_value", "gap", "tail_feature"])
def test_bounded_failed_target_prefix_rejects_unapproved_or_changed_input(SessionLocal, mutation):
    from edge.detection.packet_checkpoint_recovery import attach_plan_sha256
    state = _seed_live_resume_orchestrator_state(SessionLocal, target_status="COMPLETED")
    tail_id = _append_uncaptured_target_tail(SessionLocal, state)
    plan = _sign_bounded_orchestrator_audit(SessionLocal, state, allow_failed_target=True)
    with SessionLocal() as db:
        if mutation == "tail_captured":
            db.execute(text("UPDATE packet_capture_segments SET file_name='unexpected.pcap',error_code='CAPTURE_FAILED' WHERE id=:id"), {"id": tail_id})
        elif mutation == "prefix_value":
            db.execute(text("UPDATE packet_feature_logs SET total_bytes=777 WHERE id=:id"), {"id": state["target_feature_id"]})
        elif mutation == "gap":
            db.execute(text("UPDATE packet_capture_segments SET window_start=:time,window_end=:end WHERE id=:id"),
                       {"time": format_db_utc(state["producer_cutoff"] + timedelta(seconds=10)),
                        "end": format_db_utc(state["producer_cutoff"] + timedelta(seconds=20)), "id": tail_id})
        elif mutation == "tail_feature":
            db.execute(text("UPDATE packet_feature_logs SET capture_segment_id=:tail WHERE id=:id"),
                       {"tail": tail_id, "id": state["target_feature_id"]})
        else:
            if mutation == "default":
                plan.pop("allow_failed_target_session")
            elif mutation == "nonbool":
                plan["allow_failed_target_session"] = 1
            else:
                plan["failed_target_tail"]["segment_id"] += 1
            if mutation != "unsigned":
                plan = attach_plan_sha256(plan, generated_at=BASE)
            db.execute(text("UPDATE packet_checkpoint_recoveries SET plan_json=:plan,plan_sha256=:sha"),
                       {"plan": json.dumps(plan,sort_keys=True), "sha": plan["plan_sha256"]})
        db.commit()
    result = run_orchestration_cycle(session_factory=SessionLocal, registry=state["registry"])
    assert result.status == CYCLE_SKIPPED_NO_NEW_WINDOW
    with SessionLocal() as db:
        assert _completed(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE) == state["boundary_before"]
