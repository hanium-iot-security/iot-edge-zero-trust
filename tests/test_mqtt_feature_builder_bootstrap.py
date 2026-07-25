"""MQTT Feature Producer의 Bootstrap 가드·중복 실행 방지 테스트.

Checkpoint가 없는 상태에서 Runtime을 그냥 실행하면 시작점이 "처음부터 전부"가 되어
기존 운영 DB의 과거 `mqtt_logs`가 모두 Phase 4 Feature로 다시 만들어집니다. 기존 MVP
Feature는 공백 형식 Timestamp, Phase 4는 ISO 형식이라
`UNIQUE(device_id, window_start, window_end)`가 같은 Window를 다른 문자열로 보고 중복
Row를 허용합니다. 그래서 시작점은 반드시 명시적으로 정해져야 합니다.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.phase4_time import format_db_utc
from edge.features import collect_feature_logs
from edge.features.collect_feature_logs import (
    MQTT_FEATURE_BUILDER,
    MQTT_LOGS_SOURCE,
    phase4_producer_checkpoint_exists,
)
from edge.features.run_mqtt_feature_builder import (
    GracefulShutdown,
    ProducerBootstrapError,
    ProducerCheckpointMissingError,
    bootstrap_producer_checkpoint,
    produce_once,
    producer_lock_path,
    run_producer_cycle,
    run_producer_loop,
)
from edge.runtime_lock import RuntimeLockError, single_instance_lock


DEVICE_ID = "esp32_01"
WINDOW_0_START = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
NOW = datetime(2026, 7, 25, 12, 0, 11, tzinfo=timezone.utc)


@pytest.fixture
def SessionLocal(tmp_path: Path):
    """Bootstrap하지 않은 상태의 DB입니다."""
    db_path = tmp_path / "phase4-producer-bootstrap.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    with TestingSessionLocal() as db:
        db.execute(
            text(
                """
                INSERT INTO devices (device_id, ip_address, trust_score, status)
                VALUES (:device_id, '192.168.0.4', 100, 'normal')
                """
            ),
            {"device_id": DEVICE_ID},
        )
        db.commit()
    try:
        yield TestingSessionLocal
    finally:
        engine.dispose()


def _insert_mqtt_log(db, *, received_at: datetime) -> None:
    db.execute(
        text(
            """
            INSERT INTO mqtt_logs (
                device_id, topic, payload, payload_size,
                received_at, is_json_valid, is_topic_valid
            )
            VALUES (
                :device_id, 'iot/esp32_01/sensor', '{"device_id":"esp32_01"}', 26,
                :received_at, 1, 1
            )
            """
        ),
        {"device_id": DEVICE_ID, "received_at": format_db_utc(received_at)},
    )
    db.commit()


def _insert_legacy_feature(db, *, window_start: str, window_end: str) -> None:
    """MVP 시절 공백 형식 Timestamp로 저장된 Feature Row입니다."""
    db.execute(
        text(
            """
            INSERT INTO feature_logs (
                device_id, window_start, window_end, publish_count,
                avg_payload_size, max_payload_size, avg_message_interval,
                min_message_interval, topic_count, abnormal_topic_count,
                malformed_payload_count
            )
            VALUES (:device_id, :window_start, :window_end, 2, 26, 26, 5.0, 5.0, 1, 0, 0)
            """
        ),
        {"device_id": DEVICE_ID, "window_start": window_start, "window_end": window_end},
    )
    db.commit()


def _feature_count(db) -> int:
    return int(db.execute(text("SELECT COUNT(*) FROM feature_logs")).scalar())


# --- Checkpoint 가드 -------------------------------------------------------


def test_runtime_refuses_to_run_without_checkpoint(SessionLocal):
    with SessionLocal() as db:
        _insert_mqtt_log(db, received_at=WINDOW_0_START)

    with pytest.raises(ProducerCheckpointMissingError, match="Checkpoint가 없습니다"):
        run_producer_cycle(session_factory=SessionLocal, now=NOW)

    with SessionLocal() as db:
        assert _feature_count(db) == 0


def test_runtime_refuses_even_on_empty_database_without_checkpoint(SessionLocal):
    with pytest.raises(ProducerCheckpointMissingError):
        run_producer_cycle(session_factory=SessionLocal, now=NOW)


def test_error_message_points_to_bootstrap_and_cutover(SessionLocal):
    with SessionLocal() as db:
        with db.begin():
            with pytest.raises(ProducerCheckpointMissingError) as exc_info:
                produce_once(db, now=NOW)
    message = str(exc_info.value)
    assert "--bootstrap" in message
    assert "run_phase4_cutover.py" in message


def test_legacy_and_phase4_timestamp_formats_would_duplicate_a_window(SessionLocal):
    """가드가 왜 필요한지 보여준다: 같은 Window가 형식만 달라 UNIQUE를 통과한다."""
    with SessionLocal() as db:
        _insert_legacy_feature(
            db, window_start="2026-07-25 12:00:00", window_end="2026-07-25 12:00:10"
        )
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 3, tzinfo=timezone.utc))
        # Bootstrap을 과거 시점으로 강제하면 그 Window가 다시 처리된다.
        with db.begin():
            checkpoints.upsert_detector_checkpoint(
                db,
                detector_name=MQTT_FEATURE_BUILDER,
                source_table=MQTT_LOGS_SOURCE,
                last_processed_id=None,
                last_completed_window_end=WINDOW_0_START,
                updated_at=WINDOW_0_START,
            )

    run_producer_cycle(session_factory=SessionLocal, now=NOW)

    with SessionLocal() as db:
        rows = db.execute(
            text("SELECT window_start FROM feature_logs ORDER BY id")
        ).scalars().all()
    assert rows == ["2026-07-25 12:00:00", "2026-07-25T12:00:00Z"]


# --- Bootstrap -------------------------------------------------------------


def test_bootstrap_on_empty_database_sets_start_point(SessionLocal):
    with SessionLocal() as db:
        with db.begin():
            cutoff = bootstrap_producer_checkpoint(db, now=NOW)

    assert cutoff == datetime(2026, 7, 25, 12, 0, 10, tzinfo=timezone.utc)
    with SessionLocal() as db:
        row = checkpoints.get_detector_checkpoint(
            db, detector_name=MQTT_FEATURE_BUILDER, source_table=MQTT_LOGS_SOURCE
        )
        assert row["last_completed_window_end"] == "2026-07-25T12:00:10Z"
        assert row["last_processed_id"] is None


def test_bootstrap_refuses_when_source_rows_already_exist(SessionLocal):
    with SessionLocal() as db:
        _insert_mqtt_log(db, received_at=WINDOW_0_START)
        with pytest.raises(ProducerBootstrapError, match="run_phase4_cutover.py"):
            with db.begin():
                bootstrap_producer_checkpoint(db, now=NOW)


def test_bootstrap_can_skip_existing_source_when_explicitly_allowed(SessionLocal):
    with SessionLocal() as db:
        _insert_mqtt_log(db, received_at=WINDOW_0_START)
        with db.begin():
            cutoff = bootstrap_producer_checkpoint(db, now=NOW, allow_existing_source=True)
    assert cutoff == datetime(2026, 7, 25, 12, 0, 10, tzinfo=timezone.utc)

    # 과거 Window는 건너뛴 것으로 처리되어 Feature가 만들어지지 않는다.
    assert run_producer_cycle(session_factory=SessionLocal, now=NOW) is None
    with SessionLocal() as db:
        assert _feature_count(db) == 0


def test_bootstrap_refuses_when_checkpoint_already_exists(SessionLocal):
    with SessionLocal() as db:
        with db.begin():
            bootstrap_producer_checkpoint(db, now=NOW)
    with SessionLocal() as db:
        with pytest.raises(ProducerBootstrapError, match="이미 있습니다"):
            with db.begin():
                bootstrap_producer_checkpoint(db, now=NOW)


def test_runtime_works_after_bootstrap(SessionLocal):
    with SessionLocal() as db:
        with db.begin():
            bootstrap_producer_checkpoint(db, now=WINDOW_0_START)
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 3, tzinfo=timezone.utc))

    result = run_producer_cycle(session_factory=SessionLocal, now=NOW)

    assert result is not None
    assert result.created_feature_count == 1


# --- 중복 실행 방지 --------------------------------------------------------


def test_second_producer_instance_is_rejected(tmp_path: Path):
    lock_path = tmp_path / "producer.lock"
    with single_instance_lock(lock_path):
        with pytest.raises(RuntimeLockError):
            with single_instance_lock(lock_path):
                pass


def test_producer_lock_path_defaults_next_to_database_file():
    assert producer_lock_path().name.endswith(".mqtt-feature-builder.lock")


# --- 기존 CLI 차단 ---------------------------------------------------------


def test_legacy_cli_detects_phase4_producer(SessionLocal):
    with SessionLocal() as db:
        assert phase4_producer_checkpoint_exists(db) is False

    with SessionLocal() as db:
        with db.begin():
            bootstrap_producer_checkpoint(db, now=NOW)

    with SessionLocal() as db:
        assert phase4_producer_checkpoint_exists(db) is True


def test_legacy_cli_exits_when_phase4_checkpoint_exists(SessionLocal, monkeypatch):
    with SessionLocal() as db:
        with db.begin():
            bootstrap_producer_checkpoint(db, now=NOW)

    monkeypatch.setattr(collect_feature_logs, "SessionLocal", SessionLocal)
    monkeypatch.setattr("sys.argv", ["collect_feature_logs"])

    with pytest.raises(SystemExit, match="run_mqtt_feature_builder"):
        collect_feature_logs.main()


def test_legacy_cli_still_runs_before_cutover(SessionLocal, monkeypatch):
    monkeypatch.setattr(collect_feature_logs, "SessionLocal", SessionLocal)
    monkeypatch.setattr("sys.argv", ["collect_feature_logs"])

    # Checkpoint가 없으면 MVP 호환 경로는 그대로 동작한다.
    collect_feature_logs.main()


def test_producer_loop_requires_checkpoint(SessionLocal):
    with pytest.raises(ProducerCheckpointMissingError):
        run_producer_loop(
            shutdown=GracefulShutdown(),
            interval_seconds=0.01,
            session_factory=SessionLocal,
            max_cycles=1,
        )
