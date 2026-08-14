"""MQTT Feature Producer Runtime(P4-0-04) 테스트.

Runner의 책임은 "닫힌 Window만", "단일 Transaction", "재시작 후 정확히 한 번 재개"의
세 가지입니다. Feature 계산 자체는 collect_feature_logs 테스트가 담당합니다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.phase4_time import format_db_utc
from edge.features import collect_feature_logs
from edge.features.collect_feature_logs import MQTT_FEATURE_BUILDER, MQTT_LOGS_SOURCE
from edge.features.run_mqtt_feature_builder import (
    GracefulShutdown,
    ProducerBootstrapError,
    ProducerCheckpointMissingError,
    bootstrap_producer_checkpoint,
    compute_producer_cutoff,
    produce_once,
    producer_lock_path,
    run_producer_cycle,
    run_producer_loop,
)


DEVICE_ID = "esp32_01"
WINDOW_0_START = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
WINDOW_0_END = datetime(2026, 7, 25, 12, 0, 10, tzinfo=timezone.utc)
WINDOW_1_END = datetime(2026, 7, 25, 12, 0, 20, tzinfo=timezone.utc)


@pytest.fixture
def SessionLocal(tmp_path: Path):
    db_path = tmp_path / "phase4-mqtt-feature-builder.db"
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
        # Runtime은 Producer Checkpoint 없이는 실행을 거부한다. 신규 DB의 시작 시점을
        # WINDOW_0_START로 명시해 이후 Window만 처리 대상이 되게 한다.
        with db.begin():
            bootstrap_producer_checkpoint(db, now=WINDOW_0_START)
    try:
        yield TestingSessionLocal
    finally:
        engine.dispose()


def _insert_mqtt_log(db, *, received_at: datetime, device_id: str = DEVICE_ID) -> int:
    payload = f'{{"device_id":"{device_id}"}}'
    result = db.execute(
        text(
            """
            INSERT INTO mqtt_logs (
                device_id, topic, payload, payload_size,
                received_at, is_json_valid, is_topic_valid
            )
            VALUES (
                :device_id, :topic, :payload, :payload_size,
                :received_at, 1, 1
            )
            """
        ),
        {
            "device_id": device_id,
            "topic": f"iot/{device_id}/sensor",
            "payload": payload,
            "payload_size": len(payload),
            "received_at": format_db_utc(received_at),
        },
    )
    db.commit()
    return int(result.lastrowid)


def _feature_windows(db) -> list[tuple[str, str]]:
    rows = db.execute(
        text("SELECT window_start, window_end FROM feature_logs ORDER BY window_start")
    ).all()
    return [(row[0], row[1]) for row in rows]


def _checkpoint(db) -> dict | None:
    row = checkpoints.get_detector_checkpoint(
        db, detector_name=MQTT_FEATURE_BUILDER, source_table=MQTT_LOGS_SOURCE
    )
    return dict(row) if row is not None else None


# --- cutoff 계산 -----------------------------------------------------------


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (datetime(2026, 7, 25, 12, 0, 10, tzinfo=timezone.utc), WINDOW_0_END),
        (datetime(2026, 7, 25, 12, 0, 15, tzinfo=timezone.utc), WINDOW_0_END),
        (
            datetime(2026, 7, 25, 12, 0, 19, 999999, tzinfo=timezone.utc),
            WINDOW_0_END,
        ),
        (datetime(2026, 7, 25, 12, 0, 20, tzinfo=timezone.utc), WINDOW_1_END),
    ],
)
def test_compute_producer_cutoff_excludes_open_window(now, expected):
    assert compute_producer_cutoff(now) == expected


def test_compute_producer_cutoff_requires_timezone_aware_input():
    with pytest.raises(ValueError):
        compute_producer_cutoff(datetime(2026, 7, 25, 12, 0, 10))


# --- 닫힌 Window만 처리 ----------------------------------------------------


def test_open_window_source_is_not_turned_into_feature(SessionLocal):
    with SessionLocal() as db:
        # 12:00:12 메시지는 아직 열려 있는 [12:00:10, 12:00:20) Window에 속한다.
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 12, tzinfo=timezone.utc))

    result = run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 15, tzinfo=timezone.utc),
    )

    assert result is not None
    assert result.cutoff == WINDOW_0_END
    assert result.created_feature_count == 0
    with SessionLocal() as db:
        assert _feature_windows(db) == []
        assert _checkpoint(db)["last_completed_window_end"] == "2026-07-25T12:00:10Z"


def test_closed_window_source_becomes_feature(SessionLocal):
    with SessionLocal() as db:
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 3, tzinfo=timezone.utc))
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 8, tzinfo=timezone.utc))

    result = run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 11, tzinfo=timezone.utc),
    )

    assert result.created_feature_count == 1
    with SessionLocal() as db:
        assert _feature_windows(db) == [("2026-07-25T12:00:00Z", "2026-07-25T12:00:10Z")]
        checkpoint = _checkpoint(db)
        assert checkpoint["last_completed_window_end"] == "2026-07-25T12:00:10Z"
        assert checkpoint["last_processed_id"] == 2


# --- 빈 Window -------------------------------------------------------------


def test_empty_window_advances_checkpoint_without_feature_row(SessionLocal):
    result = run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 11, tzinfo=timezone.utc),
    )

    assert result.created_feature_count == 0
    assert result.selected_count == 0
    with SessionLocal() as db:
        assert _feature_windows(db) == []
        checkpoint = _checkpoint(db)
        assert checkpoint["last_completed_window_end"] == "2026-07-25T12:00:10Z"
        # Source Row가 없으면 last_processed_id는 유지한다.
        assert checkpoint["last_processed_id"] is None


def test_empty_window_keeps_existing_last_processed_id(SessionLocal):
    with SessionLocal() as db:
        source_id = _insert_mqtt_log(
            db, received_at=datetime(2026, 7, 25, 12, 0, 3, tzinfo=timezone.utc)
        )
    run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 11, tzinfo=timezone.utc),
    )

    # 다음 Window에는 메시지가 없다.
    run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 21, tzinfo=timezone.utc),
    )

    with SessionLocal() as db:
        checkpoint = _checkpoint(db)
        assert checkpoint["last_processed_id"] == source_id
        assert checkpoint["last_completed_window_end"] == "2026-07-25T12:00:20Z"


# --- 재시작·중복 실행 ------------------------------------------------------


def test_second_cycle_with_same_cutoff_is_a_no_op(SessionLocal):
    with SessionLocal() as db:
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 3, tzinfo=timezone.utc))
    now = datetime(2026, 7, 25, 12, 0, 11, tzinfo=timezone.utc)
    run_producer_cycle(session_factory=SessionLocal, now=now)

    assert run_producer_cycle(session_factory=SessionLocal, now=now) is None
    with SessionLocal() as db:
        assert len(_feature_windows(db)) == 1


def test_restart_resumes_after_checkpoint_without_duplicates(SessionLocal):
    with SessionLocal() as db:
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 3, tzinfo=timezone.utc))
    run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 11, tzinfo=timezone.utc),
    )

    # 재시작 후 다음 Window의 메시지가 들어온다.
    with SessionLocal() as db:
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 13, tzinfo=timezone.utc))
    result = run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 21, tzinfo=timezone.utc),
    )

    assert result.created_feature_count == 1
    with SessionLocal() as db:
        assert _feature_windows(db) == [
            ("2026-07-25T12:00:00Z", "2026-07-25T12:00:10Z"),
            ("2026-07-25T12:00:10Z", "2026-07-25T12:00:20Z"),
        ]


def test_late_source_does_not_reopen_completed_window(SessionLocal):
    with SessionLocal() as db:
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 3, tzinfo=timezone.utc))
    run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 11, tzinfo=timezone.utc),
    )

    # 이미 완료된 Window의 Source가 뒤늦게 도착한다.
    with SessionLocal() as db:
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 5, tzinfo=timezone.utc))
    result = run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 21, tzinfo=timezone.utc),
    )

    assert result.late_source_count == 1
    assert result.created_feature_count == 0
    with SessionLocal() as db:
        assert len(_feature_windows(db)) == 1


# --- Transaction -----------------------------------------------------------


def test_feature_insert_failure_rolls_back_checkpoint(SessionLocal, monkeypatch):
    with SessionLocal() as db:
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 3, tzinfo=timezone.utc))

    def _boom(*_args, **_kwargs):
        raise RuntimeError("insert failed")

    monkeypatch.setattr(collect_feature_logs, "_insert_feature_row", _boom)

    with pytest.raises(RuntimeError, match="insert failed"):
        run_producer_cycle(
            session_factory=SessionLocal,
            now=datetime(2026, 7, 25, 12, 0, 11, tzinfo=timezone.utc),
        )

    with SessionLocal() as db:
        assert _feature_windows(db) == []
        # Bootstrap 시점에서 전진하지 않았다.
        assert _checkpoint(db)["last_completed_window_end"] == "2026-07-25T12:00:00Z"


def test_checkpoint_and_feature_are_committed_together(SessionLocal):
    with SessionLocal() as db:
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 3, tzinfo=timezone.utc))
    run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 11, tzinfo=timezone.utc),
    )

    with SessionLocal() as db:
        assert len(_feature_windows(db)) == 1
        assert _checkpoint(db) is not None


def test_produce_once_returns_none_when_no_new_closed_window(SessionLocal):
    now = datetime(2026, 7, 25, 12, 0, 11, tzinfo=timezone.utc)
    with SessionLocal() as db:
        with db.begin():
            assert produce_once(db, now=now) is not None
    with SessionLocal() as db:
        with db.begin():
            assert produce_once(db, now=now) is None


# --- Loop ------------------------------------------------------------------


def test_run_producer_loop_stops_after_max_cycles(SessionLocal):
    shutdown = GracefulShutdown()
    clock_values = iter(
        [
            datetime(2026, 7, 25, 12, 0, 11, tzinfo=timezone.utc),
            datetime(2026, 7, 25, 12, 0, 21, tzinfo=timezone.utc),
        ]
    )

    completed = run_producer_loop(
        shutdown=shutdown,
        interval_seconds=0.01,
        session_factory=SessionLocal,
        max_cycles=2,
        clock=lambda: next(clock_values),
    )

    assert completed == 2
    with SessionLocal() as db:
        assert _checkpoint(db)["last_completed_window_end"] == "2026-07-25T12:00:20Z"


def test_run_producer_loop_exits_immediately_when_shutdown_requested(SessionLocal):
    shutdown = GracefulShutdown()
    shutdown.request(15, None)

    completed = run_producer_loop(
        shutdown=shutdown,
        interval_seconds=0.01,
        session_factory=SessionLocal,
        max_cycles=5,
    )

    assert completed == 0
    with SessionLocal() as db:
        assert _checkpoint(db)["last_completed_window_end"] == "2026-07-25T12:00:00Z"


@pytest.mark.parametrize("invalid", [0, -1])
def test_run_producer_loop_rejects_invalid_max_cycles(SessionLocal, invalid):
    with pytest.raises(ValueError):
        run_producer_loop(
            shutdown=GracefulShutdown(),
            interval_seconds=1.0,
            session_factory=SessionLocal,
            max_cycles=invalid,
        )


def test_run_producer_loop_rejects_non_positive_interval(SessionLocal):
    with pytest.raises(ValueError):
        run_producer_loop(
            shutdown=GracefulShutdown(),
            interval_seconds=0,
            session_factory=SessionLocal,
        )


def test_multiple_devices_share_one_cycle(SessionLocal):
    with SessionLocal() as db:
        db.execute(
            text(
                """
                INSERT INTO devices (device_id, ip_address, trust_score, status)
                VALUES ('esp32_02', '192.168.0.5', 100, 'normal')
                """
            )
        )
        db.commit()
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 3, tzinfo=timezone.utc))
        _insert_mqtt_log(
            db,
            received_at=datetime(2026, 7, 25, 12, 0, 4, tzinfo=timezone.utc),
            device_id="esp32_02",
        )

    result = run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 11, tzinfo=timezone.utc),
    )

    assert result.created_feature_count == 2


def test_cutoff_advances_across_multiple_closed_windows_in_one_cycle(SessionLocal):
    with SessionLocal() as db:
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 3, tzinfo=timezone.utc))
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 13, tzinfo=timezone.utc))

    # 서비스가 잠시 멈췄다가 두 Window가 닫힌 뒤 한 번에 재개된 상황
    result = run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 25, tzinfo=timezone.utc),
    )

    assert result.created_feature_count == 2
    with SessionLocal() as db:
        assert _checkpoint(db)["last_completed_window_end"] == "2026-07-25T12:00:20Z"
        assert _feature_windows(db) == [
            ("2026-07-25T12:00:00Z", "2026-07-25T12:00:10Z"),
            ("2026-07-25T12:00:10Z", "2026-07-25T12:00:20Z"),
        ]


def test_isolated_device_source_is_skipped(SessionLocal):
    with SessionLocal() as db:
        db.execute(
            text("UPDATE devices SET status = 'isolated' WHERE device_id = :device_id"),
            {"device_id": DEVICE_ID},
        )
        db.commit()
        _insert_mqtt_log(db, received_at=datetime(2026, 7, 25, 12, 0, 3, tzinfo=timezone.utc))

    result = run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 11, tzinfo=timezone.utc),
    )

    # 격리된 Device는 Feature를 만들지 않지만 Window 완료는 전진해야 한다.
    assert result.created_feature_count == 0
    with SessionLocal() as db:
        assert _checkpoint(db)["last_completed_window_end"] == "2026-07-25T12:00:10Z"


def test_checkpoint_updated_at_matches_cutoff(SessionLocal):
    run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 11, tzinfo=timezone.utc),
    )
    with SessionLocal() as db:
        checkpoint = _checkpoint(db)
    assert checkpoint["updated_at"] == "2026-07-25T12:00:10Z"


def test_next_cycle_only_processes_windows_after_checkpoint(SessionLocal):
    with SessionLocal() as db:
        first_id = _insert_mqtt_log(
            db, received_at=datetime(2026, 7, 25, 12, 0, 3, tzinfo=timezone.utc)
        )
    run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 11, tzinfo=timezone.utc),
    )

    with SessionLocal() as db:
        second_id = _insert_mqtt_log(
            db, received_at=datetime(2026, 7, 25, 12, 0, 13, tzinfo=timezone.utc)
        )
    result = run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 21, tzinfo=timezone.utc),
    )

    assert result.last_processed_id_before == first_id
    assert result.last_processed_id_after == second_id
    assert result.selected_count == 1


def test_producer_result_reports_window_boundaries(SessionLocal):
    result = run_producer_cycle(
        session_factory=SessionLocal,
        now=datetime(2026, 7, 25, 12, 0, 31, tzinfo=timezone.utc),
    )
    assert result.completed_window_end_before == WINDOW_0_START
    assert result.completed_window_end_after == WINDOW_0_END + timedelta(seconds=20)
