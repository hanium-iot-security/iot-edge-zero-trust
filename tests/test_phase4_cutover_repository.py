from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3

import pytest

from db.migration_runner import MIGRATIONS_DIR, apply_migrations, connect_database
from edge.detection import checkpoint_repository
from edge.detection.phase4_cutover_repository import (
    LEGACY_MIGRATION_REASON,
    initialize_phase4_cutover,
)


CUTOVER_AT = datetime(2026, 7, 21, 4, 30, 0, tzinfo=timezone.utc)
SESSION_A = "11111111-1111-4111-8111-111111111111"
SESSION_B = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def migrated_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "phase4-cutover.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    return db_path


def test_checkpoint_repository_upsert_is_caller_transaction_controlled(
    migrated_db: Path,
) -> None:
    with connect_database(migrated_db) as connection:
        connection.execute("BEGIN;")
        checkpoint_repository.upsert_detector_checkpoint(
            connection,
            detector_name="mqtt_feature_rule",
            source_table="feature_logs",
            last_processed_id=10,
            last_completed_window_end=CUTOVER_AT,
            updated_at=CUTOVER_AT,
        )
        connection.execute("ROLLBACK;")

        assert checkpoint_repository.get_detector_checkpoint(
            connection,
            detector_name="mqtt_feature_rule",
            source_table="feature_logs",
        ) is None


def test_checkpoint_repository_rejects_invalid_values(migrated_db: Path) -> None:
    with connect_database(migrated_db) as connection:
        with pytest.raises(ValueError, match="last_processed_id"):
            checkpoint_repository.upsert_detector_checkpoint(
                connection,
                detector_name="mqtt_feature_rule",
                source_table="feature_logs",
                last_processed_id=-1,
                last_completed_window_end=None,
                updated_at=CUTOVER_AT,
            )
        with pytest.raises(ValueError, match="timezone-aware"):
            checkpoint_repository.upsert_detector_checkpoint(
                connection,
                detector_name="mqtt_feature_rule",
                source_table="feature_logs",
                last_processed_id=None,
                last_completed_window_end=datetime(2026, 7, 21, 4, 30, 0),
                updated_at=CUTOVER_AT,
            )


def test_initialize_phase4_cutover_rejects_invalid_inputs(tmp_path: Path) -> None:
    missing_db = tmp_path / "missing.db"
    with pytest.raises(FileNotFoundError):
        initialize_phase4_cutover(missing_db, CUTOVER_AT)

    db_path = tmp_path / "valid.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    with pytest.raises(ValueError, match="timezone-aware UTC"):
        initialize_phase4_cutover(db_path, datetime(2026, 7, 21, 4, 30, 0))
    with pytest.raises(ValueError, match="UTC offset"):
        initialize_phase4_cutover(
            db_path,
            datetime.fromisoformat("2026-07-21T13:30:00+09:00"),
        )
    with pytest.raises(ValueError, match="whole-second precision"):
        initialize_phase4_cutover(
            db_path,
            datetime(2026, 7, 21, 4, 30, 0, 1000, tzinfo=timezone.utc),
        )


def test_initialize_phase4_cutover_empty_db_returns_exact_seven_keys(
    migrated_db: Path,
) -> None:
    summary = initialize_phase4_cutover(migrated_db, CUTOVER_AT)

    assert summary["legacy_migration_event_count"] == 0
    assert set(summary["checkpoints"]) == {
        checkpoint_repository.checkpoint_summary_key(detector_name, source_table)
        for detector_name, source_table in checkpoint_repository.PHASE4_CHECKPOINT_KEYS
    }
    for checkpoint in summary["checkpoints"].values():
        assert checkpoint == {
            "last_processed_id": None,
            "last_completed_window_end": None,
        }

    with connect_database(migrated_db) as connection:
        stored_summary = checkpoint_repository.list_phase4_checkpoint_summary(connection)
        assert stored_summary == summary["checkpoints"]
        assert connection.execute(
            "SELECT COUNT(*) AS count FROM detector_checkpoints"
        ).fetchone()["count"] == 7


def test_initialize_phase4_cutover_marks_legacy_events_once_and_preserves_fields(
    migrated_db: Path,
) -> None:
    with connect_database(migrated_db) as connection:
        before_id = _insert_detection_event(
            connection,
            event_type="ABNORMAL_TOPIC",
            score_delta=-20,
            applied_to_score=0,
            detected_at="2026-07-21T04:29:59Z",
        )
        after_id = _insert_detection_event(
            connection,
            event_type="AI_ANOMALY",
            score_delta=-15,
            applied_to_score=0,
            detected_at="2026-07-21T04:30:00Z",
        )

    first_summary = initialize_phase4_cutover(migrated_db, CUTOVER_AT)
    second_summary = initialize_phase4_cutover(migrated_db, CUTOVER_AT)

    assert first_summary["legacy_migration_event_count"] == 1
    assert second_summary["legacy_migration_event_count"] == 0
    trust_checkpoint = first_summary["checkpoints"]["trust_score_v2+detection_events"]
    assert trust_checkpoint == {
        "last_processed_id": before_id,
        "last_completed_window_end": "2026-07-21T04:30:00Z",
    }

    with connect_database(migrated_db) as connection:
        before_event = connection.execute(
            """
            SELECT id, event_type, score_delta, applied_to_score,
                   processed_at, processing_reason
            FROM detection_events
            WHERE id = ?
            """,
            (before_id,),
        ).fetchone()
        after_event = connection.execute(
            """
            SELECT id, processed_at, processing_reason
            FROM detection_events
            WHERE id = ?
            """,
            (after_id,),
        ).fetchone()
        assert before_event["event_type"] == "ABNORMAL_TOPIC"
        assert before_event["score_delta"] == -20
        assert before_event["applied_to_score"] == 0
        assert before_event["processed_at"] == "2026-07-21T04:30:00Z"
        assert before_event["processing_reason"] == LEGACY_MIGRATION_REASON
        assert after_event["processed_at"] is None
        assert after_event["processing_reason"] is None


def test_initialize_phase4_cutover_uses_existing_mqtt_watermark(
    migrated_db: Path,
) -> None:
    with connect_database(migrated_db) as connection:
        _insert_mqtt_log(connection, received_at="2026-07-21T04:29:58Z")
        included_mqtt_id = _insert_mqtt_log(connection, received_at="2026-07-21T04:29:59Z")
        _insert_mqtt_log(connection, received_at="2026-07-21T04:30:00Z")
        _insert_feature_log(
            connection,
            window_start="2026-07-21T04:29:40Z",
            window_end="2026-07-21T04:29:50Z",
        )
        included_feature_id = _insert_feature_log(
            connection,
            window_start="2026-07-21T04:29:50Z",
            window_end="2026-07-21T04:30:00Z",
        )
        _insert_feature_log(
            connection,
            window_start="2026-07-21T04:30:00Z",
            window_end="2026-07-21T04:30:10Z",
        )
        checkpoint_repository.upsert_detector_checkpoint(
            connection,
            detector_name="mqtt_feature_builder",
            source_table="mqtt_logs",
            last_processed_id=None,
            last_completed_window_end=CUTOVER_AT,
            updated_at=CUTOVER_AT,
        )

    summary = initialize_phase4_cutover(migrated_db, CUTOVER_AT)
    checkpoints = summary["checkpoints"]
    assert checkpoints["mqtt_feature_builder+mqtt_logs"] == {
        "last_processed_id": included_mqtt_id,
        "last_completed_window_end": "2026-07-21T04:30:00Z",
    }
    assert checkpoints["mqtt_message_rule+mqtt_logs"] == {
        "last_processed_id": included_mqtt_id,
        "last_completed_window_end": "2026-07-21T04:30:00Z",
    }
    assert checkpoints["mqtt_feature_rule+feature_logs"] == {
        "last_processed_id": included_feature_id,
        "last_completed_window_end": "2026-07-21T04:30:00Z",
    }
    assert checkpoints["mqtt_if+feature_logs"] == {
        "last_processed_id": included_feature_id,
        "last_completed_window_end": "2026-07-21T04:30:00Z",
    }


def test_initialize_phase4_cutover_rejects_mqtt_watermark_after_cutover(
    migrated_db: Path,
) -> None:
    with connect_database(migrated_db) as connection:
        event_id = _insert_detection_event(
            connection,
            event_type="ABNORMAL_TOPIC",
            score_delta=-20,
            applied_to_score=0,
            detected_at="2026-07-21T04:29:59Z",
        )
        checkpoint_repository.upsert_detector_checkpoint(
            connection,
            detector_name="mqtt_feature_builder",
            source_table="mqtt_logs",
            last_processed_id=1,
            last_completed_window_end=datetime(
                2026, 7, 21, 4, 30, 10, tzinfo=timezone.utc
            ),
            updated_at=CUTOVER_AT,
        )

    with pytest.raises(ValueError, match="mqtt producer watermark"):
        initialize_phase4_cutover(migrated_db, CUTOVER_AT)

    with connect_database(migrated_db) as connection:
        event = connection.execute(
            """
            SELECT processed_at, processing_reason
            FROM detection_events
            WHERE id = ?
            """,
            (event_id,),
        ).fetchone()
        assert event["processed_at"] is None
        assert event["processing_reason"] is None


def test_initialize_phase4_cutover_packet_prefix_stops_at_ready_or_failed(
    migrated_db: Path,
) -> None:
    packet_cutover_at = datetime(2026, 7, 21, 4, 30, 20, tzinfo=timezone.utc)
    with connect_database(migrated_db) as connection:
        session_a_pk = _insert_packet_session(
            connection,
            session_id=SESSION_A,
            first_window_start="2026-07-21T04:30:00Z",
        )
        processed_segment_id = _insert_packet_segment(
            connection,
            capture_session_id=session_a_pk,
            file_name="processed.pcap",
            window_start="2026-07-21T04:30:00Z",
            window_end="2026-07-21T04:30:10Z",
            status="PROCESSED",
        )
        _insert_packet_segment(
            connection,
            capture_session_id=session_a_pk,
            file_name="empty.pcap",
            window_start="2026-07-21T04:30:10Z",
            window_end="2026-07-21T04:30:20Z",
            status="EMPTY",
        )
        ready_segment_id = _insert_packet_segment(
            connection,
            capture_session_id=session_a_pk,
            file_name="ready.pcap",
            window_start="2026-07-21T04:30:20Z",
            window_end="2026-07-21T04:30:30Z",
            status="READY",
        )
        included_feature_id = _insert_packet_feature(
            connection,
            capture_segment_id=processed_segment_id,
            peer_ip="10.0.0.8",
            window_start="2026-07-21T04:30:00Z",
            window_end="2026-07-21T04:30:10Z",
        )
        _insert_packet_feature(
            connection,
            capture_segment_id=ready_segment_id,
            peer_ip="10.0.0.9",
            window_start="2026-07-21T04:30:20Z",
            window_end="2026-07-21T04:30:30Z",
        )

        session_b_pk = _insert_packet_session(
            connection,
            session_id=SESSION_B,
            capture_interface="eth1",
            first_window_start="2026-07-21T04:31:00Z",
        )
        _insert_packet_segment(
            connection,
            capture_session_id=session_b_pk,
            file_name="failed.pcap",
            capture_interface="eth1",
            window_start="2026-07-21T04:31:00Z",
            window_end="2026-07-21T04:31:10Z",
            status="FAILED",
        )

    summary = initialize_phase4_cutover(migrated_db, packet_cutover_at)

    for key in ("packet_rule+packet_feature_logs", "packet_if+packet_feature_logs"):
        assert summary["checkpoints"][key] == {
            "last_processed_id": included_feature_id,
            "last_completed_window_end": "2026-07-21T04:30:20Z",
        }


def test_initialize_phase4_cutover_rejects_completed_packet_after_cutover(
    migrated_db: Path,
) -> None:
    with connect_database(migrated_db) as connection:
        event_id = _insert_detection_event(
            connection,
            event_type="ABNORMAL_TOPIC",
            score_delta=-20,
            applied_to_score=0,
            detected_at="2026-07-21T04:29:59Z",
        )
        session_pk = _insert_packet_session(
            connection,
            session_id=SESSION_A,
            first_window_start="2026-07-21T04:29:50Z",
        )
        _insert_packet_segment(
            connection,
            capture_session_id=session_pk,
            file_name="before-cutover.pcap",
            window_start="2026-07-21T04:29:50Z",
            window_end="2026-07-21T04:30:00Z",
            status="PROCESSED",
        )
        _insert_packet_segment(
            connection,
            capture_session_id=session_pk,
            file_name="after-cutover.pcap",
            window_start="2026-07-21T04:30:00Z",
            window_end="2026-07-21T04:30:10Z",
            status="EMPTY",
        )

    with pytest.raises(ValueError, match="packet completed watermark"):
        initialize_phase4_cutover(migrated_db, CUTOVER_AT)

    with connect_database(migrated_db) as connection:
        assert connection.execute(
            "SELECT COUNT(*) AS count FROM detector_checkpoints"
        ).fetchone()["count"] == 0
        event = connection.execute(
            """
            SELECT processed_at, processing_reason
            FROM detection_events
            WHERE id = ?
            """,
            (event_id,),
        ).fetchone()
        assert event["processed_at"] is None
        assert event["processing_reason"] is None


def test_initialize_phase4_cutover_uses_stopped_snapshot_boundary(
    migrated_db: Path,
) -> None:
    with connect_database(migrated_db) as connection:
        _insert_mqtt_log(connection, received_at="2026-07-21T04:29:59Z")
        _insert_feature_log(
            connection,
            window_start="2026-07-21T04:29:50Z",
            window_end="2026-07-21T04:30:00Z",
        )
        checkpoint_repository.upsert_detector_checkpoint(
            connection,
            detector_name="mqtt_feature_builder",
            source_table="mqtt_logs",
            last_processed_id=None,
            last_completed_window_end=CUTOVER_AT,
            updated_at=CUTOVER_AT,
        )
        session_pk = _insert_packet_session(
            connection,
            session_id=SESSION_A,
            first_window_start="2026-07-21T04:29:50Z",
        )
        segment_id = _insert_packet_segment(
            connection,
            capture_session_id=session_pk,
            file_name="cutover-boundary.pcap",
            window_start="2026-07-21T04:29:50Z",
            window_end="2026-07-21T04:30:00Z",
            status="PROCESSED",
        )
        _insert_packet_feature(
            connection,
            capture_segment_id=segment_id,
            peer_ip="10.0.0.8",
            window_start="2026-07-21T04:29:50Z",
            window_end="2026-07-21T04:30:00Z",
        )
        event_id = _insert_detection_event(
            connection,
            event_type="ABNORMAL_TOPIC",
            score_delta=-20,
            applied_to_score=0,
            detected_at="2026-07-21T04:29:59Z",
        )

    summary = initialize_phase4_cutover(migrated_db, CUTOVER_AT)

    for key in (
        "mqtt_feature_builder+mqtt_logs",
        "mqtt_feature_rule+feature_logs",
        "mqtt_message_rule+mqtt_logs",
        "mqtt_if+feature_logs",
        "packet_rule+packet_feature_logs",
        "packet_if+packet_feature_logs",
        "trust_score_v2+detection_events",
    ):
        assert summary["checkpoints"][key]["last_completed_window_end"] == (
            "2026-07-21T04:30:00Z"
        )

    with connect_database(migrated_db) as connection:
        rows = connection.execute(
            """
            SELECT last_completed_window_end, updated_at
            FROM detector_checkpoints
            ORDER BY detector_name, source_table
            """
        ).fetchall()
        assert rows
        assert {row["last_completed_window_end"] for row in rows} == {
            "2026-07-21T04:30:00Z"
        }
        assert {row["updated_at"] for row in rows} == {"2026-07-21T04:30:00Z"}
        event = connection.execute(
            "SELECT processed_at FROM detection_events WHERE id = ?",
            (event_id,),
        ).fetchone()
        assert event["processed_at"] == "2026-07-21T04:30:00Z"


def test_initialize_phase4_cutover_excluded_packet_feature_does_not_advance_id(
    migrated_db: Path,
) -> None:
    with connect_database(migrated_db) as connection:
        session_a_pk = _insert_packet_session(
            connection,
            session_id=SESSION_A,
            first_window_start="2026-07-21T04:29:50Z",
        )
        included_segment_id = _insert_packet_segment(
            connection,
            capture_session_id=session_a_pk,
            file_name="included.pcap",
            window_start="2026-07-21T04:29:50Z",
            window_end="2026-07-21T04:30:00Z",
            status="PROCESSED",
        )
        included_feature_id = _insert_packet_feature(
            connection,
            capture_segment_id=included_segment_id,
            peer_ip="10.0.0.8",
            window_start="2026-07-21T04:29:50Z",
            window_end="2026-07-21T04:30:00Z",
        )

        session_b_pk = _insert_packet_session(
            connection,
            session_id=SESSION_B,
            capture_interface="eth1",
            first_window_start="2026-07-21T04:30:00Z",
        )
        excluded_segment_id = _insert_packet_segment(
            connection,
            capture_session_id=session_b_pk,
            file_name="excluded-ready.pcap",
            capture_interface="eth1",
            window_start="2026-07-21T04:30:00Z",
            window_end="2026-07-21T04:30:10Z",
            status="READY",
        )
        excluded_feature_id = _insert_packet_feature(
            connection,
            capture_segment_id=excluded_segment_id,
            peer_ip="10.0.0.9",
            window_start="2026-07-21T04:30:00Z",
            window_end="2026-07-21T04:30:10Z",
        )

    assert excluded_feature_id > included_feature_id

    summary = initialize_phase4_cutover(migrated_db, CUTOVER_AT)

    for key in ("packet_rule+packet_feature_logs", "packet_if+packet_feature_logs"):
        assert summary["checkpoints"][key] == {
            "last_processed_id": included_feature_id,
            "last_completed_window_end": "2026-07-21T04:30:00Z",
        }


def test_initialize_phase4_cutover_rolls_back_partial_writes(
    migrated_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with connect_database(migrated_db) as connection:
        event_id = _insert_detection_event(
            connection,
            event_type="ABNORMAL_TOPIC",
            score_delta=-20,
            applied_to_score=0,
            detected_at="2026-07-21T04:29:59Z",
        )

    original_upsert = checkpoint_repository.upsert_detector_checkpoint
    calls = 0

    def failing_upsert(*args, **kwargs):
        nonlocal calls
        calls += 1
        original_upsert(*args, **kwargs)
        if calls == 1:
            raise RuntimeError("forced checkpoint failure")

    monkeypatch.setattr(
        checkpoint_repository,
        "upsert_detector_checkpoint",
        failing_upsert,
    )

    with pytest.raises(RuntimeError, match="forced checkpoint failure"):
        initialize_phase4_cutover(migrated_db, CUTOVER_AT)

    with connect_database(migrated_db) as connection:
        assert connection.execute(
            "SELECT COUNT(*) AS count FROM detector_checkpoints"
        ).fetchone()["count"] == 0
        event = connection.execute(
            """
            SELECT processed_at, processing_reason
            FROM detection_events
            WHERE id = ?
            """,
            (event_id,),
        ).fetchone()
        assert event["processed_at"] is None
        assert event["processing_reason"] is None


def _insert_mqtt_log(connection: sqlite3.Connection, *, received_at: str) -> int:
    cursor = connection.execute(
        """
        INSERT INTO mqtt_logs (
            device_id, topic, payload, payload_size,
            received_at, is_json_valid, is_topic_valid
        )
        VALUES ('esp32_01', 'iot/esp32_01/sensor', '{}', 2,
                ?, 1, 1)
        """,
        (received_at,),
    )
    return int(cursor.lastrowid)


def _insert_feature_log(
    connection: sqlite3.Connection,
    *,
    window_start: str,
    window_end: str,
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO feature_logs (
            device_id, window_start, window_end, publish_count
        )
        VALUES ('esp32_01', ?, ?, 1)
        """,
        (window_start, window_end),
    )
    return int(cursor.lastrowid)


def _insert_detection_event(
    connection: sqlite3.Connection,
    *,
    event_type: str,
    score_delta: int,
    applied_to_score: int,
    detected_at: str,
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO detection_events (
            device_id, detector_type, event_type, severity,
            score_delta, applied_to_score, description, detected_at
        )
        VALUES ('esp32_01', 'RULE', ?, 'high', ?, ?, 'legacy', ?)
        """,
        (event_type, score_delta, applied_to_score, detected_at),
    )
    return int(cursor.lastrowid)


def _insert_packet_session(
    connection: sqlite3.Connection,
    *,
    session_id: str,
    capture_interface: str = "wlan0",
    first_window_start: str,
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO packet_capture_sessions (
            session_id, capture_interface, started_at, first_window_start
        )
        VALUES (?, ?, ?, ?)
        """,
        (session_id, capture_interface, first_window_start, first_window_start),
    )
    return int(cursor.lastrowid)


def _insert_packet_segment(
    connection: sqlite3.Connection,
    *,
    capture_session_id: int,
    file_name: str,
    capture_interface: str = "wlan0",
    window_start: str,
    window_end: str,
    status: str,
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO packet_capture_segments (
            capture_session_id, file_name, capture_interface,
            window_start, window_end, status
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (capture_session_id, file_name, capture_interface, window_start, window_end, status),
    )
    return int(cursor.lastrowid)


def _insert_packet_feature(
    connection: sqlite3.Connection,
    *,
    capture_segment_id: int,
    peer_ip: str,
    window_start: str,
    window_end: str,
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO packet_feature_logs (
            capture_segment_id, peer_ip, direction, window_start,
            window_end, packet_count, total_bytes, avg_packet_size,
            max_packet_size
        )
        VALUES (?, ?, 'INBOUND', ?, ?, 1, 60, 60.0, 60)
        """,
        (capture_segment_id, peer_ip, window_start, window_end),
    )
    return int(cursor.lastrowid)
