from pathlib import Path
import sqlite3

from edge.trust.trust_policy import (
    ABNORMAL_PUBLISH_RATE,
    AI_ANOMALY,
    DEVICE_ID_MISMATCH,
    LARGE_PAYLOAD,
    UNKNOWN_DEVICE,
)
from edge.trust.trust_score_service import update_trust_scores


SCHEMA_PATH = Path("db/migrations/001_init.sql")


def create_test_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "iot_security.db"
    with sqlite3.connect(db_path) as connection:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return db_path


def fetch_one(db_path: Path, query: str, params: tuple = ()) -> sqlite3.Row:
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(query, params).fetchone()


def seed_device(
    db_path: Path,
    device_id: str = "esp32_01",
    trust_score: int = 100,
    status: str = "normal",
) -> None:
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES (?, ?, ?, ?)
            """,
            (device_id, "192.168.0.4", status, trust_score),
        )


def insert_feature_log(db_path: Path, device_id: str = "esp32_01") -> int:
    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO feature_logs (
                device_id,
                window_start,
                window_end,
                publish_count
            )
            VALUES (?, '2026-01-01 00:00:00', '2026-01-01 00:00:10', 1)
            """,
            (device_id,),
        )
        return cursor.lastrowid


def insert_detection_event(
    db_path: Path,
    event_type: str,
    device_id: str = "esp32_01",
    feature_log_id: int | None = None,
    detector_type: str = "RULE",
) -> int:
    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO detection_events (
                device_id,
                feature_log_id,
                detector_type,
                event_type,
                description
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                device_id,
                feature_log_id,
                detector_type,
                event_type,
                "test event",
            ),
        )
        return cursor.lastrowid


def test_single_publish_rate_event_reduces_score_to_80(tmp_path: Path) -> None:
    db_path = create_test_db(tmp_path)
    seed_device(db_path)
    feature_log_id = insert_feature_log(db_path)
    event_id = insert_detection_event(
        db_path,
        ABNORMAL_PUBLISH_RATE,
        feature_log_id=feature_log_id,
    )

    result = update_trust_scores(db_path)

    device = fetch_one(db_path, "SELECT trust_score, status FROM devices")
    event = fetch_one(
        db_path,
        "SELECT applied_to_score, score_delta FROM detection_events WHERE id = ?",
        (event_id,),
    )
    assert result.applied_event_count == 1
    assert device["trust_score"] == 80
    assert device["status"] == "normal"
    assert event["applied_to_score"] == 1
    assert event["score_delta"] == -20


def test_same_feature_window_applies_only_largest_penalty(tmp_path: Path) -> None:
    db_path = create_test_db(tmp_path)
    seed_device(db_path)
    feature_log_id = insert_feature_log(db_path)
    mismatch_id = insert_detection_event(
        db_path,
        DEVICE_ID_MISMATCH,
        feature_log_id=feature_log_id,
    )
    publish_id = insert_detection_event(
        db_path,
        ABNORMAL_PUBLISH_RATE,
        feature_log_id=feature_log_id,
    )
    large_payload_id = insert_detection_event(
        db_path,
        LARGE_PAYLOAD,
        feature_log_id=feature_log_id,
    )
    ai_id = insert_detection_event(
        db_path,
        AI_ANOMALY,
        feature_log_id=feature_log_id,
        detector_type="AI",
    )

    first_result = update_trust_scores(db_path)
    second_result = update_trust_scores(db_path)

    device = fetch_one(db_path, "SELECT trust_score FROM devices")
    assert first_result.applied_event_count == 1
    assert second_result.applied_event_count == 0
    assert device["trust_score"] == 75

    applied_rows = fetch_one(
        db_path,
        """
        SELECT
            SUM(CASE WHEN applied_to_score = 1 THEN 1 ELSE 0 END) AS applied_count,
            SUM(CASE WHEN id = ? AND applied_to_score = 1 THEN 1 ELSE 0 END) AS mismatch_applied,
            SUM(CASE WHEN id IN (?, ?, ?) AND applied_to_score = 0 THEN 1 ELSE 0 END) AS others_unapplied
        FROM detection_events
        """,
        (mismatch_id, publish_id, large_payload_id, ai_id),
    )
    assert applied_rows["applied_count"] == 1
    assert applied_rows["mismatch_applied"] == 1
    assert applied_rows["others_unapplied"] == 3


def test_unknown_device_event_is_excluded_from_score(tmp_path: Path) -> None:
    db_path = create_test_db(tmp_path)
    seed_device(db_path)
    event_id = insert_detection_event(
        db_path,
        UNKNOWN_DEVICE,
        device_id="unknown_01",
        feature_log_id=None,
    )

    result = update_trust_scores(db_path)

    device = fetch_one(db_path, "SELECT trust_score, status FROM devices")
    event = fetch_one(
        db_path,
        "SELECT applied_to_score FROM detection_events WHERE id = ?",
        (event_id,),
    )
    history = fetch_one(db_path, "SELECT COUNT(*) AS count FROM isolation_history")
    assert result.candidate_event_count == 0
    assert device["trust_score"] == 100
    assert device["status"] == "normal"
    assert event["applied_to_score"] == 0
    assert history["count"] == 0


def test_score_below_30_isolates_device_and_records_history(tmp_path: Path) -> None:
    db_path = create_test_db(tmp_path)
    seed_device(db_path, trust_score=35, status="danger")
    feature_log_id = insert_feature_log(db_path)
    event_id = insert_detection_event(
        db_path,
        DEVICE_ID_MISMATCH,
        feature_log_id=feature_log_id,
    )

    result = update_trust_scores(db_path)

    device = fetch_one(db_path, "SELECT trust_score, status FROM devices")
    history = fetch_one(
        db_path,
        """
        SELECT action, reason, trust_score, trigger_event_id
        FROM isolation_history
        """,
    )
    history_count = fetch_one(db_path, "SELECT COUNT(*) AS count FROM isolation_history")
    assert result.applied_event_count == 1
    assert device["trust_score"] == 10
    assert device["status"] == "isolated"
    assert history_count["count"] == 1
    assert history["action"] == "ISOLATED"
    assert history["reason"] == "Trust Score below threshold"
    assert history["trust_score"] == 10
    assert history["trigger_event_id"] == event_id
