"""Detection runners부터 Trust Score API까지 실제 SQLite로 검증합니다."""

from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from backend.app.database import SessionLocal, get_db
from backend.app.main import app
from edge.detection.run_ai_detector import run_ai_detector
from edge.detection.run_rule_detector import run_rule_detector
from edge.detection.rule_detector import (
    ABNORMAL_PUBLISH_RATE,
    AI_ANOMALY,
    DEVICE_ID_MISMATCH,
    LARGE_PAYLOAD,
    MALFORMED_PAYLOAD,
    UNKNOWN_DEVICE,
)
from edge.trust.trust_policy import status_for_trust_score
from edge.trust.trust_score_service import update_trust_scores


FAKE_MODEL_PATH = Path("ai/models/fake-integration.joblib")
ANOMALY_RESULT = {
    "is_anomaly": True,
    "prediction": -1,
    "anomaly_score": -0.25,
    "detector_type": "AI",
    "event_type": AI_ANOMALY,
}


def _cleanup(db) -> None:
    for table in (
        "detection_events",
        "feature_logs",
        "mqtt_logs",
        "isolation_history",
        "devices",
    ):
        db.execute(text(f"DELETE FROM {table}"))
    db.commit()


@pytest.fixture()
def fresh_db(db_session):
    _cleanup(db_session)
    try:
        yield db_session
    finally:
        db_session.rollback()
        _cleanup(db_session)


@pytest.fixture()
def api_client():
    def override_get_db():
        with SessionLocal() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


def _db_path(db) -> Path:
    return Path(str(db.get_bind().url.database))


def _insert_device(
    db,
    device_id: str,
    trust_score: int = 100,
    status: str = "normal",
) -> None:
    db.execute(
        text(
            """
            INSERT INTO devices (device_id, trust_score, status)
            VALUES (:device_id, :trust_score, :status)
            """
        ),
        {
            "device_id": device_id,
            "trust_score": trust_score,
            "status": status,
        },
    )
    db.commit()


def _insert_feature_window(db, device_id: str) -> int:
    db.execute(
        text(
            """
            INSERT INTO feature_logs (
                device_id,
                window_start,
                window_end,
                publish_count,
                avg_payload_size,
                max_payload_size,
                avg_message_interval,
                min_message_interval,
                malformed_payload_count,
                abnormal_topic_count
            )
            VALUES (
                :device_id,
                '2026-06-29 10:00:00',
                '2026-06-29 10:00:10',
                20,
                6000.0,
                6000,
                0.5,
                0.2,
                3,
                0
            )
            """
        ),
        {"device_id": device_id},
    )
    feature_log_id = db.execute(text("SELECT last_insert_rowid()")).scalar_one()
    db.commit()
    return int(feature_log_id)


def _insert_mqtt_log(db, topic: str, payload: str) -> int:
    db.execute(
        text(
            """
            INSERT INTO mqtt_logs (
                device_id,
                topic,
                payload,
                payload_size,
                is_json_valid,
                is_topic_valid
            )
            VALUES (NULL, :topic, :payload, :payload_size, 1, 1)
            """
        ),
        {
            "topic": topic,
            "payload": payload,
            "payload_size": len(payload),
        },
    )
    mqtt_log_id = db.execute(text("SELECT last_insert_rowid()")).scalar_one()
    db.commit()
    return int(mqtt_log_id)


@contextmanager
def _mock_anomaly_prediction():
    with patch("edge.detection.run_ai_detector.load_model"), patch(
        "edge.detection.run_ai_detector.predict_feature_window",
        return_value=ANOMALY_RESULT,
    ):
        yield


def _device_state(db, device_id: str) -> tuple[int, str]:
    row = db.execute(
        text(
            """
            SELECT trust_score, status
            FROM devices
            WHERE device_id = :device_id
            """
        ),
        {"device_id": device_id},
    ).one()
    return int(row[0]), str(row[1])


def test_feature_window_rule_ai_trust_and_api_flow(fresh_db, api_client) -> None:
    _insert_device(fresh_db, "esp32_01")
    feature_log_id = _insert_feature_window(fresh_db, "esp32_01")

    first_rule = run_rule_detector(fresh_db)
    second_rule = run_rule_detector(fresh_db)
    with _mock_anomaly_prediction():
        first_ai = run_ai_detector(fresh_db, FAKE_MODEL_PATH)
        second_ai = run_ai_detector(fresh_db, FAKE_MODEL_PATH)

    assert first_rule == {"feature_events": 3, "mqtt_events": 0}
    assert second_rule == {"feature_events": 0, "mqtt_events": 0}
    assert first_ai == {"feature_events": 1}
    assert second_ai == {"feature_events": 0}

    rows_before_update = fresh_db.execute(
        text(
            """
            SELECT event_type, score_delta, applied_to_score
            FROM detection_events
            WHERE feature_log_id = :feature_log_id
            """
        ),
        {"feature_log_id": feature_log_id},
    ).mappings().all()
    assert {
        row["event_type"]: (row["score_delta"], row["applied_to_score"])
        for row in rows_before_update
    } == {
        MALFORMED_PAYLOAD: (-10, 0),
        LARGE_PAYLOAD: (-15, 0),
        ABNORMAL_PUBLISH_RATE: (-20, 0),
        AI_ANOMALY: (-15, 0),
    }

    db_path = _db_path(fresh_db)
    first_update = update_trust_scores(db_path)
    second_update = update_trust_scores(db_path)
    fresh_db.expire_all()

    assert first_update.applied_event_count == 1
    assert second_update.applied_event_count == 0
    assert _device_state(fresh_db, "esp32_01") == (80, "normal")

    rows_after_update = fresh_db.execute(
        text(
            """
            SELECT event_type, score_delta, applied_to_score
            FROM detection_events
            WHERE feature_log_id = :feature_log_id
            """
        ),
        {"feature_log_id": feature_log_id},
    ).mappings().all()
    event_state = {
        row["event_type"]: (row["score_delta"], row["applied_to_score"])
        for row in rows_after_update
    }
    assert event_state[ABNORMAL_PUBLISH_RATE] == (-20, 1)
    assert event_state[MALFORMED_PAYLOAD] == (-10, 0)
    assert event_state[LARGE_PAYLOAD] == (-15, 0)
    assert event_state[AI_ANOMALY] == (-15, 0)

    devices = api_client.get("/api/devices").json()
    events = api_client.get("/api/detection-events").json()
    summary = api_client.get("/api/trust-score/summary").json()
    history = api_client.get("/api/trust-score/esp32_01/history").json()
    isolation = api_client.get("/api/isolation/history").json()

    assert devices["items"][0]["trust_score"] == 80
    assert devices["items"][0]["status"] == "normal"
    assert events["total"] == 4
    assert sum(item["applied_to_score"] for item in events["items"]) == 1
    assert summary["items"][0]["trust_score"] == 80
    assert history["total"] == 1
    assert history["items"][0]["event_type"] == ABNORMAL_PUBLISH_RATE
    assert isolation["total"] == 0


def test_unknown_device_is_persisted_but_never_scored(fresh_db) -> None:
    _insert_device(fresh_db, "esp32_01")
    mqtt_log_id = _insert_mqtt_log(
        fresh_db,
        "iot/rogue_01/sensor",
        '{"device_id":"rogue_01"}',
    )

    first_rule = run_rule_detector(fresh_db)
    second_rule = run_rule_detector(fresh_db)
    assert first_rule == {"feature_events": 0, "mqtt_events": 1}
    assert second_rule == {"feature_events": 0, "mqtt_events": 0}

    event = fresh_db.execute(
        text(
            """
            SELECT device_id, mqtt_log_id, score_delta, applied_to_score
            FROM detection_events
            WHERE event_type = :event_type
            """
        ),
        {"event_type": UNKNOWN_DEVICE},
    ).mappings().one()
    assert event["device_id"] == "rogue_01"
    assert event["mqtt_log_id"] == mqtt_log_id
    assert event["score_delta"] == 0
    assert event["applied_to_score"] == 0

    db_path = _db_path(fresh_db)
    first_update = update_trust_scores(db_path)
    second_update = update_trust_scores(db_path)
    fresh_db.expire_all()

    assert first_update.applied_event_count == 0
    assert second_update.applied_event_count == 0
    assert _device_state(fresh_db, "esp32_01") == (100, "normal")
    assert fresh_db.execute(text("SELECT COUNT(*) FROM devices")).scalar_one() == 1
    assert fresh_db.execute(
        text(
            """
            SELECT applied_to_score
            FROM detection_events
            WHERE mqtt_log_id = :mqtt_log_id
            """
        ),
        {"mqtt_log_id": mqtt_log_id},
    ).scalar_one() == 0


def test_distinct_mismatch_messages_score_individually_and_isolate(
    fresh_db,
    api_client,
) -> None:
    _insert_device(fresh_db, "esp32_01")
    _insert_device(fresh_db, "esp32_02")

    first_three_mqtt_ids = [
        _insert_mqtt_log(
            fresh_db,
            "iot/esp32_01/sensor",
            '{"device_id":"esp32_02"}',
        )
        for _ in range(3)
    ]

    first_rule = run_rule_detector(fresh_db)
    second_rule = run_rule_detector(fresh_db)
    assert first_rule == {"feature_events": 0, "mqtt_events": 3}
    assert second_rule == {"feature_events": 0, "mqtt_events": 0}

    first_update = update_trust_scores(_db_path(fresh_db))
    second_update = update_trust_scores(_db_path(fresh_db))
    fresh_db.expire_all()

    assert first_update.applied_event_count == 3
    assert second_update.applied_event_count == 0
    assert _device_state(fresh_db, "esp32_01") == (25, "isolated")
    assert fresh_db.execute(
        text("SELECT COUNT(*) FROM isolation_history")
    ).scalar_one() == 1

    mismatch_rows = fresh_db.execute(
        text(
            """
            SELECT mqtt_log_id, score_delta, applied_to_score
            FROM detection_events
            WHERE event_type = :event_type
            ORDER BY id
            """
        ),
        {"event_type": DEVICE_ID_MISMATCH},
    ).mappings().all()
    assert [row["mqtt_log_id"] for row in mismatch_rows] == first_three_mqtt_ids
    assert all(row["score_delta"] == -25 for row in mismatch_rows)
    assert all(row["applied_to_score"] == 1 for row in mismatch_rows)

    fourth_mqtt_id = _insert_mqtt_log(
        fresh_db,
        "iot/esp32_01/sensor",
        '{"device_id":"esp32_02"}',
    )
    assert run_rule_detector(fresh_db) == {"feature_events": 0, "mqtt_events": 1}
    isolated_update = update_trust_scores(_db_path(fresh_db))
    fresh_db.expire_all()

    assert isolated_update.applied_event_count == 1
    assert _device_state(fresh_db, "esp32_01") == (0, "isolated")
    assert fresh_db.execute(
        text("SELECT COUNT(*) FROM isolation_history")
    ).scalar_one() == 1
    assert fresh_db.execute(
        text(
            """
            SELECT applied_to_score
            FROM detection_events
            WHERE mqtt_log_id = :mqtt_log_id
            """
        ),
        {"mqtt_log_id": fourth_mqtt_id},
    ).scalar_one() == 1

    device = api_client.get("/api/devices/esp32_01").json()
    events = api_client.get(
        "/api/detection-events",
        params={"device_id": "esp32_01", "event_type": DEVICE_ID_MISMATCH},
    ).json()
    summary = api_client.get("/api/trust-score/summary").json()
    history = api_client.get("/api/trust-score/esp32_01/history").json()
    isolation = api_client.get(
        "/api/isolation/history",
        params={"device_id": "esp32_01"},
    ).json()

    assert device["trust_score"] == 0
    assert device["status"] == "isolated"
    assert events["total"] == 4
    assert all(item["score_delta"] == -25 for item in events["items"])
    assert all(item["applied_to_score"] == 1 for item in events["items"])
    assert next(
        item for item in summary["items"] if item["device_id"] == "esp32_01"
    )["trust_score"] == 0
    assert history["total"] == 4
    assert history["items"][0]["score_before"] == 25
    assert history["items"][0]["score_after"] == 0
    assert isolation["total"] == 1
    assert isolation["items"][0]["trust_score"] == 25


@pytest.mark.parametrize(
    ("trust_score", "expected_status"),
    [
        (100, "normal"),
        (80, "normal"),
        (79, "warning"),
        (60, "warning"),
        (59, "danger"),
        (30, "danger"),
        (29, "isolated"),
        (0, "isolated"),
    ],
)
def test_status_boundaries(trust_score: int, expected_status: str) -> None:
    assert status_for_trust_score(trust_score) == expected_status
