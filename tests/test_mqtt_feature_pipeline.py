from datetime import datetime, timedelta, timezone

import pytest

from sqlalchemy import text

from edge.features.collect_feature_logs import collect_feature_windows
from edge.mqtt import subscriber
from edge.mqtt.subscriber import build_mqtt_log_row, insert_mqtt_log
from tests.conftest import cleanup_device


def test_build_mqtt_log_row_validates_topic_and_payload() -> None:
    row = build_mqtt_log_row(
        "iot/esp32_01/sensor",
        '{"device_id":"esp32_01"}',
        received_at=datetime(2026, 5, 26, 14, 30, 1, tzinfo=timezone.utc),
    )

    assert row["device_id"] == "esp32_01"
    assert row["payload_size"] == 24
    assert row["is_json_valid"] == 1
    assert row["is_topic_valid"] == 1
    assert row["error_message"] is None


def test_build_mqtt_log_row_uses_utc_clock_when_timestamp_is_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        subscriber,
        "_utc_now",
        lambda: datetime(2026, 7, 31, 10, 59, 47, tzinfo=timezone.utc),
        raising=False,
    )

    row = build_mqtt_log_row(
        "iot/esp32_01/sensor",
        '{"device_id":"esp32_01"}',
    )

    assert row["received_at"] == "2026-07-31T10:59:47Z"


def test_build_mqtt_log_row_formats_utc_aware_timestamp() -> None:
    row = build_mqtt_log_row(
        "iot/esp32_01/sensor",
        '{"device_id":"esp32_01"}',
        received_at=datetime(2026, 7, 31, 10, 59, 47, tzinfo=timezone.utc),
    )

    assert row["received_at"] == "2026-07-31T10:59:47Z"


def test_build_mqtt_log_row_normalizes_seoul_timestamp_to_utc() -> None:
    seoul = timezone(timedelta(hours=9))
    row = build_mqtt_log_row(
        "iot/esp32_01/sensor",
        '{"device_id":"esp32_01"}',
        received_at=datetime(2026, 7, 31, 19, 59, 47, tzinfo=seoul),
    )

    assert row["received_at"] == "2026-07-31T10:59:47Z"


def test_build_mqtt_log_row_rejects_naive_timestamp() -> None:
    with pytest.raises(ValueError, match="received_at must be timezone-aware"):
        build_mqtt_log_row(
            "iot/esp32_01/sensor",
            '{"device_id":"esp32_01"}',
            received_at=datetime(2026, 7, 31, 19, 59, 47),
        )


def test_insert_mqtt_log_keeps_last_seen_equal_to_received_at(db_session) -> None:
    device_id = "test_mqtt_utc_device"
    cleanup_device(db_session, device_id)
    db_session.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES (:device_id, '192.168.0.99', 'normal', 100)
            """
        ),
        {"device_id": device_id},
    )
    db_session.commit()

    row = build_mqtt_log_row(
        f"iot/{device_id}/sensor",
        f'{{"device_id":"{device_id}"}}',
        received_at=datetime(2026, 7, 31, 10, 59, 47, tzinfo=timezone.utc),
    )
    insert_mqtt_log(db_session, row)

    stored = db_session.execute(
        text(
            """
            SELECT m.received_at, d.last_seen_at
            FROM mqtt_logs AS m
            JOIN devices AS d ON d.device_id = m.device_id
            WHERE m.device_id = :device_id
            ORDER BY m.id DESC
            LIMIT 1
            """
        ),
        {"device_id": device_id},
    ).mappings().one()

    assert stored["received_at"] == "2026-07-31T10:59:47Z"
    assert stored["last_seen_at"] == stored["received_at"]
    cleanup_device(db_session, device_id)


def test_build_mqtt_log_row_uses_payload_device_id_for_non_iot_topic() -> None:
    row = build_mqtt_log_row("admin/system/control", '{"device_id":"esp32_01"}')

    assert row["device_id"] == "esp32_01"
    assert row["is_json_valid"] == 1
    assert row["is_topic_valid"] == 0
    assert row["error_message"] == "invalid_topic"


def test_build_mqtt_log_row_uses_topic_candidate_when_payload_has_no_device_id() -> None:
    row = build_mqtt_log_row("iot/esp32_01/control", '{"temperature":25.3}')

    assert row["device_id"] == "esp32_01"
    assert row["is_json_valid"] == 0
    assert row["is_topic_valid"] == 0
    assert row["error_message"] == "invalid_topic, invalid_payload"


def test_build_mqtt_log_row_marks_mismatch_from_topic_candidate() -> None:
    row = build_mqtt_log_row("iot/esp32_01/control", '{"device_id":"esp32_02"}')

    assert row["device_id"] == "esp32_01"
    assert row["is_json_valid"] == 1
    assert row["is_topic_valid"] == 0
    assert row["error_message"] == "invalid_topic, device_id_mismatch"


def test_collect_feature_windows_completed_windows_only(db_session) -> None:
    device_id = "test_feature_01"
    cleanup_device(db_session, device_id)
    db_session.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES (:device_id, '192.168.0.99', 'normal', 100)
            """
        ),
        {"device_id": device_id},
    )
    db_session.execute(
        text(
            """
            INSERT INTO mqtt_logs (
                device_id, topic, payload, payload_size, received_at, is_json_valid, is_topic_valid
            )
            VALUES
                (:device_id, 'iot/test_feature_01/sensor', '{"device_id":"test_feature_01"}', 31, '2026-05-26 14:30:01', 1, 1),
                (:device_id, 'iot/test_feature_01/sensor', '{"device_id":"test_feature_01"}', 31, '2026-05-26 14:30:06', 1, 1),
                (:device_id, 'admin/system/control', '{"device_id":"test_feature_01"}', 31, '2026-05-26 14:30:07', 1, 0),
                (:device_id, 'iot/test_feature_01/sensor', '{"device_id":"test_feature_01"}', 31, '2026-05-26 14:30:11', 1, 1)
            """
        ),
        {"device_id": device_id},
    )
    db_session.commit()

    collect_feature_windows(db_session, now=datetime(2026, 5, 26, 14, 30, 12), window_seconds=10)

    rows = db_session.execute(
        text(
            """
            SELECT *
            FROM feature_logs
            WHERE device_id = :device_id
            ORDER BY window_start
            """
        ),
        {"device_id": device_id},
    ).mappings().all()

    assert len(rows) == 1
    assert rows[0]["window_start"] == "2026-05-26 14:30:00"
    assert rows[0]["window_end"] == "2026-05-26 14:30:10"
    assert rows[0]["publish_count"] == 3
    assert rows[0]["abnormal_topic_count"] == 1
    assert rows[0]["malformed_payload_count"] == 0
    assert rows[0]["min_message_interval"] == 1.0
    cleanup_device(db_session, device_id)


def test_collect_feature_windows_single_message_interval_defaults_to_five_seconds(db_session) -> None:
    device_id = "test_feature_single"
    cleanup_device(db_session, device_id)
    db_session.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES (:device_id, '192.168.0.98', 'normal', 100)
            """
        ),
        {"device_id": device_id},
    )
    db_session.execute(
        text(
            """
            INSERT INTO mqtt_logs (
                device_id, topic, payload, payload_size, received_at, is_json_valid, is_topic_valid
            )
            VALUES (:device_id, 'iot/test_feature_single/sensor', '{"device_id":"test_feature_single"}', 35, '2026-05-26 14:30:01', 1, 1)
            """
        ),
        {"device_id": device_id},
    )
    db_session.commit()

    collect_feature_windows(db_session, now=datetime(2026, 5, 26, 14, 30, 11), window_seconds=10)

    row = db_session.execute(
        text("SELECT avg_message_interval, min_message_interval FROM feature_logs WHERE device_id = :device_id"),
        {"device_id": device_id},
    ).mappings().one()

    assert row["avg_message_interval"] == 5.0
    assert row["min_message_interval"] == 5.0
    cleanup_device(db_session, device_id)
