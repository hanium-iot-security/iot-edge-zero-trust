from fastapi.testclient import TestClient
from sqlalchemy import text

from backend.app.main import app
from tests.conftest import cleanup_device


def test_mqtt_logs_api_filters_and_paginates(db_session) -> None:
    device_id = "test_api_mqtt"
    cleanup_device(db_session, device_id)


def test_mqtt_logs_api_orders_mixed_timestamps_by_ingestion_id(db_session) -> None:
    device_id = "test_mqtt_order"
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
                device_id, topic, payload, payload_size,
                received_at, is_json_valid, is_topic_valid
            )
            VALUES
                (:device_id, 'iot/test_mqtt_order/sensor', '{}', 2,
                 '2026-07-31T10:00:01Z', 1, 1),
                (:device_id, 'iot/test_mqtt_order/sensor', '{}', 2,
                 '2026-07-31 10:00:09', 1, 1)
            """
        ),
        {"device_id": device_id},
    )
    db_session.commit()

    response = TestClient(app).get(f"/api/mqtt-logs?device_id={device_id}")

    assert response.status_code == 200
    assert [row["received_at"] for row in response.json()["items"]] == [
        "2026-07-31 10:00:09",
        "2026-07-31T10:00:01Z",
    ]
    cleanup_device(db_session, device_id)
    db_session.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES (:device_id, '192.168.0.97', 'normal', 100)
            """
        ),
        {"device_id": device_id},
    )
    db_session.execute(
        text(
            """
            INSERT INTO mqtt_logs (
                device_id, topic, payload, payload_size, received_at, is_json_valid, is_topic_valid, error_message
            )
            VALUES
                (:device_id, 'iot/test_api_mqtt/sensor', '{"device_id":"test_api_mqtt"}', 29, '2026-05-26 14:30:01', 1, 1, NULL),
                (:device_id, 'admin/system/control', '{"device_id":"test_api_mqtt"}', 29, '2026-05-26 14:30:02', 1, 0, 'invalid_topic')
            """
        ),
        {"device_id": device_id},
    )
    db_session.commit()

    client = TestClient(app)
    response = client.get(f"/api/mqtt-logs?device_id={device_id}&limit=1")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert len(body["items"]) == 1
    assert body["items"][0]["topic"] == "admin/system/control"

    response = client.get(f"/api/mqtt-logs?device_id={device_id}&valid_only=true")
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["is_topic_valid"] == 1
    cleanup_device(db_session, device_id)


def test_feature_logs_api_filters_and_paginates(db_session) -> None:
    device_id = "test_api_feature"
    cleanup_device(db_session, device_id)
    db_session.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES (:device_id, '192.168.0.96', 'normal', 100)
            """
        ),
        {"device_id": device_id},
    )
    db_session.execute(
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
                topic_count,
                abnormal_topic_count,
                malformed_payload_count
            )
            VALUES
                (:device_id, '2026-05-26 14:30:00', '2026-05-26 14:30:10', 2, 29.0, 29, 5.0, 5.0, 1, 0, 0),
                (:device_id, '2026-05-26 14:30:10', '2026-05-26 14:30:20', 1, 29.0, 29, 5.0, 5.0, 1, 0, 0)
            """
        ),
        {"device_id": device_id},
    )
    db_session.commit()

    client = TestClient(app)
    response = client.get(f"/api/feature-logs?device_id={device_id}&limit=1")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert len(body["items"]) == 1
    assert body["items"][0]["window_start"] == "2026-05-26 14:30:10"
    cleanup_device(db_session, device_id)
