from pathlib import Path
import sqlite3

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.database import get_db
from backend.app.main import app


SCHEMA_PATH = Path("db/migrations/001_init.sql")


@pytest.fixture
def api_client(tmp_path: Path):
    db_path = tmp_path / "api_test.db"
    with sqlite3.connect(db_path) as connection:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))

    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = testing_session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    try:
        yield TestClient(app), db_path
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def seed_api_rows(db_path: Path) -> None:
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO devices (
                device_id,
                ip_address,
                status,
                trust_score,
                last_seen_at,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "esp32_01",
                "192.168.0.21",
                "normal",
                80,
                None,
                "2026-05-11 09:00:00",
            ),
        )
        connection.execute(
            """
            INSERT INTO devices (
                device_id,
                ip_address,
                status,
                trust_score,
                last_seen_at,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "esp32_02",
                "192.168.0.22",
                "isolated",
                20,
                "2026-05-11 10:05:00",
                "2026-05-11 09:05:00",
            ),
        )
        cursor = connection.execute(
            """
            INSERT INTO feature_logs (
                device_id,
                window_start,
                window_end,
                publish_count
            )
            VALUES (?, ?, ?, ?)
            """,
            ("esp32_01", "2026-05-11 10:00:00", "2026-05-11 10:00:10", 20),
        )
        feature_log_id = cursor.lastrowid
        connection.execute(
            """
            INSERT INTO detection_events (
                device_id,
                feature_log_id,
                detector_type,
                event_type,
                severity,
                score_delta,
                applied_to_score,
                description,
                detected_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "esp32_01",
                feature_log_id,
                "RULE",
                "ABNORMAL_PUBLISH_RATE",
                "high",
                -20,
                1,
                "publish rate abnormal",
                "2026-05-11 10:00:10",
            ),
        )
        connection.execute(
            """
            INSERT INTO detection_events (
                device_id,
                feature_log_id,
                detector_type,
                event_type,
                severity,
                score_delta,
                applied_to_score,
                description,
                detected_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "esp32_01",
                feature_log_id,
                "AI",
                "AI_ANOMALY",
                "medium",
                -15,
                0,
                "ai anomaly",
                "2026-05-11 10:00:11",
            ),
        )
        connection.execute(
            """
            INSERT INTO isolation_history (
                device_id,
                action,
                reason,
                trust_score,
                trigger_event_id,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "esp32_02",
                "ISOLATED",
                "Trust Score below threshold",
                20,
                1,
                "2026-05-11 10:01:00",
            ),
        )


def test_devices_endpoint_lists_seeded_device(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)

    response = client.get("/api/devices")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["items"][0]["device_id"] == "esp32_01"
    assert body["items"][0]["trust_score"] == 80


def test_devices_status_filter(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)

    response = client.get("/api/devices", params={"status": "normal"})

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["device_id"] == "esp32_01"


def test_device_detail_returns_device(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)

    response = client.get("/api/devices/esp32_01")

    assert response.status_code == 200
    body = response.json()
    assert body["device_id"] == "esp32_01"
    assert body["ip_address"] == "192.168.0.21"
    assert body["status"] == "normal"
    assert body["trust_score"] == 80


def test_device_detail_unknown_device_returns_404(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)

    response = client.get("/api/devices/unknown_device")

    assert response.status_code == 404
    assert response.json()["detail"] == "Device not found"


def test_detection_events_endpoint_and_filters(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)

    response = client.get("/api/detection-events")
    severity_response = client.get(
        "/api/detection-events",
        params={"severity": "high"},
    )
    applied_response = client.get(
        "/api/detection-events",
        params={"applied_to_score": 1},
    )

    assert response.status_code == 200
    assert severity_response.status_code == 200
    assert applied_response.status_code == 200
    body = response.json()
    severity_body = severity_response.json()
    applied_body = applied_response.json()
    assert body["total"] == 2
    assert body["items"][0]["event_type"] == "AI_ANOMALY"
    assert body["items"][0]["score_delta"] == -15
    assert body["items"][0]["applied_to_score"] == 0
    assert severity_body["total"] == 1
    assert severity_body["items"][0]["severity"] == "high"
    assert applied_body["total"] == 1
    assert applied_body["items"][0]["event_type"] == "ABNORMAL_PUBLISH_RATE"
    assert applied_body["items"][0]["score_delta"] == -20


def test_dashboard_summary_counts_rows(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO detection_events (
                device_id,
                detector_type,
                event_type,
                severity,
                score_delta,
                applied_to_score,
                description,
                detected_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "unknown_01",
                "RULE",
                "UNKNOWN_DEVICE",
                "high",
                0,
                0,
                "unknown device",
                "2026-05-11 10:00:12",
            ),
        )

    response = client.get("/api/dashboard/summary")

    assert response.status_code == 200
    body = response.json()
    assert body["total_devices"] == 2
    assert body["normal_devices"] == 1
    assert body["isolated_devices"] == 1
    assert body["total_detection_events"] == 3
    assert body["unapplied_detection_events"] == 2
    assert body["total_isolation_events"] == 1
    assert body["recent_events_count"] == 3
    assert body["unknown_device_count"] == 1
    assert isinstance(body["last_updated"], str)
    assert len(body["latest_detection_events"]) == 3
    assert len(body["latest_isolation_events"]) == 1


def test_trust_score_summary_returns_current_device_scores(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)

    response = client.get("/api/trust-score/summary")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["items"][0]["device_id"] == "esp32_02"
    assert body["items"][0]["trust_score"] == 20
    assert body["items"][1]["device_id"] == "esp32_01"
    assert body["items"][1]["trust_score"] == 80


def test_trust_score_history_returns_only_applied_events(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)

    response = client.get("/api/trust-score/esp32_01/history")

    assert response.status_code == 200
    body = response.json()
    assert body["device_id"] == "esp32_01"
    assert body["current_score"] == 80
    assert body["current_status"] == "normal"
    assert body["total"] == 1
    assert body["items"][0]["event_type"] == "ABNORMAL_PUBLISH_RATE"
    assert body["items"][0]["score_before"] == 100
    assert body["items"][0]["score_after"] == 80
    assert body["items"][0]["applied_to_score"] == 1


def test_trust_score_history_calculates_before_pagination(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO detection_events (
                device_id,
                detector_type,
                event_type,
                severity,
                score_delta,
                applied_to_score,
                description,
                detected_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "esp32_01",
                "AI",
                "AI_ANOMALY",
                "medium",
                -15,
                1,
                "applied ai anomaly",
                "2026-05-11 10:00:12",
            ),
        )
        connection.execute(
            """
            UPDATE devices
            SET trust_score = 65, status = 'warning'
            WHERE device_id = 'esp32_01'
            """
        )

    latest_response = client.get(
        "/api/trust-score/esp32_01/history",
        params={"limit": 1, "offset": 0},
    )
    older_response = client.get(
        "/api/trust-score/esp32_01/history",
        params={"limit": 1, "offset": 1},
    )

    assert latest_response.status_code == 200
    assert older_response.status_code == 200
    latest_body = latest_response.json()
    older_body = older_response.json()
    assert latest_body["current_score"] == 65
    assert latest_body["current_status"] == "warning"
    assert latest_body["total"] == 2
    assert len(latest_body["items"]) == 1
    assert latest_body["items"][0]["event_type"] == "AI_ANOMALY"
    assert latest_body["items"][0]["score_before"] == 80
    assert latest_body["items"][0]["score_after"] == 65
    assert older_body["total"] == 2
    assert older_body["items"][0]["event_type"] == "ABNORMAL_PUBLISH_RATE"
    assert older_body["items"][0]["score_before"] == 100
    assert older_body["items"][0]["score_after"] == 80


def test_trust_score_history_unknown_device_returns_empty(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)

    response = client.get("/api/trust-score/unknown_device/history")

    assert response.status_code == 200
    body = response.json()
    assert body == {
        "device_id": "unknown_device",
        "current_score": None,
        "current_status": None,
        "items": [],
        "total": 0,
    }


def test_isolation_history_returns_rows(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)

    response = client.get("/api/isolation/history")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["device_id"] == "esp32_02"
    assert body["items"][0]["action"] == "ISOLATED"
    assert body["items"][0]["trust_score"] == 20


def test_limit_and_offset_work_on_devices_endpoint(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)

    response = client.get("/api/devices", params={"limit": 1, "offset": 1})

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert len(body["items"]) == 1
    assert body["items"][0]["device_id"] == "esp32_02"
