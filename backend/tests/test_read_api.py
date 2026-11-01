from pathlib import Path
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.database import get_db
from backend.app.main import app
from db.migration_runner import MIGRATIONS_DIR, apply_migrations


@pytest.fixture
def api_client(tmp_path: Path):
    db_path = tmp_path / "api_test.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

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
        history_cursor = connection.execute(
            """
            INSERT INTO trust_score_history (
                device_id,
                analysis_window_start,
                analysis_window_end,
                previous_score,
                calculated_delta,
                capped_delta,
                actual_delta,
                new_score,
                representative_event_ids_json,
                policy_version,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "esp32_01",
                "2026-05-11T10:00:00Z",
                "2026-05-11T10:00:10Z",
                100,
                -20,
                -20,
                -20,
                80,
                "[1]",
                "trust-score-v2",
                "2026-05-11T10:00:10Z",
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
                trust_score_history_id,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "esp32_02",
                "ISOLATED",
                "Trust Score below threshold",
                20,
                1,
                history_cursor.lastrowid,
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


def test_dashboard_recent_events_preserve_event_provenance_and_score_effects(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)
    start, end = "2026-05-11T10:00:00Z", "2026-05-11T10:00:10Z"
    with sqlite3.connect(db_path) as connection:
        capture_id = connection.execute(
            """INSERT INTO packet_capture_sessions
                (session_id, capture_interface, started_at, first_window_start, ended_at, status)
                VALUES ('11111111-1111-4111-8111-111111111111', 'test0', ?, ?, ?, 'COMPLETED')""",
            (start, start, end),
        ).lastrowid
        segment_id = connection.execute(
            """INSERT INTO packet_capture_segments
                (capture_session_id, file_name, capture_interface, window_start, window_end,
                 status, packet_count, start_delay_seconds, captured_duration_seconds)
                VALUES (?, 'summary-fixture.pcap', 'test0', ?, ?, 'PROCESSED', 1, 0, 9.9)""",
            (capture_id, start, end),
        ).lastrowid
        packet_id = connection.execute(
            """INSERT INTO packet_feature_logs
                (capture_segment_id, device_id, peer_ip, direction, window_start, window_end,
                 packet_count, total_bytes, avg_packet_size, max_packet_size,
                 mean_inter_arrival_time, distinct_dest_port_count)
                VALUES (?, 'esp32_01', '192.168.0.21', 'INBOUND', ?, ?, 1, 128, 128, 128, 0, 1)""",
            (segment_id, start, end),
        ).lastrowid
        evidence = {"source_table": "packet_feature_logs", "source_id": packet_id,
                    "trust_decision": {"ai_mode": "observe",
                                       "policy_version": "trust-ai-observation-v1",
                                       "policy_score_delta": -15}}
        connection.execute(
            """UPDATE detection_events SET feature_log_id = NULL, packet_feature_log_id = ?,
                event_type = 'AI_PACKET_ANOMALY', analysis_window_start = ?, analysis_window_end = ?,
                incident_family = 'AI_ONLY', subject_ip = '192.168.0.21', evidence_json = ?,
                evidence_schema_version = 1, processing_reason = 'AI_OBSERVATION_ONLY',
                processed_at = '2026-05-11T10:05:00Z', policy_version = 'packet-if-fixture'
                WHERE detector_type = 'AI'""",
            (packet_id, start, end, json.dumps(evidence)),
        )
        state_before = list(connection.iterdump())

    events_response = client.get("/api/detection-events", params={"limit": 5, "offset": 0})
    summary_response = client.get("/api/dashboard/summary")
    assert events_response.status_code == summary_response.status_code == 200
    events = events_response.json()["items"]
    observed = next(item for item in events if item["detector_type"] == "AI")
    assert observed["packet_feature_log_id"] == packet_id
    assert observed["analysis_window_start"] == start
    assert observed["analysis_window_end"] == end
    assert observed["evidence"] == evidence
    assert observed["processing_reason"] == "AI_OBSERVATION_ONLY"
    assert observed["processed_at"] == "2026-05-11T10:05:00Z"
    assert observed["score_delta"] == observed["policy_score_delta"] == -15
    assert observed["actual_score_delta"] == 0
    assert observed["score_effect_reason"] == "NOT_APPLIED"
    # A legacy applied flag without a completed, matching audit remains unknown.
    legacy = next(item for item in events if item["detector_type"] == "RULE")
    assert legacy["actual_score_delta"] is None
    assert legacy["score_effect_reason"] == "UNKNOWN"
    assert summary_response.json()["latest_detection_events"] == events
    with sqlite3.connect(db_path) as connection:
        assert list(connection.iterdump()) == state_before


def test_dashboard_recent_events_keep_five_item_limit_and_detection_order(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)
    with sqlite3.connect(db_path) as connection:
        for second in (12, 14, 13, 14, 12):
            connection.execute(
                """INSERT INTO detection_events
                    (device_id, detector_type, event_type, score_delta, applied_to_score, detected_at)
                    VALUES ('esp32_01', 'AI', 'AI_ANOMALY', -15, 0, ?)""",
                (f"2026-05-11T10:00:{second:02d}Z",),
            )

    events_response = client.get("/api/detection-events", params={"limit": 5, "offset": 0})
    summary_response = client.get("/api/dashboard/summary")
    assert events_response.status_code == summary_response.status_code == 200
    body = summary_response.json()
    assert body["total_detection_events"] == body["recent_events_count"] == 7
    assert body["unapplied_detection_events"] == 6
    assert len(body["latest_detection_events"]) == 5
    assert [item["id"] for item in body["latest_detection_events"]] == [6, 4, 5, 7, 3]
    assert body["latest_detection_events"] == events_response.json()["items"]


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


def test_trust_score_history_reads_history_table(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)

    response = client.get("/api/trust-score/esp32_01/history")

    assert response.status_code == 200
    body = response.json()
    assert body["device_id"] == "esp32_01"
    assert body["current_score"] == 80
    assert body["current_status"] == "normal"
    assert body["total"] == 1
    assert body["items"][0]["previous_score"] == 100
    assert body["items"][0]["new_score"] == 80
    assert body["items"][0]["representative_event_ids"] == [1]


def test_trust_score_history_calculates_before_pagination(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO trust_score_history (
                device_id,
                analysis_window_start,
                analysis_window_end,
                previous_score,
                calculated_delta,
                capped_delta,
                actual_delta,
                new_score,
                representative_event_ids_json,
                policy_version,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "esp32_01",
                "2026-05-11T10:00:10Z",
                "2026-05-11T10:00:20Z",
                80,
                -15,
                -15,
                -15,
                65,
                "[2]",
                "trust-score-v2",
                "2026-05-11T10:00:20Z",
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
    assert latest_body["items"][0]["previous_score"] == 80
    assert latest_body["items"][0]["new_score"] == 65
    assert older_body["total"] == 2
    assert older_body["items"][0]["previous_score"] == 100
    assert older_body["items"][0]["new_score"] == 80


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
    assert body["items"][0]["trust_score_history_id"] is not None


def test_limit_and_offset_work_on_devices_endpoint(api_client) -> None:
    client, db_path = api_client
    seed_api_rows(db_path)

    response = client.get("/api/devices", params={"limit": 1, "offset": 1})

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert len(body["items"]) == 1
    assert body["items"][0]["device_id"] == "esp32_02"
