from __future__ import annotations

from pathlib import Path
import sqlite3

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend.app.config import parse_allowed_origins
from backend.app.database import get_db
from backend.app.main import app
from db.migration_runner import MIGRATIONS_DIR, apply_migrations


SESSION_ID = "11111111-1111-4111-8111-111111111111"


@pytest.fixture
def api_client(tmp_path: Path):
    db_path = tmp_path / "phase4-api.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        db.execute(text("PRAGMA foreign_keys = ON"))
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


def test_detection_events_phase4_fields_filters_and_evidence(api_client) -> None:
    client, db_path = api_client
    _seed_phase4_api_rows(db_path)

    response = client.get(
        "/api/detection-events",
        params={
            "incident_family": "MESSAGE_POLICY",
            "subject_ip": "192.168.0.21",
            "processing_reason": "APPLIED_TO_TRUST",
            "window_start_from": "2026-07-23T10:00:00Z",
            "window_end_to": "2026-07-23T10:00:10Z",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["packet_feature_log_id"] is None
    assert item["incident_family"] == "MESSAGE_POLICY"
    assert item["subject_ip"] == "192.168.0.21"
    assert item["evidence"] == {"source_id": 1, "source_type": "feature_logs"}
    assert item["detected_at"] == "2026-07-23T10:00:10Z"
    assert item["processed_at"] == "2026-07-23T10:00:10Z"


def test_detection_events_bad_stored_evidence_returns_500(api_client) -> None:
    client, db_path = api_client
    _seed_phase4_api_rows(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE detection_events SET evidence_json = '{bad json'")

    response = client.get("/api/detection-events")

    assert response.status_code == 500
    assert response.json()["detail"] == "evidence_json must be valid JSON"


def test_detection_events_bad_stored_timestamp_returns_500(api_client) -> None:
    client, db_path = api_client
    _seed_phase4_api_rows(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE detection_events SET detected_at = 'bad timestamp'")

    response = client.get("/api/detection-events")

    assert response.status_code == 500
    assert response.json()["detail"] == "detected_at must be a valid timestamp"


def test_trust_isolation_and_firewall_phase4_apis(api_client) -> None:
    client, db_path = api_client
    _seed_phase4_api_rows(db_path)

    trust = client.get("/api/trust-score/esp32_01/history")
    isolation = client.get("/api/isolation/history")
    firewall = client.get("/api/firewall-rules", params={"status": "PENDING"})
    invalid_firewall = client.get("/api/firewall-rules", params={"status": "UNKNOWN"})

    assert trust.status_code == 200
    assert trust.json()["items"][0]["representative_event_ids"] == [1]
    assert isolation.status_code == 200
    assert isolation.json()["items"][0]["trust_score_history_id"] == 1
    assert isolation.json()["items"][0]["created_at"] == "2026-07-23T10:00:10Z"
    assert firewall.status_code == 200
    assert firewall.json()["total"] == 1
    assert firewall.json()["items"][0]["retry_count"] == 0
    assert firewall.json()["items"][0]["created_at"].endswith("Z")
    assert invalid_firewall.status_code == 422


def test_packet_feature_phase4_rate_fields(api_client) -> None:
    client, db_path = api_client
    _seed_phase4_api_rows(db_path)

    response = client.get("/api/packet-feature-logs")

    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["packets_per_second"] == 2.0
    assert item["bytes_per_second"] == 200.0
    assert item["nominal_packets_per_second"] == 2.0
    assert item["nominal_bytes_per_second"] == 200.0
    assert item["captured_duration_seconds"] == 5.0
    assert item["effective_packets_per_second"] == 4.0
    assert item["effective_bytes_per_second"] == 400.0
    assert item["coverage_ratio"] == 0.5
    assert item["capture_eligible"] is None


def test_health_and_cors_contracts(api_client) -> None:
    client, _ = api_client

    response = client.get("/api/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["db_connected"] is True
    assert body["server_time"].endswith("Z")
    assert parse_allowed_origins(
        " http://localhost:5173,https://example.com,http://localhost:5173 "
    ) == ["http://localhost:5173", "https://example.com"]
    with pytest.raises(ValueError, match="http or https"):
        parse_allowed_origins("ftp://example.com")
    with pytest.raises(ValueError, match="path"):
        parse_allowed_origins("https://example.com/path")
    with pytest.raises(ValueError, match="cannot be '\\*'"):
        parse_allowed_origins("*", allow_credentials=True)


def _seed_phase4_api_rows(db_path: Path) -> None:
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES ('esp32_01', '192.168.0.21', 'isolated', 25)
            """
        )
        session_pk = connection.execute(
            """
            INSERT INTO packet_capture_sessions (
                session_id, capture_interface, started_at, first_window_start
            )
            VALUES (?, 'eth0', '2026-07-23T09:59:50Z', '2026-07-23T10:00:00Z')
            """,
            (SESSION_ID,),
        ).lastrowid
        segment_id = connection.execute(
            """
            INSERT INTO packet_capture_segments (
                capture_session_id,
                file_name,
                capture_interface,
                window_start,
                window_end,
                status,
                captured_duration_seconds
            )
            VALUES (?, 'phase4.pcap', 'eth0', ?, ?, 'PROCESSED', 5.0)
            """,
            (session_pk, "2026-07-23T10:00:00Z", "2026-07-23T10:00:10Z"),
        ).lastrowid
        feature_id = connection.execute(
            """
            INSERT INTO feature_logs (
                device_id, window_start, window_end, publish_count
            )
            VALUES ('esp32_01', '2026-07-23T10:00:00Z', '2026-07-23T10:00:10Z', 20)
            """
        ).lastrowid
        connection.execute(
            """
            INSERT INTO packet_feature_logs (
                capture_segment_id,
                device_id,
                peer_ip,
                direction,
                window_start,
                window_end,
                packet_count,
                total_bytes,
                avg_packet_size,
                max_packet_size
            )
            VALUES (?, 'esp32_01', '192.168.0.21', 'INBOUND', ?, ?, 20, 2000, 100.0, 200)
            """,
            (segment_id, "2026-07-23T10:00:00Z", "2026-07-23T10:00:10Z"),
        )
        event_id = connection.execute(
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
                detected_at,
                analysis_window_start,
                analysis_window_end,
                incident_family,
                subject_ip,
                evidence_json,
                evidence_schema_version,
                processed_at,
                processing_reason,
                policy_version
            )
            VALUES (
                'esp32_01',
                ?,
                'RULE',
                'ABNORMAL_TOPIC',
                'high',
                -20,
                1,
                'topic anomaly',
                '2026-07-23T10:00:10Z',
                '2026-07-23T10:00:00Z',
                '2026-07-23T10:00:10Z',
                'MESSAGE_POLICY',
                '192.168.0.21',
                '{"source_id":1,"source_type":"feature_logs"}',
                1,
                '2026-07-23T10:00:10Z',
                'APPLIED_TO_TRUST',
                'trust-score-v2'
            )
            """,
            (feature_id,),
        ).lastrowid
        history_id = connection.execute(
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
            VALUES (
                'esp32_01',
                '2026-07-23T10:00:00Z',
                '2026-07-23T10:00:10Z',
                45,
                -20,
                -20,
                -20,
                25,
                '[1]',
                'trust-score-v2',
                '2026-07-23T10:00:10Z'
            )
            """
        ).lastrowid
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
            VALUES ('esp32_01', 'ISOLATED', 'Trust Score below threshold', 25, ?, ?, ?)
            """,
            (event_id, history_id, "2026-07-23T10:00:10Z"),
        )
        connection.execute(
            """
            INSERT INTO firewall_rules (
                device_id,
                source_ip,
                status,
                reason,
                trigger_event_id
            )
            VALUES ('esp32_01', '192.168.0.21', 'PENDING', 'Trust Score below threshold', ?)
            """,
            (event_id,),
        )
