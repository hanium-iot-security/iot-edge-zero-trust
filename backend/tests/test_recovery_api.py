from __future__ import annotations

from pathlib import Path
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.main import app
from backend.app.services import recovery_command_service
from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.trust.baseline_recovery import CONFIRMATION, BaselineRecoveryError


ADMIN_HEADERS = {"X-Recovery-Admin-Key": "test-secret"}


@pytest.fixture
def api_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "recovery-api.db"
    artifact_dir = tmp_path / "recovery-artifacts"
    apply_migrations(db_path, MIGRATIONS_DIR)
    _seed_isolated_device(db_path)

    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        db.execute(text("PRAGMA foreign_keys = ON"))
        try:
            yield db
        finally:
            db.close()

    def runtime_passed(_device: dict[str, object]) -> dict[str, object]:
        return {
            "available": True,
            "passed": True,
            "status": "VERIFIED_RELEASED",
            "rule_count": 0,
            "details": "test verifier",
        }

    monkeypatch.setattr(settings, "recovery_admin_api_key", "test-secret")
    monkeypatch.setattr(settings, "recovery_admin_principal", "operator@example")
    monkeypatch.setattr(settings, "recovery_artifact_dir", str(artifact_dir))
    monkeypatch.setattr(
        recovery_command_service,
        "firewall_runtime_verifier",
        runtime_passed,
    )

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app), db_path, artifact_dir
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def _seed_isolated_device(db_path: Path) -> None:
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES ('esp32_01', '192.168.0.21', 'isolated', 20)
            """
        )
        connection.commit()


def _device_state(db_path: Path) -> tuple[str, int]:
    with sqlite3.connect(db_path) as connection:
        return connection.execute(
            "SELECT status, trust_score FROM devices WHERE device_id = 'esp32_01'"
        ).fetchone()


def _post_preflight(client: TestClient, **payload: object):
    body = {"device_id": "esp32_01", "expected_trust_score": 20}
    body.update(payload)
    return client.post("/api/recovery/preflight", json=body, headers=ADMIN_HEADERS)


def _post_execute(client: TestClient, **payload: object):
    body = {
        "device_id": "esp32_01",
        "expected_trust_score": 20,
        "reason": "official firewall release completed",
        "confirm": CONFIRMATION,
    }
    body.update(payload)
    return client.post("/api/recovery/execute", json=body, headers=ADMIN_HEADERS)


def test_recovery_preflight_all_gates_pass(api_client) -> None:
    client, _, artifact_dir = api_client

    response = _post_preflight(client)

    assert response.status_code == 200
    body = response.json()
    assert body["can_execute"] is True
    assert body["result"] == "SUCCESS"
    assert body["current_status"] == "isolated"
    assert body["current_trust_score"] == 20
    assert body["firewall_db_state"]["passed"] is True
    assert body["firewall_runtime_verification"]["status"] == "VERIFIED_RELEASED"
    assert body["unprocessed_detection_count"] == 0
    assert not artifact_dir.exists()


def test_recovery_preflight_missing_device_is_denied(api_client) -> None:
    client, _, _ = api_client

    response = _post_preflight(client, device_id="missing-device")

    assert response.status_code == 200
    body = response.json()
    assert body["can_execute"] is False
    assert body["result"] == "DENIED"
    assert body["failure_code"] == "DEVICE_NOT_FOUND"


def test_recovery_preflight_requires_isolated_status(api_client) -> None:
    client, db_path, _ = api_client
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE devices SET status = 'normal', trust_score = 100 WHERE device_id = 'esp32_01'"
        )
        connection.commit()

    response = _post_preflight(client, expected_trust_score=100)

    assert response.status_code == 200
    body = response.json()
    assert body["can_execute"] is False
    assert body["failure_code"] == "INVALID_DEVICE_STATUS"


def test_recovery_preflight_rejects_trust_score_mismatch(api_client) -> None:
    client, db_path, _ = api_client

    response = _post_preflight(client, expected_trust_score=40)

    assert response.status_code == 200
    assert response.json()["failure_code"] == "TRUST_SCORE_MISMATCH"
    assert _device_state(db_path) == ("isolated", 20)


@pytest.mark.parametrize("status", ["PENDING", "APPLIED"])
def test_recovery_preflight_rejects_active_firewall_db_state(
    api_client,
    status: str,
) -> None:
    client, db_path, _ = api_client
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO firewall_rules (device_id, source_ip, status)
            VALUES ('esp32_01', '192.168.0.21', ?)
            """,
            (status,),
        )
        connection.commit()

    response = _post_preflight(client)

    assert response.status_code == 200
    body = response.json()
    assert body["can_execute"] is False
    assert body["failure_code"] == "ACTIVE_FIREWALL_RULE"
    assert body["firewall_db_state"]["rules"][0]["status"] == status


def test_recovery_preflight_fails_closed_when_runtime_firewall_unavailable(
    api_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, _ = api_client
    monkeypatch.setattr(
        recovery_command_service,
        "firewall_runtime_verifier",
        recovery_command_service._runtime_verification_unavailable,
    )

    response = _post_preflight(client)

    assert response.status_code == 200
    body = response.json()
    assert body["can_execute"] is False
    assert body["result"] == "HOLD"
    assert body["failure_code"] == "FIREWALL_RUNTIME_UNAVAILABLE"


def test_recovery_preflight_rejects_unprocessed_detection_event(api_client) -> None:
    client, db_path, _ = api_client
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO detection_events (
                device_id, detector_type, event_type, severity,
                score_delta, applied_to_score, detected_at, processed_at
            )
            VALUES (
                'esp32_01', 'RULE', 'PACKET_RATE_ANOMALY', 'high',
                -20, 0, '2026-08-10T00:00:00Z', NULL
            )
            """
        )
        connection.commit()

    response = _post_preflight(client)

    assert response.status_code == 200
    body = response.json()
    assert body["can_execute"] is False
    assert body["failure_code"] == "UNPROCESSED_DETECTION_EVENTS"
    assert body["unprocessed_detection_count"] == 1


def test_recovery_execute_requires_admin_and_does_not_call_core(
    api_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, _ = api_client
    calls = {"count": 0}

    def fail_if_called(**_kwargs: object) -> dict[str, object]:
        calls["count"] += 1
        raise AssertionError("core must not be called")

    monkeypatch.setattr(
        recovery_command_service,
        "execute_baseline_recovery",
        fail_if_called,
    )

    response = client.post(
        "/api/recovery/execute",
        json={
            "device_id": "esp32_01",
            "expected_trust_score": 20,
            "reason": "release verified",
            "confirm": CONFIRMATION,
        },
    )

    assert response.status_code == 401
    assert calls["count"] == 0


def test_recovery_execute_requires_explicit_confirmation(api_client) -> None:
    client, db_path, artifact_dir = api_client

    response = _post_execute(client, confirm="yes")

    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["result"] == "DENIED"
    assert detail["failure_code"] == "APPROVAL_CONFIRMATION_MISSING"
    assert _device_state(db_path) == ("isolated", 20)
    assert len(list(artifact_dir.glob("*.db"))) == 0


def test_recovery_execute_uses_authenticated_principal_not_body_value(
    api_client,
) -> None:
    client, db_path, artifact_dir = api_client

    response = _post_execute(client, approved_by="spoofed-admin")

    assert response.status_code == 200
    body = response.json()
    assert body["result"] == "SUCCESS"
    assert body["requested_by"] == "operator@example"
    assert body["approved_by"] == "operator@example"
    assert body["before_status"] == "isolated"
    assert body["before_trust_score"] == 20
    assert body["after_status"] == "normal"
    assert body["after_trust_score"] == 100
    assert body["backup_sha256"]
    assert _device_state(db_path) == ("normal", 100)

    audit = json.loads(next(artifact_dir.glob("baseline-recovery-*.json")).read_text(encoding="utf-8"))
    assert audit["audit"]["approved_by"] == "operator@example"
    assert "spoofed-admin" not in json.dumps(audit, ensure_ascii=False)


def test_duplicate_recovery_does_not_create_second_backup(api_client) -> None:
    client, _, artifact_dir = api_client

    first = _post_execute(client)
    second = _post_execute(client)

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["detail"]["failure_code"] == "INVALID_DEVICE_STATUS"
    assert len(list(artifact_dir.glob("baseline-recovery-*.db"))) == 1


def test_execute_backup_unavailable_returns_hold_without_state_change(
    api_client,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    client, db_path, _ = api_client
    artifact_file = tmp_path / "not-a-directory"
    artifact_file.write_text("occupied", encoding="utf-8")
    monkeypatch.setattr(settings, "recovery_artifact_dir", str(artifact_file))

    response = _post_execute(client)

    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["result"] == "HOLD"
    assert detail["failure_code"] == "BACKUP_UNAVAILABLE"
    assert _device_state(db_path) == ("isolated", 20)


def test_execute_core_failure_is_not_reported_as_success(
    api_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, db_path, artifact_dir = api_client

    def fail_core(**_kwargs: object) -> dict[str, object]:
        raise BaselineRecoveryError("forced core failure")

    monkeypatch.setattr(
        recovery_command_service,
        "execute_baseline_recovery",
        fail_core,
    )

    response = _post_execute(client)

    assert response.status_code == 500
    assert response.json()["detail"]["failure_code"] == "BASELINE_RECOVERY_CORE_FAILED"
    assert _device_state(db_path) == ("isolated", 20)
    history = client.get("/api/recovery/history", headers=ADMIN_HEADERS)
    assert history.status_code == 200
    assert history.json()["items"][0]["result"] == "FAILED"
    assert history.json()["items"][0]["failure_code"] == "BASELINE_RECOVERY_CORE_FAILED"
    assert list(artifact_dir.glob("recovery-command-*.json"))


def test_recovery_history_api_returns_success_audit_without_absolute_backup_path(
    api_client,
) -> None:
    client, _, _ = api_client
    execute = _post_execute(client)
    operation_id = execute.json()["operation_id"]

    list_response = client.get("/api/recovery/history", headers=ADMIN_HEADERS)
    item_response = client.get(
        f"/api/recovery/history/{operation_id}",
        headers=ADMIN_HEADERS,
    )

    assert list_response.status_code == 200
    item = list_response.json()["items"][0]
    assert item["operation_id"] == operation_id
    assert item["result"] == "SUCCESS"
    assert item["backup_reference"].startswith("baseline-recovery-")
    assert "\\" not in item["backup_reference"]
    assert "/" not in item["backup_reference"]
    assert item_response.status_code == 200
    assert item_response.json()["operation_id"] == operation_id


def test_recovery_preserves_existing_history_tables(api_client) -> None:
    client, db_path, _ = api_client
    _seed_preserved_history(db_path)
    before = {
        table: _row_count(db_path, table)
        for table in (
            "detection_events",
            "trust_score_history",
            "isolation_history",
            "firewall_rules",
            "detector_checkpoints",
            "packet_capture_sessions",
            "packet_capture_segments",
            "packet_feature_logs",
            "trust_score_compensations",
        )
    }

    response = _post_execute(client)

    assert response.status_code == 200
    assert {
        table: _row_count(db_path, table)
        for table in before
    } == before


def test_trust_compensation_read_api_returns_audit_rows(api_client) -> None:
    client, db_path, _ = api_client
    _seed_compensation(db_path)

    response = client.get(
        "/api/trust-score/compensations",
        headers=ADMIN_HEADERS,
        params={"device_id": "esp32_01"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["operation_id"] == "comp-op-1"
    assert item["reason"] == "false positive"
    assert item["approved_by"] == "operator@example"
    assert item["backup_reference"] == "trust-compensation.db"


def _row_count(db_path: Path, table: str) -> int:
    with sqlite3.connect(db_path) as connection:
        return int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])


def _seed_preserved_history(db_path: Path) -> None:
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        event_id = connection.execute(
            """
            INSERT INTO detection_events (
                device_id, detector_type, event_type, severity,
                score_delta, applied_to_score, detected_at,
                processed_at, processing_reason
            )
            VALUES (
                'esp32_01', 'RULE', 'PACKET_RATE_ANOMALY', 'high',
                -20, 1, '2026-08-10T00:00:00Z',
                '2026-08-10T00:00:01Z', 'APPLIED_TO_TRUST'
            )
            """
        ).lastrowid
        history_id = connection.execute(
            """
            INSERT INTO trust_score_history (
                device_id, analysis_window_start, analysis_window_end,
                previous_score, calculated_delta, capped_delta, actual_delta,
                new_score, representative_event_ids_json, policy_version
            )
            VALUES (
                'esp32_01', '2026-08-10T00:00:00Z',
                '2026-08-10T00:00:10Z', 40, -20, -20, -20,
                20, ?, 'trust-score-v2'
            )
            """,
            (json.dumps([event_id]),),
        ).lastrowid
        connection.execute(
            """
            INSERT INTO isolation_history (
                device_id, action, reason, trust_score,
                trigger_event_id, trust_score_history_id
            )
            VALUES ('esp32_01', 'ISOLATED', 'Trust Score below threshold', 20, ?, ?)
            """,
            (event_id, history_id),
        )
        connection.execute(
            """
            INSERT INTO firewall_rules (
                device_id, source_ip, status, trigger_event_id,
                applied_at, released_at
            )
            VALUES (
                'esp32_01', '192.168.0.21', 'REMOVED', ?,
                '2026-08-10T00:00:02Z', '2026-08-10T00:00:03Z'
            )
            """,
            (event_id,),
        )
        connection.execute(
            """
            INSERT INTO detector_checkpoints (
                detector_name, source_table, last_processed_id,
                last_completed_window_end
            )
            VALUES ('trust_score_v2', 'detection_events', 1, '2026-08-10T00:00:10Z')
            """
        )
        session_pk = connection.execute(
            """
            INSERT INTO packet_capture_sessions (
                session_id, capture_interface, started_at,
                first_window_start, ended_at, status
            )
            VALUES (
                '11111111-1111-4111-8111-111111111111', 'eth0',
                '2026-08-10T00:00:00Z', '2026-08-10T00:00:00Z',
                '2026-08-10T00:00:10Z', 'COMPLETED'
            )
            """
        ).lastrowid
        segment_pk = connection.execute(
            """
            INSERT INTO packet_capture_segments (
                capture_session_id, file_name, capture_interface,
                window_start, window_end, status, packet_count, processed_at
            )
            VALUES (
                ?, 'preserved.pcap', 'eth0', '2026-08-10T00:00:00Z',
                '2026-08-10T00:00:10Z', 'PROCESSED', 1,
                '2026-08-10T00:00:11Z'
            )
            """,
            (session_pk,),
        ).lastrowid
        connection.execute(
            """
            INSERT INTO packet_feature_logs (
                capture_segment_id, device_id, peer_ip, direction,
                window_start, window_end, packet_count, total_bytes,
                avg_packet_size, max_packet_size
            )
            VALUES (
                ?, 'esp32_01', '192.168.0.21', 'INBOUND',
                '2026-08-10T00:00:00Z', '2026-08-10T00:00:10Z',
                1, 100, 100.0, 100
            )
            """,
            (segment_pk,),
        )
        _insert_compensation(connection, event_id=event_id, history_id=history_id)
        connection.commit()


def _seed_compensation(db_path: Path) -> None:
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        event_id = connection.execute(
            """
            INSERT INTO detection_events (
                device_id, detector_type, event_type, severity,
                score_delta, applied_to_score, detected_at,
                processed_at, processing_reason
            )
            VALUES (
                'esp32_01', 'RULE', 'ABNORMAL_TOPIC', 'high',
                -20, 1, '2026-08-10T00:00:00Z',
                '2026-08-10T00:00:01Z', 'APPLIED_TO_TRUST'
            )
            """
        ).lastrowid
        history_id = connection.execute(
            """
            INSERT INTO trust_score_history (
                device_id, analysis_window_start, analysis_window_end,
                previous_score, calculated_delta, capped_delta, actual_delta,
                new_score, representative_event_ids_json, policy_version
            )
            VALUES (
                'esp32_01', '2026-08-10T00:00:00Z',
                '2026-08-10T00:00:10Z', 40, -20, -20, -20,
                20, ?, 'trust-score-v2'
            )
            """,
            (json.dumps([event_id]),),
        ).lastrowid
        _insert_compensation(connection, event_id=event_id, history_id=history_id)
        connection.commit()


def _insert_compensation(
    connection: sqlite3.Connection,
    *,
    event_id: int,
    history_id: int,
) -> None:
    connection.execute(
        """
        INSERT INTO trust_score_compensations (
            operation_id, device_id, source_event_id,
            source_trust_history_id, previous_score,
            compensation_delta, new_score, reason, approved_by,
            backup_path, backup_sha256
        )
        VALUES (
            'comp-op-1', 'esp32_01', ?, ?, 80, 20, 100,
            'false positive', 'operator@example',
            '/safe/artifacts/trust-compensation.db',
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        )
        """,
        (event_id, history_id),
    )
