"""Device policy HTTP contracts, using temporary databases only."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import sqlite3

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.main import app
from db.migration_runner import MIGRATIONS_DIR, apply_migrations


ADMIN_HEADERS = {"X-Recovery-Admin-Key": "test-secret"}
T0 = datetime(2026, 10, 2, 0, 0, 3, tzinfo=timezone.utc)
POLICY = {
    "policy_profile": "periodic-sensor-v1",
    "expected_publish_interval_seconds": 5.0,
    "publish_count_max": 15,
    "payload_size_max_bytes": 5120,
    "packet_rate_max_pps": 10.0,
    "byte_rate_max_bytes_per_second": 2500.0,
}


@pytest.fixture
def api_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request):
    from backend.app.services import device_policy_service

    db_path = tmp_path / "device-policy-api.db"
    migrations = MIGRATIONS_DIR
    migration_limit = {"legacy": 6, "pre012": 11}.get(getattr(request, "param", None))
    if migration_limit is not None:
        migrations = tmp_path / "partial-migrations"
        migrations.mkdir()
        for source in MIGRATIONS_DIR.glob("*.sql"):
            if int(source.name.split("_", 1)[0]) <= migration_limit:
                shutil.copyfile(source, migrations / source.name)
    apply_migrations(db_path, migrations)

    database_url = f"sqlite:///{db_path.as_posix()}"
    engine = create_engine(database_url, connect_args={"check_same_thread": False})
    sessions = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        with sessions() as db:
            db.execute(text("PRAGMA foreign_keys = ON"))
            yield db

    clock = {"now": T0}
    monkeypatch.setattr(device_policy_service, "utc_now", lambda: clock["now"])
    monkeypatch.setattr(settings, "database_url", database_url)
    monkeypatch.setattr(settings, "device_registration_cidr", "192.168.0.0/24")
    monkeypatch.setattr(settings, "recovery_admin_api_key", "test-secret")
    monkeypatch.setattr(settings, "recovery_admin_principal", "policy-test-admin")
    monkeypatch.setattr(settings, "firewall_lock_path", str(tmp_path / "firewall.lock"))
    monkeypatch.setattr(settings, "firewall_lock_wait_seconds", 0)
    monkeypatch.setattr(settings, "firewall_protected_ips", "192.168.0.1")
    monkeypatch.setattr(settings, "capture_interface_ip", "192.168.0.2")
    monkeypatch.setattr(settings, "packet_rule_excluded_peer_ips", "192.168.0.3")
    previous_override = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            yield client, db_path, clock
    finally:
        if previous_override is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous_override
        engine.dispose()


def registration(**changes):
    return {
        "device_id": "pico_01",
        "ip_address": "192.168.0.6",
        "device_type": "SENSOR",
        "mqtt_principal": "pico_01",
        "policy": dict(POLICY),
        "reason": "  initial device registration  ",
        **changes,
    }


def revision(*, expected=1, state="ACTIVE", policy=None):
    return {
        "expected_revision": expected,
        "registration_state": state,
        "policy": dict(POLICY) if policy is None else policy,
        "reason": "operator approved policy change",
    }


def create_device(client, **changes):
    response = client.post("/api/devices", json=registration(**changes), headers=ADMIN_HEADERS)
    assert response.status_code == 201, response.text
    return response.json()


def change_policy(client, **changes):
    return client.post(
        "/api/devices/pico_01/policy-revisions",
        json=revision(**changes),
        headers=ADMIN_HEADERS,
    )


def rows(db_path, sql, params=()):
    with sqlite3.connect(db_path) as connection:
        return connection.execute(sql, params).fetchall()


def write(db_path, sql, params=()):
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(sql, params)


def assert_business_error(response, status, code):
    assert response.status_code == status, response.text
    detail = response.json()["detail"]
    assert detail["code"] == code
    assert isinstance(detail["message"], str) and detail["message"].strip()
    return detail


def assert_validation_error(response, field):
    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert isinstance(detail, list) and detail
    assert any(field in error["loc"] for error in detail), detail


def test_registration_commits_initial_revision_and_preserves_read_envelopes(api_client):
    client, db_path, _ = api_client
    body = create_device(client)

    assert set(body) == {"device", "policy"}
    device = body["device"]
    assert device["device_id"] == "pico_01"
    assert device["ip_address"] == "192.168.0.6"
    assert device["device_type"] == "SENSOR"
    assert device["mqtt_principal"] == "pico_01"
    assert device["mqtt_topic"] == "iot/pico_01/sensor"
    assert device["status"] == "normal"
    assert device["trust_score"] == 100
    assert device["last_seen_at"] is None
    assert device["registration_state"] == "PENDING"
    assert device["registration_effective_from"] == "2026-10-02T00:00:10Z"
    assert device["current_policy_revision"] is None
    assert device["pending_policy_revision"] == 1
    assert device["auto_response_eligible"] is False
    assert device["auto_response_exclusion_reason"] == "REGISTRATION_NOT_EFFECTIVE"
    snapshot = body["policy"]
    assert set(snapshot) == {"device_id", "server_time", "latest_revision", "current", "pending", "expected_instance_id"}
    assert snapshot["expected_instance_id"] == rows(db_path, "SELECT registration_instance_id FROM devices")[0][0]
    assert snapshot["device_id"] == "pico_01"
    assert datetime.fromisoformat(snapshot["server_time"].replace("Z", "+00:00")) == T0
    assert snapshot["latest_revision"] == 1
    assert snapshot["current"] is None
    assert snapshot["pending"]["revision"] == 1
    assert snapshot["pending"]["policy"] == POLICY
    assert snapshot["pending"]["created_by"] == "policy-test-admin"
    assert snapshot["pending"]["reason"] == "initial device registration"
    assert rows(db_path, "SELECT device_id, revision, created_by FROM device_policy_revisions") == [
        ("pico_01", 1, "policy-test-admin")
    ]
    assert client.get("/api/devices/pico_01").json() == device
    assert client.get("/api/devices").json() == {"items": [device], "total": 1}
    assert client.get("/api/devices/pico_01/policy").json() == snapshot


@pytest.mark.parametrize("kind", ["registration", "revision"])
@pytest.mark.parametrize("headers", [{}, {"X-Recovery-Admin-Key": "wrong-key"}])
def test_writes_require_admin_without_mutation(api_client, kind, headers):
    client, db_path, _ = api_client
    path, body = ("/api/devices", registration()) if kind == "registration" else (
        "/api/devices/pico_01/policy-revisions", revision()
    )
    response = client.post(path, json=body, headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "RECOVERY_ADMIN_UNAUTHORIZED"}
    assert rows(db_path, "SELECT device_id FROM devices") == []
    assert rows(db_path, "SELECT revision FROM device_policy_revisions") == []


@pytest.mark.parametrize("kind", ["registration", "revision"])
def test_unconfigured_admin_key_fails_closed(api_client, monkeypatch, kind):
    client, db_path, _ = api_client
    monkeypatch.setattr(settings, "recovery_admin_api_key", "")
    path, body = ("/api/devices", registration()) if kind == "registration" else (
        "/api/devices/pico_01/policy-revisions", revision()
    )
    response = client.post(path, json=body, headers=ADMIN_HEADERS)
    assert response.status_code == 503
    assert response.json() == {"detail": "RECOVERY_ADMIN_NOT_CONFIGURED"}
    assert rows(db_path, "SELECT device_id FROM devices") == []


@pytest.mark.parametrize("field,value", [
    ("publish_count_max", True), ("publish_count_max", "15"),
    ("publish_count_max", 15.0), ("publish_count_max", None),
    ("publish_count_max", 0), ("publish_count_max", 10001),
    ("payload_size_max_bytes", False), ("payload_size_max_bytes", "5120"),
    ("payload_size_max_bytes", 1048577),
    ("expected_publish_interval_seconds", True),
    ("expected_publish_interval_seconds", "5"),
    ("expected_publish_interval_seconds", 0),
    ("expected_publish_interval_seconds", 86401),
    ("packet_rate_max_pps", "10"), ("packet_rate_max_pps", False),
    ("packet_rate_max_pps", 100001),
    ("byte_rate_max_bytes_per_second", None),
    ("byte_rate_max_bytes_per_second", 125000001),
])
def test_policy_values_are_strict_at_http_boundary(api_client, field, value):
    client, db_path, _ = api_client
    response = client.post(
        "/api/devices", json=registration(policy={**POLICY, field: value}), headers=ADMIN_HEADERS
    )
    assert_validation_error(response, field)
    assert rows(db_path, "SELECT device_id FROM devices") == []


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_nonfinite_json_returns_serializable_validation_error(api_client, token):
    client, db_path, _ = api_client
    body = json.dumps(registration(policy={**POLICY, "packet_rate_max_pps": "NONFINITE"}))
    response = client.post(
        "/api/devices",
        content=body.replace('"NONFINITE"', token),
        headers={**ADMIN_HEADERS, "Content-Type": "application/json"},
    )
    assert_validation_error(response, "packet_rate_max_pps")
    assert rows(db_path, "SELECT device_id FROM devices") == []


def test_numeric_upper_bounds_and_integer_number_inputs_are_accepted(api_client):
    client, _, _ = api_client
    policy = {
        **POLICY,
        "expected_publish_interval_seconds": 86400,
        "publish_count_max": 10000,
        "payload_size_max_bytes": 1048576,
        "packet_rate_max_pps": 100000,
        "byte_rate_max_bytes_per_second": 125000000,
    }
    body = create_device(client, policy=policy)
    assert body["policy"]["pending"]["policy"] == policy


@pytest.mark.parametrize("field,value", [
    ("registration_state", "ACTIVE"), ("created_by", "spoofed-admin"),
    ("revision", 100), ("effective_from", "2020-01-01T00:00:00Z"),
    ("trust_score", 100), ("mqtt_topic", "iot/other/sensor"),
    ("dhcp_verified", True), ("password", "not-a-secret"),
])
def test_registration_rejects_server_owned_and_unsupported_fields(api_client, field, value):
    client, db_path, _ = api_client
    response = client.post("/api/devices", json=registration(**{field: value}), headers=ADMIN_HEADERS)
    assert_validation_error(response, field)
    assert rows(db_path, "SELECT device_id FROM devices") == []


def test_policy_rejects_unknown_or_missing_fields(api_client):
    client, _, _ = api_client
    extra = client.post(
        "/api/devices", json=registration(policy={**POLICY, "ai_enabled": True}), headers=ADMIN_HEADERS
    )
    assert_validation_error(extra, "ai_enabled")
    missing_policy = dict(POLICY)
    del missing_policy["publish_count_max"]
    missing = client.post(
        "/api/devices", json=registration(policy=missing_policy), headers=ADMIN_HEADERS
    )
    assert_validation_error(missing, "publish_count_max")


@pytest.mark.parametrize("field,value", [
    ("device_id", "sensor/+"), ("device_id", "한글"),
    ("device_type", "sensor"), ("mqtt_principal", "a/b"),
    ("reason", "   "), ("reason", "line1\nline2"),
    ("reason", "a" * 501),
])
def test_identity_and_reason_validation(api_client, field, value):
    client, db_path, _ = api_client
    response = client.post("/api/devices", json=registration(**{field: value}), headers=ADMIN_HEADERS)
    assert_validation_error(response, field)
    assert rows(db_path, "SELECT device_id FROM devices") == []


@pytest.mark.parametrize("address", [
    "192.168.0.0", "192.168.0.255", "192.168.0.1", "192.168.0.2", "192.168.0.3",
    "192.168.1.6", "10.1.0.6", "127.0.0.1", "8.8.8.8", "::1", "192.168.000.6",
])
def test_registration_rejects_nonhost_protected_and_outside_lan_ips(api_client, address):
    client, db_path, _ = api_client
    response = client.post("/api/devices", json=registration(ip_address=address), headers=ADMIN_HEADERS)
    assert_validation_error(response, "ip_address")
    assert rows(db_path, "SELECT device_id FROM devices") == []


@pytest.mark.parametrize("cidr", ["", "not-a-cidr", "8.8.8.0/24"])
def test_missing_or_invalid_lan_configuration_blocks_write(api_client, monkeypatch, cidr):
    client, db_path, _ = api_client
    monkeypatch.setattr(settings, "device_registration_cidr", cidr)
    response = client.post("/api/devices", json=registration(), headers=ADMIN_HEADERS)
    assert_business_error(response, 503, "DEVICE_POLICY_CONFIG_UNAVAILABLE")
    assert rows(db_path, "SELECT device_id FROM devices") == []


@pytest.mark.parametrize("changes,code", [
    ({"ip_address": "192.168.0.7"}, "DEVICE_ID_CONFLICT"),
    ({"device_id": "pico_02", "mqtt_principal": "pico_02"}, "DEVICE_IP_CONFLICT"),
])
def test_duplicate_identity_or_ip_does_not_partially_register(api_client, changes, code):
    client, db_path, _ = api_client
    create_device(client)
    before = rows(db_path, "SELECT * FROM device_policy_revisions")
    response = client.post("/api/devices", json=registration(**changes), headers=ADMIN_HEADERS)
    assert_business_error(response, 409, code)
    assert rows(db_path, "SELECT device_id FROM devices") == [("pico_01",)]
    assert rows(db_path, "SELECT * FROM device_policy_revisions") == before


def test_pending_activation_uses_strict_next_boundary_and_then_becomes_current(api_client):
    client, db_path, clock = api_client
    create_device(client)
    clock["now"] = T0.replace(second=10)
    initial = client.get("/api/devices/pico_01/policy").json()
    assert initial["current"]["revision"] == 1
    assert initial["current"]["registration_state"] == "PENDING"
    assert initial["pending"] is None

    response = change_policy(client)
    assert response.status_code == 201, response.text
    body = response.json()
    assert set(body) == {"device_id", "server_time", "latest_revision", "current", "pending", "expected_instance_id"}
    assert body["expected_instance_id"] == initial["expected_instance_id"]
    assert body["latest_revision"] == 2
    assert body["current"]["revision"] == 1
    assert body["current"]["registration_state"] == "PENDING"
    assert body["pending"]["revision"] == 2
    assert body["pending"]["registration_state"] == "ACTIVE"
    assert body["pending"]["effective_from"] == "2026-10-02T00:00:20Z"
    before = client.get("/api/devices/pico_01").json()
    assert before["registration_state"] == "PENDING"
    assert before["current_policy_revision"] == 1
    assert before["pending_policy_revision"] == 2
    assert before["auto_response_eligible"] is False

    clock["now"] = T0.replace(second=20)
    after = client.get("/api/devices/pico_01").json()
    assert after["registration_state"] == "ACTIVE"
    assert after["current_policy_revision"] == 2
    assert after["pending_policy_revision"] is None
    assert after["auto_response_eligible"] is True
    assert after["auto_response_exclusion_reason"] is None
    final = client.get("/api/devices/pico_01/policy").json()
    assert final["current"] == body["pending"]
    assert final["pending"] is None
    assert rows(db_path, "SELECT revision FROM device_policy_revisions ORDER BY revision") == [(1,), (2,)]


def test_pending_revision_conflict_includes_revision_context(api_client):
    client, db_path, clock = api_client
    create_device(client)
    initial = assert_business_error(change_policy(client), 409, "PENDING_REVISION_EXISTS")
    assert initial["current_revision"] is None
    assert initial["pending_revision"] == 1
    assert initial["latest_revision"] == 1
    clock["now"] = T0 + timedelta(seconds=10)
    assert change_policy(client).status_code == 201
    detail = assert_business_error(change_policy(client, expected=2), 409, "PENDING_REVISION_EXISTS")
    assert detail["current_revision"] == 1
    assert detail["pending_revision"] == 2
    assert detail["latest_revision"] == 2
    assert rows(db_path, "SELECT revision FROM device_policy_revisions ORDER BY revision") == [(1,), (2,)]


def test_stale_expected_revision_is_checked_after_pending_takes_effect(api_client):
    client, db_path, clock = api_client
    create_device(client)
    clock["now"] = T0 + timedelta(seconds=10)
    assert change_policy(client).status_code == 201
    clock["now"] = T0 + timedelta(seconds=20)
    detail = assert_business_error(change_policy(client), 409, "REVISION_CONFLICT")
    assert detail["current_revision"] == 2
    assert detail["pending_revision"] is None
    assert detail["latest_revision"] == 2
    assert rows(db_path, "SELECT revision FROM device_policy_revisions ORDER BY revision") == [(1,), (2,)]


def test_identical_policy_and_state_cannot_create_a_revision(api_client):
    client, db_path, clock = api_client
    create_device(client)
    clock["now"] = T0 + timedelta(seconds=10)
    assert_business_error(change_policy(client, state="PENDING"), 409, "NO_POLICY_CHANGE")
    assert rows(db_path, "SELECT revision FROM device_policy_revisions") == [(1,)]


@pytest.mark.parametrize("value", [True, "1", 1.0, 0, 2147483648])
def test_revision_number_is_strict(api_client, value):
    client, db_path, clock = api_client
    create_device(client)
    clock["now"] = T0 + timedelta(seconds=10)
    assert_validation_error(change_policy(client, expected=value), "expected_revision")
    assert rows(db_path, "SELECT revision FROM device_policy_revisions") == [(1,)]


def test_policy_change_requires_complete_policy_and_rejects_identity_edits(api_client):
    client, db_path, clock = api_client
    create_device(client)
    clock["now"] = T0 + timedelta(seconds=10)
    incomplete = revision()
    del incomplete["policy"]
    response = client.post("/api/devices/pico_01/policy-revisions", json=incomplete, headers=ADMIN_HEADERS)
    assert_validation_error(response, "policy")
    response = client.post(
        "/api/devices/pico_01/policy-revisions",
        json={**revision(), "ip_address": "192.168.0.7"},
        headers=ADMIN_HEADERS,
    )
    assert_validation_error(response, "ip_address")
    assert rows(db_path, "SELECT revision FROM device_policy_revisions") == [(1,)]


def test_policy_update_appends_audit_without_resetting_existing_trust(api_client):
    client, db_path, clock = api_client
    create_device(client)
    write(db_path, "UPDATE devices SET trust_score=47, status='danger', last_seen_at=? WHERE device_id=?",
          ("2026-10-02T00:00:05Z", "pico_01"))
    write(db_path, """
        INSERT INTO trust_score_history (
            device_id, analysis_window_start, analysis_window_end, previous_score,
            calculated_delta, capped_delta, actual_delta, new_score,
            representative_event_ids_json, policy_version, created_at
        ) VALUES ('pico_01', '2026-10-01T23:59:50Z', '2026-10-02T00:00:00Z',
                  67, -20, -20, -20, 47, '[]', 'trust-score-v2', '2026-10-02T00:00:00Z')
    """)
    old_device = rows(db_path, "SELECT * FROM devices")
    old_revision = rows(db_path, "SELECT * FROM device_policy_revisions")
    old_history = rows(db_path, "SELECT * FROM trust_score_history")
    clock["now"] = T0 + timedelta(seconds=10)
    changed = {**POLICY, "publish_count_max": 25}
    response = change_policy(client, state="PENDING", policy=changed)
    assert response.status_code == 201, response.text
    assert response.json()["current"]["policy"] == POLICY
    pending = response.json()["pending"]
    assert pending["policy"] == changed
    assert pending["created_by"] == "policy-test-admin"
    assert pending["reason"] == "operator approved policy change"
    assert rows(db_path, "SELECT * FROM devices") == old_device
    assert rows(db_path, "SELECT * FROM device_policy_revisions WHERE revision=1") == old_revision
    assert rows(db_path, "SELECT * FROM trust_score_history") == old_history
    assert rows(db_path, "SELECT id FROM firewall_rules") == []
    assert rows(db_path, "SELECT id FROM isolation_history") == []


def test_registered_device_without_policy_keeps_read_api_but_blocks_policy_commands(api_client):
    client, db_path, _ = api_client
    write(db_path, "INSERT INTO devices (device_id, ip_address, status, trust_score) VALUES (?, ?, ?, ?)",
          ("pico_01", "192.168.0.6", "warning", 73))
    detail = client.get("/api/devices/pico_01")
    assert detail.status_code == 200
    body = detail.json()
    assert body["status"] == "warning" and body["trust_score"] == 73
    assert body["registration_state"] is None
    assert body["current_policy_revision"] is None
    assert body["pending_policy_revision"] is None
    assert body["auto_response_eligible"] is False
    assert body["auto_response_exclusion_reason"] == "POLICY_UNAVAILABLE"
    assert client.get("/api/devices").json() == {"items": [body], "total": 1}
    assert_business_error(client.get("/api/devices/pico_01/policy"), 503, "POLICY_UNAVAILABLE")
    assert_business_error(change_policy(client), 503, "POLICY_UNAVAILABLE")
    assert rows(db_path, "SELECT revision FROM device_policy_revisions") == []


@pytest.mark.parametrize("api_client", ["legacy"], indirect=True)
def test_pre007_database_remains_readable_and_policy_access_fails_closed(api_client):
    client, db_path, _ = api_client
    write(db_path, "INSERT INTO devices (device_id, ip_address, status, trust_score) VALUES (?, ?, ?, ?)",
          ("esp32_01", "192.168.0.21", "normal", 80))
    response = client.get("/api/devices")
    assert response.status_code == 200, response.text
    assert response.json()["total"] == 1
    item = response.json()["items"][0]
    assert item["device_id"] == "esp32_01"
    assert item["trust_score"] == 80
    assert item["registration_state"] is None
    assert item["auto_response_eligible"] is False
    assert item["auto_response_exclusion_reason"] == "POLICY_UNAVAILABLE"
    assert client.get("/api/devices/esp32_01").json() == item
    assert_business_error(client.get("/api/devices/esp32_01/policy"), 503, "POLICY_UNAVAILABLE")
    response = client.post("/api/devices", json=registration(), headers=ADMIN_HEADERS)
    assert_business_error(response, 503, "POLICY_UNAVAILABLE")
    assert rows(db_path, "SELECT device_id FROM devices") == [("esp32_01",)]


def test_missing_device_preserves_old_get_error_and_new_policy_error(api_client):
    client, _, _ = api_client
    old = client.get("/api/devices/missing")
    assert old.status_code == 404
    assert old.json() == {"detail": "Device not found"}
    assert_business_error(client.get("/api/devices/missing/policy"), 404, "DEVICE_NOT_FOUND")
    assert_business_error(change_policy(client), 404, "DEVICE_NOT_FOUND")


@pytest.mark.parametrize("method,suffix", [("GET", "policy"), ("POST", "policy-revisions")])
@pytest.mark.parametrize("invalid_id", ["bad%20id", "a" * 65])
def test_invalid_policy_path_identifies_path_parameter(api_client, method, suffix, invalid_id):
    client, db_path, _ = api_client
    kwargs = {"json": revision(), "headers": ADMIN_HEADERS} if method == "POST" else {}
    response = client.request(method, f"/api/devices/{invalid_id}/{suffix}", **kwargs)
    assert_validation_error(response, "device_id")
    assert [item["loc"] for item in response.json()["detail"]] == [["path", "device_id"]]
    assert rows(db_path, "SELECT device_id FROM devices") == []
    assert rows(db_path, "SELECT revision FROM device_policy_revisions") == []


def test_list_pagination_and_trust_filter_do_not_duplicate_revision_rows(api_client):
    client, db_path, clock = api_client
    create_device(client)
    create_device(client, device_id="pico_02", ip_address="192.168.0.7", mqtt_principal="pico_02")
    clock["now"] = T0 + timedelta(seconds=10)
    assert change_policy(client).status_code == 201
    write(db_path, "UPDATE devices SET status='warning', trust_score=73 WHERE device_id='pico_02'")
    page = client.get("/api/devices", params={"limit": 1, "offset": 1})
    assert page.status_code == 200
    assert page.json()["total"] == 2
    assert [item["device_id"] for item in page.json()["items"]] == ["pico_02"]
    filtered = client.get("/api/devices", params={"status": "normal"}).json()
    assert filtered["total"] == 1
    assert [item["device_id"] for item in filtered["items"]] == ["pico_01"]
    assert client.get("/api/devices", params={"status": "PENDING"}).status_code == 422


@pytest.mark.parametrize("api_client", ["pre012"], indirect=True)
def test_pre012_registration_returns_unavailable_and_rolls_back(api_client):
    client, db_path, _ = api_client
    assert rows(db_path, "SELECT max(version) FROM schema_migrations") == [(11,)]
    response = client.post("/api/devices", json=registration(), headers=ADMIN_HEADERS)
    assert_business_error(response, 503, "AI_POLICY_UNAVAILABLE")
    assert rows(db_path, "SELECT device_id FROM devices") == []
    assert rows(db_path, "SELECT revision FROM device_policy_revisions") == []


def test_partial_ai_schema_registration_returns_unavailable_and_rolls_back(api_client):
    client, db_path, _ = api_client
    write(db_path, "ALTER TABLE device_ai_policy_revisions RENAME COLUMN reason TO missing_reason")
    response = client.post("/api/devices", json=registration(), headers=ADMIN_HEADERS)
    assert_business_error(response, 503, "AI_POLICY_UNAVAILABLE")
    assert rows(db_path, "SELECT device_id FROM devices") == []
    assert rows(db_path, "SELECT revision FROM device_policy_revisions") == []
    assert rows(db_path, "SELECT revision FROM device_ai_policy_revisions") == []


def test_revision_insert_failure_rolls_back_the_whole_registration(api_client):
    client, db_path, _ = api_client
    write(db_path, """
        CREATE TRIGGER test_reject_policy BEFORE INSERT ON device_policy_revisions
        BEGIN SELECT RAISE(ABORT, 'test revision insert failure'); END
    """)
    response = client.post("/api/devices", json=registration(), headers=ADMIN_HEADERS)
    assert response.status_code == 500
    assert rows(db_path, "SELECT device_id FROM devices") == []
    assert rows(db_path, "SELECT revision FROM device_policy_revisions") == []
