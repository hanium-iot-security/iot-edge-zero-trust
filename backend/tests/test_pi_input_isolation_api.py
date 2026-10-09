"""Authenticated approval queue API; these tests never invoke a firewall."""

from pathlib import Path
import sqlite3
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.main import app
from backend.app.services import firewall_scope_extension_service as service
from backend.app.services import firewall_release_request_service as release_service
from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.runtime_lock import single_instance_lock
from tests.test_pi_input_isolation_repository import NOW, IP, DEVICE, seed_isolated_source, migrations_until


HEADERS = {"X-Recovery-Admin-Key": "local-test-key"}


@pytest.fixture
def api(tmp_path: Path, monkeypatch):
    database = tmp_path / "api.db"
    apply_migrations(database, MIGRATIONS_DIR)
    source = seed_isolated_source(database)
    engine = create_engine(f"sqlite:///{database.as_posix()}", connect_args={"check_same_thread": False, "timeout": 0})
    sessions = sessionmaker(bind=engine)

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    def get_test_db():
        with sessions() as db:
            yield db

    monkeypatch.setattr(settings, "recovery_admin_api_key", "local-test-key")
    monkeypatch.setattr(settings, "recovery_admin_principal", "server-admin")
    monkeypatch.setattr(settings, "firewall_lock_path", str(tmp_path / "worker.lock"))
    monkeypatch.setattr(settings, "firewall_lock_wait_seconds", 0)
    monkeypatch.setattr(service, "_now_utc", lambda: NOW)
    monkeypatch.setattr(release_service, "_now_utc", lambda: NOW)
    app.dependency_overrides[get_db] = get_test_db
    try:
        yield TestClient(app), database, source, sessions
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def body(source, **updates):
    data = {"device_id": DEVICE, "source_ip": IP, "approved_policy_revision": 1,
            "scope": "PI_INPUT_IPV4_ALL", "reason": "audited local scope extension",
            "request_id": str(uuid4()), "confirm": service.scope_extension_confirmation(source, IP, 1)}
    data.update(updates)
    return data


def post(api, request=None, *, source=None, headers=HEADERS):
    client, _, original, _ = api
    identifier = original if source is None else source
    return client.post(f"/api/firewall-rules/{identifier}/scope-extension-requests", json=request or body(identifier), headers=headers)


def count(database, table):
    with sqlite3.connect(database) as connection:
        return connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def test_wide_approval_and_lost_response_replay_return_same_new_pending_id(api):
    client, database, source, _ = api
    request = body(source)
    first, replay = post(api, request), post(api, request)
    assert first.status_code == replay.status_code == 201
    original = first.json()
    assert original["created"] and not original["replayed"] and not original["runtime_verified"]
    item = original["item"]
    assert (item["scope"], item["status"], item["protocol"], item["dest_port"]) == ("PI_INPUT_IPV4_ALL", "PENDING", None, None)
    assert item["id"] != source and item["source_rule_id"] == source
    assert item["requested_by"] == "server-admin" and item["request_id"] == request["request_id"]
    assert replay.json()["item"] == item and replay.json()["replayed"] and not replay.json()["created"]
    assert count(database, "firewall_rules") == 2
    queried = client.get("/api/firewall-rules").json()["items"]
    assert {row["scope"] for row in queried} == {"MQTT_IPV4_TCP_1883", "PI_INPUT_IPV4_ALL"}
    assert count(database, "firewall_release_requests") == count(database, "isolation_history") == count(database, "trust_score_history") == 0


@pytest.mark.parametrize("headers,expected", [(None, 401), ({"X-Recovery-Admin-Key": "wrong"}, 401)])
def test_approval_requires_authenticated_server_principal(api, headers, expected):
    response = post(api, headers=headers)
    assert response.status_code == expected
    assert count(api[1], "firewall_rules") == 1


def test_unconfigured_admin_fails_closed(api, monkeypatch):
    monkeypatch.setattr(settings, "recovery_admin_api_key", "")
    assert post(api).status_code == 503
    assert count(api[1], "firewall_rules") == 1


@pytest.mark.parametrize("field,value", [
    ("requested_by", "SECRET-CALLER-ACTOR"), ("scope", "MQTT_IPV4_TCP_1883"),
    ("scope", "unknown-SECRET-SCOPE"), ("source_ip", "192.168.000.31"),
    ("source_ip", "8.8.8.8"), ("source_ip", "127.0.0.1"), ("source_ip", "::1"),
    ("approved_policy_revision", True), ("approved_policy_revision", "1"),
    ("approved_policy_revision", 0), ("device_id", "SECRET BAD DEVICE"),
    ("reason", ""), ("reason", "   "), ("reason", 42),
    ("request_id", "SECRET INVALID UUID"), ("request_id", "11111111-1111-1111-8111-111111111111"),
    ("request_id", "A1B2C3D4-1111-4111-8111-111111111111"),
])
def test_strict_invalid_request_values_are_not_echoed(api, field, value):
    response = post(api, body(api[2], **{field: value}))
    assert response.status_code == 422
    assert "SECRET" not in response.text and '"input"' not in response.text
    assert count(api[1], "firewall_rules") == 1


@pytest.mark.parametrize("source", [0, -1, 9223372036854775808, "SECRET-PATH"])
def test_invalid_source_id_path_values_not_echoed(api, source):
    response = post(api, body(api[2]), source=source)
    assert response.status_code == 422
    assert "SECRET-PATH" not in response.text and '"input"' not in response.text


def test_confirm_is_bound_to_source_ip_and_revision(api):
    response = post(api, body(api[2], confirm="SECRET WRONG CONFIRM"))
    assert response.status_code == 409
    assert response.json()["detail"]["failure_code"] == "SCOPE_EXTENSION_CONFIRMATION_MISMATCH"
    assert "SECRET" not in response.text and count(api[1], "firewall_rules") == 1


@pytest.mark.parametrize("sql,code", [
    ("UPDATE devices SET status='normal'", "DEVICE_NOT_ISOLATED"),
    ("UPDATE devices SET ip_address='192.168.0.44'", "DEVICE_IP_OWNERSHIP_MISMATCH"),
    ("UPDATE firewall_rules SET status='FAILED'", "SOURCE_RULE_CHANGED"),
    ("UPDATE firewall_rules SET status='PENDING'", "SOURCE_RULE_CHANGED"),
    ("UPDATE firewall_rules SET status='REMOVED'", "SOURCE_RULE_CHANGED"),
])
def test_first_approval_requires_current_isolated_source_applied(api, sql, code):
    with sqlite3.connect(api[1]) as connection:
        connection.execute(sql)
    response = post(api)
    assert response.status_code == 409
    assert response.json()["detail"]["failure_code"] == code
    assert count(api[1], "firewall_rules") == 1


def test_pending_source_release_serializes_with_approval(api):
    client, _, source, _ = api
    response = client.post(f"/api/firewall-rules/{source}/release-requests", json={"reason": "separate source cleanup", "confirm": release_service.release_confirmation_for_rule(source)}, headers=HEADERS)
    assert response.status_code == 201
    approval = post(api)
    assert approval.status_code == 409
    assert approval.json()["detail"]["failure_code"] == "FIREWALL_RELEASE_PENDING"


def test_shared_worker_lock_and_sqlite_writer_lock_deny_without_changes(api):
    with single_instance_lock(Path(settings.firewall_lock_path)):
        response = post(api)
    assert response.status_code == 409
    assert response.json()["detail"]["failure_code"] == "FIREWALL_OPERATION_IN_PROGRESS"
    with sqlite3.connect(api[1], timeout=0) as connection:
        connection.execute("BEGIN IMMEDIATE")
        response = post(api)
        connection.rollback()
    assert response.status_code == 409
    assert response.json()["detail"]["failure_code"] == "FIREWALL_DATABASE_BUSY"
    assert count(api[1], "firewall_rules") == 1


def test_failed_wide_can_only_queue_exact_audited_release(api):
    client, _, _, sessions = api
    wide = post(api).json()["item"]["id"]
    with sessions() as db:
        db.execute(text("UPDATE firewall_rules SET status='FAILED' WHERE id=:id"), {"id": wide})
        db.commit()
    response = client.post(f"/api/firewall-rules/{wide}/release-requests", json={"reason": "runtime residue cleanup", "confirm": release_service.release_confirmation_for_rule(wide)}, headers=HEADERS)
    assert response.status_code == 201
    assert response.json()["item"]["firewall_rule_id"] == wide
    with sessions() as db:
        assert db.execute(text("SELECT status FROM firewall_rules WHERE id=:id"), {"id": wide}).scalar_one() == "FAILED"
    assert post(api).status_code == 409


def test_pre011_database_keeps_read_and_release_but_denies_wide(api, tmp_path):
    client, _, _, _ = api
    database = tmp_path / "pre011.db"
    apply_migrations(database, migrations_until(tmp_path, 10))
    source = seed_isolated_source(database)
    engine = create_engine(f"sqlite:///{database.as_posix()}", connect_args={"check_same_thread": False})
    sessions = sessionmaker(bind=engine)

    def legacy_db():
        with sessions() as db:
            yield db

    app.dependency_overrides[get_db] = legacy_db
    try:
        response = post(api, body(source), source=source)
        assert response.status_code == 503
        assert response.json()["detail"]["failure_code"] == "MIGRATION_011_REQUIRED"
        assert client.get("/api/firewall-rules").json()["items"][0]["scope"] == "MQTT_IPV4_TCP_1883"
        released = client.post(f"/api/firewall-rules/{source}/release-requests", json={"reason": "legacy cleanup", "confirm": release_service.release_confirmation_for_rule(source)}, headers=HEADERS)
        assert released.status_code == 201
    finally:
        engine.dispose()
