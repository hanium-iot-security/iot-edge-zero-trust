"""AI policy HTTP contracts against temporary migrated SQLite databases."""

from datetime import datetime, timedelta
from pathlib import Path
import sqlite3

import pytest

from backend.app.config import settings
from backend.app.services import device_ai_policy_service as service
from backend.tests.test_device_policy_api import (
    ADMIN_HEADERS, POLICY, T0, api_client, assert_business_error,
    assert_validation_error, create_device, rows, write,
)
from db.migration_runner import connect_database
from edge.policy import device_ai_policy_repository as repository
from edge.policy.device_policy import REVISION_MAX
from edge.policy.device_policy_repository import append_policy_revision
from edge.runtime_lock import single_instance_lock


READ_PATH = "/api/devices/pico_01/ai-policy"
WRITE_PATH = "/api/devices/pico_01/ai-policy-revisions"


@pytest.fixture(autouse=True)
def ai_clock(api_client, monkeypatch):
    monkeypatch.setattr(service, "utc_now", lambda: api_client[2]["now"])
    monkeypatch.setattr(settings, "trust_ai_mode", "observe")


def command(**changes):
    return {"expected_revision": 1, "mode": "OBSERVE", "reason": "  reviewed AI setting  ", **changes}


def submit(client, **changes):
    return client.post(WRITE_PATH, json=command(**changes), headers=ADMIN_HEADERS)


def ready(api_client):
    client, db_path, clock = api_client
    create_device(client)
    clock["now"] = T0.replace(second=10)
    return client, db_path, clock


def ai_rows(db_path):
    return rows(db_path, "SELECT * FROM device_ai_policy_revisions ORDER BY revision")


def disable_registration(db_path, clock):
    with connect_database(db_path) as connection:
        append_policy_revision(
            connection, device_id="pico_01", expected_revision=1,
            registration_state="DISABLED", policy=POLICY,
            reason="disabled fixture", created_by="fixture-admin",
            clock=lambda: clock["now"],
        )


def test_public_get_exposes_initial_off_pending_then_current(api_client):
    client, db_path, clock = api_client
    create_device(client)
    response = client.get(READ_PATH)
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"device_id", "server_time", "latest_revision", "current", "pending", "expected_instance_id"}
    assert body["expected_instance_id"] == rows(db_path, "SELECT registration_instance_id FROM devices")[0][0]
    assert body["device_id"] == "pico_01" and body["latest_revision"] == 1
    assert datetime.fromisoformat(body["server_time"].replace("Z", "+00:00")) == T0
    assert body["current"] is None
    assert body["pending"]["mode"] == "OFF"
    assert body["pending"]["revision"] == 1
    assert body["pending"]["effective_from"] == "2026-10-02T00:00:10Z"
    assert body["pending"]["created_by"] == "policy-test-admin"
    before = ai_rows(db_path)
    clock["now"] = T0.replace(second=10)
    current = client.get(READ_PATH).json()
    assert current["current"] == body["pending"] and current["pending"] is None
    assert ai_rows(db_path) == before


@pytest.mark.parametrize("second,microsecond", [(10, 0), (19, 999000)])
def test_post_schedules_strict_next_boundary_with_server_actor(api_client, second, microsecond):
    client, db_path, clock = ready(api_client)
    before = ai_rows(db_path)
    clock["now"] = T0.replace(second=second, microsecond=microsecond)
    response = submit(client)
    assert response.status_code == 201, response.text
    body = response.json()
    assert set(body) == {"device_id", "server_time", "latest_revision", "current", "pending", "expected_instance_id"}
    assert body["expected_instance_id"] == rows(db_path, "SELECT registration_instance_id FROM devices")[0][0]
    assert body["latest_revision"] == 2
    assert body["current"]["revision"] == 1 and body["current"]["mode"] == "OFF"
    assert body["pending"]["revision"] == 2 and body["pending"]["mode"] == "OBSERVE"
    assert body["pending"]["effective_from"] == "2026-10-02T00:00:20Z"
    assert body["pending"]["created_by"] == "policy-test-admin"
    assert body["pending"]["reason"] == "reviewed AI setting"
    assert datetime.fromisoformat(body["server_time"].replace("Z", "+00:00")) == clock["now"]
    assert ai_rows(db_path)[:1] == before
    clock["now"] = T0.replace(second=20)
    current = client.get(READ_PATH).json()
    assert current["current"] == body["pending"] and current["pending"] is None


@pytest.mark.parametrize("headers", [{}, {"X-Recovery-Admin-Key": "wrong-key"}])
def test_admin_authentication_blocks_changes(api_client, headers):
    client, db_path, _ = ready(api_client)
    before = ai_rows(db_path)
    response = client.post(WRITE_PATH, json=command(), headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "RECOVERY_ADMIN_UNAUTHORIZED"}
    assert ai_rows(db_path) == before


def test_unconfigured_admin_is_unavailable(api_client, monkeypatch):
    client, db_path, _ = ready(api_client)
    before = ai_rows(db_path)
    monkeypatch.setattr(settings, "recovery_admin_api_key", "")
    response = submit(client)
    assert response.status_code == 503
    assert response.json() == {"detail": "RECOVERY_ADMIN_NOT_CONFIGURED"}
    assert ai_rows(db_path) == before


@pytest.mark.parametrize("field,value", [
    ("expected_revision", True), ("expected_revision", "1"),
    ("expected_revision", 1.0), ("expected_revision", 0),
    ("expected_revision", REVISION_MAX + 1),
    ("mode", "ENFORCE"), ("mode", "observe"), ("mode", True), ("mode", 1), ("mode", None),
    ("reason", "   "), ("reason", "line1\nline2"), ("reason", "a" * 501),
])
def test_strict_command_fields_never_append(api_client, field, value):
    client, db_path, _ = ready(api_client)
    before = ai_rows(db_path)
    assert_validation_error(submit(client, **{field: value}), field)
    assert ai_rows(db_path) == before


@pytest.mark.parametrize("field,value", [
    ("created_by", "spoofed-admin"), ("effective_from", "2020-01-01T00:00:00Z"),
])
def test_server_owned_fields_are_rejected_without_echo(api_client, field, value):
    client, db_path, _ = ready(api_client)
    before = ai_rows(db_path)
    response = submit(client, **{field: value})
    assert_validation_error(response, field)
    assert value not in response.text
    assert ai_rows(db_path) == before


@pytest.mark.parametrize("field", ["mode", "reason"])
def test_required_command_fields_cannot_be_omitted(api_client, field):
    client, db_path, _ = ready(api_client)
    before = ai_rows(db_path)
    body = command()
    del body[field]
    response = client.post(WRITE_PATH, json=body, headers=ADMIN_HEADERS)
    assert_validation_error(response, field)
    assert ai_rows(db_path) == before


@pytest.mark.parametrize("method,suffix", [("GET", "ai-policy"), ("POST", "ai-policy-revisions")])
def test_invalid_device_path_uses_existing_validation_envelope(api_client, method, suffix):
    client, db_path, _ = api_client
    kwargs = {"json": command(), "headers": ADMIN_HEADERS} if method == "POST" else {}
    response = client.request(method, f"/api/devices/bad%20id/{suffix}", **kwargs)
    assert_validation_error(response, "device_id")
    assert [item["loc"] for item in response.json()["detail"]] == [["path", "device_id"]]
    assert ai_rows(db_path) == []


def test_unknown_device_get_and_post_are_not_found(api_client):
    client, db_path, _ = api_client
    assert_business_error(client.get(READ_PATH), 404, "DEVICE_NOT_FOUND")
    assert_business_error(submit(client), 404, "DEVICE_NOT_FOUND")
    assert ai_rows(db_path) == []


@pytest.mark.parametrize("api_client,code", [
    ("pre012", "AI_POLICY_UNAVAILABLE"), ("legacy", "POLICY_UNAVAILABLE"),
], indirect=["api_client"])
def test_missing_schema_is_unavailable_without_creating_ai_state(api_client, code):
    client, db_path, _ = api_client
    write(db_path, "INSERT INTO devices(device_id,ip_address) VALUES('pico_01','192.168.0.6')")
    before = rows(db_path, "SELECT * FROM devices")
    assert_business_error(client.get(READ_PATH), 503, code)
    assert_business_error(submit(client), 503, code)
    assert rows(db_path, "SELECT * FROM devices") == before
    assert rows(db_path, "SELECT name FROM sqlite_master WHERE name='device_ai_policy_revisions'") == []


def test_existing_device_without_ai_backfill_is_not_assumed_off(api_client):
    client, db_path, _ = api_client
    write(db_path, "INSERT INTO devices(device_id,ip_address) VALUES('pico_01','192.168.0.6')")
    assert_business_error(client.get(READ_PATH), 503, "AI_POLICY_UNAVAILABLE")
    assert_business_error(submit(client), 503, "AI_POLICY_UNAVAILABLE")
    assert ai_rows(db_path) == []


@pytest.mark.parametrize("damage", ["mode", "partial_schema"])
def test_damaged_ai_state_is_unavailable_and_preserved(api_client, damage):
    client, db_path, _ = ready(api_client)
    with sqlite3.connect(db_path) as connection:
        if damage == "mode":
            connection.execute("DROP TRIGGER trg_device_ai_policy_revisions_no_update")
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute("UPDATE device_ai_policy_revisions SET mode='ENFORCE'")
        else:
            connection.execute("ALTER TABLE device_ai_policy_revisions RENAME COLUMN reason TO missing_reason")
    before = ai_rows(db_path)
    assert_business_error(client.get(READ_PATH), 503, "AI_POLICY_UNAVAILABLE")
    assert_business_error(submit(client), 503, "AI_POLICY_UNAVAILABLE")
    assert ai_rows(db_path) == before


def test_global_enforce_blocks_observe_but_allows_safe_off(api_client, monkeypatch):
    client, db_path, clock = ready(api_client)
    before = ai_rows(db_path)
    monkeypatch.setattr(settings, "trust_ai_mode", "enforce")
    assert_business_error(submit(client), 503, "AI_POLICY_UNAVAILABLE")
    assert ai_rows(db_path) == before
    monkeypatch.setattr(settings, "trust_ai_mode", "observe")
    assert submit(client).status_code == 201
    clock["now"] = T0.replace(second=20)
    monkeypatch.setattr(settings, "trust_ai_mode", "enforce")
    response = submit(client, expected_revision=2, mode="OFF")
    assert response.status_code == 201, response.text
    assert response.json()["pending"]["mode"] == "OFF"
    assert rows(db_path, "SELECT revision,mode FROM device_ai_policy_revisions ORDER BY revision") == [
        (1, "OFF"), (2, "OBSERVE"), (3, "OFF"),
    ]


@pytest.mark.parametrize("effective", [False, True])
def test_disabled_or_pending_disable_rejects_observe(api_client, effective):
    client, db_path, clock = ready(api_client)
    disable_registration(db_path, clock)
    if effective:
        clock["now"] = T0.replace(second=20)
    before = ai_rows(db_path)
    assert_business_error(submit(client), 409, "STATE_TRANSITION_BLOCKED")
    assert ai_rows(db_path) == before


def test_disabled_device_can_schedule_off(api_client):
    client, db_path, clock = ready(api_client)
    assert submit(client).status_code == 201
    clock["now"] = T0.replace(second=20)
    disable_registration(db_path, clock)
    clock["now"] = T0.replace(second=30)
    response = submit(client, expected_revision=2, mode="OFF")
    assert response.status_code == 201, response.text
    assert response.json()["pending"]["mode"] == "OFF"


def test_pending_conflict_precedes_same_value_and_reports_revision_context(api_client):
    client, db_path, clock = api_client
    create_device(client)
    initial = assert_business_error(submit(client, mode="OFF"), 409, "PENDING_REVISION_EXISTS")
    assert (initial["current_revision"], initial["pending_revision"], initial["latest_revision"]) == (None, 1, 1)
    clock["now"] = T0.replace(second=10)
    assert submit(client).status_code == 201
    detail = assert_business_error(submit(client, expected_revision=2), 409, "PENDING_REVISION_EXISTS")
    assert (detail["current_revision"], detail["pending_revision"], detail["latest_revision"]) == (1, 2, 2)
    assert len(ai_rows(db_path)) == 2


def test_same_mode_cannot_append_revision(api_client):
    client, db_path, _ = ready(api_client)
    before = ai_rows(db_path)
    assert_business_error(submit(client, mode="OFF"), 409, "NO_POLICY_CHANGE")
    assert ai_rows(db_path) == before


def test_lost_response_can_be_recovered_by_get_and_retry_cannot_duplicate(api_client, monkeypatch):
    client, db_path, clock = ready(api_client)
    original_snapshot = service.get_ai_policy_snapshot

    def fail_response(*args, **kwargs):
        assert len(ai_rows(db_path)) == 2  # Commit happened before response construction.
        raise RuntimeError("simulated lost response after commit")

    with monkeypatch.context() as scoped:
        scoped.setattr(service, "get_ai_policy_snapshot", fail_response)
        response = submit(client)
    assert response.status_code == 500
    assert service.get_ai_policy_snapshot is original_snapshot
    recorded = client.get(READ_PATH).json()
    assert recorded["latest_revision"] == 2 and recorded["pending"]["mode"] == "OBSERVE"
    detail = assert_business_error(submit(client), 409, "REVISION_CONFLICT")
    assert (detail["current_revision"], detail["pending_revision"]) == (1, 2)
    clock["now"] = T0.replace(second=20)
    detail = assert_business_error(submit(client), 409, "REVISION_CONFLICT")
    assert (detail["current_revision"], detail["pending_revision"], detail["latest_revision"]) == (2, None, 2)
    assert len(ai_rows(db_path)) == 2


def test_shared_file_lock_prevents_ai_write(api_client):
    client, db_path, _ = ready(api_client)
    before = ai_rows(db_path)
    with single_instance_lock(Path(settings.firewall_lock_path)):
        assert_business_error(submit(client), 409, "POLICY_WRITE_BUSY")
    assert ai_rows(db_path) == before


def test_database_writer_contention_returns_busy_without_revision(api_client):
    client, db_path, _ = ready(api_client)
    before = ai_rows(db_path)
    with sqlite3.connect(db_path) as writer:
        writer.execute("BEGIN IMMEDIATE")
        try:
            assert_business_error(submit(client), 409, "POLICY_WRITE_BUSY")
        finally:
            writer.rollback()
    assert ai_rows(db_path) == before


def test_get_uses_one_snapshot_during_concurrent_revision(api_client, monkeypatch):
    client, db_path, clock = ready(api_client)
    write(db_path, "PRAGMA journal_mode=WAL")
    original = repository.get_latest_ai_revision
    inserted = False

    def append_after_read(connection, device_id):
        nonlocal inserted
        latest = original(connection, device_id)
        if not inserted:
            inserted = True
            with connect_database(db_path) as writer:
                repository.append_ai_policy_revision(
                    writer, device_id=device_id, expected_revision=1, mode="OBSERVE",
                    reason="concurrent fixture", created_by="fixture-admin", clock=lambda: clock["now"],
                )
        return latest

    monkeypatch.setattr(repository, "get_latest_ai_revision", append_after_read)
    response = client.get(READ_PATH)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["latest_revision"] == body["current"]["revision"] == 1
    assert body["pending"] is None
    assert client.get(READ_PATH).json()["pending"]["revision"] == 2


def test_post_response_uses_command_time_even_if_clock_crosses_boundary(api_client, monkeypatch):
    client, _, clock = ready(api_client)
    moments = iter([clock["now"], clock["now"] + timedelta(seconds=10)])
    monkeypatch.setattr(service, "utc_now", lambda: next(moments))
    response = submit(client)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["current"]["mode"] == "OFF" and body["pending"]["mode"] == "OBSERVE"
    assert datetime.fromisoformat(body["server_time"].replace("Z", "+00:00")) == clock["now"]


def test_ai_change_preserves_rule_trust_firewall_and_checkpoint_state(api_client, monkeypatch):
    from backend.app.services import device_policy_service

    client, db_path, _ = ready(api_client)
    write(db_path, "UPDATE devices SET trust_score=47,status='danger',last_seen_at='2026-10-02T00:00:05Z'")
    write(db_path, """INSERT INTO trust_score_history (
        device_id,analysis_window_start,analysis_window_end,previous_score,calculated_delta,
        capped_delta,actual_delta,new_score,representative_event_ids_json,policy_version,created_at
    ) VALUES ('pico_01','2026-10-01T23:59:50Z','2026-10-02T00:00:00Z',
              67,-20,-20,-20,47,'[]','trust-score-v2','2026-10-02T00:00:00Z')""")
    write(db_path, "INSERT INTO firewall_rules(device_id,source_ip,status) VALUES('pico_01','192.168.0.6','REMOVED')")
    write(db_path, """INSERT INTO detector_checkpoints (
        detector_name,source_table,last_processed_id,last_completed_window_end,updated_at
    ) VALUES ('mqtt_if','feature_logs',17,'2026-10-02T00:00:00Z','2026-10-02T00:00:00Z')""")
    tables = ("devices", "device_policy_revisions", "trust_score_history", "detection_events",
              "isolation_history", "firewall_rules", "firewall_release_requests", "detector_checkpoints")
    before = {table: rows(db_path, f"SELECT * FROM {table} ORDER BY rowid") for table in tables}
    monkeypatch.setattr(device_policy_service, "verify_runtime_firewall",
                        lambda *args: pytest.fail("AI settings must not probe or change the firewall"))
    response = submit(client)
    assert response.status_code == 201, response.text
    assert {table: rows(db_path, f"SELECT * FROM {table} ORDER BY rowid") for table in tables} == before
    assert len(ai_rows(db_path)) == 2
