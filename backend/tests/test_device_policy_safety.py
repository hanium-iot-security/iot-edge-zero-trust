"""Policy commands versus live firewall state and concurrent DB changes."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading

import pytest

from backend.app.config import settings
from backend.tests.test_device_policy_api import (
    POLICY, ADMIN_HEADERS, api_client, assert_business_error, change_policy,
    create_device, revision, rows, write,
)
from db.migration_runner import connect_database
from edge.policy import device_policy_repository


def _ready(api_client):
    client, db_path, clock = api_client
    create_device(client)
    clock["now"] += timedelta(seconds=10)
    return client, db_path, clock


def _snapshot(monkeypatch, tmp_path, *, managed_rules=None, observed_at=None, available=True):
    path = tmp_path / "runtime.json"
    path.write_text(json.dumps({
        "schema_version": "firewall-runtime-snapshot-v1",
        "observed_at": (observed_at or datetime.now(timezone.utc)).isoformat(),
        "available": available,
        "managed_rules": managed_rules or [],
        "error": None if available else "observation failed",
    }), encoding="utf-8")
    monkeypatch.setattr(settings, "firewall_runtime_snapshot_path", str(path))
    return path


def _rule(db_path, *, state="FAILED", owner="pico_01", ip="192.168.0.6", attempted=None):
    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute(
            "INSERT INTO firewall_rules(device_id,source_ip,status,last_attempted_at,updated_at) "
            "VALUES(?,?,?,?,?)", (owner, ip, state, attempted,
                                  (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()),
        )
        return cursor.lastrowid


def test_legacy_null_registration_boundary_keeps_active_status(api_client):
    client, db_path, clock = _ready(api_client)
    # Model the valid backfill shape: legacy identity, NULL registration boundary,
    # initial ACTIVE revision. Use a fresh legacy device, not mutable revisions.
    write(db_path, "INSERT INTO devices(device_id,ip_address,status,trust_score) "
          "VALUES('legacy','192.168.0.8','normal',80)")
    with connect_database(db_path) as connection:
        from edge.policy.device_policy_backfill import apply_legacy_backfill, parse_override
        from edge.policy.device_policy import IpRegistrationPolicy
        from ipaddress import IPv4Network
        apply_legacy_backfill(
            connection,
            {"legacy": parse_override({"device_id": "legacy", "device_type": "SENSOR",
                                      "policy": POLICY, "source": "verified-baseline"})},
            effective_from=clock["now"].replace(second=0),
            ip_policy=IpRegistrationPolicy(network=IPv4Network("192.168.0.0/24")),
            reason="verified migration", clock=lambda: clock["now"],
        )
    body = client.get("/api/devices/legacy").json()
    assert body["registration_effective_from"] is None
    assert body["registration_state"] == "ACTIVE"
    assert body["auto_response_eligible"] is True
    assert body["trust_score"] == 80


@pytest.mark.parametrize("kind", ["missing", "stale", "unavailable", "drop"])
def test_disable_refuses_unverified_runtime(api_client, monkeypatch, tmp_path, kind):
    client, db_path, _ = _ready(api_client)
    path = _snapshot(monkeypatch, tmp_path,
                     observed_at=datetime.now(timezone.utc) - timedelta(minutes=1) if kind == "stale" else None,
                     available=kind != "unavailable",
                     managed_rules=[{"rule_id": 9, "source_ip": "192.168.0.6"}] if kind == "drop" else [])
    if kind == "missing":
        path.unlink()
    assert_business_error(change_policy(client, state="DISABLED"), 409, "STATE_TRANSITION_BLOCKED")
    assert rows(db_path, "SELECT count(*) FROM device_policy_revisions") == [(1,)]
    assert rows(db_path, "SELECT status,trust_score FROM devices") == [("normal", 100)]


@pytest.mark.parametrize("state", ["PENDING", "APPLIED"])
@pytest.mark.parametrize("same_ip_other_owner", [False, True])
def test_disable_refuses_db_block_by_device_or_ip(api_client, monkeypatch, tmp_path, state, same_ip_other_owner):
    client, db_path, _ = _ready(api_client)
    _snapshot(monkeypatch, tmp_path)
    owner = "pico_01"
    if same_ip_other_owner:
        write(db_path, "INSERT INTO devices(device_id,ip_address) VALUES('old_owner','192.168.0.7')")
        owner = "old_owner"
    _rule(db_path, state=state, owner=owner)
    assert_business_error(change_policy(client, state="DISABLED"), 409, "STATE_TRANSITION_BLOCKED")
    assert rows(db_path, "SELECT count(*) FROM device_policy_revisions") == [(1,)]


def test_disable_refuses_pending_release_for_same_ip(api_client, monkeypatch, tmp_path):
    client, db_path, _ = _ready(api_client)
    _snapshot(monkeypatch, tmp_path)
    write(db_path, "INSERT INTO devices(device_id,ip_address) VALUES('old_owner','192.168.0.7')")
    rule_id = _rule(db_path, owner="old_owner")
    write(db_path, "INSERT INTO firewall_release_requests(firewall_rule_id,requested_by,reason,requested_at) "
          "VALUES(?,?,?,?)", (rule_id, "admin", "release", datetime.now(timezone.utc).isoformat()))
    assert_business_error(change_policy(client, state="DISABLED"), 409, "STATE_TRANSITION_BLOCKED")


@pytest.mark.parametrize("state", ["FAILED", "REMOVED"])
def test_disable_requires_observation_after_last_attempt(api_client, monkeypatch, tmp_path, state):
    client, _, _ = _ready(api_client)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _rule(api_client[1], state=state, attempted=now.isoformat())
    _snapshot(monkeypatch, tmp_path, observed_at=now)
    assert_business_error(change_policy(client, state="DISABLED"), 409, "STATE_TRANSITION_BLOCKED")


def test_verified_disable_preserves_firewall_and_score(api_client, monkeypatch, tmp_path):
    client, db_path, clock = _ready(api_client)
    _rule(db_path, attempted=(datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat())
    _snapshot(monkeypatch, tmp_path)
    before = rows(db_path, "SELECT * FROM firewall_rules")
    response = change_policy(client, state="DISABLED")
    assert response.status_code == 201, response.text
    detail = client.get("/api/devices/pico_01").json()
    assert detail["registration_state"] == "PENDING"
    assert detail["auto_response_exclusion_reason"] == "DISABLE_REQUESTED_OR_DISABLED"
    clock["now"] += timedelta(seconds=10)
    assert client.get("/api/devices/pico_01").json()["registration_state"] == "DISABLED"
    assert rows(db_path, "SELECT * FROM firewall_rules") == before
    assert rows(db_path, "SELECT status,trust_score FROM devices") == [("normal", 100)]
    assert_business_error(change_policy(client, expected=2), 409, "STATE_TRANSITION_BLOCKED")


def test_separate_worker_process_excludes_policy_write(api_client, tmp_path):
    client, db_path, _ = _ready(api_client)
    ready = tmp_path / "worker-ready"
    script = (
        "from pathlib import Path; import sys; from edge.runtime_lock import single_instance_lock\n"
        "with single_instance_lock(Path(sys.argv[1])):\n"
        " Path(sys.argv[2]).write_text('ready'); input()\n"
    )
    process = subprocess.Popen([sys.executable, "-c", script, settings.firewall_lock_path, str(ready)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, cwd=Path(__file__).resolve().parents[2])
    try:
        import time
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            if process.poll() is not None:
                pytest.fail(process.stderr.read())
            time.sleep(0.02)
        assert ready.exists()
        assert_business_error(change_policy(client), 409, "POLICY_WRITE_BUSY")
        assert rows(db_path, "SELECT count(*) FROM device_policy_revisions") == [(1,)]
    finally:
        process.communicate(input="done\n", timeout=5)


def test_concurrent_revision_commands_commit_once(api_client):
    client, db_path, _ = _ready(api_client)
    barrier = threading.Barrier(2)

    def submit():
        barrier.wait()
        return client.post("/api/devices/pico_01/policy-revisions", json=revision(), headers=ADMIN_HEADERS)

    with ThreadPoolExecutor(max_workers=2) as executor:
        replies = list(executor.map(lambda _: submit(), range(2)))
    assert sorted(response.status_code for response in replies) == [201, 409]
    assert rows(db_path, "SELECT revision FROM device_policy_revisions ORDER BY revision") == [(1,), (2,)]


def test_policy_read_remains_consistent_during_concurrent_revision(api_client, monkeypatch):
    client, db_path, clock = _ready(api_client)
    write(db_path, "PRAGMA journal_mode=WAL")
    original = device_policy_repository.get_latest_revision
    inserted = False

    def insert_after_read(connection, device_id):
        nonlocal inserted
        latest = original(connection, device_id)
        if not inserted:
            inserted = True
            with connect_database(db_path) as writer:
                device_policy_repository.append_policy_revision(
                    writer, device_id=device_id, expected_revision=1, registration_state="ACTIVE",
                    policy=POLICY, reason="concurrent administrator", created_by="test",
                    clock=lambda: clock["now"],
                )
        return latest

    monkeypatch.setattr(device_policy_repository, "get_latest_revision", insert_after_read)
    response = client.get("/api/devices/pico_01/policy")
    assert response.status_code == 200, response.text
    assert response.json()["latest_revision"] == 1
    assert response.json()["current"]["revision"] == 1
    assert response.json()["pending"] is None
    assert rows(db_path, "SELECT count(*) FROM device_policy_revisions") == [(2,)]


@pytest.mark.parametrize("kind", ["registration_boundary", "policy_profile"])
def test_invalid_existing_policy_refuses_write_before_commit(api_client, kind):
    client, db_path, clock = api_client
    registered_from = "2026-10-02T00:01:00Z" if kind == "registration_boundary" else None
    write(db_path, "INSERT INTO devices(device_id,ip_address,registration_effective_from) "
          "VALUES('broken','192.168.0.8',?)", (registered_from,))
    values = {
        "device_id": "broken", "revision": 1, "effective_from": "2026-10-02T00:00:00Z",
        "registration_state": "ACTIVE", **POLICY,
        "created_at": "2026-10-02T00:00:00.000Z", "created_by": "fixture", "reason": "legacy state",
    }
    if kind == "policy_profile":
        values["policy_profile"] = "unsupported-profile"
    write(db_path, "INSERT INTO device_policy_revisions(" + ",".join(values) + ") VALUES(" +
          ",".join("?" for _ in values) + ")", tuple(values.values()))
    before = rows(db_path, "SELECT * FROM device_policy_revisions")
    assert_business_error(client.get("/api/devices/broken/policy"), 503, "POLICY_UNAVAILABLE")
    assert client.get("/api/devices/broken").json()["auto_response_eligible"] is False
    response = client.post("/api/devices/broken/policy-revisions", json=revision(), headers=ADMIN_HEADERS)
    assert_business_error(response, 503, "POLICY_UNAVAILABLE")
    assert rows(db_path, "SELECT * FROM device_policy_revisions") == before


@pytest.mark.parametrize("field,value", [
    ("expected_publish_interval_seconds", "corrupt-text"),
    ("publish_count_max", "corrupt-text"),
    ("payload_size_max_bytes", "corrupt-text"),
    ("packet_rate_max_pps", "corrupt-text"),
    ("byte_rate_max_bytes_per_second", "corrupt-text"),
    ("publish_count_max", 15.5),
    ("payload_size_max_bytes", 5120.5),
])
def test_corrupt_stored_numbers_keep_reads_available_and_refuse_write(api_client, field, value):
    client, db_path, _ = api_client
    write(db_path, "INSERT INTO devices(device_id,ip_address) VALUES('broken','192.168.0.8')")
    values = {
        "device_id": "broken", "revision": 1, "effective_from": "2026-10-02T00:00:00Z",
        "registration_state": "ACTIVE", **POLICY, field: value,
        "created_at": "2026-10-02T00:00:00.000Z", "created_by": "fixture", "reason": "damaged import",
    }
    # Normal migration/repository writes reject these values. Bypass CHECKs only
    # in this temporary DB to model a damaged import, not a supported write path.
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute("INSERT INTO device_policy_revisions(" + ",".join(values) + ") VALUES(" +
                           ",".join("?" for _ in values) + ")", tuple(values.values()))
    before = rows(db_path, "SELECT * FROM device_policy_revisions")
    detail = client.get("/api/devices/broken")
    listing = client.get("/api/devices")
    assert detail.status_code == listing.status_code == 200
    assert listing.json() == {"items": [detail.json()], "total": 1}
    assert detail.json()["registration_state"] is None
    assert detail.json()["auto_response_eligible"] is False
    assert detail.json()["auto_response_exclusion_reason"] == "POLICY_UNAVAILABLE"
    assert_business_error(client.get("/api/devices/broken/policy"), 503, "POLICY_UNAVAILABLE")
    response = client.post("/api/devices/broken/policy-revisions", json=revision(), headers=ADMIN_HEADERS)
    assert_business_error(response, 503, "POLICY_UNAVAILABLE")
    assert rows(db_path, "SELECT * FROM device_policy_revisions") == before
    assert rows(db_path, "SELECT status,trust_score FROM devices") == [("normal", 100)]


@pytest.mark.parametrize("wait", [-1, float("nan"), float("inf")])
def test_invalid_lock_wait_fails_before_mutation(api_client, monkeypatch, wait):
    client, db_path, _ = api_client
    monkeypatch.setattr(settings, "firewall_lock_wait_seconds", wait)
    from backend.tests.test_device_policy_api import registration
    response = client.post("/api/devices", json=registration(), headers=ADMIN_HEADERS)
    assert_business_error(response, 503, "DEVICE_POLICY_CONFIG_UNAVAILABLE")
    assert rows(db_path, "SELECT count(*) FROM devices") == [(0,)]


def test_write_response_uses_admission_time_across_window_boundary(api_client, monkeypatch):
    client, db_path, clock = api_client
    from backend.app.services import device_policy_service
    start = clock["now"]

    def progressing_clock():
        now = clock["now"]
        clock["now"] += timedelta(seconds=10)
        return now

    monkeypatch.setattr(device_policy_service, "utc_now", progressing_clock)
    body = create_device(client)
    assert body["policy"]["server_time"] == start.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    assert body["policy"]["current"] is None
    assert body["policy"]["pending"]["revision"] == 1
    assert client.get("/api/devices/pico_01/policy").json()["current"]["revision"] == 1


def test_same_device_old_ip_history_refuses_disable(api_client, monkeypatch, tmp_path):
    client, db_path, _ = _ready(api_client)
    rule_id = _rule(db_path, ip="192.168.0.7")
    _snapshot(monkeypatch, tmp_path, managed_rules=[{"rule_id": rule_id, "source_ip": "192.168.0.7"}])
    before = rows(db_path, "SELECT * FROM firewall_rules")
    assert_business_error(change_policy(client, state="DISABLED"), 409, "STATE_TRANSITION_BLOCKED")
    assert rows(db_path, "SELECT count(*) FROM device_policy_revisions") == [(1,)]
    assert rows(db_path, "SELECT * FROM firewall_rules") == before


def test_revision_response_uses_admission_time_across_window_boundary(api_client, monkeypatch):
    client, _, clock = _ready(api_client)
    from backend.app.services import device_policy_service
    start = clock["now"]

    def progressing_clock():
        now = clock["now"]
        clock["now"] += timedelta(seconds=10)
        return now

    monkeypatch.setattr(device_policy_service, "utc_now", progressing_clock)
    response = change_policy(client)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["server_time"] == start.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    assert body["current"]["revision"] == 1
    assert body["pending"]["revision"] == 2
    assert client.get("/api/devices/pico_01/policy").json()["current"]["revision"] == 2
