from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.main import app
from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.trust import firewall_consistency as consistency
from edge.trust import run_firewall_runtime_snapshot as observer
from edge.trust.firewall_runtime_snapshot import (
    SNAPSHOT_SCHEMA_VERSION, verify_firewall_runtime_snapshot,
)
from edge.trust.firewall_scope import MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL
from tests.test_firewall_runtime_snapshot import ListingRunner


NOW = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)
BOOT = "11111111-1111-4111-8111-111111111111"
OTHER_BOOT = "22222222-2222-4222-8222-222222222222"


def stamp(seconds=0):
    return (NOW + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


@pytest.fixture
def environment(tmp_path, monkeypatch):
    database = tmp_path / "firewall.db"
    apply_migrations(database, MIGRATIONS_DIR)
    snapshot = tmp_path / "runtime.json"
    monkeypatch.setattr(settings, "database_url", f"sqlite:///{database.as_posix()}")
    monkeypatch.setattr(settings, "firewall_runtime_snapshot_path", str(snapshot))
    monkeypatch.setattr(settings, "firewall_runtime_snapshot_max_age_seconds", 15)
    monkeypatch.setattr(settings, "firewall_lock_path", str(tmp_path / "firewall.lock"))
    monkeypatch.setattr(settings, "firewall_lock_wait_seconds", 0)
    monkeypatch.setattr(consistency, "current_boot_id", lambda: BOOT)
    return database, snapshot


def rule(database, identifier=1, *, status="APPLIED", scope=MQTT_IPV4_TCP_1883,
         changed=-10, ip="192.168.0.5"):
    wide = scope == PI_INPUT_IPV4_ALL
    with sqlite3.connect(database) as db:
        db.execute("""INSERT INTO firewall_rules
            (id,source_ip,scope,protocol,dest_port,status,created_at,updated_at,applied_at,
             source_rule_id,approved_policy_revision,requested_by,reason,request_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            identifier, ip, scope, None if wide else "tcp", None if wide else 1883,
            status, stamp(changed), stamp(changed), stamp(changed) if status == "APPLIED" else None,
            1 if wide else None, 1 if wide else None, "admin" if wide else None,
            "fixture" if wide else None, BOOT if wide else None,
        ))


def runtime(identifier=1, ip="192.168.0.5", scope=MQTT_IPV4_TCP_1883):
    return {"rule_id": identifier, "source_ip": ip, "scope": scope}


def payload(rules=(), *, seconds=0, boot=BOOT):
    return {"schema_version": SNAPSHOT_SCHEMA_VERSION, "available": True, "error": None,
            "observed_at": stamp(seconds), "boot_id": boot, "managed_rules": list(rules)}


def observed(environment, runtime_rules=(), *, seconds=0, previous=None, boot=BOOT):
    _, path = environment
    value = payload(runtime_rules, seconds=seconds, boot=boot)
    state = consistency.read_firewall_state(settings.database_url,
                                           [row["rule_id"] for row in runtime_rules])
    value["consistency"] = consistency.build_consistency(
        value, state, previous=previous, now=NOW + timedelta(seconds=seconds),
        boot_id=boot, max_age_seconds=15,
    )
    path.write_text(json.dumps(value), encoding="utf-8")
    return value


def read(environment, *, seconds=1):
    return consistency.read_firewall_runtime_status(
        snapshot_path=environment[1], database_url=settings.database_url,
        max_age_seconds=15, now=NOW + timedelta(seconds=seconds), boot_id=BOOT,
    )


def logical_dump(path):
    with sqlite3.connect(path) as db:
        return list(db.iterdump())


def test_both_scopes_match_without_database_or_runtime_mutation(environment):
    database, snapshot = environment
    rule(database)
    rule(database, 2, scope=PI_INPUT_IPV4_ALL)
    before = logical_dump(database)
    observed(environment, [runtime(), runtime(2, scope=PI_INPUT_IPV4_ALL)])
    file_before = snapshot.read_bytes()
    result = read(environment)
    assert result["status"] == "MATCH" and result["warnings"] == []
    assert logical_dump(database) == before and snapshot.read_bytes() == file_before


@pytest.mark.parametrize("status,actual,kind", [
    ("APPLIED", [], "APPLIED_MISSING"),
    ("REMOVED", [runtime()], "REMOVED_RESIDUAL"),
    ("FAILED", [runtime()], "FAILED_RESIDUAL"),
    ("APPLIED", [runtime(ip="192.168.0.6")], "IDENTITY_MISMATCH"),
    ("APPLIED", [runtime(scope=PI_INPUT_IPV4_ALL)], "IDENTITY_MISMATCH"),
])
def test_exact_rule_mismatches(environment, status, actual, kind):
    rule(environment[0], status=status)
    observed(environment, actual)
    result = read(environment)
    assert result["status"] == "MISMATCH"
    assert result["warnings"][0]["kind"] == kind
    assert result["warnings"][0]["duration_seconds"] == 0


def test_orphan_runtime_and_failed_absent(environment):
    rule(environment[0], status="FAILED")
    observed(environment, [runtime(42)])
    result = read(environment)
    assert [item["kind"] for item in result["warnings"]] == ["ORPHAN_RUNTIME"]
    assert result["warnings"][0]["rule_id"] == 42


@pytest.mark.parametrize("actual", [[], [runtime()]])
def test_pending_rule_waits_with_or_without_os_rule(environment, actual):
    rule(environment[0], status="PENDING")
    observed(environment, actual)
    result = read(environment)
    assert result["status"] == "WAITING" and result["warnings"] == []
    assert result["waiting"] == [{"rule_id": 1, "reason_code": "OPERATION_PENDING"}]


@pytest.mark.parametrize("status", ["APPLIED", "REMOVED"])
def test_pending_release_does_not_report_disappearing_rule_as_missing(environment, status):
    rule(environment[0], status=status)
    with sqlite3.connect(environment[0]) as db:
        db.execute("""INSERT INTO firewall_release_requests
            (firewall_rule_id,requested_by,reason,requested_at,updated_at)
            VALUES(1,'admin','release',?,?)""", (stamp(-2), stamp(-2)))
    observed(environment)
    assert read(environment)["status"] == "WAITING"


@pytest.mark.parametrize("changed", [0, 1])
def test_same_second_or_newer_db_waits_for_next_observation(environment, changed):
    rule(environment[0], changed=changed)
    observed(environment)
    result = read(environment)
    assert result["status"] == "WAITING" and result["warnings"] == []


def test_api_current_db_fingerprint_hides_old_matching_result(environment):
    rule(environment[0])
    observed(environment, [runtime()])
    with sqlite3.connect(environment[0]) as db:
        db.execute("UPDATE firewall_rules SET status='REMOVED',updated_at=?,released_at=? WHERE id=1",
                   (stamp(1), stamp(1)))
    result = read(environment, seconds=2)
    assert result["status"] == "WAITING" and result["reason_code"] == "DB_CHANGED"
    # The timer, not the API, starts the next warning episode.
    assert json.loads(environment[1].read_text())["consistency"]["status"] == "MATCH"
    observed(environment, [runtime()], seconds=5)
    assert read(environment, seconds=6)["warnings"][0]["kind"] == "REMOVED_RESIDUAL"


@pytest.mark.parametrize("seconds,mutation,reason", [
    (16, lambda value: None, "SNAPSHOT_STALE"),
    (-1, lambda value: None, "SNAPSHOT_FUTURE"),
    (1, lambda value: value.update(available=False, error="read failed"), "SNAPSHOT_UNAVAILABLE"),
    (1, lambda value: value.update(schema_version="unknown"), "SNAPSHOT_MALFORMED"),
    (1, lambda value: value.pop("boot_id"), "BOOT_MISMATCH"),
    (1, lambda value: value.update(boot_id=OTHER_BOOT), "BOOT_MISMATCH"),
    (1, lambda value: value.update(managed_rules=[runtime(), runtime()]), "SNAPSHOT_MALFORMED"),
    (1, lambda value: value.pop("consistency"), "CONSISTENCY_UNAVAILABLE"),
    (1, lambda value: value["consistency"].update(status="MISMATCH"), "CONSISTENCY_MALFORMED"),
])
def test_stale_future_error_boot_and_malformed_are_unknown(environment, seconds, mutation, reason):
    value = observed(environment)
    mutation(value)
    environment[1].write_text(json.dumps(value), encoding="utf-8")
    result = read(environment, seconds=seconds)
    assert result["status"] == "UNKNOWN" and result["reason_code"] == reason
    assert result["warnings"] == []


def test_warning_episode_is_persistent_but_duplicate_does_not_advance(environment):
    rule(environment[0])
    first = observed(environment)
    duplicate = observed(environment, previous=first)
    assert duplicate["consistency"] == first["consistency"]
    second = observed(environment, seconds=5, previous=duplicate)
    issue = second["consistency"]["warnings"][0]
    assert issue["first_seen_at"] == stamp()
    assert issue["last_seen_at"] == stamp(5) and issue["duration_seconds"] == 5
    assert read(environment, seconds=10)["warnings"][0] == issue


@pytest.mark.parametrize("seconds,boot,unknown_previous", [
    (20, BOOT, False), (5, OTHER_BOOT, False), (5, BOOT, True),
])
def test_observation_gap_boot_change_and_unknown_break_duration(environment, seconds, boot, unknown_previous):
    rule(environment[0])
    first = observed(environment)
    if unknown_previous:
        first["consistency"] = consistency.unknown("DB_BUSY", observed_at=stamp())
    second = observed(environment, seconds=seconds, previous=first, boot=boot)
    issue = second["consistency"]["warnings"][0]
    assert issue["first_seen_at"] == stamp(seconds) and issue["duration_seconds"] == 0


def test_healthy_observation_ends_episode(environment):
    rule(environment[0])
    first = observed(environment)
    healthy = observed(environment, [runtime()], seconds=5, previous=first)
    assert healthy["consistency"]["status"] == "MATCH"
    again = observed(environment, seconds=10, previous=healthy)
    assert again["consistency"]["warnings"][0]["first_seen_at"] == stamp(10)


@pytest.mark.parametrize("damage", [
    "DROP TABLE firewall_release_requests",
    "UPDATE schema_migrations SET name='wrong' WHERE version=11",
    "UPDATE firewall_rules SET source_ip='not-ip' WHERE id=1",
])
def test_schema_and_stored_data_errors_are_unknown(environment, damage):
    rule(environment[0])
    observed(environment)
    with sqlite3.connect(environment[0]) as db:
        db.execute(damage)
    result = read(environment)
    assert result["status"] == "UNKNOWN"
    assert result["reason_code"] in ("FIREWALL_DATABASE_UNAVAILABLE", "FIREWALL_SCHEMA_UNAVAILABLE")


def test_missing_database_is_never_created(tmp_path):
    missing = tmp_path / "absent.db"
    with pytest.raises(consistency.FirewallConsistencyError):
        consistency.read_firewall_state(f"sqlite:///{missing.as_posix()}")
    assert not missing.exists()


def test_state_is_read_only_and_closed_before_json_publication(environment, monkeypatch):
    database, snapshot = environment
    rule(database)
    before = logical_dump(database)
    listing = ListingRunner(stdout="")
    monkeypatch.setattr(observer, "WrapperIptablesRunner", lambda _policy: listing)
    monkeypatch.setattr(observer, "current_boot_id", lambda: BOOT)
    original_write = observer._write_json_atomically
    writes = []

    def write(path, value):
        # No SQLAlchemy/SQLite read connection is still open at publication.
        with sqlite3.connect(database, timeout=0) as db:
            assert db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
        writes.append(value)
        original_write(path, value)

    monkeypatch.setattr(observer, "_write_json_atomically", write)
    assert observer.run_once() is True
    assert len(writes) == 1 and len(listing.calls) == 1
    assert logical_dump(database) == before
    assert json.loads(snapshot.read_text())["consistency"]["status"] == "MISMATCH"
    # Existing Recovery verifier still accepts the additive v2 fields.
    result = verify_firewall_runtime_snapshot(
        {"ip_address": "192.168.0.5"}, snapshot_path=snapshot, max_age_seconds=15,
    )
    assert result["status"] == "VERIFIED_RELEASED"


def test_observer_db_failure_publishes_unknown_without_disabling_runtime_snapshot(environment, monkeypatch):
    rule(environment[0])
    monkeypatch.setattr(observer, "WrapperIptablesRunner", lambda _policy: ListingRunner())
    monkeypatch.setattr(observer, "current_boot_id", lambda: BOOT)
    monkeypatch.setattr(settings, "database_url", f"sqlite:///{environment[0].parent.as_posix()}/absent.db")
    assert observer.run_once() is False
    value = json.loads(environment[1].read_text())
    assert value["available"] is True and value["consistency"]["status"] == "UNKNOWN"


def test_http_returns_read_only_status_and_refuses_changed_db(environment, monkeypatch):
    rule(environment[0])
    current = datetime.now(timezone.utc).replace(microsecond=0)
    value = payload([], seconds=(current - NOW).total_seconds())
    state = consistency.read_firewall_state(settings.database_url)
    value["consistency"] = consistency.build_consistency(
        value, state, now=current, boot_id=BOOT, max_age_seconds=15,
    )
    environment[1].write_text(json.dumps(value))
    before, file_before = logical_dump(environment[0]), environment[1].read_bytes()
    with TestClient(app) as client:
        response = client.get("/api/firewall-runtime-status")
        assert response.status_code == 200
        assert response.json()["status"] == "MISMATCH"
        assert response.json()["warnings"][0]["kind"] == "APPLIED_MISSING"
        assert logical_dump(environment[0]) == before and environment[1].read_bytes() == file_before
        with sqlite3.connect(environment[0]) as db:
            db.execute("UPDATE firewall_rules SET status='PENDING' WHERE id=1")
        changed = client.get("/api/firewall-runtime-status").json()
        assert changed["status"] == "WAITING" and changed["reason_code"] == "DB_CHANGED"


@pytest.mark.parametrize("old_warnings", [None, 5, {}, [{"key": []}]])
def test_observer_recovers_from_malformed_previous_warnings(environment, monkeypatch, old_warnings):
    rule(environment[0])
    value = observed(environment)
    value["consistency"]["warnings"] = old_warnings
    environment[1].write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(observer, "WrapperIptablesRunner", lambda _policy: ListingRunner())
    monkeypatch.setattr(observer, "current_boot_id", lambda: BOOT)
    assert observer.run_once() is True
    stored = json.loads(environment[1].read_text())["consistency"]
    assert stored["status"] == "MISMATCH"
    assert stored["warnings"][0]["duration_seconds"] == 0


def test_observer_invalid_db_rule_publishes_unknown(environment, monkeypatch):
    rule(environment[0])
    with sqlite3.connect(environment[0]) as db:
        db.execute("UPDATE firewall_rules SET source_ip='not-ip' WHERE id=1")
    monkeypatch.setattr(observer, "WrapperIptablesRunner", lambda _policy: ListingRunner())
    monkeypatch.setattr(observer, "current_boot_id", lambda: BOOT)
    assert observer.run_once() is False
    stored = json.loads(environment[1].read_text())["consistency"]
    assert stored["status"] == "UNKNOWN" and stored["warnings"] == []


def test_pending_release_with_missing_rule_is_unknown(environment):
    observed(environment)
    with sqlite3.connect(environment[0]) as db:
        db.execute("""INSERT INTO firewall_release_requests
            (firewall_rule_id,requested_by,reason,requested_at,updated_at)
            VALUES(99,'admin','corrupt reference',?,?)""", (stamp(-2), stamp(-2)))
    assert read(environment)["status"] == "UNKNOWN"
