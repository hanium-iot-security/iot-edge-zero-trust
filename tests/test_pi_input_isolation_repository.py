"""Local-only migration, approval and fresh authorization contracts."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from backend.app.security import RecoveryAdminContext
from backend.app.services import firewall_scope_extension_service as service
from backend.app.services.firewall_rule_query_service import list_firewall_rules
from db.migration_runner import MIGRATIONS_DIR, MigrationError, apply_migrations
from edge.trust import firewall_release_repository as releases
from edge.trust import firewall_repository as rules
from edge.trust.firewall_scope import MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL


NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
DEVICE = "pico_01"
IP = "192.168.0.31"
ADMIN = RecoveryAdminContext("test-admin")


def migrations_until(tmp_path, version):
    directory = tmp_path / f"migrations-{version}"
    directory.mkdir()
    for path in MIGRATIONS_DIR.glob("*.sql"):
        if int(path.name.split("_")[0]) <= version:
            (directory / path.name).write_bytes(path.read_bytes())
    return directory


def seed_isolated_source(database, *, status="APPLIED"):
    """Exact current ACTIVE fixture shared with the wide Worker tests."""
    with sqlite3.connect(database) as connection:
        connection.execute("INSERT INTO devices(device_id,ip_address,status,trust_score) VALUES (?,?,'isolated',20)", (DEVICE, IP))
        connection.execute("""INSERT INTO device_policy_revisions
            (device_id,revision,effective_from,registration_state,policy_profile,
             expected_publish_interval_seconds,publish_count_max,payload_size_max_bytes,
             packet_rate_max_pps,byte_rate_max_bytes_per_second,created_at,created_by,reason)
            VALUES (?,1,'2026-10-09T11:59:00Z','ACTIVE','periodic-sensor-v1',5,15,256,
                    100,65536,'2026-10-09T11:58:00Z','test-admin','verified fixture')""", (DEVICE,))
        return connection.execute("INSERT INTO firewall_rules(device_id,source_ip,status,reason,applied_at) VALUES (?,?,?,'original MQTT block','2026-10-09T11:59:30Z')", (DEVICE, IP, status)).lastrowid


@pytest.fixture
def environment(tmp_path, monkeypatch):
    database = tmp_path / "isolation.db"
    apply_migrations(database, MIGRATIONS_DIR)
    source = seed_isolated_source(database)
    engine = create_engine(f"sqlite:///{database.as_posix()}")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    monkeypatch.setattr(service, "_now_utc", lambda: NOW)
    try:
        yield database, sessionmaker(bind=engine), source
    finally:
        engine.dispose()


def payload(source, **updates):
    data = {"source_rule_id": source, "device_id": DEVICE, "source_ip": IP,
            "approved_policy_revision": 1, "scope": PI_INPUT_IPV4_ALL,
            "reason": "operator approved IPv4 INPUT isolation", "request_id": str(uuid4()),
            "confirm": service.scope_extension_confirmation(source, IP, 1), "admin": ADMIN}
    data.update(updates)
    return data


def approve(sessions, source, **updates):
    with sessions() as db:
        return service.create_firewall_scope_extension(db, **payload(source, **updates))


def row(db, identifier):
    return dict(db.execute(text("SELECT * FROM firewall_rules WHERE id=:id"), {"id": identifier}).mappings().one())


def execute(database, sql, values=()):
    with sqlite3.connect(database) as connection:
        connection.execute(sql, values)


def test_migration_preserves_ids_values_release_fk_indexes_and_deleted_sequence(tmp_path):
    database = tmp_path / "upgrade.db"
    apply_migrations(database, migrations_until(tmp_path, 10))
    source = seed_isolated_source(database)
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("UPDATE firewall_rules SET retry_count=2,last_error='old failure',last_attempted_at='2026-10-09T11:59:20Z',next_retry_at='2026-10-09T11:59:40Z' WHERE id=?", (source,))
        connection.execute("INSERT INTO firewall_rules(id,source_ip,status) VALUES (900,'192.168.0.99','REMOVED')")
        connection.execute("DELETE FROM firewall_rules WHERE id=900")
        release = connection.execute("INSERT INTO firewall_release_requests(firewall_rule_id,requested_by,reason,requested_at) VALUES (?,'test-admin','cleanup','2026-10-09T11:59:50Z')", (source,)).lastrowid
        before = dict(connection.execute("SELECT * FROM firewall_rules WHERE id=?", (source,)).fetchone())
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence','schema_migrations')")}
        assert len(tables) == 19
        indexes = {value[0] for value in connection.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='firewall_rules'")}
    assert apply_migrations(database, MIGRATIONS_DIR).applied_versions == list(range(11, 19))
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        after = dict(connection.execute("SELECT * FROM firewall_rules WHERE id=?", (source,)).fetchone())
        assert {key: after[key] for key in before} == before
        assert {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence','schema_migrations')")} == tables | {"device_ai_policy_revisions", "ai_runtime_snapshot", "ai_device_completions", "ai_warning_keys", "ai_warning_aggregates", "ai_warning_events", "ai_stage_activations", "packet_detection_gaps", "device_recovery_audits"}  # 012/014/015/016/017 add tables; 013 adds columns, 018 rebuilds firewall_rules.
        assert after["scope"] == MQTT_IPV4_TCP_1883
        assert all(after[key] is None for key in rules.SCOPE_COLUMNS - {"scope"})
        assert connection.execute("SELECT firewall_rule_id FROM firewall_release_requests WHERE id=?", (release,)).fetchone()[0] == source
        assert indexes <= {value[0] for value in connection.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='firewall_rules'")}
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("INSERT INTO firewall_rules(source_ip,status) VALUES ('192.168.0.99','PENDING')").lastrowid > 900
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM firewall_rules WHERE id=?", (source,))
    assert apply_migrations(database, MIGRATIONS_DIR).applied_versions == []


@pytest.mark.parametrize("deleted_high", [False, True])
def test_empty_migration_preserves_sequence(tmp_path, deleted_high):
    database = tmp_path / "empty.db"
    apply_migrations(database, migrations_until(tmp_path, 10))
    if deleted_high:
        execute(database, "INSERT INTO firewall_rules(id,source_ip,status) VALUES (500,'192.168.0.31','REMOVED')")
        execute(database, "DELETE FROM firewall_rules")
    apply_migrations(database, MIGRATIONS_DIR)
    with sqlite3.connect(database) as connection:
        identifier = connection.execute("INSERT INTO firewall_rules(source_ip) VALUES ('192.168.0.31')").lastrowid
        assert identifier > (500 if deleted_high else 0)


def test_rebuild_failure_rolls_back_schema_data_sequence_and_metadata(tmp_path):
    database = tmp_path / "rollback.db"
    directory = migrations_until(tmp_path, 10)
    apply_migrations(database, directory)
    source = seed_isolated_source(database)
    with sqlite3.connect(database) as connection:
        before = connection.execute("SELECT * FROM firewall_rules").fetchall()
        seq = connection.execute("SELECT seq FROM sqlite_sequence WHERE name='firewall_rules'").fetchone()
        schema = connection.execute("SELECT sql FROM sqlite_master WHERE name='firewall_rules'").fetchone()
    (directory / "011_pi_input_isolation.sql").write_text((MIGRATIONS_DIR / "011_pi_input_isolation.sql").read_text() + "\nINSERT INTO nonexistent_table VALUES (1);", encoding="utf-8")
    with pytest.raises(MigrationError):
        apply_migrations(database, directory)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        assert connection.execute("SELECT * FROM firewall_rules").fetchall() == before
        assert connection.execute("SELECT seq FROM sqlite_sequence WHERE name='firewall_rules'").fetchone() == seq
        assert connection.execute("SELECT sql FROM sqlite_master WHERE name='firewall_rules'").fetchone() == schema
        assert connection.execute("SELECT max(version) FROM schema_migrations").fetchone()[0] == 10
        assert connection.execute("SELECT count(*) FROM sqlite_master WHERE name IN ('firewall_rules_011','firewall_sequence_011')").fetchone()[0] == 0
        assert connection.execute("SELECT id FROM firewall_rules").fetchone()[0] == source


def test_approval_new_id_keeps_source_device_policy_and_trust_unchanged(environment):
    database, sessions, source = environment
    with sessions() as db:
        before = row(db, source)
        device = db.execute(text("SELECT * FROM devices")).all()
        policies = db.execute(text("SELECT * FROM device_policy_revisions")).all()
    result = approve(sessions, source)
    new = result["item"]
    assert new["id"] != source and new["status"] == "PENDING"
    assert (new["scope"], new["protocol"], new["dest_port"]) == (PI_INPUT_IPV4_ALL, None, None)
    assert (new["source_rule_id"], new["approved_policy_revision"], new["requested_by"]) == (source, 1, ADMIN.principal)
    assert (result["created"], result["replayed"], result["runtime_verified"]) == (True, False, False)
    with sessions() as db:
        assert row(db, source) == before
        assert db.execute(text("SELECT * FROM devices")).all() == device
        assert db.execute(text("SELECT * FROM device_policy_revisions")).all() == policies
        assert db.execute(text("SELECT count(*) FROM trust_score_history")).scalar_one() == 0
        assert db.execute(text("SELECT count(*) FROM isolation_history")).scalar_one() == 0


@pytest.mark.parametrize("status", ["PENDING", "APPLIED", "FAILED", "REMOVED"])
def test_identical_uuid_replay_returns_same_row_even_after_state_changes(environment, status):
    database, sessions, source = environment
    request = payload(source)
    with sessions() as db:
        initial = service.create_firewall_scope_extension(db, **request)
    execute(database, "UPDATE firewall_rules SET status=? WHERE id=?", (status, initial["item"]["id"]))
    execute(database, "UPDATE devices SET ip_address='192.168.0.44',status='normal'")
    with sessions() as db:
        replay = service.create_firewall_scope_extension(db, **request)
        assert replay["item"]["id"] == initial["item"]["id"]
        assert not replay["created"] and replay["replayed"]
        assert replay["item"]["status"] == status
        assert db.execute(text("SELECT count(*) FROM firewall_rules")).scalar_one() == 2


@pytest.mark.parametrize("field,value", [("source_rule_id", 99), ("device_id", "esp32_01"), ("source_ip", "192.168.0.44"), ("approved_policy_revision", 2), ("reason", "different approval"), ("admin", RecoveryAdminContext("different-admin"))])
def test_uuid_replay_changed_binding_denied(environment, field, value):
    _, sessions, source = environment
    request = payload(source)
    with sessions() as db:
        service.create_firewall_scope_extension(db, **request)
    request[field] = value
    request["confirm"] = service.scope_extension_confirmation(request["source_rule_id"], request["source_ip"], request["approved_policy_revision"])
    with sessions() as db, pytest.raises(service.FirewallScopeExtensionError) as error:
        service.create_firewall_scope_extension(db, **request)
    assert error.value.detail["failure_code"] == "REQUEST_ID_BINDING_MISMATCH"


@pytest.mark.parametrize("status", ["PENDING", "APPLIED", "FAILED"])
def test_new_uuid_cannot_bypass_unresolved_wide(environment, status):
    database, sessions, source = environment
    wide = approve(sessions, source)["item"]["id"]
    execute(database, "UPDATE firewall_rules SET status=? WHERE id=?", (status, wide))
    with pytest.raises(service.FirewallScopeExtensionError) as error:
        approve(sessions, source)
    assert error.value.detail["failure_code"] == "WIDE_RULE_REQUIRES_EXACT_RELEASE"


@pytest.mark.parametrize("audit", ["missing", "pending", "historical", "exact"])
def test_new_uuid_requires_completed_exact_release_of_previous_removed_wide(environment, audit):
    database, sessions, source = environment
    wide = approve(sessions, source)["item"]["id"]
    with sessions() as db:
        db.execute(text("UPDATE firewall_rules SET status='FAILED' WHERE id=:id"), {"id": wide})
        if audit != "missing":
            request = releases.create_release_request(db, firewall_rule_id=wide, requested_by=ADMIN.principal, reason="exact wide cleanup", requested_at=NOW)
            if audit != "pending":
                releases.mark_succeeded(db, request_id=request, processed_at=NOW + timedelta(seconds=1 if audit == "historical" else 3))
        db.execute(text("UPDATE firewall_rules SET status='REMOVED',released_at='2026-10-09T12:00:02Z' WHERE id=:id"), {"id": wide})
        db.commit()
    if audit == "exact":
        assert approve(sessions, source)["item"]["id"] > wide
    else:
        with pytest.raises(service.FirewallScopeExtensionError) as error:
            approve(sessions, source)
        assert error.value.detail["failure_code"] == "WIDE_RULE_REQUIRES_EXACT_RELEASE"


@pytest.mark.parametrize("field,value", [("scope", None), ("scope", "UNKNOWN"),
                                        ("protocol", "tcp"), ("dest_port", 1883),
                                        ("source_rule_id", None), ("source_rule_id", 999),
                                        ("approved_policy_revision", None), ("reason", ""),
                                        ("requested_by", ""), ("request_id", None),
                                        ("request_id", "00000000-0000-1000-8000-000000000000"),
                                        ("request_id", "ABCDEF00-0000-4000-8000-000000000000")])
def test_db_checks_and_fk_reject_malformed_wide_rows(environment, field, value):
    _, sessions, source = environment
    wide = approve(sessions, source)["item"]["id"]
    with sessions() as db, pytest.raises(IntegrityError) as error:
        db.execute(text(f"UPDATE firewall_rules SET {field}=:value WHERE id=:id"), {"value": value, "id": wide})
    assert isinstance(error.value.orig, sqlite3.IntegrityError)


def test_legacy_and_wide_coexist_but_each_scope_active_ip_is_unique(environment):
    _, sessions, source = environment
    wide = approve(sessions, source)["item"]["id"]
    with sessions() as db:
        assert db.execute(text("SELECT count(*) FROM firewall_rules WHERE source_ip=:ip AND status IN ('PENDING','APPLIED')"), {"ip": IP}).scalar_one() == 2
        with pytest.raises(IntegrityError) as error:
            db.execute(text("INSERT INTO firewall_rules(device_id,source_ip,scope,protocol,dest_port,reason,source_rule_id,approved_policy_revision,requested_by,request_id) SELECT device_id,source_ip,scope,protocol,dest_port,reason,source_rule_id,approved_policy_revision,requested_by,:nonce FROM firewall_rules WHERE id=:id"), {"nonce": str(uuid4()), "id": wide})
        assert isinstance(error.value.orig, sqlite3.IntegrityError)


@pytest.mark.parametrize("metadata_change", [
    "DELETE FROM schema_migrations WHERE version=11",
    "DELETE FROM schema_migrations WHERE version>=11",
    "UPDATE schema_migrations SET name='wrong_pi_input_isolation' WHERE version=11",
], ids=["011-missing-with-012", "all-post010-missing", "011-name-mismatch-with-012"])
def test_partial_scope_schema_and_inconsistent_migration_metadata_fail_closed(environment, metadata_change):
    database, sessions, source = environment
    execute(database, metadata_change)
    if "version>=11" not in metadata_change:
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT name FROM schema_migrations WHERE version=12").fetchone() == ("device_ai_policy_revisions",)
    with pytest.raises(service.FirewallScopeExtensionError) as error:
        approve(sessions, source)
    assert error.value.status_code == 503 and error.value.detail["failure_code"] == "FIREWALL_SCOPE_SCHEMA_UNAVAILABLE"
    with sessions() as db, pytest.raises(rules.AutomaticResponseBlockedError, match="FIREWALL_SCOPE_SCHEMA_UNAVAILABLE"):
        rules.authorized_automatic_rule(db, rule_id=source, required_status="APPLIED", now=NOW)


@pytest.mark.parametrize("column", sorted(rules.SCOPE_COLUMNS))
def test_missing_required_scope_column_fails_closed_with_012(environment, column):
    database, sessions, source = environment
    execute(database, f"ALTER TABLE firewall_rules RENAME COLUMN {column} TO missing_scope_column")
    with pytest.raises(service.FirewallScopeExtensionError) as error:
        approve(sessions, source)
    assert error.value.status_code == 503 and error.value.detail["failure_code"] == "FIREWALL_SCOPE_SCHEMA_UNAVAILABLE"
    with sessions() as db, pytest.raises(rules.AutomaticResponseBlockedError, match="FIREWALL_SCOPE_SCHEMA_UNAVAILABLE"):
        rules.authorized_automatic_rule(db, rule_id=source, required_status="APPLIED", now=NOW)


@pytest.mark.parametrize("change,code", [
    ("UPDATE devices SET ip_address='192.168.0.44'", "DEVICE_IP_OWNERSHIP_MISMATCH"),
    ("UPDATE devices SET status='normal'", "DEVICE_NOT_ISOLATED"),
    ("NEW_DISABLED", "DISABLE_REQUESTED_OR_DISABLED"),
    ("NEW_ACTIVE", "APPROVED_POLICY_REVISION_CHANGED"),
    ("UPDATE firewall_rules SET status='REMOVED',released_at='2026-10-09T12:00:01Z' WHERE scope='MQTT_IPV4_TCP_1883'", "SOURCE_RULE_CHANGED"),
    ("UPDATE firewall_rules SET source_ip='192.168.0.44' WHERE scope='MQTT_IPV4_TCP_1883'", "SOURCE_RULE_CHANGED"),
])
def test_worker_authorization_rechecks_after_approval(environment, change, code):
    database, sessions, source = environment
    wide = approve(sessions, source)["item"]["id"]
    if change.startswith("NEW_"):
        execute(database, """INSERT INTO device_policy_revisions
            (device_id,revision,effective_from,registration_state,policy_profile,
             expected_publish_interval_seconds,publish_count_max,payload_size_max_bytes,
             packet_rate_max_pps,byte_rate_max_bytes_per_second,created_at,created_by,reason)
            SELECT device_id,2,'2026-10-09T11:59:50Z',?,policy_profile,
                   expected_publish_interval_seconds,publish_count_max,payload_size_max_bytes,
                   packet_rate_max_pps,byte_rate_max_bytes_per_second,created_at,created_by,reason
            FROM device_policy_revisions WHERE revision=1""", (change[4:],))
    else:
        execute(database, change)
    with sessions() as db, pytest.raises(rules.AutomaticResponseBlockedError, match=code):
        rules.authorized_automatic_rule(db, rule_id=wide, required_status="PENDING", now=NOW)


@pytest.mark.parametrize("target", ["source", "wide"])
def test_pending_exact_release_blocks_new_apply_and_failed_retry(environment, target):
    _, sessions, source = environment
    wide = approve(sessions, source)["item"]["id"]
    with sessions() as db:
        db.execute(text("UPDATE firewall_rules SET status='FAILED' WHERE id=:id"), {"id": wide})
        releases.create_release_request(db, firewall_rule_id=source if target == "source" else wide, requested_by=ADMIN.principal, reason="cleanup", requested_at=NOW)
        db.commit()
        with pytest.raises(rules.AutomaticResponseBlockedError, match="FIREWALL_RELEASE_PENDING"):
            rules.reset_failed_to_pending(db, rule_id=wide, requested_at=NOW)
        assert row(db, wide)["status"] == "FAILED"


@pytest.mark.parametrize("wide_status,audit,released,processed,expected", [
    ("PENDING", True, "2026-10-09T12:00:00Z", "2026-10-09T12:00:01Z", False),
    ("APPLIED", True, "2026-10-09T12:00:00Z", "2026-10-09T12:00:00Z", True),
    ("APPLIED", True, "2026-10-09T12:00:00Z", "2026-10-09T12:00:30Z", True),
    ("APPLIED", True, "2026-10-09T12:00:00Z", "2026-10-09T11:59:59Z", False),
    ("APPLIED", False, "2026-10-09T12:00:00Z", "2026-10-09T12:00:30Z", False),
    ("APPLIED", True, None, "2026-10-09T12:00:30Z", False),
])
def test_audited_removed_source_only_restores_existing_applied_wide(environment, wide_status, audit, released, processed, expected):
    database, sessions, source = environment
    wide = approve(sessions, source)["item"]["id"]
    with sessions() as db:
        request = releases.create_release_request(db, firewall_rule_id=source, requested_by=ADMIN.principal, reason="separate legacy release", requested_at=NOW - timedelta(seconds=1))
        db.execute(text("UPDATE firewall_rules SET status='REMOVED',released_at=:time WHERE id=:id"), {"time": released, "id": source})
        db.execute(text("UPDATE firewall_rules SET status=:status WHERE id=:id"), {"status": wide_status, "id": wide})
        db.execute(text("UPDATE firewall_release_requests SET status=:status,processed_at=:processed,last_error=:error WHERE id=:id"), {"status": "SUCCEEDED" if audit else "FAILED", "processed": processed, "error": None if audit else "fixture failed", "id": request})
        db.commit()
        if expected:
            assert rules.authorized_automatic_rule(db, rule_id=wide, required_status=wide_status, now=NOW + timedelta(seconds=40))["id"] == wide
        else:
            with pytest.raises(rules.AutomaticResponseBlockedError, match="SOURCE_RULE_CHANGED"):
                rules.authorized_automatic_rule(db, rule_id=wide, required_status=wide_status, now=NOW + timedelta(seconds=40))


def test_pre011_legacy_queries_join_and_automatic_default_remain_compatible(tmp_path):
    database = tmp_path / "legacy.db"
    apply_migrations(database, migrations_until(tmp_path, 6))
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    try:
        with sessionmaker(bind=engine)() as db:
            identifier = db.execute(text("INSERT INTO firewall_rules(source_ip,status) VALUES (:ip,'APPLIED')"), {"ip": IP}).lastrowid
            request = releases.create_release_request(db, firewall_rule_id=identifier, requested_by="test-admin", reason="legacy release", requested_at=NOW)
            db.commit()
            pending = releases.list_pending_release_requests(db, limit=10)[0]
            assert (pending["id"], pending["rule_scope"], pending["rule_approved_policy_revision"]) == (request, MQTT_IPV4_TCP_1883, None)
            queried = list_firewall_rules(db)["items"][0]
            assert queried["scope"] == MQTT_IPV4_TCP_1883 and queried["protocol"] == "tcp" and queried["dest_port"] == 1883
    finally:
        engine.dispose()


def test_caller_write_is_not_discarded_by_approval(environment):
    _, sessions, source = environment
    with sessions() as db:
        db.execute(text("UPDATE devices SET trust_score=17"))
        with pytest.raises(RuntimeError, match="fresh database transaction"):
            service.create_firewall_scope_extension(db, **payload(source))
        assert db.connection().connection.driver_connection.in_transaction
        assert db.execute(text("SELECT trust_score FROM devices")).scalar_one() == 17
        db.rollback()
        assert db.execute(text("SELECT trust_score FROM devices")).scalar_one() == 20


def test_approval_lock_precedes_writer_and_spans_commit(environment, monkeypatch):
    _, sessions, source = environment
    events = []

    @contextmanager
    def lock(*args, **kwargs):
        events.append("lock")
        try:
            yield
        finally:
            events.append("unlock")

    original = rules._begin_authorization_transaction

    def begin(db, *, write=False):
        assert events == ["lock"] and write
        original(db, write=write)
        events.append("writer")

    monkeypatch.setattr(service, "single_instance_lock", lock)
    monkeypatch.setattr(rules, "_begin_authorization_transaction", begin)
    approve(sessions, source)
    assert events == ["lock", "writer", "unlock"]
