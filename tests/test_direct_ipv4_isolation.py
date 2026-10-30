"""Trust v2 creates a single auditable INPUT IPv4 isolation rule."""

from datetime import timedelta
from shutil import copyfile
import sqlite3
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.trust import firewall_repository as rules, trust_score_v2
from edge.trust.firewall_scope import MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL
from edge.trust.firewall_worker import CHECK, LIST_RULES, FirewallPolicy, INSERT, process_pending_rules, reconcile, release_rule
from edge.trust.run_firewall_worker import run_worker_cycle
from tests.test_firewall_worker import FakeIptablesRunner
from tests.test_phase4_trust_firewall import _insert_event
from tests.test_phase8_firewall_policy_gate import DEVICE, IP, NOW, _revision, _row, environment
from tests.test_pi_input_isolation_worker import _key, _release_request


START = NOW - timedelta(seconds=10)


@pytest.mark.parametrize("release_kind,residue", [("cli", False), ("cli", True), ("audited", False)])
def test_next_trust_incident_after_direct_release_preserves_old_identity_and_audit(
    environment, monkeypatch, release_kind, residue,
):
    database, sessions = environment
    _seed_trust(database, sessions)
    old_id = _isolate(sessions, monkeypatch).changes[0].firewall_rule_id
    runner = FakeIptablesRunner()
    with sessions() as db:
        assert _cycle(db, runner).applied == [old_id]
        if release_kind == "cli":
            assert release_rule(db, rule_id=old_id, runner=runner, policy=FirewallPolicy(), now=NOW)
        else:
            _release_request(db, old_id)
            _cycle(db, runner)
        old_rule = _row(db, old_id)
        old_audits = list(db.execute(text("SELECT * FROM firewall_release_requests")).mappings())
        # Model the later recovery/score state; existing recovery suites cover its approval.
        db.execute(text("UPDATE devices SET status='warning',trust_score=45"))
        next_end = NOW + timedelta(seconds=10)
        _insert_event(db, DEVICE, "DEVICE_ID_MISMATCH", incident_family="IDENTITY",
            analysis_window_start=NOW.isoformat(), analysis_window_end=next_end.isoformat(),
            detected_at=next_end.isoformat())
        db.commit()
    with sessions() as db, db.begin():
        result = trust_score_v2.apply_trust_score_v2_until(
            db, cycle_range_start=NOW, cycle_cutoff=next_end, decision_at=next_end)
    new_id = result.changes[0].firewall_rule_id
    assert new_id > old_id
    if residue:
        runner.installed.append(_key(old_id))
    with sessions() as db:
        applied = _cycle(db, runner, now=next_end)
        assert _row(db, old_id) == old_rule
        assert list(db.execute(text("SELECT * FROM firewall_release_requests")).mappings()) == old_audits
        assert db.execute(text("SELECT count(*) FROM firewall_rules")).scalar_one() == 2
        if residue:
            assert applied.validation_failed == [new_id]
            assert runner.installed == [_key(old_id)]
        else:
            assert applied.applied == [new_id]
            assert runner.installed == [_key(new_id)]


def _seed_trust(database, sessions):
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO devices(device_id,ip_address,status,trust_score) VALUES (?,?,'warning',45)",
            (DEVICE, IP),
        )
        _revision(connection, 1, NOW - timedelta(seconds=20), "ACTIVE")
    with sessions() as db:
        event_id = _insert_event(
            db, DEVICE, "DEVICE_ID_MISMATCH", incident_family="IDENTITY",
            analysis_window_start=START.isoformat(), analysis_window_end=NOW.isoformat(),
            detected_at=NOW.isoformat(),
        )
        db.commit()
    return event_id


def _isolate(sessions, monkeypatch, *, scope=PI_INPUT_IPV4_ALL, decision_at=NOW):
    monkeypatch.setattr(trust_score_v2.settings, "firewall_auto_scope", scope)
    with sessions() as db, db.begin():
        return trust_score_v2.apply_trust_score_v2_until(
            db, cycle_range_start=START, cycle_cutoff=NOW, decision_at=decision_at,
        )


def _cycle(db, runner, *, now=NOW, policy=None):
    return run_worker_cycle(
        db, runner=runner, policy=policy or FirewallPolicy(), now=now, with_reconcile=False,
    )[0]


def test_direct_wide_reconcile_keeps_scope_after_future_creation_selector_reverts(environment, monkeypatch):
    database, sessions = environment
    _seed_trust(database, sessions)
    rule_id = _isolate(sessions, monkeypatch).changes[0].firewall_rule_id
    runner = FakeIptablesRunner()
    with sessions() as db:
        assert _cycle(db, runner).applied == [rule_id]
        runner.installed.clear()  # Simulate loss of the OS rule, preserving its DB identity.
        legacy_selector = FirewallPolicy(auto_scope=MQTT_IPV4_TCP_1883)
        assert reconcile(db, runner=runner, policy=legacy_selector, now=NOW).restored == [rule_id]
        assert runner.installed == [_key(rule_id)]
        assert reconcile(db, runner=runner, policy=legacy_selector, now=NOW).verified == [rule_id]
        assert db.execute(text("SELECT count(*) FROM firewall_rules")).scalar_one() == 1
        assert _row(db, rule_id)["scope"] == PI_INPUT_IPV4_ALL
    assert runner.operations().count(INSERT) == 2


def test_future_threshold_crossing_has_one_wide_rule_and_one_exact_release(environment, monkeypatch):
    database, sessions = environment
    event = _seed_trust(database, sessions)
    result = _isolate(sessions, monkeypatch)
    rule_id = result.changes[0].firewall_rule_id
    runner = FakeIptablesRunner()
    with sessions() as db:
        row = _row(db, rule_id)
        assert row["scope"] == PI_INPUT_IPV4_ALL
        assert row["source_rule_id"] is None
        assert row["protocol"] is None and row["dest_port"] is None
        assert row["trigger_event_id"] == event
        assert row["requested_by"] == "system:trust-score-v2"
        assert row["approved_policy_revision"] == 1
        assert UUID(row["request_id"]).version == 4
        assert _cycle(db, runner).applied == [rule_id]
        assert runner.installed == [_key(rule_id)]
        _release_request(db, rule_id)
        _cycle(db, runner)
        _cycle(db, runner, policy=FirewallPolicy(auto_scope=PI_INPUT_IPV4_ALL))
        assert _row(db, rule_id)["status"] == "REMOVED"
        assert db.execute(text("SELECT count(*) FROM firewall_rules")).scalar_one() == 1
        assert db.execute(text("SELECT count(*) FROM firewall_release_requests WHERE status='SUCCEEDED'")).scalar_one() == 1
        assert runner.installed == []
    assert runner.operations().count(INSERT) == 1


def test_default_future_isolation_remains_mqtt(environment, monkeypatch):
    database, sessions = environment
    _seed_trust(database, sessions)
    result = _isolate(sessions, monkeypatch, scope=MQTT_IPV4_TCP_1883)
    with sessions() as db:
        row = _row(db, result.changes[0].firewall_rule_id)
        assert (row["scope"], row["protocol"], row["dest_port"]) == (MQTT_IPV4_TCP_1883, "tcp", 1883)
        assert row["source_rule_id"] is None and row["request_id"] is None


@pytest.mark.parametrize("damage", [
    "DELETE FROM schema_migrations WHERE version=18",
    "UPDATE schema_migrations SET name='wrong' WHERE version=18",
])
def test_missing_direct_migration_rolls_back_entire_trust_transaction(environment, monkeypatch, damage):
    database, sessions = environment
    _seed_trust(database, sessions)
    with sessions() as db:
        db.execute(text(damage))
        db.commit()
        before = {table: db.execute(text(f"SELECT * FROM {table} ORDER BY 1")).fetchall()
                  for table in ("devices", "detection_events", "trust_score_history", "isolation_history",
                                "firewall_rules", "detector_checkpoints")}
    with pytest.raises(rules.AutomaticResponseBlockedError, match="MIGRATION_018_REQUIRED"):
        _isolate(sessions, monkeypatch)
    with sessions() as db:
        for table, rows in before.items():
            assert db.execute(text(f"SELECT * FROM {table} ORDER BY 1")).fetchall() == rows


@pytest.mark.parametrize("forged_marker", [False, True])
def test_actual_017_schema_cannot_authorize_direct_even_with_forged_018_marker(tmp_path, monkeypatch, forged_marker):
    migration_dir = tmp_path / "through017"
    migration_dir.mkdir()
    for source in MIGRATIONS_DIR.glob("*.sql"):
        if int(source.name[:3]) <= 17:
            copyfile(source, migration_dir / source.name)
    database = tmp_path / "017.db"
    apply_migrations(database, migration_dir)
    engine = create_engine(f"sqlite:///{database}")
    sessions = sessionmaker(bind=engine)
    try:
        _seed_trust(database, sessions)
        if forged_marker:
            with sqlite3.connect(database) as connection:
                connection.execute("INSERT INTO schema_migrations(version,name) VALUES (18,'direct_ipv4_isolation')")
        with pytest.raises(rules.AutomaticResponseBlockedError, match="MIGRATION_018_REQUIRED"):
            _isolate(sessions, monkeypatch)
        with sessions() as db:
            assert db.execute(text("SELECT trust_score,status FROM devices")).one() == (45, "warning")
            for table in ("firewall_rules", "trust_score_history", "isolation_history", "detector_checkpoints"):
                assert db.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0
            assert db.execute(text("SELECT applied_to_score FROM detection_events")).scalar_one() == 0
    finally:
        engine.dispose()


@pytest.mark.parametrize("residue", [False, True])
def test_unattested_historical_mqtt_requires_fresh_exact_absence_without_rewriting_history(
    environment, monkeypatch, residue,
):
    database, sessions = environment
    _seed_trust(database, sessions)
    with sessions() as db:
        old_id = db.execute(text("""INSERT INTO firewall_rules(device_id,source_ip,status,released_at)
            VALUES (:device,:ip,'REMOVED','2026-08-01T00:00:00Z')"""), {"device": DEVICE, "ip": IP}).lastrowid
        db.commit()
        historical = _row(db, old_id)
    result = _isolate(sessions, monkeypatch)
    rule_id = result.changes[0].firewall_rule_id
    old_key = _key(old_id, MQTT_IPV4_TCP_1883)
    runner = FakeIptablesRunner(installed=[old_key] if residue else [])
    with sessions() as db:
        result = _cycle(db, runner)
        if residue:
            assert result.validation_failed == [rule_id]
            assert runner.installed == [old_key]
            assert INSERT not in runner.operations()
        else:
            assert result.applied == [rule_id]
            assert runner.installed == [_key(rule_id)]
        assert _row(db, old_id) == historical
        assert db.execute(text("SELECT count(*) FROM firewall_release_requests")).scalar_one() == 0
        assert runner.calls[0][-3:] == [f"hanium-firewall:{old_id}", "-j", "DROP"]


def test_policy_approval_uses_decision_time_not_old_window_cutoff(environment, monkeypatch):
    database, sessions = environment
    _seed_trust(database, sessions)
    with sqlite3.connect(database) as connection:
        _revision(connection, 2, NOW + timedelta(seconds=10), "ACTIVE")
    result = _isolate(sessions, monkeypatch, decision_at=NOW + timedelta(seconds=20, microseconds=123))
    with sessions() as db:
        row = _row(db, result.changes[0].firewall_rule_id)
        assert row["approved_policy_revision"] == 2
        assert row["created_at"] == "2026-10-03T12:00:20Z"


@pytest.mark.parametrize("damage", [
    "event_unapplied", "event_reason", "event_device", "missing_isolation", "history_score",
    "history_policy", "representative", "actor", "uuid", "revision", "ip", "normal", "disable_scheduled",
])
@pytest.mark.parametrize("operation", ["apply", "retry", "reconcile"])
def test_direct_authorization_rechecks_provenance_and_policy_before_os(
    environment, monkeypatch, damage, operation,
):
    database, sessions = environment
    _seed_trust(database, sessions)
    rule_id = _isolate(sessions, monkeypatch).changes[0].firewall_rule_id
    runner = FakeIptablesRunner()
    changes = {
        "event_unapplied": "UPDATE detection_events SET applied_to_score=0",
        "event_reason": "UPDATE detection_events SET processing_reason='NOT_REPRESENTATIVE'",
        "event_device": "UPDATE detection_events SET device_id='another-device'",
        "missing_isolation": "DELETE FROM isolation_history",
        "history_score": "UPDATE trust_score_history SET new_score=35",
        "history_policy": "UPDATE trust_score_history SET policy_version='legacy'",
        "representative": "UPDATE trust_score_history SET representative_event_ids_json='[]'",
        "actor": "UPDATE firewall_rules SET requested_by='fixture-admin'",
        "uuid": "UPDATE firewall_rules SET request_id='invalid'",
        "ip": "UPDATE devices SET ip_address='192.168.0.99'",
        "normal": "UPDATE devices SET status='normal'",
    }
    with sessions() as db:
        if operation != "apply":
            db.execute(text("UPDATE firewall_rules SET status=:status"),
                       {"status": "FAILED" if operation == "retry" else "APPLIED"})
        db.execute(text("PRAGMA ignore_check_constraints=ON"))
        if damage in {"revision", "disable_scheduled"}:
            _revision(db.connection().connection.driver_connection, 2,
                      NOW + timedelta(seconds=10) if damage == "disable_scheduled" else NOW,
                      "DISABLED" if damage == "disable_scheduled" else "ACTIVE")
        else:
            db.execute(text(changes[damage]))
        db.commit()
        before = _row(db, rule_id)
        if operation == "apply":
            assert process_pending_rules(db, runner=runner, policy=FirewallPolicy(), now=NOW).validation_failed == [rule_id]
        elif operation == "retry":
            with pytest.raises(rules.AutomaticResponseBlockedError):
                rules.reset_failed_to_pending(db, rule_id=rule_id, requested_at=NOW)
            assert _row(db, rule_id) == before
        else:
            assert reconcile(db, runner=runner, policy=FirewallPolicy(), now=NOW).validation_failed == [rule_id]
            assert _row(db, rule_id) == before
    assert runner.operations() == ([LIST_RULES] if operation == "reconcile" else [])


@pytest.mark.parametrize("scope", [MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL])
@pytest.mark.parametrize("match", ["device", "ip"])
def test_failed_sibling_in_either_scope_or_identity_prevents_apply(environment, monkeypatch, scope, match):
    database, sessions = environment
    _seed_trust(database, sessions)
    rule_id = _isolate(sessions, monkeypatch).changes[0].firewall_rule_id
    with sessions() as db:
        owner, address = (DEVICE, "192.168.0.99") if match == "device" else (None, IP)
        if scope == MQTT_IPV4_TCP_1883:
            db.execute(text("INSERT INTO firewall_rules(device_id,source_ip,status) VALUES (:owner,:ip,'FAILED')"),
                       {"owner": owner, "ip": address})
        else:
            # Historical child rows can share an IP with a different device.
            db.execute(text("""INSERT INTO firewall_rules(device_id,source_ip,status,scope,protocol,dest_port,
                source_rule_id,approved_policy_revision,requested_by,request_id,reason)
                VALUES (:owner,:ip,'FAILED',:scope,NULL,NULL,:source,1,'test',:request,'old child')"""),
                {"owner": owner, "ip": address, "scope": scope, "source": rule_id, "request": str(uuid4())})
        db.commit()
        runner = FakeIptablesRunner()
        assert process_pending_rules(db, runner=runner, policy=FirewallPolicy(), now=NOW).validation_failed == [rule_id]
        assert runner.calls == []


@pytest.mark.parametrize("case", ["protected", "release"])
def test_direct_protected_or_pending_release_never_applies(environment, monkeypatch, case):
    database, sessions = environment
    _seed_trust(database, sessions)
    rule_id = _isolate(sessions, monkeypatch).changes[0].firewall_rule_id
    runner = FakeIptablesRunner()
    with sessions() as db:
        policy = FirewallPolicy(protected_ips=frozenset({IP})) if case == "protected" else FirewallPolicy()
        if case == "release":
            db.execute(text("UPDATE firewall_rules SET status='APPLIED'"))
            db.commit()
            _release_request(db, rule_id)
            db.execute(text("UPDATE firewall_rules SET status='PENDING'"))
            db.commit()
        assert process_pending_rules(db, runner=runner, policy=policy, now=NOW).validation_failed == [rule_id]
    assert runner.calls == []


def test_transient_and_crash_retries_keep_one_identity_and_release_consumes_trigger(environment, monkeypatch):
    database, sessions = environment
    event = _seed_trust(database, sessions)
    rule_id = _isolate(sessions, monkeypatch).changes[0].firewall_rule_id
    runner = FakeIptablesRunner(fail_operations={INSERT: 1})
    with sessions() as db:
        assert _cycle(db, runner).transient_failed == [rule_id]
        before = _row(db, rule_id)
        # Model an OS insert that succeeded just before the DB commit crashed.
        runner.installed.append(_key(rule_id))
        assert _cycle(db, runner, now=NOW + timedelta(seconds=30)).already_present == [rule_id]
        assert _row(db, rule_id)["request_id"] == before["request_id"]
        _release_request(db, rule_id)
        _cycle(db, runner, now=NOW + timedelta(seconds=30))
        released = _row(db, rule_id)
        db.rollback()
        with db.begin():
            db.execute(text("BEGIN IMMEDIATE"))
            assert rules.create_pending_rule_for_device(
                db, device_id=DEVICE, source_ip=IP, reason=trust_score_v2.ISOLATION_REASON,
                trigger_event_id=event, scope=PI_INPUT_IPV4_ALL, now=NOW + timedelta(seconds=40),
            ) == rule_id
        assert _row(db, rule_id) == released
        assert db.execute(text("SELECT count(*) FROM firewall_rules")).scalar_one() == 1
        assert runner.installed == []


def test_reconcile_freshly_checks_unattested_mqtt_after_previous_success(environment, monkeypatch):
    database, sessions = environment
    _seed_trust(database, sessions)
    with sessions() as db:
        old_id = db.execute(text("INSERT INTO firewall_rules(device_id,source_ip,status) VALUES (:device,:ip,'REMOVED')"),
                            {"device": DEVICE, "ip": IP}).lastrowid
        db.commit()
    rule_id = _isolate(sessions, monkeypatch).changes[0].firewall_rule_id
    with sessions() as db:
        assert _cycle(db, FakeIptablesRunner()).applied == [rule_id]
        runner = FakeIptablesRunner(installed=[_key(old_id, MQTT_IPV4_TCP_1883)])
        result = reconcile(db, runner=runner, policy=FirewallPolicy(), now=NOW)
        assert result.validation_failed == [rule_id]
        assert runner.operations() == [LIST_RULES, CHECK]
        assert _row(db, rule_id)["status"] == "APPLIED"


@pytest.mark.parametrize("scope", [MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL])
@pytest.mark.parametrize("operation", ["apply", "reconcile"])
def test_unattested_removal_unknown_check_never_inserts_and_can_retry(
    environment, monkeypatch, scope, operation,
):
    database, sessions = environment
    _seed_trust(database, sessions)
    with sessions() as db:
        old_id = db.execute(text("INSERT INTO firewall_rules(device_id,source_ip,status) VALUES (:device,:ip,'REMOVED')"),
            {"device": DEVICE, "ip": IP}).lastrowid
        if scope == PI_INPUT_IPV4_ALL:
            old_id = db.execute(text("""INSERT INTO firewall_rules
                (device_id,source_ip,status,scope,protocol,dest_port,source_rule_id,
                 approved_policy_revision,requested_by,request_id,reason)
                VALUES (:device,:ip,'REMOVED',:scope,NULL,NULL,:parent,1,'test-admin',:request,'old extension')"""),
                {"device": DEVICE, "ip": IP, "scope": scope, "parent": old_id, "request": str(uuid4())}).lastrowid
        db.commit()
        old_rows = list(db.execute(text("SELECT * FROM firewall_rules ORDER BY id")).mappings())
    rule_id = _isolate(sessions, monkeypatch).changes[0].firewall_rule_id
    runner = FakeIptablesRunner()
    with sessions() as db:
        if operation == "reconcile":
            assert _cycle(db, runner).applied == [rule_id]
            runner.installed.clear()
        runner.calls.clear()
        original = runner.run_operation
        failed = False

        def unknown_once(operation_name, spec=None):
            nonlocal failed
            if operation_name == CHECK and spec.rule_id == old_id and not failed:
                runner.fail_operations[CHECK] = 1
                failed = True
            return original(operation_name, spec)

        runner.run_operation = unknown_once
        if operation == "apply":
            assert _cycle(db, runner).transient_failed == [rule_id]
            assert _row(db, rule_id)["status"] == "PENDING"
        else:
            assert reconcile(db, runner=runner, policy=FirewallPolicy(), now=NOW).restore_failed == [rule_id]
            assert _row(db, rule_id)["status"] == "APPLIED"
        assert INSERT not in runner.operations()
        assert runner.installed == []
        assert list(db.execute(text("SELECT * FROM firewall_rules WHERE id<>:id ORDER BY id"),
            {"id": rule_id}).mappings()) == old_rows
        assert db.execute(text("SELECT count(*) FROM firewall_release_requests")).scalar_one() == 0
        later = NOW + timedelta(seconds=30)
        if operation == "apply":
            assert _cycle(db, runner, now=later).applied == [rule_id]
        else:
            assert reconcile(db, runner=runner, policy=FirewallPolicy(), now=later).restored == [rule_id]
        assert runner.installed == [_key(rule_id)]


@pytest.mark.parametrize("status", ["PENDING", "APPLIED", "FAILED", "pending_release"])
def test_unresolved_old_rule_rolls_back_new_trust_isolation(environment, monkeypatch, status):
    database, sessions = environment
    _seed_trust(database, sessions)
    with sessions() as db:
        old_id = db.execute(text("INSERT INTO firewall_rules(device_id,source_ip,status) VALUES (:device,:ip,:status)"),
                            {"device": DEVICE, "ip": IP, "status": "APPLIED" if status == "pending_release" else status}).lastrowid
        db.commit()
        if status == "pending_release":
            _release_request(db, old_id)
            db.execute(text("UPDATE firewall_rules SET status='REMOVED' WHERE id=:id"), {"id": old_id})
            db.commit()
        before = _row(db, old_id)
    with pytest.raises(rules.AutomaticResponseBlockedError, match="EXACT_RELEASE|RELEASE_PENDING"):
        _isolate(sessions, monkeypatch)
    with sessions() as db:
        assert _row(db, old_id) == before
        assert db.execute(text("SELECT trust_score,status FROM devices")).one() == (45, "warning")
        assert db.execute(text("SELECT count(*) FROM firewall_rules")).scalar_one() == 1
        assert db.execute(text("SELECT count(*) FROM trust_score_history")).scalar_one() == 0
