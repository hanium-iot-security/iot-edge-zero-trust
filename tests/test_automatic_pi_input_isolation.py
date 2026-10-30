"""The future-isolation selector never widens existing MQTT rules."""

import pytest
from pydantic import ValidationError
from sqlalchemy import text

from backend.app.config import Settings
from edge.trust import firewall_repository as rules
from edge.trust.automatic_scope_extension import queue_automatic_scope_extensions
from edge.trust.firewall_scope import MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL
from edge.trust.firewall_worker import FirewallPolicy, reconcile
from edge.trust.run_firewall_worker import _print_dry_run, load_firewall_policy, run_worker_cycle
from tests.test_firewall_worker import FakeIptablesRunner, SessionLocal
from tests.test_phase8_firewall_policy_gate import IP, NOW, _row, _seed, environment
from tests.test_pi_input_isolation_worker import _create_wide, _key, _release_request


def enabled(**changes):
    return FirewallPolicy(auto_scope=PI_INPUT_IPV4_ALL, **changes)


def cycle(db, runner, policy=None, *, now=NOW):
    return run_worker_cycle(
        db, runner=runner, policy=policy or enabled(), now=now, with_reconcile=False,
    )[0]


def wide_rows(db):
    return list(db.execute(text("SELECT * FROM firewall_rules WHERE scope=:scope ORDER BY id"),
                           {"scope": PI_INPUT_IPV4_ALL}).mappings())


def test_setting_is_explicit_typed_and_carried_to_worker(monkeypatch):
    monkeypatch.delenv("FIREWALL_AUTO_SCOPE", raising=False)
    assert Settings(_env_file=None).firewall_auto_scope == MQTT_IPV4_TCP_1883
    assert FirewallPolicy().auto_scope == MQTT_IPV4_TCP_1883
    monkeypatch.setenv("FIREWALL_AUTO_SCOPE", PI_INPUT_IPV4_ALL)
    assert load_firewall_policy(Settings(_env_file=None)).auto_scope == PI_INPUT_IPV4_ALL
    monkeypatch.setenv("FIREWALL_AUTO_SCOPE", "ALL")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
    with pytest.raises(ValueError):
        FirewallPolicy(auto_scope="ALL")


@pytest.mark.parametrize("status", ["PENDING", "APPLIED", "FAILED"])
def test_selector_does_not_retroactively_widen_existing_mqtt(environment, status):
    database, sessions = environment
    source = _seed(database, status=status)
    runner = FakeIptablesRunner(installed=[_key(source, MQTT_IPV4_TCP_1883)] if status == "APPLIED" else [])
    with sessions() as db:
        before = _row(db, source)
        for _ in range(3):
            cycle(db, runner)
        assert wide_rows(db) == []
        assert db.execute(text("SELECT count(*) FROM firewall_rules")).scalar_one() == 1
        assert _row(db, source)["scope"] == MQTT_IPV4_TCP_1883
        if status != "PENDING":
            assert _row(db, source) == before
    if status != "PENDING":
        assert runner.calls == []


def test_historical_child_remains_independently_releasable_after_selector_reversion(environment):
    database, sessions = environment
    source = _seed(database, status="APPLIED")
    child = _create_wide(sessions, source)
    runner = FakeIptablesRunner(installed=[_key(source, MQTT_IPV4_TCP_1883)])
    with sessions() as db:
        assert cycle(db, runner, FirewallPolicy()).applied == [child]
        _release_request(db, source)
        cycle(db, runner, FirewallPolicy())
        assert runner.installed == [_key(child)]
        assert reconcile(db, runner=runner, policy=FirewallPolicy(), now=NOW).verified == [child]
        _release_request(db, child)
        cycle(db, runner, FirewallPolicy())
        cycle(db, runner)
        assert runner.installed == []
        assert len(wide_rows(db)) == 1
        assert db.execute(text("SELECT count(*) FROM firewall_release_requests WHERE status='SUCCEEDED'")).scalar_one() == 2


def test_selector_does_not_gate_pre011_worker_processing(SessionLocal):
    runner = FakeIptablesRunner()
    with SessionLocal() as db:
        source = db.execute(text("INSERT INTO firewall_rules(source_ip) VALUES (:ip)"), {"ip": IP}).lastrowid
        db.commit()
        assert cycle(db, runner, enabled()).applied == [source]


@pytest.mark.parametrize("damage", [
    "DELETE FROM schema_migrations WHERE version=11",
    "ALTER TABLE firewall_rules RENAME COLUMN requested_by TO missing_actor",
])
def test_incoherent_scope_schema_still_fails_before_os(environment, damage):
    database, sessions = environment
    source = _seed(database)
    runner = FakeIptablesRunner()
    with sessions() as db:
        db.execute(text(damage))
        db.commit()
        with pytest.raises(rules.AutomaticResponseBlockedError, match="FIREWALL_SCOPE_SCHEMA_UNAVAILABLE"):
            cycle(db, runner)
        assert _row(db, source)["status"] == "PENDING"
    assert runner.calls == []


def test_dry_run_describes_future_direct_scope_without_db_or_os_writes(environment, capsys):
    database, sessions = environment
    _seed(database, status="APPLIED")
    with sessions() as db:
        before = db.connection().connection.driver_connection.total_changes
        _print_dry_run(db, policy=enabled(), now=NOW)
        assert db.connection().connection.driver_connection.total_changes == before
        assert wide_rows(db) == []
    output = capsys.readouterr().out
    assert "FIREWALL_AUTO_SCOPE=PI_INPUT_IPV4_ALL" in output
    assert "one direct wide rule" in output


def test_unused_legacy_queue_still_refuses_existing_snapshot_or_uncommitted_write(environment):
    database, sessions = environment
    _seed(database, status="APPLIED")
    with sessions() as db:
        for statement in ("BEGIN", "UPDATE devices SET trust_score=17"):
            db.execute(text(statement))
            with pytest.raises(RuntimeError, match="fresh database transaction"):
                queue_automatic_scope_extensions(db, policy=enabled(), now=NOW)
            assert db.connection().connection.driver_connection.in_transaction
            db.rollback()
        assert wide_rows(db) == []
