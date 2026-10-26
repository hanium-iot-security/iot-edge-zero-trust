"""Opt-in automatic scope extension against real SQLite policy/audit state."""

from datetime import timedelta
from uuid import UUID

import pytest
from pydantic import ValidationError
from sqlalchemy import text

from backend.app.config import Settings
from edge.trust import firewall_repository as rules
from edge.trust.firewall_scope import MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL
from edge.trust.firewall_worker import FirewallPolicy, INSERT, reconcile
from edge.trust.run_firewall_worker import _print_dry_run, load_firewall_policy, run_worker_cycle
from tests.test_firewall_worker import FakeIptablesRunner, SessionLocal
from tests.test_phase8_firewall_policy_gate import (
    DEVICE, IP, NOW, _revision, _row, _seed, environment,
)
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


def test_existing_applied_source_queues_once_then_applies_next_cycle(environment):
    database, sessions = environment
    source = _seed(database, status="APPLIED")
    runner = FakeIptablesRunner(installed=[_key(source, MQTT_IPV4_TCP_1883)])
    with sessions() as db:
        _revision(db.connection().connection.driver_connection, 2, NOW - timedelta(seconds=10), "ACTIVE")
        db.commit()
        before = _row(db, source)
        assert cycle(db, runner).processed_count == 0
        wide = wide_rows(db)[0]
        assert wide["status"] == "PENDING"
        assert wide["id"] != source and wide["source_rule_id"] == source
        assert wide["approved_policy_revision"] == 2
        assert wide["requested_by"] == "system:firewall-worker"
        assert "FIREWALL_AUTO_SCOPE=PI_INPUT_IPV4_ALL" in wide["reason"]
        assert "automatic" in wide["reason"].lower()
        assert UUID(wide["request_id"]).version == 4
        assert _row(db, source) == before
        assert runner.calls == []
        assert cycle(db, runner).applied == [wide["id"]]
        assert cycle(db, runner).processed_count == 0
        assert len(wide_rows(db)) == 1
        assert _row(db, source) == before
        assert db.execute(text("SELECT trust_score,status FROM devices")).one() == (20, "isolated")
        assert db.execute(text("SELECT count(*) FROM trust_score_history")).scalar_one() == 0
    assert set(runner.installed) == {_key(source, MQTT_IPV4_TCP_1883), _key(wide["id"])}


def test_exact_releases_do_not_respawn_but_manual_reextension_remains_usable(environment):
    database, sessions = environment
    source = _seed(database, status="APPLIED")
    runner = FakeIptablesRunner(installed=[_key(source, MQTT_IPV4_TCP_1883)])
    with sessions() as db:
        cycle(db, runner)
        first = wide_rows(db)[0]["id"]
        cycle(db, runner)
        _release_request(db, first)
        cycle(db, runner)
        assert _row(db, first)["status"] == "REMOVED"
        assert runner.installed == [_key(source, MQTT_IPV4_TCP_1883)]
        for _ in range(2):
            cycle(db, runner)
        assert len(wide_rows(db)) == 1
    manual = _create_wide(sessions, source)
    with sessions() as db:
        assert cycle(db, runner).applied == [manual]
        _release_request(db, source)
        cycle(db, runner)
        assert runner.installed == [_key(manual)]
        result = reconcile(db, runner=runner, policy=enabled(), now=NOW)
        assert result.verified == [manual]
        _release_request(db, manual)
        cycle(db, runner)
        assert runner.installed == []
        assert len(wide_rows(db)) == 2
        assert db.execute(text("SELECT count(*) FROM firewall_release_requests WHERE status='SUCCEEDED'")).scalar_one() == 3


def test_default_preserves_applied_source_without_extension(environment):
    database, sessions = environment
    source = _seed(database, status="APPLIED")
    runner = FakeIptablesRunner()
    with sessions() as db:
        before = _row(db, source)
        cycle(db, runner, FirewallPolicy())
        assert wide_rows(db) == []
        assert _row(db, source) == before
    assert runner.calls == []


def test_pre011_legacy_cycle_works_but_opt_in_fails_before_os_changes(SessionLocal):
    runner = FakeIptablesRunner()
    with SessionLocal() as db:
        source = db.execute(text("INSERT INTO firewall_rules(source_ip) VALUES (:ip)"), {"ip": IP}).lastrowid
        db.commit()
        with pytest.raises(rules.AutomaticResponseBlockedError, match="MIGRATION_011_REQUIRED"):
            cycle(db, runner, enabled())
        assert runner.calls == []
        assert _row(db, source)["status"] == "PENDING"
        assert cycle(db, runner, FirewallPolicy()).applied == [source]


@pytest.mark.parametrize("damage", [
    "DELETE FROM schema_migrations WHERE version=11",
    "ALTER TABLE firewall_rules RENAME COLUMN requested_by TO missing_actor",
])
def test_incoherent_schema_fails_clearly_before_any_os_change(environment, damage):
    database, sessions = environment
    _seed(database)
    runner = FakeIptablesRunner()
    with sessions() as db:
        db.execute(text(damage))
        db.commit()
        with pytest.raises(rules.AutomaticResponseBlockedError, match="FIREWALL_SCOPE_SCHEMA_UNAVAILABLE"):
            cycle(db, runner)
    assert runner.calls == []


@pytest.mark.parametrize("change", ["DISABLE_SCHEDULED", "DISABLED", "MISSING_POLICY", "INVALID_PROFILE", "normal", "ip", "protected", "release"])
def test_ineligible_source_never_queues_or_calls_os(environment, change):
    database, sessions = environment
    source = _seed(database, status="APPLIED", case=change)
    runner = FakeIptablesRunner()
    with sessions() as db:
        policy = enabled()
        if change == "normal":
            db.execute(text("UPDATE devices SET status='normal'"))
        elif change == "ip":
            db.execute(text("UPDATE devices SET ip_address='192.168.0.99'"))
        elif change == "protected":
            policy = enabled(protected_ips=frozenset({IP}))
        elif change == "release":
            _release_request(db, source)
        db.commit()
        if change == "release":
            # Exercise queue gate while the release is still pending.
            from edge.trust.automatic_scope_extension import queue_automatic_scope_extensions
            assert queue_automatic_scope_extensions(db, policy=policy, now=NOW) == []
        else:
            cycle(db, runner, policy)
        assert wide_rows(db) == []
    assert runner.calls == []


@pytest.mark.parametrize("change", ["revision", "ip", "disabled", "protected"])
def test_application_rechecks_changes_after_queue_and_failed_row_never_respawns(environment, change):
    database, sessions = environment
    source = _seed(database, status="APPLIED")
    runner = FakeIptablesRunner(installed=[_key(source, MQTT_IPV4_TCP_1883)])
    with sessions() as db:
        cycle(db, runner)
        wide = wide_rows(db)[0]["id"]
        policy = enabled()
        if change == "revision":
            _revision(db.connection().connection.driver_connection, 2, NOW - timedelta(seconds=10), "ACTIVE")
        elif change == "disabled":
            _revision(db.connection().connection.driver_connection, 2, NOW + timedelta(seconds=10), "DISABLED")
        elif change == "ip":
            db.execute(text("UPDATE devices SET ip_address='192.168.0.99'"))
        else:
            policy = enabled(protected_ips=frozenset({IP}))
        db.commit()
        assert cycle(db, runner, policy).validation_failed == [wide]
        cycle(db, runner, policy)
        assert _row(db, wide)["status"] == "FAILED" and len(wide_rows(db)) == 1
    assert runner.calls == []


def test_transient_retries_exhaust_same_row_without_automatic_respawn(environment):
    database, sessions = environment
    source = _seed(database, status="APPLIED")
    runner = FakeIptablesRunner(installed=[_key(source, MQTT_IPV4_TCP_1883)], fail_operations={INSERT: 3})
    with sessions() as db:
        cycle(db, runner)
        wide = wide_rows(db)[0]["id"]
        for seconds in (0, 30, 60):
            assert cycle(db, runner, now=NOW + timedelta(seconds=seconds)).transient_failed == [wide]
            assert len(wide_rows(db)) == 1
        cycle(db, runner, now=NOW + timedelta(seconds=90))
        assert _row(db, wide)["status"] == "FAILED"
        assert _row(db, wide)["retry_count"] == 3 and len(wide_rows(db)) == 1


def test_batch_allowance_keeps_queue_bounded_and_defers_new_wide_apply(environment):
    database, sessions = environment
    source = _seed(database)
    runner = FakeIptablesRunner()
    with sessions() as db:
        policy = enabled(batch_size=1)
        assert cycle(db, runner, policy).applied == [source]
        assert wide_rows(db) == []
        assert cycle(db, runner, policy).processed_count == 0
        wide = wide_rows(db)[0]
        assert wide["status"] == "PENDING"
        assert cycle(db, runner, policy).applied == [wide["id"]]


def test_dry_run_discloses_automatic_expansion_without_db_or_os_writes(environment, capsys):
    database, sessions = environment
    _seed(database, status="APPLIED")
    with sessions() as db:
        before = db.connection().connection.driver_connection.total_changes
        _print_dry_run(db, policy=enabled(), now=NOW)
        assert db.connection().connection.driver_connection.total_changes == before
        assert wide_rows(db) == []
    assert "FIREWALL_AUTO_SCOPE=PI_INPUT_IPV4_ALL" in capsys.readouterr().out


def test_queue_refuses_existing_snapshot_or_uncommitted_write(environment):
    from edge.trust.automatic_scope_extension import queue_automatic_scope_extensions
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


def test_release_processed_before_pending_wide_apply(environment):
    database, sessions = environment
    source = _seed(database, status="APPLIED")
    runner = FakeIptablesRunner(installed=[_key(source, MQTT_IPV4_TCP_1883)])
    with sessions() as db:
        cycle(db, runner)
        wide = wide_rows(db)[0]["id"]
        _release_request(db, source)
        assert cycle(db, runner).validation_failed == [wide]
        assert _row(db, source)["status"] == "REMOVED"
        assert _row(db, wide)["status"] == "FAILED"
        assert runner.installed == []
        cycle(db, runner)
        assert len(wide_rows(db)) == 1
    assert all(f"hanium-firewall:{wide}" not in call for call in runner.calls)
