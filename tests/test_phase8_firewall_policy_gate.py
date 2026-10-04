"""Migration 007 policies authorize Worker retries and automatic restoration."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.trust import firewall_repository
from edge.trust.firewall_worker import (
    CHECK, INSERT, LIST_RULES, FirewallPolicy, FirewallRuleSpec,
    build_rule_args, plan_pending_rules, process_pending_rules, reconcile, release_rule,
)
from tests.test_firewall_worker import FakeIptablesRunner, _rule_key


NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
DEVICE = "pico_01"
IP = "192.168.0.31"


@pytest.fixture
def environment(tmp_path: Path):
    database = tmp_path / "worker-policy.db"
    apply_migrations(database, MIGRATIONS_DIR)
    engine = create_engine(f"sqlite:///{database}")
    try:
        yield database, sessionmaker(bind=engine)
    finally:
        engine.dispose()


def _seed(database, *, case="ACTIVE", status="PENDING", source_ip=IP):
    effective = NOW - timedelta(seconds=20)
    registration = None
    initial_state = case if case in {"PENDING", "DISABLED"} else "ACTIVE"
    if case == "NOT_EFFECTIVE":
        effective = NOW + timedelta(seconds=10)
        registration = effective.strftime("%Y-%m-%dT%H:%M:%SZ")
    if case == "BOUNDARY_MISMATCH":
        registration = (effective + timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO devices(device_id,ip_address,status,trust_score,registration_effective_from) "
            "VALUES (?,?,'isolated',20,?)", (DEVICE, IP, registration),
        )
        if case != "MISSING_POLICY":
            _revision(connection, 1, effective, initial_state,
                      "unsupported-profile" if case == "INVALID_PROFILE" else "periodic-sensor-v1")
        if case == "DISABLE_SCHEDULED":
            _revision(connection, 2, NOW + timedelta(seconds=10), "DISABLED")
        if case == "MISSING_SCHEMA":
            connection.execute("DROP TABLE schema_migrations")
        if case == "EMPTY_MIGRATION_METADATA":
            connection.execute("DELETE FROM schema_migrations")
        rule_id = connection.execute(
            "INSERT INTO firewall_rules(device_id,source_ip,status,retry_count,last_error) "
            "VALUES (?,?,?,3,'previous failure')", (DEVICE, source_ip, status),
        ).lastrowid
    return rule_id


def _revision(connection, revision, effective, state, profile="periodic-sensor-v1"):
    connection.execute(
        "INSERT INTO device_policy_revisions (device_id,revision,effective_from,registration_state,"
        "policy_profile,expected_publish_interval_seconds,publish_count_max,payload_size_max_bytes,"
        "packet_rate_max_pps,byte_rate_max_bytes_per_second,created_at,created_by,reason) "
        "VALUES (?,?,?,?,?,5,15,256,100,65536,'2026-10-03T11:59:00Z','test','verified fixture')",
        (DEVICE, revision, effective.strftime("%Y-%m-%dT%H:%M:%SZ"), state, profile),
    )


def _row(db, rule_id):
    return dict(db.execute(text("SELECT * FROM firewall_rules WHERE id=:id"),
                           {"id": rule_id}).mappings().one())


DENIED = [
    ("PENDING", "CURRENT_PENDING"),
    ("NOT_EFFECTIVE", "REGISTRATION_NOT_EFFECTIVE"),
    ("DISABLE_SCHEDULED", "DISABLE_REQUESTED_OR_DISABLED"),
    ("DISABLED", "DISABLE_REQUESTED_OR_DISABLED"),
    ("INVALID_PROFILE", "POLICY_UNAVAILABLE"),
    ("BOUNDARY_MISMATCH", "POLICY_UNAVAILABLE"),
    ("MISSING_POLICY", "POLICY_UNAVAILABLE"),
    ("MISSING_SCHEMA", "POLICY_UNAVAILABLE"),
    ("EMPTY_MIGRATION_METADATA", "POLICY_UNAVAILABLE"),
]


@pytest.mark.parametrize("case,reason", DENIED)
def test_ineligible_pending_rule_never_calls_firewall(environment, case, reason):
    database, sessions = environment
    rule_id = _seed(database, case=case)
    runner = FakeIptablesRunner()
    with sessions() as db:
        result = process_pending_rules(db, runner=runner, policy=FirewallPolicy(), now=NOW)
        row = _row(db, rule_id)
        assert result.validation_failed == [rule_id]
        assert (row["status"], row["last_error"]) == ("FAILED", reason)
        assert db.execute(text("SELECT trust_score FROM devices")).scalar_one() == 20
        assert db.execute(text("SELECT count(*) FROM trust_score_history")).scalar_one() == 0
    assert runner.calls == []


@pytest.mark.parametrize("case,reason", DENIED)
def test_reset_denied_without_modifying_failed_history(environment, case, reason):
    database, sessions = environment
    rule_id = _seed(database, case=case, status="FAILED")
    with sessions() as db:
        before = _row(db, rule_id)
        with pytest.raises(firewall_repository.AutomaticResponseBlockedError, match=reason):
            firewall_repository.reset_failed_to_pending(db, rule_id=rule_id, requested_at=NOW)
        assert _row(db, rule_id) == before


@pytest.mark.parametrize("case,reason", DENIED)
@pytest.mark.parametrize("installed", [False, True])
def test_reconcile_preserves_applied_history_and_never_changes_ineligible_rule(
    environment, case, reason, installed
):
    database, sessions = environment
    rule_id = _seed(database, case=case, status="APPLIED")
    spec = FirewallRuleSpec(rule_id, IP)
    actual = [_rule_key(build_rule_args(spec, operation=INSERT))] if installed else []
    runner = FakeIptablesRunner(installed=actual)
    with sessions() as db:
        before = _row(db, rule_id)
        result = reconcile(db, runner=runner, policy=FirewallPolicy(), now=NOW)
        assert result.validation_failed == [rule_id]
        assert result.restored == []
        assert _row(db, rule_id) == before
    assert runner.operations() == [LIST_RULES]
    assert runner.installed == actual


def test_active_rule_can_retry_then_apply_without_db_lock_during_os(environment):
    database, sessions = environment
    rule_id = _seed(database, status="FAILED")
    runner = FakeIptablesRunner()
    with sessions() as db:
        firewall_repository.reset_failed_to_pending(db, rule_id=rule_id, requested_at=NOW)
        db.commit()
        original_run = runner.run_operation

        def probe(operation, spec=None):
            assert not db.connection().connection.driver_connection.in_transaction
            with sqlite3.connect(database, timeout=0) as another:
                another.execute("BEGIN IMMEDIATE")
                another.rollback()
            return original_run(operation, spec)

        runner.run_operation = probe
        result = process_pending_rules(db, runner=runner, policy=FirewallPolicy(), now=NOW)
        assert result.applied == [rule_id]
        assert _row(db, rule_id)["status"] == "APPLIED"
    assert runner.operations() == [CHECK, INSERT]


def test_active_applied_rule_can_be_restored(environment):
    database, sessions = environment
    rule_id = _seed(database, status="APPLIED")
    runner = FakeIptablesRunner()
    with sessions() as db:
        result = reconcile(db, runner=runner, policy=FirewallPolicy(), now=NOW)
        assert result.restored == [rule_id]
    assert runner.operations() == [LIST_RULES, CHECK, INSERT]


def test_disabled_rule_can_still_be_released_by_operator(environment):
    database, sessions = environment
    rule_id = _seed(database, case="DISABLED", status="APPLIED")
    runner = FakeIptablesRunner(installed=[
        _rule_key(build_rule_args(FirewallRuleSpec(rule_id, IP), operation=INSERT))
    ])
    with sessions() as db:
        assert release_rule(db, rule_id=rule_id, runner=runner, policy=FirewallPolicy(), now=NOW)
        assert _row(db, rule_id)["status"] == "REMOVED"
    assert runner.installed == []


def test_rule_cannot_block_ip_that_its_device_no_longer_owns(environment):
    database, sessions = environment
    rule_id = _seed(database, source_ip="192.168.0.32")
    runner = FakeIptablesRunner()
    with sessions() as db:
        result = process_pending_rules(db, runner=runner, policy=FirewallPolicy(), now=NOW)
        assert result.validation_failed == [rule_id]
        assert _row(db, rule_id)["last_error"] == "DEVICE_IP_OWNERSHIP_MISMATCH"
    assert runner.calls == []


def test_dry_run_uses_same_gate_without_mutating_queue(environment):
    database, sessions = environment
    rule_id = _seed(database, case="DISABLE_SCHEDULED")
    with sessions() as db:
        before = _row(db, rule_id)
        plans = plan_pending_rules(db, policy=FirewallPolicy(), now=NOW)
        assert plans == [(rule_id, "VALIDATION_FAILURE: DISABLE_REQUESTED_OR_DISABLED")]
        assert _row(db, rule_id) == before


def test_existing_transaction_cannot_authorize_os_or_discard_caller_data(environment):
    database, sessions = environment
    _seed(database)
    runner = FakeIptablesRunner()
    with sessions() as db:
        db.execute(text("UPDATE devices SET trust_score=17 WHERE device_id=:id"), {"id": DEVICE})
        with pytest.raises(RuntimeError, match="fresh database transaction"):
            process_pending_rules(db, runner=runner, policy=FirewallPolicy(), now=NOW)
        assert db.execute(text("SELECT trust_score FROM devices")).scalar_one() == 17
        assert db.connection().connection.driver_connection.in_transaction
        db.rollback()
        assert db.execute(text("SELECT trust_score FROM devices")).scalar_one() == 20
    assert runner.calls == []
