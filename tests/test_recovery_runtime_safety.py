"""Recovery must prove runtime release after the last firewall operation."""

from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import threading

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend.app.config import settings
from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.trust import baseline_recovery, firewall_repository, firewall_release_repository
from edge.runtime_lock import RuntimeLockError, single_instance_lock
from edge.trust import firewall_runtime_snapshot, run_baseline_recovery, run_firewall_runtime_snapshot
from edge.trust.firewall_runtime_snapshot import (
    capture_firewall_runtime_snapshot,
    verify_firewall_runtime_snapshot,
)
from edge.trust.firewall_worker import (
    CHECK, INSERT, LIST_RULES, CommandResult, FirewallPolicy,
    FirewallTransientError, process_pending_rules, process_pending_release_requests, reconcile, release_rule,
)


DEVICE = "esp32_01"
IP = "192.168.0.21"


class FakeFirewall:
    def __init__(self):
        self.rules = {}
        self.timeout_after_insert = False
        self.timeout_after_delete = False
        self.before_operation = lambda: None

    def run_operation(self, operation, spec=None):
        self.before_operation()
        if operation == LIST_RULES:
            return CommandResult(returncode=0, stdout="\n".join(
                f'-A INPUT -s {ip}/32 -p tcp -m tcp --dport 1883 '
                f'-m comment --comment "hanium-firewall:{rule_id}" -j DROP'
                for rule_id, ip in self.rules.items()
            ))
        if operation == CHECK:
            return CommandResult(returncode=0 if spec.rule_id in self.rules else 1)
        if operation == INSERT:
            self.rules[spec.rule_id] = spec.source_ip
            if self.timeout_after_insert:
                raise FirewallTransientError("timeout after OS applied the rule")
        else:
            self.rules.pop(spec.rule_id, None)
            if self.timeout_after_delete:
                raise FirewallTransientError("timeout after OS deleted the rule")
        return CommandResult(returncode=0)


@pytest.fixture
def recovery_env(tmp_path, monkeypatch):
    database = tmp_path / "recovery.db"
    apply_migrations(database, MIGRATIONS_DIR)
    with sqlite3.connect(database) as db:
        db.execute("INSERT INTO devices(device_id,ip_address,status,trust_score) "
                   "VALUES (?,?,'isolated',20)", (DEVICE, IP))
    monkeypatch.setattr(settings, "firewall_runtime_snapshot_path", str(tmp_path / "runtime.json"))
    monkeypatch.setattr(settings, "firewall_lock_path", str(tmp_path / "firewall.lock"))
    monkeypatch.setattr(settings, "firewall_lock_wait_seconds", 0)
    engine = create_engine(f"sqlite:///{database}")
    try:
        yield database, sessionmaker(bind=engine), FakeFirewall(), tmp_path
    finally:
        engine.dispose()


def recover(database, artifacts):
    return baseline_recovery.execute_baseline_recovery(
        db_path=database, device_ids=[DEVICE], expected_trust_scores={DEVICE: 20},
        artifact_dir=artifacts, confirm=baseline_recovery.CONFIRMATION,
    )


def state(database):
    with sqlite3.connect(database) as db:
        return db.execute("SELECT status,trust_score FROM devices WHERE device_id=?", (DEVICE,)).fetchone()


def test_snapshot_before_last_attempt_is_rejected_even_inside_ttl(recovery_env):
    _, _, runner, _ = recovery_env
    now = datetime.now(timezone.utc).replace(microsecond=0)
    capture_firewall_runtime_snapshot(runner, snapshot_path=settings.firewall_runtime_snapshot_path,
                                      observed_at=now - timedelta(seconds=3))
    result = verify_firewall_runtime_snapshot(
        {"device_id": DEVICE, "ip_address": IP,
         "last_firewall_activity_at": (now - timedelta(seconds=1)).isoformat()},
        snapshot_path=settings.firewall_runtime_snapshot_path, max_age_seconds=15, now=now,
    )
    assert result["passed"] is False


def test_timeout_after_os_insert_cannot_reset_failed_rule_device(recovery_env):
    database, sessions, runner, tmp_path = recovery_env
    now = datetime.now(timezone.utc).replace(microsecond=0)
    capture_firewall_runtime_snapshot(runner, snapshot_path=settings.firewall_runtime_snapshot_path,
                                      observed_at=now - timedelta(seconds=3))
    runner.timeout_after_insert = True
    with sessions() as db:
        rule_id = firewall_repository.create_pending_rule_for_device(
            db, device_id=DEVICE, source_ip=IP, reason="test", trigger_event_id=None,
        )
        db.execute(text("UPDATE firewall_rules SET retry_count=2 WHERE id=:id"), {"id": rule_id})
        db.commit()
        process_pending_rules(db, runner=runner, policy=FirewallPolicy(), now=now - timedelta(seconds=1))
        assert db.execute(text("SELECT status FROM firewall_rules WHERE id=:id"), {"id": rule_id}).scalar() == "FAILED"
    assert runner.rules == {rule_id: IP}
    with pytest.raises(baseline_recovery.BaselineRecoveryError, match="[Rr]untime"):
        recover(database, tmp_path / "artifacts")
    assert state(database) == ("isolated", 20)


def test_core_and_cli_cannot_bypass_missing_runtime_snapshot(recovery_env):
    database, _, _, tmp_path = recovery_env
    with pytest.raises(baseline_recovery.BaselineRecoveryError, match="[Rr]untime"):
        recover(database, tmp_path / "artifacts")
    assert state(database) == ("isolated", 20)
    assert run_baseline_recovery.main([
        "execute", "--db-path", str(database), "--device", DEVICE,
        "--expected-trust-score", f"{DEVICE}=20", "--artifact-dir", str(tmp_path / "cli-artifacts"),
        "--confirm", baseline_recovery.CONFIRMATION,
    ]) == 2
    assert state(database) == ("isolated", 20)


@pytest.mark.parametrize("offset", [0, -1])
def test_same_second_or_pre_attempt_snapshot_is_not_proof(recovery_env, offset):
    _, _, runner, _ = recovery_env
    now = datetime.now(timezone.utc).replace(microsecond=0)
    capture_firewall_runtime_snapshot(runner, snapshot_path=settings.firewall_runtime_snapshot_path,
                                      observed_at=now + timedelta(seconds=offset))
    result = verify_firewall_runtime_snapshot(
        {"ip_address": IP, "last_firewall_activity_at": now.isoformat()},
        snapshot_path=settings.firewall_runtime_snapshot_path, max_age_seconds=15, now=now,
    )
    assert result["status"] == "UNAVAILABLE"


def _seed_rule(database, status, attempted_at):
    with sqlite3.connect(database) as db:
        return db.execute(
            "INSERT INTO firewall_rules(device_id,source_ip,status,last_attempted_at,applied_at) "
            "VALUES (?,?,?,?,?)", (DEVICE, IP, status, attempted_at.isoformat(), attempted_at.isoformat()),
        ).lastrowid


def test_fresh_snapshot_of_failed_residual_rule_still_blocks(recovery_env):
    database, _, runner, tmp_path = recovery_env
    now = datetime.now(timezone.utc).replace(microsecond=0)
    rule_id = _seed_rule(database, "FAILED", now - timedelta(seconds=3))
    runner.rules[rule_id] = IP
    capture_firewall_runtime_snapshot(runner, snapshot_path=settings.firewall_runtime_snapshot_path, observed_at=now)
    with pytest.raises(baseline_recovery.BaselineRecoveryHoldError, match="still has"):
        recover(database, tmp_path / "artifacts")
    assert state(database) == ("isolated", 20)


def test_release_success_then_new_snapshot_allows_recovery(recovery_env):
    database, sessions, runner, tmp_path = recovery_env
    now = datetime.now(timezone.utc).replace(microsecond=0)
    rule_id = _seed_rule(database, "APPLIED", now - timedelta(seconds=10))
    runner.rules[rule_id] = IP
    with sessions() as db:
        assert release_rule(db, rule_id=rule_id, runner=runner, policy=FirewallPolicy(), now=now - timedelta(seconds=2))
    capture_firewall_runtime_snapshot(runner, snapshot_path=settings.firewall_runtime_snapshot_path, observed_at=now)
    result = recover(database, tmp_path / "artifacts")
    assert result["runtime_firewall_check"][DEVICE]["observed_at"] == now.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert state(database) == ("normal", 100)


def test_os_delete_timeout_keeps_db_applied_and_recovery_denied(recovery_env):
    database, sessions, runner, tmp_path = recovery_env
    now = datetime.now(timezone.utc).replace(microsecond=0)
    rule_id = _seed_rule(database, "APPLIED", now - timedelta(seconds=10))
    runner.rules[rule_id] = IP
    runner.timeout_after_delete = True

    def verify_os_runs_without_db_write_lock():
        with sqlite3.connect(database, timeout=0) as probe:
            probe.execute("BEGIN IMMEDIATE")
            probe.rollback()

    runner.before_operation = verify_os_runs_without_db_write_lock
    with sessions() as db:
        request_id = firewall_release_repository.create_release_request(
            db, firewall_rule_id=rule_id, requested_by="test", reason="test", requested_at=now - timedelta(seconds=2),
        )
        db.commit()
        result = process_pending_release_requests(db, runner=runner, policy=FirewallPolicy(), now=now - timedelta(seconds=1))
        assert result.failed == [request_id]
    assert runner.rules == {}
    capture_firewall_runtime_snapshot(runner, snapshot_path=settings.firewall_runtime_snapshot_path, observed_at=now)
    with pytest.raises(baseline_recovery.BaselineRecoveryError, match="Firewall Rule"):
        recover(database, tmp_path / "artifacts")
    assert state(database) == ("isolated", 20)


def test_failed_release_attempt_requires_later_observation(recovery_env):
    database, _, runner, tmp_path = recovery_env
    now = datetime.now(timezone.utc).replace(microsecond=0)
    rule_id = _seed_rule(database, "REMOVED", now - timedelta(seconds=10))
    with sqlite3.connect(database) as db:
        db.execute(
            "INSERT INTO firewall_release_requests(firewall_rule_id,status,requested_by,reason,requested_at,processed_at,last_error) "
            "VALUES (?,'FAILED','test','test',?,?,'timeout')",
            (rule_id, (now - timedelta(seconds=3)).isoformat(), (now - timedelta(seconds=1)).isoformat()),
        )
    capture_firewall_runtime_snapshot(runner, snapshot_path=settings.firewall_runtime_snapshot_path,
                                      observed_at=now - timedelta(seconds=2))
    with pytest.raises(baseline_recovery.BaselineRecoveryHoldError, match="after the last"):
        recover(database, tmp_path / "artifacts")
    capture_firewall_runtime_snapshot(runner, snapshot_path=settings.firewall_runtime_snapshot_path, observed_at=now)
    assert recover(database, tmp_path / "retry")["result"] == "SUCCESS"


def test_disappeared_applied_rule_does_not_allow_baseline_reset(recovery_env):
    database, sessions, runner, tmp_path = recovery_env
    now = datetime.now(timezone.utc).replace(microsecond=0)
    rule_id = _seed_rule(database, "APPLIED", now - timedelta(seconds=10))
    capture_firewall_runtime_snapshot(runner, snapshot_path=settings.firewall_runtime_snapshot_path, observed_at=now)
    with pytest.raises(baseline_recovery.BaselineRecoveryError, match="Firewall Rule"):
        recover(database, tmp_path / "artifacts")
    assert state(database) == ("isolated", 20)
    with sessions() as db:
        result = reconcile(db, runner=runner, policy=FirewallPolicy(), now=now)
    assert result.restored == [rule_id]
    assert runner.rules == {rule_id: IP}


def test_worker_lock_is_acquired_before_db_write_lock(recovery_env, monkeypatch):
    database, _, runner, tmp_path = recovery_env
    capture_firewall_runtime_snapshot(runner, snapshot_path=settings.firewall_runtime_snapshot_path)
    monkeypatch.setattr(settings, "firewall_lock_wait_seconds", 2)
    entered = threading.Event()
    real_lock = baseline_recovery.single_instance_lock

    def entered_lock(*args, **kwargs):
        entered.set()
        return real_lock(*args, **kwargs)

    monkeypatch.setattr(baseline_recovery, "single_instance_lock", entered_lock)
    with ThreadPoolExecutor(max_workers=1) as pool:
        with single_instance_lock(Path(settings.firewall_lock_path)):
            future = pool.submit(recover, database, tmp_path / "artifacts")
            assert entered.wait(1)
            # Recovery is waiting for the Worker lock; it must not block the
            # Worker's final DB write after an OS attempt.
            with sqlite3.connect(database, timeout=0) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO firewall_rules(device_id,source_ip,status,last_attempted_at) "
                           "VALUES (?,?,'FAILED',?)", (DEVICE, IP, datetime.now(timezone.utc).isoformat()))
        with pytest.raises(baseline_recovery.BaselineRecoveryHoldError):
            future.result(timeout=3)
    assert state(database) == ("isolated", 20)


def test_firewall_and_db_locks_cover_verification_through_commit(recovery_env, monkeypatch):
    database, _, runner, tmp_path = recovery_env
    capture_firewall_runtime_snapshot(runner, snapshot_path=settings.firewall_runtime_snapshot_path)
    original = baseline_recovery._create_backup

    def probe_locks(database_path, backup):
        with pytest.raises(RuntimeLockError):
            with single_instance_lock(Path(settings.firewall_lock_path)):
                pytest.fail("Worker must not enter Recovery transaction")
        with pytest.raises(baseline_recovery.BaselineRecoveryHoldError, match="lock"):
            recover(database, tmp_path / "second-recovery")
        with sqlite3.connect(database, timeout=0) as other:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                other.execute("BEGIN IMMEDIATE")
        original(database_path, backup)

    monkeypatch.setattr(baseline_recovery, "_create_backup", probe_locks)
    assert recover(database, tmp_path / "artifacts")["result"] == "SUCCESS"


def test_snapshot_expiring_during_backup_rolls_back_device_reset(recovery_env, monkeypatch):
    database, _, runner, tmp_path = recovery_env
    now = datetime.now(timezone.utc).replace(microsecond=0)
    capture_firewall_runtime_snapshot(runner, snapshot_path=settings.firewall_runtime_snapshot_path, observed_at=now)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls.current

    Clock.current = now
    original = baseline_recovery._create_backup

    def slow_backup(*args):
        original(*args)
        Clock.current = now + timedelta(seconds=30)

    monkeypatch.setattr(firewall_runtime_snapshot, "datetime", Clock)
    monkeypatch.setattr(baseline_recovery, "_create_backup", slow_backup)
    with pytest.raises(baseline_recovery.BaselineRecoveryHoldError, match="stale"):
        recover(database, tmp_path / "artifacts")
    assert state(database) == ("isolated", 20)
    assert list((tmp_path / "artifacts").glob("*.db"))


def test_observer_does_not_run_os_command_when_worker_lock_is_busy(recovery_env, monkeypatch):
    _, _, runner, _ = recovery_env
    monkeypatch.setattr(run_firewall_runtime_snapshot, "WrapperIptablesRunner", lambda _: runner)
    with single_instance_lock(Path(settings.firewall_lock_path)):
        assert run_firewall_runtime_snapshot.run_once() is False
    assert not Path(settings.firewall_runtime_snapshot_path).exists()


def test_observer_os_read_holds_firewall_lock_but_no_db_write_lock(recovery_env, monkeypatch):
    database, _, runner, _ = recovery_env

    def verify_locks():
        with pytest.raises(RuntimeLockError):
            with single_instance_lock(Path(settings.firewall_lock_path)):
                pytest.fail("observer must exclude Worker")
        with sqlite3.connect(database, timeout=0) as probe:
            probe.execute("BEGIN IMMEDIATE")
            probe.rollback()

    runner.before_operation = verify_locks
    monkeypatch.setattr(run_firewall_runtime_snapshot, "WrapperIptablesRunner", lambda _: runner)
    assert run_firewall_runtime_snapshot.run_once() is True
