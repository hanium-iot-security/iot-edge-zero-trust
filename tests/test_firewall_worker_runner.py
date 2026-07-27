"""Firewall Worker Runner의 Lock·Cycle 동작 테스트.

핵심 계약은 "변경 작업은 모두 같은 Lock을 거치지만, 상시 서비스가 Lock을 독점하지
않는다"입니다. 프로세스 전체를 잠그면 서비스 실행 중 관리자 명령을 쓸 수 없습니다.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.runtime_lock import RuntimeLockError, single_instance_lock
from edge.trust import firewall_repository
from edge.trust.firewall_worker import (
    CHECK,
    INSERT,
    LIST_RULES,
    CommandResult,
    FirewallPolicy,
    FirewallRuleSpec,
    build_rule_args,
)
from edge.trust.run_firewall_worker import (
    GracefulShutdown,
    firewall_lock_path,
    run_worker_cycle,
    run_worker_loop,
)


NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
DEVICE_ID = "esp32_02"
DEVICE_IP = "192.168.0.5"


class RecordingRunner:
    def __init__(self, *, insert_failures: int = 0) -> None:
        self.installed: list[str] = []
        self.calls: list[list[str]] = []
        self.insert_failures = insert_failures

    def run_operation(
        self, operation: str, spec: FirewallRuleSpec | None = None
    ) -> CommandResult:
        args = [operation, "INPUT"] if spec is None else build_rule_args(spec, operation=operation)
        self.calls.append(args)
        if operation == LIST_RULES:
            return CommandResult(returncode=0, stdout="\n".join(self.installed))
        key = " ".join(args[3:] if operation == INSERT else args[2:])
        if operation == CHECK:
            return CommandResult(returncode=0 if key in self.installed else 1)
        if operation == INSERT:
            if self.insert_failures > 0:
                self.insert_failures -= 1
                return CommandResult(
                    returncode=2,
                    stderr="iptables: Resource temporarily unavailable.",
                )
            self.installed.insert(int(args[2]) - 1, key)
            return CommandResult(returncode=0)
        self.installed.remove(key)
        return CommandResult(returncode=0)

    def operations(self) -> list[str]:
        return [call[0] for call in self.calls]


@pytest.fixture
def SessionLocal(tmp_path: Path):
    db_path = tmp_path / "phase4-firewall-runner.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    with TestingSessionLocal() as db:
        db.execute(
            text(
                """
                INSERT INTO devices (device_id, ip_address, trust_score, status)
                VALUES (:device_id, :ip_address, 25, 'isolated')
                """
            ),
            {"device_id": DEVICE_ID, "ip_address": DEVICE_IP},
        )
        db.commit()
    try:
        yield TestingSessionLocal
    finally:
        engine.dispose()


@pytest.fixture
def policy() -> FirewallPolicy:
    return FirewallPolicy(protected_ips=frozenset({"192.168.0.20"}), batch_size=10)


def _create_pending(db) -> int:
    rule_id = firewall_repository.create_pending_rule_for_device(
        db,
        device_id=DEVICE_ID,
        source_ip=DEVICE_IP,
        reason="BROKER_DOS_SUSPECTED",
        trigger_event_id=None,
    )
    db.commit()
    return rule_id


def _status(db, rule_id: int) -> str:
    return db.execute(
        text("SELECT status FROM firewall_rules WHERE id = :id"), {"id": rule_id}
    ).scalar()


def test_loop_applies_pending_rule_and_reconciles_once(SessionLocal, policy, tmp_path: Path):
    with SessionLocal() as db:
        rule_id = _create_pending(db)
    runner = RecordingRunner()

    completed = run_worker_loop(
        runner=runner,
        policy=policy,
        shutdown=GracefulShutdown(),
        interval_seconds=0.01,
        session_factory=SessionLocal,
        max_cycles=2,
        clock=lambda: NOW,
        lock_path=tmp_path / "fw.lock",
    )

    assert completed == 2
    # Reconciliation(`-S`)은 첫 Cycle에서 한 번만 수행한다.
    assert runner.operations().count(LIST_RULES) == 1
    with SessionLocal() as db:
        assert _status(db, rule_id) == "APPLIED"


def test_loop_skips_cycle_when_admin_command_holds_lock(SessionLocal, policy, tmp_path: Path):
    lock_path = tmp_path / "fw.lock"
    with SessionLocal() as db:
        rule_id = _create_pending(db)
    runner = RecordingRunner()

    with single_instance_lock(lock_path):
        completed = run_worker_loop(
            runner=runner,
            policy=policy,
            shutdown=GracefulShutdown(),
            interval_seconds=0.01,
            session_factory=SessionLocal,
            max_cycles=1,
            clock=lambda: NOW,
            lock_path=lock_path,
            lock_wait_seconds=0.05,
        )

    assert completed == 1
    assert runner.calls == []  # Lock을 못 얻어 iptables를 건드리지 않았다
    with SessionLocal() as db:
        assert _status(db, rule_id) == "PENDING"


def test_reconcile_runs_on_first_executed_cycle_not_first_attempt(
    SessionLocal, policy, tmp_path: Path
):
    """Lock 경쟁으로 건너뛴 Cycle을 Reconciliation 완료로 오해하지 않는다."""
    lock_path = tmp_path / "fw.lock"
    with SessionLocal() as db:
        _create_pending(db)
    runner = RecordingRunner()

    with single_instance_lock(lock_path):
        run_worker_loop(
            runner=runner,
            policy=policy,
            shutdown=GracefulShutdown(),
            interval_seconds=0.01,
            session_factory=SessionLocal,
            max_cycles=1,
            clock=lambda: NOW,
            lock_path=lock_path,
            lock_wait_seconds=0.05,
        )
    assert runner.operations().count(LIST_RULES) == 0

    run_worker_loop(
        runner=runner,
        policy=policy,
        shutdown=GracefulShutdown(),
        interval_seconds=0.01,
        session_factory=SessionLocal,
        max_cycles=1,
        clock=lambda: NOW,
        lock_path=lock_path,
    )
    assert runner.operations().count(LIST_RULES) == 1


def test_reconcile_retries_on_next_cycle_after_restore_failure(
    SessionLocal, policy, tmp_path: Path
):
    with SessionLocal() as db:
        rule_id = _create_pending(db)
        initial_runner = RecordingRunner()
        run_worker_cycle(
            db,
            runner=initial_runner,
            policy=policy,
            now=NOW,
            with_reconcile=False,
        )
        assert _status(db, rule_id) == "APPLIED"

    runner = RecordingRunner(insert_failures=1)
    completed = run_worker_loop(
        runner=runner,
        policy=policy,
        shutdown=GracefulShutdown(),
        interval_seconds=0.01,
        session_factory=SessionLocal,
        max_cycles=2,
        clock=lambda: NOW,
        lock_path=tmp_path / "fw.lock",
    )

    assert completed == 2
    assert runner.operations().count(LIST_RULES) == 2
    assert runner.operations().count(INSERT) == 2
    assert len(runner.installed) == 1


def test_worker_cycle_reports_reconcile_and_pending_results(SessionLocal, policy):
    with SessionLocal() as db:
        rule_id = _create_pending(db)
        pending, reconciled = run_worker_cycle(
            db,
            runner=RecordingRunner(),
            policy=policy,
            now=NOW,
            with_reconcile=True,
        )

    assert pending.applied == [rule_id]
    assert reconciled is not None
    assert reconciled.orphan_rule_ids == []


def test_cycle_without_reconcile_skips_rule_listing(SessionLocal, policy):
    runner = RecordingRunner()
    with SessionLocal() as db:
        _create_pending(db)
        run_worker_cycle(db, runner=runner, policy=policy, now=NOW, with_reconcile=False)

    assert LIST_RULES not in runner.operations()


def test_lock_path_defaults_next_to_database_file():
    path = firewall_lock_path()
    assert path.name.endswith(".firewall.lock")


def test_loop_rejects_invalid_max_cycles(SessionLocal, policy):
    with pytest.raises(ValueError):
        run_worker_loop(
            runner=RecordingRunner(),
            policy=policy,
            shutdown=GracefulShutdown(),
            interval_seconds=1.0,
            session_factory=SessionLocal,
            max_cycles=0,
        )


def test_admin_lock_wait_raises_when_loop_holds_lock_too_long(tmp_path: Path):
    lock_path = tmp_path / "fw.lock"
    with single_instance_lock(lock_path):
        with pytest.raises(RuntimeLockError):
            with single_instance_lock(lock_path, wait_seconds=0.05, poll_interval_seconds=0.01):
                pass
