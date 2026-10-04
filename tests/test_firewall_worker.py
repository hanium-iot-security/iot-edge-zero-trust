"""Phase 4 Firewall Worker 테스트.

실제 iptables를 실행하지 않고 FakeIptablesRunner로 명령 인자와 상태 전이를
검증합니다. Match Specification이 적용·확인·삭제·Reconciliation에서 동일한지가
핵심 계약이므로, 명령 인자 자체를 비교합니다.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.trust import firewall_release_repository, firewall_repository
from edge.trust.firewall_worker import (
    CHAIN,
    CHECK,
    DELETE,
    INSERT,
    INSERT_POSITION,
    LIST_RULES,
    CommandResult,
    FirewallPolicy,
    FirewallRuleSpec,
    FirewallTransientError,
    FirewallValidationError,
    build_match_args,
    build_rule_args,
    list_managed_rule_ids,
    plan_pending_rules,
    process_pending_release_requests,
    process_pending_rules,
    reconcile,
    release_rule,
    validate_rule_row,
)


NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
DEVICE_ID = "esp32_02"
DEVICE_IP = "192.168.0.5"
PROTECTED_IP = "192.168.0.20"


class FakeIptablesRunner:
    """iptables를 흉내 내는 테스트 Runner.

    `installed`는 실제 커널 Rule 집합을, `failures`는 특정 Operation을 몇 번
    실패시킬지를 나타냅니다.
    """

    def __init__(
        self,
        *,
        installed: list[str] | None = None,
        fail_operations: dict[str, int] | None = None,
        fail_returncode: int = 2,
    ) -> None:
        self.installed: list[str] = list(installed or [])
        self.fail_operations = dict(fail_operations or {})
        self.fail_returncode = fail_returncode
        self.calls: list[list[str]] = []

    def run_operation(
        self, operation: str, spec: FirewallRuleSpec | None = None
    ) -> CommandResult:
        # 실제 Rule 규격은 운영 Wrapper가 조립하지만, 테스트는 Python 쪽 단일
        # Specification(build_rule_args)을 그대로 사용해 규격·삽입 위치까지 검증한다.
        args = [operation, CHAIN] if spec is None else build_rule_args(spec, operation=operation)
        self.calls.append(args)

        remaining = self.fail_operations.get(operation, 0)
        if remaining > 0:
            self.fail_operations[operation] = remaining - 1
            return CommandResult(
                returncode=self.fail_returncode,
                stderr="iptables: Resource temporarily unavailable.",
            )

        if operation == LIST_RULES:
            return CommandResult(returncode=0, stdout="\n".join(self.installed))

        key = _rule_key(args)
        if operation == CHECK:
            return CommandResult(returncode=0 if key in self.installed else 1)
        if operation == INSERT:
            # 실제 iptables처럼 지정된 위치(1-based)에 삽입한다.
            position = int(args[2])
            self.installed.insert(position - 1, key)
            return CommandResult(returncode=0)
        if operation == DELETE:
            if key not in self.installed:
                return CommandResult(returncode=1, stderr="Bad rule")
            self.installed.remove(key)
            return CommandResult(returncode=0)
        raise AssertionError(f"unexpected operation: {operation}")

    def operations(self) -> list[str]:
        return [call[0] for call in self.calls]


def _rule_key(args: Sequence[str]) -> str:
    """Operation·Chain·삽입 위치를 뺀 Match Specification을 커널 Rule 표현으로 씁니다."""
    match_args = args[3:] if args[0] == INSERT else args[2:]
    return " ".join(match_args)


@pytest.fixture
def SessionLocal(tmp_path: Path):
    db_path = tmp_path / "phase4-firewall-worker.db"
    legacy_migrations = tmp_path / "legacy-migrations"
    legacy_migrations.mkdir()
    for path in MIGRATIONS_DIR.glob("*.sql"):
        if int(path.name.split("_", 1)[0]) <= 6:
            shutil.copyfile(path, legacy_migrations / path.name)
    apply_migrations(db_path, legacy_migrations)
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        yield TestingSessionLocal
    finally:
        engine.dispose()


@pytest.fixture
def policy() -> FirewallPolicy:
    return FirewallPolicy(
        protected_ips=frozenset({PROTECTED_IP}),
        retry_delay_seconds=30,
        batch_size=10,
    )


def _seed_device(db, *, device_id: str = DEVICE_ID, ip_address: str = DEVICE_IP) -> None:
    db.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, trust_score, status)
            VALUES (:device_id, :ip_address, 25, 'isolated')
            """
        ),
        {"device_id": device_id, "ip_address": ip_address},
    )
    db.commit()


def _create_pending(db, *, source_ip: str = DEVICE_IP, device_id: str = DEVICE_ID) -> int:
    rule_id = firewall_repository.create_pending_rule_for_device(
        db,
        device_id=device_id,
        source_ip=source_ip,
        reason="BROKER_DOS_SUSPECTED",
        trigger_event_id=None,
    )
    db.commit()
    return rule_id


def _rule_row(db, rule_id: int) -> dict:
    row = (
        db.execute(text("SELECT * FROM firewall_rules WHERE id = :id"), {"id": rule_id})
        .mappings()
        .first()
    )
    return dict(row)


def _release_request_row(db, request_id: int) -> dict:
    row = (
        db.execute(
            text("SELECT * FROM firewall_release_requests WHERE id = :id"),
            {"id": request_id},
        )
        .mappings()
        .first()
    )
    return dict(row)


def _create_release_request(db, *, rule_id: int) -> int:
    request_id = firewall_release_repository.create_release_request(
        db,
        firewall_rule_id=rule_id,
        requested_by="operator@example",
        reason="official release approved",
        requested_at=NOW,
    )
    db.commit()
    return request_id


# --- Match Specification ---------------------------------------------------


def test_all_operations_share_one_match_specification():
    spec = FirewallRuleSpec(rule_id=7, source_ip=DEVICE_IP)
    match = build_match_args(spec)

    for operation in (CHECK, DELETE):
        assert build_rule_args(spec, operation=operation) == [operation, CHAIN, *match]
    assert build_rule_args(spec, operation=INSERT) == [
        INSERT,
        CHAIN,
        INSERT_POSITION,
        *match,
    ]
    assert match == [
        "-p",
        "tcp",
        "-s",
        DEVICE_IP,
        "--dport",
        "1883",
        "-m",
        "comment",
        "--comment",
        "hanium-firewall:7",
        "-j",
        "DROP",
    ]


def test_drop_rule_is_inserted_at_the_top_of_input_chain():
    """`-A`로 뒤에 붙이면 선행 ACCEPT에서 판정이 끝나 실제로 차단되지 않는다."""
    spec = FirewallRuleSpec(rule_id=7, source_ip=DEVICE_IP)
    args = build_rule_args(spec, operation=INSERT)
    assert args[0] == "-I"
    assert args[1:3] == [CHAIN, "1"]


def test_rule_comment_maps_to_db_row():
    assert FirewallRuleSpec(rule_id=12, source_ip=DEVICE_IP).comment == "hanium-firewall:12"


def test_build_rule_args_rejects_unsupported_operation():
    spec = FirewallRuleSpec(rule_id=1, source_ip=DEVICE_IP)
    with pytest.raises(ValueError):
        build_rule_args(spec, operation="-A")


# --- Validation ------------------------------------------------------------


def test_validate_rule_row_accepts_registered_private_ipv4(policy):
    spec = validate_rule_row(
        {"id": 1, "source_ip": DEVICE_IP, "protocol": "tcp", "dest_port": 1883, "action": "DROP"},
        policy,
    )
    assert spec == FirewallRuleSpec(rule_id=1, source_ip=DEVICE_IP)


@pytest.mark.parametrize(
    "row",
    [
        {"id": 1, "source_ip": "8.8.8.8", "protocol": "tcp", "dest_port": 1883, "action": "DROP"},
        {"id": 1, "source_ip": "169.254.10.20", "protocol": "tcp", "dest_port": 1883, "action": "DROP"},
        {"id": 1, "source_ip": "127.0.0.1", "protocol": "tcp", "dest_port": 1883, "action": "DROP"},
        {"id": 1, "source_ip": "not-an-ip", "protocol": "tcp", "dest_port": 1883, "action": "DROP"},
        {"id": 1, "source_ip": "fd00::1", "protocol": "tcp", "dest_port": 1883, "action": "DROP"},
        {"id": 1, "source_ip": DEVICE_IP, "protocol": "udp", "dest_port": 1883, "action": "DROP"},
        {"id": 1, "source_ip": DEVICE_IP, "protocol": "tcp", "dest_port": 22, "action": "DROP"},
        {"id": 1, "source_ip": DEVICE_IP, "protocol": "tcp", "dest_port": 1883, "action": "ACCEPT"},
    ],
)
def test_validate_rule_row_rejects_out_of_scope_rules(row, policy):
    with pytest.raises(FirewallValidationError):
        validate_rule_row(row, policy)


def test_validate_rule_row_rejects_protected_ip(policy):
    with pytest.raises(FirewallValidationError, match="protected IP"):
        validate_rule_row(
            {
                "id": 1,
                "source_ip": PROTECTED_IP,
                "protocol": "tcp",
                "dest_port": 1883,
                "action": "DROP",
            },
            policy,
        )


# --- PENDING 처리 ----------------------------------------------------------


def test_process_pending_rules_applies_and_marks_applied(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        runner = FakeIptablesRunner()

        result = process_pending_rules(db, runner=runner, policy=policy, now=NOW)

        assert result.applied == [rule_id]
        assert runner.operations() == [CHECK, INSERT]
        row = _rule_row(db, rule_id)
        assert row["status"] == "APPLIED"
        assert row["applied_at"] == "2026-07-25T12:00:00Z"
        assert row["last_error"] is None
        assert row["next_retry_at"] is None


def test_process_pending_rules_is_idempotent_when_rule_already_exists(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        spec = FirewallRuleSpec(rule_id=rule_id, source_ip=DEVICE_IP)
        runner = FakeIptablesRunner(
            installed=[_rule_key(build_rule_args(spec, operation=INSERT))]
        )

        result = process_pending_rules(db, runner=runner, policy=policy, now=NOW)

        assert result.already_present == [rule_id]
        assert runner.operations() == [CHECK]
        assert _rule_row(db, rule_id)["status"] == "APPLIED"


def test_process_pending_rules_records_validation_failure_immediately(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db, device_id="admin_note", ip_address=PROTECTED_IP)
        rule_id = _create_pending(db, source_ip=PROTECTED_IP, device_id="admin_note")
        runner = FakeIptablesRunner()

        result = process_pending_rules(db, runner=runner, policy=policy, now=NOW)

        assert result.validation_failed == [rule_id]
        assert runner.calls == []  # Protected IP는 iptables까지 가지 않는다
        row = _rule_row(db, rule_id)
        assert row["status"] == "FAILED"
        assert row["retry_count"] == 1
        assert row["next_retry_at"] is None
        assert "protected IP" in row["last_error"]


def test_transient_failure_retries_up_to_three_times_then_fails(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)

        for attempt in range(1, 4):
            runner = FakeIptablesRunner(fail_operations={CHECK: 1})
            now = NOW + timedelta(minutes=attempt)
            result = process_pending_rules(db, runner=runner, policy=policy, now=now)

            assert result.transient_failed == [rule_id]
            row = _rule_row(db, rule_id)
            assert row["retry_count"] == attempt
            if attempt < firewall_repository.MAX_TRANSIENT_RETRIES:
                assert row["status"] == "PENDING"
                assert row["next_retry_at"] is not None
            else:
                assert row["status"] == "FAILED"
                assert row["next_retry_at"] is None

        # 3회 실패 후에는 더 이상 자동 재시도 대상이 아니다.
        runner = FakeIptablesRunner()
        later = NOW + timedelta(hours=1)
        assert process_pending_rules(db, runner=runner, policy=policy, now=later).processed_count == 0
        assert runner.calls == []


def test_pending_rule_is_not_retried_before_next_retry_at(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        process_pending_rules(
            db, runner=FakeIptablesRunner(fail_operations={CHECK: 1}), policy=policy, now=NOW
        )

        runner = FakeIptablesRunner()
        too_soon = NOW + timedelta(seconds=policy.retry_delay_seconds - 1)
        assert process_pending_rules(db, runner=runner, policy=policy, now=too_soon).processed_count == 0

        due = NOW + timedelta(seconds=policy.retry_delay_seconds)
        assert process_pending_rules(db, runner=runner, policy=policy, now=due).applied == [rule_id]


def test_admin_can_reset_failed_rule_to_pending(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db, device_id="admin_note", ip_address=PROTECTED_IP)
        rule_id = _create_pending(db, source_ip=PROTECTED_IP, device_id="admin_note")
        process_pending_rules(db, runner=FakeIptablesRunner(), policy=policy, now=NOW)
        assert _rule_row(db, rule_id)["status"] == "FAILED"

        firewall_repository.reset_failed_to_pending(db, rule_id=rule_id, requested_at=NOW)
        db.commit()

        row = _rule_row(db, rule_id)
        assert row["status"] == "PENDING"
        assert row["retry_count"] == 0
        assert row["last_error"] is None


def test_process_pending_rules_processes_in_id_order_within_batch(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db)
        _seed_device(db, device_id="esp32_03", ip_address="192.168.0.6")
        first = _create_pending(db)
        second = _create_pending(db, source_ip="192.168.0.6", device_id="esp32_03")

        result = process_pending_rules(
            db, runner=FakeIptablesRunner(), policy=policy, now=NOW, limit=10
        )

        assert result.applied == [first, second]


def test_batch_limit_is_respected(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db)
        _seed_device(db, device_id="esp32_03", ip_address="192.168.0.6")
        first = _create_pending(db)
        _create_pending(db, source_ip="192.168.0.6", device_id="esp32_03")

        result = process_pending_rules(
            db, runner=FakeIptablesRunner(), policy=policy, now=NOW, limit=1
        )

        assert result.applied == [first]


# --- 해제 ------------------------------------------------------------------


def test_release_rule_deletes_with_same_specification(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        runner = FakeIptablesRunner()
        process_pending_rules(db, runner=runner, policy=policy, now=NOW)

        released_at = NOW + timedelta(minutes=5)
        removed = release_rule(
            db, rule_id=rule_id, runner=runner, policy=policy, now=released_at
        )

        assert removed is True
        assert runner.installed == []
        assert runner.operations()[-2:] == [CHECK, DELETE]
        row = _rule_row(db, rule_id)
        assert row["status"] == "REMOVED"
        assert row["released_at"] == "2026-07-25T12:05:00Z"


def test_release_rule_marks_removed_even_if_os_rule_is_missing(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        runner = FakeIptablesRunner()
        process_pending_rules(db, runner=runner, policy=policy, now=NOW)
        runner.installed.clear()  # 재부팅 등으로 실제 Rule만 사라진 상황

        removed = release_rule(db, rule_id=rule_id, runner=runner, policy=policy, now=NOW)

        assert removed is False
        assert _rule_row(db, rule_id)["status"] == "REMOVED"


def test_release_rule_rejects_non_applied_rule(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        with pytest.raises(FirewallValidationError, match="not APPLIED"):
            release_rule(
                db, rule_id=rule_id, runner=FakeIptablesRunner(), policy=policy, now=NOW
            )


def test_process_release_request_releases_applied_rule_and_marks_succeeded(
    SessionLocal,
    policy,
):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        runner = FakeIptablesRunner()
        process_pending_rules(db, runner=runner, policy=policy, now=NOW)
        request_id = _create_release_request(db, rule_id=rule_id)

        result = process_pending_release_requests(
            db,
            runner=runner,
            policy=policy,
            now=NOW + timedelta(minutes=5),
        )

        assert result.succeeded == [request_id]
        assert runner.installed == []
        assert _rule_row(db, rule_id)["status"] == "REMOVED"
        request = _release_request_row(db, request_id)
        assert request["status"] == "SUCCEEDED"
        assert request["processed_at"] == "2026-07-25T12:05:00Z"
        assert request["last_error"] is None


def test_process_release_request_failure_does_not_mark_rule_removed(
    SessionLocal,
    policy,
):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        runner = FakeIptablesRunner()
        process_pending_rules(db, runner=runner, policy=policy, now=NOW)
        request_id = _create_release_request(db, rule_id=rule_id)
        runner.fail_operations[DELETE] = 1

        result = process_pending_release_requests(
            db,
            runner=runner,
            policy=policy,
            now=NOW + timedelta(minutes=5),
        )

        assert result.failed == [request_id]
        assert _rule_row(db, rule_id)["status"] == "APPLIED"
        request = _release_request_row(db, request_id)
        assert request["status"] == "FAILED"
        assert "delete failed" in request["last_error"]


def test_pending_release_request_converges_after_crash_when_runtime_rule_absent(
    SessionLocal,
    policy,
):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        runner = FakeIptablesRunner()
        process_pending_rules(db, runner=runner, policy=policy, now=NOW)
        request_id = _create_release_request(db, rule_id=rule_id)
        runner.installed.clear()
        firewall_repository.mark_removed(
            db,
            rule_id=rule_id,
            released_at=NOW + timedelta(minutes=4),
        )
        db.commit()

        result = process_pending_release_requests(
            db,
            runner=runner,
            policy=policy,
            now=NOW + timedelta(minutes=5),
        )

        assert result.already_removed == [request_id]
        assert _release_request_row(db, request_id)["status"] == "SUCCEEDED"


def test_pending_release_request_fails_if_removed_rule_still_exists_at_runtime(
    SessionLocal,
    policy,
):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        runner = FakeIptablesRunner()
        process_pending_rules(db, runner=runner, policy=policy, now=NOW)
        request_id = _create_release_request(db, rule_id=rule_id)
        firewall_repository.mark_removed(
            db,
            rule_id=rule_id,
            released_at=NOW + timedelta(minutes=4),
        )
        db.commit()

        result = process_pending_release_requests(
            db,
            runner=runner,
            policy=policy,
            now=NOW + timedelta(minutes=5),
        )

        assert result.failed == [request_id]
        assert _release_request_row(db, request_id)["status"] == "FAILED"


def test_reconcile_does_not_restore_applied_rule_with_pending_release_request(
    SessionLocal,
    policy,
):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        runner = FakeIptablesRunner()
        process_pending_rules(db, runner=runner, policy=policy, now=NOW)
        _create_release_request(db, rule_id=rule_id)
        runner.installed.clear()

        result = reconcile(db, runner=runner, policy=policy, now=NOW)

        assert result.restored == []
        assert runner.installed == []
        assert _rule_row(db, rule_id)["status"] == "APPLIED"


# --- Reconciliation --------------------------------------------------------


def test_reconcile_restores_missing_applied_rule(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        runner = FakeIptablesRunner()
        process_pending_rules(db, runner=runner, policy=policy, now=NOW)
        runner.installed.clear()  # 재부팅으로 실제 Rule 소실

        result = reconcile(db, runner=runner, policy=policy, now=NOW)

        assert result.restored == [rule_id]
        assert len(runner.installed) == 1
        assert _rule_row(db, rule_id)["status"] == "APPLIED"


def test_reconcile_verifies_existing_rule_without_reapplying(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        runner = FakeIptablesRunner()
        process_pending_rules(db, runner=runner, policy=policy, now=NOW)

        result = reconcile(db, runner=runner, policy=policy, now=NOW)

        assert result.verified == [rule_id]
        assert result.restored == []
        assert len(runner.installed) == 1


def test_reconcile_keeps_orphan_rule_and_reports_it(SessionLocal, policy):
    with SessionLocal() as db:
        orphan_line = (
            '-A INPUT -s 192.168.0.99/32 -p tcp -m comment '
            '--comment "hanium-firewall:999" -m tcp --dport 1883 -j DROP'
        )
        runner = FakeIptablesRunner(installed=[orphan_line])

        result = reconcile(db, runner=runner, policy=policy, now=NOW)

        assert result.orphan_rule_ids == [999]
        assert orphan_line in runner.installed  # 자동 삭제하지 않는다


def test_reconcile_ignores_rules_without_our_comment(SessionLocal, policy):
    with SessionLocal() as db:
        runner = FakeIptablesRunner(installed=["-A INPUT -p tcp --dport 22 -j ACCEPT"])

        result = reconcile(db, runner=runner, policy=policy, now=NOW)

        assert result.orphan_rule_ids == []


def test_reconcile_does_not_report_pending_rule_as_orphan(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        spec = FirewallRuleSpec(rule_id=rule_id, source_ip=DEVICE_IP)
        runner = FakeIptablesRunner(
            installed=[_rule_key(build_rule_args(spec, operation=INSERT))]
        )

        result = reconcile(db, runner=runner, policy=policy, now=NOW)

        assert result.orphan_rule_ids == []


def test_list_managed_rule_ids_parses_comment(policy):
    runner = FakeIptablesRunner(
        installed=[
            '-A INPUT -s 192.168.0.5/32 -p tcp -m comment --comment "hanium-firewall:3" '
            "-m tcp --dport 1883 -j DROP",
            "-A INPUT -p tcp --dport 22 -j ACCEPT",
        ]
    )
    assert list_managed_rule_ids(runner) == {
        3: '-A INPUT -s 192.168.0.5/32 -p tcp -m comment --comment "hanium-firewall:3" '
        "-m tcp --dport 1883 -j DROP"
    }


def test_list_managed_rule_ids_raises_transient_on_command_failure():
    runner = FakeIptablesRunner(fail_operations={LIST_RULES: 1})
    with pytest.raises(FirewallTransientError):
        list_managed_rule_ids(runner)


# --- Dry Run ---------------------------------------------------------------


def test_plan_pending_rules_does_not_change_state(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)

        planned = plan_pending_rules(db, policy=policy, now=NOW)

        assert planned[0][0] == rule_id
        spec, iptables_args = planned[0][1]
        assert spec.rule_id == rule_id
        assert iptables_args[:3] == [INSERT, CHAIN, INSERT_POSITION]
        assert _rule_row(db, rule_id)["status"] == "PENDING"


def test_applied_rule_precedes_existing_accept_rules(SessionLocal, policy):
    """선행 ACCEPT Rule이 있어도 DROP이 그보다 앞에 놓여야 실제로 차단된다."""
    established_accept = "-p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    mqtt_accept = "-p tcp --dport 1883 -j ACCEPT"
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        runner = FakeIptablesRunner(installed=[established_accept, mqtt_accept])

        process_pending_rules(db, runner=runner, policy=policy, now=NOW)

        spec = FirewallRuleSpec(rule_id=rule_id, source_ip=DEVICE_IP)
        drop_key = _rule_key(build_rule_args(spec, operation=INSERT))
        assert runner.installed[0] == drop_key
        assert runner.installed.index(drop_key) < runner.installed.index(established_accept)


def test_reconcile_refuses_to_restore_now_protected_ip(SessionLocal):
    """운영 중 Protected IP가 바뀌면 재부팅 후에도 보호 대상을 다시 차단하지 않는다."""
    permissive = FirewallPolicy(protected_ips=frozenset(), batch_size=10)
    with SessionLocal() as db:
        _seed_device(db)
        rule_id = _create_pending(db)
        runner = FakeIptablesRunner()
        process_pending_rules(db, runner=runner, policy=permissive, now=NOW)
        runner.installed.clear()  # 재부팅으로 실제 Rule 소실

        # 그 사이 해당 IP가 관리자 장비에 재할당되어 Protected 목록에 들어왔다.
        stricter = FirewallPolicy(protected_ips=frozenset({DEVICE_IP}), batch_size=10)
        result = reconcile(db, runner=runner, policy=stricter, now=NOW)

        assert result.validation_failed == [rule_id]
        assert result.restored == []
        assert runner.installed == []
        # DB 상태는 관리자가 판단할 수 있도록 그대로 남긴다.
        assert _rule_row(db, rule_id)["status"] == "APPLIED"


def test_plan_pending_rules_reports_validation_failure(SessionLocal, policy):
    with SessionLocal() as db:
        _seed_device(db, device_id="admin_note", ip_address=PROTECTED_IP)
        _create_pending(db, source_ip=PROTECTED_IP, device_id="admin_note")

        planned = plan_pending_rules(db, policy=policy, now=NOW)

        assert isinstance(planned[0][1], str)
        assert "VALIDATION_FAILURE" in planned[0][1]
