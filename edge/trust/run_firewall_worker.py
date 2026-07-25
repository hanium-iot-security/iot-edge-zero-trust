"""Firewall Worker 실행 진입점입니다.

systemd 상시 실행(`--loop`), 단발 실행(`--once`), 관리자 명령(`--release`,
`--admin-reset-failed`), Dry Run을 하나의 CLI로 제공합니다.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
import logging
import signal
from threading import Event
import time

from sqlalchemy.orm import Session

from backend.app.config import Settings, settings
from backend.app.database import SessionLocal
from edge.trust import firewall_repository
from edge.trust.firewall_worker import (
    FirewallPolicy,
    FirewallValidationError,
    IptablesRunner,
    PendingCycleResult,
    ReconcileResult,
    SudoIptablesRunner,
    plan_pending_rules,
    process_pending_rules,
    reconcile,
    release_rule,
)

logger = logging.getLogger(__name__)

ADMIN_CONFIRM_TOKEN = "RESET-FIREWALL-RULE"


class UtcFormatter(logging.Formatter):
    """Format log timestamps in UTC regardless of the host timezone."""

    converter = time.gmtime


class GracefulShutdown:
    """Signal-backed shutdown state with an interruptible wait."""

    def __init__(self) -> None:
        self._event = Event()

    @property
    def requested(self) -> bool:
        return self._event.is_set()

    def request(self, signum: int, _frame: object | None) -> None:
        logger.info("Shutdown signal received (signum=%s)", signum)
        self._event.set()

    def install(self) -> None:
        signal.signal(signal.SIGTERM, self.request)
        signal.signal(signal.SIGINT, self.request)

    def wait(self, timeout: float) -> bool:
        return self._event.wait(timeout)


def load_firewall_policy(app_settings: Settings = settings) -> FirewallPolicy:
    """`.env` 기반 설정에서 Worker 정책을 만듭니다.

    Protected IP에는 명시 설정값과 함께 Capture Interface IP(Pi #1)를 항상 포함해
    운영 노드 자신이 차단 대상이 되는 사고를 막습니다.
    """
    protected = {
        value.strip()
        for value in app_settings.firewall_protected_ips.split(",")
        if value.strip()
    }
    if app_settings.capture_interface_ip.strip():
        protected.add(app_settings.capture_interface_ip.strip())

    return FirewallPolicy(
        protected_ips=frozenset(protected),
        iptables_path=app_settings.firewall_iptables_path,
        sudo_path=app_settings.firewall_sudo_path,
        command_timeout_seconds=app_settings.firewall_command_timeout_seconds,
        retry_delay_seconds=app_settings.firewall_retry_delay_seconds,
        batch_size=app_settings.firewall_worker_batch_size,
    )


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def run_worker_cycle(
    db: Session,
    *,
    runner: IptablesRunner,
    policy: FirewallPolicy,
    now: datetime,
    with_reconcile: bool,
) -> tuple[PendingCycleResult, ReconcileResult | None]:
    """Reconciliation(선택) 후 PENDING Batch를 처리하는 한 Cycle입니다."""
    reconcile_result = None
    if with_reconcile:
        reconcile_result = reconcile(db, runner=runner, policy=policy, now=now)
        logger.info(
            "Firewall reconciliation done (verified=%d, restored=%d, restore_failed=%d, orphan=%d)",
            len(reconcile_result.verified),
            len(reconcile_result.restored),
            len(reconcile_result.restore_failed),
            len(reconcile_result.orphan_rule_ids),
        )

    pending_result = process_pending_rules(db, runner=runner, policy=policy, now=now)
    if pending_result.processed_count:
        logger.info(
            "Firewall pending batch done (applied=%d, already_present=%d, "
            "transient_failed=%d, validation_failed=%d)",
            len(pending_result.applied),
            len(pending_result.already_present),
            len(pending_result.transient_failed),
            len(pending_result.validation_failed),
        )
    return pending_result, reconcile_result


def run_worker_loop(
    *,
    runner: IptablesRunner,
    policy: FirewallPolicy,
    shutdown: GracefulShutdown,
    interval_seconds: float,
    session_factory: Callable[[], Session] = SessionLocal,
    max_cycles: int | None = None,
    clock: Callable[[], datetime] = _now,
) -> int:
    """종료 Signal까지 Cycle을 반복합니다.

    Reconciliation은 첫 Cycle에서 한 번 수행합니다. 재부팅 직후 실제 Rule이 사라진
    상태를 가장 먼저 확인해야 하기 때문입니다.
    """
    if max_cycles is not None and max_cycles <= 0:
        raise ValueError("max_cycles must be positive")

    completed = 0
    while not shutdown.requested:
        with session_factory() as db:
            run_worker_cycle(
                db,
                runner=runner,
                policy=policy,
                now=clock(),
                with_reconcile=(completed == 0),
            )

        completed += 1
        if max_cycles is not None and completed >= max_cycles:
            break
        if shutdown.wait(interval_seconds):
            break

    return completed


def _print_dry_run(
    db: Session, *, policy: FirewallPolicy, now: datetime, sudo_path: str, iptables_path: str
) -> None:
    planned = plan_pending_rules(db, policy=policy, now=now)
    if not planned:
        print("실행 대기 중인 PENDING Rule이 없습니다.")
        return
    for rule_id, plan in planned:
        if isinstance(plan, str):
            print(f"[rule_id={rule_id}] {plan}")
            continue
        command = " ".join([sudo_path, "-n", iptables_path, *plan])
        print(f"[rule_id={rule_id}] {command}")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phase 4 Firewall Worker")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--loop", action="store_true", help="종료 Signal까지 반복 실행")
    mode.add_argument("--once", action="store_true", help="한 Cycle만 실행")
    mode.add_argument("--dry-run", action="store_true", help="실행 예정 명령만 출력")
    mode.add_argument("--reconcile-only", action="store_true", help="정합성 확인만 수행")
    mode.add_argument("--release", type=int, metavar="RULE_ID", help="APPLIED Rule 해제")
    mode.add_argument(
        "--admin-reset-failed",
        type=int,
        metavar="RULE_ID",
        help="FAILED Rule을 PENDING으로 되돌립니다(관리자 전용)",
    )
    parser.add_argument("--cycles", type=int, default=None, help="--loop에서 실행할 최대 Cycle 수")
    parser.add_argument("--interval", type=float, default=None, help="Cycle 간격(초)")
    parser.add_argument("--confirm", default=None, help=f"관리자 명령 확인 토큰({ADMIN_CONFIRM_TOKEN})")
    return parser.parse_args(argv)


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(
        UtcFormatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
    )
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging()

    policy = load_firewall_policy()
    interval = (
        args.interval
        if args.interval is not None
        else settings.firewall_worker_interval_seconds
    )

    if args.admin_reset_failed is not None:
        if args.confirm != ADMIN_CONFIRM_TOKEN:
            logger.error("관리자 명령에는 --confirm %s 가 필요합니다", ADMIN_CONFIRM_TOKEN)
            return 2
        with SessionLocal() as db:
            try:
                firewall_repository.reset_failed_to_pending(
                    db, rule_id=args.admin_reset_failed, requested_at=_now()
                )
                db.commit()
            except Exception:
                db.rollback()
                raise
        logger.warning(
            "FAILED firewall rule reset to PENDING by admin (rule_id=%s)",
            args.admin_reset_failed,
        )
        return 0

    runner = SudoIptablesRunner(policy)

    if args.dry_run:
        with SessionLocal() as db:
            _print_dry_run(
                db,
                policy=policy,
                now=_now(),
                sudo_path=policy.sudo_path,
                iptables_path=policy.iptables_path,
            )
        return 0

    if args.release is not None:
        with SessionLocal() as db:
            try:
                release_rule(
                    db,
                    rule_id=args.release,
                    runner=runner,
                    policy=policy,
                    now=_now(),
                )
            except FirewallValidationError as exc:
                logger.error("Rule 해제 실패: %s", exc)
                return 2
        return 0

    if args.reconcile_only:
        with SessionLocal() as db:
            reconcile(db, runner=runner, policy=policy, now=_now())
        return 0

    if args.once:
        with SessionLocal() as db:
            run_worker_cycle(
                db,
                runner=runner,
                policy=policy,
                now=_now(),
                with_reconcile=True,
            )
        return 0

    shutdown = GracefulShutdown()
    shutdown.install()
    completed = run_worker_loop(
        runner=runner,
        policy=policy,
        shutdown=shutdown,
        interval_seconds=interval,
        max_cycles=args.cycles,
    )
    logger.info("Firewall worker stopped (cycles=%d)", completed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
