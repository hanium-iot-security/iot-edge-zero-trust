"""Phase 4 Firewall Worker: DB의 PENDING Rule을 실제 iptables에 반영합니다.

Trust Score Transaction은 Device 상태·History와 함께 `firewall_rules`를 PENDING으로
남기기만 하고, 실제 OS 명령은 Transaction 밖의 이 Worker가 처리합니다.
iptables는 DB처럼 Rollback할 수 없으므로 "먼저 PENDING을 남기고 나중에 적용"하는
순서를 지켜야 재시도와 복구가 가능합니다.

적용·확인·삭제·Reconciliation은 모두 `build_match_args()`가 만드는 동일한 Match
Specification(Source IP, TCP, 목적지 Port 1883, Comment, DROP)을 사용합니다.
서로 다른 Specification을 쓰면 "적용은 됐는데 확인·삭제가 안 되는" 상태가 생깁니다.

DROP Rule은 `-I INPUT 1`로 Chain 맨 앞에 넣습니다. 뒤에 붙이면 선행 ACCEPT Rule에서
판정이 끝나 실제로는 차단되지 않을 수 있습니다.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import logging
import re
import subprocess
from typing import Any, Protocol

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.detection.phase4_time import require_utc_whole_second
from edge.trust import firewall_release_repository, firewall_repository

logger = logging.getLogger(__name__)

# Phase 4의 실제 차단 범위는 고정이다. 설정으로 넓히지 않는다.
CHAIN = "INPUT"
PROTOCOL = "tcp"
DEST_PORT = 1883
ACTION = "DROP"
COMMENT_PREFIX = "hanium-firewall:"
RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

CHECK = "-C"
INSERT = "-I"
DELETE = "-D"
LIST_RULES = "-S"

# INPUT Chain 맨 앞에 넣는다. `-A`로 뒤에 붙이면 앞선 ACCEPT Rule(특히
# `--ctstate ESTABLISHED,RELATED`)에서 판정이 끝나 DROP까지 도달하지 않는다. MQTT는
# 장수명 TCP 연결이므로, 공격이 진행 중인 연결이 계속 통과하면서 DB만 APPLIED가 되는
# 상태가 만들어진다. 세부계획 2.6-14의 "APPLIED와 실제 MQTT 연결·Publish 실패가 모두
# 확인된 경우"를 충족하려면 선행 ACCEPT보다 앞서야 한다.
INSERT_POSITION = "1"

# `iptables -C`는 Rule이 없을 때 종료 코드 1을 사용한다. 2 이상은 실행 자체가
# 실패한 것이므로 "Rule 없음"으로 오해하면 안 된다.
_RULE_ABSENT_RETURNCODE = 1

_COMMENT_RULE_ID_PATTERN = re.compile(
    r'--comment\s+"?' + re.escape(COMMENT_PREFIX) + r'(\d+)"?'
)


class FirewallValidationError(Exception):
    """재시도해도 결과가 달라지지 않는 오류입니다. 즉시 FAILED로 전환합니다."""


class FirewallTransientError(Exception):
    """일시 오류입니다. 유한 재시도 대상입니다."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class FirewallRuleSpec:
    """실제 iptables Rule 하나와 DB Row를 잇는 식별 정보입니다."""

    rule_id: int
    source_ip: str

    @property
    def comment(self) -> str:
        return f"{COMMENT_PREFIX}{self.rule_id}"


@dataclass(frozen=True)
class FirewallPolicy:
    """Worker 실행 정책입니다. Protected IP는 어떤 경우에도 차단하지 않습니다."""

    protected_ips: frozenset[str] = frozenset()
    wrapper_path: str = "/usr/local/sbin/hanium-firewall-rule"
    sudo_path: str = "/usr/bin/sudo"
    command_timeout_seconds: float = 10.0
    retry_delay_seconds: int = 30
    batch_size: int = 20

    def __post_init__(self) -> None:
        if self.command_timeout_seconds <= 0:
            raise ValueError("command_timeout_seconds must be positive")
        if self.retry_delay_seconds < 0:
            raise ValueError("retry_delay_seconds must not be negative")
        if self.batch_size <= 0:
            raise ValueError("batch_size must be positive")


@dataclass
class PendingCycleResult:
    applied: list[int] = field(default_factory=list)
    already_present: list[int] = field(default_factory=list)
    transient_failed: list[int] = field(default_factory=list)
    validation_failed: list[int] = field(default_factory=list)

    @property
    def processed_count(self) -> int:
        return (
            len(self.applied)
            + len(self.already_present)
            + len(self.transient_failed)
            + len(self.validation_failed)
        )


@dataclass
class ReconcileResult:
    verified: list[int] = field(default_factory=list)
    restored: list[int] = field(default_factory=list)
    restore_failed: list[int] = field(default_factory=list)
    validation_failed: list[int] = field(default_factory=list)
    orphan_rule_ids: list[int] = field(default_factory=list)


@dataclass
class ReleaseRequestCycleResult:
    succeeded: list[int] = field(default_factory=list)
    already_removed: list[int] = field(default_factory=list)
    failed: list[int] = field(default_factory=list)

    @property
    def processed_count(self) -> int:
        return len(self.succeeded) + len(self.already_removed) + len(self.failed)


class IptablesRunner(Protocol):
    """방화벽 명령 실행 경계입니다. 테스트는 Fake Runner로 대체합니다.

    Operation과 Rule 식별 정보만 전달합니다. 실제 Rule 규격은 운영 환경에서는 root
    소유 Wrapper가 조립하므로, 호출자가 Chain·Port·Target을 바꿀 수 없습니다.
    """

    def run_operation(
        self, operation: str, spec: FirewallRuleSpec | None = None
    ) -> CommandResult: ...


WRAPPER_OPERATION_NAMES = {
    CHECK: "check",
    INSERT: "insert",
    DELETE: "delete",
    LIST_RULES: "list",
}


class WrapperIptablesRunner:
    """root 소유 Wrapper를 sudo로 호출합니다.

    sudoers에 `iptables -A INPUT *`를 직접 허용하면 Worker를 거치지 않고도 pi 계정이
    임의의 INPUT Rule을 root 권한으로 추가할 수 있습니다. `validate_rule_row()`는 직접
    실행한 sudo 명령을 막을 수 없으므로, 권한 자체를 Wrapper 하나로 좁힙니다.

    인자 배열만 사용하고 `shell=True`는 사용하지 않습니다.
    """

    def __init__(self, policy: FirewallPolicy) -> None:
        self._policy = policy

    def run_operation(
        self, operation: str, spec: FirewallRuleSpec | None = None
    ) -> CommandResult:
        try:
            operation_name = WRAPPER_OPERATION_NAMES[operation]
        except KeyError as exc:
            raise ValueError(f"unsupported firewall operation: {operation!r}") from exc

        command = [self._policy.sudo_path, "-n", self._policy.wrapper_path, operation_name]
        if operation != LIST_RULES:
            if spec is None:
                raise ValueError(f"{operation_name} requires a rule spec")
            command += [spec.source_ip, str(spec.rule_id)]

        try:
            completed = subprocess.run(  # noqa: S603 - 인자 배열만 사용하며 shell을 쓰지 않는다
                command,
                capture_output=True,
                text=True,
                timeout=self._policy.command_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise FirewallTransientError(
                f"firewall command timed out after {self._policy.command_timeout_seconds}s"
            ) from exc
        except FileNotFoundError as exc:
            raise FirewallTransientError(f"firewall wrapper not found: {exc}") from exc
        except OSError as exc:
            raise FirewallTransientError(f"failed to execute firewall wrapper: {exc}") from exc

        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )


def build_match_args(spec: FirewallRuleSpec) -> list[str]:
    """적용·확인·삭제·Reconciliation이 공유하는 단일 Match Specification입니다.

    이 함수 한 곳만 바꾸면 네 경로가 함께 바뀝니다. 경로마다 다른 Specification을
    쓰면 "적용은 됐는데 확인·삭제가 안 되는" 상태가 생깁니다.
    """
    return [
        "-p",
        PROTOCOL,
        "-s",
        spec.source_ip,
        "--dport",
        str(DEST_PORT),
        "-m",
        "comment",
        "--comment",
        spec.comment,
        "-j",
        ACTION,
    ]


def build_rule_args(spec: FirewallRuleSpec, *, operation: str) -> list[str]:
    """Operation과 공유 Match Specification을 합쳐 iptables 인자를 만듭니다."""
    if operation not in (CHECK, INSERT, DELETE):
        raise ValueError(f"unsupported iptables operation: {operation!r}")
    if operation == INSERT:
        return [operation, CHAIN, INSERT_POSITION, *build_match_args(spec)]
    return [operation, CHAIN, *build_match_args(spec)]


def validate_rule_row(row: dict[str, Any], policy: FirewallPolicy) -> FirewallRuleSpec:
    """실행 직전에 차단 대상을 다시 검증합니다.

    DB CHECK 제약이 이미 protocol·dest_port·action을 강제하지만, 실제 OS 명령을
    실행하기 직전에 한 번 더 확인해야 잘못된 Row가 iptables까지 도달하지 않습니다.
    """
    rule_id = row.get("id")
    if rule_id is None:
        raise FirewallValidationError("firewall rule row has no id")

    protocol = str(row.get("protocol", "")).lower()
    if protocol != PROTOCOL:
        raise FirewallValidationError(f"unsupported protocol: {row.get('protocol')!r}")

    if int(row.get("dest_port", -1)) != DEST_PORT:
        raise FirewallValidationError(f"unsupported dest_port: {row.get('dest_port')!r}")

    action = str(row.get("action", "")).upper()
    if action != ACTION:
        raise FirewallValidationError(f"unsupported action: {row.get('action')!r}")

    source_ip = str(row.get("source_ip", ""))
    address = _require_private_ipv4(source_ip)
    if str(address) in policy.protected_ips:
        raise FirewallValidationError(f"protected IP must not be blocked: {source_ip}")

    return FirewallRuleSpec(rule_id=int(rule_id), source_ip=str(address))


def rule_exists(runner: IptablesRunner, spec: FirewallRuleSpec) -> bool:
    """동일 Specification의 실제 Rule이 있는지 확인합니다."""
    result = runner.run_operation(CHECK, spec)
    if result.returncode == 0:
        return True
    if result.returncode == _RULE_ABSENT_RETURNCODE:
        return False
    raise FirewallTransientError(
        f"iptables check failed (rc={result.returncode}): {_summarize(result.stderr)}"
    )


def insert_rule(runner: IptablesRunner, spec: FirewallRuleSpec) -> None:
    """INPUT Chain 맨 앞에 DROP Rule을 넣습니다."""
    result = runner.run_operation(INSERT, spec)
    if result.returncode != 0:
        raise FirewallTransientError(
            f"iptables insert failed (rc={result.returncode}): {_summarize(result.stderr)}"
        )


def delete_rule(runner: IptablesRunner, spec: FirewallRuleSpec) -> None:
    result = runner.run_operation(DELETE, spec)
    if result.returncode != 0:
        raise FirewallTransientError(
            f"iptables delete failed (rc={result.returncode}): {_summarize(result.stderr)}"
        )


def list_managed_rule_ids(runner: IptablesRunner) -> dict[int, str]:
    """실제 iptables에 남아 있는 `hanium-firewall:` Rule을 Rule ID별로 반환합니다."""
    result = runner.run_operation(LIST_RULES)
    if result.returncode != 0:
        raise FirewallTransientError(
            f"iptables list failed (rc={result.returncode}): {_summarize(result.stderr)}"
        )

    managed: dict[int, str] = {}
    for line in result.stdout.splitlines():
        match = _COMMENT_RULE_ID_PATTERN.search(line)
        if match is None:
            continue
        managed[int(match.group(1))] = line.strip()
    return managed


def process_pending_rules(
    db: Session,
    *,
    runner: IptablesRunner,
    policy: FirewallPolicy,
    now: datetime,
    limit: int | None = None,
) -> PendingCycleResult:
    """PENDING Rule을 ID 순서의 제한된 Batch로 처리합니다.

    Rule 하나마다 독립적으로 Commit합니다. 한 Rule의 실패가 이미 처리된 Rule의
    상태를 되돌리지 않아야 하기 때문입니다.
    """
    now_utc = require_utc_whole_second(now, "now")
    batch_size = limit if limit is not None else policy.batch_size
    rows = firewall_repository.list_pending_rules(db, now=now_utc, limit=batch_size)
    result = PendingCycleResult()

    for row in rows:
        rule_id = int(row["id"])
        try:
            row = firewall_repository.authorized_automatic_rule(
                db, rule_id=rule_id, required_status=firewall_repository.PENDING, now=now_utc
            )
            spec = validate_rule_row(row, policy)
        except (FirewallValidationError, firewall_repository.AutomaticResponseBlockedError) as exc:
            _record_validation_failure(db, rule_id=rule_id, now=now_utc, error=str(exc))
            result.validation_failed.append(rule_id)
            logger.error(
                "Firewall rule rejected by validation (rule_id=%s, source_ip=%s): %s",
                rule_id,
                row.get("source_ip"),
                exc,
            )
            continue

        try:
            already_present = rule_exists(runner, spec)
            if not already_present:
                insert_rule(runner, spec)
        except FirewallTransientError as exc:
            _record_transient_failure(
                db,
                rule_id=rule_id,
                now=now_utc,
                error=str(exc),
                retry_delay_seconds=policy.retry_delay_seconds,
            )
            result.transient_failed.append(rule_id)
            logger.warning(
                "Firewall rule application failed (rule_id=%s, source_ip=%s): %s",
                rule_id,
                spec.source_ip,
                exc,
            )
            continue

        # iptables 적용은 끝났고 DB만 남았다. 여기서 Commit이 실패하면 Row는 PENDING으로
        # 남지만, 다음 Cycle의 `-C`가 기존 Rule을 찾아 APPLIED로 수렴한다.
        try:
            firewall_repository.mark_applied(db, rule_id=rule_id, applied_at=now_utc)
            db.commit()
        except Exception:
            db.rollback()
            logger.critical(
                "iptables rule is applied but DB update failed (rule_id=%s, comment=%s)",
                rule_id,
                spec.comment,
            )
            raise

        if already_present:
            result.already_present.append(rule_id)
        else:
            result.applied.append(rule_id)
        logger.info(
            "Firewall rule applied (rule_id=%s, source_ip=%s, already_present=%s)",
            rule_id,
            spec.source_ip,
            already_present,
        )

    return result


def release_rule(
    db: Session,
    *,
    rule_id: int,
    runner: IptablesRunner,
    policy: FirewallPolicy,
    now: datetime,
) -> bool:
    """APPLIED Rule을 실제로 제거하고 REMOVED로 기록합니다."""
    now_utc = require_utc_whole_second(now, "now")
    row = _get_rule_row(db, rule_id)
    if row is None:
        raise FirewallValidationError(f"firewall rule not found: {rule_id}")
    if row["status"] != firewall_repository.APPLIED:
        raise FirewallValidationError(
            f"firewall rule is not APPLIED: {rule_id} (status={row['status']})"
        )

    spec = FirewallRuleSpec(rule_id=rule_id, source_ip=str(row["source_ip"]))
    removed_from_os = False
    if rule_exists(runner, spec):
        delete_rule(runner, spec)
        removed_from_os = True
    else:
        logger.warning(
            "Firewall rule was already absent from iptables (rule_id=%s, comment=%s)",
            rule_id,
            spec.comment,
        )

    try:
        firewall_repository.mark_removed(db, rule_id=rule_id, released_at=now_utc)
        db.commit()
    except Exception:
        db.rollback()
        raise

    logger.info(
        "Firewall rule released (rule_id=%s, source_ip=%s, removed_from_os=%s)",
        rule_id,
        spec.source_ip,
        removed_from_os,
    )
    return removed_from_os


def process_pending_release_requests(
    db: Session,
    *,
    runner: IptablesRunner,
    policy: FirewallPolicy,
    now: datetime,
    limit: int | None = None,
) -> ReleaseRequestCycleResult:
    """Process administrator-approved firewall release requests."""

    now_utc = require_utc_whole_second(now, "now")
    batch_size = limit if limit is not None else policy.batch_size
    rows = firewall_release_repository.list_pending_release_requests(
        db,
        limit=batch_size,
    )
    result = ReleaseRequestCycleResult()

    for row in rows:
        request_id = int(row["id"])
        rule_id = int(row["firewall_rule_id"])
        rule_status = str(row["rule_status"])
        try:
            if rule_status == firewall_repository.APPLIED:
                release_rule(
                    db,
                    rule_id=rule_id,
                    runner=runner,
                    policy=policy,
                    now=now_utc,
                )
                firewall_release_repository.mark_succeeded(
                    db,
                    request_id=request_id,
                    processed_at=now_utc,
                )
                db.commit()
                result.succeeded.append(request_id)
                logger.info(
                    "Firewall release request succeeded (request_id=%s, rule_id=%s)",
                    request_id,
                    rule_id,
                )
                continue

            if rule_status == firewall_repository.REMOVED:
                if _removed_rule_is_verified_absent(row, runner=runner, policy=policy):
                    firewall_release_repository.mark_succeeded(
                        db,
                        request_id=request_id,
                        processed_at=now_utc,
                    )
                    db.commit()
                    result.already_removed.append(request_id)
                    logger.info(
                        "Firewall release request converged after crash "
                        "(request_id=%s, rule_id=%s)",
                        request_id,
                        rule_id,
                    )
                    continue
                raise FirewallValidationError(
                    f"firewall rule is REMOVED in DB but still present at runtime: {rule_id}"
                )

            raise FirewallValidationError(
                f"firewall rule is not releasable: {rule_id} (status={rule_status})"
            )
        except (FirewallTransientError, FirewallValidationError, ValueError) as exc:
            db.rollback()
            try:
                firewall_release_repository.mark_failed(
                    db,
                    request_id=request_id,
                    processed_at=now_utc,
                    error=str(exc),
                )
                db.commit()
            except Exception:
                db.rollback()
                raise
            result.failed.append(request_id)
            logger.warning(
                "Firewall release request failed (request_id=%s, rule_id=%s): %s",
                request_id,
                rule_id,
                exc,
            )

    return result


def reconcile(
    db: Session,
    *,
    runner: IptablesRunner,
    policy: FirewallPolicy,
    now: datetime,
) -> ReconcileResult:
    """DB 상태와 실제 iptables Rule을 대조합니다.

    재부팅 등으로 실제 Rule이 사라져도 DB는 APPLIED로 남아 있으므로, 차단이 조용히
    풀린 상태를 복구해야 합니다. 반대로 DB에 없는 `hanium-firewall:` Rule은 자동으로
    삭제하지 않고 관리자 확인 대상으로 남깁니다.
    """
    now_utc = require_utc_whole_second(now, "now")
    result = ReconcileResult()
    managed = list_managed_rule_ids(runner)
    pending_release_ids = firewall_release_repository.pending_release_rule_ids(db)

    applied_rows = _list_rows_by_status(db, firewall_repository.APPLIED)
    for row in applied_rows:
        rule_id = int(row["id"])
        if rule_id in pending_release_ids:
            logger.info(
                "Skipping reconciliation restore for pending release request "
                "(rule_id=%s)",
                rule_id,
            )
            continue
        # 복원도 새 차단과 동일한 검증을 거친다. Protected IP 목록이 바뀌거나 DHCP로
        # IP가 재할당된 뒤 재부팅되면, 예전 APPLIED Row가 지금은 보호 대상인 IP를
        # 다시 차단할 수 있다.
        try:
            row = firewall_repository.authorized_automatic_rule(
                db, rule_id=rule_id, required_status=firewall_repository.APPLIED, now=now_utc
            )
            spec = validate_rule_row(row, policy)
        except (FirewallValidationError, firewall_repository.AutomaticResponseBlockedError) as exc:
            result.validation_failed.append(rule_id)
            logger.error(
                "Refusing to restore firewall rule that fails validation "
                "(rule_id=%s, source_ip=%s): %s",
                rule_id,
                row.get("source_ip"),
                exc,
            )
            continue

        try:
            if rule_exists(runner, spec):
                result.verified.append(rule_id)
                continue
            insert_rule(runner, spec)
        except FirewallTransientError as exc:
            result.restore_failed.append(rule_id)
            logger.error(
                "Failed to restore missing firewall rule (rule_id=%s, source_ip=%s): %s",
                rule_id,
                spec.source_ip,
                exc,
            )
            continue

        result.restored.append(rule_id)
        logger.warning(
            "Missing firewall rule restored (rule_id=%s, source_ip=%s, comment=%s)",
            rule_id,
            spec.source_ip,
            spec.comment,
        )

    active_ids = {int(row["id"]) for row in applied_rows}
    active_ids.update(
        int(row["id"]) for row in _list_rows_by_status(db, firewall_repository.PENDING)
    )
    for rule_id, rule_line in sorted(managed.items()):
        if rule_id in active_ids:
            continue
        result.orphan_rule_ids.append(rule_id)
        # 자동 삭제하지 않는다. 우리가 만들지 않은 Rule이거나 DB가 손상된 상황일 수 있고,
        # 잘못 지우면 관리자 접근까지 끊길 수 있다.
        logger.warning(
            "Unmanaged firewall rule found without an active DB row "
            "(rule_id=%s, comment=%s%s, specification=%s)",
            rule_id,
            COMMENT_PREFIX,
            rule_id,
            rule_line,
        )

    return result


def plan_pending_rules(
    db: Session,
    *,
    policy: FirewallPolicy,
    now: datetime,
    limit: int | None = None,
) -> list[tuple[int, tuple[FirewallRuleSpec, list[str]] | str]]:
    """Dry Run용으로 실행 예정 내용을 만들되 OS·DB를 건드리지 않습니다."""
    now_utc = require_utc_whole_second(now, "now")
    batch_size = limit if limit is not None else policy.batch_size
    rows = firewall_repository.list_pending_rules(db, now=now_utc, limit=batch_size)

    planned: list[tuple[int, tuple[FirewallRuleSpec, list[str]] | str]] = []
    for row in rows:
        rule_id = int(row["id"])
        try:
            row = firewall_repository.authorized_automatic_rule(
                db, rule_id=rule_id, required_status=firewall_repository.PENDING, now=now_utc
            )
            spec = validate_rule_row(row, policy)
        except (FirewallValidationError, firewall_repository.AutomaticResponseBlockedError) as exc:
            planned.append((rule_id, f"VALIDATION_FAILURE: {exc}"))
            continue
        planned.append((rule_id, (spec, build_rule_args(spec, operation=INSERT))))
    return planned


def _removed_rule_is_verified_absent(
    row: dict[str, Any],
    *,
    runner: IptablesRunner,
    policy: FirewallPolicy,
) -> bool:
    spec = validate_rule_row(
        {
            "id": row["firewall_rule_id"],
            "source_ip": row["rule_source_ip"],
            "protocol": row["rule_protocol"],
            "dest_port": row["rule_dest_port"],
            "action": row["rule_action"],
        },
        policy,
    )
    return not rule_exists(runner, spec)


def _record_validation_failure(
    db: Session, *, rule_id: int, now: datetime, error: str
) -> None:
    try:
        firewall_repository.record_validation_failure(
            db, rule_id=rule_id, attempted_at=now, error=error
        )
        db.commit()
    except Exception:
        db.rollback()
        raise


def _record_transient_failure(
    db: Session,
    *,
    rule_id: int,
    now: datetime,
    error: str,
    retry_delay_seconds: int,
) -> None:
    try:
        firewall_repository.record_transient_failure(
            db,
            rule_id=rule_id,
            attempted_at=now,
            error=error,
            retry_delay_seconds=retry_delay_seconds,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise


def _get_rule_row(db: Session, rule_id: int) -> dict[str, Any] | None:
    row = (
        db.execute(
            text("SELECT * FROM firewall_rules WHERE id = :id"),
            {"id": rule_id},
        )
        .mappings()
        .first()
    )
    return dict(row) if row is not None else None


def _list_rows_by_status(db: Session, status: str) -> list[dict[str, Any]]:
    rows = db.execute(
        text(
            """
            SELECT *
            FROM firewall_rules
            WHERE status = :status
            ORDER BY id ASC
            """
        ),
        {"status": status},
    ).mappings()
    return [dict(row) for row in rows]


def _require_private_ipv4(source_ip: str) -> ipaddress.IPv4Address:
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise FirewallValidationError(f"invalid source_ip: {source_ip!r}") from exc

    if not isinstance(address, ipaddress.IPv4Address):
        raise FirewallValidationError(f"source_ip must be IPv4: {source_ip!r}")
    if not any(address in network for network in RFC1918_NETWORKS):
        raise FirewallValidationError(
            f"source_ip must be an RFC1918 private address: {source_ip!r}"
        )
    return address


def _summarize(stderr: str, *, limit: int = 300) -> str:
    """DB `last_error`에 남길 만큼만 요약합니다."""
    collapsed = " ".join(stderr.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + "..."
