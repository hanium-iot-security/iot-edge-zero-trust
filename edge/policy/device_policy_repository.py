"""기기 등록·정책 Revision 저장소 (device-policy-v1).

- 쓰기 함수는 `BEGIN IMMEDIATE`로 쓰기 잠금을 먼저 얻고, 그 안에서 서버 시각을 정한 뒤
  검사 → 변경 → commit한다. 실패하면 전체 rollback한다.
- 공개 쓰기 함수는 트랜잭션을 직접 소유하며 이미 트랜잭션이 열린 연결은 거부한다. 여러 쓰기를
  한 트랜잭션으로 묶는 호출자(backfill, seed)는 `write_transaction()` 안에서 `*_locked` 함수를 쓴다.
- 읽기 함수는 호출자의 트랜잭션을 그대로 쓰며 commit하지 않는다.
- 연결은 호출자가 소유한다. `db.migration_runner.connect_database`로 연 별도 연결을 권장한다.

효력 시각은 정수 초 UTC 문자열이라 사전식 비교가 시간순과 같다.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from edge.policy.device_policy import (
    ALLOWED_STATE_TRANSITIONS,
    POLICY_FIELDS,
    STATE_PENDING,
    DeviceIdConflictError,
    DeviceIpConflictError,
    DeviceNotFoundError,
    DevicePolicy,
    DevicePolicyValidationError,
    IpRegistrationPolicy,
    NoPolicyChangeError,
    PendingRevisionExistsError,
    PolicyUnavailableError,
    PolicyWriteBusyError,
    RevisionConflictError,
    StateTransitionBlockedError,
    floor_to_second,
    format_utc_millis,
    format_utc_seconds,
    next_effective_boundary,
    parse_effective_from,
    require_aware,
    require_lookup_id,
    utc_now,
    validate_actor,
    validate_device_id,
    validate_device_type,
    validate_mqtt_principal,
    validate_policy,
    validate_reason,
    validate_registration_ip,
    validate_registration_state,
    validate_revision_number,
)


Clock = Callable[[], datetime]
StateChangeGuard = Callable[[sqlite3.Connection, str, str, str], None]

_REVISION_COLUMNS = (
    "device_id, revision, effective_from, registration_state, policy_profile, "
    "expected_publish_interval_seconds, publish_count_max, payload_size_max_bytes, "
    "packet_rate_max_pps, byte_rate_max_bytes_per_second, created_at, created_by, reason"
)


# ── 값 객체 ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PolicyRevision:
    """저장된 정책 Revision 하나(불변)."""

    device_id: str
    revision: int
    effective_from: str
    registration_state: str
    policy: DevicePolicy
    created_at: str
    created_by: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "revision": self.revision,
            "effective_from": self.effective_from,
            "registration_state": self.registration_state,
            "policy": self.policy.as_dict(),
            "created_at": self.created_at,
            "created_by": self.created_by,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class PolicySnapshot:
    """`GET /api/devices/{device_id}/policy` 응답과 같은 구조."""

    device_id: str
    server_time: str
    latest_revision: int
    current: PolicyRevision | None
    pending: PolicyRevision | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "server_time": self.server_time,
            "latest_revision": self.latest_revision,
            "current": self.current.as_dict() if self.current else None,
            "pending": self.pending.as_dict() if self.pending else None,
        }


@dataclass(frozen=True)
class RegisteredDevice:
    device_id: str
    ip_address: str
    created_at: str
    registration_effective_from: str
    revision: PolicyRevision


# ── 트랜잭션 ─────────────────────────────────────────────────────────────────


def _is_busy(error: sqlite3.OperationalError) -> bool:
    message = str(error).lower()
    return "locked" in message or "busy" in message


@contextmanager
def write_transaction(connection: sqlite3.Connection) -> Iterator[None]:
    """쓰기 잠금을 먼저 얻고 commit/rollback까지 책임진다.

    잠금을 제한 시간 안에 얻지 못하면 `PolicyWriteBusyError`다. 잠금을 쥔 채 파일 lock이나
    외부 명령을 기다리지 않는다(필요한 파일 lock은 이 함수 밖에서 먼저 얻는다).
    """
    if connection.in_transaction:
        raise RuntimeError(
            "write_transaction requires a connection without an open transaction"
        )
    try:
        connection.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError as exc:
        if _is_busy(exc):
            raise PolicyWriteBusyError(
                "The database write lock could not be acquired; retry with a fresh read"
            ) from exc
        raise
    try:
        yield
        connection.commit()
    except BaseException:
        if connection.in_transaction:
            connection.rollback()
        raise


# ── 읽기 ─────────────────────────────────────────────────────────────────────


def _revision_from_row(row: Any) -> PolicyRevision:
    return PolicyRevision(
        device_id=row[0],
        revision=validate_revision_number(row[1], "revision"),
        effective_from=row[2],
        registration_state=row[3],
        # Validate stored values before conversion. A damaged integer field
        # must not silently turn 15.5 into an apparently valid threshold of 15.
        policy=validate_policy(dict(zip(POLICY_FIELDS, row[4:10]))),
        created_at=row[10],
        created_by=row[11],
        reason=row[12],
    )


def _fetch_revision(
    connection: sqlite3.Connection, where: str, params: tuple[Any, ...]
) -> PolicyRevision | None:
    row = connection.execute(
        f"SELECT {_REVISION_COLUMNS} FROM device_policy_revisions "
        f"WHERE {where} ORDER BY revision DESC LIMIT 1",
        params,
    ).fetchone()
    return _revision_from_row(row) if row is not None else None


def device_exists(connection: sqlite3.Connection, device_id: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM devices WHERE device_id = ?", (require_lookup_id(device_id),)
        ).fetchone()
        is not None
    )


def get_latest_revision(
    connection: sqlite3.Connection, device_id: str
) -> PolicyRevision | None:
    return _fetch_revision(connection, "device_id = ?", (require_lookup_id(device_id),))


def get_revision_effective_at(
    connection: sqlite3.Connection, device_id: str, at: datetime
) -> PolicyRevision | None:
    """`at`에 효력이 있던 최신 Revision(`effective_from <= at`). 없으면 None."""
    device_id = require_lookup_id(device_id)
    at_text = format_utc_seconds(floor_to_second(at))
    return _fetch_revision(
        connection, "device_id = ? AND effective_from <= ?", (device_id, at_text)
    )


def get_pending_revision(
    connection: sqlite3.Connection, device_id: str, server_time: datetime
) -> PolicyRevision | None:
    """아직 효력이 시작되지 않은 최신 Revision. 쓰기 규칙상 최대 1개다."""
    device_id = require_lookup_id(device_id)
    time_text = format_utc_seconds(floor_to_second(server_time))
    return _fetch_revision(
        connection, "device_id = ? AND effective_from > ?", (device_id, time_text)
    )


def list_revisions(
    connection: sqlite3.Connection, device_id: str
) -> list[PolicyRevision]:
    rows = connection.execute(
        f"SELECT {_REVISION_COLUMNS} FROM device_policy_revisions "
        "WHERE device_id = ? ORDER BY revision ASC",
        (require_lookup_id(device_id),),
    ).fetchall()
    return [_revision_from_row(row) for row in rows]


def get_policy_snapshot(
    connection: sqlite3.Connection,
    device_id: str,
    *,
    server_time: datetime | None = None,
) -> PolicySnapshot:
    """현재 적용본·예정본·최신 revision을 한 번에 읽는다.

    정상적인 초기 효력 대기(current=None, pending=revision 1)는 오류가 아니다. 등록된 기기에
    Revision이 하나도 없으면 `PolicyUnavailableError`다.
    """
    device_id = require_lookup_id(device_id)
    now = require_aware(server_time if server_time is not None else utc_now(), "server_time")
    if not device_exists(connection, device_id):
        raise DeviceNotFoundError(f"Device {device_id!r} is not registered")
    try:
        latest = get_latest_revision(connection, device_id)
        if latest is None:
            raise PolicyUnavailableError(f"Device {device_id!r} has no policy revision")
        first = _fetch_revision(connection, "device_id = ? AND revision = 1", (device_id,))
        registered_from = connection.execute(
            "SELECT registration_effective_from FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()[0]
        snapshot = PolicySnapshot(
            device_id=device_id,
            server_time=format_utc_millis(now),
            latest_revision=latest.revision,
            current=get_revision_effective_at(connection, device_id, now),
            pending=get_pending_revision(connection, device_id, now),
        )
        if first is None:
            raise ValueError("Initial policy revision is missing")
        for revision in (first, latest, snapshot.current, snapshot.pending):
            if revision is not None:
                validate_policy(revision.policy)
                validate_registration_state(revision.registration_state)
                parse_effective_from(revision.effective_from)
                validate_revision_number(revision.revision)
        # NULL is intentionally preserved for identities registered before 007.
        if registered_from is not None:
            parse_effective_from(registered_from, "registration_effective_from")
            if registered_from != first.effective_from:
                raise ValueError("Registration and initial policy boundaries disagree")
    except (DevicePolicyValidationError, ValueError, TypeError) as exc:
        raise PolicyUnavailableError(f"Device {device_id!r} has invalid policy state") from exc
    return snapshot


def diagnose_device_ip_conflicts(connection: sqlite3.Connection) -> dict[str, list[Any]]:
    """Migration 007 적용 전에 실행하는 읽기 전용 진단.

    중복 IP가 있으면 007의 유일 인덱스 생성이 실패한다. 이 함수는 자료를 바꾸지 않고
    무엇을 먼저 정리해야 하는지만 보여준다.
    """
    duplicates = connection.execute(
        """
        SELECT ip_address, group_concat(device_id, ',')
        FROM devices
        WHERE ip_address IS NOT NULL AND ip_address <> ''
        GROUP BY ip_address
        HAVING count(*) > 1
        """
    ).fetchall()
    blanks = connection.execute(
        "SELECT device_id FROM devices WHERE ip_address IS NULL OR ip_address = ''"
    ).fetchall()
    return {
        "duplicate_ips": [
            {"ip_address": row[0], "device_ids": sorted(row[1].split(","))}
            for row in duplicates
        ],
        "blank_ip_device_ids": sorted(row[0] for row in blanks),
    }


# ── 쓰기(잠금을 이미 쥔 호출자용) ────────────────────────────────────────────


def _insert_revision(
    connection: sqlite3.Connection,
    *,
    device_id: str,
    revision: int,
    effective_from: datetime,
    registration_state: str,
    policy: DevicePolicy,
    created_at: datetime,
    created_by: str,
    reason: str,
) -> PolicyRevision:
    # 모든 revision 쓰기(등록·변경·이관·seed)가 지나는 곳이라 여기서 다시 검증한다.
    device_id = validate_device_id(device_id)
    registration_state = validate_registration_state(registration_state)
    policy = validate_policy(policy)
    reason = validate_reason(reason)
    created_by = validate_actor(created_by)
    effective_text = format_utc_seconds(effective_from)
    created_text = format_utc_millis(created_at)
    connection.execute(
        """
        INSERT INTO device_policy_revisions (
            device_id, revision, effective_from, registration_state, policy_profile,
            expected_publish_interval_seconds, publish_count_max, payload_size_max_bytes,
            packet_rate_max_pps, byte_rate_max_bytes_per_second,
            created_at, created_by, reason
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            device_id,
            revision,
            effective_text,
            registration_state,
            policy.policy_profile,
            policy.expected_publish_interval_seconds,
            policy.publish_count_max,
            policy.payload_size_max_bytes,
            policy.packet_rate_max_pps,
            policy.byte_rate_max_bytes_per_second,
            created_text,
            created_by,
            reason,
        ),
    )
    return PolicyRevision(
        device_id=device_id,
        revision=revision,
        effective_from=effective_text,
        registration_state=registration_state,
        policy=policy,
        created_at=created_text,
        created_by=created_by,
        reason=reason,
    )


def create_device_locked(
    connection: sqlite3.Connection,
    *,
    device_id: str,
    ip_address: str,
    device_type: str,
    mqtt_principal: str | None,
    policy: DevicePolicy,
    reason: str,
    created_by: str,
    initial_state: str,
    effective_from: datetime,
    now: datetime,
) -> RegisteredDevice:
    """기기와 초기 revision 1을 만든다. 쓰기 잠금과 LAN·제외 주소 검증은 호출자 책임이다.

    Trust 필드는 기존 기본값(normal/100/last_seen 없음)으로 시작한다. `mqtt_principal`은
    관리자 등록에서는 필수지만, 확인되지 않은 값을 지어내지 않도록 seed는 None을 쓸 수 있다.
    """
    device_id = validate_device_id(device_id)
    ip_address = validate_registration_ip(ip_address, IpRegistrationPolicy())  # 정규 형식·RFC1918
    device_type = validate_device_type(device_type)
    if mqtt_principal is not None:
        mqtt_principal = validate_mqtt_principal(mqtt_principal)
    created_at = format_utc_seconds(floor_to_second(now))
    effective_text = format_utc_seconds(effective_from)

    if device_exists(connection, device_id):
        raise DeviceIdConflictError(f"Device {device_id!r} is already registered")
    owner = connection.execute(
        "SELECT device_id FROM devices WHERE ip_address = ?", (ip_address,)
    ).fetchone()
    if owner is not None:
        raise DeviceIpConflictError(
            f"IP address {ip_address} is already assigned to {owner[0]!r}"
        )

    try:
        connection.execute(
            """
            INSERT INTO devices (
                device_id, ip_address, status, trust_score, created_at,
                device_type, mqtt_principal, registration_effective_from
            )
            VALUES (?, ?, 'normal', 100, ?, ?, ?, ?)
            """,
            (device_id, ip_address, created_at, device_type, mqtt_principal, effective_text),
        )
        revision = _insert_revision(
            connection,
            device_id=device_id,
            revision=1,
            effective_from=effective_from,
            registration_state=initial_state,
            policy=policy,
            created_at=now,
            created_by=created_by,
            reason=reason,
        )
    except sqlite3.IntegrityError as exc:
        message = str(exc)
        if "devices.ip_address" in message:
            raise DeviceIpConflictError(f"IP address {ip_address} is already assigned") from exc
        if "devices.device_id" in message:
            raise DeviceIdConflictError(f"Device {device_id!r} is already registered") from exc
        raise
    return RegisteredDevice(
        device_id=device_id,
        ip_address=ip_address,
        created_at=created_at,
        registration_effective_from=effective_text,
        revision=revision,
    )


# ── 쓰기(공개 API: 트랜잭션 소유) ────────────────────────────────────────────


def register_device(
    connection: sqlite3.Connection,
    *,
    device_id: Any,
    ip_address: Any,
    device_type: Any,
    mqtt_principal: Any,
    policy: Mapping[str, Any] | DevicePolicy,
    reason: Any,
    created_by: Any,
    ip_policy: IpRegistrationPolicy,
    clock: Clock = utc_now,
) -> RegisteredDevice:
    """신규 기기를 PENDING으로 등록한다(기기 + revision 1을 한 트랜잭션으로).

    효력은 쓰기 잠금을 얻은 뒤 서버가 정한 시각의 **엄격히 다음** UTC 10초 경계에 시작한다.
    입력 검증 오류는 DB에 접근하기 전에 발생한다.
    """
    device_id = validate_device_id(device_id)
    ip_address = validate_registration_ip(ip_address, ip_policy)
    device_type = validate_device_type(device_type)
    mqtt_principal = validate_mqtt_principal(mqtt_principal)
    policy = validate_policy(policy)
    reason = validate_reason(reason)
    created_by = validate_actor(created_by)

    with write_transaction(connection):
        now = require_aware(clock(), "clock()")
        return create_device_locked(
            connection,
            device_id=device_id,
            ip_address=ip_address,
            device_type=device_type,
            mqtt_principal=mqtt_principal,
            policy=policy,
            reason=reason,
            created_by=created_by,
            initial_state=STATE_PENDING,
            effective_from=next_effective_boundary(now),
            now=now,
        )


def append_policy_revision(
    connection: sqlite3.Connection,
    *,
    device_id: Any,
    expected_revision: Any,
    registration_state: Any,
    policy: Mapping[str, Any] | DevicePolicy,
    reason: Any,
    created_by: Any,
    clock: Clock = utc_now,
    state_change_guard: StateChangeGuard | None = None,
) -> PolicyRevision:
    """정책값·등록 상태를 새 revision으로 추가한다. 기존 revision은 수정하지 않는다.

    같은 쓰기 잠금 안에서 기기·정책 존재 → `expected_revision` 충돌 → 예정 revision 존재 →
    상태 전이 → `state_change_guard` → 변경 없음 순으로 검사한다. 부분 PATCH 없이 항상 완전한
    정책을 받는다.

    `state_change_guard(connection, device_id, from_state, to_state)`는 상태가 바뀔 때만 호출되며,
    활성 차단·대기 요청처럼 이 모듈이 모르는 조건이 있으면 `StateTransitionBlockedError`로 막는다.
    잠금을 쥔 채 파일 lock이나 외부 명령을 기다리면 안 된다.
    """
    device_id = validate_device_id(device_id)
    expected_revision = validate_revision_number(expected_revision)
    new_state = validate_registration_state(registration_state)
    policy = validate_policy(policy)
    reason = validate_reason(reason)
    created_by = validate_actor(created_by)

    with write_transaction(connection):
        now = require_aware(clock(), "clock()")
        if not device_exists(connection, device_id):
            raise DeviceNotFoundError(f"Device {device_id!r} is not registered")
        # Validate existing metadata and policy inside the write transaction,
        # before inserting anything or returning an error after a commit.
        snapshot = get_policy_snapshot(connection, device_id, server_time=now)
        current, pending = snapshot.current, snapshot.pending
        latest = pending if pending is not None else current
        if latest is None:
            raise PolicyUnavailableError(f"Device {device_id!r} has no effective or pending policy")
        current_number = current.revision if current is not None else None
        pending_number = pending.revision if pending is not None else None

        if expected_revision != latest.revision:
            raise RevisionConflictError(
                f"expected_revision {expected_revision} does not match latest revision "
                f"{latest.revision}",
                current_revision=current_number,
                pending_revision=pending_number,
            )
        if pending is not None:
            raise PendingRevisionExistsError(
                f"Revision {pending.revision} is still pending",
                current_revision=current_number,
                pending_revision=pending.revision,
            )

        from_state = latest.registration_state
        if new_state not in ALLOWED_STATE_TRANSITIONS[from_state]:
            raise StateTransitionBlockedError(
                f"Registration state {from_state} cannot change to {new_state}"
                if from_state != new_state
                else f"A {from_state} device cannot receive new policy revisions"
            )
        if new_state != from_state and state_change_guard is not None:
            state_change_guard(connection, device_id, from_state, new_state)
        if new_state == from_state and policy == latest.policy:
            raise NoPolicyChangeError("The request does not change the registration state or policy")

        return _insert_revision(
            connection,
            device_id=device_id,
            revision=latest.revision + 1,
            effective_from=next_effective_boundary(now),
            registration_state=new_state,
            policy=policy,
            created_at=now,
            created_by=created_by,
            reason=reason,
        )


__all__ = [
    "Clock",
    "PolicyRevision",
    "PolicySnapshot",
    "RegisteredDevice",
    "StateChangeGuard",
    "append_policy_revision",
    "create_device_locked",
    "device_exists",
    "diagnose_device_ip_conflicts",
    "get_latest_revision",
    "get_pending_revision",
    "get_policy_snapshot",
    "get_revision_effective_at",
    "list_revisions",
    "register_device",
    "write_transaction",
]
