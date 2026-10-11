"""기기별 AI 모드 Revision 저장소 (P9-03).

`device_policy_repository`와 같은 규칙을 따른다. 쓰기 함수는 `BEGIN IMMEDIATE`로 쓰기 잠금을 먼저
얻고 그 안에서 서버 시각을 정한 뒤 검사 → 변경 → commit하며, 읽기 함수는 호출자의 트랜잭션을 쓴다.
기존 Revision은 수정하지 않는다. 설정이 없거나 손상됐으면 OFF로 꾸미지 않고
`AiPolicyUnavailableError`로 알린다.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from edge.policy.device_ai_policy import (
    AI_MODE_OBSERVE,
    AiPolicyUnavailableError,
    validate_ai_mode,
)
from edge.policy.device_policy import (
    STATE_DISABLED,
    DeviceNotFoundError,
    DevicePolicyValidationError,
    NoPolicyChangeError,
    PendingRevisionExistsError,
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
    validate_reason,
    validate_revision_number,
)
from edge.policy.device_policy_repository import Clock, device_exists, write_transaction


_COLUMNS = "device_id, revision, mode, effective_from, created_at, created_by, reason"


@dataclass(frozen=True)
class AiPolicyRevision:
    """저장된 AI 모드 Revision 하나(불변)."""

    device_id: str
    revision: int
    mode: str
    effective_from: str
    created_at: str
    created_by: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "revision": self.revision,
            "mode": self.mode,
            "effective_from": self.effective_from,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class AiPolicySnapshot:
    device_id: str
    server_time: str
    latest_revision: int
    current: AiPolicyRevision | None
    pending: AiPolicyRevision | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "server_time": self.server_time,
            "latest_revision": self.latest_revision,
            "current": self.current.as_dict() if self.current else None,
            "pending": self.pending.as_dict() if self.pending else None,
        }


# ── 읽기 ─────────────────────────────────────────────────────────────────────


def _revision_from_row(row: Any) -> AiPolicyRevision:
    parse_effective_from(row[3])
    return AiPolicyRevision(
        device_id=row[0],
        revision=validate_revision_number(row[1], "revision"),
        mode=validate_ai_mode(row[2]),
        effective_from=row[3],
        created_at=row[4],
        created_by=row[5],
        reason=row[6],
    )


def _fetch(
    connection: sqlite3.Connection, where: str, params: tuple[Any, ...]
) -> AiPolicyRevision | None:
    row = connection.execute(
        f"SELECT {_COLUMNS} FROM device_ai_policy_revisions "
        f"WHERE {where} ORDER BY revision DESC LIMIT 1",
        params,
    ).fetchone()
    return _revision_from_row(row) if row is not None else None


def get_latest_ai_revision(
    connection: sqlite3.Connection, device_id: str
) -> AiPolicyRevision | None:
    return _fetch(connection, "device_id = ?", (require_lookup_id(device_id),))


def get_ai_revision_effective_at(
    connection: sqlite3.Connection, device_id: str, at: datetime
) -> AiPolicyRevision | None:
    """`at`에 효력이 있던 최신 Revision(`effective_from <= at`). 없으면 None."""
    at_text = format_utc_seconds(floor_to_second(at))
    return _fetch(
        connection,
        "device_id = ? AND effective_from <= ?",
        (require_lookup_id(device_id), at_text),
    )


def get_pending_ai_revision(
    connection: sqlite3.Connection, device_id: str, server_time: datetime
) -> AiPolicyRevision | None:
    """아직 효력이 시작되지 않은 최신 Revision. 쓰기 규칙상 최대 1개다."""
    time_text = format_utc_seconds(floor_to_second(server_time))
    return _fetch(
        connection,
        "device_id = ? AND effective_from > ?",
        (require_lookup_id(device_id), time_text),
    )


def list_ai_revisions(connection: sqlite3.Connection, device_id: str) -> list[AiPolicyRevision]:
    rows = connection.execute(
        f"SELECT {_COLUMNS} FROM device_ai_policy_revisions WHERE device_id = ? ORDER BY revision",
        (require_lookup_id(device_id),),
    ).fetchall()
    return [_revision_from_row(row) for row in rows]


def get_ai_policy_snapshot(
    connection: sqlite3.Connection,
    device_id: str,
    *,
    server_time: datetime | None = None,
) -> AiPolicySnapshot:
    """현재 적용본·예정본·최신 revision을 한 번에 읽는다.

    초기 효력 대기(current=None, pending=revision 1)는 오류가 아니다. Revision이 하나도 없거나
    값이 손상됐으면 `AiPolicyUnavailableError`다.
    """
    device_id = require_lookup_id(device_id)
    now = require_aware(server_time if server_time is not None else utc_now(), "server_time")
    if not device_exists(connection, device_id):
        raise DeviceNotFoundError(f"Device {device_id!r} is not registered")
    try:
        latest = get_latest_ai_revision(connection, device_id)
        if latest is None:
            raise AiPolicyUnavailableError(f"Device {device_id!r} has no AI policy revision")
        return AiPolicySnapshot(
            device_id=device_id,
            server_time=format_utc_millis(now),
            latest_revision=latest.revision,
            current=get_ai_revision_effective_at(connection, device_id, now),
            pending=get_pending_ai_revision(connection, device_id, now),
        )
    except (DevicePolicyValidationError, ValueError, TypeError) as exc:
        raise AiPolicyUnavailableError(f"Device {device_id!r} has invalid AI policy state") from exc


# ── 쓰기 ─────────────────────────────────────────────────────────────────────


def insert_ai_revision(
    connection: sqlite3.Connection,
    *,
    device_id: Any,
    revision: int,
    mode: Any,
    effective_from: datetime,
    created_at: datetime,
    created_by: Any,
    reason: Any,
) -> AiPolicyRevision:
    """모든 AI revision 쓰기(등록·변경·이관)가 지나는 곳이라 여기서 다시 검증한다.

    쓰기 잠금은 호출자 책임이다.
    """
    device_id = validate_device_id(device_id)
    mode = validate_ai_mode(mode)
    reason = validate_reason(reason)
    created_by = validate_actor(created_by)
    effective_text = format_utc_seconds(effective_from)
    created_text = format_utc_millis(created_at)
    connection.execute(
        """
        INSERT INTO device_ai_policy_revisions (
            device_id, revision, mode, effective_from, created_at, created_by, reason
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (device_id, revision, mode, effective_text, created_text, created_by, reason),
    )
    return AiPolicyRevision(
        device_id=device_id,
        revision=revision,
        mode=mode,
        effective_from=effective_text,
        created_at=created_text,
        created_by=created_by,
        reason=reason,
    )


def _latest_registration_state(connection: sqlite3.Connection, device_id: str) -> str | None:
    row = connection.execute(
        "SELECT registration_state FROM device_policy_revisions "
        "WHERE device_id = ? ORDER BY revision DESC LIMIT 1",
        (device_id,),
    ).fetchone()
    return row[0] if row is not None else None


def append_ai_policy_revision(
    connection: sqlite3.Connection,
    *,
    device_id: Any,
    expected_revision: Any,
    mode: Any,
    reason: Any,
    created_by: Any,
    clock: Clock = utc_now,
) -> AiPolicyRevision:
    """AI 모드를 새 revision으로 추가한다. 효력은 엄격히 다음 UTC 10초 경계다.

    같은 쓰기 잠금 안에서 기기·AI 설정 존재 → `expected_revision` 충돌 → 예정 revision 존재 →
    DISABLED 기기의 OBSERVE 전환 → 변경 없음 순으로 검사한다. 입력 검증 오류는 DB에 접근하기
    전에 발생한다. 전역 AI 모드(`TRUST_AI_MODE`) 확인은 호출하는 API의 책임이다.
    """
    device_id = validate_device_id(device_id)
    expected_revision = validate_revision_number(expected_revision)
    mode = validate_ai_mode(mode)
    reason = validate_reason(reason)
    created_by = validate_actor(created_by)

    with write_transaction(connection):
        now = require_aware(clock(), "clock()")
        snapshot = get_ai_policy_snapshot(connection, device_id, server_time=now)
        current, pending = snapshot.current, snapshot.pending
        latest = pending if pending is not None else current
        if latest is None:
            raise AiPolicyUnavailableError(f"Device {device_id!r} has no effective AI policy")
        current_number = current.revision if current is not None else None

        if expected_revision != latest.revision:
            raise RevisionConflictError(
                f"expected_revision {expected_revision} does not match latest revision "
                f"{latest.revision}",
                current_revision=current_number,
                pending_revision=pending.revision if pending is not None else None,
            )
        if pending is not None:
            raise PendingRevisionExistsError(
                f"Revision {pending.revision} is still pending",
                current_revision=current_number,
                pending_revision=pending.revision,
            )
        if mode == AI_MODE_OBSERVE and _latest_registration_state(connection, device_id) == STATE_DISABLED:
            raise StateTransitionBlockedError("A DISABLED device cannot be set to OBSERVE")
        if mode == latest.mode:
            raise NoPolicyChangeError("The request does not change the AI mode")

        return insert_ai_revision(
            connection,
            device_id=device_id,
            revision=latest.revision + 1,
            mode=mode,
            effective_from=next_effective_boundary(now),
            created_at=now,
            created_by=created_by,
            reason=reason,
        )


__all__ = [
    "AiPolicyRevision",
    "AiPolicySnapshot",
    "append_ai_policy_revision",
    "get_ai_policy_snapshot",
    "get_ai_revision_effective_at",
    "get_latest_ai_revision",
    "get_pending_ai_revision",
    "insert_ai_revision",
    "list_ai_revisions",
]
