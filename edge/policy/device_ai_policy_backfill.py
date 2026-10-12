"""AI 설정 도입 전부터 있던 기기의 초기 AI 모드 이관 (P9-03).

코드 기본값이 아니라 운영자가 승인한 목록(`LegacyAiOverride`)만 입력으로 받는다.

- 승인 목록에 없는 기기가 하나라도 있으면 아무것도 변경하지 않고 모든 문제를 한 번에 보고한다.
  설정 누락을 OFF로 꾸미지 않는다.
- 이미 AI revision이 있는 기기는 건너뛰므로 재실행해도 기존 값을 덮어쓰지 않는다.
- 기기·Trust·정책 테이블은 읽기만 하고 `device_ai_policy_revisions`에만 쓴다.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from edge.policy.device_ai_policy import validate_ai_mode
from edge.policy.device_ai_policy_repository import insert_ai_revision
from edge.policy.device_policy import (
    BackfillBlockedError,
    DevicePolicyValidationError,
    format_utc_seconds,
    parse_effective_from,
    require_aware,
    utc_now,
    validate_actor,
    validate_device_id,
    validate_reason,
)
from edge.policy.device_policy_repository import Clock, write_transaction


@dataclass(frozen=True)
class LegacyAiOverride:
    """기존 기기 하나의 승인된 초기 AI 모드."""

    device_id: str
    mode: str
    #: 승인 근거(승인 목록 식별자 등). 감사 이력의 작성자에 남는다.
    source: str


@dataclass(frozen=True)
class AiBackfillPlan:
    to_create: tuple[str, ...]
    already_revised: tuple[str, ...]
    problems: tuple[str, ...]


@dataclass(frozen=True)
class AiBackfillResult:
    created: tuple[str, ...]
    already_revised: tuple[str, ...]


def parse_ai_override(raw: Mapping[str, Any]) -> LegacyAiOverride:
    """승인 목록의 기기 항목을 strict하게 읽는다."""
    if not isinstance(raw, Mapping):
        raise DevicePolicyValidationError("AI override must be an object")
    required = {"device_id", "mode", "source"}
    unknown = sorted(str(key) for key in raw if key not in required)
    if unknown:
        raise DevicePolicyValidationError(f"unsupported override fields: {unknown}")
    missing = sorted(required - set(raw))
    if missing:
        raise DevicePolicyValidationError(f"missing override fields: {missing}")
    return LegacyAiOverride(
        device_id=validate_device_id(raw["device_id"]),
        mode=validate_ai_mode(raw["mode"]),
        source=validate_actor(raw["source"], "source"),
    )


def _revalidated(overrides: Mapping[str, LegacyAiOverride]) -> dict[str, LegacyAiOverride]:
    """직접 만든 override 객체도 승인 목록과 같은 규칙으로 다시 검증한다."""
    if not isinstance(overrides, Mapping):
        raise DevicePolicyValidationError("overrides must be a mapping of device_id to override")
    checked: dict[str, LegacyAiOverride] = {}
    for key, value in overrides.items():
        if not isinstance(value, LegacyAiOverride):
            raise DevicePolicyValidationError("overrides must be LegacyAiOverride objects")
        parsed = parse_ai_override(
            {"device_id": value.device_id, "mode": value.mode, "source": value.source}
        )
        if key != parsed.device_id:
            raise DevicePolicyValidationError(
                f"override key {key!r} does not match its device_id {parsed.device_id!r}"
            )
        checked[key] = parsed
    return checked


def _plan_locked(
    connection: sqlite3.Connection, overrides: Mapping[str, LegacyAiOverride]
) -> AiBackfillPlan:
    rows = connection.execute(
        """
        SELECT d.device_id,
               EXISTS (SELECT 1 FROM device_ai_policy_revisions r WHERE r.device_id = d.device_id)
        FROM devices d
        ORDER BY d.device_id
        """
    ).fetchall()
    known = {str(row[0]) for row in rows}
    problems = [
        f"UNKNOWN_OVERRIDE:{device_id}: no such device in the database"
        for device_id in sorted(set(overrides) - known)
    ]
    to_create: list[str] = []
    already: list[str] = []
    for device_id, has_revision in rows:
        if has_revision:
            already.append(device_id)
        elif device_id in overrides:
            to_create.append(device_id)
        else:
            problems.append(f"MISSING_OVERRIDE:{device_id}: an approved AI mode is required")
    return AiBackfillPlan(tuple(to_create), tuple(already), tuple(problems))


def plan_ai_backfill(
    connection: sqlite3.Connection, overrides: Mapping[str, LegacyAiOverride]
) -> AiBackfillPlan:
    """dry-run. 아무것도 쓰지 않고 무엇이 만들어지고 무엇이 막히는지 보여준다."""
    return _plan_locked(connection, _revalidated(overrides))


def apply_ai_backfill(
    connection: sqlite3.Connection,
    overrides: Mapping[str, LegacyAiOverride],
    *,
    effective_from: datetime,
    reason: str,
    clock: Clock = utc_now,
) -> AiBackfillResult:
    """AI revision이 없는 모든 기존 기기에 승인된 초기 revision 1을 만든다(한 트랜잭션).

    `effective_from`은 운영자가 확인한 이관 효력 시점(UTC, 10초 경계)이다. 과거 시점도 허용한다.
    그 이전 Window는 `AI_POLICY_UNAVAILABLE`로 남고 모드를 추정하지 않는다.
    """
    reason_text = validate_reason(reason)
    effective = parse_effective_from(
        format_utc_seconds(require_aware(effective_from, "effective_from"))
    )
    overrides = _revalidated(overrides)

    with write_transaction(connection):
        now = require_aware(clock(), "clock()")
        plan = _plan_locked(connection, overrides)
        if plan.problems:
            raise BackfillBlockedError(
                f"AI backfill blocked by {len(plan.problems)} problem(s); nothing was changed",
                problems=plan.problems,
            )
        for device_id in plan.to_create:
            override = overrides[device_id]
            insert_ai_revision(
                connection,
                device_id=device_id,
                revision=1,
                mode=override.mode,
                effective_from=effective,
                created_at=now,
                created_by=f"backfill:{override.source}"[:128],
                reason=reason_text,
            )
    return AiBackfillResult(created=plan.to_create, already_revised=plan.already_revised)
