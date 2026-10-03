"""정책 도입 전부터 있던 기기(기존 ESP32)에 초기 정책 revision을 만드는 이관.

코드 기본값이 아니라 운영자가 baseline manifest에서 확인한 실제 운영값(`LegacyDeviceOverride`)을
입력으로 받는다.

- 사전 조건을 하나라도 못 지키면 아무것도 변경하지 않고 모든 문제를 한 번에 보고한다.
- 이미 revision이 있는 기기는 건너뛰며 재실행해도 기존 값을 덮어쓰지 않는다.
- ACTIVE로 이관하되 Trust 점수·상태·차단·이력은 바꾸지 않는다(적용 전후를 비교해 달라지면 rollback).
- `registration_effective_from`은 NULL로 둔다. 이관 이전 Window의 등록 판정은 그대로이고
  그 Window의 정책은 추정하지 않고 `POLICY_UNAVAILABLE`로 남긴다.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from edge.policy.device_policy import (
    STATE_ACTIVE,
    BackfillBlockedError,
    DevicePolicy,
    DevicePolicyError,
    DevicePolicyValidationError,
    IpRegistrationPolicy,
    format_utc_seconds,
    parse_effective_from,
    require_aware,
    utc_now,
    validate_actor,
    validate_device_id,
    validate_device_type,
    validate_mqtt_principal,
    validate_policy,
    validate_reason,
    validate_registration_ip,
)
from edge.policy.device_policy_repository import (
    Clock,
    _insert_revision,
    write_transaction,
)


# 이관 전후로 값이 달라지면 안 되는 자료. 없는 테이블은 건너뛴다(최소 schema 테스트 DB 허용).
_PROTECTED_TABLES = (
    "trust_score_history",
    "isolation_history",
    "firewall_rules",
    "firewall_release_requests",
    "detection_events",
)


@dataclass(frozen=True)
class LegacyDeviceOverride:
    """기존 기기 하나의 확인된 운영값."""

    device_id: str
    device_type: str
    policy: DevicePolicy
    #: 운영값의 출처(baseline manifest 식별자 등). 감사 이력의 작성자에 남는다.
    source: str
    #: 확인되지 않았으면 None으로 두고 NULL로 저장한다.
    mqtt_principal: str | None = None


@dataclass(frozen=True)
class BackfillPlan:
    to_create: tuple[str, ...]
    already_revised: tuple[str, ...]
    problems: tuple[str, ...]


@dataclass(frozen=True)
class BackfillResult:
    created: tuple[str, ...]
    already_revised: tuple[str, ...]


def parse_override(raw: Mapping[str, Any]) -> LegacyDeviceOverride:
    """manifest의 기기 항목을 strict하게 읽는다."""
    if not isinstance(raw, Mapping):
        raise DevicePolicyValidationError("device override must be an object")
    required = {"device_id", "device_type", "policy", "source"}
    allowed = required | {"mqtt_principal"}
    unknown = sorted(str(key) for key in raw if key not in allowed)
    if unknown:
        raise DevicePolicyValidationError(f"unsupported override fields: {unknown}")
    missing = sorted(required - set(raw))
    if missing:
        raise DevicePolicyValidationError(f"missing override fields: {missing}")
    principal = raw.get("mqtt_principal")
    return LegacyDeviceOverride(
        device_id=validate_device_id(raw["device_id"]),
        device_type=validate_device_type(raw["device_type"]),
        policy=validate_policy(raw["policy"]),
        source=validate_actor(raw["source"], "source"),
        mqtt_principal=None if principal is None else validate_mqtt_principal(principal),
    )


def _revalidated(overrides: Mapping[str, LegacyDeviceOverride]) -> dict[str, LegacyDeviceOverride]:
    """직접 만든 override 객체도 manifest와 같은 규칙으로 다시 검증한다."""
    if not isinstance(overrides, Mapping):
        raise DevicePolicyValidationError("overrides must be a mapping of device_id to override")
    checked: dict[str, LegacyDeviceOverride] = {}
    for key, value in overrides.items():
        if not isinstance(value, LegacyDeviceOverride):
            raise DevicePolicyValidationError("overrides must be LegacyDeviceOverride objects")
        raw: dict[str, Any] = {
            "device_id": value.device_id,
            "device_type": value.device_type,
            "policy": value.policy,
            "source": value.source,
        }
        if value.mqtt_principal is not None:
            raw["mqtt_principal"] = value.mqtt_principal
        parsed = parse_override(raw)
        if key != parsed.device_id:
            raise DevicePolicyValidationError(
                f"override key {key!r} does not match its device_id {parsed.device_id!r}"
            )
        checked[key] = parsed
    return checked


def _plan_locked(
    connection: sqlite3.Connection,
    overrides: Mapping[str, LegacyDeviceOverride],
    ip_policy: IpRegistrationPolicy,
) -> BackfillPlan:
    rows = connection.execute(
        """
        SELECT d.device_id, d.ip_address, d.device_type, d.mqtt_principal,
               EXISTS (SELECT 1 FROM device_policy_revisions r WHERE r.device_id = d.device_id)
        FROM devices d
        ORDER BY d.device_id
        """
    ).fetchall()

    to_create: list[str] = []
    already: list[str] = []
    problems: list[str] = []
    known = {str(row[0]) for row in rows}

    for device_id in sorted(set(overrides) - known):
        problems.append(f"UNKNOWN_OVERRIDE:{device_id}: no such device in the database")

    for device_id, ip_address, device_type, principal, has_revision in rows:
        if has_revision:
            already.append(device_id)
            continue
        override = overrides.get(device_id)
        if override is None:
            problems.append(
                f"MISSING_OVERRIDE:{device_id}: confirmed operating values are required"
            )
            continue
        if ip_address is None or ip_address == "":
            problems.append(f"IP_MISSING:{device_id}: device has no IP address")
        else:
            try:
                validate_registration_ip(ip_address, ip_policy)
            except DevicePolicyValidationError as exc:
                problems.append(f"IP_INVALID:{device_id}: {exc.message}")
        if device_type is not None and device_type != override.device_type:
            problems.append(
                f"METADATA_MISMATCH:{device_id}: device_type is {device_type!r}, "
                f"override says {override.device_type!r}"
            )
        if (
            principal is not None
            and override.mqtt_principal is not None
            and principal != override.mqtt_principal
        ):
            problems.append(
                f"METADATA_MISMATCH:{device_id}: mqtt_principal differs from the override"
            )
        to_create.append(device_id)

    return BackfillPlan(
        to_create=tuple(to_create),
        already_revised=tuple(already),
        problems=tuple(problems),
    )


def plan_legacy_backfill(
    connection: sqlite3.Connection,
    overrides: Mapping[str, LegacyDeviceOverride],
    *,
    ip_policy: IpRegistrationPolicy,
) -> BackfillPlan:
    """dry-run. 아무것도 쓰지 않고 무엇이 만들어지고 무엇이 막히는지 보여준다."""
    return _plan_locked(connection, _revalidated(overrides), ip_policy)


def _fingerprint(connection: sqlite3.Connection) -> dict[str, Any]:
    devices = [
        tuple(row)
        for row in connection.execute(
            "SELECT device_id, ip_address, status, trust_score, last_seen_at, created_at "
            "FROM devices ORDER BY device_id"
        ).fetchall()
    ]
    existing = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    tables: dict[str, tuple[int, Any]] = {}
    for table in _PROTECTED_TABLES:
        if table in existing:
            count, max_id = connection.execute(
                f"SELECT count(*), max(id) FROM {table}"
            ).fetchone()
            tables[table] = (int(count), max_id)
    return {"devices": devices, "tables": tables}


def apply_legacy_backfill(
    connection: sqlite3.Connection,
    overrides: Mapping[str, LegacyDeviceOverride],
    *,
    effective_from: datetime,
    ip_policy: IpRegistrationPolicy,
    reason: str,
    clock: Clock = utc_now,
) -> BackfillResult:
    """revision이 없는 모든 기존 기기에 ACTIVE 초기 revision을 만든다(한 트랜잭션).

    `effective_from`은 운영자가 확인한 이관 효력 시점(UTC, 10초 경계)이다. 과거 시점도
    허용한다(이미 운영 중이던 정책이므로). 서버 API의 "과거 효력 시점 금지" 규칙은 이 경로에
    적용되지 않는다.
    """
    reason_text = validate_reason(reason)
    effective = parse_effective_from(
        format_utc_seconds(require_aware(effective_from, "effective_from"))
    )
    overrides = _revalidated(overrides)

    with write_transaction(connection):
        now = require_aware(clock(), "clock()")
        plan = _plan_locked(connection, overrides, ip_policy)
        if plan.problems:
            raise BackfillBlockedError(
                f"Backfill blocked by {len(plan.problems)} problem(s); nothing was changed",
                problems=plan.problems,
            )

        before = _fingerprint(connection)
        for device_id in plan.to_create:
            override = overrides[device_id]
            connection.execute(
                """
                UPDATE devices
                SET device_type = COALESCE(device_type, ?),
                    mqtt_principal = COALESCE(mqtt_principal, ?)
                WHERE device_id = ?
                """,
                (override.device_type, override.mqtt_principal, device_id),
            )
            _insert_revision(
                connection,
                device_id=device_id,
                revision=1,
                effective_from=effective,
                registration_state=STATE_ACTIVE,
                policy=override.policy,
                created_at=now,
                created_by=f"backfill:{override.source}"[:128],
                reason=reason_text,
            )
        if _fingerprint(connection) != before:
            raise DevicePolicyError(
                "Backfill changed trust, firewall or history data; rolled back"
            )

    return BackfillResult(created=plan.to_create, already_revised=plan.already_revised)
