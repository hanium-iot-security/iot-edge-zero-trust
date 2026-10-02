"""Window 시점의 등록 집합과 기기 정책 조회 (device-policy-v1 4절 resolver 인터페이스).

항상 호출자가 넘긴 `window_start_utc`에 유효했던 값을 반환하며 처리 시각·현재 설정으로 과거를
다시 해석하지 않는다. 감점·차단 자격 판단은 하지 않는다(Trust의 책임). 트랜잭션은 호출자가
소유하고 이 모듈은 commit하지 않는다.

`window_start_utc`는 timezone-aware datetime 또는 DB 시각 문자열이며, naive 값은 기존
Phase 4 계약(`parse_db_utc`)과 같이 UTC로 해석한다.
"""

from __future__ import annotations

import ipaddress
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from edge.detection.phase4_time import parse_db_utc
from edge.policy.device_policy import DevicePolicy, format_utc_seconds
from edge.policy.device_policy_repository import get_revision_effective_at


RESOLUTION_OK = "OK"
RESOLUTION_NOT_REGISTERED = "NOT_REGISTERED"
RESOLUTION_POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"

REASON_NOT_REGISTERED = "DEVICE_NOT_REGISTERED_AT_WINDOW"
REASON_NO_REVISION = "NO_POLICY_REVISION"
REASON_NO_EFFECTIVE_REVISION = "NO_EFFECTIVE_REVISION_AT_WINDOW"


@dataclass(frozen=True)
class DevicePolicyResolution:
    resolution: str
    device_id: str
    device_policy_revision: int | None
    effective_from: str | None
    registration_state: str | None
    policy: DevicePolicy | None
    reason: str | None


def _to_utc(window_start_utc: datetime | str) -> datetime:
    return parse_db_utc(window_start_utc, "window_start_utc")


def _registration_effective_from(
    connection: sqlite3.Connection, device_id: str
) -> tuple[bool, str | None]:
    row = connection.execute(
        "SELECT registration_effective_from FROM devices WHERE device_id = ?",
        (device_id,),
    ).fetchone()
    if row is None:
        return False, None
    return True, row[0]


def _registered_at(effective_from: str | None, at_text: str) -> bool:
    # NULL은 정책 도입 전부터 있던 기존 기기다. 기존 Identity 판정과 같이 항상 등록된 것으로 본다.
    return effective_from is None or effective_from <= at_text


def registered_device_ids_at(
    connection: sqlite3.Connection, window_start_utc: datetime | str
) -> set[str]:
    """`window_start_utc`에 이미 등록 효력이 있던 Device ID 집합."""
    at_text = format_utc_seconds(_to_utc(window_start_utc))
    rows = connection.execute(
        """
        SELECT device_id FROM devices
        WHERE registration_effective_from IS NULL OR registration_effective_from <= ?
        """,
        (at_text,),
    ).fetchall()
    return {str(row[0]) for row in rows}


def registered_device_by_ip_at(
    connection: sqlite3.Connection, source_ip: Any, window_start_utc: datetime | str
) -> str | None:
    """`source_ip`를 가진 기기가 그 시점에 등록돼 있었다면 Device ID, 아니면 None.

    등록 효력 이전 Window를 새 기기에 소급 귀속하지 않는다. 형식이 올바르지 않은 IP는 None이다.
    """
    try:
        canonical = str(ipaddress.IPv4Address(source_ip))
    except (ipaddress.AddressValueError, ValueError):
        return None
    row = connection.execute(
        "SELECT device_id, registration_effective_from FROM devices WHERE ip_address = ?",
        (canonical,),
    ).fetchone()
    if row is None:
        return None
    at_text = format_utc_seconds(_to_utc(window_start_utc))
    return str(row[0]) if _registered_at(row[1], at_text) else None


def resolve_device_policy(
    connection: sqlite3.Connection, device_id: str, window_start_utc: datetime | str
) -> DevicePolicyResolution:
    """`window_start_utc`에 유효했던 기기 정책을 조회한다.

    - 미등록이거나 등록 효력 전: `NOT_REGISTERED`
    - 등록돼 있지만 그 시점의 revision이 없거나 모순: `POLICY_UNAVAILABLE` (기본값으로 보정하지 않는다)
    - 그 외: `OK`와 당시 revision·등록 상태·불변 정책 스냅샷
    """
    window_start = _to_utc(window_start_utc)
    at_text = format_utc_seconds(window_start)

    exists, effective_from = _registration_effective_from(connection, device_id)
    if not exists or not _registered_at(effective_from, at_text):
        return DevicePolicyResolution(
            resolution=RESOLUTION_NOT_REGISTERED,
            device_id=device_id,
            device_policy_revision=None,
            effective_from=None,
            registration_state=None,
            policy=None,
            reason=REASON_NOT_REGISTERED,
        )

    revision = get_revision_effective_at(connection, device_id, window_start)
    if revision is None:
        any_revision = connection.execute(
            "SELECT 1 FROM device_policy_revisions WHERE device_id = ? LIMIT 1",
            (device_id,),
        ).fetchone()
        return DevicePolicyResolution(
            resolution=RESOLUTION_POLICY_UNAVAILABLE,
            device_id=device_id,
            device_policy_revision=None,
            effective_from=None,
            registration_state=None,
            policy=None,
            reason=REASON_NO_EFFECTIVE_REVISION if any_revision else REASON_NO_REVISION,
        )

    return DevicePolicyResolution(
        resolution=RESOLUTION_OK,
        device_id=device_id,
        device_policy_revision=revision.revision,
        effective_from=revision.effective_from,
        registration_state=revision.registration_state,
        policy=revision.policy,
        reason=None,
    )
