"""Window 시점의 기기별 AI 모드 조회 (P9-03).

항상 호출자가 넘긴 `window_start_utc`에 유효했던 Revision을 반환하며 처리 시각·현재 설정으로
과거를 다시 해석하지 않는다(OFF→OBSERVE 전환이 과거 OFF 구간을 되살리지 않는다). 설정이 없거나
그 시점에 효력이 있는 Revision이 없으면 OFF로 보정하지 않고 `AI_POLICY_UNAVAILABLE`로 알린다.
트랜잭션은 호출자가 소유하고 이 모듈은 commit하지 않는다.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from edge.policy.device_ai_policy_repository import (
    get_ai_revision_effective_at,
    get_latest_ai_revision,
)
from edge.policy.device_ai_policy import AiPolicyUnavailableError
from edge.policy.device_policy import DevicePolicyValidationError, require_lookup_id
from edge.policy.device_policy_repository import device_exists
from edge.policy.device_policy_resolver import _to_utc


AI_RESOLUTION_OK = "OK"
AI_RESOLUTION_NOT_REGISTERED = "NOT_REGISTERED"
AI_RESOLUTION_UNAVAILABLE = "AI_POLICY_UNAVAILABLE"

REASON_NO_AI_REVISION = "NO_AI_POLICY_REVISION"
REASON_NO_EFFECTIVE_AI_REVISION = "NO_EFFECTIVE_AI_REVISION_AT_WINDOW"
REASON_AI_POLICY_INVALID = "AI_POLICY_INVALID"


@dataclass(frozen=True)
class AiModeResolution:
    resolution: str
    device_id: str
    ai_policy_revision: int | None
    effective_from: str | None
    mode: str | None
    reason: str | None


def _unavailable(device_id: str, reason: str) -> AiModeResolution:
    return AiModeResolution(AI_RESOLUTION_UNAVAILABLE, device_id, None, None, None, reason)


def resolve_ai_mode(
    connection: sqlite3.Connection, device_id: str, window_start_utc: datetime | str
) -> AiModeResolution:
    """`window_start_utc`에 유효했던 기기 AI 모드를 조회한다.

    - 미등록: `NOT_REGISTERED` (등록 효력 판단은 기기 정책 resolver의 책임이다)
    - 설정 없음·그 시점의 revision 없음·손상: `AI_POLICY_UNAVAILABLE` (모드를 추정하지 않는다)
    - 그 외: `OK`와 당시 revision·모드
    """
    device_id = require_lookup_id(device_id)
    window_start = _to_utc(window_start_utc)
    if not device_exists(connection, device_id):
        return AiModeResolution(
            AI_RESOLUTION_NOT_REGISTERED, device_id, None, None, None, "DEVICE_NOT_REGISTERED"
        )
    try:
        revision = get_ai_revision_effective_at(connection, device_id, window_start)
        if revision is None:
            has_any = get_latest_ai_revision(connection, device_id) is not None
            return _unavailable(
                device_id, REASON_NO_EFFECTIVE_AI_REVISION if has_any else REASON_NO_AI_REVISION
            )
    except (DevicePolicyValidationError, AiPolicyUnavailableError, ValueError, TypeError):
        return _unavailable(device_id, REASON_AI_POLICY_INVALID)
    return AiModeResolution(
        AI_RESOLUTION_OK, device_id, revision.revision, revision.effective_from, revision.mode, None
    )
