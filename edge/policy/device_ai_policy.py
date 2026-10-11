"""기기별 AI 모드 설정의 상수·입력 검증·오류 정의 (P9-03).

DB 접근이 없는 순수 모듈이다. 등록·정책(`device_policy`)과 같은 검증 규칙과 오류 계층을
공유하므로 API는 기존 `DevicePolicyError.code` 매핑을 그대로 쓴다.
"""

from __future__ import annotations

from typing import Any

from edge.policy.device_policy import DevicePolicyError, DevicePolicyValidationError


AI_MODE_OFF = "OFF"
AI_MODE_OBSERVE = "OBSERVE"
# ENFORCE는 Phase 9 범위 밖이라 저장하지 않는다.
AI_MODES = (AI_MODE_OFF, AI_MODE_OBSERVE)

INITIAL_AI_REASON = "default AI mode at device registration"


class AiPolicyUnavailableError(DevicePolicyError):
    """기기의 AI 설정이 없거나 손상됐다(API 503). OFF로 간주하지 않는다."""

    code = "AI_POLICY_UNAVAILABLE"


def validate_ai_mode(value: Any) -> str:
    if type(value) is str and value == "ENFORCE":
        raise DevicePolicyValidationError(
            "mode: ENFORCE is not supported in this phase", field="mode"
        )
    if type(value) is not str or value not in AI_MODES:
        raise DevicePolicyValidationError(f"mode: must be one of {list(AI_MODES)}", field="mode")
    return value
