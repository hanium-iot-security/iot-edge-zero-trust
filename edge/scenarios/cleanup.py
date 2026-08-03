"""실행 전 Baseline 확인 / 실행 후 Cleanup 훅.

  - Baseline: Device ``active`` 상태, 시작 Trust Score, 활성 Firewall/
    iptables Rule 없음, 정상 MQTT 연결 가능 상태를 확인한다.
  - Cleanup: 공격 Process·MQTT Client·Firewall Rule·iptables를 정리하고
    다음 Run 실행 가능 상태를 확인한다. 실패하면 새 Run을 시작하지 않고
    RESET_FAILED로 기록한다 (Scenario Runner가 처리).

DB·iptables 접근은 Raspberry Pi에서만 완전하게 수행할 수 있으므로, 여기서는
Protocol과 안전한 기본값(no-op=항상 성공)만 제공한다. Pi #2에서 실제 구현을 연결한다.
"""

from __future__ import annotations

from typing import Protocol


class BaselineCheck(Protocol):
    """실행 전 Baseline 확인.

    Device ``active`` 상태, 시작 Trust Score, 활성 Firewall·iptables Rule
    없음, 정상 MQTT 연결 가능 상태를 확인하고 실패 시 ``(False, 사유)``를 반환한다.
    """

    def __call__(self) -> tuple[bool, str | None]: ...


class CleanupHook(Protocol):
    """실행 후 Cleanup.

    공격 Process·MQTT Client 종료, Firewall Rule·iptables 정리, Device·Trust 상태 복구를 수행하고 성공 여부를 반환한다.
    """

    def __call__(self) -> tuple[bool, str | None]: ...


def default_baseline_check() -> tuple[bool, str | None]:
    """로컬 개발/Dry-run 기본값 — 항상 통과. Pi에서는 반드시 교체해야 한다."""
    return True, None


def default_cleanup_hook() -> tuple[bool, str | None]:
    """로컬 개발/Dry-run 기본값 — 항상 통과. Pi에서는 반드시 교체해야 한다."""
    return True, None


# --- Pi #2에서 연결할 훅의 예시 뼈대 ---
#
# def pi_baseline_check() -> tuple[bool, str | None]:
#     # TODO: devices.status == 'active' 확인
#     # TODO: 시작 Trust Score 기록
#     # TODO: 활성 firewall_rules / iptables Rule 없음 확인
#     # TODO: 정상 MQTT 연결·Publish 가능 확인
#     return True, None
#
#
# def pi_cleanup_hook() -> tuple[bool, str | None]:
#     # TODO: 공격 MQTT Client / 스캔 Process 종료
#     # TODO: firewall_rules DB Row 정리
#     # TODO: 실제 iptables Rule 제거
#     # TODO: Device·Trust 상태 복구 결과 기록
#     return True, None