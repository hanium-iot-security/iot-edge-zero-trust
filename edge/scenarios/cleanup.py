"""실행 전 Baseline 확인 / 실행 후 Cleanup 훅.

  - Baseline: Device ``active`` 상태, 시작 Trust Score, 활성 Firewall/
    iptables Rule 없음, 정상 MQTT 연결 가능 상태를 확인한다.
  - Cleanup: 공격 Process·MQTT Client·Firewall Rule·iptables를 정리하고
    다음 Run 실행 가능 상태를 확인한다. 실패하면 새 Run을 시작하지 않고
    RESET_FAILED로 기록한다 (Scenario Runner가 처리).

DB·iptables 접근은 Raspberry Pi에서만 완전하게 수행할 수 있으므로, 여기서는
Protocol과 안전한 기본값(no-op=항상 성공)만 제공한다. Pi #2에서 실제 구현을 연결한다.

.. important:: Cleanup 구현 시 금지 사항
   실제 Cleanup 훅을 구현할 때 다음 동작은 허용하지 않는다 — 대신 승인된 Firewall
   Release 절차·보상(compensating) 절차를 사용하고 기존 Audit 이력은 보존해야 한다.

   - ``firewall_rules`` 이력 Row를 직접 DELETE하는 것
   - Trust Score를 직접 임의의 값으로 초기화하는 것
   - Device 상태를 직접 임의의 값으로 초기화하는 것

   Trust Score를 되돌려야 하는 경우 ``edge/trust/trust_compensation.py``의
   ``inspect_trust_compensation``/``execute_trust_compensation`` (운영자 승인·
   사유 입력·DB 백업·SHA256·Audit JSON 로그를 갖춘 보상 절차, CLI는
   ``edge/trust/run_trust_compensation.py``)을 사용한다. 이 절차는 사람이 건별로
   ``approved_by``·``reason``·``--confirm``을 입력하도록 설계된 운영자 도구이므로,
   Scenario Runner가 매 반복 실행 뒤 자동으로 호출하는 ``CleanupHook``에 그대로
   결합하지 않는다 — 자동 Cleanup은 "정상 상태로 복귀했는지 확인"까지만 담당하고,
   이미 반영된 Trust Score를 되돌려야 하는 예외 상황은 운영자가 별도로 위 도구를 사용해 처리한다.

   또한 ``default_baseline_check``/``default_cleanup_hook``(no-op)은 Local
   개발·Dry-run 전용이다. ``ScenarioRunner``는 ``allow_execute=True``(CLI
   ``--execute``)로 실공격을 실행하기 전에 이 훅들이 실제 구현으로 교체되었는지
   여부까지는 자동으로 검증하지 않으므로, Pi에서 non-dry-run 실행을 준비할 때는
   반드시 아래 예시 뼈대를 실제 DB/iptables 확인 로직으로 교체한 뒤 전달해야 한다.
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

    구현 시 firewall_rules 이력 삭제, Trust Score/Device 상태 직접 초기화는
    금지한다 (승인된 Release·보상 절차를 사용할 것 — 모듈 docstring 참고).
    """

    def __call__(self) -> tuple[bool, str | None]: ...


def default_baseline_check() -> tuple[bool, str | None]:
    """로컬 개발/Dry-run 기본값 — 항상 통과. Pi에서는 반드시 교체해야 한다.

    non-dry-run 실행에는 ``ScenarioRunner(allow_execute=True)``와 함께
    실제 훅을 명시적으로 전달해야 한다 — 이 no-op 기본값을 그대로 실공격
    실행에 사용하지 않는다.
    """
    return True, None


def default_cleanup_hook() -> tuple[bool, str | None]:
    """로컬 개발/Dry-run 기본값 — 항상 통과. Pi에서는 반드시 교체해야 한다.

    non-dry-run 실행에는 ``ScenarioRunner(allow_execute=True)``와 함께
    실제 훅을 명시적으로 전달해야 한다 — 이 no-op 기본값을 그대로 실공격
    실행에 사용하지 않는다.
    """
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
#     # TODO: firewall_rules DB Row는 DELETE하지 말고, 승인된 Firewall Release
#     #       절차(예: 상태를 REMOVED로 전이)로만 정리한다 (Audit 이력 보존)
#     # TODO: Trust Score를 자동으로 되돌려야 하는 상황이 감지되면, 여기서 직접
#     #       초기화하지 말고 False를 반환해 RESET_FAILED로 기록한 뒤, 운영자가
#     #       edge/trust/trust_compensation.py(execute_trust_compensation) 또는
#     #       edge/trust/run_trust_compensation.py CLI로 승인 절차를 거쳐 처리한다.
#     return True, None