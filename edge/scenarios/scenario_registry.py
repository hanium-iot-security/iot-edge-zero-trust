"""Scenario Registry."""

from __future__ import annotations

from dataclasses import dataclass, field

from edge.phase5.contracts import EvaluationScope

# 대표 시나리오 3계열 (시나리오 우선순위 > 공식 반복 E2E 3계열)
SERIES_MQTT_ABNORMAL_PUBLISH = "MQTT_ABNORMAL_PUBLISH"
SERIES_IDENTITY_MESSAGE_POLICY = "IDENTITY_MESSAGE_POLICY"
SERIES_PACKET_ANOMALY = "PACKET_ANOMALY"

ALL_SERIES = (
    SERIES_MQTT_ABNORMAL_PUBLISH,
    SERIES_IDENTITY_MESSAGE_POLICY,
    SERIES_PACKET_ANOMALY,
)


@dataclass(frozen=True)
class ScenarioDefinition:
    """단일 시나리오 명세.

    ``module``은 ``python -m <module>`` 형태로 실행할 attacks/ 스크립트다.
    ``default_args``의 key는 해당 스크립트 argparse 옵션 이름(언더스코어 표기, 예: ``device_id``)과 정확히 같아야 한다.
    """
    scenario_id: str
    series: str
    scenario_version: str
    description: str
    module: str
    default_args: dict[str, str] = field(default_factory=dict)

    # 입력 계약
    evaluation_scope: str = EvaluationScope.FULL_E2E.value
    duration_seconds: float = 0.0
    intensity: str = "medium"
    requires_target_device_id: bool = False
    requires_target_source_ip: bool = False

    # 반복 실행 기준
    min_functional_runs: int = 3
    target_baseline_runs: int = 10
    detection_expected: bool = True
    expected_event_types: tuple[str, ...] = ()
    expected_incident_families: tuple[str, ...] = ()  # 문서화 전용
    expected_severity: str = "medium"  # 문서화 전용
    trust_change_expected: bool = True
    expected_score_delta_range: tuple[int, int] = (-100, -1)  # 문서화 전용
    isolation_expected: bool = False  # 문서화 전용 (trust/firewall/block_expected가 실제 반영값)
    firewall_rule_expected: bool = False
    block_expected: bool = False
    evidence_fields: tuple[str, ...] = ()  # 문서화 전용

    # Packet 계열 여부 (실기기 필요 + Packet Rule Gate 대상)
    requires_hardware: bool = False  # 문서화 전용 (requires_packet_rule_gate가 실제 Gate 체크에 쓰임)
    requires_packet_rule_gate: bool = False

    # "생성 메시지·패킷 수 또는 실행량" 계산 방법
    #   "count_arg": default_args[volume_arg_name]을 그대로 실행량으로 사용
    #   "duration_x_rate": duration_seconds * rate_pps 를 실행량으로 사용
    #   "port_range": end_port - start_port + 1 을 실행량으로 사용
    volume_strategy: str = "count_arg"
    volume_arg_name: str = "count"
    volume_unit: str = "messages"


SCENARIOS: dict[str, ScenarioDefinition] = {}


def register(defn: ScenarioDefinition) -> ScenarioDefinition:
    if defn.scenario_id in SCENARIOS:
        raise ValueError(f"scenario_id 중복 등록: {defn.scenario_id!r}")
    SCENARIOS[defn.scenario_id] = defn
    return defn


def get_scenario(scenario_id: str) -> ScenarioDefinition:
    try:
        return SCENARIOS[scenario_id]
    except KeyError as exc:
        raise KeyError(
            f"등록되지 않은 scenario_id={scenario_id!r}. 사용 가능: {sorted(SCENARIOS)}"
        ) from exc


def scenarios_by_series(series: str) -> list[ScenarioDefinition]:
    return [s for s in SCENARIOS.values() if s.series == series]


# 계열별 정의 모듈을 import해 Registry에 등록시킨다. (하단 import: 순환 참조 방지)
from edge.scenarios import mqtt_scenarios as _mqtt_scenarios  # noqa: F401
from edge.scenarios import packet_scenarios as _packet_scenarios  # noqa: F401
from edge.scenarios import policy_scenarios as _policy_scenarios  # noqa: F401