"""공식 반복 E2E 3계열 — 1. 등록 기기 MQTT 비정상 Publish (Flooding).

MQTT Rule을 주 탐지로 사용하고, Trust 하락·Firewall 적용·기존 연결 Publish 실패·신규 연결 실패까지 FULL_E2E로 검증한다.
"""

from __future__ import annotations

from edge.detection.rule_detector import ABNORMAL_PUBLISH_RATE
from edge.phase5.contracts import EvaluationScope
from edge.scenarios.scenario_registry import (
    SERIES_MQTT_ABNORMAL_PUBLISH,
    ScenarioDefinition,
    register,
)

register(
    ScenarioDefinition(
        scenario_id="mqtt_abnormal_publish_rate",
        series=SERIES_MQTT_ABNORMAL_PUBLISH,
        scenario_version="v1",
        description="등록 기기의 비정상 Publish 패턴(Flooding)을 반복 재현한다.",
        module="attacks.flooding_attack",
        default_args={"count": "30", "interval": "0.2"},
        evaluation_scope=EvaluationScope.FULL_E2E.value,
        duration_seconds=30 * 0.2,
        intensity="high",
        requires_target_device_id=True,
        target_baseline_runs=10,
        expected_event_types=(ABNORMAL_PUBLISH_RATE,),
        expected_incident_families=("FLOODING",),
        expected_severity="high",
        expected_score_delta_range=(-20, -20),
        isolation_expected=True,
        firewall_rule_expected=True,
        block_expected=True,
        evidence_fields=("publish_count", "min_message_interval"),
        volume_strategy="count_arg",
        volume_arg_name="count",
        volume_unit="messages",
    )
)