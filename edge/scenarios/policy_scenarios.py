"""공식 반복 E2E 3계열 — 2. 식별·메시지 정책 위반 + 보조 Detection 시나리오.

미등록 기기 또는 Device ID 불일치 중 대표 시나리오를 선정하고, 시나리오 계약의 기대 결과에 따라 정책 Event·Trust 반영 또는 DETECTION_ONLY로 검증한다.

  - 대표(FULL_E2E): ``mqtt_device_id_mismatch`` — 등록 기기이므로 Trust 반영·Firewall 적용·실제 차단까지 끝까지 검증 가능해 대표로 선정했다.
  - ``mqtt_unknown_device``는 미등록 기기라 Trust Score가 적용되지 않으므로 DETECTION_ONLY로 둔다.
  - 보조 Detection 시나리오: 비정상 Topic, 잘못된 Payload는 DETECTION_ONLY로 검증하고 공식 반복 FULL_E2E 목표 10회를 요구하지 않는다.

.. note:: device_id_mismatch_attack.py는 ``--topic-device-id``/``--payload-device-id``를
   지정하지 않으면 REGISTERED_DEVICES의 앞 두 값을 결정적으로 사용한다.
   Manifest의 대상 Device와 실제 감점 대상이 어긋나지 않도록, 반복 실행 시 항상 같은
   기기 쌍이 검증 대상이 된다.
"""

from __future__ import annotations

from edge.detection.rule_detector import (
    ABNORMAL_TOPIC,
    DEVICE_ID_MISMATCH,
    LARGE_PAYLOAD,
    MALFORMED_PAYLOAD,
    UNKNOWN_DEVICE,
)
from edge.phase5.contracts import EvaluationScope
from edge.scenarios.scenario_registry import (
    SERIES_IDENTITY_MESSAGE_POLICY,
    ScenarioDefinition,
    register,
)

# --- 대표 (FULL_E2E) ---------------------------------------------------
register(
    ScenarioDefinition(
        scenario_id="mqtt_device_id_mismatch",
        series=SERIES_IDENTITY_MESSAGE_POLICY,
        scenario_version="v1",
        description="정상 Topic으로 접속하되 Payload의 device_id를 다른 등록 기기로 위조한다.",
        module="attacks.device_id_mismatch_attack",
        default_args={"count": "4", "interval": "2.0"},
        evaluation_scope=EvaluationScope.FULL_E2E.value,
        duration_seconds=4 * 2.0,
        intensity="medium",
        requires_target_device_id=True,
        target_device_id_arg_names=("topic-device-id",),
        secondary_device_id_arg_name="payload-device-id",
        min_functional_runs=3,  # 대표 항목 최소 3회
        target_baseline_runs=10,
        expected_event_types=(DEVICE_ID_MISMATCH,),
        expected_incident_families=("IDENTITY",),
        expected_severity="high",
        expected_score_delta_range=(-25, -25),
        isolation_expected=True,
        firewall_rule_expected=True,
        block_expected=True,
        evidence_fields=("topic_device_id", "payload_device_id"),
    )
)

# --- 보조 (DETECTION_ONLY) ---------------------------------------------
register(
    ScenarioDefinition(
        scenario_id="mqtt_unknown_device",
        series=SERIES_IDENTITY_MESSAGE_POLICY,
        scenario_version="v1",
        description="미등록 기기가 정상 Topic으로 Publish한다. 미등록 기기는 Trust Score를 적용하지 않는다.",
        module="attacks.unknown_device_attack",
        default_args={"count": "4", "interval": "2.0"},
        evaluation_scope=EvaluationScope.DETECTION_ONLY.value,
        duration_seconds=4 * 2.0,
        intensity="low",
        requires_target_device_id=False,
        min_functional_runs=1,
        target_baseline_runs=3,
        expected_event_types=(UNKNOWN_DEVICE,),
        expected_incident_families=("IDENTITY",),
        expected_severity="high",
        trust_change_expected=False,
        expected_score_delta_range=(0, 0),
        isolation_expected=False,
        firewall_rule_expected=False,
        block_expected=False,
        evidence_fields=("device_id", "topic"),
    )
)
register(
    ScenarioDefinition(
        scenario_id="mqtt_abnormal_topic",
        series=SERIES_IDENTITY_MESSAGE_POLICY,
        scenario_version="v1",
        description="[보조] Zero Trust 정책에 어긋나는 비정상 Topic으로 Publish한다.",
        module="attacks.abnormal_topic_attack",
        default_args={"count": "5", "interval": "1.5"},
        evaluation_scope=EvaluationScope.DETECTION_ONLY.value,
        duration_seconds=5 * 1.5,
        intensity="low",
        requires_target_device_id=True,
        min_functional_runs=1,
        target_baseline_runs=3,
        expected_event_types=(ABNORMAL_TOPIC,),
        expected_incident_families=("MESSAGE_POLICY",),
        expected_severity="high",
        expected_score_delta_range=(-20, -20),
        isolation_expected=False,
        firewall_rule_expected=False,
        block_expected=False,
        evidence_fields=("topic",),
    )
)
register(
    ScenarioDefinition(
        scenario_id="mqtt_malformed_payload",
        series=SERIES_IDENTITY_MESSAGE_POLICY,
        scenario_version="v1",
        description="[보조] JSON 문법 오류 또는 필수 필드가 누락된 Payload를 반복 전송한다.",
        module="attacks.malformed_payload_attack",
        default_args={"count": "5", "interval": "1.5"},
        evaluation_scope=EvaluationScope.DETECTION_ONLY.value,
        duration_seconds=5 * 1.5,
        intensity="low",
        requires_target_device_id=True,
        min_functional_runs=1,
        target_baseline_runs=3,
        expected_event_types=(MALFORMED_PAYLOAD,),
        expected_incident_families=("MESSAGE_POLICY",),
        expected_severity="medium",
        expected_score_delta_range=(-10, -10),
        isolation_expected=False,
        firewall_rule_expected=False,
        block_expected=False,
        evidence_fields=("raw_payload_sample",),
    )
)
register(
    ScenarioDefinition(
        scenario_id="mqtt_large_payload",
        series=SERIES_IDENTITY_MESSAGE_POLICY,
        scenario_version="v1",
        description="[보조/카드 명시 목록 외 추가] 5120 bytes를 초과하는 대형 Payload를 반복 전송한다.",
        module="attacks.large_payload_attack",
        default_args={"count": "3", "interval": "4.5"},
        evaluation_scope=EvaluationScope.DETECTION_ONLY.value,
        duration_seconds=3 * 4.5,
        intensity="low",
        requires_target_device_id=True,
        min_functional_runs=1,
        target_baseline_runs=3,
        expected_event_types=(LARGE_PAYLOAD,),
        expected_incident_families=("MESSAGE_POLICY",),
        expected_severity="medium",
        expected_score_delta_range=(-15, -15),
        isolation_expected=False,
        firewall_rule_expected=False,
        block_expected=False,
        evidence_fields=("payload_size",),
    )
)