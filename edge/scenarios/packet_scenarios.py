"""공식 반복 E2E 3계열 — 3. 등록 기기 Packet 이상 행위 + 보조 Detection 시나리오.

  - 대표(FULL_E2E): Packet Rate 이상. Packet Rule·Packet IF·Trust·Firewall·실제 TCP 1883 차단까지 검증한다.
  - 보조(DETECTION_ONLY): Byte Rate 단독, Port Scan, Broker DoS Packet Rule 검증.

  - Packet Rule Stage가 Detection Orchestrator에 등록되고 Required Stage·Checkpoint·Trust Barrier 계약에 포함되는지 확인
  - 4종 Packet Rule Event가 detection_events에 저장되는 Physical Smoke 결과를 확인
  - 위 조건이 완료되지 않은 경우 Packet Rate·Byte Rate·Port Scan·Broker DoS 검증은 HOLD로 기록하고, MQTT·정책 위반 Scenario Runner와 Cleanup 작업은 병렬로 계속 진행한다.

이 Gate 확인은 DB/Orchestrator 상태를 실제로 조회해야 하므로 Raspberry Pi 쪽에서 최종 확정한다. 이 모듈은 그 결과를 코드에 반영할 수 있는 단일 지점(``is_packet_rule_gate_confirmed``)만 제공하며, 안전 기본값은 **미확인
(False → HOLD)** 이다.

.. note:: FULL_E2E 격리 도달 가능성 (미해결 — 실측 필요)
   packet_rate_flood(duration=12초)는 Capture Window(10초) 기준 최대 2개 Window에서만
   감점이 발생할 수 있어, 현재 Trust 격리 임계값(30점 미만)까지 도달하는지는 실측으로
   확인해야 한다. 이 카드에서는 duration을 임의로 늘리지 않았다 — Threshold·Trust 정책
   변경은 Phase 5 제외 범위(Threshold 최종 확정은 Phase 6)이며, 실측 없이 duration만
   늘리면 Packet Capture·평가 계약의 다른 가정(예: Window 수 기반 채점 로직)이 깨질 수
   있다. FULL_E2E 유지 여부는 담당자가 실측 후 별도로 판단해야 한다.
"""

from __future__ import annotations

import os

from edge.phase5.contracts import EvaluationScope
from edge.scenarios.scenario_registry import (
    SERIES_PACKET_ANOMALY,
    ScenarioDefinition,
    register,
)
from edge.trust.trust_policy import (
    BROKER_DOS_SUSPECTED,
    BYTE_RATE_ANOMALY,
    PACKET_RATE_ANOMALY,
    PORT_SCAN,
)

PACKET_RULE_GATE_CONFIRMED_DEFAULT = False


def is_packet_rule_gate_confirmed() -> bool:
    env_override = os.environ.get("PHASE5_PACKET_RULE_GATE_CONFIRMED")
    if env_override is not None:
        return env_override.strip().lower() in {"1", "true", "yes", "y"}
    return PACKET_RULE_GATE_CONFIRMED_DEFAULT


# --- 대표 (FULL_E2E) — Packet Rate 이상 ---------------------------------
register(
    ScenarioDefinition(
        scenario_id="packet_rate_flood",
        series=SERIES_PACKET_ANOMALY,
        scenario_version="v1",
        description="packets_per_second > packet_rate_threshold(기본 10.0)를 유발하는 패킷 폭주.",
        module="attacks.packet_rate_flood_attack",
        default_args={"duration": "12", "rate_pps": "80", "payload_bytes": "64"},
        evaluation_scope=EvaluationScope.FULL_E2E.value,
        duration_seconds=12.0,
        intensity="high",
        requires_target_source_ip=True,
        target_device_id_arg_names=(),  # Packet 계열은 target_device_id를 command에 전달하지 않음
        target_host_arg_name="target-host",  # packet_rate_flood_attack.py의 --target-host
        target_baseline_runs=10,
        expected_event_types=(PACKET_RATE_ANOMALY,),
        expected_incident_families=("FLOODING",),
        expected_severity="medium",
        expected_score_delta_range=(-20, -20),
        isolation_expected=True,
        firewall_rule_expected=True,
        block_expected=True,
        evidence_fields=("packets_per_second", "captured_duration_seconds"),
        requires_hardware=True,
        requires_packet_rule_gate=True,
        volume_strategy="duration_x_rate",
        volume_unit="packets",
    )
)

# --- 보조 (DETECTION_ONLY) — Broker DoS -------------------------------
# Extractor의 mqtt_related_packet_count는 MQTT decode가 아니라 TCP src/dst
# port 1883 패킷 수다. 기본 24회 TCP connect/close는 성공한 handshake 기준
# INBOUND SYN 24개와 port-1883 TCP 패킷 48개를 계획해 v3 strict >10 AND >20을
# bounded하게 재현한다. 실제 Packet Feature/Event가 물리 Smoke의 판정 근거다.
register(
    ScenarioDefinition(
        scenario_id="packet_broker_dos",
        series=SERIES_PACKET_ANOMALY,
        scenario_version="v1",
        description=(
            "[보조] MQTT listener에 bounded TCP connect/close를 수행해 "
            "tcp_syn_count > 10 AND mqtt_related_packet_count > 20을 함께 유발한다. "
            "mqtt_related는 MQTT decode가 아니라 TCP port 1883 기준이다."
        ),
        module="attacks.broker_dos_attack",
        default_args={
            "target_port": "1883",
            "count": "24",
            "rate_cps": "8",
            "connect_timeout_ms": "200",
        },
        evaluation_scope=EvaluationScope.DETECTION_ONLY.value,
        duration_seconds=3.0,
        intensity="medium",
        requires_target_source_ip=True,
        target_device_id_arg_names=(),
        target_host_arg_name="target-host",
        min_functional_runs=1,
        target_baseline_runs=3,
        expected_event_types=(BROKER_DOS_SUSPECTED,),
        expected_incident_families=("FLOODING",),
        expected_severity="high",
        trust_change_expected=False,
        expected_score_delta_range=(0, 0),
        isolation_expected=False,
        firewall_rule_expected=False,
        block_expected=False,
        evidence_fields=("tcp_syn_count", "mqtt_related_packet_count"),
        requires_hardware=True,
        requires_packet_rule_gate=True,
        volume_strategy="count_arg",
        volume_arg_name="count",
        volume_unit="connections",
    )
)

# --- 보조 (DETECTION_ONLY) — Byte Rate 단독 조건 -------------------------
# 표준 MTU 1500 기준 IPv4 단편화를 피하도록 UDP payload를 1200 bytes로 제한한다.
# 추정 IPv4 계층 속도는 4pps * (1200 payload + 8 UDP + 20 IPv4) = 4912 B/s로,
# packet rate threshold(10)는 넘지 않고 byte rate threshold(2500)는 여유 있게 넘는다.
register(
    ScenarioDefinition(
        scenario_id="packet_byte_rate_flood",
        series=SERIES_PACKET_ANOMALY,
        scenario_version="v2",
        description="[보조: Byte Rate 단독 조건] IPv4 단편화 없이 packets_per_second는 threshold 미만으로 유지하면서 bytes_per_second만 threshold(기본 2500.0)를 초과시킨다.",
        module="attacks.packet_rate_flood_attack",
        default_args={"duration": "12", "rate_pps": "4", "payload_bytes": "1200"},
        evaluation_scope=EvaluationScope.DETECTION_ONLY.value,
        duration_seconds=12.0,
        intensity="medium",
        requires_target_source_ip=True,
        target_device_id_arg_names=(),  # Packet 계열은 target_device_id를 command에 전달하지 않음
        target_host_arg_name="target-host",  # packet_rate_flood_attack.py의 --target-host
        min_functional_runs=1,  # 하위 항목별 기능 검증 1회 이상
        target_baseline_runs=3,
        expected_event_types=(BYTE_RATE_ANOMALY,),
        expected_incident_families=("FLOODING",),
        expected_severity="medium",
        expected_score_delta_range=(-20, -20),
        isolation_expected=False,
        firewall_rule_expected=False,
        block_expected=False,
        evidence_fields=("bytes_per_second", "total_bytes"),
        requires_hardware=True,
        requires_packet_rule_gate=True,
        volume_strategy="duration_x_rate",
        volume_unit="packets",
    )
)

# --- 보조 (DETECTION_ONLY) — Port Scan -----------------------------------
register(
    ScenarioDefinition(
        scenario_id="packet_port_scan",
        series=SERIES_PACKET_ANOMALY,
        scenario_version="v1",
        description=(
            "[보조] distinct_port_count > port_scan_distinct_port_threshold(기본 5) "
            "그리고(AND) syn_count > port_scan_syn_threshold(기본 5)를 함께 유발하는 "
            "TCP Connect Scan. 실제 판정 조건은 OR가 아니라 AND다."
            "스캔 자체는 격리 대상이 아니라 탐지 검증이 목적."
        ),
        module="attacks.port_scan_attack",
        default_args={"start_port": "1", "end_port": "256", "timeout_ms": "150"},
        evaluation_scope=EvaluationScope.DETECTION_ONLY.value,
        duration_seconds=0.0,  # port 수에 따라 가변 — volume_strategy로 별도 계산
        intensity="medium",
        requires_target_source_ip=True,
        target_device_id_arg_names=(),  # Packet 계열은 target_device_id를 command에 전달하지 않음
        target_host_arg_name="target",  # port_scan_attack.py는 --target-host가 아니라 --target을 씀
        min_functional_runs=1,  # 하위 항목별 기능 검증 1회 이상
        target_baseline_runs=3,  # 다른 보조 시나리오와 동일 기준 (대표 항목만 10회 목표)
        expected_event_types=(PORT_SCAN,),
        expected_incident_families=("SCAN",),
        expected_severity="high",
        expected_score_delta_range=(-20, -20),
        isolation_expected=False,
        firewall_rule_expected=False,
        block_expected=False,
        evidence_fields=("distinct_dest_port_count", "tcp_syn_count"),
        requires_hardware=True,
        requires_packet_rule_gate=True,
        volume_strategy="port_range",
        volume_unit="ports",
    )
)
