"""edge/scenarios/scenario_registry.py 및 계열별 정의 테스트."""

from __future__ import annotations

import pytest

from edge.detection.rule_detector import RULE_EVENT_TYPES
from edge.phase5.contracts import EvaluationScope
from edge.scenarios.scenario_registry import (
    SCENARIOS,
    SERIES_IDENTITY_MESSAGE_POLICY,
    SERIES_MQTT_ABNORMAL_PUBLISH,
    SERIES_PACKET_ANOMALY,
    ScenarioDefinition,
    get_scenario,
    register,
    scenarios_by_series,
)
from edge.trust.trust_policy import (
    BROKER_DOS_SUSPECTED,
    BYTE_RATE_ANOMALY,
    PACKET_RATE_ANOMALY,
    PORT_SCAN,
)

_KNOWN_EVENT_TYPES = RULE_EVENT_TYPES | {
    PACKET_RATE_ANOMALY,
    BYTE_RATE_ANOMALY,
    PORT_SCAN,
    BROKER_DOS_SUSPECTED,
}


def test_three_official_series_are_present():
    series = {defn.series for defn in SCENARIOS.values()}
    assert series == {
        SERIES_MQTT_ABNORMAL_PUBLISH,
        SERIES_IDENTITY_MESSAGE_POLICY,
        SERIES_PACKET_ANOMALY,
    }


def test_each_series_has_exactly_one_full_e2e_representative():
    """각 계열은 "대표 시나리오"(FULL_E2E) 1개를 선정한다."""
    for series in (
        SERIES_MQTT_ABNORMAL_PUBLISH,
        SERIES_IDENTITY_MESSAGE_POLICY,
        SERIES_PACKET_ANOMALY,
    ):
        full_e2e = [
            s
            for s in scenarios_by_series(series)
            if s.evaluation_scope == EvaluationScope.FULL_E2E.value
        ]
        assert len(full_e2e) == 1, f"{series}: FULL_E2E 대표가 {len(full_e2e)}개입니다."


def test_expected_event_types_are_known_detector_constants():
    for defn in SCENARIOS.values():
        for event_type in defn.expected_event_types:
            assert event_type in _KNOWN_EVENT_TYPES, (
                f"{defn.scenario_id}의 event_type={event_type!r}가 "
                "edge/detection·edge/trust의 실제 상수와 다릅니다 (신규 Event "
                "Type 추가 금지)."
            )


def test_packet_scenarios_require_packet_rule_gate():
    for defn in scenarios_by_series(SERIES_PACKET_ANOMALY):
        assert defn.requires_packet_rule_gate is True
        assert defn.requires_hardware is True


def test_get_scenario_unknown_id_raises():
    with pytest.raises(KeyError):
        get_scenario("does_not_exist")


def test_register_rejects_duplicate_scenario_id():
    dummy = ScenarioDefinition(
        scenario_id="mqtt_abnormal_publish_rate",  # 이미 등록된 ID
        series=SERIES_MQTT_ABNORMAL_PUBLISH,
        scenario_version="v1",
        description="dup",
        module="attacks.flooding_attack",
    )
    with pytest.raises(ValueError):
        register(dummy)


def test_min_functional_runs_matches_representative_vs_auxiliary_rule():
    """대표 항목은 최소 3회, 하위(보조) 항목은 최소 1회 이상."""
    for defn in SCENARIOS.values():
        is_representative = defn.evaluation_scope == EvaluationScope.FULL_E2E.value
        if is_representative:
            assert defn.min_functional_runs >= 3, (
                f"{defn.scenario_id}: 대표 시나리오인데 min_functional_runs="
                f"{defn.min_functional_runs} (최소 3 필요)"
            )
        else:
            assert defn.min_functional_runs >= 1, (
                f"{defn.scenario_id}: min_functional_runs는 최소 1 이상이어야 합니다."
            )
