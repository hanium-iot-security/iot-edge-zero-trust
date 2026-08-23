"""tests/test_packet_attacks.py

attacks/packet_rate_flood_attack.py, attacks/port_scan_attack.py 단위 테스트.

기존 tests/test_attacks.py는 MQTT 애플리케이션 계층 공격(flooding, large_payload,
malformed_payload, abnormal_topic, unknown_device, device_id_mismatch) 6종만
다루고, Packet 계층 공격(packet_rate_flood_attack, port_scan_attack) 2종은
테스트가 없었다. Phase 6-B에서 Pi4 Attack/Test Node가 이 두 스크립트로
Scenario P1/P2/P3(세부계획 6.7)를 반복 실행하므로, 최소한 각 스크립트의
`_validate_args`(안전 상한)가 회귀되지 않도록 고정한다.

Mosquitto/네트워크 없이 로컬에서 실행 가능하다 (소켓 전송 자체는 검증하지 않고
`_validate_args`의 경계값 판정만 검증한다).

실행:
    PYTHONPATH=. pytest tests/test_packet_attacks.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from attacks import packet_rate_flood_attack as rate_flood
from attacks import port_scan_attack as port_scan
from attacks.config import BROKER_HOST


def _rate_flood_args(**overrides):
    """packet_rate_flood_attack.parse_args()가 만드는 Namespace와 동일한 필드를
    가진 SimpleNamespace를 만든다. argparse를 거치지 않고 _validate_args만 단위
    테스트하기 위함이다."""
    import argparse

    defaults = dict(
        target_host=BROKER_HOST,
        target_host_legacy=None,
        port=19999,
        duration=12.0,
        rate_pps=80.0,
        payload_bytes=64,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _port_scan_args(**overrides):
    import argparse

    defaults = dict(
        target=BROKER_HOST,
        start_port=port_scan.DEFAULT_START_PORT,
        end_port=port_scan.DEFAULT_END_PORT,
        timeout_ms=port_scan.DEFAULT_TIMEOUT_MS,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ── packet_rate_flood_attack ────────────────────────────────────────────────

class TestPacketRateFloodAttackValidation:
    def test_default_args_pass_validation(self):
        args = _rate_flood_args()
        rate_flood._validate_args(args)  # should not raise

    def test_legacy_target_flag_overrides_target_host(self):
        args = _rate_flood_args(target_host=BROKER_HOST, target_host_legacy="192.168.0.99")
        rate_flood._validate_args(args)
        assert args.target_host == "192.168.0.99"

    def test_rejects_duration_below_minimum(self):
        args = _rate_flood_args(duration=rate_flood.MIN_DURATION_SECONDS - 0.01)
        with pytest.raises(SystemExit):
            rate_flood._validate_args(args)

    def test_rejects_duration_above_maximum(self):
        args = _rate_flood_args(duration=rate_flood.MAX_DURATION_SECONDS + 1)
        with pytest.raises(SystemExit):
            rate_flood._validate_args(args)

    def test_rejects_zero_or_negative_rate_pps(self):
        """0 이하 rate_pps는 무제한 속도 전송으로 이어지므로 반드시 거부되어야 한다."""
        for bad_rate in (0.0, -1.0):
            args = _rate_flood_args(rate_pps=bad_rate)
            with pytest.raises(SystemExit):
                rate_flood._validate_args(args)

    def test_rejects_rate_pps_above_maximum(self):
        args = _rate_flood_args(rate_pps=rate_flood.MAX_RATE_PPS + 1)
        with pytest.raises(SystemExit):
            rate_flood._validate_args(args)

    def test_rejects_payload_bytes_out_of_range(self):
        args_low = _rate_flood_args(payload_bytes=rate_flood.MIN_PAYLOAD_BYTES - 1)
        with pytest.raises(SystemExit):
            rate_flood._validate_args(args_low)

        args_high = _rate_flood_args(payload_bytes=rate_flood.MAX_PAYLOAD_BYTES + 1)
        with pytest.raises(SystemExit):
            rate_flood._validate_args(args_high)

    def test_rejects_port_out_of_range(self):
        args_low = _rate_flood_args(port=rate_flood.MIN_PORT - 1)
        with pytest.raises(SystemExit):
            rate_flood._validate_args(args_low)

        args_high = _rate_flood_args(port=rate_flood.MAX_PORT + 1)
        with pytest.raises(SystemExit):
            rate_flood._validate_args(args_high)


class TestPacketRateFloodScenarioContract:
    """세부계획 6.3.3 / 12.1 — Scenario 기본값이 Packet Rule 실제 Threshold와
    맞물려 의도한 시나리오(FULL_E2E 초과 vs Byte-rate 단독 초과)를 실제로
    만족하는지 잠근다. packet_scenarios.py의 default_args를 여기서 다시
    선언하지 않고, 그 값이 바뀌면 이 테스트가 자동으로 깨지도록
    edge.scenarios.packet_scenarios의 등록값을 직접 읽는다.
    """

    def test_full_e2e_default_args_exceed_packet_rate_threshold(self):
        from edge.detection.packet_rule_detector import DEFAULT_PACKET_RULE_POLICY
        from edge.scenarios.scenario_registry import get_scenario

        scenario = get_scenario("packet_rate_flood")
        rate_pps = float(scenario.default_args["rate_pps"])
        duration = float(scenario.default_args["duration"])

        # _validate_args가 통과하는 안전 범위 안에 있어야 하고,
        assert rate_flood.MIN_RATE_PPS <= rate_pps <= rate_flood.MAX_RATE_PPS
        # 동시에 Packet Rule의 packet_rate_threshold를 실제로 초과해야
        # PACKET_RATE_ANOMALY가 트리거된다 (세부계획 6.3.3 FULL_E2E 대표 시나리오).
        assert rate_pps > DEFAULT_PACKET_RULE_POLICY.packet_rate_threshold, (
            f"scenario packet_rate_flood의 rate_pps({rate_pps})가 "
            f"packet_rate_threshold({DEFAULT_PACKET_RULE_POLICY.packet_rate_threshold})를 "
            "초과하지 않습니다. 둘 중 하나가 바뀌어 계약이 깨졌을 수 있습니다."
        )
        # Capture Window(10초)보다 길게 유지되어야 최소 1개 이상 완전한 Window를 포함한다.
        from edge.packet.capture_policy import NOMINAL_WINDOW_SECONDS

        assert duration > NOMINAL_WINDOW_SECONDS

    def test_byte_rate_only_default_args_stay_under_rate_but_over_byte_threshold(self):
        """세부계획 6.3.3: 'Packet Rate는 Rule Threshold 아래, Byte Rate만
        초과하도록 확인'을 실제 default_args 값으로 다시 검증한다."""
        from edge.detection.packet_rule_detector import DEFAULT_PACKET_RULE_POLICY
        from edge.scenarios.scenario_registry import get_scenario

        scenario = get_scenario("packet_byte_rate_flood")
        rate_pps = float(scenario.default_args["rate_pps"])
        payload_bytes = int(scenario.default_args["payload_bytes"])

        assert rate_pps < DEFAULT_PACKET_RULE_POLICY.packet_rate_threshold, (
            f"packet_byte_rate_flood 시나리오의 rate_pps({rate_pps})가 "
            f"packet_rate_threshold({DEFAULT_PACKET_RULE_POLICY.packet_rate_threshold}) 이상입니다. "
            "이러면 PACKET_RATE_ANOMALY까지 함께 트리거되어 Byte-rate 단독 시나리오 계약이 깨집니다."
        )

        computed_byte_rate = rate_pps * payload_bytes
        assert computed_byte_rate > DEFAULT_PACKET_RULE_POLICY.byte_rate_threshold, (
            f"packet_byte_rate_flood 시나리오의 계산된 byte_rate({computed_byte_rate})가 "
            f"byte_rate_threshold({DEFAULT_PACKET_RULE_POLICY.byte_rate_threshold})를 "
            "초과하지 않습니다. BYTE_RATE_ANOMALY가 트리거되지 않을 수 있습니다."
        )

    def test_byte_rate_only_default_args_pass_generator_safety_validation(self):
        from edge.scenarios.scenario_registry import get_scenario

        scenario = get_scenario("packet_byte_rate_flood")
        args = _rate_flood_args(
            rate_pps=float(scenario.default_args["rate_pps"]),
            payload_bytes=int(scenario.default_args["payload_bytes"]),
            duration=float(scenario.default_args["duration"]),
        )
        rate_flood._validate_args(args)  # should not raise


# ── port_scan_attack ────────────────────────────────────────────────────────

class TestPortScanAttackValidation:
    def test_default_args_pass_validation(self):
        args = _port_scan_args()
        port_scan._validate_args(args)  # should not raise

    def test_rejects_inverted_port_range(self):
        args = _port_scan_args(start_port=2000, end_port=1000)
        with pytest.raises(SystemExit):
            port_scan._validate_args(args)

    def test_rejects_start_port_below_one(self):
        args = _port_scan_args(start_port=0)
        with pytest.raises(SystemExit):
            port_scan._validate_args(args)

    def test_rejects_end_port_above_65535(self):
        args = _port_scan_args(start_port=1, end_port=65536)
        with pytest.raises(SystemExit):
            port_scan._validate_args(args)

    def test_rejects_zero_or_negative_timeout(self):
        for bad_timeout in (0, -10):
            args = _port_scan_args(timeout_ms=bad_timeout)
            with pytest.raises(SystemExit):
                port_scan._validate_args(args)

    def test_rejects_range_that_would_exceed_runner_timeout_budget(self):
        """port_count * timeout_ms가 Runner Timeout(120s) - 여유(20s)를 넘으면
        조기에 거부해야 한다 (Scenario Runner Timeout에 걸려 결과가 애매하게
        HOLD/실패로 남는 것을 사전에 방지)."""
        # 5000개 포트 * 150ms = 750초 >> 100초 예산
        args = _port_scan_args(start_port=1, end_port=5000, timeout_ms=150)
        with pytest.raises(SystemExit):
            port_scan._validate_args(args)

    def test_default_range_satisfies_distinct_port_threshold(self):
        """Packet Rule의 distinct_dest_port_count > 15 조건을 만족하려면
        기본 포트 범위가 최소 16개 이상이어야 한다."""
        from edge.detection.packet_rule_detector import DEFAULT_PACKET_RULE_POLICY

        port_count = port_scan.DEFAULT_END_PORT - port_scan.DEFAULT_START_PORT + 1
        assert port_count > DEFAULT_PACKET_RULE_POLICY.port_scan_distinct_port_threshold

    def test_default_range_stays_within_runner_timeout_budget(self):
        args = _port_scan_args()
        port_scan._validate_args(args)  # should not raise (기본값은 항상 예산 내여야 함)


class TestPortScanScenarioContract:
    def test_scenario_default_args_match_module_defaults(self):
        """packet_scenarios.py의 default_args가 port_scan_attack.py 자체 기본값과
        어긋나면(둘 중 하나만 바뀌면) 조용히 다른 시나리오가 실행될 수 있으므로
        여기서 동기화 여부를 고정한다."""
        from edge.scenarios.scenario_registry import get_scenario

        scenario = get_scenario("packet_port_scan")
        assert int(scenario.default_args["start_port"]) == port_scan.DEFAULT_START_PORT
        assert int(scenario.default_args["end_port"]) == port_scan.DEFAULT_END_PORT
        assert int(scenario.default_args["timeout_ms"]) == port_scan.DEFAULT_TIMEOUT_MS

    def test_scenario_default_args_pass_generator_safety_validation(self):
        from edge.scenarios.scenario_registry import get_scenario

        scenario = get_scenario("packet_port_scan")
        args = _port_scan_args(
            start_port=int(scenario.default_args["start_port"]),
            end_port=int(scenario.default_args["end_port"]),
            timeout_ms=int(scenario.default_args["timeout_ms"]),
        )
        port_scan._validate_args(args)  # should not raise