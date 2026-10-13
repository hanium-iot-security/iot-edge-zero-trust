"""Bounded Broker DoS Packet Rule smoke generator tests."""

from __future__ import annotations

from datetime import datetime
from math import inf, nan

import pytest

from attacks.broker_dos_attack import (
    DEFAULT_CONNECTION_COUNT,
    DEFAULT_CONNECT_TIMEOUT_MS,
    DEFAULT_RATE_CPS,
    AttackPlan,
    _attempt_connection,
    build_attack_plan,
    execute_attack,
    parse_args,
)
from edge.detection.packet_rule_detector import (
    DEFAULT_PACKET_RULE_POLICY,
    detect_packet_rules,
)
from edge.features.packet_feature_utils import ParsedPacket, build_packet_features
from edge.phase5.contracts import EvaluationScope
from edge.scenarios.scenario_registry import get_scenario
from edge.trust.trust_policy import BROKER_DOS_SUSPECTED


PI_IP = "192.168.0.20"
ATTACK_NODE_IP = "192.168.0.30"
WINDOW_START = datetime(2025, 1, 1, 0, 0, 0)
WINDOW_END = datetime(2025, 1, 1, 0, 0, 10)
WINDOW_TS = 1735689600.0


def test_default_plan_is_bounded_and_exceeds_broker_dos_contract() -> None:
    plan = build_attack_plan(target_host=PI_IP)

    assert plan == AttackPlan(
        target_host=PI_IP,
        target_port=1883,
        count=DEFAULT_CONNECTION_COUNT,
        rate_cps=DEFAULT_RATE_CPS,
        connect_timeout_ms=DEFAULT_CONNECT_TIMEOUT_MS,
    )
    assert plan.count == 24
    assert plan.nominal_duration_seconds == pytest.approx(3.0)
    assert plan.worst_case_duration_seconds == pytest.approx(4.8)
    assert plan.planned_tcp_syn_count == 24
    assert plan.planned_mqtt_related_packet_count == 48
    assert plan.planned_tcp_syn_count > DEFAULT_PACKET_RULE_POLICY.broker_dos_tcp_syn_threshold
    assert (
        plan.planned_mqtt_related_packet_count
        > DEFAULT_PACKET_RULE_POLICY.broker_dos_mqtt_packet_threshold
    )


def test_parser_accepts_scenario_registry_underscore_argument_names() -> None:
    args = parse_args(
        [
            "--target-host",
            PI_IP,
            "--target_port",
            "1883",
            "--count",
            "24",
            "--rate_cps",
            "8",
            "--connect_timeout_ms",
            "200",
        ]
    )

    assert args.target_host == PI_IP
    assert args.target_port == 1883
    assert args.count == 24
    assert args.rate_cps == pytest.approx(8.0)
    assert args.connect_timeout_ms == 200


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"target_host": ""}, "target-host"),
        ({"target_host": "8.8.8.8"}, "private or loopback"),
        ({"target_port": 0}, "target-port"),
        ({"target_port": 8883}, "target-port.*1883"),
        ({"target_port": 65536}, "target-port"),
        ({"count": 0}, "count"),
        ({"count": 101}, "count"),
        ({"rate_cps": 0.0}, "rate-cps"),
        ({"rate_cps": 21.0}, "rate-cps"),
        ({"rate_cps": nan}, "rate-cps"),
        ({"rate_cps": inf}, "rate-cps"),
        ({"connect_timeout_ms": 0}, "connect-timeout-ms"),
        ({"connect_timeout_ms": 2001}, "connect-timeout-ms"),
        ({"count": 100, "connect_timeout_ms": 2000}, "bounded duration"),
    ],
)
def test_build_attack_plan_rejects_unsafe_or_unbounded_inputs(
    overrides: dict[str, object], message: str
) -> None:
    values: dict[str, object] = {"target_host": PI_IP}
    values.update(overrides)

    with pytest.raises(ValueError, match=message):
        build_attack_plan(**values)  # type: ignore[arg-type]


class _FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        assert seconds >= 0
        self.now += seconds


def test_execute_attack_attempts_exactly_the_bounded_plan_without_network() -> None:
    plan = build_attack_plan(target_host=PI_IP, count=4, rate_cps=4)
    calls: list[tuple[str, int, float]] = []
    clock = _FakeClock()

    def connect_attempt(host: str, port: int, timeout_seconds: float) -> bool:
        calls.append((host, port, timeout_seconds))
        return len(calls) % 2 == 1

    result = execute_attack(
        plan,
        connect_attempt=connect_attempt,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    assert calls == [(PI_IP, 1883, 0.2)] * 4
    assert result.attempted == 4
    assert result.succeeded == 2
    assert result.failed == 2
    assert result.interrupted is False
    assert result.elapsed_seconds == pytest.approx(0.75)


def test_execute_attack_revalidates_a_programmatically_constructed_plan() -> None:
    unsafe_plan = AttackPlan(
        target_host=PI_IP,
        target_port=1883,
        count=1000,
        rate_cps=1000,
        connect_timeout_ms=200,
    )
    calls = 0

    def connect_attempt(_host: str, _port: int, _timeout_seconds: float) -> bool:
        nonlocal calls
        calls += 1
        return True

    with pytest.raises(ValueError, match="count"):
        execute_attack(unsafe_plan, connect_attempt=connect_attempt)

    assert calls == 0


def test_execute_attack_stops_cleanly_on_keyboard_interrupt() -> None:
    plan = build_attack_plan(target_host=PI_IP, count=10, rate_cps=10)
    calls = 0
    clock = _FakeClock()

    def connect_attempt(_host: str, _port: int, _timeout_seconds: float) -> bool:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise KeyboardInterrupt
        return True

    result = execute_attack(
        plan,
        connect_attempt=connect_attempt,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    assert calls == 3
    assert result.attempted == 2
    assert result.succeeded == 2
    assert result.failed == 0
    assert result.interrupted is True


def test_connection_socket_is_closed_when_connect_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSocket:
        def __init__(self) -> None:
            self.timeout: float | None = None
            self.closed = False

        def __enter__(self) -> "FakeSocket":
            return self

        def __exit__(self, *_args: object) -> None:
            self.closed = True

        def settimeout(self, timeout: float) -> None:
            self.timeout = timeout

        def connect_ex(self, _address: tuple[str, int]) -> int:
            raise OSError("synthetic failure")

    fake_socket = FakeSocket()
    monkeypatch.setattr("attacks.broker_dos_attack.socket.socket", lambda *_args: fake_socket)

    assert _attempt_connection(PI_IP, 1883, 0.2) is False
    assert fake_socket.timeout == pytest.approx(0.2)
    assert fake_socket.closed is True


def test_successful_connection_plan_matches_actual_extractor_feature_contract() -> None:
    packets: list[ParsedPacket] = []
    for index in range(24):
        src_port = 40000 + index
        offset = index / 10
        packets.extend(
            [
                ParsedPacket(
                    timestamp=WINDOW_TS + offset,
                    src_ip=ATTACK_NODE_IP,
                    dst_ip=PI_IP,
                    protocol="TCP",
                    src_port=src_port,
                    dst_port=1883,
                    tcp_flags=0x02,
                    packet_length=60,
                ),
                ParsedPacket(
                    timestamp=WINDOW_TS + offset + 0.001,
                    src_ip=ATTACK_NODE_IP,
                    dst_ip=PI_IP,
                    protocol="TCP",
                    src_port=src_port,
                    dst_port=1883,
                    tcp_flags=0x10,
                    packet_length=52,
                ),
            ]
        )

    rows = build_packet_features(
        packets, PI_IP, WINDOW_START, WINDOW_END, broker_target_ip=PI_IP,
    )

    assert len(rows) == 1
    row = rows[0]
    assert row["peer_ip"] == ATTACK_NODE_IP
    assert row["direction"] == "INBOUND"
    assert row["packet_count"] == 48
    assert row["total_bytes"] == 2688
    assert row["distinct_dest_port_count"] == 1
    assert row["tcp_syn_count"] == 24
    assert row["broker_target_ip"] == PI_IP
    assert row["broker_target_port"] == 1883
    assert row["broker_target_syn_count"] == 24
    assert row["mqtt_related_packet_count"] == 48
    assert row["tcp_syn_count"] > 10
    assert row["mqtt_related_packet_count"] > 20


def test_default_burst_remains_detectable_across_a_capture_window_boundary() -> None:
    packets: list[ParsedPacket] = []
    # A worst-case 12/12 split of the 24 successful handshakes across adjacent
    # 10-second windows. Each connection contributes an inbound SYN and ACK.
    for index in range(24):
        src_port = 41000 + index
        offset = 8.5 + (index / 8)
        packets.extend(
            [
                ParsedPacket(
                    timestamp=WINDOW_TS + offset,
                    src_ip=ATTACK_NODE_IP,
                    dst_ip=PI_IP,
                    protocol="TCP",
                    src_port=src_port,
                    dst_port=1883,
                    tcp_flags=0x02,
                    packet_length=60,
                ),
                ParsedPacket(
                    timestamp=WINDOW_TS + offset + 0.001,
                    src_ip=ATTACK_NODE_IP,
                    dst_ip=PI_IP,
                    protocol="TCP",
                    src_port=src_port,
                    dst_port=1883,
                    tcp_flags=0x10,
                    packet_length=52,
                ),
            ]
        )

    windows = [
        (datetime(2025, 1, 1, 0, 0, 0), datetime(2025, 1, 1, 0, 0, 10)),
        (datetime(2025, 1, 1, 0, 0, 10), datetime(2025, 1, 1, 0, 0, 20)),
    ]
    rows = [
        build_packet_features(
            packets, PI_IP, window_start, window_end, broker_target_ip=PI_IP,
        )[0]
        for window_start, window_end in windows
    ]

    assert [(row["tcp_syn_count"], row["mqtt_related_packet_count"]) for row in rows] == [
        (12, 24),
        (12, 24),
    ]
    for row in rows:
        assert row["broker_target_syn_count"] == 12
        row["captured_duration_seconds"] = 10.0
        event_types = {
            event["event_type"]
            for event in detect_packet_rules(row, DEFAULT_PACKET_RULE_POLICY)
        }
        assert event_types == {BROKER_DOS_SUSPECTED}


def test_official_broker_dos_scenario_uses_bounded_generator_contract() -> None:
    scenario = get_scenario("packet_broker_dos")

    assert scenario.module == "attacks.broker_dos_attack"
    assert scenario.scenario_version == "v1"
    assert scenario.default_args == {
        "target_port": "1883",
        "count": "24",
        "rate_cps": "8",
        "connect_timeout_ms": "200",
    }
    assert scenario.target_host_arg_name == "target-host"
    assert scenario.evaluation_scope == EvaluationScope.DETECTION_ONLY.value
    assert scenario.expected_event_types == (BROKER_DOS_SUSPECTED,)
    assert scenario.volume_strategy == "count_arg"
    assert scenario.volume_arg_name == "count"
    assert scenario.volume_unit == "connections"
    assert scenario.isolation_expected is False
    assert scenario.firewall_rule_expected is False
    assert scenario.block_expected is False
