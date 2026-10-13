from __future__ import annotations

import argparse
from dataclasses import replace

import pytest

import attacks.packet_rate_flood_attack as packet_rate_flood_attack
import attacks.port_scan_attack as port_scan_attack
from backend.app.config import Settings
from edge.detection.packet_rule_detector import (
    DEFAULT_PACKET_RULE_POLICY,
    detect_packet_rules,
)
from edge.scenarios import packet_scenarios as _packet_scenarios  # noqa: F401
from edge.scenarios.scenario_registry import get_scenario


def _row(**overrides):
    row = {
        "device_id": "esp32_01",
        "peer_ip": "192.168.0.4",
        "direction": "INBOUND",
        "broker_target_ip": "192.168.0.20",
        "broker_target_port": 1883,
        "captured_duration_seconds": 10.0,
        "packet_count": 0,
        "total_bytes": 0,
        "distinct_dest_port_count": 0,
        "tcp_syn_count": 0,
        "mqtt_related_packet_count": 0,
        "broker_target_syn_count": 0,
    }
    row.update(overrides)
    return row


def _event_types(row):
    return {
        event["event_type"]
        for event in detect_packet_rules(row, DEFAULT_PACKET_RULE_POLICY)
    }


def test_default_packet_rule_policy_keeps_calibrated_thresholds_in_v4() -> None:
    policy = DEFAULT_PACKET_RULE_POLICY

    assert policy.packet_rate_threshold == 10.0
    assert policy.byte_rate_threshold == 2_500.0
    assert policy.port_scan_distinct_port_threshold == 5
    assert policy.port_scan_syn_threshold == 5
    assert policy.broker_dos_tcp_syn_threshold == 10
    assert policy.broker_dos_mqtt_packet_threshold == 20
    assert policy.version == "packet-rule-policy-v4"


def test_backend_settings_defaults_match_packet_rule_policy_v4() -> None:
    settings = Settings(_env_file=None)

    assert settings.packet_rule_packet_rate_threshold == 10.0
    assert settings.packet_rule_byte_rate_threshold == 2_500.0
    assert settings.packet_rule_port_scan_distinct_port_threshold == 5
    assert settings.packet_rule_port_scan_syn_threshold == 5
    assert settings.packet_rule_broker_dos_tcp_syn_threshold == 10
    assert settings.packet_rule_broker_dos_mqtt_packet_threshold == 20
    assert settings.packet_rule_policy_version == "packet-rule-policy-v4"


@pytest.mark.parametrize(
    ("row", "expected_event"),
    [
        (_row(packet_count=100), "PACKET_RATE_ANOMALY"),
        (_row(total_bytes=25_000), "BYTE_RATE_ANOMALY"),
        (_row(distinct_dest_port_count=5, tcp_syn_count=5), "PORT_SCAN"),
        (_row(tcp_syn_count=10, broker_target_syn_count=10, mqtt_related_packet_count=20), "BROKER_DOS_SUSPECTED"),
    ],
)
def test_exact_v4_threshold_does_not_emit_event(row, expected_event) -> None:
    assert expected_event not in _event_types(row)


@pytest.mark.parametrize(
    ("row", "expected_event"),
    [
        (_row(packet_count=101), "PACKET_RATE_ANOMALY"),
        (_row(total_bytes=25_001), "BYTE_RATE_ANOMALY"),
        (_row(distinct_dest_port_count=6, tcp_syn_count=6), "PORT_SCAN"),
        (_row(tcp_syn_count=11, broker_target_syn_count=11, mqtt_related_packet_count=21), "BROKER_DOS_SUSPECTED"),
    ],
)
def test_v4_threshold_exceedance_emits_expected_event(row, expected_event) -> None:
    assert _event_types(row) == {expected_event}


@pytest.mark.parametrize(
    "row",
    [
        _row(distinct_dest_port_count=6, tcp_syn_count=5),
        _row(distinct_dest_port_count=5, tcp_syn_count=6),
    ],
)
def test_port_scan_v4_keeps_and_condition(row) -> None:
    assert "PORT_SCAN" not in _event_types(row)


@pytest.mark.parametrize(
    "row",
    [
        _row(tcp_syn_count=11, broker_target_syn_count=11, mqtt_related_packet_count=20),
        _row(tcp_syn_count=10, broker_target_syn_count=10, mqtt_related_packet_count=21),
    ],
)
def test_broker_dos_v4_keeps_and_condition(row) -> None:
    assert "BROKER_DOS_SUSPECTED" not in _event_types(row)


def test_management_exclusion_skips_v4_rules_but_other_peers_remain_in_scope() -> None:
    policy = replace(
        DEFAULT_PACKET_RULE_POLICY,
        excluded_peer_ips=frozenset({"192.168.0.3"}),
    )
    violating = {
        "captured_duration_seconds": 10.0,
        "packet_count": 101,
        "total_bytes": 25_001,
        "distinct_dest_port_count": 6,
        "tcp_syn_count": 11,
        "mqtt_related_packet_count": 21,
        "broker_target_syn_count": 11,
    }

    management = _row(device_id=None, peer_ip="192.168.0.3", **violating)
    unregistered = _row(device_id=None, peer_ip="192.168.0.30", **violating)
    registered = _row(device_id="esp32_01", peer_ip="192.168.0.4", **violating)

    assert detect_packet_rules(management, policy) == []
    assert len(detect_packet_rules(unregistered, policy)) == 4
    assert len(detect_packet_rules(registered, policy)) == 4


def test_byte_only_scenario_is_unfragmented_and_crosses_only_byte_rate() -> None:
    scenario = get_scenario("packet_byte_rate_flood")
    rate_pps = float(scenario.default_args["rate_pps"])
    payload_bytes = int(scenario.default_args["payload_bytes"])
    detector_window_seconds = 10.0

    ipv4_header_bytes = 20
    udp_header_bytes = 8
    ipv4_packet_bytes = payload_bytes + udp_header_bytes + ipv4_header_bytes
    estimated_ipv4_bytes_per_second = rate_pps * ipv4_packet_bytes
    detector_row = _row(
        captured_duration_seconds=detector_window_seconds,
        packet_count=int(rate_pps * detector_window_seconds),
        total_bytes=int(
            estimated_ipv4_bytes_per_second * detector_window_seconds
        ),
    )
    detector_events = _event_types(detector_row)

    assert scenario.scenario_version == "v2"
    assert scenario.default_args == {
        "duration": "12",
        "rate_pps": "4",
        "payload_bytes": "1200",
    }
    assert ipv4_packet_bytes == 1_228
    assert ipv4_packet_bytes <= 1_500
    assert rate_pps < DEFAULT_PACKET_RULE_POLICY.packet_rate_threshold
    assert estimated_ipv4_bytes_per_second == 4_912
    assert estimated_ipv4_bytes_per_second > DEFAULT_PACKET_RULE_POLICY.byte_rate_threshold
    assert "BYTE_RATE_ANOMALY" in detector_events
    assert "PACKET_RATE_ANOMALY" not in detector_events


def test_generator_summary_distinguishes_payload_rate_from_detector_ip_rate() -> None:
    assert hasattr(packet_rate_flood_attack, "_format_completion_summary")

    summary = packet_rate_flood_attack._format_completion_summary(
        sent=4,
        elapsed=1.0,
        payload_bytes=1200,
    )

    assert "avg_payload_bps=4800" in summary
    assert "estimated_unfragmented_ipv4_bps=4912" in summary
    assert "avg_bps=" not in summary


def test_port_scan_warns_when_range_cannot_cross_v3_threshold(capsys) -> None:
    port_scan_attack._validate_args(
        argparse.Namespace(start_port=1, end_port=5, timeout_ms=1)
    )

    assert "distinct_port_count > 5" in capsys.readouterr().out


def test_port_scan_accepts_six_port_range_without_threshold_warning(capsys) -> None:
    port_scan_attack._validate_args(
        argparse.Namespace(start_port=1, end_port=6, timeout_ms=1)
    )

    assert "경고" not in capsys.readouterr().out


def test_port_scan_runtime_summary_uses_v3_thresholds() -> None:
    assert hasattr(port_scan_attack, "_format_policy_summary")
    assert port_scan_attack._format_policy_summary() == (
        "탐지 조건: distinct_port_count > 5 AND syn_count > 5 (기본 Policy)"
    )
