from __future__ import annotations

from types import SimpleNamespace

import pytest

from backend.app import config
from edge.detection.packet_rule_detector import PacketRulePolicy, detect_packet_rules


def _policy_with_management_peer(peer_ip: str) -> PacketRulePolicy:
    return PacketRulePolicy(
        packet_rate_threshold=50.0,
        byte_rate_threshold=100_000.0,
        port_scan_distinct_port_threshold=15,
        port_scan_syn_threshold=15,
        broker_dos_tcp_syn_threshold=30,
        broker_dos_mqtt_packet_threshold=100,
        version="packet-rule-policy-test-v1",
        packet_rate_excluded_peer_ips=frozenset({peer_ip}),
    )


def _settings(raw_excluded_peer_ips: str) -> SimpleNamespace:
    return SimpleNamespace(
        packet_rule_packet_rate_threshold=50.0,
        packet_rule_byte_rate_threshold=100_000.0,
        packet_rule_port_scan_distinct_port_threshold=15,
        packet_rule_port_scan_syn_threshold=15,
        packet_rule_broker_dos_tcp_syn_threshold=30,
        packet_rule_broker_dos_mqtt_packet_threshold=100,
        packet_rule_policy_version="packet-rule-policy-test-v1",
        packet_rule_packet_rate_excluded_peer_ips=raw_excluded_peer_ips,
    )


def test_management_peer_skips_only_packet_rate_rule() -> None:
    policy = _policy_with_management_peer("192.168.0.3")
    row = {
        "peer_ip": "192.168.0.3",
        "packet_count": 1_000,
        "total_bytes": 1_000,
        "distinct_dest_port_count": 20,
        "tcp_syn_count": 20,
        "mqtt_related_packet_count": 0,
        "captured_duration_seconds": 10.0,
    }

    events = detect_packet_rules(row, policy)
    event_types = {event["event_type"] for event in events}

    assert "PACKET_RATE_ANOMALY" not in event_types
    assert "PORT_SCAN" in event_types


def test_non_excluded_peer_still_triggers_packet_rate_rule() -> None:
    policy = _policy_with_management_peer("192.168.0.3")
    row = {
        "peer_ip": "192.168.0.30",
        "packet_count": 1_000,
        "total_bytes": 1_000,
        "distinct_dest_port_count": 2,
        "tcp_syn_count": 1,
        "mqtt_related_packet_count": 0,
        "captured_duration_seconds": 10.0,
    }

    events = detect_packet_rules(row, policy)
    assert [event["event_type"] for event in events] == ["PACKET_RATE_ANOMALY"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", frozenset()),
        ("   ", frozenset()),
        ("192.168.0.3", frozenset({"192.168.0.3"})),
        (
            " 192.168.0.3, 192.168.0.10 ,192.168.0.3 ",
            frozenset({"192.168.0.3", "192.168.0.10"}),
        ),
    ],
)
def test_from_env_parses_packet_rate_excluded_peer_ips(
    monkeypatch: pytest.MonkeyPatch,
    raw: str,
    expected: frozenset[str],
) -> None:
    monkeypatch.setattr(config, "settings", _settings(raw))

    policy = PacketRulePolicy.from_env()

    assert policy.packet_rate_excluded_peer_ips == expected


@pytest.mark.parametrize(
    "raw",
    [
        "not-an-ip",
        "192.168.0.999",
        "192.168.0.3,invalid",
    ],
)
def test_from_env_rejects_invalid_packet_rate_excluded_peer_ip(
    monkeypatch: pytest.MonkeyPatch,
    raw: str,
) -> None:
    monkeypatch.setattr(config, "settings", _settings(raw))

    with pytest.raises(ValueError, match="packet_rate_excluded_peer_ips"):
        PacketRulePolicy.from_env()
