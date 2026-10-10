"""P9-08: strict Packet Rule boundaries use decimal source values."""

from dataclasses import replace

import pytest

from edge.detection.packet_rule_detector import (
    DEFAULT_PACKET_RULE_POLICY,
    detect_packet_rules,
    effective_bytes_per_second,
    effective_packets_per_second,
)


@pytest.mark.parametrize("count, expected", [(114, False), (115, False), (116, True)])
def test_packet_rate_decimal_boundary(count: int, expected: bool) -> None:
    policy = replace(DEFAULT_PACKET_RULE_POLICY, packet_rate_threshold=12.5)
    row = {
        "packet_count": count,
        "total_bytes": 0,
        "captured_duration_seconds": 9.2,
        "distinct_dest_port_count": 0,
        "tcp_syn_count": 0,
        "mqtt_related_packet_count": 0,
    }
    events = detect_packet_rules(row, policy)
    assert ("PACKET_RATE_ANOMALY" in {event["event_type"] for event in events}) is expected


@pytest.mark.parametrize("count, expected", [(114, False), (115, False), (116, True)])
def test_byte_rate_decimal_boundary(count: int, expected: bool) -> None:
    policy = replace(DEFAULT_PACKET_RULE_POLICY, byte_rate_threshold=12.5)
    row = {
        "packet_count": 0,
        "total_bytes": count,
        "captured_duration_seconds": 9.2,
        "distinct_dest_port_count": 0,
        "tcp_syn_count": 0,
        "mqtt_related_packet_count": 0,
    }
    events = detect_packet_rules(row, policy)
    assert ("BYTE_RATE_ANOMALY" in {event["event_type"] for event in events}) is expected


def test_displayed_rate_matches_exact_boundary() -> None:
    assert effective_packets_per_second(115, 9.2) == 12.5
    assert effective_bytes_per_second(115, 9.2) == 12.5
