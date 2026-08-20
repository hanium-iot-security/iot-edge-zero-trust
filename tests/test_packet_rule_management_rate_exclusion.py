from __future__ import annotations

from edge.detection.packet_rule_detector import PacketRulePolicy, detect_packet_rules


def _policy_with_management_peer(peer_ip: str) -> PacketRulePolicy:
    policy = PacketRulePolicy(
        packet_rate_threshold=50.0,
        byte_rate_threshold=100_000.0,
        port_scan_distinct_port_threshold=15,
        port_scan_syn_threshold=15,
        broker_dos_tcp_syn_threshold=30,
        broker_dos_mqtt_packet_threshold=100,
        version="packet-rule-policy-test-v1",
    )
    # RED 단계: 아직 production dataclass에 정식 필드가 없으므로 테스트가 원하는
    # 정책 값을 임시 주입한다. 구현 후에는 정식 생성자 인자로 교체한다.
    object.__setattr__(policy, "packet_rate_excluded_peer_ips", frozenset({peer_ip}))
    return policy


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
