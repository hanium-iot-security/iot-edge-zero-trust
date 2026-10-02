from datetime import datetime, timedelta, timezone

import pytest

from edge.detection.packet_rule_detector import (
    DEFAULT_PACKET_RULE_POLICY,
    detect_packet_rules,
)
from edge.detection.rule_detector import detect_feature_rules, detect_mqtt_rules
from edge.policy.resolver import (
    DevicePolicyResolver,
    DevicePolicyRevision,
    RegistrationRevision,
    INVALID_POLICY_REVISION,
    POLICY_UNAVAILABLE,
    UNREGISTERED_AT_WINDOW,
    next_utc_window_boundary,
)


T0 = datetime(2026, 9, 30, 0, 0, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(seconds=10)
T2 = T1 + timedelta(seconds=10)


def _policy(device_id: str, revision: int, effective_from: datetime, *,
            publish: int, payload: int, packets: float, bytes_: float
            ) -> DevicePolicyRevision:
    return DevicePolicyRevision(
        device_id, revision, effective_from, publish, payload, packets, bytes_
    )


def _feature(*, publish: int, payload: int) -> dict:
    return {
        "publish_count": publish,
        "max_payload_size": payload,
        "malformed_payload_count": 0,
        "abnormal_topic_count": 0,
    }


def _packet(*, count: int, total_bytes: int, duration: float) -> dict:
    return {
        "peer_ip": "192.0.2.10", "packet_count": count,
        "total_bytes": total_bytes, "captured_duration_seconds": duration,
        "distinct_dest_port_count": 0, "tcp_syn_count": 0,
        "mqtt_related_packet_count": 0,
    }


def test_two_devices_use_four_independent_limits_with_exact_and_exceeded_edges():
    low = _policy("low", 1, T0, publish=10, payload=100, packets=5, bytes_=50)
    high = _policy("high", 1, T0, publish=20, payload=200, packets=10, bytes_=100)
    resolver = DevicePolicyResolver(
        [RegistrationRevision("low", "ACTIVE", T0),
         RegistrationRevision("high", "ACTIVE", T0)],
        [low, high],
    )
    same_feature = _feature(publish=11, payload=101)
    same_packet = _packet(count=51, total_bytes=501, duration=10)
    assert {event["event_type"] for event in detect_feature_rules(
        same_feature, resolver.resolve("low", T0).policy
    )} == {"ABNORMAL_PUBLISH_RATE", "LARGE_PAYLOAD"}
    assert detect_feature_rules(same_feature, resolver.resolve("high", T0).policy) == []
    assert {event["event_type"] for event in detect_packet_rules(
        same_packet, DEFAULT_PACKET_RULE_POLICY, resolver.resolve("low", T0).policy
    )} == {"PACKET_RATE_ANOMALY", "BYTE_RATE_ANOMALY"}
    assert detect_packet_rules(
        same_packet, DEFAULT_PACKET_RULE_POLICY, resolver.resolve("high", T0).policy
    ) == []

    assert detect_feature_rules(_feature(publish=10, payload=100), low) == []
    assert {event["event_type"] for event in detect_feature_rules(
        _feature(publish=11, payload=101), low
    )} == {"ABNORMAL_PUBLISH_RATE", "LARGE_PAYLOAD"}
    assert detect_packet_rules(_packet(count=50, total_bytes=500, duration=10),
                               DEFAULT_PACKET_RULE_POLICY, low) == []
    assert {event["event_type"] for event in detect_packet_rules(
        _packet(count=51, total_bytes=501, duration=10),
        DEFAULT_PACKET_RULE_POLICY, low
    )} == {"PACKET_RATE_ANOMALY", "BYTE_RATE_ANOMALY"}


def test_policy_boundary_and_delayed_window_keep_original_revision():
    old = _policy("esp32_01", 1, T0, publish=5, payload=100, packets=5, bytes_=50)
    new = _policy("esp32_01", 2, T1, publish=50, payload=1000, packets=50, bytes_=500)
    resolver = DevicePolicyResolver(
        [RegistrationRevision("esp32_01", "ACTIVE", T0)], [old, new]
    )
    assert next_utc_window_boundary(T0) == T1
    assert next_utc_window_boundary(T0 + timedelta(seconds=9, milliseconds=999)) == T1
    assert resolver.current_and_scheduled("esp32_01", T0) == (old, new)
    assert resolver.resolve("esp32_01", T0).policy == old
    assert resolver.resolve("esp32_01", T1).policy == new
    assert detect_feature_rules(_feature(publish=6, payload=101),
                                resolver.resolve("esp32_01", T0).policy)
    assert detect_feature_rules(_feature(publish=6, payload=101),
                                resolver.resolve("esp32_01", T1).policy) == []


def test_registration_before_raw_is_not_applied_retroactively_to_identity_or_ip():
    resolver = DevicePolicyResolver(
        [RegistrationRevision("esp32_01", "ACTIVE", T0, "192.0.2.1"),
         RegistrationRevision("esp32_02", "PENDING", T1, "192.0.2.2")],
        [],
    )
    assert resolver.resolve("esp32_02", T0).reason == UNREGISTERED_AT_WINDOW
    assert resolver.device_id_for_ip("192.0.2.2", T0) is None
    assert resolver.device_id_for_ip("192.0.2.2", T1) == "esp32_02"
    raw = {"topic": "iot/esp32_01/sensor", "payload": '{"device_id":"esp32_02"}'}
    old_events = detect_mqtt_rules(raw, resolver.registered_ids_at(T0))
    assert old_events[0]["event_type"] == "UNKNOWN_DEVICE"
    assert old_events[0]["device_id"] == "esp32_02"
    assert detect_mqtt_rules(raw, resolver.registered_ids_at(T1))[0][
        "event_type"
    ] == "DEVICE_ID_MISMATCH"


def test_pending_disabled_are_registered_and_policy_gaps_are_explicit():
    resolver = DevicePolicyResolver(
        [RegistrationRevision("pending", "PENDING", T0),
         RegistrationRevision("disabled", "DISABLED", T0)], [],
    )
    assert resolver.registered_ids_at(T0) == {"pending", "disabled"}
    assert resolver.resolve("pending", T0).reason == POLICY_UNAVAILABLE
    assert resolver.resolve("disabled", T0).reason == POLICY_UNAVAILABLE


def test_bad_revision_is_reported_without_using_a_default():
    resolver = DevicePolicyResolver(
        [RegistrationRevision("esp32_01", "ACTIVE", T0)],
        [_policy("esp32_01", 0, T0, publish=10, payload=100,
                 packets=5, bytes_=50)],
    )
    result = resolver.resolve("esp32_01", T0)
    assert result.reason == INVALID_POLICY_REVISION
    assert result.policy is None
    with pytest.raises(ValueError, match="window_start"):
        resolver.resolve("esp32_01", T0 + timedelta(seconds=1))


def test_duplicate_or_decreasing_policy_revision_is_rejected():
    for revision in (1, 0):
        resolver = DevicePolicyResolver(
            [RegistrationRevision("esp32_01", "ACTIVE", T0)],
            [_policy("esp32_01", 1, T0, publish=10, payload=100,
                     packets=5, bytes_=50),
             _policy("esp32_01", revision, T1, publish=20, payload=200,
                     packets=10, bytes_=100)],
        )
        assert resolver.resolve("esp32_01", T0).policy.revision == 1
        assert resolver.resolve("esp32_01", T1).reason == INVALID_POLICY_REVISION


def test_message_rule_uses_receive_time_payload_validity_for_invalid_utf8():
    # Stored payload text may be valid JSON after invalid bytes became U+FFFD.
    row = {
        "topic": "iot/esp32_01/sensor",
        "payload": '{"device_id":"esp32_02","note":"�"}',
        "is_json_valid": 0,
    }
    assert detect_mqtt_rules(row, {"esp32_01", "esp32_02"}) == []
    assert detect_mqtt_rules({**row, "is_json_valid": 1},
                             {"esp32_01", "esp32_02"})[0]["event_type"] == "DEVICE_ID_MISMATCH"
