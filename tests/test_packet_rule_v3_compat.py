"""Explicit v3 keeps incumbent judgments; default/other policies keep v4."""
from dataclasses import replace

import pytest

from edge.detection.packet_rule_detector import DEFAULT_PACKET_RULE_POLICY, detect_packet_rules


V3 = replace(DEFAULT_PACKET_RULE_POLICY, version="packet-rule-policy-v3")
V4 = DEFAULT_PACKET_RULE_POLICY


def row(**changes):
    value = dict(peer_ip="192.168.0.5", direction="INBOUND", captured_duration_seconds=10.0,
                 packet_count=0, total_bytes=0, distinct_dest_port_count=1,
                 tcp_syn_count=11, mqtt_related_packet_count=21,
                 broker_target_ip=None, broker_target_port=None, broker_target_syn_count=None)
    value.update(changes)
    return value


def broker_event(key):
    return dict(event_type="BROKER_DOS_SUSPECTED", severity="high",
                observed_value={key: 11, "mqtt_related_packet_count": 21},
                threshold={key: 10, "mqtt_related_packet_count": 20})


def test_v3_unknown_broker_evidence_keeps_old_event_and_keys():
    value = row()
    assert detect_packet_rules(value, V3) == [broker_event("tcp_syn_count")]
    assert detect_packet_rules(value, V4) == [dict(
        event_type="BROKER_DOS_EVIDENCE_UNAVAILABLE", severity="low", observed_value=None,
        threshold=None, reason="BROKER_TARGET_SYN_COUNT_MISSING")]


def test_v3_nonbroker_syns_keep_incumbent_dos_while_v4_uses_target_count():
    value = row(broker_target_ip="192.168.0.20", broker_target_port=1883, broker_target_syn_count=0)
    assert detect_packet_rules(value, V3) == [broker_event("tcp_syn_count")]
    assert detect_packet_rules(value, V4) == []


def test_matching_counts_still_keep_version_specific_observed_and_threshold_keys():
    value = row(broker_target_ip="192.168.0.20", broker_target_port=1883, broker_target_syn_count=11)
    assert detect_packet_rules(value, V3) == [broker_event("tcp_syn_count")]
    assert detect_packet_rules(value, V4) == [broker_event("broker_target_syn_count")]


@pytest.mark.parametrize("extra", [
    {"broker_target_syn_count": True},
    {"broker_target_syn_count": -1},
    {"broker_target_syn_count": 11, "broker_target_ip": "not-ip", "broker_target_port": 1883},
    {"broker_target_syn_count": 11, "broker_target_ip": "192.168.0.20", "broker_target_port": 9001},
])
def test_v3_ignores_fields_the_incumbent_never_read_but_v4_still_validates(extra):
    value = row(**extra)
    assert detect_packet_rules(value, V3) == [broker_event("tcp_syn_count")]
    with pytest.raises(ValueError):
        detect_packet_rules(value, V4)


@pytest.mark.parametrize("version", ["packet-rule-policy-v4", "packet-rule-policy-v3-custom"])
def test_only_exact_v3_literal_selects_compatibility(version):
    assert detect_packet_rules(row(), replace(V4, version=version))[0]["event_type"] == "BROKER_DOS_EVIDENCE_UNAVAILABLE"
    assert V4.version == "packet-rule-policy-v4"


@pytest.mark.parametrize(("syn", "mqtt"), [(10, 21), (11, 20), (10, 20)])
def test_both_versions_keep_strict_broker_and_threshold(syn, mqtt):
    value = row(tcp_syn_count=syn, mqtt_related_packet_count=mqtt,
                broker_target_ip="192.168.0.20", broker_target_port=1883, broker_target_syn_count=syn)
    assert detect_packet_rules(value, V3) == detect_packet_rules(value, V4) == []


@pytest.mark.parametrize(("field", "event", "packet_count", "total_bytes"), [
    ("packet_rate_threshold", "PACKET_RATE_ANOMALY", 115, 4600),
    ("byte_rate_threshold", "BYTE_RATE_ANOMALY", 1, 115),
])
def test_v3_keeps_incumbent_float_boundary_while_v4_keeps_decimal_boundary(field, event, packet_count, total_bytes):
    value = row(captured_duration_seconds=9.2, packet_count=packet_count, total_bytes=total_bytes,
                tcp_syn_count=0, mqtt_related_packet_count=0)
    thresholds = dict(packet_rate_threshold=1_000_000.0, byte_rate_threshold=1_000_000.0)
    thresholds[field] = 12.5
    base = replace(V4, **thresholds)
    old = detect_packet_rules(value, replace(base, version=V3.version))
    count = packet_count if field == "packet_rate_threshold" else total_bytes
    assert old == [dict(event_type=event, severity="medium",
                        observed_value=float(count) / 9.2, threshold=12.5)]
    assert old[0]["observed_value"] > 12.5
    assert detect_packet_rules(value, base) == []


def test_rate_opt_out_and_peer_exclusion_keep_existing_scope():
    value = row(packet_count=1000, total_bytes=100_000)
    assert detect_packet_rules(value, V3, include_rate_rules=False) == [broker_event("tcp_syn_count")]
    for policy in (V3, V4):
        excluded = replace(policy, excluded_peer_ips=frozenset({value["peer_ip"]}))
        assert detect_packet_rules(value, excluded) == []


def test_v3_accepts_pre_migration_feature_shape_without_new_columns():
    value = {key: item for key, item in row().items() if not key.startswith("broker_target_")}
    assert detect_packet_rules(value, V3) == [broker_event("tcp_syn_count")]
