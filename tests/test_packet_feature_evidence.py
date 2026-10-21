"""Bounded NULL-column compatibility for already recorded source digests."""
from copy import deepcopy
import hashlib
import json

import pytest

from edge.packet.feature_evidence import (
    packet_feature_evidence_matches, packet_feature_manifest_matches,
)


ADDED = ("broker_target_ip", "broker_target_port", "broker_target_syn_count")


def legacy_rows():
    first = dict(id=31, capture_segment_id=14, device_id="esp32_02", peer_ip="192.168.0.5",
        direction="INBOUND", window_start="2026-10-21T01:00:00Z", window_end="2026-10-21T01:00:10Z",
        packet_count=4, total_bytes=300, avg_packet_size=75.0, max_packet_size=120,
        mean_inter_arrival_time=1.25, distinct_dest_port_count=1, tcp_syn_count=0,
        mqtt_related_packet_count=4, non_mqtt_tcp_udp_packet_count=0,
        capture_scope="관측 원본", created_at="2026-10-21T01:00:11Z")
    second = dict(first, id=32, direction="OUTBOUND", packet_count=2, total_bytes=80,
                  avg_packet_size=40.0, max_packet_size=40, mqtt_related_packet_count=2)
    return [first, second]


def current_rows():
    return [dict(row, **dict.fromkeys(ADDED)) for row in legacy_rows()]


def sha(rows, *, ensure_ascii=False):
    body = json.dumps(rows, ensure_ascii=ensure_ascii, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def test_full_old_and_current_digests_match_without_reinterpretation():
    for rows in (legacy_rows(), current_rows()):
        assert packet_feature_evidence_matches(rows, sha(rows)) is True
    measured = current_rows()
    measured[0].update(broker_target_ip="192.168.0.20", broker_target_port=1883,
                       broker_target_syn_count=0)
    assert packet_feature_evidence_matches(measured, sha(measured)) is True


def test_exact_three_added_nulls_preserve_the_legacy_digest():
    assert packet_feature_evidence_matches(current_rows(), sha(legacy_rows())) is True


@pytest.mark.parametrize("ensure_ascii", [False, True])
def test_unicode_keeps_each_callers_original_serialization(ensure_ascii):
    old, current = legacy_rows(), current_rows()
    for rows, expected in ((old, sha(old, ensure_ascii=ensure_ascii)),
                           (current, sha(current, ensure_ascii=ensure_ascii)),
                           (current, sha(old, ensure_ascii=ensure_ascii))):
        assert packet_feature_evidence_matches(rows, expected, ensure_ascii=ensure_ascii) is True
        assert packet_feature_evidence_matches(rows, expected, ensure_ascii=not ensure_ascii) is False


@pytest.mark.parametrize(("field", "value"), [
    ("packet_count", 4.0), ("id", 31.0), ("packet_count", 5),
    ("avg_packet_size", 75), ("window_start", "2026-10-21T01:00:01Z"),
    ("device_id", None), ("capture_scope", "다른 원본"),
])
def test_legacy_field_types_and_values_cannot_be_repaired(field, value):
    rows = current_rows()
    rows[0][field] = value
    assert packet_feature_evidence_matches(rows, sha(legacy_rows())) is False


@pytest.mark.parametrize("change", ["reverse", "insert", "delete", "old_field_missing"])
def test_row_order_membership_and_original_columns_are_immutable(change):
    rows = current_rows()
    if change == "reverse":
        rows.reverse()
    elif change == "insert":
        rows.append(deepcopy(rows[0]))
    elif change == "delete":
        rows.pop()
    else:
        del rows[0]["created_at"]
    assert packet_feature_evidence_matches(rows, sha(legacy_rows())) is False


@pytest.mark.parametrize(("field", "value"), [
    ("broker_target_syn_count", 0), ("broker_target_syn_count", False),
    ("broker_target_syn_count", 1), ("broker_target_ip", "192.168.0.20"),
    ("broker_target_ip", ""), ("broker_target_port", 1883),
])
def test_measured_or_other_non_null_added_values_never_match_legacy(field, value):
    rows = current_rows()
    rows[0][field] = value
    assert packet_feature_evidence_matches(rows, sha(legacy_rows())) is False


@pytest.mark.parametrize("field", ADDED)
def test_each_added_column_must_be_present_for_legacy_compatibility(field):
    rows = current_rows()
    del rows[0][field]
    assert packet_feature_evidence_matches(rows, sha(legacy_rows())) is False


def test_unknown_null_columns_and_mixed_shapes_do_not_enable_projection():
    rows = current_rows()
    rows[0]["future_column"] = None
    assert packet_feature_evidence_matches(rows, sha(legacy_rows())) is False
    assert packet_feature_evidence_matches([legacy_rows()[0], current_rows()[1]], sha(legacy_rows())) is False


def test_no_input_mutation_on_full_legacy_and_failed_comparisons():
    rows = current_rows()
    before = deepcopy(rows)
    for expected in (sha(rows), sha(legacy_rows()), "0" * 64):
        packet_feature_evidence_matches(rows, expected)
        assert rows == before


def test_empty_rows_require_their_exact_full_digest():
    assert packet_feature_evidence_matches([], sha([])) is True
    assert packet_feature_evidence_matches([], sha(legacy_rows())) is False


def test_current_full_null_digest_does_not_match_later_measured_values():
    rows = current_rows()
    expected = sha(rows)
    rows[0].update(broker_target_ip="192.168.0.20", broker_target_port=1883,
                   broker_target_syn_count=0)
    assert packet_feature_evidence_matches(rows, expected) is False


@pytest.mark.parametrize("expected", [None, False, 1, [], {}, "", "a" * 63, "g" * 64, "A" * 64])
def test_invalid_expected_digest_fails_closed(expected):
    assert packet_feature_evidence_matches(current_rows(), expected) is False


@pytest.mark.parametrize("rows", [None, {}, [None], [1], ["row"], [[]]])
def test_non_row_shapes_fail_closed_even_when_their_json_digest_is_supplied(rows):
    assert packet_feature_evidence_matches(rows, sha(rows)) is False


@pytest.mark.parametrize("value", [float("nan"), float("inf"), b"bytes", {"not-json"}])
def test_noncanonical_json_values_fail_closed(value):
    rows = current_rows()
    rows[0]["packet_count"] = value
    assert packet_feature_evidence_matches(rows, "a" * 64) is False


@pytest.mark.parametrize("change", [None, "segment_value", "segment_order", "feature_order", "unknown_null"])
def test_bounded_manifest_binds_segments_and_exact_legacy_features(change):
    segments = [dict(id=14, window_start="2026-10-21T01:00:00Z", status="PROCESSED"),
                dict(id=15, window_start="2026-10-21T01:00:10Z", status="EMPTY")]
    expected = sha(dict(segments=segments, features=legacy_rows()))
    rows = current_rows()
    if change == "segment_value":
        segments[0]["status"] = "EMPTY"
    elif change == "segment_order":
        segments.reverse()
    elif change == "feature_order":
        rows.reverse()
    elif change == "unknown_null":
        rows[0]["future_column"] = None
    before = deepcopy((segments, rows))
    assert packet_feature_manifest_matches(segments, rows, expected) is (change is None)
    assert (segments, rows) == before


@pytest.mark.parametrize("segments", [None, {}, [None], [0], [[]]])
def test_bounded_manifest_rejects_nonsegment_shapes_even_with_matching_digest(segments):
    rows = current_rows()
    expected = sha(dict(segments=segments, features=rows))
    assert packet_feature_manifest_matches(segments, rows, expected) is False
