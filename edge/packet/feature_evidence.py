"""Verify sealed Packet Feature rows across the nullable Migration 013 addition.

New evidence still binds the complete current rows. Historical evidence can match
only the exact pre-013 representation when all three added fields remain NULL.
No stored seal, row value, row order, or surrounding audit envelope is rewritten.
"""
from __future__ import annotations

import hashlib
import json


LEGACY_PACKET_FEATURE_FIELDS = frozenset((
    "id", "capture_segment_id", "device_id", "peer_ip", "direction",
    "window_start", "window_end", "packet_count", "total_bytes",
    "avg_packet_size", "max_packet_size", "mean_inter_arrival_time",
    "distinct_dest_port_count", "tcp_syn_count", "mqtt_related_packet_count",
    "non_mqtt_tcp_udp_packet_count", "capture_scope", "created_at",
))
MIGRATION_013_FIELDS = frozenset((
    "broker_target_ip", "broker_target_port", "broker_target_syn_count",
))


def packet_feature_evidence_matches(rows, expected_sha256, *, ensure_ascii=False):
    """Keep the caller's original JSON encoding; accept no generic projection."""
    return _matches(rows, expected_sha256, ensure_ascii, lambda value: value)


def packet_feature_manifest_matches(segments, rows, expected_sha256):
    """Bind unchanged segments and feature rows in the bounded-replay manifest."""
    if not isinstance(segments, list) or any(not isinstance(row, dict) for row in segments):
        return False
    return _matches(rows, expected_sha256, False,
                    lambda value: {"segments": segments, "features": value})


def _matches(rows, expected_sha256, ensure_ascii, envelope):
    if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_sha256)
            or not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
            or type(ensure_ascii) is not bool):
        return False

    def digest(value):
        encoded = json.dumps(envelope(value), ensure_ascii=ensure_ascii, allow_nan=False,
                             sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    try:
        if digest(rows) == expected_sha256:
            return True
        if not rows or any(
                set(row) != LEGACY_PACKET_FEATURE_FIELDS | MIGRATION_013_FIELDS
                or any(row[key] is not None for key in MIGRATION_013_FIELDS)
                for row in rows):
            return False
        legacy = [{key: value for key, value in row.items() if key not in MIGRATION_013_FIELDS}
                  for row in rows]
        return digest(legacy) == expected_sha256
    except (TypeError, ValueError, OverflowError):
        return False
