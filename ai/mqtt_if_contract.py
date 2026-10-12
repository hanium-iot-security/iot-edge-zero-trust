"""MQTT IF inputs for standalone offline validation, without data admission."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from math import isfinite
from numbers import Integral, Real
from typing import Any

import numpy as np


MQTT_IF_FEATURES = (
    "publish_count",
    "avg_payload_size",
    "max_payload_size",
    "avg_message_interval",
    "min_message_interval",
)
MQTT_IF_INTEGER_FEATURES = frozenset(("publish_count", "max_payload_size"))
MQTT_IF_FEATURE_VERSION = "mqtt-if-features-v1"
MQTT_IF_TRANSFORM_VERSION = "mqtt-identity-v1"
MQTT_IF_NOMINAL_WINDOW_SECONDS = 10.0
MQTT_IF_SCORE_DIRECTION = "lower_is_more_anomalous"
MQTT_IF_THRESHOLD_OPERATOR = "<"
MQTT_IF_SINGLE_MESSAGE_FALLBACK_SECONDS = 5.0


def mqtt_interval_semantics() -> dict[str, Any]:
    """Describe the existing builder's fallback, not a measured send period."""
    return {
        "single_message_fallback_seconds": MQTT_IF_SINGLE_MESSAGE_FALLBACK_SECONDS,
        "single_message_is_observed_interval": False,
        "multi_message_source": "within_window_received_at_differences",
    }


def mqtt_feature_vector(row: Mapping[str, Any]) -> tuple[float, ...]:
    """Validate a typed Feature row; CSV coercion and QC are separate work."""
    if not isinstance(row, Mapping):
        raise ValueError("MQTT feature row must be a mapping")
    values = []
    for name in MQTT_IF_FEATURES:
        if name not in row:
            raise ValueError(f"missing MQTT feature field: {name}")
        value = row[name]
        if isinstance(value, (bool, np.bool_)) or not isinstance(value, Real):
            raise ValueError(f"{name} must be a real number, excluding bool")
        if name in MQTT_IF_INTEGER_FEATURES and not isinstance(value, Integral):
            raise ValueError(f"{name} must be an integer")
        try:
            numeric = float(value)
        except (OverflowError, ValueError) as exc:
            raise ValueError(f"{name} must be finite") from exc
        if not isfinite(numeric):
            raise ValueError(f"{name} must be finite")
        if numeric < 0:
            raise ValueError(f"{name} must be non-negative")
        values.append(numeric)
    if values[0] == 1 and any(
        value != MQTT_IF_SINGLE_MESSAGE_FALLBACK_SECONDS for value in values[-2:]
    ):
        raise ValueError("single-message MQTT intervals must retain the 5.0-second fallback")
    return tuple(values)


def mqtt_feature_matrix(rows: Iterable[Mapping[str, Any]]) -> np.ndarray:
    """Preserve row and feature order without scaling, clipping or imputation."""
    vectors = [mqtt_feature_vector(row) for row in rows]
    if not vectors:
        return np.empty((0, len(MQTT_IF_FEATURES)), dtype=float)
    matrix = np.asarray(vectors, dtype=float)
    # sklearn IF converts inputs to float32 internally. Reject overflow there
    # instead of accepting a finite float64 value that inference cannot use.
    if np.any(matrix > np.finfo(np.float32).max):
        raise ValueError("MQTT features must be representable as finite float32")
    return matrix
