"""Packet Isolation Forest 학습·추론에서 공통으로 사용하는 Feature 계약입니다."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from math import isfinite
from numbers import Integral, Real
from typing import Any

import numpy as np


PACKET_IF_FEATURE_VERSION = "packet-if-features-v1"
PACKET_IF_TRANSFORM_VERSION = "packet-10s-normalization-v1"
PACKET_IF_NOMINAL_WINDOW_SECONDS = 10.0
PACKET_IF_ARTIFACT_SCHEMA_VERSION = 1
PACKET_IF_MODEL_FILENAME = "model.joblib"
PACKET_IF_METADATA_FILENAME = "metadata.json"
PACKET_IF_TRAINING_REPORT_FILENAME = "training_report.json"
PACKET_IF_SCORE_DIRECTION = "higher_is_more_anomalous"
PACKET_IF_THRESHOLD_OPERATOR = ">"

PACKET_IF_RAW_FEATURES = (
    "packet_count",
    "total_bytes",
    "avg_packet_size",
    "max_packet_size",
    "mean_inter_arrival_time",
    "distinct_dest_port_count",
    "captured_duration_seconds",
)

# 반드시 음이 아닌 정수여야 하는 원본 필드 (bool·소수 거부)
PACKET_IF_INTEGER_RAW_FEATURES = (
    "packet_count",
    "total_bytes",
    "max_packet_size",
    "distinct_dest_port_count",
)

PACKET_IF_FEATURES = (
    "packet_count_10s",
    "total_bytes_10s",
    "avg_packet_size",
    "max_packet_size",
    "mean_inter_arrival_time",
    "distinct_dest_port_count",
)


def transform_packet_feature_row(row: Mapping[str, Any]) -> dict[str, float]:
    """원본 Packet Feature Row를 검증하고 모델 입력 계약으로 변환합니다."""
    int_values = {
        name: _require_non_negative_integer(row, name)
        for name in PACKET_IF_INTEGER_RAW_FEATURES
    }
    avg_packet_size = _require_non_negative_finite_number(row, "avg_packet_size")
    mean_inter_arrival_time = _require_non_negative_finite_number(
        row, "mean_inter_arrival_time"
    )
    duration = _require_captured_duration(row)

    normalization_factor = PACKET_IF_NOMINAL_WINDOW_SECONDS / duration
    transformed = {
        "packet_count_10s": int_values["packet_count"] * normalization_factor,
        "total_bytes_10s": int_values["total_bytes"] * normalization_factor,
        "avg_packet_size": avg_packet_size,
        "max_packet_size": int_values["max_packet_size"],
        "mean_inter_arrival_time": mean_inter_arrival_time,
        "distinct_dest_port_count": int_values["distinct_dest_port_count"],
    }
    for name, value in transformed.items():
        if not isfinite(value):
            raise ValueError(f"{name} must be finite after normalization")
    return transformed


def packet_feature_vector(row: Mapping[str, Any]) -> tuple[float, ...]:
    """변환된 Row를 고정된 Feature 순서의 Vector로 반환합니다."""
    transformed = transform_packet_feature_row(row)
    return tuple(transformed[name] for name in PACKET_IF_FEATURES)


def packet_feature_matrix(rows: Iterable[Mapping[str, Any]]) -> np.ndarray:
    """여러 Row를 Packet IF Feature 순서의 2차원 실수 Matrix로 반환합니다."""
    vectors = [packet_feature_vector(row) for row in rows]
    if not vectors:
        return np.empty((0, len(PACKET_IF_FEATURES)), dtype=float)
    return np.asarray(vectors, dtype=float)


def validate_packet_feature_order(feature_order: Sequence[str]) -> None:
    """Artifact 또는 Dataset의 Feature 순서가 계약과 다르면 거부합니다."""
    actual = tuple(feature_order)
    if actual != PACKET_IF_FEATURES:
        raise ValueError(
            f"packet feature order mismatch: expected={PACKET_IF_FEATURES}, actual={actual}"
        )


def _require_non_negative_integer(
    row: Mapping[str, Any],
    field_name: str,
) -> float:
    if field_name not in row:
        raise ValueError(f"missing packet feature field: {field_name}")

    value = row[field_name]
    if isinstance(value, bool) or not isinstance(value, Integral):
        raise ValueError(f"{field_name} must be a non-negative integer")
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative")
    return float(value)


def _require_non_negative_finite_number(
    row: Mapping[str, Any],
    field_name: str,
) -> float:
    if field_name not in row:
        raise ValueError(f"missing packet feature field: {field_name}")

    value = row[field_name]
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{field_name} must be a real number")

    numeric_value = float(value)
    if not isfinite(numeric_value):
        raise ValueError(f"{field_name} must be finite")
    if numeric_value < 0:
        raise ValueError(f"{field_name} must be non-negative")
    return numeric_value


def _require_captured_duration(row: Mapping[str, Any]) -> float:
    field_name = "captured_duration_seconds"
    if field_name not in row:
        raise ValueError(f"missing packet feature field: {field_name}")

    value = row[field_name]
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{field_name} must be a real number")

    numeric_value = float(value)
    if not isfinite(numeric_value):
        raise ValueError(f"{field_name} must be finite")
    if numeric_value <= 0:
        raise ValueError(f"{field_name} must be greater than zero")
    if numeric_value > PACKET_IF_NOMINAL_WINDOW_SECONDS:
        raise ValueError(
            f"{field_name} must be at most {PACKET_IF_NOMINAL_WINDOW_SECONDS}"
        )
    return numeric_value
