from __future__ import annotations

from copy import deepcopy

import numpy as np
import pytest

from ai.packet_if_contract import (
    PACKET_IF_FEATURES,
    packet_feature_matrix,
    packet_feature_vector,
    transform_packet_feature_row,
    validate_packet_feature_order,
)


def _raw_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "packet_count": 90,
        "total_bytes": 9_000,
        "avg_packet_size": 100.0,
        "max_packet_size": 150,
        "mean_inter_arrival_time": 0.1,
        "distinct_dest_port_count": 3,
        "captured_duration_seconds": 10.0,
    }
    row.update(overrides)
    return row


def test_transform_keeps_ten_second_counts_and_feature_order() -> None:
    transformed = transform_packet_feature_row(_raw_row())

    assert tuple(transformed) == PACKET_IF_FEATURES
    assert transformed == {
        "packet_count_10s": 90.0,
        "total_bytes_10s": 9_000.0,
        "avg_packet_size": 100.0,
        "max_packet_size": 150.0,
        "mean_inter_arrival_time": 0.1,
        "distinct_dest_port_count": 3.0,
    }


def test_transform_normalizes_nine_second_counts_to_ten_seconds() -> None:
    transformed = transform_packet_feature_row(
        _raw_row(
            packet_count=90,
            total_bytes=9_000,
            captured_duration_seconds=9.0,
        )
    )

    assert transformed["packet_count_10s"] == pytest.approx(100.0)
    assert transformed["total_bytes_10s"] == pytest.approx(10_000.0)


def test_transform_does_not_mutate_input_row() -> None:
    row = _raw_row()
    original = deepcopy(row)

    transform_packet_feature_row(row)

    assert row == original


@pytest.mark.parametrize(
    "field_name",
    [
        "packet_count",
        "total_bytes",
        "avg_packet_size",
        "max_packet_size",
        "mean_inter_arrival_time",
        "distinct_dest_port_count",
        "captured_duration_seconds",
    ],
)
def test_transform_rejects_missing_required_field(field_name: str) -> None:
    row = _raw_row()
    del row[field_name]

    with pytest.raises(ValueError, match=f"missing packet feature field: {field_name}"):
        transform_packet_feature_row(row)


@pytest.mark.parametrize("invalid_value", [None, "1.0", True])
def test_transform_rejects_non_numeric_values(invalid_value: object) -> None:
    with pytest.raises(ValueError, match="packet_count must be a real number"):
        transform_packet_feature_row(_raw_row(packet_count=invalid_value))


@pytest.mark.parametrize("invalid_value", [float("nan"), float("inf"), float("-inf")])
def test_transform_rejects_non_finite_values(invalid_value: float) -> None:
    with pytest.raises(ValueError, match="total_bytes must be finite"):
        transform_packet_feature_row(_raw_row(total_bytes=invalid_value))


def test_transform_rejects_negative_feature() -> None:
    with pytest.raises(ValueError, match="avg_packet_size must be non-negative"):
        transform_packet_feature_row(_raw_row(avg_packet_size=-0.1))


def test_transform_rejects_non_finite_normalized_value() -> None:
    with pytest.raises(
        ValueError,
        match="packet_count_10s must be finite after normalization",
    ):
        transform_packet_feature_row(
            _raw_row(
                packet_count=1e308,
                total_bytes=1.0,
                captured_duration_seconds=1e-308,
            )
        )


@pytest.mark.parametrize("duration", [0, -0.1])
def test_transform_rejects_non_positive_duration(duration: float) -> None:
    expected = (
        "captured_duration_seconds must be greater than zero"
        if duration == 0
        else "captured_duration_seconds must be non-negative"
    )
    with pytest.raises(ValueError, match=expected):
        transform_packet_feature_row(
            _raw_row(captured_duration_seconds=duration)
        )


def test_packet_feature_vector_follows_contract_order() -> None:
    assert packet_feature_vector(_raw_row()) == (
        90.0,
        9_000.0,
        100.0,
        150.0,
        0.1,
        3.0,
    )


def test_packet_feature_matrix_has_stable_empty_shape() -> None:
    matrix = packet_feature_matrix([])

    assert matrix.shape == (0, len(PACKET_IF_FEATURES))
    assert matrix.dtype == np.dtype(float)


def test_validate_packet_feature_order_accepts_exact_contract() -> None:
    validate_packet_feature_order(PACKET_IF_FEATURES)


def test_validate_packet_feature_order_rejects_reordered_features() -> None:
    reordered = tuple(reversed(PACKET_IF_FEATURES))

    with pytest.raises(ValueError, match="packet feature order mismatch"):
        validate_packet_feature_order(reordered)
