from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest

from ai.packet_if_contract import (
    PACKET_IF_ARTIFACT_SCHEMA_VERSION,
    PACKET_IF_FEATURE_VERSION,
    PACKET_IF_FEATURES,
    PACKET_IF_METADATA_FILENAME,
    PACKET_IF_MODEL_FILENAME,
    PACKET_IF_SCORE_DIRECTION,
    PACKET_IF_THRESHOLD_OPERATOR,
    PACKET_IF_TRANSFORM_VERSION,
    packet_feature_matrix,
)
from ai.packet_if_dataset import PACKET_IF_DATASET_VERSION, file_sha256
from ai.predict_packet_isolation_forest import (
    load_packet_if_artifact,
    predict_packet_feature_csv,
    predict_packet_feature_row,
    predict_packet_feature_rows,
)


def _raw_row(index: int = 0) -> dict[str, float | int]:
    return {
        "packet_count": 20 + index,
        "total_bytes": 2_000 + index * 100,
        "avg_packet_size": 100.0 + index,
        "max_packet_size": 130 + index,
        "mean_inter_arrival_time": 0.2 + index * 0.01,
        "distinct_dest_port_count": 1 + index % 2,
        "captured_duration_seconds": 9.0 if index % 2 else 10.0,
    }


def _write_artifact(
    artifact_dir: Path,
    *,
    feature_count: int = len(PACKET_IF_FEATURES),
    stored_object: object | None = None,
) -> dict[str, object]:
    artifact_dir.mkdir(parents=True)
    model_path = artifact_dir / PACKET_IF_MODEL_FILENAME
    if stored_object is None:
        matrix = packet_feature_matrix([_raw_row(index) for index in range(20)])
        if feature_count != len(PACKET_IF_FEATURES):
            matrix = matrix[:, :feature_count]
        model = IsolationForest(
            n_estimators=20,
            contamination="auto",
            random_state=42,
            n_jobs=1,
        ).fit(matrix)
        stored_object = model
    joblib.dump(stored_object, model_path)

    metadata: dict[str, object] = {
        "artifact_schema_version": PACKET_IF_ARTIFACT_SCHEMA_VERSION,
        "model_type": "IsolationForest",
        "model_version": "packet-if-test-v1",
        "model_filename": PACKET_IF_MODEL_FILENAME,
        "model_sha256": file_sha256(model_path),
        "scaler_type": None,
        "feature_version": PACKET_IF_FEATURE_VERSION,
        "feature_order": list(PACKET_IF_FEATURES),
        "transform_version": PACKET_IF_TRANSFORM_VERSION,
        "score_direction": PACKET_IF_SCORE_DIRECTION,
        "threshold": 0.0,
        "threshold_percentile": 99.0,
        "threshold_operator": PACKET_IF_THRESHOLD_OPERATOR,
        "threshold_source": "normal_validation",
        "training_parameters": {
            "n_estimators": 20,
            "contamination": "auto",
            "random_state": 42,
            "n_jobs": 1,
        },
        "capture_policy_version": "packet-capture-policy-v1",
        "dataset_version": PACKET_IF_DATASET_VERSION,
        "dataset_sha256": "a" * 64,
        "manifest_sha256": "b" * 64,
        "sessions": {
            "train": ["11111111-1111-4111-8111-111111111111"],
            "validation": ["22222222-2222-4222-8222-222222222222"],
            "test": [
                "33333333-3333-4333-8333-333333333333",
                "44444444-4444-4444-8444-444444444444",
            ],
        },
        "row_counts": {
            "train": 20,
            "validation": 10,
            "test": 20,
        },
        "library_versions": {
            "python": "3.10.11",
            "numpy": "2.0.2",
            "pandas": "2.2.3",
            "scikit_learn": "1.6.1",
            "joblib": "1.4.2",
        },
        "git_commit_sha": "c" * 40,
        "created_at": "2026-07-23T00:00:00Z",
    }
    _write_metadata(artifact_dir, metadata)
    return metadata


def _write_metadata(
    artifact_dir: Path,
    metadata: dict[str, object],
) -> None:
    (artifact_dir / PACKET_IF_METADATA_FILENAME).write_text(
        json.dumps(metadata, indent=2) + "\n",
        encoding="utf-8",
    )


def test_load_and_predict_valid_artifact(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifact"
    _write_artifact(artifact_dir)

    artifact = load_packet_if_artifact(artifact_dir)
    prediction = predict_packet_feature_row(artifact, _raw_row(1))

    assert artifact.model_version == "packet-if-test-v1"
    assert prediction.model_version == artifact.model_version
    assert prediction.anomaly_score == pytest.approx(
        -prediction.raw_decision_score
    )
    assert prediction.threshold == 0.0
    assert prediction.is_anomaly == (
        prediction.anomaly_score > prediction.threshold
    )
    assert prediction.feature_values[0] == pytest.approx(21 * 10 / 9)
    assert len(prediction.feature_values) == len(PACKET_IF_FEATURES)


def test_threshold_is_strictly_greater_than(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifact"
    metadata = _write_artifact(artifact_dir)
    initial = predict_packet_feature_row(
        load_packet_if_artifact(artifact_dir),
        _raw_row(2),
    )

    metadata["threshold"] = initial.anomaly_score
    _write_metadata(artifact_dir, metadata)
    equal_prediction = predict_packet_feature_row(
        load_packet_if_artifact(artifact_dir),
        _raw_row(2),
    )

    metadata["threshold"] = np.nextafter(initial.anomaly_score, -np.inf)
    _write_metadata(artifact_dir, metadata)
    above_prediction = predict_packet_feature_row(
        load_packet_if_artifact(artifact_dir),
        _raw_row(2),
    )

    assert equal_prediction.is_anomaly is False
    assert above_prediction.is_anomaly is True


def test_predict_rows_preserves_order_and_accepts_empty_input(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "artifact"
    _write_artifact(artifact_dir)
    artifact = load_packet_if_artifact(artifact_dir)

    predictions = predict_packet_feature_rows(
        artifact,
        [_raw_row(3), _raw_row(4)],
    )

    assert predictions[0].feature_values[0] == pytest.approx(23 * 10 / 9)
    assert predictions[1].feature_values[0] == pytest.approx(24)
    assert predict_packet_feature_rows(artifact, []) == ()


def test_predict_csv_returns_summary(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifact"
    _write_artifact(artifact_dir)
    csv_path = tmp_path / "input.csv"
    pd.DataFrame([_raw_row(0), _raw_row(1)]).to_csv(csv_path, index=False)

    result = predict_packet_feature_csv(artifact_dir, csv_path)

    assert result["model_version"] == "packet-if-test-v1"
    assert result["total_count"] == 2
    assert result["normal_count"] + result["anomaly_count"] == 2


def test_load_rejects_missing_metadata(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="metadata not found"):
        load_packet_if_artifact(tmp_path / "missing")


def test_load_rejects_missing_model(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifact"
    _write_artifact(artifact_dir)
    (artifact_dir / PACKET_IF_MODEL_FILENAME).unlink()

    with pytest.raises(FileNotFoundError, match="model not found"):
        load_packet_if_artifact(artifact_dir)


def test_load_rejects_invalid_metadata_json(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir()
    (artifact_dir / PACKET_IF_METADATA_FILENAME).write_text(
        "{invalid",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid Packet IF metadata JSON"):
        load_packet_if_artifact(artifact_dir)


def test_load_rejects_model_sha256_mismatch_before_deserialization(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "artifact"
    _write_artifact(artifact_dir)
    with (artifact_dir / PACKET_IF_MODEL_FILENAME).open("ab") as handle:
        handle.write(b"tampered")

    with pytest.raises(ValueError, match="model SHA256 mismatch"):
        load_packet_if_artifact(artifact_dir)


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "message"),
    [
        ("feature_version", "packet-if-features-v2", "feature_version mismatch"),
        ("transform_version", "other-transform", "transform_version mismatch"),
        ("score_direction", "lower_is_more_anomalous", "score_direction mismatch"),
        ("threshold_operator", ">=", "threshold_operator mismatch"),
        ("dataset_version", "packet-if-dataset-v2", "dataset_version mismatch"),
    ],
)
def test_load_rejects_metadata_contract_mismatch(
    tmp_path: Path,
    field_name: str,
    invalid_value: str,
    message: str,
) -> None:
    artifact_dir = tmp_path / "artifact"
    metadata = _write_artifact(artifact_dir)
    metadata[field_name] = invalid_value
    _write_metadata(artifact_dir, metadata)

    with pytest.raises(ValueError, match=message):
        load_packet_if_artifact(artifact_dir)


def test_load_rejects_feature_order_mismatch(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifact"
    metadata = _write_artifact(artifact_dir)
    metadata["feature_order"] = list(reversed(PACKET_IF_FEATURES))
    _write_metadata(artifact_dir, metadata)

    with pytest.raises(ValueError, match="feature order mismatch"):
        load_packet_if_artifact(artifact_dir)


@pytest.mark.parametrize("threshold", [float("nan"), float("inf"), True, "0.1"])
def test_load_rejects_invalid_threshold(
    tmp_path: Path,
    threshold: object,
) -> None:
    artifact_dir = tmp_path / "artifact"
    metadata = _write_artifact(artifact_dir)
    metadata["threshold"] = threshold
    _write_metadata(artifact_dir, metadata)

    with pytest.raises(ValueError, match="threshold"):
        load_packet_if_artifact(artifact_dir)


def test_load_rejects_unexpected_scaler(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifact"
    metadata = _write_artifact(artifact_dir)
    metadata["scaler_type"] = "StandardScaler"
    _write_metadata(artifact_dir, metadata)

    with pytest.raises(ValueError, match="scaler_type"):
        load_packet_if_artifact(artifact_dir)


def test_load_rejects_non_isolation_forest_model(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifact"
    metadata = _write_artifact(artifact_dir, stored_object={"not": "a model"})

    with pytest.raises(ValueError, match="must be an IsolationForest"):
        load_packet_if_artifact(artifact_dir)

    assert metadata["model_sha256"] == file_sha256(
        artifact_dir / PACKET_IF_MODEL_FILENAME
    )


def test_load_rejects_wrong_model_feature_count(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifact"
    _write_artifact(artifact_dir, feature_count=5)

    with pytest.raises(ValueError, match="model feature count mismatch"):
        load_packet_if_artifact(artifact_dir)


def test_predict_applies_raw_feature_validation(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifact"
    _write_artifact(artifact_dir)
    artifact = load_packet_if_artifact(artifact_dir)
    row = _raw_row()
    row["captured_duration_seconds"] = 0

    with pytest.raises(
        ValueError,
        match="captured_duration_seconds must be greater than zero",
    ):
        predict_packet_feature_row(artifact, row)
