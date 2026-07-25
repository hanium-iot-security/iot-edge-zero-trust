"""검증된 Packet Isolation Forest Artifact Bundle을 읽고 추론합니다."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from math import isfinite
from numbers import Real
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
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
    validate_packet_feature_order,
)
from ai.packet_if_dataset import PACKET_IF_DATASET_VERSION, file_sha256


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PacketIFArtifact:
    model: IsolationForest
    model_path: Path
    metadata_path: Path
    model_version: str
    threshold: float
    metadata: dict[str, Any]


@dataclass(frozen=True)
class PacketIFPrediction:
    model_version: str
    raw_decision_score: float
    anomaly_score: float
    threshold: float
    is_anomaly: bool
    feature_values: tuple[float, ...]


def load_packet_if_artifact(artifact_dir: Path) -> PacketIFArtifact:
    """Model 역직렬화 전에 Metadata와 파일 무결성을 검증합니다."""
    metadata_path = artifact_dir / PACKET_IF_METADATA_FILENAME
    metadata = _load_metadata(metadata_path)
    model_version, threshold = _validate_metadata(metadata)

    model_path = artifact_dir / PACKET_IF_MODEL_FILENAME
    if not model_path.is_file():
        raise FileNotFoundError(f"Packet IF model not found: {model_path}")

    expected_sha256 = metadata["model_sha256"]
    actual_sha256 = file_sha256(model_path)
    if actual_sha256 != expected_sha256:
        raise ValueError(
            "Packet IF model SHA256 mismatch: "
            f"expected={expected_sha256}, actual={actual_sha256}"
        )

    try:
        model = joblib.load(model_path)
    except Exception as exc:
        raise ValueError(f"unable to load Packet IF model: {model_path}") from exc
    if not isinstance(model, IsolationForest):
        raise ValueError("Packet IF artifact model must be an IsolationForest")

    feature_count = getattr(model, "n_features_in_", None)
    if feature_count != len(PACKET_IF_FEATURES):
        raise ValueError(
            "Packet IF model feature count mismatch: "
            f"expected={len(PACKET_IF_FEATURES)}, actual={feature_count}"
        )

    return PacketIFArtifact(
        model=model,
        model_path=model_path,
        metadata_path=metadata_path,
        model_version=model_version,
        threshold=threshold,
        metadata=metadata,
    )


def predict_packet_feature_row(
    artifact: PacketIFArtifact,
    row: dict[str, Any],
) -> PacketIFPrediction:
    """저장된 Artifact 계약으로 원본 Packet Feature Row 하나를 추론합니다."""
    predictions = predict_packet_feature_rows(artifact, [row])
    return predictions[0]


def predict_packet_feature_rows(
    artifact: PacketIFArtifact,
    rows: list[dict[str, Any]],
) -> tuple[PacketIFPrediction, ...]:
    """입력 순서를 유지하면서 원본 Packet Feature Row들을 추론합니다."""
    matrix = packet_feature_matrix(rows)
    if matrix.shape[0] == 0:
        return ()

    raw_scores = np.asarray(
        artifact.model.decision_function(matrix),
        dtype=float,
    )
    if raw_scores.shape != (matrix.shape[0],):
        raise ValueError(
            "Packet IF model returned an unexpected score shape: "
            f"{raw_scores.shape}"
        )
    if not np.isfinite(raw_scores).all():
        raise ValueError("Packet IF model returned a non-finite score")

    anomaly_score_values = -raw_scores
    return tuple(
        PacketIFPrediction(
            model_version=artifact.model_version,
            raw_decision_score=float(raw_score),
            anomaly_score=float(anomaly_score),
            threshold=artifact.threshold,
            is_anomaly=bool(anomaly_score > artifact.threshold),
            feature_values=tuple(float(value) for value in feature_values),
        )
        for raw_score, anomaly_score, feature_values in zip(
            raw_scores,
            anomaly_score_values,
            matrix,
            strict=True,
        )
    )


def predict_packet_feature_csv(
    artifact_dir: Path,
    csv_path: Path,
) -> dict[str, float | int | str]:
    """CSV를 추론하고 CLI 검증용 요약 결과를 반환합니다."""
    if not csv_path.is_file():
        raise FileNotFoundError(f"Packet IF input CSV not found: {csv_path}")
    frame = pd.read_csv(csv_path)
    if frame.empty:
        raise ValueError("Packet IF input CSV must contain at least one row")

    artifact = load_packet_if_artifact(artifact_dir)
    predictions = predict_packet_feature_rows(
        artifact,
        frame.to_dict(orient="records"),
    )
    anomaly_score_values = np.asarray(
        [prediction.anomaly_score for prediction in predictions],
        dtype=float,
    )
    anomaly_count = sum(prediction.is_anomaly for prediction in predictions)
    return {
        "model_version": artifact.model_version,
        "total_count": len(predictions),
        "normal_count": len(predictions) - anomaly_count,
        "anomaly_count": anomaly_count,
        "threshold": artifact.threshold,
        "anomaly_score_min": float(np.min(anomaly_score_values)),
        "anomaly_score_max": float(np.max(anomaly_score_values)),
        "anomaly_score_mean": float(np.mean(anomaly_score_values)),
    }


def _load_metadata(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Packet IF metadata not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid Packet IF metadata JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Packet IF metadata must be a JSON object")
    return payload


def _validate_metadata(metadata: dict[str, Any]) -> tuple[str, float]:
    _require_exact_integer(
        metadata,
        "artifact_schema_version",
        PACKET_IF_ARTIFACT_SCHEMA_VERSION,
    )
    _require_exact_string(metadata, "model_type", "IsolationForest")
    model_version = _require_non_empty_string(metadata, "model_version")
    _require_exact_string(metadata, "model_filename", PACKET_IF_MODEL_FILENAME)
    _require_sha256(metadata, "model_sha256")
    if metadata.get("scaler_type", object()) is not None:
        raise ValueError("Packet IF artifact scaler_type must be null")

    _require_exact_string(
        metadata,
        "feature_version",
        PACKET_IF_FEATURE_VERSION,
    )
    feature_order = metadata.get("feature_order")
    if not isinstance(feature_order, list) or not all(
        isinstance(value, str) for value in feature_order
    ):
        raise ValueError("Packet IF metadata feature_order must be a string list")
    validate_packet_feature_order(feature_order)
    _require_exact_string(
        metadata,
        "transform_version",
        PACKET_IF_TRANSFORM_VERSION,
    )
    _require_exact_string(
        metadata,
        "score_direction",
        PACKET_IF_SCORE_DIRECTION,
    )
    _require_exact_string(
        metadata,
        "threshold_operator",
        PACKET_IF_THRESHOLD_OPERATOR,
    )
    _require_exact_string(metadata, "threshold_source", "normal_validation")

    threshold = _require_finite_real(metadata, "threshold")
    percentile = _require_finite_real(metadata, "threshold_percentile")
    if not 0 < percentile < 100:
        raise ValueError(
            "Packet IF metadata threshold_percentile must be between 0 and 100"
        )

    _require_non_empty_string(metadata, "capture_policy_version")
    _require_exact_string(
        metadata,
        "dataset_version",
        PACKET_IF_DATASET_VERSION,
    )
    _require_sha256(metadata, "dataset_sha256")
    _require_sha256(metadata, "manifest_sha256")
    _validate_training_parameters(metadata.get("training_parameters"))
    _validate_sessions(metadata.get("sessions"))
    _validate_row_counts(metadata.get("row_counts"))
    _validate_library_versions(metadata.get("library_versions"))
    _require_git_commit_sha(metadata, "git_commit_sha")
    _require_utc_timestamp(metadata, "created_at")
    return model_version, threshold


def _validate_training_parameters(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("Packet IF metadata training_parameters must be an object")

    n_estimators = value.get("n_estimators")
    if (
        isinstance(n_estimators, bool)
        or not isinstance(n_estimators, int)
        or n_estimators <= 0
    ):
        raise ValueError(
            "Packet IF metadata n_estimators must be a positive integer"
        )
    if value.get("contamination") != "auto":
        raise ValueError("Packet IF metadata contamination must be 'auto'")

    random_state = value.get("random_state")
    if isinstance(random_state, bool) or not isinstance(random_state, int):
        raise ValueError("Packet IF metadata random_state must be an integer")
    if value.get("n_jobs") != 1:
        raise ValueError("Packet IF metadata n_jobs must be 1")


def _validate_sessions(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("Packet IF metadata sessions must be an object")
    all_session_ids: list[str] = []
    for split in ("train", "validation", "test"):
        session_ids = value.get(split)
        if not isinstance(session_ids, list) or not session_ids:
            raise ValueError(
                f"Packet IF metadata sessions.{split} must be a non-empty list"
            )
        if not all(
            isinstance(session_id, str) and session_id.strip()
            for session_id in session_ids
        ):
            raise ValueError(
                f"Packet IF metadata sessions.{split} contains an invalid value"
            )
        all_session_ids.extend(session_ids)
    if len(set(all_session_ids)) != len(all_session_ids):
        raise ValueError("Packet IF metadata contains a session in multiple splits")


def _validate_row_counts(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("Packet IF metadata row_counts must be an object")
    for split in ("train", "validation", "test"):
        row_count = value.get(split)
        if (
            isinstance(row_count, bool)
            or not isinstance(row_count, int)
            or row_count <= 0
        ):
            raise ValueError(
                f"Packet IF metadata row_counts.{split} must be positive"
            )


def _validate_library_versions(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("Packet IF metadata library_versions must be an object")
    for library_name in (
        "python",
        "numpy",
        "pandas",
        "scikit_learn",
        "joblib",
    ):
        library_version = value.get(library_name)
        if not isinstance(library_version, str) or not library_version.strip():
            raise ValueError(
                "Packet IF metadata is missing library version: "
                f"{library_name}"
            )


def _require_exact_integer(
    metadata: dict[str, Any],
    field_name: str,
    expected: int,
) -> None:
    value = metadata.get(field_name)
    if isinstance(value, bool) or not isinstance(value, int) or value != expected:
        raise ValueError(
            f"Packet IF metadata {field_name} mismatch: "
            f"expected={expected!r}, actual={value!r}"
        )


def _require_exact_string(
    metadata: dict[str, Any],
    field_name: str,
    expected: str,
) -> None:
    value = metadata.get(field_name)
    if value != expected:
        raise ValueError(
            f"Packet IF metadata {field_name} mismatch: "
            f"expected={expected!r}, actual={value!r}"
        )


def _require_non_empty_string(
    metadata: dict[str, Any],
    field_name: str,
) -> str:
    value = metadata.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"Packet IF metadata {field_name} must be a non-empty string"
        )
    return value.strip()


def _require_finite_real(
    metadata: dict[str, Any],
    field_name: str,
) -> float:
    value = metadata.get(field_name)
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"Packet IF metadata {field_name} must be a real number")
    result = float(value)
    if not isfinite(result):
        raise ValueError(f"Packet IF metadata {field_name} must be finite")
    return result


def _require_sha256(metadata: dict[str, Any], field_name: str) -> str:
    value = metadata.get(field_name)
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError(
            f"Packet IF metadata {field_name} must be a lowercase SHA256"
        )
    return value


def _require_git_commit_sha(
    metadata: dict[str, Any],
    field_name: str,
) -> str:
    value = metadata.get(field_name)
    if not isinstance(value, str) or len(value) != 40 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError(
            f"Packet IF metadata {field_name} must be a lowercase SHA1"
        )
    return value


def _require_utc_timestamp(
    metadata: dict[str, Any],
    field_name: str,
) -> datetime:
    value = metadata.get(field_name)
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(
            f"Packet IF metadata {field_name} must be a UTC timestamp ending in Z"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(
            f"Packet IF metadata {field_name} must be an ISO-8601 timestamp"
        ) from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"Packet IF metadata {field_name} must use UTC")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description="Packet Isolation Forest 추론")
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--csv", type=Path, required=True)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    result = predict_packet_feature_csv(args.artifact_dir, args.csv)
    logger.info(
        "Packet IF prediction complete: total=%d, normal=%d, anomaly=%d",
        result["total_count"],
        result["normal_count"],
        result["anomaly_count"],
    )
    logger.info(
        "model_version=%s, threshold=%.8f, anomaly_score=[%.8f, %.8f]",
        result["model_version"],
        result["threshold"],
        result["anomaly_score_min"],
        result["anomaly_score_max"],
    )


if __name__ == "__main__":
    main()
