"""검증된 Packet Isolation Forest Artifact Bundle을 읽고 추론합니다."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import version as package_version
import io
import json
import logging
from math import isclose, isfinite
from numbers import Real
from pathlib import Path
import platform
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
    PACKET_IF_NOMINAL_WINDOW_SECONDS,
    PACKET_IF_PACKET_COUNT_FORMULA,
    PACKET_IF_SCORE_DIRECTION,
    PACKET_IF_THRESHOLD_OPERATOR,
    PACKET_IF_TOTAL_BYTES_FORMULA,
    PACKET_IF_TRAINING_REPORT_FILENAME,
    PACKET_IF_TRANSFORM_VERSION,
    packet_feature_matrix,
    validate_packet_feature_order,
)
from ai.packet_if_artifact import (
    bytes_sha256,
    packet_if_bundle_sha256_bytes,
)
from ai.packet_if_dataset import load_packet_if_dataset
from ai.packet_if_phase5_manifest import (
    PACKET_IF_DATASET_VERSION_V2,
    SUPPORTED_PACKET_IF_DATASET_VERSIONS,
)
from edge.packet.capture_policy import CapturePolicy


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PacketIFArtifact:
    model: IsolationForest
    model_path: Path
    metadata_path: Path
    training_report_path: Path
    model_version: str
    threshold: float
    bundle_sha256: str
    capture_policy: CapturePolicy
    metadata: dict[str, Any]


@dataclass(frozen=True)
class PacketIFPrediction:
    model_version: str
    raw_decision_score: float
    anomaly_score: float
    threshold: float
    is_anomaly: bool
    feature_values: tuple[float, ...]


def load_packet_if_artifact(
    artifact_dir: Path,
    *,
    expected_bundle_sha256: str,
    expected_model_version: str | None = None,
) -> PacketIFArtifact:
    """Verify an externally pinned Bundle before deserializing its model."""
    expected_bundle_sha256 = _validate_external_sha256(
        expected_bundle_sha256,
        "expected_bundle_sha256",
    )
    metadata_path = artifact_dir / PACKET_IF_METADATA_FILENAME
    model_path = artifact_dir / PACKET_IF_MODEL_FILENAME
    training_report_path = artifact_dir / PACKET_IF_TRAINING_REPORT_FILENAME
    bundle_files = {
        PACKET_IF_METADATA_FILENAME: _read_artifact_file(
            metadata_path,
            "metadata",
        ),
        PACKET_IF_MODEL_FILENAME: _read_artifact_file(
            model_path,
            "model",
        ),
        PACKET_IF_TRAINING_REPORT_FILENAME: _read_artifact_file(
            training_report_path,
            "training report",
        ),
    }
    actual_bundle_sha256 = packet_if_bundle_sha256_bytes(bundle_files)
    if actual_bundle_sha256 != expected_bundle_sha256:
        raise ValueError(
            "Packet IF Bundle SHA256 mismatch: "
            f"expected={expected_bundle_sha256}, actual={actual_bundle_sha256}"
        )

    metadata = _load_metadata_bytes(
        bundle_files[PACKET_IF_METADATA_FILENAME],
        metadata_path,
    )
    model_version, threshold, capture_policy = _validate_metadata(metadata)
    if (
        expected_model_version is not None
        and model_version != expected_model_version
    ):
        raise ValueError(
            "Packet IF model version mismatch: "
            f"expected={expected_model_version!r}, actual={model_version!r}"
        )

    expected_sha256 = metadata["model_sha256"]
    actual_sha256 = bytes_sha256(bundle_files[PACKET_IF_MODEL_FILENAME])
    if actual_sha256 != expected_sha256:
        raise ValueError(
            "Packet IF model SHA256 mismatch: "
            f"expected={expected_sha256}, actual={actual_sha256}"
        )
    expected_report_sha256 = metadata["training_report_sha256"]
    actual_report_sha256 = bytes_sha256(
        bundle_files[PACKET_IF_TRAINING_REPORT_FILENAME]
    )
    if actual_report_sha256 != expected_report_sha256:
        raise ValueError(
            "Packet IF training report SHA256 mismatch: "
            f"expected={expected_report_sha256}, actual={actual_report_sha256}"
        )
    _load_training_report_bytes(
        bundle_files[PACKET_IF_TRAINING_REPORT_FILENAME],
        training_report_path,
    )
    _validate_runtime_library_versions(metadata["library_versions"])

    try:
        model = joblib.load(
            io.BytesIO(bundle_files[PACKET_IF_MODEL_FILENAME])
        )
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
    _validate_model_parameters(
        model,
        metadata["training_parameters"],
    )

    return PacketIFArtifact(
        model=model,
        model_path=model_path,
        metadata_path=metadata_path,
        training_report_path=training_report_path,
        model_version=model_version,
        threshold=threshold,
        bundle_sha256=actual_bundle_sha256,
        capture_policy=capture_policy,
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
    _validate_inference_capture_coverage(rows, artifact.capture_policy)

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
    manifest_path: Path,
    *,
    expected_bundle_sha256: str,
    expected_model_version: str | None = None,
) -> dict[str, float | int | str]:
    """Validate a canonical Dataset Bundle and return an inference summary."""
    dataset = load_packet_if_dataset(csv_path, manifest_path)
    artifact = load_packet_if_artifact(
        artifact_dir,
        expected_bundle_sha256=expected_bundle_sha256,
        expected_model_version=expected_model_version,
    )
    if dataset.manifest.capture_policy != artifact.capture_policy:
        raise ValueError(
            "Packet IF offline dataset Capture Policy does not match Artifact"
        )
    frame = pd.concat(
        [dataset.train, dataset.validation, dataset.test],
        ignore_index=True,
    )
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


def _read_artifact_file(path: Path, label: str) -> bytes:
    if not path.exists():
        raise FileNotFoundError(f"Packet IF {label} not found: {path}")
    if path.is_symlink():
        raise ValueError(f"Packet IF {label} must not be a symlink: {path}")
    if not path.is_file():
        raise ValueError(f"Packet IF {label} must be a regular file: {path}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ValueError(f"unable to read Packet IF {label}: {path}") from exc


def _load_metadata_bytes(content: bytes, path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid Packet IF metadata JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Packet IF metadata must be a JSON object")
    return payload


def _load_training_report_bytes(content: bytes, path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"invalid Packet IF training report JSON: {path}"
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("Packet IF training report must be a JSON object")
    return payload


def _validate_metadata(
    metadata: dict[str, Any],
) -> tuple[str, float, CapturePolicy]:
    _require_exact_integer(
        metadata,
        "artifact_schema_version",
        PACKET_IF_ARTIFACT_SCHEMA_VERSION,
    )
    _require_exact_string(metadata, "model_type", "IsolationForest")
    model_version = _require_non_empty_string(metadata, "model_version")
    _require_exact_string(metadata, "model_filename", PACKET_IF_MODEL_FILENAME)
    _require_sha256(metadata, "model_sha256")
    _require_exact_string(
        metadata,
        "training_report_filename",
        PACKET_IF_TRAINING_REPORT_FILENAME,
    )
    _require_sha256(metadata, "training_report_sha256")
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

    capture_policy = _validate_capture_policy_metadata(metadata)
    _validate_normalization_metadata(metadata.get("normalization"))
    dataset_version = _require_supported_dataset_version(metadata)
    _validate_normal_policy_version(metadata, dataset_version=dataset_version)
    _require_sha256(metadata, "dataset_sha256")
    _require_sha256(metadata, "manifest_sha256")
    _validate_training_parameters(metadata.get("training_parameters"))
    _validate_sessions(metadata.get("sessions"))
    _validate_row_counts(metadata.get("row_counts"))
    _validate_library_versions(metadata.get("library_versions"))
    _require_git_commit_sha(metadata, "git_commit_sha")
    _require_utc_timestamp(metadata, "created_at")
    return model_version, threshold, capture_policy


def _require_supported_dataset_version(metadata: dict[str, Any]) -> str:
    value = _require_non_empty_string(metadata, "dataset_version")
    if value not in SUPPORTED_PACKET_IF_DATASET_VERSIONS:
        raise ValueError(
            "Packet IF metadata dataset_version mismatch: "
            f"supported={sorted(SUPPORTED_PACKET_IF_DATASET_VERSIONS)!r}, "
            f"actual={value!r}"
        )
    return value


def _validate_normal_policy_version(
    metadata: dict[str, Any],
    *,
    dataset_version: str,
) -> str | None:
    value = metadata.get("normal_policy_version")
    if dataset_version == PACKET_IF_DATASET_VERSION_V2:
        return _require_non_empty_string(metadata, "normal_policy_version")
    if value is None:
        return None
    return _require_non_empty_string(metadata, "normal_policy_version")


def _validate_capture_policy_metadata(
    metadata: dict[str, Any],
) -> CapturePolicy:
    policy_version = _require_non_empty_string(
        metadata,
        "capture_policy_version",
    )
    value = metadata.get("capture_policy")
    if not isinstance(value, dict):
        raise ValueError("Packet IF metadata capture_policy must be an object")

    nested_version = _require_non_empty_string(value, "version")
    if nested_version != policy_version:
        raise ValueError(
            "Packet IF metadata Capture Policy version mismatch: "
            f"expected={policy_version!r}, actual={nested_version!r}"
        )

    nominal_window_seconds = _require_finite_real(
        value,
        "nominal_window_seconds",
    )
    if not isclose(
        nominal_window_seconds,
        PACKET_IF_NOMINAL_WINDOW_SECONDS,
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise ValueError(
            "Packet IF metadata nominal_window_seconds mismatch: "
            f"expected={PACKET_IF_NOMINAL_WINDOW_SECONDS}, "
            f"actual={nominal_window_seconds}"
        )

    policy = CapturePolicy(
        max_start_delay_seconds=_require_finite_real(
            value,
            "max_start_delay_seconds",
        ),
        minimum_duration_seconds=_require_finite_real(
            value,
            "minimum_duration_seconds",
        ),
        epsilon_seconds=_require_finite_real(value, "epsilon_seconds"),
        version=nested_version,
    )
    minimum_coverage_ratio = _require_finite_real(
        value,
        "minimum_coverage_ratio",
    )
    expected_coverage_ratio = (
        policy.minimum_duration_seconds / PACKET_IF_NOMINAL_WINDOW_SECONDS
    )
    if not isclose(
        minimum_coverage_ratio,
        expected_coverage_ratio,
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise ValueError(
            "Packet IF metadata minimum_coverage_ratio mismatch: "
            f"expected={expected_coverage_ratio}, "
            f"actual={minimum_coverage_ratio}"
        )
    return policy


def _validate_normalization_metadata(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("Packet IF metadata normalization must be an object")
    _require_exact_string(value, "version", PACKET_IF_TRANSFORM_VERSION)
    nominal_window_seconds = _require_finite_real(
        value,
        "nominal_window_seconds",
    )
    if not isclose(
        nominal_window_seconds,
        PACKET_IF_NOMINAL_WINDOW_SECONDS,
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise ValueError(
            "Packet IF metadata normalization nominal_window_seconds mismatch"
        )
    _require_exact_string(
        value,
        "packet_count_formula",
        PACKET_IF_PACKET_COUNT_FORMULA,
    )
    _require_exact_string(
        value,
        "total_bytes_formula",
        PACKET_IF_TOTAL_BYTES_FORMULA,
    )


def _validate_inference_capture_coverage(
    rows: list[dict[str, Any]],
    capture_policy: CapturePolicy,
) -> None:
    minimum_eligible_duration = max(
        0.0,
        capture_policy.minimum_duration_seconds - capture_policy.epsilon_seconds,
    )
    for index, row in enumerate(rows):
        duration = float(row["captured_duration_seconds"])
        if duration < minimum_eligible_duration:
            raise ValueError(
                "Packet IF inference row is below the Artifact Capture Policy "
                f"minimum duration: index={index}, duration={duration}, "
                f"minimum={minimum_eligible_duration}"
            )


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
    _python_major_minor(value["python"])


def _validate_runtime_library_versions(value: dict[str, Any]) -> None:
    expected_python = _python_major_minor(value["python"])
    actual_python_version = platform.python_version()
    actual_python = _python_major_minor(actual_python_version)
    current_versions = {
        "numpy": package_version("numpy"),
        "pandas": package_version("pandas"),
        "scikit_learn": package_version("scikit-learn"),
        "joblib": package_version("joblib"),
    }
    mismatches = {
        library_name: {
            "expected": value[library_name],
            "actual": actual_version,
        }
        for library_name, actual_version in current_versions.items()
        if value[library_name] != actual_version
    }
    if expected_python != actual_python:
        mismatches["python"] = {
            "expected": value["python"],
            "actual": actual_python_version,
        }
    if mismatches:
        raise ValueError(
            "Packet IF runtime library version mismatch: "
            + json.dumps(mismatches, sort_keys=True)
        )


def _python_major_minor(value: str) -> tuple[int, int]:
    parts = value.split(".")
    if len(parts) < 2:
        raise ValueError(
            "Packet IF metadata Python version must include major and minor"
        )
    try:
        return int(parts[0]), int(parts[1])
    except ValueError as exc:
        raise ValueError(
            "Packet IF metadata Python version must include numeric major and minor"
        ) from exc


def _validate_model_parameters(
    model: IsolationForest,
    expected: dict[str, Any],
) -> None:
    actual = model.get_params(deep=False)
    for parameter_name in (
        "n_estimators",
        "contamination",
        "random_state",
        "n_jobs",
    ):
        if actual.get(parameter_name) != expected[parameter_name]:
            raise ValueError(
                "Packet IF model parameter mismatch: "
                f"{parameter_name} expected={expected[parameter_name]!r}, "
                f"actual={actual.get(parameter_name)!r}"
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


def _validate_external_sha256(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a lowercase SHA256")
    normalized = value.strip()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef"
        for character in normalized
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA256")
    return normalized


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
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-bundle-sha256", required=True)
    parser.add_argument("--expected-model-version")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    result = predict_packet_feature_csv(
        args.artifact_dir,
        args.csv,
        args.manifest,
        expected_bundle_sha256=args.expected_bundle_sha256,
        expected_model_version=args.expected_model_version,
    )
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
