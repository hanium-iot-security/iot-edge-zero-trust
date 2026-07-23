"""재현 가능한 Packet Isolation Forest Artifact Bundle을 학습합니다."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import version as package_version
import json
import logging
from math import isfinite
from numbers import Real
import os
from pathlib import Path
import platform
import subprocess
from typing import Any
from uuid import uuid4

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from ai.packet_if_contract import (
    PACKET_IF_ARTIFACT_SCHEMA_VERSION,
    PACKET_IF_FEATURE_VERSION,
    PACKET_IF_FEATURES,
    PACKET_IF_METADATA_FILENAME,
    PACKET_IF_MODEL_FILENAME,
    PACKET_IF_SCORE_DIRECTION,
    PACKET_IF_THRESHOLD_OPERATOR,
    PACKET_IF_TRAINING_REPORT_FILENAME,
    PACKET_IF_TRANSFORM_VERSION,
    packet_feature_matrix,
)
from ai.packet_if_dataset import (
    ATTACK_LABEL,
    NORMAL_LABEL,
    PacketIFDataset,
    file_sha256,
    load_packet_if_dataset,
)


logger = logging.getLogger(__name__)

DEFAULT_MODEL_VERSION = "packet-if-v1"
DEFAULT_N_ESTIMATORS = 100
DEFAULT_RANDOM_STATE = 42
DEFAULT_THRESHOLD_PERCENTILE = 99.0
CONTAMINATION = "auto"
SCALER_TYPE = None


@dataclass(frozen=True)
class PacketIFTrainingArtifacts:
    model_path: Path
    metadata_path: Path
    training_report_path: Path
    threshold: float
    model_sha256: str


def train_packet_isolation_forest(
    dataset: PacketIFDataset,
    *,
    artifact_dir: Path,
    model_version: str = DEFAULT_MODEL_VERSION,
    threshold_percentile: float = DEFAULT_THRESHOLD_PERCENTILE,
    n_estimators: int = DEFAULT_N_ESTIMATORS,
    random_state: int = DEFAULT_RANDOM_STATE,
    git_commit_sha: str,
    manifest_sha256: str,
    overwrite: bool = False,
) -> PacketIFTrainingArtifacts:
    """Train으로 학습하고 Validation으로 Threshold를 정한 뒤 Test를 평가합니다."""
    _validate_training_options(
        model_version=model_version,
        threshold_percentile=threshold_percentile,
        n_estimators=n_estimators,
        random_state=random_state,
        git_commit_sha=git_commit_sha,
        manifest_sha256=manifest_sha256,
    )
    paths = _artifact_paths(artifact_dir)
    _prepare_artifact_directory(paths, overwrite=overwrite)

    train_matrix = packet_feature_matrix(dataset.train.to_dict(orient="records"))
    validation_matrix = packet_feature_matrix(
        dataset.validation.to_dict(orient="records")
    )
    test_matrix = packet_feature_matrix(dataset.test.to_dict(orient="records"))
    if train_matrix.shape[0] == 0 or validation_matrix.shape[0] == 0:
        raise ValueError("train and validation datasets must contain rows")

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=CONTAMINATION,
        random_state=random_state,
        n_jobs=1,
    )
    model.fit(train_matrix)

    train_scores = anomaly_scores(model, train_matrix)
    validation_scores = anomaly_scores(model, validation_matrix)
    test_scores = anomaly_scores(model, test_matrix)
    threshold = float(np.percentile(validation_scores, threshold_percentile))

    _atomic_joblib_dump(model, paths["model"])
    model_sha256 = file_sha256(paths["model"])
    created_at = _utc_now_string()

    report = _build_training_report(
        dataset=dataset,
        train_scores=train_scores,
        validation_scores=validation_scores,
        test_scores=test_scores,
        threshold=threshold,
        threshold_percentile=threshold_percentile,
    )
    _atomic_write_json(paths["report"], report)

    metadata = {
        "artifact_schema_version": PACKET_IF_ARTIFACT_SCHEMA_VERSION,
        "model_type": "IsolationForest",
        "model_version": model_version,
        "model_filename": PACKET_IF_MODEL_FILENAME,
        "model_sha256": model_sha256,
        "scaler_type": SCALER_TYPE,
        "feature_version": PACKET_IF_FEATURE_VERSION,
        "feature_order": list(PACKET_IF_FEATURES),
        "transform_version": PACKET_IF_TRANSFORM_VERSION,
        "score_direction": PACKET_IF_SCORE_DIRECTION,
        "threshold": threshold,
        "threshold_percentile": float(threshold_percentile),
        "threshold_operator": PACKET_IF_THRESHOLD_OPERATOR,
        "threshold_source": "normal_validation",
        "training_parameters": {
            "n_estimators": n_estimators,
            "contamination": CONTAMINATION,
            "random_state": random_state,
            "n_jobs": 1,
        },
        "capture_policy_version": dataset.manifest.capture_policy_version,
        "dataset_version": dataset.manifest.dataset_version,
        "dataset_sha256": dataset.manifest.dataset_sha256,
        "manifest_sha256": manifest_sha256,
        "sessions": {
            "train": list(dataset.session_ids("train")),
            "validation": list(dataset.session_ids("validation")),
            "test": list(dataset.session_ids("test")),
        },
        "row_counts": {
            "train": int(len(dataset.train)),
            "validation": int(len(dataset.validation)),
            "test": int(len(dataset.test)),
        },
        "library_versions": {
            "python": platform.python_version(),
            "numpy": package_version("numpy"),
            "pandas": package_version("pandas"),
            "scikit_learn": package_version("scikit-learn"),
            "joblib": package_version("joblib"),
        },
        "git_commit_sha": git_commit_sha,
        "created_at": created_at,
    }
    # Metadata를 Bundle 완료 표식으로 사용하기 위해 마지막에 기록합니다.
    _atomic_write_json(paths["metadata"], metadata)

    return PacketIFTrainingArtifacts(
        model_path=paths["model"],
        metadata_path=paths["metadata"],
        training_report_path=paths["report"],
        threshold=threshold,
        model_sha256=model_sha256,
    )


def anomaly_scores(model: IsolationForest, matrix: np.ndarray) -> np.ndarray:
    """sklearn 점수를 값이 클수록 이상인 Anomaly Score로 변환합니다."""
    raw_scores = model.decision_function(matrix)
    return -np.asarray(raw_scores, dtype=float)


def train_from_files(
    *,
    dataset_path: Path,
    manifest_path: Path,
    artifact_dir: Path,
    model_version: str = DEFAULT_MODEL_VERSION,
    threshold_percentile: float = DEFAULT_THRESHOLD_PERCENTILE,
    n_estimators: int = DEFAULT_N_ESTIMATORS,
    random_state: int = DEFAULT_RANDOM_STATE,
    git_commit_sha: str | None = None,
    overwrite: bool = False,
) -> PacketIFTrainingArtifacts:
    dataset = load_packet_if_dataset(dataset_path, manifest_path)
    commit_sha = git_commit_sha or current_git_commit_sha()
    return train_packet_isolation_forest(
        dataset,
        artifact_dir=artifact_dir,
        model_version=model_version,
        threshold_percentile=threshold_percentile,
        n_estimators=n_estimators,
        random_state=random_state,
        git_commit_sha=commit_sha,
        manifest_sha256=file_sha256(manifest_path),
        overwrite=overwrite,
    )


def current_git_commit_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("unable to resolve current Git commit SHA") from exc
    commit_sha = result.stdout.strip()
    _validate_git_commit_sha(commit_sha)
    return commit_sha


def _build_training_report(
    *,
    dataset: PacketIFDataset,
    train_scores: np.ndarray,
    validation_scores: np.ndarray,
    test_scores: np.ndarray,
    threshold: float,
    threshold_percentile: float,
) -> dict[str, Any]:
    test_labels = dataset.test["traffic_label"].astype(str).to_numpy()
    return {
        "threshold": threshold,
        "threshold_percentile": float(threshold_percentile),
        "threshold_operator": PACKET_IF_THRESHOLD_OPERATOR,
        "score_direction": PACKET_IF_SCORE_DIRECTION,
        "splits": {
            "train": _score_summary(train_scores, threshold),
            "validation": _score_summary(validation_scores, threshold),
            "test": _score_summary(test_scores, threshold),
        },
        "test_by_label": {
            label: _score_summary(test_scores[test_labels == label], threshold)
            for label in (NORMAL_LABEL, ATTACK_LABEL)
        },
    }


def _score_summary(scores: np.ndarray, threshold: float) -> dict[str, float | int]:
    if scores.size == 0:
        raise ValueError("score summary requires at least one value")
    anomaly_count = int(np.sum(scores > threshold))
    return {
        "row_count": int(scores.size),
        "anomaly_count": anomaly_count,
        "anomaly_rate": float(anomaly_count / scores.size),
        "score_min": float(np.min(scores)),
        "score_max": float(np.max(scores)),
        "score_mean": float(np.mean(scores)),
    }


def _artifact_paths(artifact_dir: Path) -> dict[str, Path]:
    return {
        "model": artifact_dir / PACKET_IF_MODEL_FILENAME,
        "metadata": artifact_dir / PACKET_IF_METADATA_FILENAME,
        "report": artifact_dir / PACKET_IF_TRAINING_REPORT_FILENAME,
    }


def _prepare_artifact_directory(
    paths: dict[str, Path],
    *,
    overwrite: bool,
) -> None:
    artifact_dir = paths["model"].parent
    artifact_dir.mkdir(parents=True, exist_ok=True)
    existing = [path for path in paths.values() if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Packet IF artifact already exists; use overwrite=True to replace it: "
            + ", ".join(str(path) for path in existing)
        )


def _atomic_joblib_dump(model: IsolationForest, destination: Path) -> None:
    temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
    try:
        joblib.dump(model, temporary)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_write_json(destination: Path, payload: dict[str, Any]) -> None:
    temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _validate_training_options(
    *,
    model_version: str,
    threshold_percentile: float,
    n_estimators: int,
    random_state: int,
    git_commit_sha: str,
    manifest_sha256: str,
) -> None:
    if not isinstance(model_version, str) or not model_version.strip():
        raise ValueError("model_version must be a non-empty string")
    if (
        isinstance(threshold_percentile, bool)
        or not isinstance(threshold_percentile, Real)
        or not isfinite(float(threshold_percentile))
        or not 0 < threshold_percentile < 100
    ):
        raise ValueError("threshold_percentile must be greater than 0 and less than 100")
    if (
        isinstance(n_estimators, bool)
        or not isinstance(n_estimators, int)
        or n_estimators <= 0
    ):
        raise ValueError("n_estimators must be a positive integer")
    if isinstance(random_state, bool) or not isinstance(random_state, int):
        raise ValueError("random_state must be an integer")
    _validate_git_commit_sha(git_commit_sha)
    _validate_sha256(manifest_sha256, "manifest_sha256")


def _validate_git_commit_sha(value: str) -> None:
    if not isinstance(value, str) or len(value) != 40 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("git_commit_sha must be a lowercase 40-character SHA1")


def _validate_sha256(value: str, field_name: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError(f"{field_name} must be a lowercase 64-character SHA256")


def _utc_now_string() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Packet Isolation Forest 학습")
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--model-version", default=DEFAULT_MODEL_VERSION)
    parser.add_argument(
        "--threshold-percentile",
        type=float,
        default=DEFAULT_THRESHOLD_PERCENTILE,
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=DEFAULT_N_ESTIMATORS,
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=DEFAULT_RANDOM_STATE,
    )
    parser.add_argument("--git-commit-sha", default=None)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    artifacts = train_from_files(
        dataset_path=args.dataset,
        manifest_path=args.manifest,
        artifact_dir=args.artifact_dir,
        model_version=args.model_version,
        threshold_percentile=args.threshold_percentile,
        n_estimators=args.n_estimators,
        random_state=args.random_state,
        git_commit_sha=args.git_commit_sha,
        overwrite=args.overwrite,
    )
    logger.info("Packet IF model: %s", artifacts.model_path)
    logger.info("Packet IF metadata: %s", artifacts.metadata_path)
    logger.info("Packet IF threshold: %.8f", artifacts.threshold)


if __name__ == "__main__":
    main()
