"""재현 가능한 Packet Isolation Forest Artifact Bundle을 학습합니다."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
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
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Iterator

import joblib
import numpy as np
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
)
from ai.packet_if_artifact import packet_if_bundle_sha256
from ai.packet_if_dataset import (
    ATTACK_LABEL,
    NORMAL_LABEL,
    PacketIFDataset,
    file_sha256,
    load_packet_if_dataset,
)
from edge.packet.capture_policy import (
    DEFAULT_CAPTURE_POLICY,
    CapturePolicy,
)


logger = logging.getLogger(__name__)

_TRAINING_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

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
    metadata_sha256: str
    training_report_sha256: str
    bundle_sha256: str


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
    capture_policy: CapturePolicy = DEFAULT_CAPTURE_POLICY,
    before_publish: Callable[[], None] | None = None,
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
    _validate_dataset_capture_policy(dataset, capture_policy)
    _validate_artifact_destination(
        artifact_dir=artifact_dir,
        model_version=model_version,
    )

    train_matrix = packet_feature_matrix(dataset.train.to_dict(orient="records"))
    validation_matrix = packet_feature_matrix(
        dataset.validation.to_dict(orient="records")
    )
    test_matrix = packet_feature_matrix(dataset.test.to_dict(orient="records"))
    if train_matrix.shape[0] == 0 or validation_matrix.shape[0] == 0:
        raise ValueError("train and validation datasets must contain rows")

    with _artifact_staging_directory(
        artifact_dir,
        before_publish=before_publish,
    ) as staging_dir:
        staging_paths = _artifact_paths(staging_dir)
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
        threshold = float(
            np.percentile(validation_scores, threshold_percentile)
        )

        _write_joblib(staging_paths["model"], model)
        model_sha256 = file_sha256(staging_paths["model"])
        created_at = _utc_now_string()

        report = _build_training_report(
            dataset=dataset,
            train_scores=train_scores,
            validation_scores=validation_scores,
            test_scores=test_scores,
            threshold=threshold,
            threshold_percentile=threshold_percentile,
        )
        _write_json(staging_paths["report"], report)
        training_report_sha256 = file_sha256(staging_paths["report"])

        metadata = {
            "artifact_schema_version": PACKET_IF_ARTIFACT_SCHEMA_VERSION,
            "model_type": "IsolationForest",
            "model_version": model_version,
            "model_filename": PACKET_IF_MODEL_FILENAME,
            "model_sha256": model_sha256,
            "training_report_filename": PACKET_IF_TRAINING_REPORT_FILENAME,
            "training_report_sha256": training_report_sha256,
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
            "capture_policy_version": capture_policy.version,
            "capture_policy": _capture_policy_metadata(capture_policy),
            "normalization": {
                "version": PACKET_IF_TRANSFORM_VERSION,
                "nominal_window_seconds": PACKET_IF_NOMINAL_WINDOW_SECONDS,
                "packet_count_formula": PACKET_IF_PACKET_COUNT_FORMULA,
                "total_bytes_formula": PACKET_IF_TOTAL_BYTES_FORMULA,
            },
            "dataset_version": dataset.manifest.dataset_version,
            "normal_policy_version": dataset.manifest.normal_policy_version,
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
        _write_json(staging_paths["metadata"], metadata)
        metadata_sha256 = file_sha256(staging_paths["metadata"])
        bundle_sha256 = packet_if_bundle_sha256(staging_dir)

    paths = _artifact_paths(artifact_dir)
    return PacketIFTrainingArtifacts(
        model_path=paths["model"],
        metadata_path=paths["metadata"],
        training_report_path=paths["report"],
        threshold=threshold,
        model_sha256=model_sha256,
        metadata_sha256=metadata_sha256,
        training_report_sha256=training_report_sha256,
        bundle_sha256=bundle_sha256,
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
    capture_policy: CapturePolicy | None = None,
) -> PacketIFTrainingArtifacts:
    dataset_sha256 = file_sha256(dataset_path)
    manifest_sha256 = file_sha256(manifest_path)
    dataset = load_packet_if_dataset(dataset_path, manifest_path)
    _require_training_inputs_unchanged(
        dataset_path,
        manifest_path,
        dataset_sha256=dataset_sha256,
        manifest_sha256=manifest_sha256,
    )
    if dataset.manifest.dataset_sha256 != dataset_sha256:
        raise RuntimeError(
            "Packet IF training Dataset changed while loading: "
            f"{dataset_path}"
        )
    commit_sha = git_commit_sha or current_git_commit_sha()
    resolved_capture_policy = capture_policy or CapturePolicy.from_env()
    return train_packet_isolation_forest(
        dataset,
        artifact_dir=artifact_dir,
        model_version=model_version,
        threshold_percentile=threshold_percentile,
        n_estimators=n_estimators,
        random_state=random_state,
        git_commit_sha=commit_sha,
        manifest_sha256=manifest_sha256,
        capture_policy=resolved_capture_policy,
        before_publish=lambda: _require_training_inputs_unchanged(
            dataset_path,
            manifest_path,
            dataset_sha256=dataset_sha256,
            manifest_sha256=manifest_sha256,
        ),
    )


def _require_training_inputs_unchanged(
    dataset_path: Path,
    manifest_path: Path,
    *,
    dataset_sha256: str,
    manifest_sha256: str,
) -> None:
    for path, expected_sha256, label in (
        (dataset_path, dataset_sha256, "Dataset"),
        (manifest_path, manifest_sha256, "Dataset Manifest"),
    ):
        if file_sha256(path) != expected_sha256:
            raise RuntimeError(
                f"Packet IF training {label} changed during training: {path}"
            )


def current_git_commit_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            cwd=_TRAINING_REPOSITORY_ROOT,
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
        "dataset_version": dataset.manifest.dataset_version,
        "normal_policy_version": dataset.manifest.normal_policy_version,
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


def _validate_dataset_capture_policy(
    dataset: PacketIFDataset,
    capture_policy: CapturePolicy,
) -> None:
    if dataset.manifest.capture_policy != capture_policy:
        raise ValueError(
            "Packet IF dataset Capture Policy mismatch: "
            f"expected={capture_policy!r}, "
            f"actual={dataset.manifest.capture_policy!r}"
        )

    minimum_eligible_duration = max(
        0.0,
        capture_policy.minimum_duration_seconds - capture_policy.epsilon_seconds,
    )
    for split_name, frame in (
        ("train", dataset.train),
        ("validation", dataset.validation),
        ("test", dataset.test),
    ):
        for row in frame.to_dict(orient="records"):
            duration = float(row["captured_duration_seconds"])
            if duration < minimum_eligible_duration:
                raise ValueError(
                    "Packet IF dataset row is below the Capture Policy minimum "
                    f"duration: split={split_name}, "
                    f"packet_feature_log_id={row['packet_feature_log_id']}, "
                    f"duration={duration}, minimum={minimum_eligible_duration}"
                )


def _capture_policy_metadata(capture_policy: CapturePolicy) -> dict[str, Any]:
    return {
        "version": capture_policy.version,
        "nominal_window_seconds": PACKET_IF_NOMINAL_WINDOW_SECONDS,
        "max_start_delay_seconds": capture_policy.max_start_delay_seconds,
        "minimum_duration_seconds": capture_policy.minimum_duration_seconds,
        "epsilon_seconds": capture_policy.epsilon_seconds,
        "minimum_coverage_ratio": (
            capture_policy.minimum_duration_seconds
            / PACKET_IF_NOMINAL_WINDOW_SECONDS
        ),
    }


def _artifact_paths(artifact_dir: Path) -> dict[str, Path]:
    return {
        "model": artifact_dir / PACKET_IF_MODEL_FILENAME,
        "metadata": artifact_dir / PACKET_IF_METADATA_FILENAME,
        "report": artifact_dir / PACKET_IF_TRAINING_REPORT_FILENAME,
    }


def _validate_artifact_destination(
    *,
    artifact_dir: Path,
    model_version: str,
) -> None:
    if artifact_dir.name != model_version:
        raise ValueError(
            "Packet IF artifact directory name must match model_version: "
            f"directory={artifact_dir.name!r}, model_version={model_version!r}"
        )
    if artifact_dir.exists():
        raise FileExistsError(
            "Packet IF artifact already exists; use a new version directory "
            f"to retrain: {artifact_dir}"
        )


@contextmanager
def _artifact_staging_directory(
    artifact_dir: Path,
    *,
    before_publish: Callable[[], None] | None = None,
) -> Iterator[Path]:
    parent = artifact_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    lock_path = parent / f".{artifact_dir.name}.build.lock"
    try:
        lock_descriptor = os.open(
            lock_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError as exc:
        raise RuntimeError(
            f"another Packet IF build holds the lock: {lock_path}"
        ) from exc

    staging_dir: Path | None = None
    try:
        try:
            os.write(
                lock_descriptor,
                f"pid={os.getpid()}\n".encode("ascii"),
            )
        finally:
            os.close(lock_descriptor)
        staging_dir = Path(
            tempfile.mkdtemp(
                prefix=f".{artifact_dir.name}.",
                suffix=".tmp",
                dir=parent,
            )
        )
        yield staging_dir
        _fsync_directory(staging_dir)
        if artifact_dir.exists():
            raise FileExistsError(
                "Packet IF artifact appeared during build; refusing to replace "
                f"it: {artifact_dir}"
            )
        if before_publish is not None:
            before_publish()
        os.rename(staging_dir, artifact_dir)
        staging_dir = None
        _fsync_directory(parent)
    finally:
        if staging_dir is not None:
            shutil.rmtree(staging_dir, ignore_errors=True)
        lock_path.unlink(missing_ok=True)


def _write_joblib(destination: Path, model: IsolationForest) -> None:
    joblib.dump(model, destination)
    _fsync_file(destination)


def _write_json(destination: Path, payload: dict[str, Any]) -> None:
    destination.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _fsync_file(destination)


def _fsync_file(path: Path) -> None:
    # Windows의 os.fsync()는 쓰기 가능한 CRT descriptor가 필요합니다.
    with path.open("r+b") as handle:
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
    )
    logger.info("Packet IF model: %s", artifacts.model_path)
    logger.info("Packet IF metadata: %s", artifacts.metadata_path)
    logger.info("Packet IF threshold: %.8f", artifacts.threshold)
    logger.info("Packet IF bundle SHA256: %s", artifacts.bundle_sha256)


if __name__ == "__main__":
    main()
