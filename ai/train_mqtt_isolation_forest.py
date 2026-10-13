"""Train an offline MQTT IF candidate from reviewed normal-group inputs only."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version as package_version
import json
from math import isfinite
from numbers import Real
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from ai.mqtt_if_artifact import (
    MQTT_IF_ARTIFACT_SCHEMA_VERSION, MQTT_IF_BUNDLE_FILENAMES,
    MQTT_IF_METADATA_FILENAME, MQTT_IF_MODEL_FILENAME, MQTT_IF_REPORT_FILENAME,
    inspect_mqtt_if_bundle, load_inspected_mqtt_if_artifact,
    mqtt_if_bundle_sha256_bytes, score_mqtt_feature_rows,
)
from ai.mqtt_if_contract import (
    MQTT_IF_FEATURES, MQTT_IF_FEATURE_VERSION, MQTT_IF_NOMINAL_WINDOW_SECONDS,
    MQTT_IF_SCORE_DIRECTION, MQTT_IF_THRESHOLD_OPERATOR, MQTT_IF_TRANSFORM_VERSION,
    mqtt_feature_matrix, mqtt_interval_semantics,
)
from ai.mqtt_if_dataset import load_mqtt_if_dataset


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROLES = ("train", "calibration", "validation")


@dataclass(frozen=True)
class MQTTIFTrainingArtifacts:
    artifact_dir: Path
    model_path: Path
    metadata_path: Path
    training_report_path: Path
    threshold: float
    model_sha256: str
    training_report_sha256: str
    bundle_sha256: str


def train_from_files(
    manifest_path: Path,
    *,
    artifact_dir: Path,
    model_version: str,
    threshold_percentile: float,
    n_estimators: int = 100,
    random_state: int = 42,
) -> MQTTIFTrainingArtifacts:
    """Fit train only; calibrate on normal calibration; report held-out validation.

    The explicit lower-tail percentile is an experiment setting, not a quality
    acceptance criterion. This function neither grants data approval nor activates
    the candidate. It always loads inputs through the MQTT dataset contract.
    """
    _validate_options(model_version, threshold_percentile, n_estimators, random_state)
    artifact_dir = Path(artifact_dir)
    if artifact_dir.name != model_version:
        raise ValueError("artifact directory name must match model_version")
    if artifact_dir.exists() or artifact_dir.is_symlink():
        raise FileExistsError("artifact already exists; use a new version directory")
    manifest_path = Path(manifest_path).resolve()
    artifact_dir = artifact_dir.resolve()
    if artifact_dir.is_relative_to(manifest_path.parent):
        raise ValueError("artifact directory must be outside the dataset input directory")
    dataset = load_mqtt_if_dataset(manifest_path)
    matrices = {role: mqtt_feature_matrix(dataset.rows[role]) for role in ROLES}
    if any(len(matrix) == 0 for matrix in matrices.values()):
        raise ValueError("train, calibration and validation must each contain selected rows")
    source = _source_provenance()
    model = IsolationForest(
        n_estimators=n_estimators, contamination="auto", random_state=random_state, n_jobs=1,
    )
    model.fit(matrices["train"])
    scores = {role: _decision_scores(model, matrices[role]) for role in ROLES}
    threshold = float(np.percentile(scores["calibration"], threshold_percentile, method="linear"))
    contract = {
        "model_version": model_version,
        "feature_order": list(MQTT_IF_FEATURES),
        "score_method": "decision_function",
        "score_direction": MQTT_IF_SCORE_DIRECTION,
        "threshold_operator": MQTT_IF_THRESHOLD_OPERATOR,
        "threshold": threshold,
        "threshold_source": "normal_calibration",
        "threshold_percentile": float(threshold_percentile),
        "percentile_method": "linear",
        "interval_semantics": mqtt_interval_semantics(),
    }
    common = {
        **contract,
        "scope": "offline_candidate_only", "training_approved": False,
        "operational_activation_verified": False,
        "evaluation_scope": "held_out_normal_alarm_rates_only",
        "threshold_is_acceptance_criterion": False,
        "dataset_provenance": dataset.provenance,
        "source_code": source,
        "training_parameters": {
            "n_estimators": n_estimators, "contamination": "auto",
            "random_state": random_state, "n_jobs": 1,
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    report = {
        **common,
        "interpretation": (
            "Normal-only candidate measurements. Alarm rates are not attack detection, "
            "precision, recall, production performance or model acceptance. Calibration "
            "rates are in-sample threshold diagnostics; validation groups are held out."
        ),
        "splits": {
            role: _score_summary(scores[role], threshold, dataset.rows[role]) for role in ROLES
        },
        "validation_by_device": _group_summaries(
            dataset.rows["validation"], scores["validation"], threshold, "device_id",
        ),
        "validation_by_group": _group_summaries(
            dataset.rows["validation"], scores["validation"], threshold, "source_capture_group_id",
        ),
    }
    with _bundle_directory(artifact_dir) as staging:
        joblib.dump(model, staging / MQTT_IF_MODEL_FILENAME)
        _write_json(staging / MQTT_IF_REPORT_FILENAME, report)
        model_sha = _file_sha(staging / MQTT_IF_MODEL_FILENAME)
        report_sha = _file_sha(staging / MQTT_IF_REPORT_FILENAME)
        metadata = {
            **common,
            "artifact_schema_version": MQTT_IF_ARTIFACT_SCHEMA_VERSION,
            "model_type": "IsolationForest",
            "model_filename": MQTT_IF_MODEL_FILENAME, "model_sha256": model_sha,
            "training_report_filename": MQTT_IF_REPORT_FILENAME,
            "training_report_sha256": report_sha,
            "feature_version": MQTT_IF_FEATURE_VERSION,
            "transform_version": MQTT_IF_TRANSFORM_VERSION,
            "nominal_window_seconds": MQTT_IF_NOMINAL_WINDOW_SECONDS,
            "scaler_type": None,
            "library_versions": {
                "python": platform.python_version(),
                **{key: package_version(package) for key, package in (
                    ("numpy", "numpy"), ("scipy", "scipy"),
                    ("scikit_learn", "scikit-learn"), ("joblib", "joblib"),
                )},
            },
        }
        _write_json(staging / MQTT_IF_METADATA_FILENAME, metadata)
        pin = mqtt_if_bundle_sha256_bytes({name: (staging / name).read_bytes() for name in MQTT_IF_BUNDLE_FILENAMES})
        inspection = inspect_mqtt_if_bundle(
            staging, expected_bundle_sha256=pin, expected_model_version=model_version,
        )
        loaded = load_inspected_mqtt_if_artifact(inspection)
        predictions = score_mqtt_feature_rows(loaded, dataset.rows["validation"])
        if not np.array_equal([p.raw_decision_score for p in predictions], scores["validation"]):
            raise ValueError("published-model validation scores differ from training report")
        if [p.is_anomaly for p in predictions] != list(scores["validation"] < threshold):
            raise ValueError("published-model threshold decisions differ from training report")
    return MQTTIFTrainingArtifacts(
        artifact_dir=artifact_dir, model_path=artifact_dir / MQTT_IF_MODEL_FILENAME,
        metadata_path=artifact_dir / MQTT_IF_METADATA_FILENAME,
        training_report_path=artifact_dir / MQTT_IF_REPORT_FILENAME,
        threshold=threshold, model_sha256=model_sha, training_report_sha256=report_sha,
        bundle_sha256=pin,
    )


def _decision_scores(model, matrix):
    scores = np.asarray(model.decision_function(matrix), dtype=float)
    if scores.shape != (len(matrix),) or not np.isfinite(scores).all():
        raise ValueError("model returned invalid decision scores")
    return scores


def _score_summary(scores, threshold, rows):
    alarms = int(np.sum(scores < threshold))
    return {
        "row_count": len(rows), "alarm_count": alarms, "normal_alarm_rate": alarms / len(rows),
        "score_min": float(np.min(scores)), "score_max": float(np.max(scores)),
        "score_mean": float(np.mean(scores)),
        "single_message_fallback_count": sum(row["publish_count"] == 1 for row in rows),
    }


def _group_summaries(rows, scores, threshold, field):
    result = {}
    for key in sorted({row[field] for row in rows}):
        indices = [index for index, row in enumerate(rows) if row[field] == key]
        result[key] = _score_summary(scores[indices], threshold, [rows[i] for i in indices])
    return result


def _source_provenance():
    def git(*args):
        return subprocess.check_output(
            ["git", "-C", str(PROJECT_ROOT), *args], text=True, timeout=10,
        ).rstrip("\r\n")
    commit = git("rev-parse", "HEAD")
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise ValueError("source HEAD must be an exact Git commit SHA")
    status = git("status", "--porcelain", "--untracked-files=normal")
    return {"git_commit_sha": commit, "dirty": bool(status), "working_tree_status": status.splitlines()}


def _validate_options(model_version, percentile, n_estimators, random_state):
    if (not isinstance(model_version, str) or not model_version or model_version != model_version.strip()
            or model_version in (".", "..") or any(c in model_version for c in '/\\')):
        raise ValueError("model_version must be a nonempty version directory name")
    if isinstance(percentile, (bool, np.bool_)) or not isinstance(percentile, Real) or not isfinite(float(percentile)) or not 0 < percentile < 100:
        raise ValueError("threshold_percentile must be finite and strictly between 0 and 100")
    if type(n_estimators) is not int or n_estimators <= 0:
        raise ValueError("n_estimators must be a positive integer")
    if type(random_state) is not int or not 0 <= random_state < 2**32:
        raise ValueError("random_state must be an integer in [0, 2**32)")


def _file_sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")


@contextmanager
def _bundle_directory(destination):
    """Publish a complete new Bundle using the existing Packet trainer pattern."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    lock = destination.parent / ("." + destination.name + ".build.lock")
    descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    staging = None
    try:
        staging = Path(tempfile.mkdtemp(prefix="." + destination.name + ".", suffix=".tmp", dir=destination.parent))
        yield staging
        for name in MQTT_IF_BUNDLE_FILENAMES:
            with (staging / name).open("r+b") as handle:
                os.fsync(handle.fileno())
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("artifact appeared during training; refusing to replace it")
        if staging.resolve().parent != destination.parent.resolve():
            raise ValueError("staging directory escaped the output parent")
        os.rename(staging, destination)
        staging = None
    finally:
        if staging is not None:
            if staging.resolve().parent != destination.parent.resolve() or staging.is_symlink():
                raise ValueError("refusing cleanup outside the output staging directory")
            shutil.rmtree(staging)
        lock.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--model-version", required=True)
    parser.add_argument("--threshold-percentile", required=True, type=float,
                        help="Explicit lower-tail percentile of normal calibration scores; not an acceptance criterion")
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args(argv)
    artifacts = train_from_files(
        args.manifest, artifact_dir=args.artifact_dir, model_version=args.model_version,
        threshold_percentile=args.threshold_percentile, n_estimators=args.n_estimators,
        random_state=args.random_state,
    )
    print(json.dumps({
        "scope": "offline_candidate_only", "training_approved": False,
        "operational_activation_verified": False,
        "artifact_dir": str(artifacts.artifact_dir), "threshold": artifacts.threshold,
        "bundle_sha256": artifacts.bundle_sha256,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
