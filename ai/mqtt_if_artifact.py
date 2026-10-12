"""Read-once MQTT IF Bundle inspection and offline scoring.

Integrity checks do not certify the report's claims or dataset eligibility.
Only deserialize a Bundle whose external pin comes from a trusted source:
joblib/pickle can execute code even when its bytes match a hash.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
import hashlib
from importlib.metadata import version as package_version
import io
import json
from math import isfinite
from numbers import Real
import os
from pathlib import Path
import platform
import re
import stat
from typing import Any
import warnings

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import InconsistentVersionWarning
from sklearn.utils.validation import check_is_fitted

from ai.mqtt_if_contract import (
    MQTT_IF_FEATURES,
    MQTT_IF_FEATURE_VERSION,
    MQTT_IF_NOMINAL_WINDOW_SECONDS,
    MQTT_IF_SCORE_DIRECTION,
    MQTT_IF_THRESHOLD_OPERATOR,
    MQTT_IF_TRANSFORM_VERSION,
    mqtt_feature_matrix,
    mqtt_interval_semantics,
)


MQTT_IF_ARTIFACT_SCHEMA_VERSION = 1
MQTT_IF_MODEL_FILENAME = "model.joblib"
MQTT_IF_METADATA_FILENAME = "metadata.json"
MQTT_IF_REPORT_FILENAME = "training_report.json"
MQTT_IF_BUNDLE_FILENAMES = (
    MQTT_IF_MODEL_FILENAME,
    MQTT_IF_METADATA_FILENAME,
    MQTT_IF_REPORT_FILENAME,
)
VERIFICATION_SCOPE = "offline_input_bundle_model_contract_only"


@dataclass(frozen=True)
class MQTTIFInspection:
    """A pinned bytes snapshot. Inspection does not unpickle the model."""

    artifact_dir: Path
    bundle_sha256: str
    model_version: str
    threshold: float
    file_sha256: tuple[tuple[str, str], ...]
    _files: tuple[tuple[str, bytes], ...] = field(repr=False)

    @property
    def metadata(self) -> dict[str, Any]:
        return _json_object(dict(self._files)[MQTT_IF_METADATA_FILENAME], "metadata")

    @property
    def report(self) -> dict[str, Any]:
        return _json_object(dict(self._files)[MQTT_IF_REPORT_FILENAME], "report")

    def summary(self) -> dict[str, Any]:
        return {
            "verification_scope": VERIFICATION_SCOPE,
            "bundle_sha256": self.bundle_sha256,
            "file_sha256": dict(self.file_sha256),
            "model_version": self.model_version,
            "threshold": self.threshold,
            "score_method": "decision_function",
            "score_direction": MQTT_IF_SCORE_DIRECTION,
            "threshold_operator": MQTT_IF_THRESHOLD_OPERATOR,
            "interval_semantics": mqtt_interval_semantics(),
            "model_deserialized": False,
            "data_eligibility_verified": False,
            "report_claims_verified": False,
            "operational_activation_verified": False,
        }


@dataclass(frozen=True)
class MQTTIFArtifact:
    inspection: MQTTIFInspection
    model: IsolationForest = field(repr=False)


@dataclass(frozen=True)
class MQTTIFPrediction:
    model_version: str
    bundle_sha256: str
    raw_decision_score: float
    anomaly_score: float
    threshold: float
    is_anomaly: bool
    feature_values: tuple[float, ...]
    interval_is_fallback: bool


def mqtt_if_bundle_sha256_bytes(files: Mapping[str, bytes]) -> str:
    """Hash the three named files with the Packet Bundle framing convention."""
    digest = hashlib.sha256()
    for filename in MQTT_IF_BUNDLE_FILENAMES:
        if filename not in files or not isinstance(files[filename], bytes):
            raise ValueError(f"MQTT IF Bundle is missing bytes: {filename}")
        name = filename.encode("utf-8")
        content = files[filename]
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def inspect_mqtt_if_bundle(
    artifact_dir: Path,
    *,
    expected_bundle_sha256: str,
    expected_model_version: str | None = None,
) -> MQTTIFInspection:
    """Read each file once; verify external pin and JSON before unpickling."""
    expected_pin = _sha256(expected_bundle_sha256, "expected_bundle_sha256")
    artifact_dir = Path(artifact_dir)
    files = {
        name: _read_regular_file(artifact_dir / name)
        for name in MQTT_IF_BUNDLE_FILENAMES
    }
    return _inspect_snapshot(artifact_dir, files, expected_pin, expected_model_version)


def load_inspected_mqtt_if_artifact(inspection: MQTTIFInspection) -> MQTTIFArtifact:
    """Deserialize the inspected bytes, with no path reopen or model cache."""
    # Recheck the in-memory contract; callers cannot bypass inspection by
    # constructing an inconsistent inspection value. Files are never reread.
    inspection = _inspect_snapshot(
        inspection.artifact_dir,
        dict(inspection._files),
        inspection.bundle_sha256,
        inspection.model_version,
    )
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", InconsistentVersionWarning)
            model = joblib.load(io.BytesIO(dict(inspection._files)[MQTT_IF_MODEL_FILENAME]))
    except Exception as exc:
        raise ValueError("unable to deserialize MQTT IF model") from exc
    if type(model) is not IsolationForest:
        raise ValueError("MQTT IF model must be a sklearn IsolationForest")
    try:
        check_is_fitted(model, (
            "estimators_", "estimators_features_", "max_samples_", "offset_", "n_features_in_",
        ))
    except Exception as exc:
        raise ValueError("MQTT IF model must be fitted") from exc
    if model.n_features_in_ != len(MQTT_IF_FEATURES):
        raise ValueError("MQTT IF model must have exactly five features")
    names = getattr(model, "feature_names_in_", None)
    if names is not None and tuple(names) != MQTT_IF_FEATURES:
        raise ValueError("MQTT IF fitted model feature order mismatch")
    if not model.estimators_ or len(model.estimators_) != len(model.estimators_features_):
        raise ValueError("MQTT IF model has inconsistent fitted estimators")
    _finite_number(model.offset_, "model offset")
    # Exercise fitted internals without using real data or asserting accuracy.
    _decision_scores(model, np.zeros((1, len(MQTT_IF_FEATURES))))
    return MQTTIFArtifact(inspection=inspection, model=model)


def score_mqtt_feature_rows(
    artifact: MQTTIFArtifact,
    rows: Iterable[Mapping[str, Any]],
) -> tuple[MQTTIFPrediction, ...]:
    """Offline inference only; no dataset/QC, events, checkpoints or writes."""
    matrix = mqtt_feature_matrix(rows)
    if not len(matrix):
        return ()
    scores = _decision_scores(artifact.model, matrix)
    return tuple(
        MQTTIFPrediction(
            model_version=artifact.inspection.model_version,
            bundle_sha256=artifact.inspection.bundle_sha256,
            raw_decision_score=float(score),
            anomaly_score=float(score),
            threshold=artifact.inspection.threshold,
            is_anomaly=bool(score < artifact.inspection.threshold),
            feature_values=tuple(float(value) for value in vector),
            interval_is_fallback=bool(vector[0] == 1),
        )
        for score, vector in zip(scores, matrix, strict=True)
    )


def _inspect_snapshot(
    artifact_dir: Path,
    files: Mapping[str, bytes],
    expected_pin: str,
    expected_model_version: str | None,
) -> MQTTIFInspection:
    actual_pin = mqtt_if_bundle_sha256_bytes(files)
    if actual_pin != _sha256(expected_pin, "expected_bundle_sha256"):
        raise ValueError("MQTT IF external Bundle SHA256 mismatch")
    metadata = _json_object(files[MQTT_IF_METADATA_FILENAME], "metadata")
    report = _json_object(files[MQTT_IF_REPORT_FILENAME], "report")
    _validate_metadata(metadata)
    model_version = _nonempty_string(metadata.get("model_version"), "model_version")
    if expected_model_version is not None and model_version != expected_model_version:
        raise ValueError("MQTT IF model version mismatch")
    for name, field_name in (
        (MQTT_IF_MODEL_FILENAME, "model_sha256"),
        (MQTT_IF_REPORT_FILENAME, "training_report_sha256"),
    ):
        if hashlib.sha256(files[name]).hexdigest() != _sha256(metadata.get(field_name), field_name):
            raise ValueError(f"MQTT IF {field_name} mismatch")
    # These duplicated fields catch a stale/wrong report, not false statistics.
    for key in ("model_version", "feature_order", "score_method", "score_direction",
                "threshold_operator", "threshold", "threshold_source", "interval_semantics"):
        if key not in report or report[key] != metadata[key]:
            raise ValueError(f"MQTT IF report contract mismatch: {key}")
    _finite_number(report["threshold"], "report threshold")
    _validate_interval_semantics(report["interval_semantics"])
    _validate_libraries(metadata.get("library_versions"))
    return MQTTIFInspection(
        artifact_dir=artifact_dir,
        bundle_sha256=actual_pin,
        model_version=model_version,
        threshold=_finite_number(metadata["threshold"], "threshold"),
        file_sha256=tuple((name, hashlib.sha256(files[name]).hexdigest()) for name in MQTT_IF_BUNDLE_FILENAMES),
        _files=tuple((name, files[name]) for name in MQTT_IF_BUNDLE_FILENAMES),
    )


def _validate_metadata(metadata: dict[str, Any]) -> None:
    schema_version = metadata.get("artifact_schema_version")
    if type(schema_version) is not int or schema_version != MQTT_IF_ARTIFACT_SCHEMA_VERSION:
        raise ValueError("MQTT IF artifact_schema_version mismatch")
    expected = {
        "model_type": "IsolationForest",
        "model_filename": MQTT_IF_MODEL_FILENAME,
        "training_report_filename": MQTT_IF_REPORT_FILENAME,
        "feature_version": MQTT_IF_FEATURE_VERSION,
        "feature_order": list(MQTT_IF_FEATURES),
        "transform_version": MQTT_IF_TRANSFORM_VERSION,
        "score_method": "decision_function",
        "score_direction": MQTT_IF_SCORE_DIRECTION,
        "threshold_operator": MQTT_IF_THRESHOLD_OPERATOR,
        "interval_semantics": mqtt_interval_semantics(),
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ValueError(f"MQTT IF metadata contract mismatch: {key}")
    _validate_interval_semantics(metadata["interval_semantics"])
    if _finite_number(metadata.get("nominal_window_seconds"), "nominal_window_seconds") != MQTT_IF_NOMINAL_WINDOW_SECONDS:
        raise ValueError("MQTT IF nominal_window_seconds mismatch")
    _finite_number(metadata.get("threshold"), "threshold")
    _nonempty_string(metadata.get("threshold_source"), "threshold_source")


def _validate_interval_semantics(semantics: Any) -> None:
    if not isinstance(semantics, dict) or semantics != mqtt_interval_semantics():
        raise ValueError("MQTT IF interval semantics mismatch")
    if semantics["single_message_is_observed_interval"] is not False:
        raise ValueError("MQTT IF single-message interval must be marked fallback")
    _finite_number(semantics["single_message_fallback_seconds"], "single message fallback")


def _validate_libraries(versions: Any) -> None:
    if not isinstance(versions, dict):
        raise ValueError("MQTT IF library_versions must be an object")
    expected_python = _nonempty_string(versions.get("python"), "python version")
    if not re.fullmatch(r"\d+\.\d+\.\d+", expected_python):
        raise ValueError("MQTT IF Python version must include major.minor.patch")
    if expected_python.split(".")[:2] != platform.python_version().split(".")[:2]:
        raise ValueError("MQTT IF Python major/minor version mismatch")
    for key, package in (("numpy", "numpy"), ("scipy", "scipy"),
                         ("scikit_learn", "scikit-learn"), ("joblib", "joblib")):
        if _nonempty_string(versions.get(key), f"{key} version") != package_version(package):
            raise ValueError(f"MQTT IF runtime library version mismatch: {key}")


def _read_regular_file(path: Path) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"MQTT IF Bundle member must be a regular non-symlink file: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError(f"MQTT IF Bundle member changed while opening: {path.name}")
        return stream.read()


def _json_object(content: bytes, label: str) -> dict[str, Any]:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate MQTT IF {label} JSON key: {key}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f"non-finite MQTT IF {label} JSON constant: {value}")

    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_constant=invalid_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid MQTT IF {label} JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"MQTT IF {label} must be a JSON object")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{label} must be an externally supplied lowercase SHA256")
    return value


def _finite_number(value: Any, label: str) -> float:
    if isinstance(value, (bool, np.bool_)) or not isinstance(value, Real):
        raise ValueError(f"{label} must be a finite real number")
    try:
        numeric = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{label} must be finite") from exc
    if not isfinite(numeric):
        raise ValueError(f"{label} must be finite")
    return numeric


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{label} must be a non-empty trimmed string")
    return value


def _decision_scores(model: IsolationForest, matrix: np.ndarray) -> np.ndarray:
    try:
        scores = np.asarray(model.decision_function(matrix), dtype=float)
    except Exception as exc:
        raise ValueError("MQTT IF model could not score the feature matrix") from exc
    if scores.shape != (len(matrix),) or not np.isfinite(scores).all():
        raise ValueError("MQTT IF model returned invalid decision scores")
    return scores
