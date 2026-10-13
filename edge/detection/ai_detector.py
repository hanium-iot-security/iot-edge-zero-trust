"""Isolation Forest 추론 도우미.

입력 feature:
- publish_count
- avg_payload_size
- max_payload_size
- avg_message_interval
- min_message_interval
"""

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.utils.validation import check_is_fitted

from ai.mqtt_if_artifact import MQTTIFArtifact, score_mqtt_feature_rows

from edge.detection.rule_detector import AI_ANOMALY, DETECTOR_AI, ISOLATION_FOREST_FEATURES

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = Path("ai/models/isolation_forest.joblib")

_model_cache: dict[Path, IsolationForest] = {}


def clear_model_cache(model_path: Path | None = None) -> None:
    """캐시된 모델을 제거합니다. model_path 미지정 시 전체 캐시를 초기화합니다."""
    if model_path is None:
        _model_cache.clear()
    else:
        _model_cache.pop(model_path.resolve(), None)


def load_model(model_path: Path = DEFAULT_MODEL_PATH) -> IsolationForest:
    resolved_path = model_path.resolve()
    if resolved_path not in _model_cache:
        if not resolved_path.exists():
            raise FileNotFoundError(f"모델 파일이 없습니다: {resolved_path}")
        model = joblib.load(resolved_path)
        if type(model) is not IsolationForest:
            raise ValueError("MQTT legacy model must be an IsolationForest")
        check_is_fitted(model, ("estimators_", "estimators_features_", "offset_", "n_features_in_"))
        if model.n_features_in_ != len(ISOLATION_FOREST_FEATURES):
            raise ValueError("MQTT legacy model must have exactly five features")
        names = getattr(model, "feature_names_in_", None)
        if names is not None and tuple(names) != ISOLATION_FOREST_FEATURES:
            raise ValueError("MQTT legacy model feature order mismatch")
        scores = np.asarray(model.decision_function(np.zeros((1, len(ISOLATION_FOREST_FEATURES)))))
        if scores.shape != (1,) or not np.isfinite(scores).all():
            raise ValueError("MQTT legacy model returned invalid decision scores")
        _model_cache[resolved_path] = model
    return _model_cache[resolved_path]


def extract_features(feature_row: dict[str, Any]) -> np.ndarray:
    missing = [col for col in ISOLATION_FOREST_FEATURES if col not in feature_row]
    if missing:
        raise KeyError(f"feature_row에 필수 키가 없습니다: {missing}")
    return np.array([[feature_row[col] for col in ISOLATION_FOREST_FEATURES]], dtype=float)


def predict_feature_window(
    feature_row: dict[str, Any],
    model_path: Path = DEFAULT_MODEL_PATH,
) -> dict[str, Any]:
    model = load_model(model_path)
    X = extract_features(feature_row)

    prediction = int(model.predict(X)[0])
    anomaly_score = float(model.decision_function(X)[0])
    is_anomaly = prediction == -1

    return {
        "is_anomaly": is_anomaly,
        "prediction": prediction,
        "anomaly_score": anomaly_score,
        "detector_type": DETECTOR_AI,
        "event_type": AI_ANOMALY if is_anomaly else None,
    }


def predict_bundle_feature_window(
    feature_row: dict[str, Any], artifact: MQTTIFArtifact,
) -> dict[str, Any]:
    """Use the inspected Bundle's threshold, not sklearn's implicit zero boundary."""
    result = score_mqtt_feature_rows(artifact, [feature_row])[0]
    return {
        "is_anomaly": result.is_anomaly,
        "prediction": -1 if result.is_anomaly else 1,
        "anomaly_score": result.anomaly_score,
        "detector_type": DETECTOR_AI,
        "event_type": AI_ANOMALY if result.is_anomaly else None,
        "model_version": result.model_version,
        "bundle_sha256": result.bundle_sha256,
        "raw_decision_score": result.raw_decision_score,
        "threshold": result.threshold,
        "feature_values": dict(zip(ISOLATION_FOREST_FEATURES, result.feature_values, strict=True)),
        "interval_is_fallback": result.interval_is_fallback,
    }
