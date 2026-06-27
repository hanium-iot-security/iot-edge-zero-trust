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
        _model_cache[resolved_path] = joblib.load(resolved_path)
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
