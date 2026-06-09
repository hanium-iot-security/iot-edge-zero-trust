"""ai_detector 및 train 모듈 단위 테스트."""

from pathlib import Path

import joblib
import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from ai.train_isolation_forest import validate_contamination, load_features
from edge.detection.ai_detector import clear_model_cache, extract_features, load_model, predict_feature_window
from edge.detection.rule_detector import AI_ANOMALY, DETECTOR_AI, ISOLATION_FOREST_FEATURES


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def trained_model_path(tmp_path: Path) -> Path:
    """소규모 정상 데이터로 학습한 임시 Isolation Forest 모델 경로."""
    rng = np.random.default_rng(42)
    X = rng.normal(loc=[2, 24, 24, 5, 5], scale=[0.3, 1, 1, 0.3, 0.3], size=(200, 5))
    model = IsolationForest(n_estimators=10, contamination=0.01, random_state=42)
    model.fit(X)
    model_path = tmp_path / "isolation_forest.joblib"
    joblib.dump(model, model_path)
    return model_path


@pytest.fixture()
def normal_feature_row() -> dict:
    return {
        "publish_count": 2,
        "avg_payload_size": 24.0,
        "max_payload_size": 24,
        "avg_message_interval": 5.0,
        "min_message_interval": 5.0,
    }


@pytest.fixture()
def anomaly_feature_row() -> dict:
    return {
        "publish_count": 30,
        "avg_payload_size": 24.0,
        "max_payload_size": 24,
        "avg_message_interval": 0.2,
        "min_message_interval": 0.1,
    }


# ---------------------------------------------------------------------------
# load_features (train_isolation_forest)
# ---------------------------------------------------------------------------

class TestLoadFeatures:
    def test_valid_csv_returns_only_five_columns(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "features.csv"
        csv_path.write_text(
            "publish_count,avg_payload_size,max_payload_size,avg_message_interval,min_message_interval,extra_col\n"
            "2,24.0,24,5.0,5.0,ignored\n"
        )
        df = load_features(csv_path)
        assert list(df.columns) == list(ISOLATION_FOREST_FEATURES)
        assert len(df) == 1

    def test_missing_column_raises(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "features.csv"
        csv_path.write_text("publish_count,avg_payload_size\n2,24.0\n")
        with pytest.raises(ValueError, match="필수 컬럼"):
            load_features(csv_path)

    def test_null_value_raises(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "features.csv"
        csv_path.write_text(
            "publish_count,avg_payload_size,max_payload_size,avg_message_interval,min_message_interval\n"
            "2,,24,5.0,5.0\n"
        )
        with pytest.raises(ValueError, match="결측치"):
            load_features(csv_path)


# ---------------------------------------------------------------------------
# validate_contamination
# ---------------------------------------------------------------------------

class TestValidateContamination:
    def test_valid_values(self) -> None:
        for value in (0.01, 0.05, 0.1, 0.5):
            validate_contamination(value)  # 예외 없어야 함

    def test_zero_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_contamination(0.0)

    def test_negative_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_contamination(-0.1)

    def test_above_half_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_contamination(0.51)


# ---------------------------------------------------------------------------
# extract_features
# ---------------------------------------------------------------------------

class TestExtractFeatures:
    def test_valid_row_returns_correct_shape(self, normal_feature_row: dict) -> None:
        X = extract_features(normal_feature_row)
        assert X.shape == (1, len(ISOLATION_FOREST_FEATURES))

    def test_valid_row_returns_correct_values(self, normal_feature_row: dict) -> None:
        X = extract_features(normal_feature_row)
        expected = [normal_feature_row[col] for col in ISOLATION_FOREST_FEATURES]
        assert list(X[0]) == pytest.approx(expected)

    def test_missing_key_raises(self, normal_feature_row: dict) -> None:
        del normal_feature_row["publish_count"]
        with pytest.raises(KeyError):
            extract_features(normal_feature_row)

    def test_all_keys_missing_raises(self) -> None:
        with pytest.raises(KeyError):
            extract_features({})


# ---------------------------------------------------------------------------
# load_model
# ---------------------------------------------------------------------------

class TestLoadModel:
    def test_nonexistent_path_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_model(tmp_path / "not_exist.joblib")

    def test_valid_model_loads(self, trained_model_path: Path) -> None:
        model = load_model(trained_model_path)
        assert isinstance(model, IsolationForest)

    def test_model_is_cached(self, trained_model_path: Path) -> None:
        model_a = load_model(trained_model_path)
        model_b = load_model(trained_model_path)
        assert model_a is model_b

    def test_clear_specific_cache(self, trained_model_path: Path) -> None:
        model_a = load_model(trained_model_path)
        clear_model_cache(trained_model_path)
        model_b = load_model(trained_model_path)
        assert model_a is not model_b

    def test_clear_all_cache(self, trained_model_path: Path) -> None:
        model_a = load_model(trained_model_path)
        clear_model_cache()
        model_b = load_model(trained_model_path)
        assert model_a is not model_b


# ---------------------------------------------------------------------------
# predict_feature_window
# ---------------------------------------------------------------------------

class TestPredictFeatureWindow:
    def test_returns_expected_keys(self, trained_model_path: Path, normal_feature_row: dict) -> None:
        result = predict_feature_window(normal_feature_row, trained_model_path)
        assert {"is_anomaly", "prediction", "anomaly_score", "detector_type", "event_type"} == set(result.keys())

    def test_normal_input_is_not_anomaly(self, trained_model_path: Path, normal_feature_row: dict) -> None:
        result = predict_feature_window(normal_feature_row, trained_model_path)
        assert result["is_anomaly"] is False
        assert result["prediction"] == 1
        assert result["event_type"] is None
        assert result["detector_type"] == DETECTOR_AI

    def test_anomaly_input_is_anomaly(self, trained_model_path: Path, anomaly_feature_row: dict) -> None:
        result = predict_feature_window(anomaly_feature_row, trained_model_path)
        assert result["is_anomaly"] is True
        assert result["prediction"] == -1
        assert result["event_type"] == AI_ANOMALY

    def test_anomaly_score_is_float(self, trained_model_path: Path, normal_feature_row: dict) -> None:
        result = predict_feature_window(normal_feature_row, trained_model_path)
        assert isinstance(result["anomaly_score"], float)
