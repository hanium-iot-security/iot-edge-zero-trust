"""저장된 Isolation Forest 모델로 feature window를 추론합니다."""

import argparse
import logging
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from edge.detection.rule_detector import ISOLATION_FOREST_FEATURES

logger = logging.getLogger(__name__)


def load_model(model_path: Path) -> IsolationForest:
    if not model_path.exists():
        raise FileNotFoundError(f"모델 파일이 없습니다: {model_path}")
    return joblib.load(model_path)


def load_features(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path)

    missing = [col for col in ISOLATION_FOREST_FEATURES if col not in df.columns]
    if missing:
        raise ValueError(f"CSV에 필수 컬럼이 없습니다: {missing}")

    df = df[list(ISOLATION_FOREST_FEATURES)].copy()

    if df.isnull().any().any():
        null_counts = df.isnull().sum()
        raise ValueError(f"결측치가 존재합니다:\n{null_counts[null_counts > 0]}")

    for col in ISOLATION_FOREST_FEATURES:
        df[col] = pd.to_numeric(df[col], errors="raise")

    return df


def predict_csv(model_path: Path, csv_path: Path) -> dict[str, float | int]:
    model = load_model(model_path)
    df = load_features(csv_path)
    X = df.values

    predictions = model.predict(X)
    scores = model.decision_function(X)

    normal_count = sum(1 for p in predictions if p == 1)
    anomaly_count = sum(1 for p in predictions if p == -1)

    result = {
        "total_count": len(predictions),
        "normal_count": int(normal_count),
        "anomaly_count": int(anomaly_count),
        "score_min": float(scores.min()),
        "score_max": float(scores.max()),
        "score_mean": float(scores.mean()),
    }

    logger.info("총 %d개 | 정상: %d개 | 이상: %d개", result["total_count"], result["normal_count"], result["anomaly_count"])
    logger.info("anomaly score 범위: min=%.4f, max=%.4f, mean=%.4f", result["score_min"], result["score_max"], result["score_mean"])

    anomaly_rows = [(i, scores[i]) for i, p in enumerate(predictions) if p == -1]
    if anomaly_rows:
        logger.info("\n이상 탐지 row (index, score):")
        for idx, score in anomaly_rows[:10]:
            feature_values = {col: float(v) for col, v in zip(ISOLATION_FOREST_FEATURES, X[idx])}
            logger.info("  row %d: score=%.4f | %s", idx, score, feature_values)
        if len(anomaly_rows) > 10:
            logger.info("  ... 외 %d개", len(anomaly_rows) - 10)

    return result


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    parser = argparse.ArgumentParser(description="Isolation Forest 추론")
    parser.add_argument("--model", type=Path, required=True, help="모델 파일 경로 (.joblib)")
    parser.add_argument("--csv", type=Path, required=True, help="추론할 feature CSV 경로")
    args = parser.parse_args()

    if not args.csv.exists():
        logger.error("오류: CSV 파일이 없습니다: %s", args.csv)
        sys.exit(1)

    predict_csv(args.model, args.csv)


if __name__ == "__main__":
    main()
