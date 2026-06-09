"""정상 feature CSV 데이터로 Isolation Forest 모델을 학습합니다."""

import argparse
import logging
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from edge.detection.rule_detector import ISOLATION_FOREST_FEATURES

logger = logging.getLogger(__name__)

N_ESTIMATORS = 100
CONTAMINATION = 0.01
RANDOM_STATE = 42


def validate_contamination(contamination: float) -> None:
    if not 0 < contamination <= 0.5:
        raise ValueError("contamination은 0보다 크고 0.5 이하이어야 합니다.")


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


def train(csv_path: Path, model_path: Path, contamination: float = CONTAMINATION) -> dict[str, float | int]:
    validate_contamination(contamination)

    logger.info("CSV 로드 중: %s", csv_path)
    df = load_features(csv_path)
    logger.info("학습 데이터: %d행, feature %s, contamination=%.2f", len(df), list(ISOLATION_FOREST_FEATURES), contamination)

    X = df.values

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=contamination,
        random_state=RANDOM_STATE,
    )
    model.fit(X)

    predictions = model.predict(X)
    scores = model.decision_function(X)

    normal_count = int(np.sum(predictions == 1))
    anomaly_count = int(np.sum(predictions == -1))
    logger.info("학습 데이터 예측 결과: 정상 %d개 / 이상 %d개", normal_count, anomaly_count)
    logger.info("anomaly score 범위: min=%.4f, max=%.4f, mean=%.4f", scores.min(), scores.max(), scores.mean())

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    logger.info("모델 저장 완료: %s", model_path)

    return {
        "total_count": len(predictions),
        "normal_count": normal_count,
        "anomaly_count": anomaly_count,
        "score_min": float(scores.min()),
        "score_max": float(scores.max()),
        "score_mean": float(scores.mean()),
    }


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    parser = argparse.ArgumentParser(description="Isolation Forest 학습")
    parser.add_argument("--csv", type=Path, required=True, help="정상 feature CSV 경로")
    parser.add_argument("--model", type=Path, required=True, help="모델 저장 경로 (.joblib)")
    parser.add_argument("--contamination", type=float, default=CONTAMINATION, help="오염 비율 (기본값: 0.01)")
    args = parser.parse_args()

    if not args.csv.exists():
        logger.error("오류: CSV 파일이 없습니다: %s", args.csv)
        sys.exit(1)

    train(args.csv, args.model, args.contamination)


if __name__ == "__main__":
    main()
