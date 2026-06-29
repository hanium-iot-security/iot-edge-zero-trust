"""전체 feature_logs를 순회하며 AI(Isolation Forest) 탐지를 실행합니다.

이벤트별 중복 방지는 writer(insert_detection_event)가 단일 책임으로 처리합니다.
"""

import logging
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.database import SessionLocal
from edge.detection.ai_detector import DEFAULT_MODEL_PATH, load_model, predict_feature_window
from edge.detection.detection_event_writer import insert_detection_event
from edge.detection.rule_detector import AI_ANOMALY, DETECTOR_AI

logger = logging.getLogger(__name__)


def run_ai_detector(
    db: Session,
    model_path: Path = DEFAULT_MODEL_PATH,
) -> dict[str, int]:
    """feature_logs에 대해 AI 탐지를 실행합니다.

    Session / commit / rollback은 이 함수(runner)가 담당합니다.

    Returns:
        {"feature_events": int} — 새로 저장된 이벤트 수
    """
    try:
        load_model(model_path)
        feature_events = _process_feature_logs(db, model_path)
        db.commit()
        return {"feature_events": feature_events}
    except Exception:
        db.rollback()
        raise


def _process_feature_logs(db: Session, model_path: Path) -> int:
    rows = db.execute(
        text(
            """
            SELECT id, device_id,
                   publish_count, avg_payload_size, max_payload_size,
                   avg_message_interval, min_message_interval
            FROM feature_logs
            ORDER BY id
            """
        )
    ).fetchall()

    count = 0
    for row in rows:
        feature_row = dict(row._mapping)
        feature_log_id = feature_row.pop("id")
        device_id = feature_row["device_id"]

        result = predict_feature_window(feature_row, model_path)
        if not result["is_anomaly"]:
            continue

        event_id = insert_detection_event(
            db,
            device_id=device_id,
            detector_type=DETECTOR_AI,
            event_type=AI_ANOMALY,
            severity="medium",
            description=(
                "Isolation Forest 기반 이상 탐지 "
                f"(anomaly_score={result['anomaly_score']:.4f})"
            ),
            feature_log_id=feature_log_id,
        )
        if event_id is not None:
            count += 1
            logger.info(
                "AI anomaly detected for %s (feature_log_id=%s, score=%.4f)",
                device_id, feature_log_id, result["anomaly_score"],
            )

    return count


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    with SessionLocal() as db:
        result = run_ai_detector(db)
    logger.info(
        "AI detection complete — feature_events=%d",
        result["feature_events"],
    )


if __name__ == "__main__":
    main()
