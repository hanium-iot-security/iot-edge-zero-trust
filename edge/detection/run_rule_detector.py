"""전체 feature_logs / mqtt_logs를 순회하며 Rule 탐지를 실행합니다.

이벤트별 중복 방지는 writer(insert_detection_event)가 단일 책임으로 처리합니다.
"""

import logging

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.database import SessionLocal
from edge.detection.detection_event_writer import insert_detection_event
from edge.detection.rule_detector import (
    ABNORMAL_PUBLISH_RATE,
    ABNORMAL_TOPIC,
    DETECTOR_RULE,
    LARGE_PAYLOAD,
    MALFORMED_PAYLOAD,
    detect_feature_rules,
    detect_mqtt_rules,
)

logger = logging.getLogger(__name__)

_FEATURE_DESCRIPTIONS = {
    ABNORMAL_PUBLISH_RATE: lambda r: (
        f"publish_count={r['publish_count']}, min_interval={r['min_message_interval']:.2f}s"
    ),
    LARGE_PAYLOAD: lambda r: f"max_payload_size={r['max_payload_size']} bytes",
    MALFORMED_PAYLOAD: lambda r: f"malformed_payload_count={r['malformed_payload_count']}",
    ABNORMAL_TOPIC: lambda r: f"abnormal_topic_count={r['abnormal_topic_count']}",
}


def run_rule_detector(db: Session) -> dict[str, int]:
    """feature_logs + mqtt_logs에 대해 Rule 탐지를 실행합니다.

    Session / commit / rollback은 이 함수(runner)가 담당합니다.

    Returns:
        {"feature_events": int, "mqtt_events": int} — 새로 저장된 이벤트 수
    """
    try:
        registered = _load_registered_devices(db)
        feature_events = _process_feature_logs(db)
        mqtt_events = _process_mqtt_logs(db, registered)
        db.commit()
        return {"feature_events": feature_events, "mqtt_events": mqtt_events}
    except Exception:
        db.rollback()
        raise


def _load_registered_devices(db: Session) -> set[str]:
    rows = db.execute(text("SELECT device_id FROM devices")).fetchall()
    return {row[0] for row in rows}


def _process_feature_logs(db: Session) -> int:
    rows = db.execute(
        text(
            """
            SELECT id, device_id,
                   publish_count, min_message_interval,
                   max_payload_size, malformed_payload_count, abnormal_topic_count
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

        for event in detect_feature_rules(feature_row):
            desc = _FEATURE_DESCRIPTIONS.get(event["event_type"], lambda r: "")(feature_row)
            result = insert_detection_event(
                db,
                device_id=device_id,
                detector_type=DETECTOR_RULE,
                event_type=event["event_type"],
                severity=event["severity"],
                description=desc,
                feature_log_id=feature_log_id,
            )
            if result is not None:
                count += 1
                logger.info(
                    "Rule event %s for %s (feature_log_id=%s)",
                    event["event_type"], device_id, feature_log_id,
                )

    return count


def _process_mqtt_logs(db: Session, registered: set[str]) -> int:
    rows = db.execute(
        text(
            """
            SELECT id, topic, payload
            FROM mqtt_logs
            ORDER BY id
            """
        )
    ).fetchall()

    count = 0
    for row in rows:
        mqtt_log_id, topic, payload = row[0], row[1], row[2] or ""
        mqtt_row = {"topic": topic, "payload": payload}

        for event in detect_mqtt_rules(mqtt_row, registered):
            result = insert_detection_event(
                db,
                device_id=event["device_id"],
                detector_type=DETECTOR_RULE,
                event_type=event["event_type"],
                severity=event["severity"],
                description=(
                    f"topic={topic!r}, "
                    f"payload_device_id={event.get('payload_id')!r}"
                ),
                mqtt_log_id=mqtt_log_id,
            )
            if result is not None:
                count += 1
                logger.info(
                    "Rule event %s for %s (mqtt_log_id=%s)",
                    event["event_type"], event["device_id"], mqtt_log_id,
                )

    return count


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    with SessionLocal() as db:
        result = run_rule_detector(db)
    logger.info(
        "Rule detection complete — feature_events=%d, mqtt_events=%d",
        result["feature_events"],
        result["mqtt_events"],
    )


if __name__ == "__main__":
    main()
