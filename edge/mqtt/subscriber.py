"""MQTT telemetry를 받아 mqtt_logs에 저장하는 subscriber 진입점."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from pathlib import Path
import sys
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import paho.mqtt.client as mqtt
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import SessionLocal
from edge.detection.phase4_time import format_db_utc
from edge.features.feature_utils import extract_payload_device_id, payload_size
from edge.mqtt.topic_utils import (
    extract_device_id_candidate_from_topic,
    extract_device_id_from_topic,
    is_telemetry_topic,
)

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_received_at(value: datetime | None) -> datetime:
    timestamp = value if value is not None else _utc_now()
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("received_at must be timezone-aware")
    return timestamp.astimezone(timezone.utc).replace(microsecond=0)


def _decode_payload(payload: str | bytes) -> str:
    if isinstance(payload, bytes):
        return payload.decode("utf-8", errors="replace")
    return payload


def build_mqtt_log_row(
    topic: str,
    payload: str | bytes,
    received_at: datetime | None = None,
) -> dict[str, Any]:
    payload_text = _decode_payload(payload)
    payload_device_id = extract_payload_device_id(payload)
    strict_topic_device_id = extract_device_id_from_topic(topic)
    topic_device_id_candidate = extract_device_id_candidate_from_topic(topic)
    is_topic_valid = is_telemetry_topic(topic)
    is_json_valid = payload_device_id is not None

    device_id = topic_device_id_candidate or payload_device_id
    error_parts: list[str] = []
    if not is_topic_valid:
        error_parts.append("invalid_topic")
    if not is_json_valid:
        error_parts.append("invalid_payload")
    if topic_device_id_candidate and payload_device_id and topic_device_id_candidate != payload_device_id:
        error_parts.append("device_id_mismatch")

    return {
        "device_id": device_id,
        "topic": topic,
        "payload": payload_text,
        "payload_size": payload_size(payload),
        "received_at": format_db_utc(_normalize_received_at(received_at)),
        "is_json_valid": 1 if is_json_valid else 0,
        "is_topic_valid": 1 if is_topic_valid else 0,
        "error_message": ", ".join(error_parts) if error_parts else None,
    }


def insert_mqtt_log(db: Session, row: dict[str, Any]) -> int:
    result = db.execute(
        text(
            """
            INSERT INTO mqtt_logs (
                device_id,
                topic,
                payload,
                payload_size,
                received_at,
                is_json_valid,
                is_topic_valid,
                error_message
            )
            VALUES (
                :device_id,
                :topic,
                :payload,
                :payload_size,
                :received_at,
                :is_json_valid,
                :is_topic_valid,
                :error_message
            )
            """
        ),
        row,
    )
    if row["device_id"]:
        db.execute(
            text(
                """
                UPDATE devices
                SET last_seen_at = :received_at
                WHERE device_id = :device_id
                """
            ),
            {"device_id": row["device_id"], "received_at": row["received_at"]},
        )
    db.commit()
    return int(result.lastrowid or 0)


def save_mqtt_message(topic: str, payload: str | bytes, received_at: datetime | None = None) -> int:
    row = build_mqtt_log_row(topic=topic, payload=payload, received_at=received_at)
    with SessionLocal() as db:
        return insert_mqtt_log(db, row)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

    def on_connect(client: mqtt.Client, _userdata, _flags, reason_code, _properties) -> None:
        if getattr(reason_code, "is_failure", False):
            logger.error("MQTT broker 연결 실패: reason_code=%s", reason_code)
            return
        client.subscribe(settings.mqtt_subscribe_topic)
        logger.info("MQTT broker 연결 완료: %s:%s, topic=%s", settings.mqtt_host, settings.mqtt_port, settings.mqtt_subscribe_topic)

    def on_message(_client: mqtt.Client, _userdata, message: mqtt.MQTTMessage) -> None:
        try:
            log_id = save_mqtt_message(message.topic, message.payload)
            logger.info("mqtt_logs 저장 완료: id=%s topic=%s", log_id, message.topic)
        except Exception:
            logger.exception("MQTT message 저장 실패: topic=%s", message.topic)

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(settings.mqtt_host, settings.mqtt_port, keepalive=60)
    client.loop_forever()


if __name__ == "__main__":
    main()
