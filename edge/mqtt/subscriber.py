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
from edge.mqtt.identity import (
    classify_mqtt_identity,
    fetch_registered_device_ids,
)
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
    """mqtt_logs Raw 증적을 저장하고, 등록 Device의 정상 활동만 last_seen_at에 반영한다.

    Raw 증적(topic, payload, device_id 후보, error_message 등)은 Identity 판정
    결과와 무관하게 그대로 저장한다. `row["device_id"]`는 Topic 후보 또는 Payload
    값으로 채워지는 "최선 추정 후보"일 뿐이며, 이 값이 등록 기기와 일치한다는
    사실만으로 곧바로 그 기기의 정상 활동으로 신뢰하지 않는다.

    last_seen_at 갱신은 `edge.mqtt.identity.classify_mqtt_identity`(공통 Helper)가
    엄격한 정상 Telemetry(`MqttIdentityResult.is_normal_telemetry` — 정상 Topic +
    정상 Payload + 동일 등록 Device)로 판정한 경우에만 수행한다. Topic 형식이
    비정상이거나(예: `iot/esp32_01/cmd`) Payload가 손상돼 Device ID를 못 뽑은
    경우는 등록 Device로 귀속은 가능(MATCHED)해도 last_seen_at은 갱신하지 않는다.
    DEVICE_ID_MISMATCH·UNKNOWN_DEVICE 메시지는 Raw 증적으로는 남지만 등록 Device의
    정상 last_seen_at을 갱신하지 않는다.
    """
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
        registered_devices = fetch_registered_device_ids(db)
        identity = classify_mqtt_identity(row["topic"], row["payload"], registered_devices)
        if identity.is_normal_telemetry:
            db.execute(
                text(
                    """
                    UPDATE devices
                    SET last_seen_at = :received_at
                    WHERE device_id = :device_id
                    """
                ),
                {
                    "device_id": identity.attributed_device_id,
                    "received_at": row["received_at"],
                },
            )
    db.commit()
    return int(result.lastrowid or 0)


def save_mqtt_message(topic: str, payload: str | bytes, received_at: datetime | None = None) -> int:
    row = build_mqtt_log_row(topic=topic, payload=payload, received_at=received_at)
    with SessionLocal() as db:
        return insert_mqtt_log(db, row)


def apply_mqtt_credentials(client: mqtt.Client, *, username: str, password: str) -> None:
    """설정된 경우에만 MQTT Username/Password 인증을 적용한다.

    Mosquitto가 아직 익명 접근을 허용하는 전환 기간에는 `MQTT_SUBSCRIBER_USERNAME`을
    비워두면 기존처럼 익명 연결을 유지한다. Broker가 인증·ACL을 강제한 뒤에는 Username을
    반드시 설정해야 Subscribe가 유지된다.
    """
    if username:
        client.username_pw_set(username, password or None)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    apply_mqtt_credentials(
        client,
        username=settings.mqtt_subscriber_username,
        password=settings.mqtt_subscriber_password,
    )

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