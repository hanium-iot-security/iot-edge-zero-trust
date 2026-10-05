"""MQTT telemetry를 받아 mqtt_logs에 저장하는 subscriber 진입점."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from pathlib import Path
import signal
import sys
from threading import Event, Thread
from typing import Any, Callable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import paho.mqtt.client as mqtt
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import SessionLocal
from edge.detection.phase4_time import format_db_utc, floor_window_start, parse_db_utc
from edge.features.feature_utils import extract_payload_device_id, payload_size
from edge.mqtt.identity import (
    classify_mqtt_identity,
    fetch_registered_device_ids,
    payload_validity_from_log_row,
)
from edge.policy.repository import load_policy_resolver
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
    return timestamp.astimezone(timezone.utc)


def _format_received_at(value: datetime) -> str:
    if value.microsecond:
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return format_db_utc(value)


PAYLOAD_DECODE_OK = "OK"
PAYLOAD_DECODE_INVALID_UTF8 = "INVALID_UTF8"


def _decode_payload(payload: str | bytes) -> str:
    if isinstance(payload, bytes):
        return payload.decode("utf-8", errors="replace")
    return payload


def _raw_payload(payload: str | bytes) -> tuple[bytes, str]:
    """수신 원본 바이트와 엄격한 UTF-8 해석 결과(`mqtt_logs.payload_decode_status`)."""
    raw = payload if isinstance(payload, bytes) else payload.encode("utf-8")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw, PAYLOAD_DECODE_INVALID_UTF8
    return raw, PAYLOAD_DECODE_OK


def build_mqtt_log_row(
    topic: str,
    payload: str | bytes,
    received_at: datetime | None = None,
) -> dict[str, Any]:
    payload_text = _decode_payload(payload)
    payload_raw, payload_decode_status = _raw_payload(payload)
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
        "payload_raw": payload_raw,
        "payload_decode_status": payload_decode_status,
        "received_at": _format_received_at(_normalize_received_at(received_at)),
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
    resolver = load_policy_resolver(db)
    received_at = parse_db_utc(row["received_at"], "received_at", allow_subseconds=True)
    window_start = floor_window_start(received_at.replace(microsecond=0))
    registered_devices = (
        resolver.registered_ids_at(window_start)
        if resolver is not None else fetch_registered_device_ids(db)
    )
    identity = classify_mqtt_identity(
        row["topic"],
        row["payload"],
        registered_devices,
        is_payload_valid=payload_validity_from_log_row(row),
    )
    registration = (
        resolver.registration_at(identity.attributed_device_id, window_start)
        if resolver is not None and identity.attributed_device_id is not None
        else None
    )
    # 원본 컬럼이 없는 호출자(직접 만든 row)는 NULL로 저장한다.
    raw_row = {"payload_raw": None, "payload_decode_status": None, **row}
    if registration is not None and registration.status == "DISABLED":
        errors = [part for part in (row.get("error_message"), "disabled_device_communication") if part]
        raw_row["error_message"] = ", ".join(errors)
    result = db.execute(
        text(
            """
            INSERT INTO mqtt_logs (
                device_id,
                topic,
                payload,
                payload_size,
                payload_raw,
                payload_decode_status,
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
                :payload_raw,
                :payload_decode_status,
                :received_at,
                :is_json_valid,
                :is_topic_valid,
                :error_message
            )
            """
        ),
        raw_row,
    )
    if row["device_id"]:
        if identity.is_normal_telemetry and (
            registration is None or registration.status != "DISABLED"
        ):
            db.execute(
                text(
                    """
                    UPDATE devices
                    SET last_seen_at = :received_at
                    WHERE device_id = :device_id
                      AND (
                          last_seen_at IS NULL
                          OR julianday(last_seen_at) < julianday(:received_at)
                      )
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


def run_mqtt_loop(client: mqtt.Client, *, shutdown_requested: Callable[[], bool]) -> None:
    """Stop receiving, then join the current callback before reporting success.

    Paho's loop_forever retains its normal reconnect behavior. Its worker must
    finish (including any database commit) before this function returns. A dead
    network worker or failed callback is a service failure, not a clean stop.
    """
    finished = Event()
    failures: list[BaseException] = []

    def receive() -> None:
        try:
            client.loop_forever()
        except BaseException as exc:
            failures.append(exc)
        else:
            if not shutdown_requested():
                failures.append(RuntimeError("MQTT network loop stopped unexpectedly"))
        finally:
            finished.set()

    worker = Thread(target=receive, name="mqtt-subscriber", daemon=False)
    started = False
    try:
        if not shutdown_requested():
            worker.start()
            started = True
            while not shutdown_requested() and not finished.wait(0.1):
                pass
    finally:
        try:
            result = client.disconnect()
            if result not in (mqtt.MQTT_ERR_SUCCESS, mqtt.MQTT_ERR_NO_CONN):
                raise RuntimeError(f"MQTT disconnect failed: {result}")
        finally:
            if started:
                worker.join()
    if failures:
        raise RuntimeError("MQTT receiver failed") from failures[0]


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    stopping = False

    def request_stop(_signum: int, _frame: object) -> None:
        # No logging, DB calls, or Event lock acquisition inside a signal handler.
        nonlocal stopping
        stopping = True

    previous_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    for sig in previous_handlers:
        signal.signal(sig, request_stop)
    try:
        return _main(shutdown_requested=lambda: stopping)
    finally:
        for sig, previous in previous_handlers.items():
            signal.signal(sig, previous)


def _main(*, shutdown_requested: Callable[[], bool]) -> int:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    apply_mqtt_credentials(
        client,
        username=settings.mqtt_subscriber_username,
        password=settings.mqtt_subscriber_password,
    )

    def on_connect(client: mqtt.Client, _userdata, _flags, reason_code, _properties) -> None:
        if getattr(reason_code, "is_failure", False):
            raise RuntimeError(f"MQTT broker connection rejected: {reason_code}")
        result, _mid = client.subscribe(settings.mqtt_subscribe_topic)
        if result != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"MQTT subscription failed: {result}")
        logger.info("MQTT broker 연결 완료: %s:%s, topic=%s", settings.mqtt_host, settings.mqtt_port, settings.mqtt_subscribe_topic)

    def on_message(_client: mqtt.Client, _userdata, message: mqtt.MQTTMessage) -> None:
        try:
            log_id = save_mqtt_message(message.topic, message.payload)
            logger.info("mqtt_logs 저장 완료: id=%s topic=%s", log_id, message.topic)
        except Exception:
            logger.exception("MQTT message 저장 실패: topic=%s", message.topic)
            raise

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(settings.mqtt_host, settings.mqtt_port, keepalive=60)
    run_mqtt_loop(client, shutdown_requested=shutdown_requested)
    logger.info("MQTT subscriber stopped after receiver drain")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
