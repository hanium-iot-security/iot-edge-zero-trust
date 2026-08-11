"""MQTT Device Identity 공통 판정 모듈.

Topic Device ID · Payload Device ID · 등록 Device 여부 판정을 이 모듈 한 곳에서만
정의한다. Subscriber(last_seen_at 갱신 여부 결정), Feature Builder(정상 MQTT
Feature 집계 대상 여부 결정), Message Rule Detector(DEVICE_ID_MISMATCH,
UNKNOWN_DEVICE 판정)가 이 모듈을 공유하며 각자 Topic/Payload 파싱이나 등록 Device
판정 로직을 중복 구현하지 않는다.

판정 우선순위(기존 UNKNOWN_DEVICE 우선 판정 계약 — 회귀 검증 대상):
1. topic_id / payload_id 중 하나라도 등록되지 않음 → UNKNOWN_DEVICE
2. 둘 다 등록 기기이지만 서로 다름 → DEVICE_ID_MISMATCH
3. 둘 다 등록 기기이며 같음(또는 둘 중 하나만 추출됐고 그 값이 등록 기기) → MATCHED
4. 둘 다 추출 불가 → NO_CANDIDATE

이 모듈은 `error_message`처럼 이미 파생된 문자열을 다시 Parsing하지 않는다. 항상
Raw Topic과 Raw Payload에서 직접 다시 계산한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.features.feature_utils import extract_payload_device_id
from edge.mqtt.topic_utils import extract_device_id_candidate_from_topic


class IdentityStatus(str, Enum):
    """MQTT 메시지 하나에 대한 Device Identity 판정 결과."""

    #: Topic Device ID와 Payload Device ID가 서로 모순되지 않고, 식별된 Device가
    #: 등록 기기다. 정상 Telemetry 활동으로 인정한다(last_seen_at 갱신, Feature 집계 포함).
    MATCHED = "MATCHED"
    #: Topic Device ID와 Payload Device ID가 모두 존재하고 모두 등록 기기이지만
    #: 서로 다르다. Payload 위조(Application Identity Detection) 대상이다.
    DEVICE_ID_MISMATCH = "DEVICE_ID_MISMATCH"
    #: Topic 또는 Payload에서 추출한 Device ID 중 하나 이상이 등록되지 않은 기기다.
    UNKNOWN_DEVICE = "UNKNOWN_DEVICE"
    #: Topic과 Payload 어느 쪽에서도 Device ID 후보를 추출할 수 없다.
    NO_CANDIDATE = "NO_CANDIDATE"


@dataclass(frozen=True)
class MqttIdentityResult:
    """Identity 판정 결과와 그 근거가 된 원본 값들."""

    topic_device_id: str | None
    payload_device_id: str | None
    status: IdentityStatus
    #: MATCHED일 때만 값이 있다. 등록 Device의 정상 활동으로 귀속해도 되는 Device ID.
    attributed_device_id: str | None
    #: UNKNOWN_DEVICE일 때만 값이 있다. 등록되지 않은 것으로 판정된 Device ID.
    unregistered_device_id: str | None = None

    @property
    def is_normal_telemetry(self) -> bool:
        """등록 Device의 정상 Telemetry 활동(last_seen_at 갱신, Feature 집계 포함)인지."""
        return self.status is IdentityStatus.MATCHED


def classify_mqtt_identity(
    topic: str,
    payload: str | bytes,
    registered_devices: set[str],
) -> MqttIdentityResult:
    """Raw Topic/Payload와 등록 Device 집합으로부터 Identity를 판정한다. DB 접근 없음.

    `registered_devices`는 호출자가 원하는 기준(예: 전체 등록 기기, Isolation 여부 무관)으로 미리 구성해 전달한다.
    이 함수 자체는 어떤 집합을 등록 기기로 볼지 결정하지 않는다.
    """
    topic_id = extract_device_id_candidate_from_topic(topic)
    payload_id = extract_payload_device_id(payload)

    if topic_id is None and payload_id is None:
        return MqttIdentityResult(
            topic_device_id=None,
            payload_device_id=None,
            status=IdentityStatus.NO_CANDIDATE,
            attributed_device_id=None,
        )

    topic_registered = (topic_id in registered_devices) if topic_id else None
    payload_registered = (payload_id in registered_devices) if payload_id else None

    if topic_registered is False or payload_registered is False:
        # Topic 우선 판정: Topic 쪽이 미등록이면 Topic ID를, 그렇지 않으면(=Payload 쪽이 미등록) Payload ID를 미등록 Device ID로 보고한다.
        unregistered_id = topic_id if topic_registered is False else payload_id
        return MqttIdentityResult(
            topic_device_id=topic_id,
            payload_device_id=payload_id,
            status=IdentityStatus.UNKNOWN_DEVICE,
            attributed_device_id=None,
            unregistered_device_id=unregistered_id,
        )

    if topic_id and payload_id and topic_id != payload_id:
        return MqttIdentityResult(
            topic_device_id=topic_id,
            payload_device_id=payload_id,
            status=IdentityStatus.DEVICE_ID_MISMATCH,
            attributed_device_id=None,
        )

    attributed = topic_id or payload_id
    return MqttIdentityResult(
        topic_device_id=topic_id,
        payload_device_id=payload_id,
        status=IdentityStatus.MATCHED,
        attributed_device_id=attributed,
    )


def fetch_registered_device_ids(db: Session) -> set[str]:
    """devices 테이블에 존재하는 모든 Device ID(Isolation 상태 무관).

    Identity 판정(등록 여부)은 현재 Isolation 상태와 무관하게 "이 Device ID를 아는가"
    만 확인한다. Feature 집계 대상 여부처럼 Isolation 상태를 반영해야 하는 별도
    기준은 호출자가 추가로 적용한다.
    """
    rows = db.execute(text("SELECT device_id FROM devices")).scalars()
    return {str(device_id) for device_id in rows}