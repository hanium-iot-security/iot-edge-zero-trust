"""attacks/ 공통 설정."""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import paho.mqtt.client as mqtt

from backend.app.config import settings

# Mosquitto broker 설정 — .env의 mqtt_host / mqtt_port 값을 사용
# 로컬 테스트: .env 없으면 settings 기본값(localhost:1883) 적용
# Raspberry Pi 실기기: .env에 mqtt_host=<Pi IP> 설정
BROKER_HOST = settings.mqtt_host
BROKER_PORT = settings.mqtt_port
KEEPALIVE   = 60

# 공식 MQTT Scenario/Test Tool 전용 Credential.
# 비워두면 기존처럼 익명 연결을 시도한다(Broker가 아직 allow_anonymous true인 전환 기간용).
# Broker가 인증·ACL을 강제한 뒤에는 .env의 MQTT_TEST_TOOL_USERNAME/MQTT_TEST_TOOL_PASSWORD를 채워야
# attacks/* 스크립트가 계속 Publish할 수 있다. 실제 Secret 값은 이 파일이나 Git에 절대 기록하지 않는다.
BROKER_USERNAME = settings.mqtt_test_tool_username
BROKER_PASSWORD = settings.mqtt_test_tool_password

# 등록된 기기 목록 (db/seed_devices.py와 동기화)
REGISTERED_DEVICES = ["esp32_01", "esp32_02"]

# 정상 topic 템플릿 — settings.mqtt_normal_topic 패턴 기준
# "iot/+/sensor" → 실제 publish 시 + 자리에 device_id 대입
NORMAL_TOPIC_TPL = "iot/{device_id}/sensor"

# 비정상 topic 패턴 (ABNORMAL_TOPIC, UNKNOWN_DEVICE 공격에서 사용)
MALICIOUS_TOPICS = [
    "admin/system/control",
    "test/hack",
    "iot/unknown/sensor",
    "cmd/exec",
    "device/update/firmware",
    "backdoor/shell",
    "../../../etc/passwd",
    "iot/esp32_02/cmd",
    "iot/esp32_02/admin",
    "iot/esp32_02/debug",
    "mgmt/reset",
    "factory/reset",
    "ota/update",
    "debug/console",
]

def build_mqtt_client(client_id: str) -> mqtt.Client:
    """공식 MQTT Scenario/Test Tool Credential이 적용된 Client를 생성한다.

    모든 attacks/* 스크립트는 `mqtt.Client(client_id=...)`를 직접 만드는 대신 이
    Helper를 사용해야 한다. 공통 Credential 로직을 여기 한 곳에서만 정의하고,
    각 공격 스크립트가 Username/Password 적용 로직을 중복 구현하지 않는다.

    `BROKER_USERNAME`이 비어 있으면(전환 기간) 기존처럼 익명 연결을 시도한다.
    """
    client = mqtt.Client(client_id=client_id)
    if BROKER_USERNAME:
        client.username_pw_set(BROKER_USERNAME, BROKER_PASSWORD or None)
    return client