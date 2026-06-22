"""attacks/ 공통 설정."""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import settings

# Mosquitto broker 설정 — .env의 mqtt_host / mqtt_port 값을 사용
# 로컬 테스트: .env 없으면 settings 기본값(localhost:1883) 적용
# Raspberry Pi 실기기: .env에 mqtt_host=<Pi IP> 설정
BROKER_HOST = settings.mqtt_host
BROKER_PORT = settings.mqtt_port
KEEPALIVE   = 60

# 등록된 기기 목록 (db/seed_devices.py와 동기화)
REGISTERED_DEVICES = ["esp32_01", "esp32_02", "esp32_03"]

# 정상 topic 템플릿 — settings.mqtt_normal_topic 패턴 기준
# "iot/+/sensor" → 실제 publish 시 + 자리에 device_id 대입
NORMAL_TOPIC_TPL = "iot/{device_id}/sensor"

# 비정상 topic 패턴 (ABNORMAL_TOPIC, UNKNOWN_DEVICE 공격에서 사용)
MALICIOUS_TOPICS = [
    "admin/system/control",
    "test/hack",
    "$SYS/broker/clients/total",
    "$SYS/broker/uptime",
    "iot/unknown/sensor",
    "cmd/exec",
    "device/update/firmware",
    "backdoor/shell",
    "../../../etc/passwd",
    "iot/#",
    "iot/+/cmd",
    "mgmt/reset",
    "factory/reset",
    "ota/update",
    "debug/console",
]