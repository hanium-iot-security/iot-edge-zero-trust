"""Unknown device 공격 시나리오 진입점.

저장되는 detection event_type은 UNKNOWN_DEVICE를 사용해야 합니다.

탐지 기준:
  - devices 테이블에 등록되지 않은 device_id 사용

주의:
  - UNKNOWN_DEVICE는 Trust Score 감점 대상이 아님
  - 미등록 기기 접근 이벤트로 기록 후 즉시 차단 / 메시지 무시 처리

실행 예시:
  python -m attacks.unknown_device_attack
  python -m attacks.unknown_device_attack --host 192.168.0.10 --count 4
"""

import argparse
import json
import random
import string
import time

import paho.mqtt.client as mqtt

from attacks.config import BROKER_HOST, BROKER_PORT, KEEPALIVE, REGISTERED_DEVICES, NORMAL_TOPIC_TPL

_VENDOR_DEFAULT_IDS = [
    "ESP_XXXXXX", "ESP32_DEV", "Arduino_001", "RPi_Node_01",
    "smartplug_001", "cam_default", "sensor_node_1",
    "DVES_XXXXXX", "tasmota_XXXX", "sonoff_XXXX", "tuya_device", "zigbee_bridge",
]

_ABNORMAL_TOPICS = [
    "admin/system/control", "cmd/exec", "backdoor/shell",
    "device/update/firmware", "ota/update", "debug/console",
]


def _rand_str(length: int = 4) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _fake_device_id() -> str:
    """등록 기기와 겹치지 않는 미등록 device_id 생성."""
    subtype = random.choice(["rogue", "cloned", "vendor_default", "botnet"])

    if subtype == "rogue":
        return f"esp32_{_rand_str()}"

    elif subtype == "cloned":
        base = random.choice(REGISTERED_DEVICES)
        return random.choice([
            base.replace("0", "O"),
            base + "_clone",
            base + "x",
            "esp32-" + base.split("_")[-1],
        ])

    elif subtype == "vendor_default":
        return random.choice(_VENDOR_DEFAULT_IDS)

    else:  # botnet
        return random.choice([
            f"node_{_rand_str(8)}",
            f"bot_{random.randint(1000, 9999)}",
            f"client_{_rand_str(6)}",
        ])


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MQTT Unknown Device Attack (UNKNOWN_DEVICE)")
    p.add_argument("--host",           default=BROKER_HOST)
    p.add_argument("--port",           default=BROKER_PORT, type=int)
    p.add_argument("--count",          default=4,           type=int,   help="보낼 메시지 수")
    p.add_argument("--interval",       default=2.0,         type=float)
    p.add_argument("--abnormal-topic", action="store_true",
                   help="abnormal topic과 unknown device를 조합하는 케이스 (별도 시나리오)")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    client = mqtt.Client(client_id=f"attacker_unknown_{_rand_str()}")
    client.connect(args.host, args.port, KEEPALIVE)
    client.loop_start()

    print(f"[UnknownDevice] 미등록 device_id로 MQTT publish")
    print(f"  탐지 조건: device_id가 devices 테이블에 없음 → 즉시 차단")
    if args.abnormal_topic:
        print(f"  모드: abnormal topic 조합 (subscriber 미수신 가능)")
    print()

    for i in range(args.count):
        fake_id = _fake_device_id()
        if args.abnormal_topic:
            topic = random.choice(_ABNORMAL_TOPICS)
        else:
            topic = NORMAL_TOPIC_TPL.format(device_id=fake_id)
        payload = json.dumps({"device_id": fake_id})
        result  = client.publish(topic, payload, qos=0)
        print(f"  [{i+1}/{args.count}] device_id={fake_id!r} topic={topic!r} (mid={result.mid})")
        time.sleep(args.interval)

    client.loop_stop()
    client.disconnect()
    print(f"\n[UnknownDevice] 완료 — {args.count}개 미등록 기기 메시지 발행")


if __name__ == "__main__":
    main()
