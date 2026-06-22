"""Abnormal topic 공격 시나리오 진입점.

저장되는 detection event_type은 ABNORMAL_TOPIC을 사용해야 합니다.

탐지 기준:
  - 10초 window 내 허용되지 않은 topic 형식 3회 이상
  - 허용 topic 형식: iot/{device_id}/sensor

실행 예시:
  python -m attacks.abnormal_topic_attack
  python -m attacks.abnormal_topic_attack --host 192.168.0.10 --count 5
"""

import argparse
import json
import random
import string
import time

import paho.mqtt.client as mqtt

from attacks.config import BROKER_HOST, BROKER_PORT, KEEPALIVE, REGISTERED_DEVICES

# subscriber의 is_telemetry_topic() 기준으로 False가 되는 topic 패턴
_ABNORMAL_TOPIC_POOL = [
    # 시스템 topic 접근
    "$SYS/broker/clients/total",
    "$SYS/broker/clients/connected",
    "$SYS/broker/messages/sent",
    "$SYS/broker/uptime",
    "$SYS/broker/version",
    # 명령어 실행 topic
    "cmd/exec",
    "device/update/firmware",
    "ota/update",
    "mgmt/reset",
    "factory/reset",
    "admin/system/control",
    "backdoor/shell",
    "debug/console",
    # path traversal
    "../../../sensor",
    "iot/../admin/control",
    "iot/%2e%2e/admin",
    # 와일드카드 삽입
    "iot/#",
    "#",
    "+/+/sensor",
    "iot/+/cmd",
    # 형식 불일치
    "test/hack",
]


def _rand_str(length: int = 4) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MQTT Abnormal Topic Attack (ABNORMAL_TOPIC)")
    p.add_argument("--host",      default=BROKER_HOST)
    p.add_argument("--port",      default=BROKER_PORT,                      type=int)
    p.add_argument("--device_id", default=random.choice(REGISTERED_DEVICES),
                   help="payload에 넣을 device_id (등록된 기기)")
    p.add_argument("--count",     default=5,                                type=int,   help="보낼 메시지 수 (≥3 권장)")
    p.add_argument("--interval",  default=1.5,                              type=float)
    return p.parse_args()


def main() -> None:
    args      = parse_args()
    device_id = args.device_id

    client = mqtt.Client(client_id=f"attacker_topic_{_rand_str()}")
    client.connect(args.host, args.port, KEEPALIVE)
    client.loop_start()

    print(f"[AbnormalTopic] payload device_id={device_id}")
    print(f"  탐지 조건: abnormal_topic_count >= 3 (10초 window)")
    print()

    for i in range(args.count):
        topic   = random.choice(_ABNORMAL_TOPIC_POOL)
        payload = json.dumps({"device_id": device_id})
        result  = client.publish(topic, payload, qos=0)
        print(f"  [{i+1}/{args.count}] topic={topic!r} (mid={result.mid})")
        time.sleep(args.interval)

    client.loop_stop()
    client.disconnect()
    print(f"\n[AbnormalTopic] 완료 — {args.count}개 비정상 topic 발행")


if __name__ == "__main__":
    main()
