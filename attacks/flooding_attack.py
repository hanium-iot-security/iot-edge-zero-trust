"""Flooding 공격 시나리오 진입점.

저장되는 detection event_type은 ABNORMAL_PUBLISH_RATE를 사용해야 합니다.

탐지 기준:
  - 10초 window 동안 publish_count > 15
  - 또는 min_message_interval < 1.0초

실행 예시:
  python -m attacks.flooding_attack
  python -m attacks.flooding_attack --host 192.168.0.10 --count 30 --interval 0.1
"""

import argparse
import json
import random
import string
import time

import paho.mqtt.client as mqtt

from attacks.config import BROKER_HOST, BROKER_PORT, KEEPALIVE, REGISTERED_DEVICES, NORMAL_TOPIC_TPL


def _rand_str(length: int = 4) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _normal_payload(device_id: str) -> str:
    return json.dumps({
        "device_id":   device_id,
        "temperature": round(random.uniform(20.0, 30.0), 2),
        "humidity":    round(random.uniform(40.0, 70.0), 2),
    })


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MQTT Flooding Attack (ABNORMAL_PUBLISH_RATE)")
    p.add_argument("--host",      default=BROKER_HOST)
    p.add_argument("--port",      default=BROKER_PORT,                      type=int)
    p.add_argument("--device_id", default="esp32_02")
    p.add_argument("--count",     default=30,                               type=int,   help="10초 안에 보낼 메시지 수")
    p.add_argument("--interval",  default=0.2,                              type=float, help="메시지 간격(초)")
    return p.parse_args()


def main() -> None:
    args      = parse_args()
    device_id = args.device_id
    topic     = NORMAL_TOPIC_TPL.format(device_id=device_id)

    client = mqtt.Client(client_id=f"attacker_flood_{_rand_str()}")
    client.connect(args.host, args.port, KEEPALIVE)
    client.loop_start()

    print(f"[Flooding] {device_id} → {topic}")
    print(f"  count={args.count}, interval={args.interval}s")
    print(f"  탐지 조건: publish_count > 15 or min_interval < 1.0")
    print()

    for i in range(args.count):
        payload = _normal_payload(device_id)
        result  = client.publish(topic, payload, qos=0)
        print(f"  [{i+1:>3}/{args.count}] mid={result.mid} payload={payload[:50]}")
        time.sleep(args.interval)

    client.loop_stop()
    client.disconnect()
    print(f"\n[Flooding] 완료 — {args.count}개 메시지 발행")


if __name__ == "__main__":
    main()