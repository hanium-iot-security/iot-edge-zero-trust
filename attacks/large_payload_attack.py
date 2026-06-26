"""Large payload 공격 시나리오 진입점.

저장되는 detection event_type은 LARGE_PAYLOAD를 사용해야 합니다.

탐지 기준:
  - max_payload_size > 5120 bytes

실행 예시:
  python -m attacks.large_payload_attack
  python -m attacks.large_payload_attack --host 192.168.0.10 --count 3
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


def _large_payload(device_id: str) -> bytes:
    """5 KB 초과 valid JSON payload — 3가지 subtype 중 랜덤."""
    subtype = random.choice(["buffer_overflow", "data_exfiltration", "binary"])

    if subtype == "buffer_overflow":
        size = random.randint(10240, 131072)
        body = json.dumps({"device_id": device_id, "data": "A" * (size - 40)})

    elif subtype == "data_exfiltration":
        size = random.randint(5121, 51200)
        b64  = ''.join(random.choices(string.ascii_letters + string.digits + '+/=', k=size - 60))
        body = json.dumps({"device_id": device_id, "data": b64})

    else:  # binary
        size = random.randint(5121, 20480)
        body = json.dumps({"device_id": device_id, "raw": "\\x00\\x01\\xFF" * (size // 12)})

    return body.encode("utf-8")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MQTT Large Payload Attack (LARGE_PAYLOAD)")
    p.add_argument("--host",      default=BROKER_HOST)
    p.add_argument("--port",      default=BROKER_PORT,                      type=int)
    p.add_argument("--device_id", default="esp32_02")
    p.add_argument("--count",     default=3,                                type=int,   help="보낼 메시지 수")
    p.add_argument("--interval",  default=4.5,                              type=float, help="메시지 간격(초)")
    return p.parse_args()


def main() -> None:
    args      = parse_args()
    device_id = args.device_id
    topic     = NORMAL_TOPIC_TPL.format(device_id=device_id)

    client = mqtt.Client(client_id=f"attacker_large_{_rand_str()}")
    client.connect(args.host, args.port, KEEPALIVE)
    client.loop_start()

    print(f"[LargePayload] {device_id} → {topic}")
    print(f"  탐지 조건: max_payload_size > 5120 bytes")
    print()

    for i in range(args.count):
        payload_bytes = _large_payload(device_id)
        size_kb       = len(payload_bytes) / 1024
        result        = client.publish(topic, payload_bytes, qos=0)
        print(f"  [{i+1}/{args.count}] {size_kb:.1f} KB 전송 (mid={result.mid})")
        time.sleep(args.interval)

    client.loop_stop()
    client.disconnect()
    print(f"\n[LargePayload] 완료 — {args.count}개 메시지 발행")


if __name__ == "__main__":
    main()
