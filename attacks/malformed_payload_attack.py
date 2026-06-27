"""Malformed payload 공격 시나리오 진입점.

저장되는 detection event_type은 MALFORMED_PAYLOAD를 사용해야 합니다.

탐지 기준:
  - 10초 window 내 깨진 JSON 또는 device_id 누락 payload 3회 이상

실행 예시:
  python -m attacks.malformed_payload_attack
  python -m attacks.malformed_payload_attack --host 192.168.0.10 --count 5
"""

import argparse
import random
import time

import paho.mqtt.client as mqtt

from attacks.config import BROKER_HOST, BROKER_PORT, KEEPALIVE, REGISTERED_DEVICES, NORMAL_TOPIC_TPL

# subscriber의 parse_payload_json / _payload_device_id 기준으로
# is_json_valid=0 또는 device_id=None 이 되는 패턴만 수록
_MALFORMED_POOL = [
    # 깨진 JSON 구조
    '{"device_id":}',
    '{"device_id": "esp32_01"',
    '{device_id: "esp32_01"}',
    '[{"device_id":"esp32_01"}]',
    # device_id 필드 없음 / 유효하지 않은 값
    '{}',
    '',
    'null',
    '{"dev": "esp32_01"}',
    '{"DEVICE_ID": "esp32_01"}',
    '{"device_id": null}',
    '{"device_id": 12345}',
    '{"device_id": ""}',
    # 프로토콜 혼용
    '<!-- XML injection -->',
    'SELECT * FROM devices;',
    '<script>alert(1)</script>',
]


def _rand_str(length: int = 4) -> str:
    import string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MQTT Malformed Payload Attack (MALFORMED_PAYLOAD)")
    p.add_argument("--host",      default=BROKER_HOST)
    p.add_argument("--port",      default=BROKER_PORT,                      type=int)
    p.add_argument("--device_id", default="esp32_02")
    p.add_argument("--count",     default=5,                                type=int,   help="보낼 깨진 메시지 수 (≥3 권장)")
    p.add_argument("--interval",  default=1.5,                              type=float, help="메시지 간격(초)")
    return p.parse_args()


def main() -> None:
    args      = parse_args()
    device_id = args.device_id
    topic     = NORMAL_TOPIC_TPL.format(device_id=device_id)

    client = mqtt.Client(client_id=f"attacker_malform_{_rand_str()}")
    client.connect(args.host, args.port, KEEPALIVE)
    client.loop_start()

    print(f"[MalformedPayload] {device_id} → {topic}")
    print(f"  탐지 조건: malformed_payload_count >= 3 (10초 window)")
    print()

    for i in range(args.count):
        payload = random.choice(_MALFORMED_POOL)
        result  = client.publish(topic, payload, qos=0)
        print(f"  [{i+1}/{args.count}] mid={result.mid} payload={repr(payload[:60])}")
        time.sleep(args.interval)

    client.loop_stop()
    client.disconnect()
    print(f"\n[MalformedPayload] 완료 — {args.count}개 깨진 메시지 발행")


if __name__ == "__main__":
    main()
