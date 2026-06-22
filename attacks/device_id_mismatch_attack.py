"""Device ID mismatch 공격 시나리오 진입점.

저장되는 detection event_type은 DEVICE_ID_MISMATCH를 사용해야 합니다.

탐지 기준:
  - topic의 device_id와 payload의 device_id가 서로 다른 경우
  - topic과 payload 양쪽 device_id가 모두 존재해야 함 (둘 다 등록 기기)
  - 미등록 device_id가 포함되면 UNKNOWN_DEVICE가 우선 적용됨

실행 예시:
  python -m attacks.device_id_mismatch_attack
  python -m attacks.device_id_mismatch_attack --host 192.168.0.10 --count 4
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


def _mismatch_pair() -> tuple[str, str]:
    """
    둘 다 등록 기기이지만 서로 다른 (topic_device_id, payload_device_id) 쌍 반환.
    두 값이 모두 등록 기기여야 DEVICE_ID_MISMATCH로 처리됨.
    (미등록 포함 시 UNKNOWN_DEVICE 우선)
    """
    topic_id   = random.choice(REGISTERED_DEVICES)
    others     = [d for d in REGISTERED_DEVICES if d != topic_id]
    payload_id = random.choice(others)
    return topic_id, payload_id


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MQTT Device ID Mismatch Attack (DEVICE_ID_MISMATCH)")
    p.add_argument("--host",     default=BROKER_HOST)
    p.add_argument("--port",     default=BROKER_PORT, type=int)
    p.add_argument("--count",    default=4,           type=int,   help="보낼 메시지 수")
    p.add_argument("--interval", default=2.0,         type=float)
    return p.parse_args()


def main() -> None:
    args = parse_args()

    client = mqtt.Client(client_id=f"attacker_mismatch_{_rand_str()}")
    client.connect(args.host, args.port, KEEPALIVE)
    client.loop_start()

    print(f"[DeviceIDMismatch] topic device_id ≠ payload device_id")
    print(f"  탐지 조건: 두 device_id가 모두 존재하지만 서로 다름")
    print()

    for i in range(args.count):
        topic_id, payload_id = _mismatch_pair()
        topic   = NORMAL_TOPIC_TPL.format(device_id=topic_id)
        payload = json.dumps({
            "device_id":   payload_id,
            "temperature": round(random.uniform(20.0, 30.0), 2),
            "humidity":    round(random.uniform(40.0, 70.0), 2),
        })
        result = client.publish(topic, payload, qos=0)
        print(f"  [{i+1}/{args.count}] topic={topic_id!r} payload.device_id={payload_id!r} (mid={result.mid})")
        time.sleep(args.interval)

    client.loop_stop()
    client.disconnect()
    print(f"\n[DeviceIDMismatch] 완료 — {args.count}개 불일치 메시지 발행")


if __name__ == "__main__":
    main()
