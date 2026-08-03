"""Packet/Byte Rate 이상 공격 시나리오 진입점.

저장되는 detection event_type은 PACKET_RATE_ANOMALY 또는 BYTE_RATE_ANOMALY를
사용해야 합니다 (실제 판정은 edge/detection/packet_rule_detector.py의
PacketRulePolicy 기준을 따릅니다).

탐지 기준 (DEFAULT_PACKET_RULE_POLICY 기준, Pilot 이후 조정될 수 있음):
  - packets_per_second > packet_rate_threshold (기본 50.0)
  - 또는 bytes_per_second > byte_rate_threshold (기본 100000.0)

이 스크립트는 MQTT 애플리케이션 계층이 아니라 UDP 패킷을 직접 대상 Host로
전송해 Raspberry Pi Packet Capture(모든 INBOUND 트래픽)에서 packets_per_second
·bytes_per_second를 끌어올린다. 대상 Host의 UDP Listener 존재 여부와 무관하게
패킷 자체는 캡처된다.

실행 예시:
  python -m attacks.packet_rate_flood_attack
  python -m attacks.packet_rate_flood_attack --target 192.168.0.10 --duration 12 --rate_pps 80
  python -m attacks.packet_rate_flood_attack --rate_pps 40 --payload_bytes 1400  # byte rate 위주
"""

from __future__ import annotations

import argparse
import socket
import time

from attacks.config import BROKER_HOST


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Packet/Byte Rate Anomaly Attack")
    p.add_argument("--target", default=BROKER_HOST, help="대상 Host (기본: Raspberry Pi/Broker)")
    p.add_argument("--port", default=19999, type=int, help="대상 UDP Port (Listener 불필요)")
    p.add_argument("--duration", default=12.0, type=float, help="공격 지속 시간(초). Capture Window(10초)보다 길게 권장")
    p.add_argument("--rate_pps", default=80.0, type=float, help="초당 전송 패킷 수")
    p.add_argument("--payload_bytes", default=64, type=int, help="패킷당 Payload 크기(byte). byte_rate 위주 검증 시 크게 설정")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    interval = 1.0 / args.rate_pps if args.rate_pps > 0 else 0.0
    payload = b"P" * max(args.payload_bytes, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[PacketRateFlood] target={args.target}:{args.port}")
    print(f"  duration={args.duration}s, rate_pps={args.rate_pps}, payload_bytes={len(payload)}")
    print(f"  탐지 조건: packets_per_second > 50.0 or bytes_per_second > 100000.0 (기본 Policy)")
    print()

    sent = 0
    started = time.monotonic()
    deadline = started + args.duration
    try:
        while time.monotonic() < deadline:
            sock.sendto(payload, (args.target, args.port))
            sent += 1
            if interval:
                time.sleep(interval)
    finally:
        sock.close()

    elapsed = time.monotonic() - started
    total_bytes = sent * len(payload)
    print(
        f"[PacketRateFlood] 완료 — sent={sent} packets, "
        f"elapsed={elapsed:.2f}s, "
        f"avg_pps={sent / elapsed if elapsed else 0:.1f}, "
        f"avg_bps={total_bytes / elapsed if elapsed else 0:.0f}"
    )


if __name__ == "__main__":
    main()