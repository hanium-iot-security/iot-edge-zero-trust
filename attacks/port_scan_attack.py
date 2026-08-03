"""Port Scan 공격 시나리오 진입점.

저장되는 detection event_type은 PORT_SCAN을 사용해야 합니다.

탐지 기준 (DEFAULT_PACKET_RULE_POLICY 기준, Pilot 이후 조정될 수 있음):
  - distinct_port_count > port_scan_distinct_port_threshold (기본 15)
  - 또는 syn_count > port_scan_syn_threshold (기본 15)

evaluation_scope=DETECTION_ONLY 시나리오다 (scenario_runner.catalog 참고).
스캔 자체는 격리 대상 행위가 아니라 Packet Rule 탐지 검증이 목적이므로,
Trust/Firewall 단계까지 성공해야 SUCCESS로 판정하지 않는다.

실행 예시:
  python -m attacks.port_scan_attack
  python -m attacks.port_scan_attack --target 192.168.0.10 --start_port 1 --end_port 1024
"""

from __future__ import annotations

import argparse
import socket
import time

from attacks.config import BROKER_HOST


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="TCP Connect Port Scan Attack")
    p.add_argument("--target", default=BROKER_HOST, help="대상 Host (기본: Raspberry Pi/Broker)")
    p.add_argument("--start_port", default=1, type=int)
    p.add_argument("--end_port", default=1024, type=int, help="distinct_port_count > 15를 만족하려면 최소 16개 이상 포트 필요")
    p.add_argument("--timeout_ms", default=150, type=int, help="포트당 connect timeout(ms)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    timeout_s = max(args.timeout_ms, 1) / 1000.0
    ports = range(args.start_port, args.end_port + 1)
    port_count = len(list(ports))

    print(f"[PortScan] target={args.target} ports={args.start_port}-{args.end_port} ({port_count}개)")
    print(f"  탐지 조건: distinct_port_count > 15 or syn_count > 15 (기본 Policy)")
    print()

    open_ports: list[int] = []
    scanned = 0
    started = time.monotonic()
    for port in range(args.start_port, args.end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_s)
        try:
            result = sock.connect_ex((args.target, port))
            if result == 0:
                open_ports.append(port)
        except OSError:
            pass
        finally:
            sock.close()
        scanned += 1

    elapsed = time.monotonic() - started
    print(
        f"[PortScan] 완료 — scanned={scanned} ports, open={len(open_ports)}, "
        f"elapsed={elapsed:.2f}s"
    )
    if open_ports:
        print(f"  open_ports(sample)={open_ports[:10]}")


if __name__ == "__main__":
    main()