"""Port Scan 공격 시나리오 진입점.

저장되는 detection event_type은 PORT_SCAN을 사용해야 합니다.

탐지 기준 (DEFAULT_PACKET_RULE_POLICY 기준, Pilot 이후 조정될 수 있음):
  - distinct_port_count > port_scan_distinct_port_threshold (기본 15)
  - 그리고(AND) syn_count > port_scan_syn_threshold (기본 15)
  실제 edge/detection/packet_rule_detector.py의 판정 조건은 OR가 아니라 AND이므로,
  두 조건을 모두 만족하도록 포트 수·연결 시도 수를 함께 확보해야 한다
  (TCP Connect Scan은 성공/실패와 무관하게 SYN을 발생시키므로 포트 수만
  16개 이상이면 일반적으로 두 조건을 함께 만족한다).

evaluation_scope=DETECTION_ONLY 시나리오다 (scenario_runner.catalog 참고).
스캔 자체는 격리 대상 행위가 아니라 Packet Rule 탐지 검증이 목적이므로,
Trust/Firewall 단계까지 성공해야 SUCCESS로 판정하지 않는다.

Runner 기본 Timeout(120초)을 초과하지 않도록 --end_port 기본값을 --timeout_ms와
함께 계산한다. 기본값(포트 1~256, 포트당 150ms)은 (256개 * 150ms = 38.4초)로
120초 이내에 여유 있게 끝난다. 더 넓은 범위가 필요하면 --timeout_ms를 줄이거나
Runner의 command_timeout_seconds를 함께 조정해야 한다.

실행 예시:
  python -m attacks.port_scan_attack
  python -m attacks.port_scan_attack --target 192.168.0.10 --start_port 1 --end_port 1024 --timeout_ms 50
"""

from __future__ import annotations

import argparse
import socket
import time

from attacks.config import BROKER_HOST

# 기본 Runner Timeout(DEFAULT_COMMAND_TIMEOUT_SECONDS=120s)에 여유 있게 맞춘 기본 범위.
# 16개 이상 포트를 스캔해야 distinct_port_count > 15 조건을 만족한다.
DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 256
DEFAULT_TIMEOUT_MS = 150
_SAFETY_MARGIN_SECONDS = 20.0
_ASSUMED_RUNNER_TIMEOUT_SECONDS = 120.0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="TCP Connect Port Scan Attack")
    p.add_argument("--target", default=BROKER_HOST, help="대상 Host (기본: Raspberry Pi/Broker)")
    p.add_argument("--start_port", default=DEFAULT_START_PORT, type=int)
    p.add_argument(
        "--end_port",
        default=DEFAULT_END_PORT,
        type=int,
        help="distinct_port_count > 15를 만족하려면 최소 16개 이상 포트 필요",
    )
    p.add_argument("--timeout_ms", default=DEFAULT_TIMEOUT_MS, type=int, help="포트당 connect timeout(ms)")
    return p.parse_args()


def _validate_args(args: argparse.Namespace) -> None:
    if args.start_port < 1 or args.end_port < args.start_port or args.end_port > 65535:
        raise SystemExit(
            f"포트 범위가 올바르지 않습니다 (start_port={args.start_port}, end_port={args.end_port})"
        )
    if args.timeout_ms <= 0:
        raise SystemExit(f"--timeout_ms는 0보다 커야 합니다 (입력값: {args.timeout_ms})")

    port_count = args.end_port - args.start_port + 1
    worst_case_seconds = port_count * (args.timeout_ms / 1000.0)
    # Runner의 DEFAULT_COMMAND_TIMEOUT_SECONDS(120s)를 초과할 위험이 있으면 조기에 거부한다.
    if worst_case_seconds > _ASSUMED_RUNNER_TIMEOUT_SECONDS - _SAFETY_MARGIN_SECONDS:
        raise SystemExit(
            f"port_count({port_count}) * timeout_ms({args.timeout_ms}) 최악 소요 시간이 "
            f"약 {worst_case_seconds:.1f}초로 Runner 기본 Timeout"
            f"({_ASSUMED_RUNNER_TIMEOUT_SECONDS:.0f}초)에 근접하거나 초과할 수 있습니다. "
            "--end_port를 줄이거나 --timeout_ms를 낮추세요."
        )
    if port_count <= 15:
        print(
            f"[PortScan] 경고: port_count={port_count}로 distinct_port_count > 15 조건을 "
            "만족하지 못할 수 있습니다."
        )


def main() -> None:
    args = parse_args()
    _validate_args(args)
    timeout_s = args.timeout_ms / 1000.0
    ports = range(args.start_port, args.end_port + 1)
    port_count = len(list(ports))

    print(f"[PortScan] target={args.target} ports={args.start_port}-{args.end_port} ({port_count}개)")
    print(f"  탐지 조건: distinct_port_count > 15 AND syn_count > 15 (기본 Policy)")
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