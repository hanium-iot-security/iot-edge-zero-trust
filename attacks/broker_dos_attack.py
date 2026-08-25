"""Bounded Broker DoS Packet Rule smoke generator.

This tool repeatedly opens and closes short TCP connections to the MQTT
listener.  It is intentionally limited to loopback/private IPv4 targets and
bounded counts, rates, timeouts, and total duration.  Use it only on the
project's isolated lab network.

The Packet Feature Extractor does not decode MQTT application payloads for
``mqtt_related_packet_count``.  It counts TCP packets whose source or
destination port is 1883.  A successful TCP connection therefore contributes
an inbound SYN and an inbound handshake ACK to the Pi-side INBOUND feature
row.  The official 24-connection smoke plan is sized to exceed the strict
Packet Rule v3 contract (``tcp_syn_count > 10`` and
``mqtt_related_packet_count > 20``) without an unbounded flood.

Example (Pi4 Attack/Test Node -> Pi5 broker)::

    python -m attacks.broker_dos_attack --target-host 192.168.0.20

The generator reports connection attempts, not captured Feature values.  The
Packet Feature row and ``BROKER_DOS_SUSPECTED`` event remain the authoritative
physical-smoke evidence.
"""

from __future__ import annotations

import argparse
import ipaddress
import math
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass

from attacks.config import BROKER_HOST


DEFAULT_TARGET_PORT = 1883
DEFAULT_CONNECTION_COUNT = 24
DEFAULT_RATE_CPS = 8.0
DEFAULT_CONNECT_TIMEOUT_MS = 200

MIN_CONNECTION_COUNT = 1
MAX_CONNECTION_COUNT = 100
MIN_RATE_CPS = 0.1
MAX_RATE_CPS = 20.0
MIN_CONNECT_TIMEOUT_MS = 1
MAX_CONNECT_TIMEOUT_MS = 2000
MAX_BOUNDED_DURATION_SECONDS = 30.0


@dataclass(frozen=True)
class AttackPlan:
    target_host: str
    target_port: int
    count: int
    rate_cps: float
    connect_timeout_ms: int

    @property
    def nominal_duration_seconds(self) -> float:
        return self.count / self.rate_cps

    @property
    def worst_case_duration_seconds(self) -> float:
        return max(
            self.nominal_duration_seconds,
            self.count * (self.connect_timeout_ms / 1000.0),
        )

    @property
    def planned_tcp_syn_count(self) -> int:
        return self.count

    @property
    def planned_mqtt_related_packet_count(self) -> int:
        # A successful TCP handshake contributes inbound SYN + ACK packets.
        return self.count * 2


@dataclass(frozen=True)
class AttackResult:
    attempted: int
    succeeded: int
    failed: int
    elapsed_seconds: float
    interrupted: bool


def _is_private_or_loopback_ipv4(host: str) -> bool:
    if host.strip().lower() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.version == 4 and (address.is_private or address.is_loopback)


def build_attack_plan(
    *,
    target_host: str,
    target_port: int = DEFAULT_TARGET_PORT,
    count: int = DEFAULT_CONNECTION_COUNT,
    rate_cps: float = DEFAULT_RATE_CPS,
    connect_timeout_ms: int = DEFAULT_CONNECT_TIMEOUT_MS,
) -> AttackPlan:
    """Validate inputs and return a finite, bounded connection plan."""
    normalized_host = target_host.strip()
    if not normalized_host:
        raise ValueError("--target-host must be non-empty")
    if not _is_private_or_loopback_ipv4(normalized_host):
        raise ValueError("--target-host must be a private or loopback IPv4 address")
    if target_port != DEFAULT_TARGET_PORT:
        raise ValueError(
            f"--target-port must be {DEFAULT_TARGET_PORT} because "
            "mqtt_related_packet_count only counts TCP port 1883"
        )
    if not MIN_CONNECTION_COUNT <= count <= MAX_CONNECTION_COUNT:
        raise ValueError(
            f"--count must be in {MIN_CONNECTION_COUNT}..{MAX_CONNECTION_COUNT}"
        )
    if not math.isfinite(rate_cps) or not MIN_RATE_CPS <= rate_cps <= MAX_RATE_CPS:
        raise ValueError(f"--rate-cps must be finite and in {MIN_RATE_CPS}..{MAX_RATE_CPS}")
    if not MIN_CONNECT_TIMEOUT_MS <= connect_timeout_ms <= MAX_CONNECT_TIMEOUT_MS:
        raise ValueError(
            "--connect-timeout-ms must be in "
            f"{MIN_CONNECT_TIMEOUT_MS}..{MAX_CONNECT_TIMEOUT_MS}"
        )

    plan = AttackPlan(
        target_host=normalized_host,
        target_port=target_port,
        count=count,
        rate_cps=rate_cps,
        connect_timeout_ms=connect_timeout_ms,
    )
    if plan.worst_case_duration_seconds > MAX_BOUNDED_DURATION_SECONDS:
        raise ValueError(
            "bounded duration exceeds "
            f"{MAX_BOUNDED_DURATION_SECONDS:.0f}s "
            f"(calculated={plan.worst_case_duration_seconds:.1f}s)"
        )
    return plan


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bounded Broker DoS Packet Rule smoke (private lab networks only)"
    )
    parser.add_argument("--target-host", default=BROKER_HOST)
    parser.add_argument(
        "--target-port", "--target_port", dest="target_port", type=int,
        default=DEFAULT_TARGET_PORT,
    )
    parser.add_argument("--count", type=int, default=DEFAULT_CONNECTION_COUNT)
    parser.add_argument(
        "--rate-cps", "--rate_cps", dest="rate_cps", type=float,
        default=DEFAULT_RATE_CPS,
    )
    parser.add_argument(
        "--connect-timeout-ms", "--connect_timeout_ms",
        dest="connect_timeout_ms", type=int, default=DEFAULT_CONNECT_TIMEOUT_MS,
    )
    return parser.parse_args(argv)


def _attempt_connection(host: str, port: int, timeout_seconds: float) -> bool:
    """Attempt one TCP connection and always close the socket."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout_seconds)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


def execute_attack(
    plan: AttackPlan,
    *,
    connect_attempt: Callable[[str, int, float], bool] = _attempt_connection,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> AttackResult:
    """Execute at most ``plan.count`` connection attempts at the planned rate."""
    # Keep the safety boundary in the executor as well as the CLI/build path so
    # programmatic callers cannot bypass the bounds by constructing AttackPlan.
    plan = build_attack_plan(
        target_host=plan.target_host,
        target_port=plan.target_port,
        count=plan.count,
        rate_cps=plan.rate_cps,
        connect_timeout_ms=plan.connect_timeout_ms,
    )
    started = monotonic()
    attempted = 0
    succeeded = 0
    interrupted = False
    timeout_seconds = plan.connect_timeout_ms / 1000.0

    try:
        for index in range(plan.count):
            scheduled_at = started + (index / plan.rate_cps)
            delay = scheduled_at - monotonic()
            if delay > 0:
                sleep(delay)

            connected = connect_attempt(
                plan.target_host,
                plan.target_port,
                timeout_seconds,
            )
            attempted += 1
            if connected:
                succeeded += 1
    except KeyboardInterrupt:
        interrupted = True

    elapsed = monotonic() - started
    return AttackResult(
        attempted=attempted,
        succeeded=succeeded,
        failed=attempted - succeeded,
        elapsed_seconds=elapsed,
        interrupted=interrupted,
    )


def main() -> None:
    args = parse_args()
    try:
        plan = build_attack_plan(
            target_host=args.target_host,
            target_port=args.target_port,
            count=args.count,
            rate_cps=args.rate_cps,
            connect_timeout_ms=args.connect_timeout_ms,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    print("[BrokerDoS] bounded Packet Rule smoke — private lab networks only")
    print(f"  target={plan.target_host}:{plan.target_port}")
    print(
        f"  count={plan.count}, rate_cps={plan.rate_cps:g}, "
        f"connect_timeout_ms={plan.connect_timeout_ms}"
    )
    print(
        "  expected Feature contract (successful handshakes): "
        f"tcp_syn_count≈{plan.planned_tcp_syn_count}, "
        f"mqtt_related_packet_count≈{plan.planned_mqtt_related_packet_count}"
    )
    print("  expected Event: BROKER_DOS_SUSPECTED (strict >10 SYN AND >20 port-1883 TCP)")

    result = execute_attack(plan)
    effective_rate = (
        result.attempted / result.elapsed_seconds if result.elapsed_seconds > 0 else 0.0
    )
    status = "interrupted" if result.interrupted else "completed"
    print(
        f"[BrokerDoS] {status} — attempted={result.attempted}, "
        f"connected={result.succeeded}, failed={result.failed}, "
        f"elapsed={result.elapsed_seconds:.2f}s, effective_cps={effective_rate:.1f}"
    )
    print("  captured Packet Feature/Event를 실제 Smoke 판정 근거로 사용하세요.")


if __name__ == "__main__":
    main()
