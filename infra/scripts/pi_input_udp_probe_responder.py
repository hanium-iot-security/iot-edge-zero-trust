#!/usr/bin/env python3
"""Foreground, opt-in UDP response helper for one physical ESP32 probe.

Default invocation only prints its plan. No firewall, DB, service or credentials
are touched. The serving CLI has fixed addresses and finite resource limits.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import socket
import sys
import time

PI_ADDRESS = "192.168.0.20"
DEVICE_ADDRESS = "192.168.0.5"
PORT = 9002
DEVICE_PORT = 42100
MAX_BYTES = 128
# Read one complete UDP datagram (fixed 64 KiB ceiling) so Windows does not
# turn an oversized test packet into WSAEMSGSIZE. Acceptance remains 128 B.
MAX_DATAGRAM_BYTES = 65535
OVERALL_SECONDS = 300
IDLE_SECONDS = 120
MAX_DATAGRAMS = 30
REQUEST_PREFIX = b"P9UDP:"
REPLY_PREFIX = b"P9UDP-ACK:"
NONCE = re.compile(rb"[A-Za-z0-9_-]{8,32}\Z")


def reply_for(payload: bytes, peer: tuple[str, int], *,
              expected_address: str = DEVICE_ADDRESS,
              expected_port: int = DEVICE_PORT) -> bytes | None:
    """Return a response only to the exact source and a valid bounded nonce."""
    if peer != (expected_address, expected_port) or len(payload) > MAX_BYTES:
        return None
    if not payload.startswith(REQUEST_PREFIX):
        return None
    nonce = payload[len(REQUEST_PREFIX):]
    return REPLY_PREFIX + nonce if NONCE.fullmatch(nonce) else None


def serve_socket(sock: socket.socket, *, expected_address: str = DEVICE_ADDRESS,
                 expected_port: int = DEVICE_PORT,
                 overall_seconds: float = OVERALL_SECONDS,
                 idle_seconds: float = IDLE_SECONDS,
                 max_datagrams: int = MAX_DATAGRAMS,
                 emit=lambda event: None) -> dict[str, object]:
    """Use an already bound socket; caller owns its lifetime.

    This separate loop permits real loopback protocol tests without binding a
    production address or requiring Linux/root in the test process.
    """
    if overall_seconds <= 0 or idle_seconds <= 0 or max_datagrams < 1:
        raise ValueError("positive limits required")
    started = last_received = time.monotonic()
    received = replied = 0
    while True:
        now = time.monotonic()
        remaining = min(started + overall_seconds - now,
                        last_received + idle_seconds - now)
        if remaining <= 0:
            reason = ("overall_timeout" if now >= started + overall_seconds
                      else "idle_timeout")
            break
        if received >= max_datagrams:
            reason = "datagram_budget"
            break
        sock.settimeout(remaining)
        try:
            payload, peer = sock.recvfrom(MAX_DATAGRAM_BYTES)
        except socket.timeout:
            continue
        received += 1
        last_received = time.monotonic()
        reply = reply_for(payload, peer, expected_address=expected_address,
                          expected_port=expected_port)
        if reply is None:
            emit({"kind": "rejected", "source_ip": peer[0],
                  "source_port": peer[1], "bytes": len(payload)})
            continue
        sent = sock.sendto(reply, peer)
        if sent != len(reply):
            raise OSError("short UDP response")
        replied += 1
        emit({"kind": "response_sent", "source_ip": peer[0],
              "source_port": peer[1],
              "nonce": payload[len(REQUEST_PREFIX):].decode("ascii"),
              "bytes": sent})
    return {"kind": "stopped", "reason": reason, "received": received,
            "replied": replied, "elapsed_seconds": round(time.monotonic() - started, 3)}


def plan() -> dict[str, object]:
    return {"kind": "physical_esp32_udp_probe_plan", "executed": False,
            "bind_ip": PI_ADDRESS, "port": PORT,
            "only_source_ip": DEVICE_ADDRESS, "only_source_port": DEVICE_PORT,
            "max_payload_bytes": MAX_BYTES, "max_datagrams": MAX_DATAGRAMS,
            "overall_seconds": OVERALL_SECONDS, "idle_seconds": IDLE_SECONDS,
            "foreground_only": True, "root_allowed": False}


def _emit(event: dict[str, object]) -> None:
    print(json.dumps(event, ensure_ascii=True), flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true",
                        help="serve only on the fixed Pi address after physical-test approval")
    args = parser.parse_args(argv)
    if not args.serve:
        _emit(plan())
        return 0
    if sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() == 0:
        parser.error("serving requires Linux and an unprivileged user")
    if (PI_ADDRESS != "192.168.0.20" or DEVICE_ADDRESS != "192.168.0.5"
            or not ipaddress.IPv4Address(PI_ADDRESS).is_private
            or not ipaddress.IPv4Address(DEVICE_ADDRESS).is_private):
        parser.error("fixed testbed address contract changed")
    # No address/port overrides, reuse-port, wildcard bind, thread or daemon.
    prior = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    def stop(signum, frame):
        raise KeyboardInterrupt
    try:
        for sig in prior:
            signal.signal(sig, stop)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((PI_ADDRESS, PORT))
            _emit({**plan(), "kind": "ready", "executed": True})
            try:
                _emit(serve_socket(sock, emit=_emit))
            except KeyboardInterrupt:
                _emit({"kind": "stopped", "reason": "operator_stop"})
    except OSError as error:
        _emit({"kind": "failed", "error": str(error)})
        return 2
    finally:
        for sig, handler in prior.items():
            signal.signal(sig, handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
