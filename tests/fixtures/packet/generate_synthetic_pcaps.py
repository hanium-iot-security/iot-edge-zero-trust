"""empty_window.pcap / partial_capture.pcap 합성 생성 스크립트.

실제 트래픽으로는 "패킷이 0개인 10초 구간"이나 "쓰다가 잘린 pcap"을 안정적으로
재현하기 어렵기 때문에, 표준 libpcap 파일 포맷을 struct로 직접 작성해 결정적으로
만듭니다. dpkt/scapy 등 외부 의존성이 없습니다.

Test Pack의 나머지 3개(normal_mqtt, port_scan, packet_flood)는 실제 Raspberry Pi
#1 + ESP32에서 tcpdump로 수집해야 합니다 (docs/packet-capture-runbook.md 참고).

사용법:
    python tests/fixtures/packet/generate_synthetic_pcaps.py [출력 디렉터리]
    (기본 출력 디렉터리: tests/fixtures/packet/pcap/)
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

# libpcap 표준 global header (24 bytes, little-endian, microsecond timestamp)
_MAGIC_NUMBER = 0xA1B2C3D4
_VERSION_MAJOR = 2
_VERSION_MINOR = 4
_THISZONE = 0
_SIGFIGS = 0
_SNAPLEN = 65535
_LINKTYPE_ETHERNET = 1


def _build_global_header() -> bytes:
    return struct.pack(
        "<IHHiIII",
        _MAGIC_NUMBER,
        _VERSION_MAJOR,
        _VERSION_MINOR,
        _THISZONE,
        _SIGFIGS,
        _SNAPLEN,
        _LINKTYPE_ETHERNET,
    )


def _build_packet_record(*, ts_sec: int, ts_usec: int, incl_len: int, orig_len: int, payload: bytes) -> bytes:
    """per-packet record header(16 bytes) + payload.

    incl_len이 실제 payload 길이보다 크면, 이 레코드는 의도적으로 잘린(truncated)
    상태가 됩니다 (partial_capture.pcap 생성에 사용).
    """
    header = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
    return header + payload


def _minimal_ethernet_ipv4_tcp_syn_packet() -> bytes:
    """정상적으로 파싱 가능한 최소 Ethernet/IPv4/TCP SYN 패킷 (파싱 자체를 검증하려는
    목적이 아니라, "정상 레코드 하나 + 잘린 레코드 하나"의 조합을 만들기 위한 용도입니다.
    프로토콜 상세 파싱 검증은 Packet Feature Extractor(dpkt 기반) 담당입니다.
    """
    eth_dst = b"\x00\x11\x22\x33\x44\x55"
    eth_src = b"\x66\x77\x88\x99\xaa\xbb"
    eth_type = b"\x08\x00"  # IPv4
    eth_header = eth_dst + eth_src + eth_type

    # IPv4 header (20 bytes, no options)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # version(4) + IHL(5)
        0,  # DSCP/ECN
        40,  # total length (IP header 20 + TCP header 20)
        0,  # identification
        0,  # flags/fragment offset
        64,  # TTL
        6,  # protocol: TCP
        0,  # checksum (검증 목적 아니므로 0으로 둠)
        bytes([192, 168, 0, 4]),
        bytes([192, 168, 0, 20]),
    )

    # TCP header (20 bytes, SYN flag, destination port 1883)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        51000,  # source port
        1883,  # destination port (MQTT)
        0,  # sequence number
        0,  # ack number
        0x50,  # data offset(5) << 4
        0x02,  # flags: SYN
        65535,  # window size
        0,  # checksum
        0,  # urgent pointer
    )

    return eth_header + ip_header + tcp_header


def generate_empty_window_pcap(output_path: Path) -> None:
    """패킷이 하나도 없는, 정상적으로 닫힌 10초 Window pcap.

    Extractor 입장에서는 "정상 종료됐지만 대상 Packet이 없는 경우" (Segment 상태 EMPTY)를
    검증하는 데 사용합니다. global header만 있고 패킷 레코드는 0개입니다.
    """
    output_path.write_bytes(_build_global_header())


def generate_partial_capture_pcap(output_path: Path) -> None:
    """쓰는 도중 프로세스가 죽어서 마지막 레코드가 중간에 잘린 pcap.

    global header + 정상 레코드 1개 + "incl_len은 100바이트라고 선언했지만 실제로는
    20바이트만 쓰이고 파일이 끝난" 잘린 레코드로 구성됩니다. Capture Wrapper가
    재시작 시 이런 .pcap.tmp를 PARTIAL_CAPTURE로 처리하는지, 혹은 Extractor가 이런
    ready pcap을 열었을 때 파싱 실패로 처리하는지 검증하는 데 사용합니다.
    """
    payload = _minimal_ethernet_ipv4_tcp_syn_packet()
    complete_record = _build_packet_record(
        ts_sec=1_752_537_610,  # 2026-07-15T00:00:10Z
        ts_usec=0,
        incl_len=len(payload),
        orig_len=len(payload),
        payload=payload,
    )

    truncated_payload = payload[:20]  # 실제로는 20바이트만 쓰고 파일이 끊김
    truncated_record = _build_packet_record(
        ts_sec=1_752_537_611,
        ts_usec=500_000,
        incl_len=len(payload),  # 선언은 원래 길이(len(payload))
        orig_len=len(payload),
        payload=truncated_payload,  # 그러나 실제로는 20바이트만 존재
    )

    output_path.write_bytes(_build_global_header() + complete_record + truncated_record)


def main() -> None:
    output_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tests/fixtures/packet/pcap")
    output_dir.mkdir(parents=True, exist_ok=True)

    empty_path = output_dir / "empty_window.pcap"
    partial_path = output_dir / "partial_capture.pcap"

    generate_empty_window_pcap(empty_path)
    generate_partial_capture_pcap(partial_path)

    print(f"생성 완료: {empty_path} ({empty_path.stat().st_size} bytes)")
    print(f"생성 완료: {partial_path} ({partial_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()