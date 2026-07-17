"""pcap을 파싱하고 10초 Packet Feature를 계산합니다."""

from __future__ import annotations

import calendar
import csv
import struct
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import dpkt


INBOUND = "INBOUND"
OUTBOUND = "OUTBOUND"
MQTT_PORT = 1883
TCP_SYN = 0x02

# pcap 파일 구조 상수
PCAP_GLOBAL_HEADER_SIZE = 24   # magic + version + zone + sigfigs + snaplen + network
PCAP_RECORD_HEADER_SIZE = 16   # ts_sec + ts_usec + caplen + orig_len
PCAP_MAGIC_LE = 0xa1b2c3d4    # little-endian pcap (표준)
PCAP_MAGIC_BE = 0xd4c3b2a1    # big-endian pcap


class PcapParseError(Exception):
    """pcap 파일 자체가 손상되었거나 읽을 수 없을 때 발생합니다."""


class UnsupportedPcapFormat(PcapParseError):
    """지원하지 않는 Datalink 타입의 pcap 파일입니다."""


class PartialPcapError(PcapParseError):
    """일부 패킷만 파싱에 실패한 pcap 파일입니다 (나머지는 정상 파싱됨)."""


DLT_EN10MB = 1


@dataclass
class ParsedPacket:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None
    dst_port: int | None
    tcp_flags: int | None
    packet_length: int


def _bytes_to_ip(ip_bytes: bytes) -> str:
    return ".".join(str(b) for b in ip_bytes)


def parse_pcap(path: Path) -> list[ParsedPacket]:
    """pcap 파일에서 IP 패킷 목록을 반환합니다.

    - 파일 없음: FileNotFoundError
    - 깨진 pcap / Reader 초기화 실패: PcapParseError
    - 정상 파싱이지만 IP 패킷 없음: []
    - 일부 패킷 파싱 실패: PartialPcapError
    - 모든 패킷 파싱 실패: PcapParseError
    """
    if not path.exists():
        raise FileNotFoundError(f"pcap 파일을 찾을 수 없습니다: {path}")

    packets: list[ParsedPacket] = []
    try:
        with open(path, "rb") as f:
            try:
                reader = dpkt.pcap.Reader(f)
            except Exception as e:
                raise PcapParseError(f"pcap Reader 초기화 실패: {path}") from e

            if reader.datalink() != DLT_EN10MB:
                raise UnsupportedPcapFormat(
                    f"지원하지 않는 Datalink 타입: {reader.datalink()} "
                    f"(Ethernet=1만 지원): {path}"
                )

            # dpkt.pcap.Reader는 caplen보다 짧은 body도 오류 없이 반환한다.
            # Record Header 잘림·Body 잘림을 직접 감지하기 위해
            # global header 이후를 raw bytes로 읽어 각 record의 완결성을 검증한다.
            f.seek(0)
            magic_le = struct.unpack("<I", f.read(4))[0]
            endian = "<" if magic_le == PCAP_MAGIC_LE else ">"
            f.seek(PCAP_GLOBAL_HEADER_SIZE)

            total_records = 0
            valid_records = 0  # Ethernet 파싱까지 성공한 record 수 (ARP/IPv6 포함)
            parse_errors = 0

            while True:
                hdr_raw = f.read(PCAP_RECORD_HEADER_SIZE)
                if not hdr_raw:
                    break  # 정상 EOF
                if len(hdr_raw) < PCAP_RECORD_HEADER_SIZE:
                    # Record Header 잘림
                    parse_errors += 1
                    break

                ts_sec, ts_usec, caplen, _orig_len = struct.unpack(
                    f"{endian}IIII", hdr_raw
                )
                body = f.read(caplen)
                total_records += 1

                if len(body) < caplen:
                    # Body 잘림: 더 읽을 수 없으므로 즉시 종료
                    parse_errors += 1
                    break

                ts = ts_sec + ts_usec / 1e6

                try:
                    eth = dpkt.ethernet.Ethernet(body)
                    valid_records += 1  # Ethernet 파싱 성공 (IP 여부 무관)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    src_ip = _bytes_to_ip(ip.src)
                    dst_ip = _bytes_to_ip(ip.dst)
                    packet_length = ip.len

                    protocol = "OTHER"
                    src_port: int | None = None
                    dst_port: int | None = None
                    tcp_flags: int | None = None

                    if isinstance(ip.data, dpkt.tcp.TCP):
                        protocol = "TCP"
                        tcp = ip.data
                        src_port = tcp.sport
                        dst_port = tcp.dport
                        tcp_flags = tcp.flags
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        protocol = "UDP"
                        udp = ip.data
                        src_port = udp.sport
                        dst_port = udp.dport

                    packets.append(ParsedPacket(
                        timestamp=ts,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol=protocol,
                        src_port=src_port,
                        dst_port=dst_port,
                        tcp_flags=tcp_flags,
                        packet_length=packet_length,
                    ))
                except Exception:
                    parse_errors += 1
                    continue

            if parse_errors > 0:
                # valid_records가 0이면 정상 파싱된 record가 하나도 없음 (ARP/IPv6 포함)
                if valid_records == 0:
                    raise PcapParseError(
                        f"모든 레코드 파싱 실패 ({parse_errors}/{total_records}): {path}"
                    )
                raise PartialPcapError(
                    f"일부 레코드 파싱 실패 ({parse_errors}/{total_records}): {path}"
                )
    except PcapParseError:
        raise
    except Exception as e:
        raise PcapParseError(f"pcap 읽기 실패: {path}") from e

    return packets


def classify_direction(
    src_ip: str,
    dst_ip: str,
    pi_ip: str,
) -> tuple[str, str] | tuple[None, None]:
    """INBOUND/OUTBOUND 방향과 peer_ip를 반환합니다. Pi와 무관한 패킷이면 (None, None)."""
    if dst_ip == pi_ip:
        return INBOUND, src_ip
    if src_ip == pi_ip:
        return OUTBOUND, dst_ip
    return None, None


def _inter_arrival_times(timestamps: list[float]) -> list[float]:
    sorted_ts = sorted(timestamps)
    return [sorted_ts[i] - sorted_ts[i - 1] for i in range(1, len(sorted_ts))]


def _is_mqtt_related(protocol: str, src_port: int | None, dst_port: int | None) -> bool:
    return protocol == "TCP" and (src_port == MQTT_PORT or dst_port == MQTT_PORT)


def _is_non_mqtt_tcp_udp(
    protocol: str,
    src_port: int | None,
    dst_port: int | None,
) -> bool:
    if protocol not in ("TCP", "UDP"):
        return False
    if protocol == "TCP" and (src_port == MQTT_PORT or dst_port == MQTT_PORT):
        return False
    return True


def build_packet_features(
    packets: list[ParsedPacket],
    pi_ip: str,
    window_start: datetime,
    window_end: datetime,
) -> list[dict[str, Any]]:
    """peer_ip + direction 기준 그룹별 Packet Feature row 리스트를 반환합니다.

    window_start/window_end는 UTC datetime 기준입니다.
    timezone 정보가 없는 값은 UTC로 간주하며, UTC-aware 값도 허용합니다.
    window에 해당 패킷이 없으면 빈 리스트를 반환합니다.
    """
    # UTC datetime을 epoch second로 변환
    window_start_ts = float(calendar.timegm(window_start.timetuple()))
    window_end_ts = float(calendar.timegm(window_end.timetuple()))

    window_start_str = window_start.strftime("%Y-%m-%dT%H:%M:%SZ")
    window_end_str = window_end.strftime("%Y-%m-%dT%H:%M:%SZ")

    groups: dict[tuple[str, str], list[ParsedPacket]] = {}
    for pkt in packets:
        if not (window_start_ts <= pkt.timestamp < window_end_ts):
            continue
        direction, peer_ip = classify_direction(pkt.src_ip, pkt.dst_ip, pi_ip)
        if direction is None or peer_ip is None:
            continue
        key = (peer_ip, direction)
        if key not in groups:
            groups[key] = []
        groups[key].append(pkt)

    rows: list[dict[str, Any]] = []
    for (peer_ip, direction), group in sorted(groups.items()):
        timestamps = [pkt.timestamp for pkt in group]
        intervals = _inter_arrival_times(timestamps)
        lengths = [pkt.packet_length for pkt in group]

        rows.append({
            "peer_ip": peer_ip,
            "direction": direction,
            "window_start": window_start_str,
            "window_end": window_end_str,
            "packet_count": len(group),
            "total_bytes": sum(lengths),
            "avg_packet_size": sum(lengths) / len(lengths),
            "max_packet_size": max(lengths),
            "mean_inter_arrival_time": sum(intervals) / len(intervals) if intervals else 0.0,
            "distinct_dest_port_count": len({
                pkt.dst_port
                for pkt in group
                if pkt.protocol in ("TCP", "UDP") and pkt.dst_port is not None
            }),
            "tcp_syn_count": sum(
                1 for pkt in group
                if pkt.protocol == "TCP"
                and pkt.tcp_flags is not None
                and (pkt.tcp_flags & TCP_SYN)
            ),
            "mqtt_related_packet_count": sum(
                1 for pkt in group
                if _is_mqtt_related(pkt.protocol, pkt.src_port, pkt.dst_port)
            ),
            "non_mqtt_tcp_udp_packet_count": sum(
                1 for pkt in group
                if _is_non_mqtt_tcp_udp(pkt.protocol, pkt.src_port, pkt.dst_port)
            ),
        })

    return rows


# --- Device ID 매핑 ---

def build_ip_device_map(device_rows: list[dict[str, Any]]) -> dict[str, str]:
    """DB에서 조회한 devices rows를 {ip_address: device_id} 매핑으로 변환합니다.

    ip_address가 None이거나 빈 문자열인 row는 무시합니다.
    """
    return {
        str(row["ip_address"]): str(row["device_id"])
        for row in device_rows
        if row.get("ip_address")
    }


def resolve_device_id(peer_ip: str, ip_device_map: dict[str, str]) -> str | None:
    """peer_ip를 device_id로 변환합니다. 매핑 실패 시 None을 반환합니다."""
    return ip_device_map.get(peer_ip)


# --- CSV Export ---

CSV_FIELDS = (
    "session_id",
    "device_id",
    "peer_ip",
    "direction",
    "window_start",
    "window_end",
    "packet_count",
    "total_bytes",
    "avg_packet_size",
    "max_packet_size",
    "mean_inter_arrival_time",
    "distinct_dest_port_count",
    "tcp_syn_count",
    "mqtt_related_packet_count",
    "non_mqtt_tcp_udp_packet_count",
)


def export_packet_features_csv(
    rows: list[dict[str, Any]],
    output_path: Path,
) -> int:
    """Packet Feature rows를 CSV로 저장하고 저장된 row 수를 반환합니다.

    rows에 없는 CSV_FIELDS 컬럼은 빈 문자열로 채웁니다.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in CSV_FIELDS})
    return len(rows)
