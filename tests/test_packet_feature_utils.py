"""packet_feature_utils.py 순수 함수 테스트."""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

import pytest

from edge.features.packet_feature_utils import (
    CSV_FIELDS,
    INBOUND,
    OUTBOUND,
    ParsedPacket,
    PartialPcapError,
    PcapParseError,
    UnsupportedPcapFormat,
    _inter_arrival_times,
    _is_mqtt_related,
    _is_non_mqtt_tcp_udp,
    build_ip_device_map,
    build_packet_features,
    classify_direction,
    export_packet_features_csv,
    parse_pcap,
    resolve_device_id,
)

PI_IP = "192.168.0.20"
ESP_IP = "192.168.0.10"
EXTERNAL_IP = "10.0.0.1"

WINDOW_START = datetime(2025, 1, 1, 0, 0, 0)
WINDOW_END = datetime(2025, 1, 1, 0, 0, 10)

# WINDOW_START epoch (UTC): 1735689600.0
WINDOW_TS = 1735689600.0


def _tcp_pkt(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    flags: int = 0x00,
    length: int = 100,
    offset: float = 0.0,
) -> ParsedPacket:
    return ParsedPacket(
        timestamp=WINDOW_TS + offset,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol="TCP",
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags,
        packet_length=length,
    )


def _udp_pkt(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    length: int = 80,
    offset: float = 0.0,
) -> ParsedPacket:
    return ParsedPacket(
        timestamp=WINDOW_TS + offset,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol="UDP",
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=None,
        packet_length=length,
    )


class TestParsePcap:
    def test_file_not_found_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            parse_pcap(tmp_path / "nonexistent.pcap")

    def test_corrupted_pcap_raises_parse_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.pcap"
        bad.write_bytes(b"\x00\x01\x02\x03")  # 잘못된 magic bytes
        with pytest.raises(PcapParseError):
            parse_pcap(bad)

    def test_empty_file_raises_parse_error(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.pcap"
        empty.write_bytes(b"")
        with pytest.raises(PcapParseError):
            parse_pcap(empty)

    def test_non_ethernet_datalink_raises_unsupported_format(self, tmp_path: Path) -> None:
        """Ethernet(DLT=1)이 아닌 pcap은 UnsupportedPcapFormat을 발생시킨다."""
        import dpkt

        pcap_path = tmp_path / "loopback.pcap"
        DLT_NULL = 0  # loopback
        with open(pcap_path, "wb") as f:
            writer = dpkt.pcap.Writer(f, linktype=DLT_NULL)
            writer.writepkt(b"\x00" * 20)

        with pytest.raises(UnsupportedPcapFormat):
            parse_pcap(pcap_path)

    def test_all_packets_corrupted_raises_parse_error(self, tmp_path: Path) -> None:
        """유효한 Ethernet pcap이지만 모든 패킷이 파싱 실패하면 PcapParseError."""
        import dpkt
        from unittest.mock import patch

        pcap_path = tmp_path / "all_corrupt.pcap"
        with open(pcap_path, "wb") as f:
            writer = dpkt.pcap.Writer(f)
            writer.writepkt(b"\x00" * 14)  # 패킷 1개

        with patch(
            "edge.features.packet_feature_utils.dpkt.ethernet.Ethernet",
            side_effect=Exception("forced parse failure"),
        ):
            with pytest.raises(PcapParseError) as exc_info:
                parse_pcap(pcap_path)
        # PartialPcapError가 아닌 기본 PcapParseError여야 함 (전체 실패)
        assert not isinstance(exc_info.value, PartialPcapError)

    def test_partial_packets_corrupted_raises_partial_pcap_error(
        self, tmp_path: Path
    ) -> None:
        """정상 1개 + 손상 1개: 일부 실패면 PartialPcapError를 발생시킨다."""
        import dpkt
        from unittest.mock import patch

        pcap_path = tmp_path / "partial_corrupt.pcap"
        with open(pcap_path, "wb") as f:
            writer = dpkt.pcap.Writer(f)
            writer.writepkt(b"\x00" * 14)  # 패킷 1
            writer.writepkt(b"\x00" * 14)  # 패킷 2

        call_count = [0]
        original = dpkt.ethernet.Ethernet

        def _sometimes_fail(buf):
            call_count[0] += 1
            if call_count[0] == 2:
                raise Exception("forced failure on 2nd packet")
            return original(buf)

        with patch(
            "edge.features.packet_feature_utils.dpkt.ethernet.Ethernet",
            side_effect=_sometimes_fail,
        ):
            with pytest.raises(PartialPcapError):
                parse_pcap(pcap_path)


class TestClassifyDirection:
    def test_inbound(self) -> None:
        direction, peer_ip = classify_direction(ESP_IP, PI_IP, PI_IP)
        assert direction == INBOUND
        assert peer_ip == ESP_IP

    def test_outbound(self) -> None:
        direction, peer_ip = classify_direction(PI_IP, ESP_IP, PI_IP)
        assert direction == OUTBOUND
        assert peer_ip == ESP_IP

    def test_unrelated_returns_none(self) -> None:
        direction, peer_ip = classify_direction(ESP_IP, EXTERNAL_IP, PI_IP)
        assert direction is None
        assert peer_ip is None


class TestInterArrivalTimes:
    def test_empty(self) -> None:
        assert _inter_arrival_times([]) == []

    def test_single(self) -> None:
        assert _inter_arrival_times([1.0]) == []

    def test_two_packets(self) -> None:
        result = _inter_arrival_times([1.0, 3.0])
        assert result == pytest.approx([2.0])

    def test_three_packets_sorted(self) -> None:
        result = _inter_arrival_times([5.0, 1.0, 3.0])
        assert result == pytest.approx([2.0, 2.0])


class TestMqttRelated:
    def test_tcp_dst_1883(self) -> None:
        assert _is_mqtt_related("TCP", 50000, 1883) is True

    def test_tcp_src_1883(self) -> None:
        assert _is_mqtt_related("TCP", 1883, 50000) is True

    def test_tcp_neither(self) -> None:
        assert _is_mqtt_related("TCP", 443, 80) is False

    def test_none_ports(self) -> None:
        assert _is_mqtt_related("TCP", None, None) is False

    def test_udp_1883_is_not_mqtt(self) -> None:
        """UDP 1883은 MQTT(TCP 전용)가 아니다."""
        assert _is_mqtt_related("UDP", 50000, 1883) is False
        assert _is_mqtt_related("UDP", 1883, 50000) is False


class TestNonMqttTcpUdp:
    def test_tcp_non_mqtt(self) -> None:
        assert _is_non_mqtt_tcp_udp("TCP", 443, 8080) is True

    def test_udp_non_mqtt(self) -> None:
        assert _is_non_mqtt_tcp_udp("UDP", 5000, 5001) is True

    def test_tcp_mqtt_dst(self) -> None:
        assert _is_non_mqtt_tcp_udp("TCP", 50000, 1883) is False

    def test_tcp_mqtt_src(self) -> None:
        assert _is_non_mqtt_tcp_udp("TCP", 1883, 50000) is False

    def test_other_protocol(self) -> None:
        assert _is_non_mqtt_tcp_udp("OTHER", 443, 80) is False

    def test_udp_1883_is_non_mqtt(self) -> None:
        """UDP 1883은 MQTT(TCP 전용)가 아니므로 non_mqtt_tcp_udp에 포함된다."""
        assert _is_non_mqtt_tcp_udp("UDP", 50000, 1883) is True
        assert _is_non_mqtt_tcp_udp("UDP", 1883, 50000) is True


class TestBuildPacketFeatures:
    def test_empty_returns_empty_list(self) -> None:
        result = build_packet_features([], PI_IP, WINDOW_START, WINDOW_END)
        assert result == []

    def test_unrelated_packets_skipped(self) -> None:
        pkts = [_tcp_pkt(ESP_IP, EXTERNAL_IP, 443, 80)]
        result = build_packet_features(pkts, PI_IP, WINDOW_START, WINDOW_END)
        assert result == []

    def test_out_of_window_skipped(self) -> None:
        pkt = _tcp_pkt(ESP_IP, PI_IP, 50000, 1883, offset=10.0)  # timestamp == window_end
        result = build_packet_features([pkt], PI_IP, WINDOW_START, WINDOW_END)
        assert result == []

    def test_inbound_basic_fields(self) -> None:
        pkts = [_tcp_pkt(ESP_IP, PI_IP, 50000, 1883, length=100, offset=0.0)]
        rows = build_packet_features(pkts, PI_IP, WINDOW_START, WINDOW_END)

        assert len(rows) == 1
        row = rows[0]
        assert row["peer_ip"] == ESP_IP
        assert row["direction"] == INBOUND
        assert row["packet_count"] == 1
        assert row["total_bytes"] == 100
        assert row["avg_packet_size"] == pytest.approx(100.0)
        assert row["max_packet_size"] == 100
        assert row["window_start"] == "2025-01-01T00:00:00Z"
        assert row["window_end"] == "2025-01-01T00:00:10Z"

    def test_outbound_basic_fields(self) -> None:
        pkts = [_tcp_pkt(PI_IP, ESP_IP, 50000, 1883, length=60, offset=1.0)]
        rows = build_packet_features(pkts, PI_IP, WINDOW_START, WINDOW_END)

        assert len(rows) == 1
        assert rows[0]["direction"] == OUTBOUND
        assert rows[0]["peer_ip"] == ESP_IP

    def test_mean_inter_arrival_time_single_packet(self) -> None:
        pkts = [_tcp_pkt(ESP_IP, PI_IP, 50000, 1883, offset=0.0)]
        rows = build_packet_features(pkts, PI_IP, WINDOW_START, WINDOW_END)
        assert rows[0]["mean_inter_arrival_time"] == pytest.approx(0.0)

    def test_mean_inter_arrival_time_multiple_packets(self) -> None:
        pkts = [
            _tcp_pkt(ESP_IP, PI_IP, 50000, 1883, offset=0.0),
            _tcp_pkt(ESP_IP, PI_IP, 50000, 1883, offset=2.0),
            _tcp_pkt(ESP_IP, PI_IP, 50000, 1883, offset=4.0),
        ]
        rows = build_packet_features(pkts, PI_IP, WINDOW_START, WINDOW_END)
        assert rows[0]["mean_inter_arrival_time"] == pytest.approx(2.0)

    def test_packet_count_and_total_bytes(self) -> None:
        pkts = [
            _tcp_pkt(ESP_IP, PI_IP, 50000, 8080, length=100, offset=0.0),
            _tcp_pkt(ESP_IP, PI_IP, 50001, 8080, length=200, offset=1.0),
        ]
        rows = build_packet_features(pkts, PI_IP, WINDOW_START, WINDOW_END)
        assert rows[0]["packet_count"] == 2
        assert rows[0]["total_bytes"] == 300
        assert rows[0]["avg_packet_size"] == pytest.approx(150.0)
        assert rows[0]["max_packet_size"] == 200

    def test_distinct_dest_port_count(self) -> None:
        pkts = [
            _tcp_pkt(ESP_IP, PI_IP, 50000, 80, offset=0.0),
            _tcp_pkt(ESP_IP, PI_IP, 50001, 443, offset=1.0),
            _tcp_pkt(ESP_IP, PI_IP, 50002, 80, offset=2.0),
        ]
        rows = build_packet_features(pkts, PI_IP, WINDOW_START, WINDOW_END)
        assert rows[0]["distinct_dest_port_count"] == 2

    def test_tcp_syn_count(self) -> None:
        SYN = 0x02
        pkts = [
            _tcp_pkt(ESP_IP, PI_IP, 50000, 80, flags=SYN, offset=0.0),
            _tcp_pkt(ESP_IP, PI_IP, 50001, 80, flags=0x10, offset=1.0),  # ACK
        ]
        rows = build_packet_features(pkts, PI_IP, WINDOW_START, WINDOW_END)
        assert rows[0]["tcp_syn_count"] == 1

    def test_mqtt_related_packet_count(self) -> None:
        pkts = [
            _tcp_pkt(ESP_IP, PI_IP, 50000, 1883, offset=0.0),  # MQTT
            _tcp_pkt(ESP_IP, PI_IP, 50001, 443, offset=1.0),   # not MQTT
        ]
        rows = build_packet_features(pkts, PI_IP, WINDOW_START, WINDOW_END)
        assert rows[0]["mqtt_related_packet_count"] == 1

    def test_non_mqtt_tcp_udp_count(self) -> None:
        pkts = [
            _tcp_pkt(ESP_IP, PI_IP, 50000, 1883, offset=0.0),  # MQTT → excluded
            _tcp_pkt(ESP_IP, PI_IP, 50001, 443, offset=1.0),   # TCP non-MQTT → included
            _udp_pkt(ESP_IP, PI_IP, 5000, 5001, offset=2.0),   # UDP non-MQTT → included
        ]
        rows = build_packet_features(pkts, PI_IP, WINDOW_START, WINDOW_END)
        assert rows[0]["non_mqtt_tcp_udp_packet_count"] == 2

    def test_separate_groups_by_peer_ip(self) -> None:
        pkts = [
            _tcp_pkt(ESP_IP, PI_IP, 50000, 1883, offset=0.0),
            _tcp_pkt(EXTERNAL_IP, PI_IP, 50000, 1883, offset=1.0),
        ]
        rows = build_packet_features(pkts, PI_IP, WINDOW_START, WINDOW_END)
        assert len(rows) == 2
        peer_ips = {r["peer_ip"] for r in rows}
        assert peer_ips == {ESP_IP, EXTERNAL_IP}

    def test_separate_groups_by_direction(self) -> None:
        pkts = [
            _tcp_pkt(ESP_IP, PI_IP, 50000, 1883, offset=0.0),  # INBOUND
            _tcp_pkt(PI_IP, ESP_IP, 1883, 50000, offset=1.0),  # OUTBOUND
        ]
        rows = build_packet_features(pkts, PI_IP, WINDOW_START, WINDOW_END)
        assert len(rows) == 2
        directions = {r["direction"] for r in rows}
        assert directions == {INBOUND, OUTBOUND}


class TestBuildIpDeviceMap:
    def test_basic_mapping(self) -> None:
        device_rows = [
            {"ip_address": "192.168.0.10", "device_id": "esp32_01"},
            {"ip_address": "192.168.0.11", "device_id": "esp32_02"},
        ]
        result = build_ip_device_map(device_rows)
        assert result == {"192.168.0.10": "esp32_01", "192.168.0.11": "esp32_02"}

    def test_none_ip_skipped(self) -> None:
        device_rows = [
            {"ip_address": None, "device_id": "esp32_01"},
            {"ip_address": "192.168.0.11", "device_id": "esp32_02"},
        ]
        result = build_ip_device_map(device_rows)
        assert result == {"192.168.0.11": "esp32_02"}

    def test_empty_ip_skipped(self) -> None:
        device_rows = [{"ip_address": "", "device_id": "esp32_01"}]
        result = build_ip_device_map(device_rows)
        assert result == {}

    def test_empty_rows(self) -> None:
        assert build_ip_device_map([]) == {}


class TestResolveDeviceId:
    def test_hit(self) -> None:
        mapping = {"192.168.0.10": "esp32_01"}
        assert resolve_device_id("192.168.0.10", mapping) == "esp32_01"

    def test_miss_returns_none(self) -> None:
        assert resolve_device_id("10.0.0.99", {}) is None


class TestExportPacketFeaturesCsv:
    def test_creates_file_with_header(self, tmp_path: Path) -> None:
        out = tmp_path / "export.csv"
        rows = [
            {
                "session_id": "sess_01",
                "device_id": "esp32_01",
                "peer_ip": "192.168.0.10",
                "direction": INBOUND,
                "window_start": "2025-01-01T00:00:00Z",
                "window_end": "2025-01-01T00:00:10Z",
                "packet_count": 5,
                "total_bytes": 500,
                "avg_packet_size": 100.0,
                "max_packet_size": 120,
                "mean_inter_arrival_time": 2.0,
                "distinct_dest_port_count": 1,
                "tcp_syn_count": 1,
                "mqtt_related_packet_count": 4,
                "non_mqtt_tcp_udp_packet_count": 1,
            }
        ]
        count = export_packet_features_csv(rows, out)

        assert count == 1
        assert out.exists()

        with open(out, newline="") as f:
            reader = csv.DictReader(f)
            assert list(reader.fieldnames) == list(CSV_FIELDS)
            data = list(reader)

        assert len(data) == 1
        assert data[0]["device_id"] == "esp32_01"
        assert data[0]["packet_count"] == "5"

    def test_missing_fields_written_as_empty(self, tmp_path: Path) -> None:
        out = tmp_path / "export.csv"
        export_packet_features_csv([{"peer_ip": "192.168.0.10"}], out)

        with open(out, newline="") as f:
            reader = csv.DictReader(f)
            data = list(reader)

        assert data[0]["session_id"] == ""
        assert data[0]["peer_ip"] == "192.168.0.10"

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        out = tmp_path / "nested" / "dir" / "export.csv"
        export_packet_features_csv([], out)
        assert out.exists()

    def test_empty_rows_writes_header_only(self, tmp_path: Path) -> None:
        out = tmp_path / "export.csv"
        count = export_packet_features_csv([], out)
        assert count == 0
        with open(out, newline="") as f:
            lines = f.readlines()
        assert len(lines) == 1  # header only
