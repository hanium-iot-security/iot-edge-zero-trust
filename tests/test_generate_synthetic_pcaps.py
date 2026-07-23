"""tests/fixtures/packet/generate_synthetic_pcaps.py 검증.

empty_window.pcap과 partial_capture.pcap이 실제로 의도한 구조
(패킷 0개 / 마지막 레코드가 잘린 상태)를 만드는지 확인합니다.
"""

from __future__ import annotations

from pathlib import Path
import struct
import sys

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "packet"
sys.path.insert(0, str(FIXTURES_DIR))

from generate_synthetic_pcaps import (  # noqa: E402
    _MAGIC_NUMBER,
    generate_empty_window_pcap,
    generate_partial_capture_pcap,
)

GLOBAL_HEADER_SIZE = 24
RECORD_HEADER_SIZE = 16


def _read_global_header(data: bytes) -> tuple[int, int, int, int]:
    magic, version_major, version_minor, network = struct.unpack(
        "<IHH12xI", data[:GLOBAL_HEADER_SIZE]
    )
    return magic, version_major, version_minor, network


class TestGenerateEmptyWindowPcap:
    def test_has_valid_global_header_and_zero_packets(self, tmp_path: Path) -> None:
        output_path = tmp_path / "empty_window.pcap"

        generate_empty_window_pcap(output_path)
        data = output_path.read_bytes()

        magic, version_major, version_minor, network = _read_global_header(data)
        assert magic == _MAGIC_NUMBER
        assert (version_major, version_minor) == (2, 4)
        assert network == 1  # LINKTYPE_ETHERNET
        assert len(data) == GLOBAL_HEADER_SIZE  # 패킷 레코드가 전혀 없음


class TestGeneratePartialCapturePcap:
    def test_first_record_is_complete(self, tmp_path: Path) -> None:
        output_path = tmp_path / "partial_capture.pcap"
        generate_partial_capture_pcap(output_path)
        data = output_path.read_bytes()

        offset = GLOBAL_HEADER_SIZE
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(
            "<IIII", data[offset : offset + RECORD_HEADER_SIZE]
        )
        offset += RECORD_HEADER_SIZE
        remaining_after_first_record = len(data) - offset
        assert remaining_after_first_record >= incl_len  # 첫 레코드는 잘리지 않음

    def test_last_record_is_truncated(self, tmp_path: Path) -> None:
        """두 번째(마지막) 레코드는 헤더가 선언한 길이보다 실제 파일에 남은 바이트가 적어야 한다."""
        output_path = tmp_path / "partial_capture.pcap"
        generate_partial_capture_pcap(output_path)
        data = output_path.read_bytes()

        offset = GLOBAL_HEADER_SIZE
        _ts_sec, _ts_usec, first_incl_len, _orig_len = struct.unpack(
            "<IIII", data[offset : offset + RECORD_HEADER_SIZE]
        )
        offset += RECORD_HEADER_SIZE + first_incl_len

        _ts_sec, _ts_usec, second_incl_len, _orig_len = struct.unpack(
            "<IIII", data[offset : offset + RECORD_HEADER_SIZE]
        )
        offset += RECORD_HEADER_SIZE
        actually_available = len(data) - offset

        assert actually_available < second_incl_len  # 선언된 길이만큼 실제로 존재하지 않음 (잘림)