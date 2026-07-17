"""Packet Capture Wrapper 단위 테스트 (DB 미사용).

- pcap_naming.py: UTC 10초 경계 계산, 파일명 생성/파싱 (순수 로직)
- capture_runtime.py: tcpdump 실행 결과에 따른 ready/failed 파일 이동 (I/O, 가짜 프로세스로 검증)
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest

from edge.packet.capture_runtime import (
    CaptureOutcome,
    CaptureRuntimeConfig,
    execute_capture_window,
)
from edge.packet.pcap_naming import (
    build_pcap_filename,
    format_utc_iso,
    next_utc_boundary,
    parse_pcap_filename,
    parse_utc_iso,
    sanitize_interface_name,
    tmp_filename_to_ready,
)

SESSION_ID = "550e8400-e29b-41d4-a716-446655440000"


def _utc(*args) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# pcap_naming.py
# ---------------------------------------------------------------------------


class TestNextUtcBoundary:
    def test_waits_for_next_boundary_from_mid_window(self) -> None:
        now = _utc(2026, 7, 15, 10, 0, 3)
        assert next_utc_boundary(now, 10) == _utc(2026, 7, 15, 10, 0, 10)

    def test_exact_boundary_returns_itself(self) -> None:
        now = _utc(2026, 7, 15, 10, 0, 10)
        assert next_utc_boundary(now, 10) == _utc(2026, 7, 15, 10, 0, 10)

    def test_microsecond_past_boundary_rolls_to_next(self) -> None:
        now = _utc(2026, 7, 15, 10, 0, 10).replace(microsecond=500_000)
        assert next_utc_boundary(now, 10) == _utc(2026, 7, 15, 10, 0, 20)

    def test_crosses_minute_boundary(self) -> None:
        now = _utc(2026, 7, 15, 10, 0, 55)
        assert next_utc_boundary(now, 10) == _utc(2026, 7, 15, 10, 1, 0)

    def test_rejects_naive_datetime(self) -> None:
        with pytest.raises(ValueError):
            next_utc_boundary(datetime(2026, 7, 15, 10, 0, 3), 10)


class TestSanitizeInterfaceName:
    def test_keeps_safe_characters(self) -> None:
        assert sanitize_interface_name("eth0") == "eth0"

    def test_keeps_dots_underscores_hyphens(self) -> None:
        assert sanitize_interface_name("enx00.11_22-33") == "enx00.11_22-33"

    def test_strips_unsafe_characters(self) -> None:
        assert sanitize_interface_name("eth0;rm -rf") == "eth0rm-rf"

    def test_rejects_all_unsafe(self) -> None:
        with pytest.raises(ValueError):
            sanitize_interface_name("!!!")


class TestIsoFormatting:
    def test_format_matches_db_check_constraint_shape(self) -> None:
        value = _utc(2026, 7, 15, 0, 0, 10)
        assert format_utc_iso(value) == "2026-07-15T00:00:10Z"

    def test_roundtrip(self) -> None:
        value = _utc(2026, 7, 15, 0, 0, 10)
        assert parse_utc_iso(format_utc_iso(value)) == value


class TestPcapFilename:
    def test_build_tmp_and_ready_filenames(self) -> None:
        window_start = _utc(2026, 7, 15, 0, 0, 10)
        window_end = _utc(2026, 7, 15, 0, 0, 20)

        tmp_name = build_pcap_filename(
            session_id=SESSION_ID,
            interface="eth0",
            window_start=window_start,
            window_end=window_end,
            tmp=True,
        )
        ready_name = build_pcap_filename(
            session_id=SESSION_ID,
            interface="eth0",
            window_start=window_start,
            window_end=window_end,
            tmp=False,
        )

        start_epoch = int(window_start.timestamp())
        end_epoch = int(window_end.timestamp())
        assert tmp_name == f"capture_{SESSION_ID}_eth0_{start_epoch}_{end_epoch}.pcap.tmp"
        assert ready_name == f"capture_{SESSION_ID}_eth0_{start_epoch}_{end_epoch}.pcap"
        assert tmp_filename_to_ready(tmp_name) == ready_name

    def test_rejects_non_positive_window(self) -> None:
        window_start = _utc(2026, 7, 15, 0, 0, 10)
        with pytest.raises(ValueError):
            build_pcap_filename(
                session_id=SESSION_ID,
                interface="eth0",
                window_start=window_start,
                window_end=window_start,
                tmp=False,
            )

    def test_parse_round_trips_ready_filename(self) -> None:
        window_start = _utc(2026, 7, 15, 0, 0, 10)
        window_end = _utc(2026, 7, 15, 0, 0, 20)
        filename = build_pcap_filename(
            session_id=SESSION_ID,
            interface="eth0",
            window_start=window_start,
            window_end=window_end,
            tmp=False,
        )

        parsed = parse_pcap_filename(filename)

        assert parsed is not None
        assert parsed.session_id == SESSION_ID
        assert parsed.interface == "eth0"
        assert parsed.window_start == window_start
        assert parsed.window_end == window_end
        assert parsed.is_tmp is False

    def test_parse_detects_tmp_suffix(self) -> None:
        filename = f"capture_{SESSION_ID}_eth0_1752537610_1752537620.pcap.tmp"
        parsed = parse_pcap_filename(filename)
        assert parsed is not None
        assert parsed.is_tmp is True

    def test_parse_rejects_malformed_filename(self) -> None:
        assert parse_pcap_filename("not_a_pcap_file.txt") is None
        assert parse_pcap_filename("capture_bad-uuid_eth0_1_2.pcap") is None


# ---------------------------------------------------------------------------
# capture_runtime.py
# ---------------------------------------------------------------------------


@dataclass
class FakeCaptureProcess:
    """실제 tcpdump 없이 지정된 CaptureOutcome을 돌려주는 테스트용 프로세스.

    completed_full_window=True인 경우 tcpdump가 실제로 pcap 파일을 만든 것처럼
    output_path에 더미 바이트를 써서 흉내낸다.
    """

    outcome: CaptureOutcome
    write_file: bool = True
    last_call: dict | None = None

    def capture_window(self, *, interface: str, output_path: Path, window_seconds: float) -> CaptureOutcome:
        self.last_call = {
            "interface": interface,
            "output_path": output_path,
            "window_seconds": window_seconds,
        }
        if self.write_file:
            output_path.write_bytes(b"fake-pcap-bytes")
        return self.outcome


def _make_config(tmp_path: Path) -> CaptureRuntimeConfig:
    return CaptureRuntimeConfig(
        capture_interface="eth0",
        window_seconds=10,
        incoming_dir=tmp_path / "incoming",
        ready_dir=tmp_path / "ready",
        failed_dir=tmp_path / "failed",
    )


class TestCaptureRuntimeConfigFromEnv:
    def test_default_capture_filter_limits_to_tcp_or_udp(self) -> None:
        """5.1 절: 1차 Capture는 TCP/UDP 트래픽으로 한정해야 한다."""
        config = CaptureRuntimeConfig.from_env()
        assert config.capture_filter == "tcp or udp"


class TestCaptureRuntimeConfigWindowSecondsValidation:
    def test_rejects_window_seconds_other_than_ten(self) -> None:
        """DB CHECK 제약(window_end - window_start == 10초)과 어긋나면 즉시 실패해야 한다."""
        with pytest.raises(ValueError, match="window_seconds must be 10"):
            CaptureRuntimeConfig(
                capture_interface="eth0",
                window_seconds=5,
                incoming_dir=Path("incoming"),
                ready_dir=Path("ready"),
                failed_dir=Path("failed"),
            )

    def test_accepts_window_seconds_ten(self) -> None:
        config = CaptureRuntimeConfig(
            capture_interface="eth0",
            window_seconds=10,
            incoming_dir=Path("incoming"),
            ready_dir=Path("ready"),
            failed_dir=Path("failed"),
        )
        assert config.window_seconds == 10


class TestExecuteCaptureWindowSuccess:
    def test_moves_file_to_ready_and_strips_tmp_suffix(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        config.ensure_directories()
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        process = FakeCaptureProcess(outcome=CaptureOutcome(completed_full_window=True, exit_code=-15))

        result = execute_capture_window(
            process,
            config,
            session_id=SESSION_ID,
            window_start=window_start,
            window_end=window_end,
        )

        expected_ready_name = build_pcap_filename(
            session_id=SESSION_ID, interface="eth0",
            window_start=window_start, window_end=window_end, tmp=False,
        )
        assert result.success is True
        assert result.file_name == expected_ready_name
        assert result.final_path == config.ready_dir / expected_ready_name
        assert result.final_path.exists()
        assert not (config.incoming_dir / f"{expected_ready_name}.tmp").exists()

    def test_passes_correct_interface_and_window_seconds_to_process(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        config.ensure_directories()
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        process = FakeCaptureProcess(outcome=CaptureOutcome(completed_full_window=True, exit_code=-15))

        execute_capture_window(
            process, config, session_id=SESSION_ID,
            window_start=window_start, window_end=window_end,
        )

        assert process.last_call["interface"] == "eth0"
        assert process.last_call["window_seconds"] == 10.0


class TestExecuteCaptureWindowFailure:
    def test_partial_capture_moves_file_to_failed_dir(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        config.ensure_directories()
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        process = FakeCaptureProcess(outcome=CaptureOutcome(completed_full_window=False, exit_code=1))

        result = execute_capture_window(
            process, config, session_id=SESSION_ID,
            window_start=window_start, window_end=window_end,
        )

        assert result.success is False
        assert result.error_code == "PARTIAL_CAPTURE"
        assert result.final_path == config.failed_dir / result.file_name
        assert result.final_path.exists()
        assert not (config.ready_dir / result.file_name).exists()

    def test_process_that_never_wrote_a_file_does_not_crash(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        config.ensure_directories()
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        process = FakeCaptureProcess(
            outcome=CaptureOutcome(completed_full_window=False, exit_code=127),
            write_file=False,
        )

        result = execute_capture_window(
            process, config, session_id=SESSION_ID,
            window_start=window_start, window_end=window_end,
        )

        assert result.success is False
        assert not result.final_path.exists()

    def test_sigkill_escalation_is_not_treated_as_success(self, tmp_path: Path) -> None:
        """SIGTERM에 응답하지 않아 SIGKILL까지 실행된 경우, window_seconds를 다 채웠어도
        pcap 파일이 깨졌을 수 있으므로 성공으로 취급하면 안 된다."""
        config = _make_config(tmp_path)
        config.ensure_directories()
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        process = FakeCaptureProcess(
            outcome=CaptureOutcome(completed_full_window=True, exit_code=-9, terminated_cleanly=False)
        )

        result = execute_capture_window(
            process, config, session_id=SESSION_ID,
            window_start=window_start, window_end=window_end,
        )

        assert result.success is False
        assert result.error_code == "PARTIAL_CAPTURE"
        assert "SIGKILL" in result.error_message
        assert result.final_path == config.failed_dir / result.file_name
        assert result.final_path.exists()
        assert not (config.ready_dir / result.file_name).exists()