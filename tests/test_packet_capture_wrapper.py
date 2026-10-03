"""Packet Capture Wrapper 단위 테스트 (DB 미사용).

- pcap_naming.py: UTC 10초 경계 계산, 파일명 생성/파싱 (순수 로직)
- capture_runtime.py: tcpdump 실행 결과에 따른 ready/failed 파일 이동 (I/O, 가짜 프로세스로 검증)
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import io
import subprocess
from unittest.mock import Mock, call

import pytest

from edge.packet.capture_policy import CapturePolicy
from edge.packet.capture_runtime import (
    CaptureOutcome,
    CaptureRuntimeConfig,
    TcpdumpCaptureProcess,
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


@pytest.mark.parametrize("forced_kill", [False, True])
def test_tcpdump_immediate_capture_preserves_shutdown_quality(
    monkeypatch, tmp_path, forced_kill
) -> None:
    process = Mock()
    process.stderr = io.BytesIO(b"")
    process.poll.return_value = None
    outcomes = [subprocess.TimeoutExpired("tcpdump", 10)]
    if forced_kill:
        outcomes.append(subprocess.TimeoutExpired("tcpdump", 5))
    outcomes.append(0)
    process.wait.side_effect = outcomes
    spawn = Mock(return_value=process)
    monkeypatch.setattr("edge.packet.capture_runtime.subprocess.Popen", spawn)

    result = TcpdumpCaptureProcess(capture_filter="tcp or udp").capture_window(
        interface="eth0", output_path=tmp_path / "window.pcap", window_seconds=10
    )

    arguments = spawn.call_args.args[0]
    assert "--immediate-mode" in arguments
    assert "-U" in arguments
    assert arguments[-1] == "tcp or udp"
    assert result.completed_full_window is True
    assert result.terminated_cleanly is (not forced_kill)
    assert result.stop_requested_at is not None
    expected_calls = [call.wait(timeout=10), call.poll(), call.terminate(), call.wait(timeout=5)]
    if forced_kill:
        expected_calls += [call.kill(), call.wait(timeout=5)]
    assert process.method_calls == expected_calls


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
            output_path.write_bytes(Path("tests/fixtures/packet/pcap/empty_window.pcap").read_bytes())
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


class TestExecuteCaptureWindowDriftCorrection:
    """PR #18 후속 리뷰: UTC Window 실행 지연이 연속 Capture에서 누적되는 문제 보완.

    capture_started_at을 주면, window_start 기준 고정 10초가 아니라
    window_end까지 남은 시간만큼만 tcpdump에 요청해야 한다.
    """

    def test_no_drift_requests_full_window_seconds(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        config.ensure_directories()
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        process = FakeCaptureProcess(outcome=CaptureOutcome(completed_full_window=True, exit_code=-15))

        execute_capture_window(
            process, config, session_id=SESSION_ID,
            window_start=window_start, window_end=window_end,
            capture_started_at=window_start,  # 지연 없음
        )

        assert process.last_call["window_seconds"] == 10.0

    def test_late_start_shrinks_requested_duration_to_avoid_accumulation(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        config.ensure_directories()
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        capture_started_at = window_start.replace(microsecond=300_000)  # 0.3초 늦게 시작
        process = FakeCaptureProcess(outcome=CaptureOutcome(completed_full_window=True, exit_code=-15))

        execute_capture_window(
            process, config, session_id=SESSION_ID,
            window_start=window_start, window_end=window_end,
            capture_started_at=capture_started_at,
        )

        # 10초가 아니라 window_end까지 남은 9.7초만 요청해야, 다음 Window로 지연이
        # 이어지지 않고 이번 Window 안에서 자체 보정된다.
        assert process.last_call["window_seconds"] == pytest.approx(9.7, abs=1e-6)

    def test_capture_started_at_omitted_falls_back_to_fixed_window_seconds(self, tmp_path: Path) -> None:
        """capture_started_at을 안 주면 기존 방식(window_end - window_start)으로 동작한다."""
        config = _make_config(tmp_path)
        config.ensure_directories()
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        process = FakeCaptureProcess(outcome=CaptureOutcome(completed_full_window=True, exit_code=-15))

        execute_capture_window(
            process, config, session_id=SESSION_ID,
            window_start=window_start, window_end=window_end,
        )

        assert process.last_call["window_seconds"] == 10.0

    def test_capture_started_at_past_window_end_does_not_invoke_process(self, tmp_path: Path) -> None:
        """window_end을 이미 지난 채로 발견되면 tcpdump조차 실행하지 않고
        즉시 LATE_CAPTURE로 처리해야 한다 (Capture 경계 상태표: "Runtime이 현재 Window를 대기하다가
        actual_start >= window_end가 됨" -> FAILED/LATE_CAPTURE). file_name은 DB CHECK 제약상 NULL이어야 하므로
        실제 파일이 어디에도 생성되지 않는다."""
        config = _make_config(tmp_path)
        config.ensure_directories()
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        process = FakeCaptureProcess(outcome=CaptureOutcome(completed_full_window=True, exit_code=-15))

        result = execute_capture_window(
            process, config, session_id=SESSION_ID,
            window_start=window_start, window_end=window_end,
            capture_started_at=_utc(2026, 7, 15, 10, 0, 25),  # window_end보다도 늦음
        )

        assert process.last_call is None  # capture_window()가 호출되지 않음
        assert result.success is False
        assert result.error_code == "LATE_CAPTURE"
        assert result.file_name is None
        assert result.final_path is None
        assert result.captured_duration_seconds == 0.0
        assert result.actual_capture_started_at is None
        # incoming/ready/failed 어디에도 파일이 생성되지 않아야 한다.
        expected_ready_name = build_pcap_filename(
            session_id=SESSION_ID, interface="eth0",
            window_start=window_start, window_end=window_end, tmp=False,
        )
        assert not (config.ready_dir / expected_ready_name).exists()
        assert not (config.failed_dir / expected_ready_name).exists()

    def test_start_delay_beyond_policy_but_before_window_end_is_late_capture(self, tmp_path: Path) -> None:
        """window은 아직 안 끝났어도, 허용 지연(기본 1.0초+epsilon)을 넘겼다면
        tcpdump를 실행하지 않고 LATE_CAPTURE여야 한다."""
        config = _make_config(tmp_path)
        config.ensure_directories()
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        capture_started_at = window_start.replace(microsecond=500_000)  # 0.5초 지연: 허용 초과
        process = FakeCaptureProcess(outcome=CaptureOutcome(completed_full_window=True, exit_code=-15))
        policy = CapturePolicy(max_start_delay_seconds=0.3, minimum_duration_seconds=9.5)

        result = execute_capture_window(
            process, config, session_id=SESSION_ID,
            window_start=window_start, window_end=window_end,
            capture_started_at=capture_started_at,
            policy=policy,
        )

        assert process.last_call is None
        assert result.error_code == "LATE_CAPTURE"
        assert result.start_delay_seconds == pytest.approx(0.5)

    def test_start_delay_within_policy_before_window_end_still_captures(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        config.ensure_directories()
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        capture_started_at = window_start.replace(microsecond=300_000)  # 0.3초 지연: 기본 정책 허용 범위
        process = FakeCaptureProcess(outcome=CaptureOutcome(completed_full_window=True, exit_code=-15))

        result = execute_capture_window(
            process, config, session_id=SESSION_ID,
            window_start=window_start, window_end=window_end,
            capture_started_at=capture_started_at,
        )

        assert process.last_call is not None
        assert result.success is True
        assert result.error_code is None
        assert result.start_delay_seconds == pytest.approx(0.3)
        assert result.captured_duration_seconds == pytest.approx(9.7, abs=1e-6)

    def test_capture_started_at_before_window_start_is_clamped(self, tmp_path: Path) -> None:
        """NTP 보정 등으로 clock()이 window_start 이전 시각을 반환하는 방어적 케이스.

        정상 흐름에서는 Runtime이 항상 window_start까지 대기한 뒤 capture_started_at을
        읽으므로 이 상황이 발생할 수 없지만, 두 clock() 호출 사이에 시계가 뒤로
        조정될 가능성을 배제할 수 없다. 이 경우에도 tcpdump에 명목 10초를 넘는
        캡처를 요청해서는 안 되고, start_delay_seconds는 0으로 clamp돼야 한다.
        """
        config = _make_config(tmp_path)
        config.ensure_directories()
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        capture_started_at = _utc(2026, 7, 15, 10, 0, 8)  # window_start보다 2초 이름
        process = FakeCaptureProcess(outcome=CaptureOutcome(completed_full_window=True, exit_code=-15))

        result = execute_capture_window(
            process, config, session_id=SESSION_ID,
            window_start=window_start, window_end=window_end,
            capture_started_at=capture_started_at,
        )

        assert result.success is True
        # tcpdump에는 명목 10초까지만 요청해야 한다 (12초를 요청하면 안 됨).
        assert process.last_call["window_seconds"] == pytest.approx(10.0)
        assert result.start_delay_seconds == 0.0
        assert result.captured_duration_seconds == pytest.approx(10.0)
        # actual_capture_started_at도 window_start로 clamp되어야 한다
        # (raw capture_started_at을 그대로 저장하면 Window보다 이른 시각이 Evidence에 남는다).
        assert result.actual_capture_started_at == window_start


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
        """파일이 아예 생성되지 않은 경우, 존재하지 않는 파일명을 합성하지 않고
        file_name/final_path를 NULL로 반환해야 한다 (존재하지 않는 예정 파일명을 합성하지 않는다)."""
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
        assert result.error_code == "PCAP_FILE_MISSING"
        assert result.file_name is None
        assert result.final_path is None

    def test_partial_capture_with_existing_file_keeps_file_name(self, tmp_path: Path) -> None:
        """파일이 실제로 생성됐다면 (write_file=True, 기본값) 여전히 PARTIAL_CAPTURE로
        분류되고 file_name이 채워져야 한다 -- PCAP_FILE_MISSING과의 회귀 방지용 대조 테스트."""
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
        assert result.file_name is not None
        assert result.final_path is not None
        assert result.final_path.exists()

    def test_partial_capture_duration_reflects_actual_exit_time_not_nominal_window_end(
        self, tmp_path: Path
    ) -> None:
        """조기 종료된 PARTIAL_CAPTURE는 captured_duration_seconds가 실제 종료 시각
        기준으로 계산돼야 한다. 명목 window_end 기준으로 계산하면 프로세스가 시작
        2초 만에 죽어도 captured_duration_seconds가 9~10초로 나와 실제 캡처량을
        과대평가하게 된다."""
        config = _make_config(tmp_path)
        config.ensure_directories()
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        actual_exit_at = _utc(2026, 7, 15, 10, 0, 12)  # window_start로부터 2초 만에 죽음
        process = FakeCaptureProcess(outcome=CaptureOutcome(completed_full_window=False, exit_code=1))

        result = execute_capture_window(
            process, config, session_id=SESSION_ID,
            window_start=window_start, window_end=window_end,
            capture_started_at=window_start,
            clock=lambda: actual_exit_at,
        )

        assert result.success is False
        assert result.error_code == "PARTIAL_CAPTURE"
        assert result.captured_duration_seconds == pytest.approx(2.0)
        assert result.capture_process_exited_at == actual_exit_at
        # 이 케이스는 프로세스가 스스로 먼저 종료돼 Wrapper가 종료를 "요청"한 적이
        # 없으므로, capture_stop_requested_at도 실제 관측된 종료 시각을 대신 쓴다
        # (window_end라는 허수를 넣지 않는다).
        assert result.capture_stop_requested_at == actual_exit_at

    def test_stop_requested_at_from_outcome_is_used_and_clamped_to_window_end(self, tmp_path: Path) -> None:
        """CaptureOutcome.stop_requested_at(TcpdumpCaptureProcess가 실제 SIGTERM을 보낸
        시각)이 있으면 그 값을 그대로 capture_stop_requested_at으로 사용해야 하고,
        window_end보다 늦게 들어온 경우(OS 스케줄링 지연)에는 captured_duration_seconds
        계산에서 window_end로 clamp돼야 한다. window_end를 무조건 대입하면 이 필드가
        이미 있는 window_end 컬럼의 복사본일 뿐이라 스케줄링 지연을 감사할 수 없다."""
        config = _make_config(tmp_path)
        config.ensure_directories()
        window_start = _utc(2026, 7, 15, 10, 0, 10)
        window_end = _utc(2026, 7, 15, 10, 0, 20)
        # OS 스케줄링 지연으로 SIGTERM이 명목 window_end보다 0.4초 늦게 나간 상황.
        late_stop_requested_at = window_end.replace(microsecond=400_000)
        process = FakeCaptureProcess(
            outcome=CaptureOutcome(
                completed_full_window=True,
                exit_code=-15,
                stop_requested_at=late_stop_requested_at,
            )
        )

        result = execute_capture_window(
            process, config, session_id=SESSION_ID,
            window_start=window_start, window_end=window_end,
            capture_started_at=window_start,
        )

        assert result.success is True
        # 실제 관측값이 그대로 저장돼야 한다 (window_end로 뭉개지 않는다).
        assert result.capture_stop_requested_at == late_stop_requested_at
        # 하지만 captured_duration_seconds는 여전히 10초를 넘지 않도록 clamp된다.
        assert result.captured_duration_seconds == pytest.approx(10.0)


    def test_pcap_file_missing_reports_zero_captured_duration(self, tmp_path: Path) -> None:
        """파일이 아예 생성되지 않았다면, 프로세스가 얼마나 오래 떠 있었든 실제로
        캡처된 데이터는 없으므로 captured_duration_seconds는 0이어야 한다."""
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
            capture_started_at=window_start,
            clock=lambda: _utc(2026, 7, 15, 10, 0, 18),  # 8초 동안 떠 있었지만 파일은 없음
        )

        assert result.error_code == "PCAP_FILE_MISSING"
        assert result.captured_duration_seconds == 0.0

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
