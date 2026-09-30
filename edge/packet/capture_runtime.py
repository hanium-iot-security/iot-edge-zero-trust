"""tcpdump Capture Wrapper: 프로세스 실행 + incoming -> ready/failed 파일 이동.

DB 접근은 하지 않습니다 (capture_session_repository.py 담당).
실제 tcpdump 실행 부분(CaptureProcess)은 프로토콜로 분리되어 있어
테스트에서는 FakeCaptureProcess로 대체할 수 있습니다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
from math import isfinite
import os
from pathlib import Path
from typing import Callable, Protocol
import subprocess

from edge.packet.capture_policy import CapturePolicy, compute_effective_capture_window
from edge.packet.pcap_naming import build_pcap_filename, tmp_filename_to_ready

logger = logging.getLogger(__name__)

TERMINATE_GRACE_SECONDS = 5.0

PARTIAL_CAPTURE = "PARTIAL_CAPTURE"

# 프로세스는 시작됐지만 pcap 파일이 아예 생성되지 않은 채로 종료된 경우.
PCAP_FILE_MISSING = "PCAP_FILE_MISSING"

# 허용 지연(PCAP_MAX_START_DELAY_SECONDS)을 초과했거나 Window가 이미 끝나버려
# tcpdump 프로세스를 아예 실행하지 못한 경우.
LATE_CAPTURE = "LATE_CAPTURE"


class CaptureProcessError(RuntimeError):
    """tcpdump 프로세스를 시작하지 못했을 때 발생합니다."""


@dataclass(frozen=True)
class CaptureOutcome:
    # True: window_seconds 동안 정상 실행되다가 Wrapper가 의도적으로 종료시킴 (성공)
    # False: Wrapper가 신호를 보내기 전에 프로세스가 스스로 종료됨 (실패로 간주)
    completed_full_window: bool
    exit_code: int | None
    # True: SIGTERM만으로 정상 종료됨 (pcap 파일이 깨끗하게 닫혔을 것으로 신뢰 가능)
    # False: SIGTERM에 응답하지 않아 SIGKILL까지 실행함 (pcap 파일이 깨졌을 수 있어 신뢰 불가)
    terminated_cleanly: bool = True

    stop_requested_at: datetime | None = None

class CaptureProcess(Protocol):
    def capture_window(
        self,
        *,
        interface: str,
        output_path: Path,
        window_seconds: float,
    ) -> CaptureOutcome: ...


class TcpdumpCaptureProcess:
    """실제 tcpdump 바이너리를 실행하는 기본 구현."""

    def __init__(
        self,
        *,
        tcpdump_path: str = "tcpdump",
        capture_filter: str | None = None,
        terminate_grace_seconds: float = TERMINATE_GRACE_SECONDS,
    ) -> None:
        self._tcpdump_path = tcpdump_path
        self._capture_filter = capture_filter
        self._terminate_grace_seconds = terminate_grace_seconds

    def capture_window(
        self,
        *,
        interface: str,
        output_path: Path,
        window_seconds: float,
    ) -> CaptureOutcome:
        # -U flushes the output file; immediate mode also disables input buffering.
        # Otherwise the final packets can remain unread when a short window ends.
        args = [
            self._tcpdump_path, "-i", interface, "-w", str(output_path),
            "-U", "--immediate-mode",
        ]
        if self._capture_filter:
            args.append(self._capture_filter)

        try:
            process = subprocess.Popen(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            raise CaptureProcessError(f"failed to start tcpdump on {interface!r}: {exc}") from exc

        try:
            # window_seconds 안에 tcpdump가 스스로 종료됐다면 비정상 상황이다
            # (권한 문제, 인터페이스 소멸 등). 이 경우 Partial Capture로 처리한다.
            exit_code = process.wait(timeout=window_seconds)
            return CaptureOutcome(completed_full_window=False, exit_code=exit_code)
        except subprocess.TimeoutExpired:
            pass

        # 정상 경로: window가 끝났으므로 Wrapper가 캡처를 종료시킨다.
        # SIGTERM으로 정상 종료시켜야 tcpdump가 pcap 파일을 안전하게 flush하고 닫는다.
        stop_requested_at = datetime.now(timezone.utc)
        process.terminate()
        try:
            exit_code = process.wait(timeout=self._terminate_grace_seconds)
            return CaptureOutcome(
                completed_full_window=True,
                exit_code=exit_code,
                terminated_cleanly=True,
                stop_requested_at=stop_requested_at,
            )
        except subprocess.TimeoutExpired:
            # SIGTERM에 응답하지 않아 SIGKILL까지 실행함 -- pcap 파일이 깨졌을 수 있으므로
            # window_seconds를 다 채웠더라도 성공으로 취급하지 않는다.
            process.kill()
            exit_code = process.wait(timeout=self._terminate_grace_seconds)
            return CaptureOutcome(
                completed_full_window=True,
                exit_code=exit_code,
                terminated_cleanly=False,
                stop_requested_at=stop_requested_at,
            )


@dataclass(frozen=True)
class CaptureRuntimeConfig:
    capture_interface: str
    window_seconds: int
    incoming_dir: Path
    ready_dir: Path
    failed_dir: Path
    tcpdump_path: str = "tcpdump"
    capture_filter: str | None = None
    # 지연 판정에 쓰는 Versioned Capture Policy.
    capture_policy: CapturePolicy = field(default_factory=CapturePolicy)

    def __post_init__(self) -> None:
        if not isfinite(self.window_seconds) or self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.window_seconds != 10:
            # packet_capture_segments의 DB CHECK 제약이 window_end - window_start == 10초를
            # 강제한다. 여기서 미리 걸러내지 않으면 DB insert 시점에서야 IntegrityError로
            # 실패하게 되어 원인 파악이 어려워진다.
            raise ValueError(
                f"window_seconds must be 10 to satisfy the DB CHECK constraint on "
                f"packet_capture_segments (got {self.window_seconds})"
            )

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "CaptureRuntimeConfig":
        from backend.app.config import settings

        return cls(
            capture_interface=settings.capture_interface,
            window_seconds=settings.pcap_window_seconds,
            incoming_dir=Path(settings.pcap_incoming_dir),
            ready_dir=Path(settings.pcap_ready_dir),
            failed_dir=Path(settings.pcap_failed_dir),
            capture_filter=settings.pcap_capture_filter,
            capture_policy=CapturePolicy.from_env(),
        )

    def ensure_directories(self) -> None:
        for directory in (self.incoming_dir, self.ready_dir, self.failed_dir):
            directory.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class CaptureWindowResult:
    success: bool
    # LATE_CAPTURE인 경우 tcpdump를 아예 실행하지 않으므로 file_name/final_path가 없다
    # (packet_capture_segments DB CHECK: error_code='LATE_CAPTURE'이면 file_name IS NULL).
    file_name: str | None
    final_path: Path | None
    exit_code: int | None
    error_code: str | None = None
    error_message: str | None = None
    # --- Phase 4 Timing Metadata ---
    # LATE_CAPTURE에서는 전부 None/0.0으로 고정된다 (DB CHECK와 동일한 계약).
    actual_capture_started_at: datetime | None = None
    capture_stop_requested_at: datetime | None = None
    capture_process_exited_at: datetime | None = None
    start_delay_seconds: float | None = None
    captured_duration_seconds: float | None = None


def execute_capture_window(
    process: CaptureProcess,
    config: CaptureRuntimeConfig,
    *,
    session_id: str,
    window_start: datetime,
    window_end: datetime,
    capture_started_at: datetime | None = None,
    policy: CapturePolicy | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> CaptureWindowResult:
    """한 Window(10초)를 캡처하고 결과를 파일 이동 + Timing Metadata로 반환합니다.

    capture_started_at이 주어지면 Capture 경계 상태표에 따라 지연을 판정합니다:
      - capture_started_at이 이미 window_end 이후이거나
      - 허용 지연(policy.max_start_delay_seconds + epsilon)을 초과했다면
      tcpdump 프로세스를 아예 실행하지 않고 LATE_CAPTURE로 확정합니다.

    capture_started_at을 생략하면(레거시 호출부 호환) 지연 판정 없이 고정
    window_seconds(window_end - window_start)로 그대로 진행합니다.
    """
    active_policy = policy if policy is not None else config.capture_policy

    tmp_filename = build_pcap_filename(
        session_id=session_id,
        interface=config.capture_interface,
        window_start=window_start,
        window_end=window_end,
        tmp=True,
    )
    tmp_path = config.incoming_dir / tmp_filename
    ready_filename = tmp_filename_to_ready(tmp_filename)

    if capture_started_at is None:
        # 레거시 호출부(capture_started_at 미지정)는 지연 판정 없이 고정
        # window_seconds로 진행한다. 실제 Runtime(run_packet_capture.py)은 항상
        # capture_started_at을 넘겨준다.
        effective_started_at = window_start
        start_delay_seconds: float | None = None
        window_seconds = (window_end - window_start).total_seconds()
    else:
        start_delay_seconds = max(0.0, (capture_started_at - window_start).total_seconds())

        already_expired = capture_started_at >= window_end
        exceeds_allowed_delay = start_delay_seconds > active_policy.max_start_delay_seconds + active_policy.epsilon_seconds

        if already_expired or exceeds_allowed_delay:
            if already_expired:
                reason = (
                    f"capture_started_at({capture_started_at.isoformat()}) is at/after "
                    f"window_end({window_end.isoformat()}); window fully expired before "
                    f"capture could start"
                )
            else:
                reason = (
                    f"start_delay_seconds={start_delay_seconds:.3f} exceeds allowed "
                    f"max_start_delay_seconds={active_policy.max_start_delay_seconds} "
                    f"(+epsilon={active_policy.epsilon_seconds}); capture process not started "
                    f"(policy_version={active_policy.version})"
                )
            logger.warning(
                "LATE_CAPTURE: %s (window=%s~%s)",
                reason, window_start.isoformat(), window_end.isoformat(),
            )
            return CaptureWindowResult(
                success=False,
                file_name=None,
                final_path=None,
                exit_code=None,
                error_code=LATE_CAPTURE,
                error_message=reason,
                actual_capture_started_at=None,
                capture_stop_requested_at=None,
                capture_process_exited_at=None,
                start_delay_seconds=start_delay_seconds,
                captured_duration_seconds=0.0,
            )

        effective_started_at = max(capture_started_at, window_start)
        window_seconds = max(0.0, (window_end - effective_started_at).total_seconds())

    process_exited_at_fallback = clock  # 아래에서 실제 종료 직후 시각을 기록하는 데 사용

    outcome = process.capture_window(
        interface=config.capture_interface,
        output_path=tmp_path,
        window_seconds=window_seconds,
    )
    capture_process_exited_at = process_exited_at_fallback()

    if outcome.stop_requested_at is not None:
        # 실제 관측값 (TcpdumpCaptureProcess가 process.terminate() 직전에 기록).
        capture_stop_requested_at = outcome.stop_requested_at
    elif outcome.completed_full_window:
        # Wrapper가 이 Window를 끝내기로 판단한 경우인데 관측값이 없다
        # (FakeCaptureProcess 같은 테스트 더블). window_end를 최선의 근사치로 쓴다.
        capture_stop_requested_at = window_end
    else:
        # 프로세스가 스스로 먼저 종료돼 Wrapper가 종료를 요청한 적이 없다. 실제
        # 관측된 종료 시각(capture_process_exited_at)을 대신 사용한다.
        capture_stop_requested_at = capture_process_exited_at

    if outcome.completed_full_window and outcome.terminated_cleanly:
        _effective_start, _effective_end, captured_duration_seconds = compute_effective_capture_window(
            window_start=window_start,
            window_end=window_end,
            actual_capture_started_at=effective_started_at,
            capture_stop_requested_at=capture_stop_requested_at,
        )
        final_path = _atomic_rename_same_filesystem(tmp_path, config.ready_dir / ready_filename)
        return CaptureWindowResult(
            success=True,
            file_name=ready_filename,
            final_path=final_path,
            exit_code=outcome.exit_code,
            actual_capture_started_at=effective_started_at,
            capture_stop_requested_at=capture_stop_requested_at,
            capture_process_exited_at=capture_process_exited_at,
            start_delay_seconds=start_delay_seconds if start_delay_seconds is not None else 0.0,
            captured_duration_seconds=captured_duration_seconds,
        )

    # PARTIAL_CAPTURE(파일은 있으나 조기 종료)와 PCAP_FILE_MISSING(파일이 아예
    # 생성되지 않음)을 구분한다. move 전에 확인해야 한다 -- 성공 시
    # _move_to_failed가 tmp_path를 옮겨버려서 이후엔 존재 여부를 알 수 없다.
    file_was_created = tmp_path.exists()
    final_path = _move_to_failed(tmp_path, config.failed_dir / ready_filename)

    if not file_was_created:
        # 파일이 아예 생성되지 않았으므로 실제로 캡처된 데이터는 없다 (0초).
        captured_duration_seconds = 0.0
    else:
        # 프로세스가 명목 window_end까지 살아남지 못했다면 (자력 조기 종료)
        # capture_stop_requested_at은 위에서 이미 capture_process_exited_at으로
        # fallback돼 있다. window_end를 그대로 쓰면 2초 만에 죽은 캡처도
        # captured_duration_seconds가 9~10초로 나와 실제 캡처량을 과대평가하게 된다.

        _effective_start, _effective_end, captured_duration_seconds = compute_effective_capture_window(
            window_start=window_start,
            window_end=window_end,
            actual_capture_started_at=effective_started_at,
            capture_stop_requested_at=capture_stop_requested_at,
        )

    if not outcome.completed_full_window:
        error_message = (
            f"tcpdump exited before the {window_seconds:.0f}s window completed "
            f"(exit_code={outcome.exit_code})"
        )
    else:
        error_message = (
            f"tcpdump did not respond to SIGTERM within the grace period and had to be "
            f"SIGKILLed; pcap file may be corrupted (exit_code={outcome.exit_code})"
        )

    if not file_was_created:
        return CaptureWindowResult(
            success=False,
            file_name=None,
            final_path=None,
            exit_code=outcome.exit_code,
            error_code=PCAP_FILE_MISSING,
            error_message=error_message,
            actual_capture_started_at=effective_started_at,
            capture_stop_requested_at=capture_stop_requested_at,
            capture_process_exited_at=capture_process_exited_at,
            start_delay_seconds=start_delay_seconds if start_delay_seconds is not None else 0.0,
            captured_duration_seconds=captured_duration_seconds,
        )

    return CaptureWindowResult(
        success=False,
        file_name=ready_filename,
        final_path=final_path,
        exit_code=outcome.exit_code,
        error_code=PARTIAL_CAPTURE,
        error_message=error_message,
        actual_capture_started_at=effective_started_at,
        capture_stop_requested_at=capture_stop_requested_at,
        capture_process_exited_at=capture_process_exited_at,
        start_delay_seconds=start_delay_seconds if start_delay_seconds is not None else 0.0,
        captured_duration_seconds=captured_duration_seconds,
    )


def _atomic_rename_same_filesystem(source: Path, destination: Path) -> Path:
    """같은 파일시스템 안에서 확장자만 제거하는 원자적 rename (3.1 절)."""
    os.replace(source, destination)
    return destination


def _move_to_failed(source: Path, destination: Path) -> Path:
    """비정상 종료된 캡처 파일을 failed 디렉터리로 옮깁니다.

    tcpdump가 파일을 아예 만들지 못하고 죽었을 수도 있으므로 존재 여부를 확인한다.
    """
    if source.exists():
        os.replace(source, destination)
        return destination
    return source