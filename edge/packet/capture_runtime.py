"""tcpdump Capture Wrapper: 프로세스 실행 + incoming -> ready/failed 파일 이동.

DB 접근은 하지 않습니다 (capture_session_repository.py 담당).
실제 tcpdump 실행 부분(CaptureProcess)은 프로토콜로 분리되어 있어
테스트에서는 FakeCaptureProcess로 대체할 수 있습니다.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from math import isfinite
import os
from pathlib import Path
from typing import Protocol
import subprocess

from edge.packet.pcap_naming import build_pcap_filename, tmp_filename_to_ready

TERMINATE_GRACE_SECONDS = 5.0

PARTIAL_CAPTURE = "PARTIAL_CAPTURE"


class CaptureProcessError(RuntimeError):
    """tcpdump 프로세스를 시작하지 못했을 때 발생합니다."""


@dataclass(frozen=True)
class CaptureOutcome:
    # True: window_seconds 동안 정상 실행되다가 Wrapper가 의도적으로 종료시킴 (성공)
    # False: Wrapper가 신호를 보내기 전에 프로세스가 스스로 종료됨 (실패로 간주)
    completed_full_window: bool
    exit_code: int | None


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
        args = [self._tcpdump_path, "-i", interface, "-w", str(output_path), "-U"]
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
        process.terminate()
        try:
            exit_code = process.wait(timeout=self._terminate_grace_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            exit_code = process.wait(timeout=self._terminate_grace_seconds)
        return CaptureOutcome(completed_full_window=True, exit_code=exit_code)


@dataclass(frozen=True)
class CaptureRuntimeConfig:
    capture_interface: str
    window_seconds: int
    incoming_dir: Path
    ready_dir: Path
    failed_dir: Path
    tcpdump_path: str = "tcpdump"
    capture_filter: str | None = None

    def __post_init__(self) -> None:
        if not isfinite(self.window_seconds) or self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

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
        )

    def ensure_directories(self) -> None:
        for directory in (self.incoming_dir, self.ready_dir, self.failed_dir):
            directory.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class CaptureWindowResult:
    success: bool
    file_name: str
    final_path: Path
    exit_code: int | None
    error_code: str | None = None
    error_message: str | None = None


def execute_capture_window(
    process: CaptureProcess,
    config: CaptureRuntimeConfig,
    *,
    session_id: str,
    window_start: datetime,
    window_end: datetime,
) -> CaptureWindowResult:
    """하나의 UTC 10초 Window를 캡처하고 결과에 따라 ready/failed로 원자적으로 이동시킵니다.

    반환된 CaptureWindowResult.success == True 이면 파일은 이미 ready_dir에 있고,
    호출자(run_packet_capture.py)는 capture_session_repository.insert_ready_segment()를
    호출해 READY row를 만들면 됩니다. False이면 failed_dir로 이미 이동되어 있으므로
    호출자는 insert_failed_segment()를 호출합니다.
    """
    tmp_filename = build_pcap_filename(
        session_id=session_id,
        interface=config.capture_interface,
        window_start=window_start,
        window_end=window_end,
        tmp=True,
    )
    tmp_path = config.incoming_dir / tmp_filename
    window_seconds = (window_end - window_start).total_seconds()

    outcome = process.capture_window(
        interface=config.capture_interface,
        output_path=tmp_path,
        window_seconds=window_seconds,
    )

    ready_filename = tmp_filename_to_ready(tmp_filename)

    if outcome.completed_full_window:
        final_path = _atomic_rename_same_filesystem(tmp_path, config.ready_dir / ready_filename)
        return CaptureWindowResult(
            success=True,
            file_name=ready_filename,
            final_path=final_path,
            exit_code=outcome.exit_code,
        )

    final_path = _move_to_failed(tmp_path, config.failed_dir / ready_filename)
    return CaptureWindowResult(
        success=False,
        file_name=ready_filename,
        final_path=final_path,
        exit_code=outcome.exit_code,
        error_code=PARTIAL_CAPTURE,
        error_message=(
            f"tcpdump exited before the {window_seconds:.0f}s window completed "
            f"(exit_code={outcome.exit_code})"
        ),
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