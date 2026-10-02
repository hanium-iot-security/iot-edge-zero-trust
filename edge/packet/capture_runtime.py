"""tcpdump Capture Wrapper: 프로세스 실행 + incoming -> ready/failed 파일 이동.

DB 접근은 하지 않습니다 (capture_session_repository.py 담당).
실제 tcpdump 실행 부분(CaptureProcess)은 프로토콜로 분리되어 있어
테스트에서는 FakeCaptureProcess로 대체할 수 있습니다.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import logging
import json
from math import isfinite
import os
from pathlib import Path
import re
import signal
import stat
import struct
import threading
from typing import Callable, Protocol
import subprocess

from edge.packet.capture_policy import CapturePolicy, compute_effective_capture_window
from edge.packet.pcap_naming import build_pcap_filename, tmp_filename_to_ready

logger = logging.getLogger(__name__)

TERMINATE_GRACE_SECONDS = 5.0
STDERR_LIMIT_BYTES = 64 * 1024
STDERR_DRAIN_TIMEOUT_SECONDS = 1.0

PARTIAL_CAPTURE = "PARTIAL_CAPTURE"

# 프로세스는 시작됐지만 pcap 파일이 아예 생성되지 않은 채로 종료된 경우.
PCAP_FILE_MISSING = "PCAP_FILE_MISSING"

# 허용 지연(PCAP_MAX_START_DELAY_SECONDS)을 초과했거나 Window가 이미 끝나버려
# tcpdump 프로세스를 아예 실행하지 못한 경우.
LATE_CAPTURE = "LATE_CAPTURE"


class CaptureProcessError(RuntimeError):
    """tcpdump 실행 또는 종료 진단을 안전하게 완료하지 못했을 때 발생합니다."""


@dataclass(frozen=True)
class CaptureOutcome:
    # True: 예정된 Window 끝에 Wrapper가 종료를 요청함. 성공/품질은 별도 판정한다.
    # False: Wrapper가 신호를 보내기 전에 프로세스가 스스로 종료됨 (실패로 간주)
    completed_full_window: bool
    exit_code: int | None
    # True: 예정 종료 후 허용 exit code이며 강제 kill/진단 수집 실패가 없음.
    # PCAP 완결성과 packet loss는 이 값만으로 보장하지 않는다.
    terminated_cleanly: bool = True

    stop_requested_at: datetime | None = None
    stderr_tail: str = ""
    stderr_truncated: bool = False
    stderr_complete: bool | None = None
    stderr_error: str | None = None
    packets_captured: int | None = None
    packets_received: int | None = None
    packets_dropped: int | None = None
    packets_dropped_by_interface: int | None = None


class _StderrDrain:
    """Continuously drain the pipe while retaining bounded diagnostic evidence."""

    _statistics = re.compile(
        rb"^\s*(\d+) packets? (captured|received by filter|dropped by kernel|dropped by interface)\s*$"
    )
    _fields = {
        b"captured": "packets_captured", b"received by filter": "packets_received",
        b"dropped by kernel": "packets_dropped", b"dropped by interface": "packets_dropped_by_interface",
    }

    def __init__(self, stream) -> None:
        self.stream = stream
        self.tail = bytearray()
        self.line_tail = b""
        self.truncated = False
        self.complete = False
        self.error = None
        self.statistics = {}
        self.thread = threading.Thread(target=self._read, name="packet-capture-stderr", daemon=True)

    def _parse_line(self, line: bytes) -> None:
        match = self._statistics.fullmatch(line)
        if match:
            self.statistics[self._fields[match[2]]] = int(match[1])

    def _read(self) -> None:
        try:
            while chunk := self.stream.read(8192):
                self.tail.extend(chunk)
                if len(self.tail) > STDERR_LIMIT_BYTES:
                    del self.tail[:-STDERR_LIMIT_BYTES]
                    self.truncated = True
                lines = (self.line_tail + chunk).split(b"\n")
                for line in lines[:-1]:
                    self._parse_line(line)
                self.line_tail = lines[-1][-4096:]
            self._parse_line(self.line_tail)
            self.complete = True
        except (OSError, ValueError) as exc:
            self.error = str(exc)

    def finish(self) -> dict:
        self.thread.join(STDERR_DRAIN_TIMEOUT_SECONDS)
        if self.thread.is_alive():
            # Do not close a stream while another thread holds its blocking read
            # lock. Abort this runtime instead of hanging or publishing READY.
            raise CaptureProcessError("tcpdump stderr pipe did not close after process exit")
        self.stream.close()
        # Replacement decoding can expand invalid bytes; cap the UTF-8 result too.
        tail = bytes(self.tail).decode("utf-8", errors="replace")
        encoded = tail.encode("utf-8")
        if len(encoded) > STDERR_LIMIT_BYTES:
            tail = encoded[-STDERR_LIMIT_BYTES:].decode("utf-8", errors="ignore")
            self.truncated = True
        return {
            "stderr_tail": tail, "stderr_truncated": self.truncated,
            "stderr_complete": self.complete, "stderr_error": self.error,
            **self.statistics,
        }

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
        inherited_lock_fds: tuple[int, ...] = (),
    ) -> None:
        self._tcpdump_path = tcpdump_path
        self._capture_filter = capture_filter
        self._terminate_grace_seconds = terminate_grace_seconds
        self._inherited_lock_fds = inherited_lock_fds

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
                env={**os.environ, "LC_ALL": "C"},
                **({"pass_fds": self._inherited_lock_fds} if os.name == "posix" else {}),
            )
        except OSError as exc:
            raise CaptureProcessError(f"failed to start tcpdump on {interface!r}: {exc}") from exc

        drain = _StderrDrain(process.stderr)
        drain.thread.start()
        full_window = False
        forced_kill = False
        stop_requested_at = None
        try:
            try:
                exit_code = process.wait(timeout=window_seconds)
            except subprocess.TimeoutExpired:
                # An independent exit racing with the timeout is not our stop.
                exit_code = process.poll()
                if exit_code is None:
                    stop_requested_at = datetime.now(timezone.utc)
                    process.terminate()
                    full_window = True
                    try:
                        exit_code = process.wait(timeout=self._terminate_grace_seconds)
                    except subprocess.TimeoutExpired:
                        forced_kill = True
                        process.kill()
                        exit_code = process.wait(timeout=self._terminate_grace_seconds)
        except BaseException:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=self._terminate_grace_seconds)
            drain.finish()
            raise
        diagnostics = drain.finish()
        return CaptureOutcome(
            completed_full_window=full_window, exit_code=exit_code,
            terminated_cleanly=(
                full_window and not forced_kill and exit_code in (0, -signal.SIGTERM)
                and diagnostics["stderr_complete"]
            ),
            stop_requested_at=stop_requested_at, **diagnostics,
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
    diagnostics_path: Path | None = None


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

    packet_loss = any(
        count is not None and count > 0
        for count in (outcome.packets_dropped, outcome.packets_dropped_by_interface)
    )
    clean_exit = (
        outcome.completed_full_window and outcome.terminated_cleanly
        and outcome.exit_code in (0, -signal.SIGTERM)
        and outcome.stderr_complete is not False and not packet_loss
    )
    file_validation_error = _pcap_file_error(tmp_path) if clean_exit and tmp_path.exists() else None

    def with_diagnostics(result: CaptureWindowResult) -> CaptureWindowResult:
        directory = config.ready_dir if result.success else config.failed_dir
        path = directory / f"{ready_filename}.capture.json"
        drop_status = (
            "observed_loss" if packet_loss
            else "unknown" if outcome.packets_dropped is None
            else "no_kernel_drops_reported"
        )
        metadata = {
            "schema_version": "packet-capture-diagnostics-v1",
            "session_id": session_id, "capture_interface": config.capture_interface,
            "window_start": window_start.isoformat(), "window_end": window_end.isoformat(),
            "pcap_file_name": result.file_name, "expected_pcap_file_name": ready_filename,
            "success": result.success, "error_code": result.error_code,
            "file_validation_error": file_validation_error,
            "error_message": result.error_message, "exit_code": outcome.exit_code,
            "completed_full_window": outcome.completed_full_window,
            "terminated_cleanly": outcome.terminated_cleanly,
            "stderr_tail": outcome.stderr_tail, "stderr_truncated": outcome.stderr_truncated,
            "stderr_complete": outcome.stderr_complete, "stderr_error": outcome.stderr_error,
            "packets_captured": outcome.packets_captured,
            "packets_received": outcome.packets_received,
            "packets_dropped": outcome.packets_dropped,
            "packets_dropped_by_interface": outcome.packets_dropped_by_interface,
            "drop_status": drop_status,
        }
        temporary = path.with_suffix(path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(metadata, handle, ensure_ascii=True, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        return replace(result, diagnostics_path=path)

    if clean_exit and tmp_path.exists() and file_validation_error is None:
        _effective_start, _effective_end, captured_duration_seconds = compute_effective_capture_window(
            window_start=window_start,
            window_end=window_end,
            actual_capture_started_at=effective_started_at,
            capture_stop_requested_at=capture_stop_requested_at,
        )
        final_path = config.ready_dir / ready_filename
        result = with_diagnostics(CaptureWindowResult(
            success=True,
            file_name=ready_filename,
            final_path=final_path,
            exit_code=outcome.exit_code,
            actual_capture_started_at=effective_started_at,
            capture_stop_requested_at=capture_stop_requested_at,
            capture_process_exited_at=capture_process_exited_at,
            start_delay_seconds=start_delay_seconds if start_delay_seconds is not None else 0.0,
            captured_duration_seconds=captured_duration_seconds,
        ))
        # Publish READY only after diagnostic evidence has been persisted. A
        # failed publication must not leave a sidecar claiming success.
        try:
            _atomic_rename_same_filesystem(tmp_path, final_path)
        except OSError as publish_error:
            try:
                discard_unpublished_capture_diagnostics(config, ready_filename)
            except OSError as cleanup_error:
                logger.exception("Failed to retract capture diagnostics after PCAP publication failed: %s", publish_error)
                raise CaptureProcessError(
                    f"PCAP publication failed ({publish_error}); diagnostic cleanup failed "
                    f"({cleanup_error}); startup reconciliation must retract the sidecar"
                ) from cleanup_error
            raise
        return result

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
    elif outcome.exit_code == -9 and not outcome.terminated_cleanly:
        error_message = (
            f"tcpdump did not respond to SIGTERM within the grace period and had to be "
            f"SIGKILLed; pcap file may be corrupted (exit_code={outcome.exit_code})"
        )
    elif outcome.exit_code not in (0, -signal.SIGTERM):
        error_message = f"tcpdump failed while stopping (exit_code={outcome.exit_code})"
    elif packet_loss:
        error_message = (
            f"tcpdump reported packet loss; excluded from READY "
            f"(kernel={outcome.packets_dropped}, interface={outcome.packets_dropped_by_interface})"
        )
    elif file_validation_error is not None:
        error_message = file_validation_error
    elif not file_was_created:
        error_message = "tcpdump exited without creating the capture file"
    else:
        error_message = "tcpdump shutdown or stderr collection was not clean"

    if not file_was_created:
        return with_diagnostics(CaptureWindowResult(
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
        ))

    return with_diagnostics(CaptureWindowResult(
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
    ))


def _pcap_file_error(path: Path) -> str | None:
    """Validate the classic PCAP envelope, without decoding packet payloads.

    A 24-byte empty capture is valid. Zero bytes, incomplete record headers and
    truncated bodies are not. Protocol parsing remains the Extractor's job.
    """
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            return "capture output is not a regular file"
        # Replacing a regular file by a FIFO after lstat must not block open;
        # replacing it by a symlink must not redirect the validation read.
        flags = getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        with open(path, "rb", opener=lambda name, mode: os.open(name, mode | flags)) as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                return "capture output is not a regular file"
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                return "capture output changed before validation"
            size = opened.st_size
            header = handle.read(24)
            byte_orders = {
                b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
                b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",
            }
            endian = byte_orders.get(header[:4])
            if len(header) != 24 or endian is None:
                return "capture output has an invalid or truncated PCAP header"
            major, minor = struct.unpack(f"{endian}HH", header[4:8])
            snaplen = struct.unpack(f"{endian}I", header[16:20])[0]
            if (major, minor) != (2, 4) or snaplen == 0:
                return "capture output has an unsupported PCAP version or snaplen"
            while record := handle.read(16):
                if len(record) != 16:
                    return "capture output has a truncated PCAP record header"
                _, _, captured, original = struct.unpack(f"{endian}IIII", record)
                if captured > snaplen or captured > original or captured > size - handle.tell():
                    return "capture output has an invalid or truncated PCAP record body"
                handle.seek(captured, os.SEEK_CUR)
        return None
    except (OSError, ValueError, struct.error) as exc:
        return f"capture output validation failed: {exc}"


def _atomic_rename_same_filesystem(source: Path, destination: Path) -> Path:
    """같은 파일시스템 안에서 확장자만 제거하는 원자적 rename (3.1 절)."""
    os.replace(source, destination)
    return destination


def discard_unpublished_capture_diagnostics(config: CaptureRuntimeConfig, file_name: str) -> None:
    """Retract evidence for a PCAP that failed publication or remains incoming.

    Cleanup errors propagate: callers must stop instead of treating the orphan
    success sidecar as settled evidence. Never call this for processed PCAPs.
    """
    (config.ready_dir / f"{file_name}.capture.json").unlink(missing_ok=True)


def _move_to_failed(source: Path, destination: Path) -> Path:
    """비정상 종료된 캡처 파일을 failed 디렉터리로 옮깁니다.

    tcpdump가 파일을 아예 만들지 못하고 죽었을 수도 있으므로 존재 여부를 확인한다.
    """
    if source.exists():
        os.replace(source, destination)
        return destination
    return source
