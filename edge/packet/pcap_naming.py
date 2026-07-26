"""UTC 10초 Window 경계 계산과 pcap 파일명 규칙.

이 모듈은 파일시스템/DB/프로세스에 접근하지 않는 순수 함수만 담습니다.
Phase 3-B 세부 계획 2.1, 3.1 절의 규칙을 그대로 구현합니다.

파일명 규칙:
    작성 중: capture_{session_id}_{interface}_{window_start_epoch}_{window_end_epoch}.pcap.tmp
    완료 후: capture_{session_id}_{interface}_{window_start_epoch}_{window_end_epoch}.pcap
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re


_INTERFACE_UNSAFE_PATTERN = re.compile(r"[^A-Za-z0-9._-]")

_ISO_UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

_FILENAME_PATTERN = re.compile(
    r"^capture_"
    r"(?P<session_id>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
    r"_(?P<interface>[A-Za-z0-9._-]+)"
    r"_(?P<window_start_epoch>\d+)"
    r"_(?P<window_end_epoch>\d+)"
    r"\.pcap(?P<tmp>\.tmp)?$"
)


def next_utc_boundary(now: datetime, window_seconds: int) -> datetime:
    """now 이후(포함) 가장 가까운 UTC window_seconds 경계를 반환합니다.

    예: window_seconds=10, now=10:00:03 -> 10:00:10
        now=10:00:10.000000 (정확히 경계) -> 10:00:10 (그대로)
        now=10:00:10.500000 (경계 직후) -> 10:00:20
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")

    now_utc = now.astimezone(timezone.utc)
    epoch = int(now_utc.timestamp())
    remainder = epoch % window_seconds
    on_exact_boundary = remainder == 0 and now_utc.microsecond == 0

    boundary_epoch = epoch if on_exact_boundary else epoch - remainder + window_seconds
    return datetime.fromtimestamp(boundary_epoch, tz=timezone.utc)


def sanitize_interface_name(interface: str) -> str:
    """파일명에 안전한 영문·숫자·점·밑줄·하이픈만 남깁니다 (5.1 절)."""
    sanitized = _INTERFACE_UNSAFE_PATTERN.sub("", interface)
    if not sanitized:
        raise ValueError(f"interface name has no safe characters: {interface!r}")
    return sanitized


def format_utc_iso(value: datetime) -> str:
    """DB/API 계약에 맞는 UTC ISO 8601 문자열로 변환합니다 (예: 2026-07-15T00:00:10Z).

    Window 경계(window_start/window_end)는 정의상 항상 정수 초 UTC 경계이므로 이
    포맷으로 충분하다. 실제 wall-clock 관측값(Timing Metadata)에는
    format_utc_iso_precise()를 사용한다 -- 이 함수로 그대로 저장하면 밀리초 이하
    지연·조기 종료 정보가 소실된다.
    """
    if value.tzinfo is None:
        raise ValueError("value must be timezone-aware")
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime(_ISO_UTC_FORMAT)


def format_utc_iso_precise(value: datetime) -> str:
    """마이크로초까지 보존하는 UTC ISO 8601 문자열 (예: 2026-07-15T00:00:10.300000Z).

    Phase 4 세부계획 2.1 절의 Timing Metadata(actual_capture_started_at,
    capture_stop_requested_at, capture_process_exited_at)처럼 정수 초 경계가 아닌
    실제 관측 시각을 기록할 때 사용한다. Window 경계용 format_utc_iso()와 달리
    microsecond를 자르지 않는다.

    datetime.isoformat()은 microsecond가 정확히 0이면 소수점 이하를 아예 생략해서
    같은 컬럼 안에서도 값에 따라 포맷 길이가 달라지는 문제가 있어, strftime으로
    항상 6자리 마이크로초를 명시적으로 포함시킨다.
    """
    if value.tzinfo is None:
        raise ValueError("value must be timezone-aware")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_utc_iso(value: str) -> datetime:
    return datetime.strptime(value, _ISO_UTC_FORMAT).replace(tzinfo=timezone.utc)


def build_pcap_filename(
    *,
    session_id: str,
    interface: str,
    window_start: datetime,
    window_end: datetime,
    tmp: bool,
) -> str:
    safe_interface = sanitize_interface_name(interface)
    start_epoch = int(window_start.astimezone(timezone.utc).timestamp())
    end_epoch = int(window_end.astimezone(timezone.utc).timestamp())
    if end_epoch <= start_epoch:
        raise ValueError("window_end must be after window_start")

    suffix = ".pcap.tmp" if tmp else ".pcap"
    return f"capture_{session_id}_{safe_interface}_{start_epoch}_{end_epoch}{suffix}"


def tmp_filename_to_ready(tmp_filename: str) -> str:
    """작성 중 파일명(.pcap.tmp)에서 확장자만 제거한 완료 파일명을 반환합니다."""
    if not tmp_filename.endswith(".pcap.tmp"):
        raise ValueError(f"not a .pcap.tmp file name: {tmp_filename!r}")
    return tmp_filename[: -len(".tmp")]


@dataclass(frozen=True)
class ParsedPcapFilename:
    session_id: str
    interface: str
    window_start: datetime
    window_end: datetime
    is_tmp: bool


def parse_pcap_filename(filename: str) -> ParsedPcapFilename | None:
    """capture_* 파일명을 구성 요소로 분해합니다.

    Crash Recovery(3.4 절)에서 ready/incoming에 남은 파일의 메타데이터를
    재구성할 때 사용합니다. 형식이 맞지 않으면 None을 반환합니다.
    """
    match = _FILENAME_PATTERN.match(filename)
    if match is None:
        return None

    start_epoch = int(match.group("window_start_epoch"))
    end_epoch = int(match.group("window_end_epoch"))
    if end_epoch <= start_epoch:
        return None

    return ParsedPcapFilename(
        session_id=match.group("session_id"),
        interface=match.group("interface"),
        window_start=datetime.fromtimestamp(start_epoch, tz=timezone.utc),
        window_end=datetime.fromtimestamp(end_epoch, tz=timezone.utc),
        is_tmp=match.group("tmp") is not None,
    )