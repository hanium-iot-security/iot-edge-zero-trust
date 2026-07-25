"""packet_capture_sessions / packet_capture_segments DB 읽기/쓰기.

이 모듈은 Session/commit/rollback을 스스로 책임지지 않습니다 (호출자가 담당).
tcpdump 실행이나 파일시스템 rename은 capture_runtime.py가 담당합니다.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.packet.pcap_naming import format_utc_iso, format_utc_iso_precise, parse_utc_iso

PARTIAL_CAPTURE = "PARTIAL_CAPTURE"
PCAP_FILE_MISSING = "PCAP_FILE_MISSING"
LATE_CAPTURE = "LATE_CAPTURE"


@dataclass(frozen=True)
class SessionRecord:
    id: int
    session_id: str
    capture_interface: str
    status: str


@dataclass(frozen=True)
class PacketCaptureReadiness:
    session_id: str
    packet_capture_ready_through: datetime | None


def create_session(
    db: Session,
    *,
    session_id: str,
    capture_interface: str,
    started_at: datetime,
) -> int:
    """새 packet_capture_sessions row를 RUNNING 상태로 생성하고 내부 id를 반환합니다."""
    result = db.execute(
        text(
            """
            INSERT INTO packet_capture_sessions (
                session_id, capture_interface, started_at, status
            )
            VALUES (:session_id, :capture_interface, :started_at, 'RUNNING')
            """
        ),
        {
            "session_id": session_id,
            "capture_interface": capture_interface,
            "started_at": format_utc_iso(started_at),
        },
    )
    return int(result.lastrowid or 0)


def set_first_window_start(db: Session, session_pk: int, first_window_start: datetime) -> None:
    db.execute(
        text(
            """
            UPDATE packet_capture_sessions
            SET first_window_start = :first_window_start,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :id
            """
        ),
        {"first_window_start": format_utc_iso(first_window_start), "id": session_pk},
    )


def record_capture_gap(
    db: Session,
    session_pk: int,
    gap_start: datetime,
    gap_end: datetime,
) -> None:
    """이전 Session 마지막 Segment와 새 Session의 first_window_start 사이 공백 기록."""
    db.execute(
        text(
            """
            UPDATE packet_capture_sessions
            SET capture_gap_start = :gap_start,
                capture_gap_end = :gap_end,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :id
            """
        ),
        {"gap_start": format_utc_iso(gap_start), "gap_end": format_utc_iso(gap_end), "id": session_pk},
    )


def close_session(db: Session, session_pk: int, ended_at: datetime, status: str) -> None:
    if status not in ("COMPLETED", "FAILED"):
        raise ValueError(f"invalid terminal session status: {status!r}")
    db.execute(
        text(
            """
            UPDATE packet_capture_sessions
            SET ended_at = :ended_at,
                status = :status,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :id
            """
        ),
        {"ended_at": format_utc_iso(ended_at), "status": status, "id": session_pk},
    )


def close_stale_running_sessions(db: Session, capture_interface: str, ended_at: datetime) -> int:
    """서비스가 비정상 종료되어 RUNNING 상태로 남아있는 이전 Session들을 FAILED로 마감합니다.

    새 Session을 시작하기 전에 호출해야 합니다. 반환값은 마감한 Session 개수입니다.
    """
    result = db.execute(
        text(
            """
            UPDATE packet_capture_sessions
            SET status = 'FAILED',
                ended_at = :ended_at,
                updated_at = CURRENT_TIMESTAMP
            WHERE capture_interface = :capture_interface AND status = 'RUNNING'
            """
        ),
        {"ended_at": format_utc_iso(ended_at), "capture_interface": capture_interface},
    )
    return result.rowcount


def find_session_pk_by_session_id(db: Session, session_id: str) -> int | None:
    row = db.execute(
        text("SELECT id FROM packet_capture_sessions WHERE session_id = :session_id"),
        {"session_id": session_id},
    ).first()
    return int(row[0]) if row is not None else None


def find_last_segment_window_end(db: Session, capture_interface: str) -> datetime | None:
    """같은 interface의 가장 최근 Segment window_end를 반환합니다 (Gap 계산용)."""
    row = db.execute(
        text(
            """
            SELECT MAX(window_end)
            FROM packet_capture_segments
            WHERE capture_interface = :capture_interface
            """
        ),
        {"capture_interface": capture_interface},
    ).first()
    if row is None or row[0] is None:
        return None
    return parse_utc_iso(row[0])


def find_segment_by_file_name(db: Session, file_name: str) -> dict | None:
    row = db.execute(
        text(
            """
            SELECT id, capture_session_id, file_name, capture_interface,
                   window_start, window_end, status
            FROM packet_capture_segments
            WHERE file_name = :file_name
            """
        ),
        {"file_name": file_name},
    ).mappings().first()
    return dict(row) if row is not None else None


def get_capture_session_by_session_id(
    db: Session,
    *,
    session_id: str,
) -> dict | None:
    row = db.execute(
        text(
            """
            SELECT id, session_id, capture_interface, started_at,
                   first_window_start, ended_at, capture_gap_start,
                   capture_gap_end, status, created_at, updated_at
            FROM packet_capture_sessions
            WHERE session_id = :session_id
            """
        ),
        {"session_id": session_id},
    ).mappings().first()
    return dict(row) if row is not None else None


def list_capture_segments_by_session(
    db: Session,
    *,
    session_id: str,
) -> list[dict]:
    rows = db.execute(
        text(
            """
            SELECT pcsg.id, pcsg.capture_session_id, pcsg.file_name,
                   pcsg.capture_interface, pcsg.window_start, pcsg.window_end,
                   pcsg.status, pcsg.packet_count, pcsg.processed_at,
                   pcsg.error_code, pcsg.error_message,
                   pcsg.created_at, pcsg.updated_at
            FROM packet_capture_segments pcsg
            JOIN packet_capture_sessions pcs
                ON pcs.id = pcsg.capture_session_id
            WHERE pcs.session_id = :session_id
            ORDER BY pcsg.window_start ASC, pcsg.id ASC
            """
        ),
        {"session_id": session_id},
    ).mappings()
    return [dict(row) for row in rows]


def get_packet_capture_ready_through(
    db: Session,
    *,
    session_id: str,
) -> PacketCaptureReadiness | None:
    session = get_capture_session_by_session_id(db, session_id=session_id)
    if session is None:
        return None

    first_window_start = session.get("first_window_start")
    if first_window_start is None:
        return PacketCaptureReadiness(session_id=session_id, packet_capture_ready_through=None)

    expected_window_start = _parse_db_utc(first_window_start)
    ready_through: datetime | None = None
    completed_statuses = {"READY", "PROCESSED", "EMPTY"}

    for segment in list_capture_segments_by_session(db, session_id=session_id):
        window_start = _parse_db_utc(segment["window_start"])
        if window_start < expected_window_start:
            continue
        if window_start > expected_window_start:
            break
        if segment["status"] not in completed_statuses:
            break

        window_end = _parse_db_utc(segment["window_end"])
        if window_end != window_start + timedelta(seconds=10):
            break

        ready_through = window_end
        expected_window_start = window_end

    return PacketCaptureReadiness(
        session_id=session_id,
        packet_capture_ready_through=ready_through,
    )


def insert_ready_segment(
    db: Session,
    *,
    capture_session_pk: int,
    file_name: str,
    capture_interface: str,
    window_start: datetime,
    window_end: datetime,
    actual_capture_started_at: datetime | None = None,
    capture_stop_requested_at: datetime | None = None,
    capture_process_exited_at: datetime | None = None,
    start_delay_seconds: float | None = None,
    captured_duration_seconds: float | None = None,
) -> int:
    """캡처가 정상 종료된 pcap에 대해 READY 상태 Segment row를 생성합니다.

    Timing Metadata 인자들은 전부 선택 사항이다 (기본값 None). Crash Recovery
    경로(reconcile_orphan_ready_files 등)처럼 실제 tcpdump 실행 시각을 알 수 없는
    호출부는 이 값들을 생략해도 되며, 이 경우 명목 Window와 실제 Coverage를
    구분하는 Phase 4 Packet Feature API는 해당 Segment를 "Timing Metadata 없음"으로
    간주해 학습·추론·Trust 입력에서 제외한다 (공통 적격 함수, capture_policy.py 참고).
    """
    result = db.execute(
        text(
            """
            INSERT INTO packet_capture_segments (
                capture_session_id, file_name, capture_interface,
                window_start, window_end, status,
                actual_capture_started_at, capture_stop_requested_at,
                capture_process_exited_at, start_delay_seconds,
                captured_duration_seconds
            )
            VALUES (
                :capture_session_id, :file_name, :capture_interface,
                :window_start, :window_end, 'READY',
                :actual_capture_started_at, :capture_stop_requested_at,
                :capture_process_exited_at, :start_delay_seconds,
                :captured_duration_seconds
            )
            """
        ),
        {
            "capture_session_id": capture_session_pk,
            "file_name": file_name,
            "capture_interface": capture_interface,
            "window_start": format_utc_iso(window_start),
            "window_end": format_utc_iso(window_end),
            "actual_capture_started_at": _optional_utc_iso_precise(actual_capture_started_at),
            "capture_stop_requested_at": _optional_utc_iso_precise(capture_stop_requested_at),
            "capture_process_exited_at": _optional_utc_iso_precise(capture_process_exited_at),
            "start_delay_seconds": start_delay_seconds,
            "captured_duration_seconds": captured_duration_seconds,
        },
    )
    return int(result.lastrowid or 0)


def insert_failed_segment(
    db: Session,
    *,
    capture_session_pk: int,
    file_name: str | None,
    capture_interface: str,
    window_start: datetime,
    window_end: datetime,
    error_code: str,
    error_message: str,
    actual_capture_started_at: datetime | None = None,
    capture_stop_requested_at: datetime | None = None,
    capture_process_exited_at: datetime | None = None,
    start_delay_seconds: float | None = None,
    captured_duration_seconds: float | None = None,
) -> int:
    """Partial Capture 등 영구 실패로 확정된 pcap에 대해 FAILED Segment row를 생성합니다.

    error_code='LATE_CAPTURE'는 DB CHECK 제약상 file_name/Timing Metadata(시작 지연
    제외)가 모두 NULL이어야 한다. 이 경우 별도 헬퍼 insert_late_capture_segment()를
    사용하는 것을 권장한다 (실수로 값을 채워 CHECK 위반을 일으키는 것을 방지).
    """
    result = db.execute(
        text(
            """
            INSERT INTO packet_capture_segments (
                capture_session_id, file_name, capture_interface,
                window_start, window_end, status, error_code, error_message,
                processed_at,
                actual_capture_started_at, capture_stop_requested_at,
                capture_process_exited_at, start_delay_seconds,
                captured_duration_seconds
            )
            VALUES (
                :capture_session_id, :file_name, :capture_interface,
                :window_start, :window_end, 'FAILED', :error_code, :error_message,
                CURRENT_TIMESTAMP,
                :actual_capture_started_at, :capture_stop_requested_at,
                :capture_process_exited_at, :start_delay_seconds,
                :captured_duration_seconds
            )
            """
        ),
        {
            "capture_session_id": capture_session_pk,
            "file_name": file_name,
            "capture_interface": capture_interface,
            "window_start": format_utc_iso(window_start),
            "window_end": format_utc_iso(window_end),
            "error_code": error_code,
            "error_message": error_message,
            "actual_capture_started_at": _optional_utc_iso_precise(actual_capture_started_at),
            "capture_stop_requested_at": _optional_utc_iso_precise(capture_stop_requested_at),
            "capture_process_exited_at": _optional_utc_iso_precise(capture_process_exited_at),
            "start_delay_seconds": start_delay_seconds,
            "captured_duration_seconds": captured_duration_seconds,
        },
    )
    return int(result.lastrowid or 0)


def insert_late_capture_segment(
    db: Session,
    *,
    capture_session_pk: int,
    capture_interface: str,
    window_start: datetime,
    window_end: datetime,
    error_message: str,
    start_delay_seconds: float | None = None,
) -> int:
    """허용 지연을 초과해 Capture Process를 아예 실행하지 못한 Window를 기록합니다.

    예정된 Window를 대기한 뒤 허용 지연을 초과한 경우에는 FAILED/LATE_CAPTURE Segment 한 건을 남기고 Session을 마감한다."

    file_name/actual_capture_started_at/capture_stop_requested_at/
    capture_process_exited_at은 DB CHECK 제약에 따라 항상 NULL이고
    captured_duration_seconds는 항상 0으로 고정된다. start_delay_seconds만
    감사용으로 실제 관측된 지연을 남긴다 (CHECK 제약이 이 컬럼은 제한하지 않음).

    호출자는 이 Segment 저장 직후 부모 Session을 FAILED로 마감해야 한다.
    """
    return insert_failed_segment(
        db,
        capture_session_pk=capture_session_pk,
        file_name=None,
        capture_interface=capture_interface,
        window_start=window_start,
        window_end=window_end,
        error_code=LATE_CAPTURE,
        error_message=error_message,
        actual_capture_started_at=None,
        capture_stop_requested_at=None,
        capture_process_exited_at=None,
        start_delay_seconds=start_delay_seconds,
        captured_duration_seconds=0.0,
    )


def _optional_utc_iso_precise(value: datetime | None) -> str | None:
    """actual_capture_started_at/capture_stop_requested_at/capture_process_exited_at처럼
    실제 wall-clock 관측값인 필드용. window_start/window_end와 달리 밀리초 이하
    정밀도를 보존한다."""
    return format_utc_iso_precise(value) if value is not None else None


def _parse_db_utc(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = parse_utc_iso(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0)
