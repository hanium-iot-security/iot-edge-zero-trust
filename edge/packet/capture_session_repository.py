"""packet_capture_sessions / packet_capture_segments DB 읽기/쓰기.

Phase 3-B 세부 계획 4.2, 4.3, 3.2, 3.3, 3.4 절의 규칙을 구현합니다.
이 모듈은 Session/commit/rollback을 스스로 책임지지 않습니다 (호출자가 담당).
tcpdump 실행이나 파일시스템 rename은 capture_runtime.py가 담당합니다.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.packet.pcap_naming import format_utc_iso, parse_utc_iso

PARTIAL_CAPTURE = "PARTIAL_CAPTURE"
PCAP_FILE_MISSING = "PCAP_FILE_MISSING"


@dataclass(frozen=True)
class SessionRecord:
    id: int
    session_id: str
    capture_interface: str
    status: str


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


def insert_ready_segment(
    db: Session,
    *,
    capture_session_pk: int,
    file_name: str,
    capture_interface: str,
    window_start: datetime,
    window_end: datetime,
) -> int:
    """캡처가 정상 종료된 pcap에 대해 READY 상태 Segment row를 생성합니다 (2.1 절 5번)."""
    result = db.execute(
        text(
            """
            INSERT INTO packet_capture_segments (
                capture_session_id, file_name, capture_interface,
                window_start, window_end, status
            )
            VALUES (
                :capture_session_id, :file_name, :capture_interface,
                :window_start, :window_end, 'READY'
            )
            """
        ),
        {
            "capture_session_id": capture_session_pk,
            "file_name": file_name,
            "capture_interface": capture_interface,
            "window_start": format_utc_iso(window_start),
            "window_end": format_utc_iso(window_end),
        },
    )
    return int(result.lastrowid or 0)


def insert_failed_segment(
    db: Session,
    *,
    capture_session_pk: int,
    file_name: str,
    capture_interface: str,
    window_start: datetime,
    window_end: datetime,
    error_code: str,
    error_message: str,
) -> int:
    """Partial Capture 등 영구 실패로 확정된 pcap에 대해 FAILED Segment row를 생성합니다."""
    result = db.execute(
        text(
            """
            INSERT INTO packet_capture_segments (
                capture_session_id, file_name, capture_interface,
                window_start, window_end, status, error_code, error_message,
                processed_at
            )
            VALUES (
                :capture_session_id, :file_name, :capture_interface,
                :window_start, :window_end, 'FAILED', :error_code, :error_message,
                CURRENT_TIMESTAMP
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
        },
    )
    return int(result.lastrowid or 0)