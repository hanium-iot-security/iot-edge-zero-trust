"""Packet Capture Session/Segment Lifecycle 테스트 (실제 SQLite DB 사용).

- capture_session_repository.py: packet_capture_sessions/segments DB 읽기/쓰기
- run_packet_capture.py: Session 생성, Gap 기록, 캡처 루프, Crash Recovery 전체 흐름
"""

from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from backend.app.config import settings
from backend.app.database import SessionLocal
from db.migration_runner import apply_migrations
from edge.packet import capture_session_repository as repo
from edge.packet.capture_runtime import CaptureOutcome, CaptureRuntimeConfig
from edge.packet.pcap_naming import build_pcap_filename, format_utc_iso, parse_utc_iso
from edge.packet.run_packet_capture import (
    GracefulShutdown,
    reconcile_leftover_tmp_files,
    reconcile_orphan_failed_files,
    reconcile_orphan_ready_files,
    reconcile_stale_running_sessions,
    run_capture_loop,
    start_new_session,
)

SESSION_ID_A = "550e8400-e29b-41d4-a716-446655440000"
SESSION_ID_B = "660e8400-e29b-41d4-a716-446655440001"


def _utc(*args) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


@pytest.fixture()
def db_session():
    db_path = settings.database_url.removeprefix("sqlite:///")
    apply_migrations(db_path=db_path, migrations_dir="db/migrations")
    with SessionLocal() as db:
        # 테스트 DB 파일은 pytest 세션 전체에서 재사용되므로 매 테스트 전에 초기화한다.
        db.execute(text("DELETE FROM packet_capture_segments"))
        db.execute(text("DELETE FROM packet_capture_sessions"))
        db.commit()
        yield db


def _make_config(tmp_path: Path) -> CaptureRuntimeConfig:
    config = CaptureRuntimeConfig(
        capture_interface="eth0",
        window_seconds=10,
        incoming_dir=tmp_path / "incoming",
        ready_dir=tmp_path / "ready",
        failed_dir=tmp_path / "failed",
    )
    config.ensure_directories()
    return config


@dataclass
class FakeCaptureProcess:
    outcomes: list  # queue of CaptureOutcome consumed one per call
    write_file: bool = True

    def capture_window(self, *, interface, output_path, window_seconds):
        outcome = self.outcomes.pop(0)
        if self.write_file:
            output_path.write_bytes(b"fake-pcap-bytes")
        return outcome


@dataclass
class _MutableClock:
    """테스트에서 clock()/sleep() 둘 다 같은 가짜 시계를 공유하게 만드는 헬퍼."""

    value: datetime

    def now(self) -> datetime:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += timedelta(seconds=seconds)


@dataclass
class _OverheadCaptureProcess:
    """실제 tcpdump 대신, '요청받은 시간만큼 캡처 + 매 호출마다 고정 오버헤드'를
    가짜 시계에 반영하는 프로세스. DB commit·로깅 등 부수 작업 시간을 흉내낸다.

    PR #18 후속 리뷰: UTC Window 실행 지연이 연속 Capture에서 누적되는지 검증할 때 사용.
    """

    clock: _MutableClock
    overhead_seconds: float
    calls: list = field(default_factory=list)

    def capture_window(self, *, interface, output_path, window_seconds):
        self.calls.append(window_seconds)
        output_path.write_bytes(b"fake-pcap-bytes")
        self.clock.advance(window_seconds + self.overhead_seconds)
        return CaptureOutcome(completed_full_window=True, exit_code=-15)


# ---------------------------------------------------------------------------
# capture_session_repository.py
# ---------------------------------------------------------------------------


class TestSessionLifecycle:
    def test_create_session_returns_running_row(self, db_session) -> None:
        session_pk = repo.create_session(
            db_session,
            session_id=SESSION_ID_A,
            capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 3),
        )
        db_session.commit()

        assert session_pk > 0
        assert repo.find_session_pk_by_session_id(db_session, SESSION_ID_A) == session_pk

    def test_set_first_window_start_and_close(self, db_session) -> None:
        session_pk = repo.create_session(
            db_session,
            session_id=SESSION_ID_A,
            capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 3),
        )
        repo.set_first_window_start(db_session, session_pk, _utc(2026, 7, 15, 10, 0, 10))
        repo.close_session(db_session, session_pk, _utc(2026, 7, 15, 11, 0, 0), "COMPLETED")
        db_session.commit()

        row = db_session.execute(
            text(
                "SELECT status, first_window_start, ended_at FROM packet_capture_sessions WHERE id = :id"
            ),
            {"id": session_pk},
        ).mappings().first()
        assert row["status"] == "COMPLETED"
        assert row["first_window_start"] == "2026-07-15T10:00:10Z"
        assert row["ended_at"] == "2026-07-15T11:00:00Z"

    def test_close_session_rejects_invalid_status(self, db_session) -> None:
        session_pk = repo.create_session(
            db_session,
            session_id=SESSION_ID_A,
            capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 3),
        )
        with pytest.raises(ValueError):
            repo.close_session(db_session, session_pk, _utc(2026, 7, 15, 11, 0, 0), "RUNNING")


class TestCaptureGap:
    def test_record_capture_gap(self, db_session) -> None:
        session_pk = repo.create_session(
            db_session,
            session_id=SESSION_ID_A,
            capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 3),
        )
        repo.record_capture_gap(
            db_session,
            session_pk,
            gap_start=_utc(2026, 7, 15, 9, 0, 0),
            gap_end=_utc(2026, 7, 15, 10, 0, 10),
        )
        db_session.commit()

        row = db_session.execute(
            text(
                "SELECT capture_gap_start, capture_gap_end FROM packet_capture_sessions WHERE id = :id"
            ),
            {"id": session_pk},
        ).mappings().first()
        assert row["capture_gap_start"] == "2026-07-15T09:00:00Z"
        assert row["capture_gap_end"] == "2026-07-15T10:00:10Z"

    def test_find_last_segment_window_end_returns_none_when_no_segments(self, db_session) -> None:
        assert repo.find_last_segment_window_end(db_session, "eth0") is None

    def test_find_last_segment_window_end_returns_max_across_sessions(self, db_session) -> None:
        session_pk = repo.create_session(
            db_session,
            session_id=SESSION_ID_A,
            capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 0),
        )
        repo.insert_ready_segment(
            db_session,
            capture_session_pk=session_pk,
            file_name="capture_a.pcap",
            capture_interface="eth0",
            window_start=_utc(2026, 7, 15, 10, 0, 0),
            window_end=_utc(2026, 7, 15, 10, 0, 10),
        )
        repo.insert_ready_segment(
            db_session,
            capture_session_pk=session_pk,
            file_name="capture_b.pcap",
            capture_interface="eth0",
            window_start=_utc(2026, 7, 15, 10, 0, 10),
            window_end=_utc(2026, 7, 15, 10, 0, 20),
        )
        db_session.commit()

        assert repo.find_last_segment_window_end(db_session, "eth0") == _utc(2026, 7, 15, 10, 0, 20)


class TestSegments:
    def test_insert_ready_segment_then_lookup_by_file_name(self, db_session) -> None:
        session_pk = repo.create_session(
            db_session,
            session_id=SESSION_ID_A,
            capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 0),
        )
        repo.insert_ready_segment(
            db_session,
            capture_session_pk=session_pk,
            file_name="capture_ready.pcap",
            capture_interface="eth0",
            window_start=_utc(2026, 7, 15, 10, 0, 0),
            window_end=_utc(2026, 7, 15, 10, 0, 10),
        )
        db_session.commit()

        found = repo.find_segment_by_file_name(db_session, "capture_ready.pcap")
        assert found is not None
        assert found["status"] == "READY"
        assert found["capture_session_id"] == session_pk

    def test_duplicate_file_name_raises_integrity_error(self, db_session) -> None:
        session_pk = repo.create_session(
            db_session,
            session_id=SESSION_ID_A,
            capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 0),
        )
        repo.insert_ready_segment(
            db_session,
            capture_session_pk=session_pk,
            file_name="capture_dup.pcap",
            capture_interface="eth0",
            window_start=_utc(2026, 7, 15, 10, 0, 0),
            window_end=_utc(2026, 7, 15, 10, 0, 10),
        )
        db_session.commit()

        with pytest.raises(IntegrityError):
            repo.insert_ready_segment(
                db_session,
                capture_session_pk=session_pk,
                file_name="capture_dup.pcap",
                capture_interface="eth0",
                window_start=_utc(2026, 7, 15, 10, 0, 20),
                window_end=_utc(2026, 7, 15, 10, 0, 30),
            )
            db_session.commit()
        db_session.rollback()

    def test_insert_failed_segment_records_error_code(self, db_session) -> None:
        session_pk = repo.create_session(
            db_session,
            session_id=SESSION_ID_A,
            capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 0),
        )
        repo.insert_failed_segment(
            db_session,
            capture_session_pk=session_pk,
            file_name="capture_partial.pcap",
            capture_interface="eth0",
            window_start=_utc(2026, 7, 15, 10, 0, 0),
            window_end=_utc(2026, 7, 15, 10, 0, 10),
            error_code=repo.PARTIAL_CAPTURE,
            error_message="leftover .pcap.tmp found on restart",
        )
        db_session.commit()

        found = repo.find_segment_by_file_name(db_session, "capture_partial.pcap")
        assert found is not None
        assert found["status"] == "FAILED"

    def test_insert_ready_segment_stores_timing_metadata(self, db_session) -> None:
        session_pk = repo.create_session(
            db_session, session_id=SESSION_ID_A, capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 0),
        )
        repo.insert_ready_segment(
            db_session,
            capture_session_pk=session_pk,
            file_name="capture_timed.pcap",
            capture_interface="eth0",
            window_start=_utc(2026, 7, 15, 10, 0, 0),
            window_end=_utc(2026, 7, 15, 10, 0, 10),
            actual_capture_started_at=_utc(2026, 7, 15, 10, 0, 0).replace(microsecond=300_000),
            # 실제 SIGTERM이 명목 window_end(10:00:10)보다 0.4초 늦게 나간 상황을 흉내낸다
            # (OS 스케줄링 지연). 이 필드도 실제 관측값이므로 window_end와 다를 수 있다.
            capture_stop_requested_at=_utc(2026, 7, 15, 10, 0, 10).replace(microsecond=400_000),
            capture_process_exited_at=_utc(2026, 7, 15, 10, 0, 10).replace(microsecond=50_000),
            start_delay_seconds=0.3,
            captured_duration_seconds=9.7,
        )
        db_session.commit()

        row = db_session.execute(
            text(
                "SELECT start_delay_seconds, captured_duration_seconds, "
                "capture_stop_requested_at, actual_capture_started_at, "
                "capture_process_exited_at FROM packet_capture_segments "
                "WHERE file_name = 'capture_timed.pcap'"
            )
        ).mappings().first()
        assert row["start_delay_seconds"] == pytest.approx(0.3)
        assert row["captured_duration_seconds"] == pytest.approx(9.7)
        # actual_capture_started_at/capture_stop_requested_at/capture_process_exited_at은
        # 전부 실제 wall-clock 관측값이므로 format_utc_iso()(정수 초로 truncate)가 아니라
        # microsecond를 보존하는 format_utc_iso_precise()로 저장돼야 한다. capture_stop_
        # requested_at은 window_end와 항상 같은 값이 아니라 실제 SIGTERM 호출 시각이라는
        # 점이 이 필드가 별도 컬럼으로 존재하는 이유이므로, 소수점이 사라지면(예:
        # "2026-07-15T10:00:10Z") 회귀다.
        assert row["actual_capture_started_at"] == "2026-07-15T10:00:00.300000Z"
        assert row["capture_stop_requested_at"] == "2026-07-15T10:00:10.400000Z"
        assert row["capture_process_exited_at"] == "2026-07-15T10:00:10.050000Z"


    def test_insert_ready_segment_without_timing_metadata_defaults_to_null(self, db_session) -> None:
        """Crash Recovery 경로처럼 Timing Metadata를 모르는 호출부는 생략할 수 있다."""
        session_pk = repo.create_session(
            db_session, session_id=SESSION_ID_A, capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 0),
        )
        repo.insert_ready_segment(
            db_session,
            capture_session_pk=session_pk,
            file_name="capture_no_timing.pcap",
            capture_interface="eth0",
            window_start=_utc(2026, 7, 15, 10, 0, 0),
            window_end=_utc(2026, 7, 15, 10, 0, 10),
        )
        db_session.commit()

        row = db_session.execute(
            text(
                "SELECT start_delay_seconds, captured_duration_seconds "
                "FROM packet_capture_segments WHERE file_name = 'capture_no_timing.pcap'"
            )
        ).mappings().first()
        assert row["start_delay_seconds"] is None
        assert row["captured_duration_seconds"] is None


class TestInsertLateCaptureSegment:
    """Phase 4 세부계획 2.1 절: 허용 지연 초과 Window의 감사용 FAILED/LATE_CAPTURE Segment."""

    def test_stores_failed_late_capture_with_null_file_name(self, db_session) -> None:
        session_pk = repo.create_session(
            db_session, session_id=SESSION_ID_A, capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 0),
        )
        repo.insert_late_capture_segment(
            db_session,
            capture_session_pk=session_pk,
            capture_interface="eth0",
            window_start=_utc(2026, 7, 15, 10, 0, 10),
            window_end=_utc(2026, 7, 15, 10, 0, 20),
            error_message="start_delay_seconds=15.0 exceeds allowed max_start_delay_seconds=1.0",
            start_delay_seconds=15.0,
        )
        db_session.commit()

        row = db_session.execute(
            text(
                "SELECT status, error_code, file_name, actual_capture_started_at, "
                "capture_stop_requested_at, capture_process_exited_at, "
                "start_delay_seconds, captured_duration_seconds "
                "FROM packet_capture_segments WHERE window_start = '2026-07-15T10:00:10Z'"
            )
        ).mappings().first()
        assert row["status"] == "FAILED"
        assert row["error_code"] == "LATE_CAPTURE"
        assert row["file_name"] is None
        assert row["actual_capture_started_at"] is None
        assert row["capture_stop_requested_at"] is None
        assert row["capture_process_exited_at"] is None
        assert row["captured_duration_seconds"] == 0.0
        # start_delay_seconds는 감사용으로 남는다 (DB CHECK가 이 컬럼은 제한하지 않음).
        assert row["start_delay_seconds"] == pytest.approx(15.0)

    def test_multiple_late_capture_segments_with_null_file_name_do_not_collide(self, db_session) -> None:
        """file_name UNIQUE 제약이 있어도 NULL은 SQLite에서 서로 구분되므로 여러 건 저장 가능."""
        session_pk = repo.create_session(
            db_session, session_id=SESSION_ID_A, capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 0),
        )
        repo.insert_late_capture_segment(
            db_session, capture_session_pk=session_pk, capture_interface="eth0",
            window_start=_utc(2026, 7, 15, 10, 0, 10), window_end=_utc(2026, 7, 15, 10, 0, 20),
            error_message="first", start_delay_seconds=2.0,
        )
        repo.insert_late_capture_segment(
            db_session, capture_session_pk=session_pk, capture_interface="eth0",
            window_start=_utc(2026, 7, 15, 10, 0, 20), window_end=_utc(2026, 7, 15, 10, 0, 30),
            error_message="second", start_delay_seconds=3.0,
        )
        db_session.commit()

        count = db_session.execute(
            text("SELECT COUNT(*) FROM packet_capture_segments WHERE error_code = 'LATE_CAPTURE'")
        ).scalar()
        assert count == 2


# ---------------------------------------------------------------------------
# run_packet_capture.py
# ---------------------------------------------------------------------------


class TestStartNewSession:
    def test_creates_session_and_first_window_start(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        now = _utc(2026, 7, 15, 10, 0, 3)

        session_pk, session_id, first_window_start = start_new_session(db_session, config, now)

        assert session_pk > 0
        assert first_window_start == _utc(2026, 7, 15, 10, 0, 10)
        assert repo.find_session_pk_by_session_id(db_session, session_id) == session_pk

    def test_records_gap_from_previous_segment(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        old_session_pk = repo.create_session(
            db_session, session_id=SESSION_ID_A,
            capture_interface="eth0", started_at=_utc(2026, 7, 15, 9, 0, 0),
        )
        repo.insert_ready_segment(
            db_session, capture_session_pk=old_session_pk, file_name="old.pcap",
            capture_interface="eth0",
            window_start=_utc(2026, 7, 15, 9, 0, 0), window_end=_utc(2026, 7, 15, 9, 0, 10),
        )
        db_session.commit()

        now = _utc(2026, 7, 15, 10, 0, 3)
        session_pk, _session_id, first_window_start = start_new_session(db_session, config, now)

        row = db_session.execute(
            text("SELECT capture_gap_start, capture_gap_end FROM packet_capture_sessions WHERE id = :id"),
            {"id": session_pk},
        ).mappings().first()
        assert row["capture_gap_start"] == "2026-07-15T09:00:10Z"
        assert row["capture_gap_end"] == format_utc_iso(first_window_start)


class TestRunCaptureLoop:
    def test_captures_two_successful_windows(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        session_pk, session_id, first_window_start = start_new_session(
            db_session, config, _utc(2026, 7, 15, 10, 0, 3)
        )
        process = FakeCaptureProcess(
            outcomes=[
                CaptureOutcome(completed_full_window=True, exit_code=-15),
                CaptureOutcome(completed_full_window=True, exit_code=-15),
            ]
        )
        shutdown = GracefulShutdown()

        windows_captured = run_capture_loop(
            db_session, process, config,
            session_pk=session_pk, session_id=session_id,
            first_window_start=first_window_start,
            shutdown=shutdown, max_windows=2,
            clock=lambda: first_window_start,  # 지연 없이 정확히 window_start에 시작한 척
            sleep=lambda _seconds: None,
        )

        assert windows_captured == 2
        segments = db_session.execute(
            text("SELECT status FROM packet_capture_segments ORDER BY window_start")
        ).fetchall()
        assert [row[0] for row in segments] == ["READY", "READY"]

    def test_partial_capture_recorded_as_failed(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        session_pk, session_id, first_window_start = start_new_session(
            db_session, config, _utc(2026, 7, 15, 10, 0, 3)
        )
        process = FakeCaptureProcess(
            outcomes=[CaptureOutcome(completed_full_window=False, exit_code=1)]
        )
        shutdown = GracefulShutdown()

        run_capture_loop(
            db_session, process, config,
            session_pk=session_pk, session_id=session_id,
            first_window_start=first_window_start,
            shutdown=shutdown, max_windows=1,
            clock=lambda: first_window_start,
            sleep=lambda _seconds: None,
        )

        row = db_session.execute(
            text("SELECT status, error_code FROM packet_capture_segments")
        ).mappings().first()
        assert row["status"] == "FAILED"
        assert row["error_code"] == "PARTIAL_CAPTURE"

    def test_shutdown_flag_stops_loop_before_next_window(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        session_pk, session_id, first_window_start = start_new_session(
            db_session, config, _utc(2026, 7, 15, 10, 0, 3)
        )
        process = FakeCaptureProcess(
            outcomes=[CaptureOutcome(completed_full_window=True, exit_code=-15)]
        )
        shutdown = GracefulShutdown()
        shutdown.requested = True  # 이미 종료 신호가 온 상태로 시작

        windows_captured = run_capture_loop(
            db_session, process, config,
            session_pk=session_pk, session_id=session_id,
            first_window_start=first_window_start,
            shutdown=shutdown,
            clock=lambda: _utc(2026, 7, 15, 10, 0, 30),
            sleep=lambda _seconds: None,
        )

        assert windows_captured == 0

    def test_expired_window_transitions_to_new_session(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        # first_window_start=10:00:10 이지만, "현재 시각"은 이미 10:00:25로
        # window_end(10:00:20)를 지나버린 상황을 흉내낸다.
        first_window_start = _utc(2026, 7, 15, 10, 0, 10)
        original_session_pk = repo.create_session(
            db_session, session_id=SESSION_ID_A, capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 3),
        )
        db_session.commit()

        process = FakeCaptureProcess(
            outcomes=[CaptureOutcome(completed_full_window=True, exit_code=-15)]
        )
        shutdown = GracefulShutdown()

        windows_captured = run_capture_loop(
            db_session, process, config,
            session_pk=original_session_pk, session_id=SESSION_ID_A,
            first_window_start=first_window_start,
            shutdown=shutdown, max_windows=1,
            clock=lambda: _utc(2026, 7, 15, 10, 0, 25),
            sleep=lambda _seconds: None,
        )

        assert windows_captured == 1

        # 원래 Session은 허용 지연 초과(LATE_CAPTURE)로 인해 FAILED로 마감돼야 한다
        # (Phase 4 세부계획 2.1 절: "부모 packet_capture_sessions.status=FAILED로 마감한다").
        original_row = db_session.execute(
            text("SELECT status FROM packet_capture_sessions WHERE id = :id"),
            {"id": original_session_pk},
        ).mappings().first()
        assert original_row["status"] == "FAILED"

        segments = db_session.execute(
            text(
                "SELECT capture_session_id, window_start, status, error_code, file_name "
                "FROM packet_capture_segments ORDER BY window_start"
            )
        ).fetchall()
        # 놓친 10:00:10 Window는 감사용 FAILED/LATE_CAPTURE Segment 한 건으로 남고
        # (file_name은 NULL), 실제로 캡처된 Window는 10:00:30(다음 신선한 경계)이다.
        assert len(segments) == 2
        late_session_pk, late_window_start, late_status, late_error_code, late_file_name = segments[0]
        assert late_window_start == "2026-07-15T10:00:10Z"
        assert late_status == "FAILED"
        assert late_error_code == "LATE_CAPTURE"
        assert late_file_name is None
        assert late_session_pk == original_session_pk

        captured_session_pk, captured_window_start, captured_status, _, captured_file_name = segments[1]
        assert captured_window_start == "2026-07-15T10:00:30Z"
        assert captured_status == "READY"
        assert captured_file_name is not None
        # 그리고 그 READY Segment는 원래 Session이 아니라 새로 만들어진 Session에 연결됐어야 한다.
        assert captured_session_pk != original_session_pk

        # 새 Session도 max_windows 도달로 정상 종료되어 COMPLETED로 마감돼야 한다.
        new_session_row = db_session.execute(
            text("SELECT status FROM packet_capture_sessions WHERE id = :id"),
            {"id": captured_session_pk},
        ).mappings().first()
        assert new_session_row["status"] == "COMPLETED"

    def test_expired_window_transition_records_capture_gap_on_new_session(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        old_session_pk = repo.create_session(
            db_session, session_id=SESSION_ID_A, capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 0),
        )
        # 이전 Session에서 실제로 정상 캡처된 Segment가 하나 있다고 가정한다
        # (10:00:00~10:00:10). 다음 Window(10:00:10~10:00:20)가 만료되어 발견된다.
        repo.insert_ready_segment(
            db_session, capture_session_pk=old_session_pk, file_name="prior.pcap",
            capture_interface="eth0",
            window_start=_utc(2026, 7, 15, 10, 0, 0), window_end=_utc(2026, 7, 15, 10, 0, 10),
        )
        db_session.commit()

        first_window_start = _utc(2026, 7, 15, 10, 0, 10)
        process = FakeCaptureProcess(
            outcomes=[CaptureOutcome(completed_full_window=True, exit_code=-15)]
        )
        shutdown = GracefulShutdown()

        run_capture_loop(
            db_session, process, config,
            session_pk=old_session_pk, session_id=SESSION_ID_A,
            first_window_start=first_window_start,
            shutdown=shutdown, max_windows=1,
            clock=lambda: _utc(2026, 7, 15, 10, 0, 25),  # window_end(10:00:20)를 이미 지남
            sleep=lambda _seconds: None,
        )

        segment = db_session.execute(
            text(
                "SELECT capture_session_id FROM packet_capture_segments "
                "WHERE window_start = '2026-07-15T10:00:30Z' AND status = 'READY'"
            )
        ).mappings().first()
        new_session_pk = segment["capture_session_id"]

        row = db_session.execute(
            text("SELECT capture_gap_start, capture_gap_end FROM packet_capture_sessions WHERE id = :id"),
            {"id": new_session_pk},
        ).mappings().first()

        # LATE_CAPTURE 감사 Segment가 놓친 Window(10:00:10~10:00:20)를 이미 기록했으므로,
        # Gap은 그 Segment의 window_end(10:00:20)부터 새 Session의
        # first_window_start(10:00:30)까지만 "알 수 없는 공백"으로 좁혀져야 한다.
        assert row["capture_gap_start"] == "2026-07-15T10:00:20Z"
        assert row["capture_gap_end"] == "2026-07-15T10:00:30Z"

    def test_first_ever_window_expiring_still_records_capture_gap(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        # 세션은 있지만(막 create_session만 한 상태), Segment는 이 interface에 대해
        # 이 DB 전체에서 단 하나도 없다 -- find_last_segment_window_end가 None을 반환.
        session_pk = repo.create_session(
            db_session, session_id=SESSION_ID_A, capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 3),
        )
        db_session.commit()
        assert repo.find_last_segment_window_end(db_session, "eth0") is None

        first_window_start = _utc(2026, 7, 15, 10, 0, 10)  # 첫 Window부터
        process = FakeCaptureProcess(
            outcomes=[CaptureOutcome(completed_full_window=True, exit_code=-15)]
        )
        shutdown = GracefulShutdown()

        run_capture_loop(
            db_session, process, config,
            session_pk=session_pk, session_id=SESSION_ID_A,
            first_window_start=first_window_start,
            shutdown=shutdown, max_windows=1,
            clock=lambda: _utc(2026, 7, 15, 10, 0, 25),  # window_end(10:00:20)를 이미 지남
            sleep=lambda _seconds: None,
        )

        segment = db_session.execute(
            text(
                "SELECT capture_session_id FROM packet_capture_segments "
                "WHERE status = 'READY'"
            )
        ).mappings().first()
        new_session_pk = segment["capture_session_id"]

        row = db_session.execute(
            text("SELECT capture_gap_start, capture_gap_end FROM packet_capture_sessions WHERE id = :id"),
            {"id": new_session_pk},
        ).mappings().first()

        # 이전 Segment가 전혀 없었지만, LATE_CAPTURE 감사 Segment가 놓친 첫
        # Window(10:00:10~10:00:20)를 기록했으므로 Gap은 그 이후(10:00:20)부터
        # 새 Session의 first_window_start(10:00:30)까지만 남는다.
        assert row["capture_gap_start"] == "2026-07-15T10:00:20Z"
        assert row["capture_gap_end"] == "2026-07-15T10:00:30Z"

    def test_late_wakeup_after_sleep_transitions_to_new_session(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        session_pk, session_id, first_window_start = start_new_session(
            db_session, config, _utc(2026, 7, 15, 10, 0, 3)
        )  # first_window_start == 10:00:10, window_end == 10:00:20

        clock = _MutableClock(_utc(2026, 7, 15, 10, 0, 5))  # 아직 window_start 전, 만료 아님

        def oversleep(seconds: float) -> None:
            # 요청받은 것보다 20초 더 걸려서 깨어난 상황을 흉내낸다
            # (OS 스케줄링 지연·시스템 부하 시뮬레이션).
            clock.advance(seconds + 20)

        process = FakeCaptureProcess(
            outcomes=[CaptureOutcome(completed_full_window=True, exit_code=-15)]
        )
        shutdown = GracefulShutdown()

        windows_captured = run_capture_loop(
            db_session, process, config,
            session_pk=session_pk, session_id=session_id,
            first_window_start=first_window_start,
            shutdown=shutdown, max_windows=1,
            clock=clock.now,
            sleep=oversleep,
        )

        # 만료된 Window(10:00:10~10:00:20)는 실제 tcpdump 실행 없이 건너뛰고, 다음
        # 신선한 경계(10:00:30~)의 Window 딱 1개만 실제로 캡처됐어야 한다.
        assert windows_captured == 1
        assert process.outcomes == []  # 큐에 넣어둔 outcome이 정확히 1번만 소비됨
                                        # (만료된 Window에서는 capture_window()가 호출 안 됨)

        original_row = db_session.execute(
            text("SELECT status FROM packet_capture_sessions WHERE id = :id"),
            {"id": session_pk},
        ).mappings().first()
        # 허용 지연 초과(LATE_CAPTURE)로 인한 전환이므로 원래 Session은 FAILED로 마감된다.
        assert original_row["status"] == "FAILED"

        segments = db_session.execute(
            text("SELECT capture_session_id, window_start, status FROM packet_capture_segments ORDER BY window_start")
        ).fetchall()
        # 놓친 Window에 대한 감사용 FAILED/LATE_CAPTURE Segment 한 건 + 실제 캡처된
        # READY Segment 한 건, 총 두 건이어야 한다.
        assert len(segments) == 2
        late_session_pk, late_window_start, late_status = segments[0]
        assert late_session_pk == session_pk
        assert late_window_start == "2026-07-15T10:00:10Z"
        assert late_status == "FAILED"

        captured_session_pk, captured_window_start, captured_status = segments[1]
        assert captured_session_pk != session_pk  # 새 Session에 연결됨
        assert captured_window_start == "2026-07-15T10:00:30Z"
        assert captured_status == "READY"


    def test_shutdown_requested_during_sleep_stops_before_capturing(self, db_session, tmp_path) -> None:
        """window_start까지 대기하는 도중 종료 신호가 오면, 대기가 끝나도
        새 캡처를 시작하지 않고 즉시 빠져나가야 한다."""
        config = _make_config(tmp_path)
        session_pk, session_id, first_window_start = start_new_session(
            db_session, config, _utc(2026, 7, 15, 10, 0, 3)
        )
        process = FakeCaptureProcess(
            outcomes=[CaptureOutcome(completed_full_window=True, exit_code=-15)]
        )
        shutdown = GracefulShutdown()

        def sleep_and_request_shutdown(_seconds: float) -> None:
            # sleep 도중(=대기 중) 종료 신호가 도착한 상황을 흉내낸다.
            shutdown.requested = True

        windows_captured = run_capture_loop(
            db_session, process, config,
            session_pk=session_pk, session_id=session_id,
            first_window_start=first_window_start,
            shutdown=shutdown,
            clock=lambda: _utc(2026, 7, 15, 10, 0, 5),  # 아직 window_start 전 (만료 아님)
            sleep=sleep_and_request_shutdown,
        )

        assert windows_captured == 0
        assert process.outcomes == [CaptureOutcome(completed_full_window=True, exit_code=-15)]  # 소비 안 됨

    def test_normal_exit_closes_session_as_completed(self, db_session, tmp_path) -> None:
        """max_windows 도달로 정상 종료되면, run_capture_loop 자신이 현재 활성
        Session을 COMPLETED로 마감해야 한다 (main()이 더 이상 이 책임을 갖지 않음)."""
        config = _make_config(tmp_path)
        session_pk, session_id, first_window_start = start_new_session(
            db_session, config, _utc(2026, 7, 15, 10, 0, 3)
        )
        process = FakeCaptureProcess(
            outcomes=[CaptureOutcome(completed_full_window=True, exit_code=-15)]
        )
        shutdown = GracefulShutdown()

        run_capture_loop(
            db_session, process, config,
            session_pk=session_pk, session_id=session_id,
            first_window_start=first_window_start,
            shutdown=shutdown, max_windows=1,
            clock=lambda: first_window_start,
            sleep=lambda _seconds: None,
        )

        row = db_session.execute(
            text("SELECT status FROM packet_capture_sessions WHERE id = :id"),
            {"id": session_pk},
        ).mappings().first()
        assert row["status"] == "COMPLETED"

    def test_exception_marks_current_session_as_failed_and_reraises(self, db_session, tmp_path) -> None:
        """루프 도중 처리되지 않은 예외가 발생하면, 그 시점에 활성화돼 있던 Session을
        FAILED로 마감한 뒤 예외를 다시 던져야 한다 (systemd Restart=on-failure 유도)."""
        config = _make_config(tmp_path)
        session_pk, session_id, first_window_start = start_new_session(
            db_session, config, _utc(2026, 7, 15, 10, 0, 3)
        )

        class ExplodingCaptureProcess:
            def capture_window(self, *, interface, output_path, window_seconds):
                raise RuntimeError("simulated tcpdump launch failure")

        shutdown = GracefulShutdown()

        with pytest.raises(RuntimeError, match="simulated tcpdump launch failure"):
            run_capture_loop(
                db_session, ExplodingCaptureProcess(), config,
                session_pk=session_pk, session_id=session_id,
                first_window_start=first_window_start,
                shutdown=shutdown, max_windows=1,
                # window_start와 정확히 같은 시각으로 둬서, "만료된 Window" 경로가
                # 먼저 발동하지 않고 원래 Session이 여전히 활성인 상태에서 예외가
                # 발생하도록 한다.
                clock=lambda: first_window_start,
                sleep=lambda _seconds: None,
            )

        row = db_session.execute(
            text("SELECT status FROM packet_capture_sessions WHERE id = :id"),
            {"id": session_pk},
        ).mappings().first()
        assert row["status"] == "FAILED"


class TestRunCaptureLoopLateCaptureWithinWindow:
    """정상 실행 중이며 window_start < actual_start < window_end, 지연 1초 초과" -> Capture Process를 실행하지 않고 FAILED/LATE_CAPTURE로 처리."""

    def test_delay_beyond_policy_skips_capture_and_fails_session(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        session_pk, session_id, first_window_start = start_new_session(
            db_session, config, _utc(2026, 7, 15, 10, 0, 3)
        )  # first_window_start == 10:00:10, window_end == 10:00:20

        # 첫 sleep에서만 window_start보다 2초 늦게 깨어난 척한다 (window_end 전이지만
        # 기본 정책(1.0초+epsilon)을 초과하는 지연). 이후 sleep은 정상적으로 요청한
        # 시간만큼만 흘려보내 두 번째 Window는 정책 범위 안에서 캡처되게 한다.
        clock = _MutableClock(_utc(2026, 7, 15, 10, 0, 3))
        sleep_calls = {"count": 0}

        def sleep_late_once(seconds: float) -> None:
            sleep_calls["count"] += 1
            overshoot = 2.0 if sleep_calls["count"] == 1 else 0.0
            clock.advance(seconds + overshoot)

        process = FakeCaptureProcess(
            outcomes=[CaptureOutcome(completed_full_window=True, exit_code=-15)]
        )
        shutdown = GracefulShutdown()

        windows_captured = run_capture_loop(
            db_session, process, config,
            session_pk=session_pk, session_id=session_id,
            first_window_start=first_window_start,
            shutdown=shutdown, max_windows=1,
            clock=clock.now,
            sleep=sleep_late_once,
        )

        # LATE_CAPTURE로 건너뛴 Window는 max_windows 카운트에 포함되지 않으므로,
        # 다음 정수 경계에서 실제로 캡처된 Window 1개가 소진될 때까지 루프가 계속된다.
        assert windows_captured == 1
        assert process.outcomes == []

        original_row = db_session.execute(
            text("SELECT status FROM packet_capture_sessions WHERE id = :id"),
            {"id": session_pk},
        ).mappings().first()
        assert original_row["status"] == "FAILED"

        segments = db_session.execute(
            text(
                "SELECT window_start, status, error_code FROM packet_capture_segments "
                "ORDER BY window_start"
            )
        ).fetchall()
        assert len(segments) == 2
        assert segments[0] == ("2026-07-15T10:00:10Z", "FAILED", "LATE_CAPTURE")
        assert segments[1][1] == "READY"


class TestCumulativeDriftDoesNotAccumulate:
    """PR #18 후속 리뷰: UTC Window의 실행 지연이 연속 Capture에서 누적될 수 있는 문제 보완.

    매 Window마다 일정한 오버헤드(DB commit·로깅 등, 예: 0.3초)가 있어도,
    execute_capture_window의 self-correcting duration 덕분에 지연이 다음 Window로
    누적되지 않고, 5개 Window 모두 정확히 10초 간격의 UTC 경계에 기록되어야 한다.
    """

    def test_repeated_overhead_does_not_skip_windows_or_drift_labels(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        session_pk, session_id, first_window_start = start_new_session(
            db_session, config, _utc(2026, 7, 15, 10, 0, 3)
        )
        clock = _MutableClock(first_window_start)
        process = _OverheadCaptureProcess(clock=clock, overhead_seconds=0.3)
        shutdown = GracefulShutdown()

        windows_captured = run_capture_loop(
            db_session, process, config,
            session_pk=session_pk, session_id=session_id,
            first_window_start=first_window_start,
            shutdown=shutdown, max_windows=5,
            clock=clock.now,
            sleep=clock.advance,
        )

        assert windows_captured == 5

        rows = db_session.execute(
            text("SELECT window_start FROM packet_capture_segments ORDER BY window_start")
        ).fetchall()
        starts = [parse_utc_iso(row[0]) for row in rows]

        # 5개 모두 캡처됐다 (기존 버그였다면 반복 40회 중 34회쯤에서 하나가 통째로 스킵됨).
        assert len(starts) == 5
        assert starts[0] == first_window_start
        # 각 Window는 서로 정확히 10초 간격의 UTC 경계여야 한다 -- 라벨 자체는
        # 지연과 무관하게 항상 고정 산술로 계산되므로 절대 어긋나지 않는다.
        for i in range(1, len(starts)):
            assert (starts[i] - starts[i - 1]).total_seconds() == 10.0

        # 실제로 tcpdump에 요청한 duration이 self-correcting되어, 첫 Window만 정상
        # 10초이고 이후로는 오버헤드(0.3초)만큼 줄어든 채로 안정화되어야 한다
        # (계속 줄어들며 누적되는 게 아니라 일정 수준에서 멈춰야 함).
        assert process.calls[0] == pytest.approx(10.0, abs=1e-6)
        for later_call in process.calls[1:]:
            assert later_call == pytest.approx(9.7, abs=1e-6)


class TestCrashRecovery:
    def test_reconciles_leftover_tmp_as_partial_capture(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        session_id = SESSION_ID_A
        session_pk = repo.create_session(
            db_session, session_id=session_id, capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 0),
        )
        db_session.commit()

        tmp_filename = build_pcap_filename(
            session_id=session_id, interface="eth0",
            window_start=_utc(2026, 7, 15, 10, 0, 0), window_end=_utc(2026, 7, 15, 10, 0, 10),
            tmp=True,
        )
        (config.incoming_dir / tmp_filename).write_bytes(b"partial-bytes")

        reconciled = reconcile_leftover_tmp_files(db_session, config)

        assert reconciled == 1
        assert not (config.incoming_dir / tmp_filename).exists()
        segment = repo.find_segment_by_file_name(db_session, tmp_filename[: -len(".tmp")])
        assert segment is not None
        assert segment["status"] == "FAILED"

    def test_reconciles_orphan_ready_file(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        session_id = SESSION_ID_A
        repo.create_session(
            db_session, session_id=session_id, capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 0),
        )
        db_session.commit()

        ready_filename = build_pcap_filename(
            session_id=session_id, interface="eth0",
            window_start=_utc(2026, 7, 15, 10, 0, 0), window_end=_utc(2026, 7, 15, 10, 0, 10),
            tmp=False,
        )
        (config.ready_dir / ready_filename).write_bytes(b"ready-bytes")

        reconciled = reconcile_orphan_ready_files(db_session, config)

        assert reconciled == 1
        segment = repo.find_segment_by_file_name(db_session, ready_filename)
        assert segment is not None
        assert segment["status"] == "READY"

    def test_reconciles_orphan_failed_file(self, db_session, tmp_path) -> None:
        """failed/에는 파일이 있지만 DB에 Segment row가 없는 경우를 복구한다 (리뷰 항목 7).

        파일을 failed/로 옮긴 뒤 DB insert가 실패했거나 그 사이 프로세스가 죽은 상황을 흉내낸다.
        """
        config = _make_config(tmp_path)
        session_id = SESSION_ID_A
        repo.create_session(
            db_session, session_id=session_id, capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 0),
        )
        db_session.commit()

        failed_filename = build_pcap_filename(
            session_id=session_id, interface="eth0",
            window_start=_utc(2026, 7, 15, 10, 0, 0), window_end=_utc(2026, 7, 15, 10, 0, 10),
            tmp=False,
        )
        (config.failed_dir / failed_filename).write_bytes(b"failed-bytes")

        reconciled = reconcile_orphan_failed_files(db_session, config)

        assert reconciled == 1
        segment = repo.find_segment_by_file_name(db_session, failed_filename)
        assert segment is not None
        assert segment["status"] == "FAILED"

    def test_orphan_failed_reconcile_is_idempotent(self, db_session, tmp_path) -> None:
        """이미 Segment row가 있는 failed 파일은 다시 처리하지 않는다 (중복 방지)."""
        config = _make_config(tmp_path)
        session_pk = repo.create_session(
            db_session, session_id=SESSION_ID_A, capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 10, 0, 0),
        )
        repo.insert_failed_segment(
            db_session, capture_session_pk=session_pk, file_name="already_recorded.pcap",
            capture_interface="eth0",
            window_start=_utc(2026, 7, 15, 10, 0, 0), window_end=_utc(2026, 7, 15, 10, 0, 10),
            error_code=repo.PARTIAL_CAPTURE, error_message="original failure",
        )
        db_session.commit()
        (config.failed_dir / "already_recorded.pcap").write_bytes(b"failed-bytes")

        reconciled = reconcile_orphan_failed_files(db_session, config)

        assert reconciled == 0


class TestStaleRunningSessionRecovery:
    """리뷰 항목 5: 비정상 종료로 남아있는 RUNNING Session을 재시작 시 FAILED로 마감."""

    def test_closes_stale_running_session_as_failed(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        stale_session_pk = repo.create_session(
            db_session, session_id=SESSION_ID_A, capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 9, 0, 0),
        )
        db_session.commit()

        reconciled = reconcile_stale_running_sessions(
            db_session, config, _utc(2026, 7, 15, 10, 0, 0)
        )

        assert reconciled == 1
        row = db_session.execute(
            text("SELECT status, ended_at FROM packet_capture_sessions WHERE id = :id"),
            {"id": stale_session_pk},
        ).mappings().first()
        assert row["status"] == "FAILED"
        assert row["ended_at"] == "2026-07-15T10:00:00Z"

    def test_does_not_touch_already_terminal_sessions(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        completed_session_pk = repo.create_session(
            db_session, session_id=SESSION_ID_A, capture_interface="eth0",
            started_at=_utc(2026, 7, 15, 9, 0, 0),
        )
        repo.close_session(db_session, completed_session_pk, _utc(2026, 7, 15, 9, 30, 0), "COMPLETED")
        db_session.commit()

        reconciled = reconcile_stale_running_sessions(
            db_session, config, _utc(2026, 7, 15, 10, 0, 0)
        )

        assert reconciled == 0
        row = db_session.execute(
            text("SELECT status FROM packet_capture_sessions WHERE id = :id"),
            {"id": completed_session_pk},
        ).mappings().first()
        assert row["status"] == "COMPLETED"

    def test_only_affects_matching_capture_interface(self, db_session, tmp_path) -> None:
        config = _make_config(tmp_path)
        other_interface_session_pk = repo.create_session(
            db_session, session_id=SESSION_ID_A, capture_interface="eth1",
            started_at=_utc(2026, 7, 15, 9, 0, 0),
        )
        db_session.commit()

        reconciled = reconcile_stale_running_sessions(
            db_session, config, _utc(2026, 7, 15, 10, 0, 0)
        )  # config.capture_interface == "eth0"

        assert reconciled == 0
        row = db_session.execute(
            text("SELECT status FROM packet_capture_sessions WHERE id = :id"),
            {"id": other_interface_session_pk},
        ).mappings().first()
        assert row["status"] == "RUNNING"