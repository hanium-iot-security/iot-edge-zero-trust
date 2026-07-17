"""Packet Capture Session/Segment Lifecycle 테스트 (실제 SQLite DB 사용).

- capture_session_repository.py: packet_capture_sessions/segments DB 읽기/쓰기
- run_packet_capture.py: Session 생성, Gap 기록, 캡처 루프, Crash Recovery 전체 흐름
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from backend.app.config import settings
from backend.app.database import SessionLocal
from db.migration_runner import apply_migrations
from edge.packet import capture_session_repository as repo
from edge.packet.capture_runtime import CaptureOutcome, CaptureRuntimeConfig
from edge.packet.pcap_naming import build_pcap_filename, format_utc_iso
from edge.packet.run_packet_capture import (
    GracefulShutdown,
    reconcile_leftover_tmp_files,
    reconcile_orphan_ready_files,
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
            clock=lambda: _utc(2026, 7, 15, 10, 0, 30),  # 이미 window_start를 지난 척
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
            clock=lambda: _utc(2026, 7, 15, 10, 0, 30),
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