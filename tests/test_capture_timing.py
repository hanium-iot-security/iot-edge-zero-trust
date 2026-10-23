"""Capture diagnostics observe delays without changing quality or persistence."""

from datetime import datetime, timedelta, timezone
import io
import json
import logging
from pathlib import Path
from types import SimpleNamespace
import subprocess
from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from db.migration_runner import apply_migrations
from edge.packet import capture_runtime, run_packet_capture
from edge.packet import capture_session_repository as repo
from edge.packet.capture_runtime import CaptureOutcome, CaptureRuntimeConfig, execute_capture_window


BASE = datetime(2026, 10, 5, tzinfo=timezone.utc)
SESSION_ID = "550e8400-e29b-41d4-a716-446655440000"


class Clock:
    def __init__(self):
        self.elapsed = 0.0

    def advance(self, seconds):
        self.elapsed += seconds

    def monotonic(self):
        return self.elapsed

    def now(self):
        return BASE + timedelta(seconds=self.elapsed)


class Capture:
    def __init__(self, clock, *, drain_seconds=0, report_process_timing=True):
        self.clock = clock
        self.drain_seconds = drain_seconds
        self.report_process_timing = report_process_timing
        self.calls = 0

    def capture_window(self, *, interface, output_path, window_seconds):
        self.calls += 1
        output_path.write_bytes(Path("tests/fixtures/packet/pcap/empty_window.pcap").read_bytes())
        self.clock.advance(window_seconds)
        exited = self.clock.now()
        self.clock.advance(self.drain_seconds)
        diagnostics = (
            {"process_wait_completed_at": exited,
             "phase_timings_seconds": {"capture_wait_seconds": window_seconds,
                                       "stderr_drain_seconds": self.drain_seconds}}
            if self.report_process_timing else {}
        )
        return CaptureOutcome(True, 0, stop_requested_at=exited, **diagnostics)


def config(tmp_path):
    value = CaptureRuntimeConfig("eth0", 10, tmp_path / "incoming", tmp_path / "ready", tmp_path / "failed")
    value.ensure_directories()
    return value


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "capture.db"
    apply_migrations(path)
    engine = create_engine(f"sqlite:///{path}")
    try:
        with Session(engine) as session:
            yield session
    finally:
        engine.dispose()


@pytest.mark.parametrize("window_seconds", [10.0, 0.1])
def test_process_setup_consumes_remaining_window_budget(monkeypatch, tmp_path, window_seconds):
    clock = Clock()
    child = Mock(stderr=io.BytesIO(b""))
    child.poll.return_value = None
    waits = []

    def wait(*, timeout):
        waits.append(timeout)
        if len(waits) == 1:
            clock.advance(timeout)
            raise subprocess.TimeoutExpired("tcpdump", timeout)
        clock.advance(0.4)
        return 0

    def spawn(*args, **kwargs):
        clock.advance(0.2)
        return child

    class Drain:
        def __init__(self, _stream):
            self.thread = SimpleNamespace(start=lambda: clock.advance(0.1))

        def finish(self):
            clock.advance(0.3)
            return {"stderr_complete": True}

    child.wait.side_effect = wait
    monkeypatch.setattr(capture_runtime.subprocess, "Popen", spawn)
    monkeypatch.setattr(capture_runtime, "_StderrDrain", Drain)
    outcome = capture_runtime.TcpdumpCaptureProcess(monotonic=clock.monotonic, clock=clock.now).capture_window(
        interface="eth0", output_path=tmp_path / "capture.pcap", window_seconds=window_seconds)

    remaining = max(0, window_seconds - 0.3)
    stopped = max(window_seconds, 0.3)
    assert waits == pytest.approx([remaining, 5])
    assert outcome.completed_full_window and outcome.terminated_cleanly
    assert outcome.phase_timings_seconds == pytest.approx({
        "spawn_seconds": 0.2, "stderr_setup_seconds": 0.1, "capture_wait_seconds": remaining,
        "termination_wait_seconds": 0.4, "stderr_drain_seconds": 0.3})
    assert outcome.stop_requested_at == BASE + timedelta(seconds=stopped)
    assert outcome.process_wait_completed_at == BASE + timedelta(seconds=stopped + 0.4)
    assert clock.now() == BASE + timedelta(seconds=stopped + 0.7)


@pytest.mark.parametrize("report_process_timing", [True, False])
def test_file_phases_preserve_wrapper_exit_fallback_and_single_sidecar_sync(
    monkeypatch, tmp_path, report_process_timing
):
    clock = Clock()
    value = config(tmp_path)
    validate, fsync, publish = capture_runtime._pcap_file_error, capture_runtime.os.fsync, capture_runtime._atomic_rename_same_filesystem
    synced = []

    def slow_validation(path):
        result = validate(path)
        clock.advance(0.1)
        return result

    def slow_sync(fd):
        synced.append(fd)
        fsync(fd)
        clock.advance(0.2)

    def slow_publication(source, target):
        result = publish(source, target)
        clock.advance(0.4)
        return result

    monkeypatch.setattr(capture_runtime, "_pcap_file_error", slow_validation)
    monkeypatch.setattr(capture_runtime.os, "fsync", slow_sync)
    monkeypatch.setattr(capture_runtime, "_atomic_rename_same_filesystem", slow_publication)
    result = execute_capture_window(Capture(clock, drain_seconds=0.3, report_process_timing=report_process_timing), value,
                                    session_id=SESSION_ID, window_start=BASE, window_end=BASE + timedelta(seconds=10),
                                    capture_started_at=BASE, clock=clock.now, monotonic=clock.monotonic)

    assert result.success
    assert result.capture_process_exited_at == BASE + timedelta(seconds=10.3)
    assert result.process_wait_completed_at == (BASE + timedelta(seconds=10) if report_process_timing else None)
    assert result.phase_timings_seconds["pcap_validation_seconds"] == pytest.approx(0.1)
    assert result.phase_timings_seconds["sidecar_persist_seconds"] == pytest.approx(0.2)
    assert result.phase_timings_seconds["pcap_publish_seconds"] == pytest.approx(0.4)
    assert result.captured_duration_seconds == 10 and result.start_delay_seconds == 0
    assert len(synced) == 1 and len(list(value.ready_dir.iterdir())) == 2
    sidecar = json.loads(result.diagnostics_path.read_text())
    assert sidecar["schema_version"] == "packet-capture-diagnostics-v1"
    assert "phase_timings_seconds" not in sidecar and "process_wait_completed_at" not in sidecar


def test_ready_log_reports_separate_insert_and_committed_timings(db, tmp_path, monkeypatch, caplog):
    clock = Clock()
    value = config(tmp_path)
    source_pk, source_id, first = run_packet_capture.start_new_session(db, value, clock.now(), clock=clock.now)
    insert, commit = repo.insert_ready_segment, db.commit

    def slow_insert(*args, **kwargs):
        result = insert(*args, **kwargs)
        clock.advance(0.3)
        return result

    def slow_commit():
        commit()
        clock.advance(0.4)

    monkeypatch.setattr(repo, "insert_ready_segment", slow_insert)
    monkeypatch.setattr(db, "commit", slow_commit)
    caplog.set_level(logging.INFO, logger=run_packet_capture.__name__)
    assert run_packet_capture.run_capture_loop(db, Capture(clock), value, session_pk=source_pk, session_id=source_id,
                                               first_window_start=first, shutdown=run_packet_capture.GracefulShutdown(),
                                               max_windows=1, clock=clock.now, sleep=clock.advance,
                                               monotonic=clock.monotonic) == 1
    logs = [record.getMessage() for record in caplog.records if record.getMessage().startswith("READY segment 생성:")]
    assert len(logs) == 1
    timing = json.loads(logs[0].split(" timing=", 1)[1])
    assert timing["timing_seconds"]["db_insert_seconds"] == pytest.approx(0.3)
    assert timing["timing_seconds"]["db_commit_seconds"] == pytest.approx(0.4)
    assert timing["process_wait_completed_at"] == (BASE + timedelta(seconds=10)).isoformat()
    assert db.execute(text("SELECT COUNT(*) FROM packet_capture_segments WHERE status='READY'")).scalar() == 1


def test_commit_failure_has_no_ready_completion_log_and_preserves_pcap(db, tmp_path, monkeypatch, caplog):
    clock = Clock()
    value = config(tmp_path)
    source_pk, source_id, first = run_packet_capture.start_new_session(db, value, clock.now(), clock=clock.now)
    commit = db.commit
    calls = 0

    def fail_first_commit():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("capture commit failed")
        commit()

    monkeypatch.setattr(db, "commit", fail_first_commit)
    caplog.set_level(logging.INFO, logger=run_packet_capture.__name__)
    with pytest.raises(RuntimeError, match="capture commit failed"):
        run_packet_capture.run_capture_loop(db, Capture(clock), value, session_pk=source_pk, session_id=source_id,
                                            first_window_start=first, shutdown=run_packet_capture.GracefulShutdown(),
                                            max_windows=1, clock=clock.now, sleep=clock.advance, monotonic=clock.monotonic)
    assert not any(record.getMessage().startswith("READY segment 생성:") for record in caplog.records)
    assert db.execute(text("SELECT COUNT(*) FROM packet_capture_segments")).scalar() == 0
    assert db.execute(text("SELECT status FROM packet_capture_sessions WHERE id=:id"), {"id": source_pk}).scalar() == "FAILED"
    assert len(list(value.ready_dir.glob("*.pcap"))) == 1


def test_expired_warning_carries_previous_committed_window_without_hiding_loss(db, tmp_path, monkeypatch, caplog):
    clock = Clock()
    value = config(tmp_path)
    source_pk, source_id, first = run_packet_capture.start_new_session(db, value, clock.now(), clock=clock.now)
    insert = repo.insert_ready_segment
    calls = 0

    def slow_first_insert(*args, **kwargs):
        nonlocal calls
        result = insert(*args, **kwargs)
        calls += 1
        if calls == 1:
            clock.advance(11.2)
        return result

    monkeypatch.setattr(repo, "insert_ready_segment", slow_first_insert)
    caplog.set_level(logging.INFO, logger=run_packet_capture.__name__)
    process = Capture(clock)
    assert run_packet_capture.run_capture_loop(db, process, value, session_pk=source_pk, session_id=source_id,
                                               first_window_start=first, shutdown=run_packet_capture.GracefulShutdown(),
                                               max_windows=2, clock=clock.now, sleep=clock.advance,
                                               monotonic=clock.monotonic) == 2
    logs = [record.getMessage() for record in caplog.records if record.getMessage().startswith("LATE_CAPTURE segment 생성:")]
    assert len(logs) == 1
    previous = json.loads(logs[0].split(" previous_window_timing=", 1)[1])
    assert previous["session_id"] == source_id and previous["window_end"] == "2026-10-05T00:00:10Z"
    assert previous["timing_seconds"]["db_insert_seconds"] == pytest.approx(11.2)
    failed = db.execute(text("SELECT error_code,file_name,start_delay_seconds FROM packet_capture_segments WHERE status='FAILED'")).mappings().one()
    assert failed["error_code"] == "LATE_CAPTURE" and failed["file_name"] is None
    assert failed["start_delay_seconds"] == pytest.approx(11.2) and process.calls == 2
