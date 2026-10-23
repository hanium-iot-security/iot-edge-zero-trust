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
    sidecar_phases = {key: duration for key, duration in result.phase_timings_seconds.items()
                      if key.startswith("sidecar_") and key != "sidecar_persist_seconds"}
    assert len(sidecar_phases) == 7
    assert sidecar_phases["sidecar_fsync_seconds"] == pytest.approx(0.2)
    assert sum(sidecar_phases.values()) == pytest.approx(result.phase_timings_seconds["sidecar_persist_seconds"])
    assert result.phase_timings_seconds["pcap_publish_seconds"] == pytest.approx(0.4)
    assert result.captured_duration_seconds == 10 and result.start_delay_seconds == 0
    assert len(synced) == 1 and len(list(value.ready_dir.iterdir())) == 2
    sidecar = json.loads(result.diagnostics_path.read_text())
    assert sidecar["schema_version"] == "packet-capture-diagnostics-v1"
    assert "phase_timings_seconds" not in sidecar and "process_wait_completed_at" not in sidecar


def test_sidecar_phases_split_delays_without_changing_bytes_or_durability_order(tmp_path, monkeypatch):
    baseline_clock = Clock()
    baseline_config = config(tmp_path / "baseline")
    baseline = execute_capture_window(
        Capture(baseline_clock), baseline_config, session_id=SESSION_ID,
        window_start=BASE, window_end=BASE + timedelta(seconds=10),
        capture_started_at=BASE, clock=baseline_clock.now, monotonic=baseline_clock.monotonic)
    baseline_bytes = baseline.diagnostics_path.read_bytes()

    clock = Clock()
    value = config(tmp_path / "measured")
    events = []
    open_path, with_suffix = Path.open, Path.with_suffix
    fsync, rename = capture_runtime.os.fsync, capture_runtime.os.replace

    class TimedHandle:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            self.handle.__enter__()
            return self

        def write(self, text):
            result = self.handle.write(text)
            if text == "\n":
                events.append("write")
                clock.advance(0.3)
            return result

        def flush(self):
            self.handle.flush()
            events.append("flush")
            clock.advance(0.4)

        def fileno(self):
            return self.handle.fileno()

        def __exit__(self, *args):
            result = self.handle.__exit__(*args)
            events.append("close")
            clock.advance(0.6)
            return result

    def slow_prepare(path, suffix):
        result = with_suffix(path, suffix)
        if path.name.endswith(".capture.json"):
            events.append("prepare")
            clock.advance(0.1)
        return result

    def slow_open(path, *args, **kwargs):
        handle = open_path(path, *args, **kwargs)
        if not path.name.endswith(".capture.json.tmp"):
            return handle
        events.append("open")
        clock.advance(0.2)
        return TimedHandle(handle)

    def slow_fsync(fd):
        fsync(fd)
        events.append("fsync")
        clock.advance(0.5)

    def slow_rename(source, destination):
        result = rename(source, destination)
        if Path(source).name.endswith(".capture.json.tmp"):
            events.append("sidecar_publish")
            clock.advance(0.7)
        elif Path(source).name.endswith(".pcap.tmp"):
            events.append("pcap_publish")
        return result

    monkeypatch.setattr(Path, "with_suffix", slow_prepare)
    monkeypatch.setattr(Path, "open", slow_open)
    monkeypatch.setattr(capture_runtime.os, "fsync", slow_fsync)
    monkeypatch.setattr(capture_runtime.os, "replace", slow_rename)
    result = execute_capture_window(
        Capture(clock), value, session_id=SESSION_ID,
        window_start=BASE, window_end=BASE + timedelta(seconds=10),
        capture_started_at=BASE, clock=clock.now, monotonic=clock.monotonic)

    assert result.success and result.captured_duration_seconds == 10
    expected = {
        "sidecar_prepare_seconds": 0.1, "sidecar_open_seconds": 0.2,
        "sidecar_serialize_write_seconds": 0.3, "sidecar_flush_seconds": 0.4,
        "sidecar_fsync_seconds": 0.5, "sidecar_close_seconds": 0.6,
        "sidecar_rename_seconds": 0.7,
    }
    assert {key: result.phase_timings_seconds[key] for key in expected} == pytest.approx(expected)
    assert result.phase_timings_seconds["sidecar_persist_seconds"] == pytest.approx(sum(expected.values()))
    assert events == ["prepare", "open", "write", "flush", "fsync", "close", "sidecar_publish", "pcap_publish"]
    assert result.diagnostics_path.read_bytes() == baseline_bytes
    metadata = json.loads(baseline_bytes)
    assert metadata["schema_version"] == "packet-capture-diagnostics-v1"
    assert not any(key.startswith("sidecar_") or key == "phase_timings_seconds" for key in metadata)
    assert baseline_bytes.endswith(b"\n") and not baseline_bytes.endswith(b"\n\n")
    assert len(list(value.ready_dir.iterdir())) == 2


@pytest.mark.parametrize("failure_stage", ["fsync", "sidecar_publish"])
def test_sidecar_phase_failure_never_reports_completion_or_publishes_ready(
    db, tmp_path, monkeypatch, caplog, failure_stage,
):
    clock = Clock()
    value = config(tmp_path)
    pk, session_id, first = run_packet_capture.start_new_session(db, value, clock.now(), clock=clock.now)
    fsync, rename = capture_runtime.os.fsync, capture_runtime.os.replace
    sync_calls = []

    def fail_sync(fd):
        sync_calls.append(fd)
        if failure_stage == "fsync":
            raise OSError("fixture sidecar fsync failed")
        return fsync(fd)

    def fail_publish(source, destination):
        if Path(source).name.endswith(".capture.json.tmp"):
            raise OSError("fixture sidecar rename failed")
        return rename(source, destination)

    monkeypatch.setattr(capture_runtime.os, "fsync", fail_sync)
    monkeypatch.setattr(capture_runtime.os, "replace", fail_publish)
    caplog.set_level(logging.INFO, logger=run_packet_capture.__name__)
    with pytest.raises(OSError, match="fixture sidecar"):
        run_packet_capture.run_capture_loop(
            db, Capture(clock), value, session_pk=pk, session_id=session_id,
            first_window_start=first, shutdown=run_packet_capture.GracefulShutdown(),
            max_windows=1, clock=clock.now, sleep=clock.advance, monotonic=clock.monotonic)

    assert len(sync_calls) == 1
    assert not list(value.ready_dir.glob("*.pcap"))
    assert not list(value.ready_dir.glob("*.capture.json"))
    assert len(list(value.incoming_dir.glob("*.pcap.tmp"))) == 1
    assert db.execute(text("SELECT COUNT(*) FROM packet_capture_segments")).scalar() == 0
    assert db.execute(text("SELECT status FROM packet_capture_sessions WHERE id=:pk"), {"pk": pk}).scalar() == "FAILED"
    assert not any(record.getMessage().startswith(("READY segment 생성:", "FAILED segment 생성:"))
                   for record in caplog.records)


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
    assert "sidecar_rename_seconds" in timing["timing_seconds"]
    assert sum(duration for key, duration in timing["timing_seconds"].items()
               if key.startswith("sidecar_") and key != "sidecar_persist_seconds") == pytest.approx(
                   timing["timing_seconds"]["sidecar_persist_seconds"])
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
