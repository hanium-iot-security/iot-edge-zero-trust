"""Capture safety regressions using local fixtures; never starts tcpdump."""

from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import threading
import time
from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import apply_migrations
from edge.packet import capture_runtime, run_packet_capture
from edge.packet.capture_lock import capture_lock_paths, capture_resource_locks
from edge.packet.capture_runtime import CaptureOutcome, CaptureRuntimeConfig, execute_capture_window
from edge.packet.pcap_naming import build_pcap_filename
from edge.runtime_lock import RuntimeLockError


SESSION_ID = "550e8400-e29b-41d4-a716-446655440000"
START = datetime(2026, 10, 1, 0, 0, tzinfo=timezone.utc)


def _config(path: Path) -> CaptureRuntimeConfig:
    config = CaptureRuntimeConfig("eth0", 10, path / "incoming", path / "ready", path / "failed")
    config.ensure_directories()
    return config


class _PcapProcess:
    def __init__(self, outcome: CaptureOutcome):
        self.outcome = outcome

    def capture_window(self, *, interface, output_path, window_seconds):
        output_path.write_bytes(Path("tests/fixtures/packet/pcap/empty_window.pcap").read_bytes())
        return self.outcome


@pytest.mark.parametrize("exit_code", [1, 2, -9, None])
def test_window_timeout_and_valid_pcap_do_not_hide_error_exit(tmp_path, exit_code):
    config = _config(tmp_path)
    result = execute_capture_window(
        _PcapProcess(CaptureOutcome(True, exit_code)), config,
        session_id=SESSION_ID, window_start=START, window_end=START + timedelta(seconds=10),
    )
    assert result.success is False
    assert result.error_code == "PARTIAL_CAPTURE"
    assert result.final_path.parent == config.failed_dir
    assert not list(config.ready_dir.glob("*.pcap"))


def test_duplicate_cli_is_rejected_before_live_session_or_tmp_cleanup(tmp_path, monkeypatch):
    database = tmp_path / "capture.db"
    apply_migrations(db_path=database, migrations_dir="db/migrations")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    factory = sessionmaker(bind=engine)
    config = _config(tmp_path)
    monkeypatch.setattr(run_packet_capture, "SessionLocal", factory)
    monkeypatch.setattr(run_packet_capture.CaptureRuntimeConfig, "from_env", lambda: config)
    monkeypatch.setattr(run_packet_capture.GracefulShutdown, "install", lambda self: None)
    monkeypatch.setattr(sys, "argv", ["run_packet_capture", "--windows", "1"])
    calls = []

    def hold_first_capture(db, process, config, **kwargs):
        calls.append(kwargs["session_id"])
        if len(calls) > 1:
            return 0
        start = kwargs["first_window_start"]
        live_file = config.incoming_dir / build_pcap_filename(
            session_id=kwargs["session_id"], interface="eth0", window_start=start,
            window_end=start + timedelta(seconds=10), tmp=True,
        )
        live_file.write_bytes(b"still being captured")
        with pytest.raises(RuntimeLockError):
            run_packet_capture.main()
        assert live_file.read_bytes() == b"still being captured"
        assert db.execute(text("SELECT status FROM packet_capture_sessions")).scalars().all() == ["RUNNING"]
        assert db.execute(text("SELECT COUNT(*) FROM packet_capture_segments")).scalar() == 0
        return 0

    monkeypatch.setattr(run_packet_capture, "run_capture_loop", hold_first_capture)
    try:
        run_packet_capture.main()
        assert len(calls) == 1
    finally:
        engine.dispose()


def test_stderr_is_drained_without_pipe_deadlock_and_retained_with_a_bound(tmp_path, monkeypatch):
    real_popen = subprocess.Popen
    script = (
        "import sys; sys.stderr.buffer.write(b'x'*2000000+b'\\n'); "
        "sys.stderr.write('7 packets captured\\n9 packets received by filter\\n2 packets dropped by kernel\\n'); "
        "sys.stderr.flush(); sys.exit(2)"
    )
    monkeypatch.setattr(capture_runtime.subprocess, "Popen", lambda args, **kwargs: real_popen(
        [sys.executable, "-u", "-c", script], **kwargs,
    ))
    result = capture_runtime.TcpdumpCaptureProcess().capture_window(
        interface="fixture", output_path=tmp_path / "not-created.pcap", window_seconds=5,
    )
    assert result.completed_full_window is False
    assert result.exit_code == 2
    assert result.terminated_cleanly is False
    assert len(result.stderr_tail.encode("utf-8")) <= capture_runtime.STDERR_LIMIT_BYTES
    assert result.stderr_truncated is True
    assert result.stderr_complete is True
    assert (result.packets_captured, result.packets_received, result.packets_dropped) == (7, 9, 2)
    assert not any(thread.name == "packet-capture-stderr" for thread in threading.enumerate())


def test_missing_statistics_remain_unknown_in_diagnostics(tmp_path, monkeypatch):
    process = Mock()
    process.stderr = io.BytesIO(b"tcpdump: fixture diagnostic\n")
    process.wait.side_effect = [subprocess.TimeoutExpired("tcpdump", 10), 0]
    process.poll.return_value = None
    monkeypatch.setattr(capture_runtime.subprocess, "Popen", Mock(return_value=process))
    result = capture_runtime.TcpdumpCaptureProcess().capture_window(
        interface="fixture", output_path=tmp_path / "not-created.pcap", window_seconds=10,
    )
    assert result.terminated_cleanly is True
    assert result.packets_captured is None
    assert result.packets_received is None
    assert result.packets_dropped is None
    assert result.stderr_complete is True


def test_observed_packet_loss_is_failed_and_sidecar_preserves_quality(tmp_path):
    config = _config(tmp_path)
    outcome = CaptureOutcome(True, 0, packets_captured=2, packets_received=5, packets_dropped=3)
    result = execute_capture_window(
        _PcapProcess(outcome), config, session_id=SESSION_ID,
        window_start=START, window_end=START + timedelta(seconds=10),
    )
    assert result.success is False
    assert result.error_code == "PARTIAL_CAPTURE"
    metadata = json.loads(result.diagnostics_path.read_text(encoding="utf-8"))
    assert metadata["session_id"] == SESSION_ID
    assert metadata["window_start"] == START.isoformat()
    assert metadata["pcap_file_name"] == result.file_name
    assert metadata["packets_dropped"] == 3
    assert metadata["drop_status"] == "observed_loss"
    assert result.diagnostics_path.name.endswith(".capture.json")
    assert not list(config.ready_dir.glob("*.pcap"))


@pytest.mark.parametrize("exit_code", [0, -15, 1, -9])
def test_planned_stop_accepts_only_success_or_sigterm(tmp_path, monkeypatch, exit_code):
    process = Mock()
    process.stderr = io.BytesIO(b"1 packet captured\n1 packet received by filter\n0 packets dropped by kernel\n")
    process.wait.side_effect = [subprocess.TimeoutExpired("tcpdump", 10), exit_code]
    process.poll.return_value = None
    monkeypatch.setattr(capture_runtime.subprocess, "Popen", Mock(return_value=process))
    result = capture_runtime.TcpdumpCaptureProcess().capture_window(
        interface="fixture", output_path=tmp_path / "unused", window_seconds=10,
    )
    assert result.completed_full_window is True
    assert result.terminated_cleanly is (exit_code in (0, -15))
    assert (result.packets_captured, result.packets_received, result.packets_dropped) == (1, 1, 0)


def test_exit_racing_with_deadline_is_not_a_wrapper_stop(tmp_path, monkeypatch):
    process = Mock()
    process.stderr = io.BytesIO(b"")
    process.wait.side_effect = subprocess.TimeoutExpired("tcpdump", 10)
    process.poll.return_value = 0
    monkeypatch.setattr(capture_runtime.subprocess, "Popen", Mock(return_value=process))
    result = capture_runtime.TcpdumpCaptureProcess().capture_window(
        interface="fixture", output_path=tmp_path / "unused", window_seconds=10,
    )
    assert result.completed_full_window is False
    assert result.terminated_cleanly is False
    assert result.stop_requested_at is None
    process.terminate.assert_not_called()


def test_stderr_read_failure_is_not_a_clean_capture(tmp_path, monkeypatch):
    class BrokenStream(io.BytesIO):
        def read(self, count):
            raise OSError("fixture pipe failure")

    process = Mock()
    process.stderr = BrokenStream()
    process.wait.side_effect = [subprocess.TimeoutExpired("tcpdump", 10), 0]
    process.poll.return_value = None
    monkeypatch.setattr(capture_runtime.subprocess, "Popen", Mock(return_value=process))
    result = capture_runtime.TcpdumpCaptureProcess().capture_window(
        interface="fixture", output_path=tmp_path / "unused", window_seconds=10,
    )
    assert result.terminated_cleanly is False
    assert result.stderr_complete is False
    assert result.stderr_error == "fixture pipe failure"
    assert not any(thread.name == "packet-capture-stderr" for thread in threading.enumerate())


def test_stderr_eof_timeout_fails_without_waiting_indefinitely(tmp_path, monkeypatch):
    release = threading.Event()

    class HeldOpenStream(io.BytesIO):
        def read(self, count):
            release.wait(timeout=5)
            return b""

    process = Mock()
    process.stderr = HeldOpenStream()
    process.wait.return_value = 0
    monkeypatch.setattr(capture_runtime.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(capture_runtime, "STDERR_DRAIN_TIMEOUT_SECONDS", 0.02)
    try:
        with pytest.raises(capture_runtime.CaptureProcessError, match="stderr pipe did not close"):
            capture_runtime.TcpdumpCaptureProcess().capture_window(
                interface="fixture", output_path=tmp_path / "unused", window_seconds=10,
            )
    finally:
        release.set()
        for thread in threading.enumerate():
            if thread.name == "packet-capture-stderr":
                thread.join(timeout=2)
        process.stderr.close()
    assert not any(thread.name == "packet-capture-stderr" for thread in threading.enumerate())


def test_unknown_drop_counts_do_not_reject_otherwise_valid_capture(tmp_path):
    config = _config(tmp_path)
    result = execute_capture_window(
        _PcapProcess(CaptureOutcome(True, 0)), config, session_id=SESSION_ID,
        window_start=START, window_end=START + timedelta(seconds=10),
    )
    assert result.success is True
    metadata = json.loads(result.diagnostics_path.read_text(encoding="utf-8"))
    assert metadata["drop_status"] == "unknown"
    assert metadata["packets_captured"] is None
    assert metadata["packets_received"] is None
    assert metadata["packets_dropped"] is None


def test_diagnostic_write_failure_never_publishes_ready_pcap(tmp_path, monkeypatch):
    config = _config(tmp_path)

    def fail_dump(*args, **kwargs):
        raise OSError("fixture full disk")

    monkeypatch.setattr(capture_runtime.json, "dump", fail_dump)
    with pytest.raises(OSError, match="full disk"):
        execute_capture_window(
            _PcapProcess(CaptureOutcome(True, 0)), config, session_id=SESSION_ID,
            window_start=START, window_end=START + timedelta(seconds=10),
        )
    assert not list(config.ready_dir.glob("*.pcap"))
    assert len(list(config.incoming_dir.glob("*.pcap.tmp"))) == 1


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_failed_pcap_publication_retracts_success_diagnostics_on_failure_or_restart(
    tmp_path, monkeypatch, cleanup_fails,
):
    config = _config(tmp_path)
    database = tmp_path / "capture.db"
    apply_migrations(db_path=database, migrations_dir="db/migrations")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    factory = sessionmaker(bind=engine)
    now = START
    failures = {"cleanup": cleanup_fails}
    original_replace = os.replace
    original_unlink = Path.unlink

    def fail_publication(source, destination):
        if Path(source).name.endswith(".pcap.tmp") and Path(destination).parent == config.ready_dir:
            # Capture evidence must already be durable before PCAP publication.
            sidecar = config.ready_dir / f"{Path(destination).name}.capture.json"
            assert json.loads(sidecar.read_text(encoding="utf-8"))["success"] is True
            raise PermissionError("fixture PCAP publication failure")
        return original_replace(source, destination)

    def controlled_unlink(path, *args, **kwargs):
        if failures["cleanup"] and path.name.endswith(".capture.json"):
            raise PermissionError("fixture diagnostic cleanup failure")
        return original_unlink(path, *args, **kwargs)

    class ClockedProcess(_PcapProcess):
        def capture_window(self, **kwargs):
            nonlocal now
            super().capture_window(**kwargs)
            now += timedelta(seconds=kwargs["window_seconds"])
            return CaptureOutcome(True, 0, stop_requested_at=now)

    def sleep(seconds):
        nonlocal now
        now += timedelta(seconds=seconds)

    monkeypatch.setattr(capture_runtime.os, "replace", fail_publication)
    monkeypatch.setattr(Path, "unlink", controlled_unlink)
    try:
        with factory() as db:
            pk, session_id, start = run_packet_capture.start_new_session(db, config, now)
            exception = capture_runtime.CaptureProcessError if cleanup_fails else PermissionError
            with pytest.raises(exception, match="PCAP publication fail"):
                run_packet_capture.run_capture_loop(
                    db, ClockedProcess(CaptureOutcome(True, 0)), config,
                    session_pk=pk, session_id=session_id, first_window_start=start,
                    shutdown=run_packet_capture.GracefulShutdown(), max_windows=1,
                    clock=lambda: now, sleep=sleep,
                )
            assert db.execute(text("SELECT status FROM packet_capture_sessions")).scalar_one() == "FAILED"
            assert db.execute(text("SELECT COUNT(*) FROM packet_capture_segments")).scalar_one() == 0
            assert not list(config.ready_dir.glob("*.pcap"))
            assert len(list(config.ready_dir.glob("*.capture.json"))) == int(cleanup_fails)
            assert len(list(config.incoming_dir.glob("*.pcap.tmp"))) == 1
            if cleanup_fails:
                # The same persisted files can remain after a wrapper crash.
                # Startup must fail closed while diagnostic cleanup still fails.
                with pytest.raises(PermissionError, match="diagnostic cleanup failure"):
                    run_packet_capture.reconcile_leftover_tmp_files(db, config)
                assert len(list(config.incoming_dir.glob("*.pcap.tmp"))) == 1
                assert not list(config.failed_dir.glob("*.pcap"))
                assert db.execute(text("SELECT COUNT(*) FROM packet_capture_segments")).scalar_one() == 0
                failures["cleanup"] = False
            run_packet_capture.reconcile_leftover_tmp_files(db, config)
            run_packet_capture.reconcile_orphan_ready_files(db, config)
            run_packet_capture.reconcile_orphan_failed_files(db, config)
            assert not list(config.ready_dir.glob("*.capture.json"))
            assert not list(config.incoming_dir.glob("*.pcap.tmp"))
            assert len(list(config.failed_dir.glob("*.pcap"))) == 1
            assert db.execute(text("SELECT status FROM packet_capture_segments")).scalar_one() == "FAILED"
    finally:
        failures["cleanup"] = False
        engine.dispose()


def test_clean_exit_without_file_is_failed_with_diagnostics(tmp_path):
    class NoFileProcess:
        def capture_window(self, **kwargs):
            return CaptureOutcome(True, 0)

    config = _config(tmp_path)
    result = execute_capture_window(
        NoFileProcess(), config, session_id=SESSION_ID,
        window_start=START, window_end=START + timedelta(seconds=10),
    )
    assert result.success is False
    assert result.error_code == "PCAP_FILE_MISSING"
    assert result.file_name is None
    assert result.diagnostics_path.is_file()


@pytest.mark.parametrize("shared", ["db", "incoming", "ready", "failed"])
def test_any_shared_resource_rejects_a_second_runtime(tmp_path, shared):
    original = _config(tmp_path / "original")
    other = _config(tmp_path / "other")
    names = ("incoming", "ready", "failed")
    first_dirs = [getattr(original, name + "_dir") for name in names]
    second_dirs = [getattr(original if shared == name else other, name + "_dir") for name in names]
    first_db = tmp_path / "original.db"
    second_db = first_db if shared == "db" else tmp_path / "other.db"
    with capture_resource_locks(first_db, first_dirs):
        with pytest.raises(RuntimeLockError):
            with capture_resource_locks(second_db, second_dirs):
                pytest.fail("a shared capture resource was not locked")
    # Partial acquisition on the rejected attempt must not leave locks behind.
    with capture_resource_locks(second_db, second_dirs):
        pass


def test_canonical_paths_share_locks_for_relative_and_absolute_names(tmp_path, monkeypatch):
    config = _config(tmp_path)
    monkeypatch.chdir(tmp_path)
    with capture_resource_locks(Path("capture.db"), [Path("incoming")]):
        with pytest.raises(RuntimeLockError):
            with capture_resource_locks(tmp_path / "capture.db", [config.incoming_dir]):
                pytest.fail("relative alias bypassed the capture lock")
    paths = capture_lock_paths(Path("capture.db"), [Path("incoming/../incoming"), Path("incoming")])
    assert len(paths) == 2
    assert paths == tuple(sorted(paths, key=lambda path: os.path.normcase(str(path))))


def test_symlink_alias_cannot_bypass_directory_lock(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(actual, target_is_directory=True)
    except OSError:
        pytest.skip("host does not permit creating symlinks")
    with capture_resource_locks(tmp_path / "one.db", [actual]):
        with pytest.raises(RuntimeLockError):
            with capture_resource_locks(tmp_path / "two.db", [alias]):
                pytest.fail("symlink alias bypassed the capture lock")


def test_crashed_owner_releases_os_locks_without_deleting_lock_files(tmp_path):
    database = tmp_path / "capture.db"
    directory = tmp_path / "incoming"
    script = (
        "from pathlib import Path; import sys; "
        "from edge.packet.capture_lock import capture_resource_locks; "
        "lock=capture_resource_locks(Path(sys.argv[1]), [Path(sys.argv[2])]); "
        "lock.__enter__(); print('LOCKED', flush=True); sys.stdin.read()"
    )
    owner = subprocess.Popen(
        [sys.executable, "-B", "-u", "-c", script, str(database), str(directory)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        assert owner.stdout.readline().strip() == "LOCKED"
        with pytest.raises(RuntimeLockError):
            with capture_resource_locks(database, [directory]):
                pytest.fail("another process bypassed a live owner")
        owner.kill()
        owner.wait(timeout=5)
        assert all(path.exists() for path in capture_lock_paths(database, [directory]))
        with capture_resource_locks(database, [directory]):
            pass
    finally:
        if owner.poll() is None:
            owner.kill()
        owner.communicate(timeout=5)


@pytest.mark.parametrize("contents", [
    b"", b"not a pcap", Path("tests/fixtures/packet/pcap/empty_window.pcap").read_bytes() + b"short",
    Path("tests/fixtures/packet/pcap/partial_capture.pcap").read_bytes(),
])
def test_success_exit_does_not_publish_invalid_pcap(tmp_path, contents):
    class InvalidFileProcess:
        def capture_window(self, *, output_path, **kwargs):
            output_path.write_bytes(contents)
            return CaptureOutcome(True, 0)

    config = _config(tmp_path)
    result = execute_capture_window(
        InvalidFileProcess(), config, session_id=SESSION_ID,
        window_start=START, window_end=START + timedelta(seconds=10),
    )
    assert result.success is False
    assert result.error_code == "PARTIAL_CAPTURE"
    assert result.final_path.read_bytes() == contents
    metadata = json.loads(result.diagnostics_path.read_text(encoding="utf-8"))
    assert metadata["file_validation_error"]
    assert not list(config.ready_dir.glob("*.pcap"))


def test_pcap_validation_rejects_regular_file_replaced_after_lstat(tmp_path, monkeypatch):
    candidate = tmp_path / "candidate.pcap"
    replacement = tmp_path / "replacement.pcap"
    valid = Path("tests/fixtures/packet/pcap/empty_window.pcap").read_bytes()
    candidate.write_bytes(valid)
    replacement.write_bytes(valid)
    original_lstat = Path.lstat

    def replace_after_lstat(path):
        observed = original_lstat(path)
        if path == candidate:
            replacement.replace(candidate)
        return observed

    monkeypatch.setattr(Path, "lstat", replace_after_lstat)
    assert capture_runtime._pcap_file_error(candidate) == "capture output changed before validation"
    # The validation descriptor must be closed even on this early rejection.
    candidate.replace(tmp_path / "rejected.pcap")


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO and no-follow file opening")
@pytest.mark.parametrize("replacement_type", ["fifo", "symlink"])
def test_pcap_validation_rejects_special_file_replacement_without_blocking(tmp_path, replacement_type):
    script = """
import os, sys
from pathlib import Path
from edge.packet import capture_runtime
candidate = Path(sys.argv[1])
target = candidate.with_name('target.pcap')
valid = Path('tests/fixtures/packet/pcap/empty_window.pcap').read_bytes()
candidate.write_bytes(valid)
target.write_bytes(valid)
original_lstat = Path.lstat
def replace_after_lstat(path):
    observed = original_lstat(path)
    if path == candidate:
        candidate.unlink()
        if sys.argv[2] == 'fifo':
            os.mkfifo(candidate)
        else:
            candidate.symlink_to(target)
    return observed
Path.lstat = replace_after_lstat
error = capture_runtime._pcap_file_error(candidate)
assert error is not None, 'replacement was accepted as valid capture'
assert target.read_bytes() == valid
print('REJECTED', flush=True)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", script, str(tmp_path / "candidate.pcap"), replacement_type],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        stdout, stderr = child.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate(timeout=5)
        pytest.fail("PCAP validation blocked on a replacement FIFO")
    assert child.returncode == 0, stderr
    assert stdout.strip() == "REJECTED"


def test_interface_drop_is_quality_failure_even_if_kernel_reports_zero(tmp_path):
    config = _config(tmp_path)
    result = execute_capture_window(
        _PcapProcess(CaptureOutcome(True, 0, packets_dropped=0, packets_dropped_by_interface=1)),
        config, session_id=SESSION_ID, window_start=START, window_end=START + timedelta(seconds=10),
    )
    assert result.success is False
    assert "packet loss" in result.error_message


@pytest.mark.skipif(os.name != "posix", reason="tcpdump inherited flock descriptors are a POSIX runtime contract")
def test_live_child_keeps_resource_locks_after_wrapper_is_killed(tmp_path):
    database = tmp_path / "capture.db"
    directory = tmp_path / "incoming"
    script = """
from pathlib import Path
import subprocess, sys
from edge.packet.capture_lock import capture_resource_locks
with capture_resource_locks(Path(sys.argv[1]), [Path(sys.argv[2])]) as descriptors:
    child = subprocess.Popen(
        [sys.executable, '-c', 'import time; time.sleep(60)'], pass_fds=descriptors,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    print(child.pid, flush=True)
    sys.stdin.read()
"""
    wrapper = subprocess.Popen(
        [sys.executable, "-B", "-u", "-c", script, str(database), str(directory)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    child_pid = None
    try:
        child_pid = int(wrapper.stdout.readline().strip())
        wrapper.kill()
        wrapper.wait(timeout=5)
        with pytest.raises(RuntimeLockError):
            with capture_resource_locks(database, [directory]):
                pytest.fail("orphan capture child lost the resource lock")
        os.kill(child_pid, signal.SIGKILL)
        child_pid = None
        deadline = time.monotonic() + 5
        while True:
            try:
                with capture_resource_locks(database, [directory]):
                    break
            except RuntimeLockError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
    finally:
        if child_pid is not None:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if wrapper.poll() is None:
            wrapper.kill()
        wrapper.communicate(timeout=5)


@pytest.mark.skipif(os.name != "posix", reason="pass_fds is supported by the deployment platform, POSIX")
def test_tcpdump_inherits_capture_lock_descriptors(tmp_path, monkeypatch):
    process = Mock()
    process.stderr = io.BytesIO(b"")
    process.wait.side_effect = [subprocess.TimeoutExpired("tcpdump", 10), 0]
    process.poll.return_value = None
    spawn = Mock(return_value=process)
    monkeypatch.setattr(capture_runtime.subprocess, "Popen", spawn)
    with capture_resource_locks(tmp_path / "capture.db", [tmp_path / "incoming"]) as descriptors:
        capture_runtime.TcpdumpCaptureProcess(inherited_lock_fds=descriptors).capture_window(
            interface="fixture", output_path=tmp_path / "unused", window_seconds=10,
        )
        assert descriptors
        assert spawn.call_args.kwargs["pass_fds"] == descriptors
