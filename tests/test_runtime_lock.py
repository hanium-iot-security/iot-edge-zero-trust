"""Edge Runtime 공용 단일 실행 Lock 테스트."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import textwrap
import time

import pytest

from edge.runtime_lock import RuntimeLockError, resolve_lock_path, single_instance_lock


def test_second_holder_is_rejected(tmp_path: Path):
    lock_path = tmp_path / "runtime.lock"
    with single_instance_lock(lock_path):
        with pytest.raises(RuntimeLockError, match="another process holds the lock"):
            with single_instance_lock(lock_path):
                pass


def test_lock_is_reusable_after_release(tmp_path: Path):
    lock_path = tmp_path / "runtime.lock"
    with single_instance_lock(lock_path):
        pass
    with single_instance_lock(lock_path):
        pass


def test_wait_seconds_gives_up_after_timeout(tmp_path: Path):
    lock_path = tmp_path / "runtime.lock"
    with single_instance_lock(lock_path):
        started = time.monotonic()
        with pytest.raises(RuntimeLockError):
            with single_instance_lock(
                lock_path, wait_seconds=0.3, poll_interval_seconds=0.05
            ):
                pass
        assert time.monotonic() - started >= 0.3


def test_wait_seconds_acquires_lock_released_by_another_process(tmp_path: Path):
    """상시 서비스가 Cycle 사이에 Lock을 놓으면 관리자 명령이 이어받는다."""
    lock_path = tmp_path / "runtime.lock"
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            textwrap.dedent(
                f"""
                import time
                from pathlib import Path
                from edge.runtime_lock import single_instance_lock

                with single_instance_lock(Path({str(lock_path)!r})):
                    time.sleep(0.5)
                """
            ),
        ],
        cwd=Path.cwd(),
    )
    try:
        time.sleep(0.2)
        with single_instance_lock(lock_path, wait_seconds=5.0, poll_interval_seconds=0.05):
            pass
    finally:
        holder.wait(timeout=10)


def test_lock_file_records_pid(tmp_path: Path):
    lock_path = tmp_path / "runtime.lock"
    with single_instance_lock(lock_path):
        assert "pid=" in lock_path.read_text(encoding="ascii")


def test_negative_wait_is_rejected(tmp_path: Path):
    with pytest.raises(ValueError):
        with single_instance_lock(tmp_path / "runtime.lock", wait_seconds=-1):
            pass


def test_resolve_lock_path_uses_sqlite_file_location():
    assert resolve_lock_path(
        "sqlite:///backend/data/iot_security.db",
        suffix=".firewall.lock",
        fallback="data/firewall-worker.lock",
    ) == Path("backend/data/iot_security.db.firewall.lock")


def test_resolve_lock_path_falls_back_for_non_sqlite_urls():
    assert resolve_lock_path(
        "postgresql://localhost/iot",
        suffix=".firewall.lock",
        fallback="data/firewall-worker.lock",
    ) == Path("data/firewall-worker.lock")
