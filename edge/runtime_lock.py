"""Edge Runtime 공용 단일 실행 Lock입니다.

같은 자원(DB 상태와 실제 OS 상태)을 바꾸는 명령이 동시에 실행되면 상태가 어긋납니다.
Firewall Worker는 서비스가 상시 실행되는 동안에도 관리자가 수동 명령을 실행할 수
있어야 하므로, Lock은 **프로세스 전체가 아니라 변경 작업 단위**로 잡습니다. 그래서
`--loop` 서비스는 Cycle 사이에 Lock을 놓고, 관리자 명령은 잠깐 기다렸다가 획득합니다.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import os
from pathlib import Path
import time

DEFAULT_POLL_INTERVAL_SECONDS = 0.2


class RuntimeLockError(Exception):
    """다른 프로세스가 같은 Lock을 보유하고 있습니다."""


@contextmanager
def single_instance_lock(
    lock_path: Path,
    *,
    wait_seconds: float = 0.0,
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> Iterator[None]:
    """Lock을 획득하지 못하면 `RuntimeLockError`를 발생시킵니다.

    `wait_seconds`가 0보다 크면 그 시간까지 재시도합니다. 상시 서비스가 Cycle을
    수행하는 짧은 순간과 관리자 명령이 겹쳤을 때 바로 실패하지 않게 하기 위한 것입니다.
    """
    if wait_seconds < 0:
        raise ValueError("wait_seconds must not be negative")

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + wait_seconds

    if os.name == "posix":
        import fcntl

        with lock_path.open("a+", encoding="ascii") as lock_file:
            while True:
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        raise RuntimeLockError(
                            f"another process holds the lock: {lock_path}"
                        ) from exc
                    time.sleep(poll_interval_seconds)

            lock_file.seek(0)
            lock_file.truncate()
            lock_file.write(f"pid={os.getpid()}\n")
            lock_file.flush()
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        return

    while True:
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError as exc:
            if time.monotonic() >= deadline:
                raise RuntimeLockError(
                    f"another process holds the lock: {lock_path}"
                ) from exc
            time.sleep(poll_interval_seconds)

    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.close(descriptor)
        yield
    finally:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def resolve_lock_path(database_url: str, *, suffix: str, fallback: str) -> Path:
    """SQLite DB 파일 옆에 Lock 파일 경로를 만듭니다."""
    if database_url.startswith("sqlite:///"):
        db_path = Path(database_url.removeprefix("sqlite:///"))
        return db_path.with_suffix(db_path.suffix + suffix)
    return Path(fallback)
