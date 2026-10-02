"""Hold capture resources for the entire runtime, including crash reconciliation.

OS advisory locks are released when their final owner exits. On POSIX, tcpdump
inherits the descriptors so an orphan child still protects its capture files.
Persistent lock files are never deleted or treated as proof of a live owner.
"""

from collections.abc import Iterator, Sequence
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path

from edge.runtime_lock import RuntimeLockError


def capture_lock_paths(database_path: Path, capture_directories: Sequence[Path]) -> tuple[Path, ...]:
    database = database_path.expanduser().resolve()
    paths = {database.with_name(database.name + ".packet-capture.lock")}
    paths.update(directory.expanduser().resolve() / ".packet-capture.lock" for directory in capture_directories)
    return tuple(sorted(paths, key=lambda path: os.path.normcase(str(path))))


@contextmanager
def _resource_lock(path: Path) -> Iterator[int | None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        if os.name == "posix":
            import fcntl
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeLockError(f"capture resource already in use: {path}") from exc
            # Closing our descriptor releases only our reference. A running
            # tcpdump child inherits this same open-file description and keeps
            # the lock if its wrapper crashes; never force LOCK_UN here.
            unlock = lambda: None
        elif os.name == "nt":
            import msvcrt
            # Windows locks byte zero, including when an earlier owner crashed.
            if path.stat().st_size == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeLockError(f"capture resource already in use: {path}") from exc

            def unlock():
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            raise RuntimeLockError(f"capture locks unsupported on platform: {os.name}")
        try:
            yield handle.fileno() if os.name == "posix" else None
        finally:
            unlock()


@contextmanager
def capture_resource_locks(database_path: Path, capture_directories: Sequence[Path]) -> Iterator[tuple[int, ...]]:
    """Same DB OR any shared capture directory prevents a second writer."""
    with ExitStack() as stack:
        inherited_fds = []
        for path in capture_lock_paths(database_path, capture_directories):
            descriptor = stack.enter_context(_resource_lock(path))
            if descriptor is not None:
                inherited_fds.append(descriptor)
        yield tuple(inherited_fds)
