"""Native SQLite backup contracts using invented databases and real WAL writes."""
from contextlib import closing, contextmanager
import hashlib
import math
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
from types import SimpleNamespace

import pytest

from edge.maintenance import run_planned_maintenance as cli


def make_database(path, *, mode="wal", rows=500, invalid_fk=False):
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute(f"PRAGMA journal_mode={mode}").fetchone()[0] == mode
        conn.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, payload BLOB)")
        conn.executemany("INSERT INTO sample(payload) VALUES (?)", [(b"x" * 3900,)] * rows)
        conn.execute("CREATE TABLE marker(generation INTEGER)")
        conn.execute("INSERT INTO marker VALUES (0)")
        conn.execute("CREATE TABLE child(parent_id INTEGER REFERENCES sample(id))")
        conn.executemany("INSERT INTO child VALUES (?)", [(rows + 1 if invalid_fk else 1,)] * 5000)
        conn.commit()


@pytest.fixture
def sources(monkeypatch):
    opened = []
    original = cli.connection

    @contextmanager
    def tracked(*args, **kwargs):
        with original(*args, **kwargs) as conn:
            opened.append(conn)
            yield conn

    monkeypatch.setattr(cli, "connection", tracked)
    return opened


def assert_sources_closed(sources):
    assert sources
    for conn in sources:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            conn.execute("SELECT 1")


def assert_no_checksum(root):
    assert not list(root.rglob("*.sha256"))


def test_wal_backup_pins_starting_generation_while_writer_commits(tmp_path, monkeypatch, sources):
    database = tmp_path / "source.db"
    make_database(database)
    with closing(sqlite3.connect(database)) as conn:
        pages = conn.execute("PRAGMA page_count").fetchone()[0]
    start_writer, stop_writer, first_commit = (threading.Event() for _ in range(3))
    commits, failures, sleeps = [], [], []

    def writer():
        try:
            if not start_writer.wait(3):
                return
            with closing(sqlite3.connect(database, timeout=1)) as conn:
                while not stop_writer.is_set():
                    conn.execute("UPDATE marker SET generation=generation+1")
                    conn.execute("INSERT INTO sample(payload) VALUES (?)", (b"later",))
                    conn.commit()
                    commits.append(1)
                    first_commit.set()
                    stop_writer.wait(.01)
        except Exception as exc:
            failures.append(exc)

    def cooperate(delay):
        sleeps.append(delay)
        start_writer.set()
        assert first_commit.wait(2), "the WAL read snapshot must allow writer commits"
        time.sleep(delay)

    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=time.monotonic, sleep=cooperate))
    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    try:
        result = cli.online_backup(database, tmp_path / "backup", timeout=10)
    finally:
        stop_writer.set()
        thread.join(4)
    assert not thread.is_alive() and not failures
    assert len(commits) >= 10
    assert len(sleeps) == math.ceil(pages / 16) - 1
    assert all(delay == .02 for delay in sleeps)
    assert list(result) == ["backup_path", "backup_sha256"]
    backup = Path(result["backup_path"])
    with closing(sqlite3.connect(backup)) as conn:
        assert conn.execute("SELECT generation FROM marker").fetchone() == (0,)
        assert conn.execute("SELECT COUNT(*) FROM sample").fetchone() == (500,)
        assert conn.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    with closing(sqlite3.connect(database)) as conn:
        assert conn.execute("SELECT generation FROM marker").fetchone() == (len(commits),)
        assert conn.execute("SELECT COUNT(*) FROM sample").fetchone() == (500 + len(commits),)
        assert conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (0, 0, 0)
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == result["backup_sha256"]
    assert backup.with_suffix(".db.sha256").read_text() == (
        result["backup_sha256"] + "  database.backup.db\n")
    assert_sources_closed(sources)


def test_non_wal_backup_keeps_mode_and_fast_copy_without_explicit_transaction(
        tmp_path, monkeypatch, sources):
    database = tmp_path / "source.db"
    make_database(database, mode="delete", rows=1)
    before = database.read_bytes()
    traces = []
    original = cli.connection

    @contextmanager
    def traced(*args, **kwargs):
        with original(*args, **kwargs) as conn:
            conn.set_trace_callback(traces.append)
            yield conn

    monkeypatch.setattr(cli, "connection", traced)
    monkeypatch.setattr(cli, "time", SimpleNamespace(
        monotonic=time.monotonic,
        sleep=lambda _: pytest.fail("non-WAL backup must not add cooperative pacing")))
    result = cli.online_backup(database, tmp_path / "backup")
    assert database.read_bytes() == before
    assert not any(statement.upper().startswith("BEGIN") for statement in traces)
    with closing(sqlite3.connect(database)) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone() == ("delete",)
    with closing(sqlite3.connect(result["backup_path"])) as conn:
        assert conn.execute("SELECT COUNT(*) FROM sample").fetchone() == (1,)
    assert_sources_closed(sources)


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), -float("inf"), None, "bad"])
def test_invalid_timeout_is_rejected_before_filesystem_work(tmp_path, timeout):
    root = tmp_path / "must-not-exist"
    with pytest.raises(cli.MaintenanceHold, match="finite positive"):
        cli.online_backup(tmp_path / "missing.db", root, timeout=timeout)
    assert not root.exists()


def test_copy_timeout_releases_source_and_does_not_publish(tmp_path, monkeypatch, sources):
    database, root = tmp_path / "source.db", tmp_path / "backup"
    make_database(database)
    clock = SimpleNamespace(now=0)

    def expire(_):
        clock.now = 11

    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=lambda: clock.now, sleep=expire))
    with pytest.raises(cli.MaintenanceHold, match="timed out"):
        cli.online_backup(database, root, timeout=10)
    assert_sources_closed(sources)
    with closing(sqlite3.connect(database, timeout=0)) as conn:
        conn.execute("UPDATE marker SET generation=1")
        conn.commit()
        assert conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (0, 0, 0)
    assert_no_checksum(root)


@pytest.mark.parametrize("pragma", ["PRAGMA integrity_check", "PRAGMA foreign_key_check"])
def test_verification_deadline_interrupts_sql_and_releases_source(
        tmp_path, monkeypatch, sources, pragma):
    database, root = tmp_path / "source.db", tmp_path / "backup"
    make_database(database)
    clock = SimpleNamespace(now=0)
    original = sqlite3.connect

    class VerificationConnection(sqlite3.Connection):
        def execute(self, statement, *args, **kwargs):
            if statement == pragma:
                clock.now = 11
            return super().execute(statement, *args, **kwargs)

    def connect(*args, **kwargs):
        kwargs["factory"] = VerificationConnection
        return original(*args, **kwargs)

    monkeypatch.setattr(cli.sqlite3, "connect", connect)
    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=lambda: clock.now, sleep=lambda _: None))
    with pytest.raises(cli.MaintenanceHold, match="timed out"):
        cli.online_backup(database, root, timeout=10)
    assert_sources_closed(sources)
    assert_no_checksum(root)


@pytest.mark.parametrize("stage", ["update", "hexdigest"])
def test_hash_deadline_prevents_checksum_publication(tmp_path, monkeypatch, stage):
    database, root = tmp_path / "source.db", tmp_path / "backup"
    make_database(database, rows=1)
    clock = SimpleNamespace(now=0)
    original = hashlib.sha256

    class SlowDigest:
        def __init__(self):
            self.digest = original()

        def update(self, chunk):
            self.digest.update(chunk)
            if stage == "update":
                clock.now = 11

        def hexdigest(self):
            result = self.digest.hexdigest()
            if stage == "hexdigest":
                clock.now = 11
            return result

    monkeypatch.setattr(cli.hashlib, "sha256", SlowDigest)
    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=lambda: clock.now, sleep=lambda _: None))
    with pytest.raises(cli.MaintenanceHold, match="timed out"):
        cli.online_backup(database, root, timeout=10)
    assert_no_checksum(root)


@pytest.mark.parametrize("stage", ["open", "write", "close"])
def test_publication_deadline_removes_only_new_checksum(tmp_path, monkeypatch, stage):
    database, root = tmp_path / "source.db", tmp_path / "backup"
    make_database(database, rows=1)
    clock = SimpleNamespace(now=0)
    original = Path.open

    @contextmanager
    def slow_publication(path, *args, **kwargs):
        with original(path, *args, **kwargs) as stream:
            if stage == "open":
                clock.now = 11

            class Writer:
                def write(self, value):
                    result = stream.write(value)
                    if stage == "write":
                        clock.now = 11
                    return result

            yield Writer()
        if stage == "close":
            clock.now = 11

    def open_file(path, *args, **kwargs):
        if path.suffix == ".sha256":
            return slow_publication(path, *args, **kwargs)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_file)
    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=lambda: clock.now, sleep=lambda _: None))
    with pytest.raises(cli.MaintenanceHold, match="timed out"):
        cli.online_backup(database, root, timeout=10)
    assert_no_checksum(root)


def test_foreign_key_failure_does_not_publish_and_releases_source(tmp_path, monkeypatch, sources):
    database, root = tmp_path / "source.db", tmp_path / "backup"
    make_database(database, invalid_fk=True)
    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=time.monotonic, sleep=lambda _: None))
    with pytest.raises(cli.MaintenanceHold, match="foreign-key"):
        cli.online_backup(database, root)
    assert_sources_closed(sources)
    assert_no_checksum(root)


@pytest.mark.parametrize("collision", ["directory", "database.backup.db", "database.backup.db.sha256"])
def test_exclusive_artifacts_preserve_existing_files(tmp_path, monkeypatch, collision):
    database, root = tmp_path / "source.db", tmp_path / "backup"
    make_database(database, mode="delete", rows=1)
    folder = root / "fixed-artifact"
    existing = folder / ("keep.txt" if collision == "directory" else collision)
    monkeypatch.setattr(cli.uuid, "uuid4", lambda: "fixed-artifact")
    original = Path.open
    if collision == "directory":
        folder.mkdir(parents=True)
        existing.write_bytes(b"existing artifact")
    else:
        def collide(path, *args, **kwargs):
            if path == existing:
                with original(path, "wb") as stream:
                    stream.write(b"existing artifact")
            return original(path, *args, **kwargs)
        monkeypatch.setattr(Path, "open", collide)
    with pytest.raises(FileExistsError):
        cli.online_backup(database, root)
    monkeypatch.setattr(Path, "open", original)
    assert existing.read_bytes() == b"existing artifact"


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes are unavailable on Windows")
def test_artifact_directories_and_files_are_private(tmp_path):
    database, root = tmp_path / "source.db", tmp_path / "backup"
    make_database(database, mode="delete", rows=1)
    backup = Path(cli.online_backup(database, root)["backup_path"])
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(backup.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert stat.S_IMODE(backup.with_suffix(".db.sha256").stat().st_mode) == 0o600


def test_filesystem_setup_uses_the_same_deadline(tmp_path, monkeypatch):
    root = tmp_path / "backup"
    clock = SimpleNamespace(now=0)
    original = Path.mkdir

    def mkdir(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == root:
            clock.now = 11
        return result

    monkeypatch.setattr(Path, "mkdir", mkdir)
    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=lambda: clock.now, sleep=lambda _: None))
    with pytest.raises(cli.MaintenanceHold, match="timed out"):
        cli.online_backup(tmp_path / "missing.db", root, timeout=10)
    assert_no_checksum(root)


def test_busy_copy_obeys_deadline_without_retrying_the_backup(tmp_path, monkeypatch, sources):
    database, root = tmp_path / "source.db", tmp_path / "backup"
    make_database(database, rows=1)
    original = sqlite3.connect
    blockers, statuses, attempts = [], [], []

    class BusyConnection(sqlite3.Connection):
        def backup(self, target, **kwargs):
            attempts.append(1)
            progress = kwargs["progress"]

            def observed(status, remaining, total):
                statuses.append(status)
                return progress(status, remaining, total)

            return super().backup(target, **{**kwargs, "progress": observed})

    def connect(path, **kwargs):
        target = Path(str(path)).name == "database.backup.db"
        conn = original(path, **{**kwargs, "factory": BusyConnection, "timeout": 0})
        if target:
            blocker = original(path, timeout=0, isolation_level=None)
            blockers.append(blocker)
            blocker.execute("BEGIN EXCLUSIVE")
        return conn

    monkeypatch.setattr(cli.sqlite3, "connect", connect)
    try:
        with pytest.raises(cli.MaintenanceHold, match="timed out"):
            cli.online_backup(database, root, timeout=.1)
    finally:
        for blocker in blockers:
            blocker.close()
    assert 5 in statuses  # SQLITE_BUSY; named constant requires Python 3.11.
    assert len(attempts) == 1
    assert_sources_closed(sources)
    assert_no_checksum(root)


def test_integrity_failure_does_not_publish_and_releases_source(tmp_path, monkeypatch, sources):
    database, root = tmp_path / "source.db", tmp_path / "backup"
    make_database(database, rows=1)
    with closing(sqlite3.connect(database)) as conn:
        conn.execute("CREATE TABLE guarded(value INTEGER CHECK(value > 0))")
        conn.execute("PRAGMA ignore_check_constraints=ON")
        conn.execute("INSERT INTO guarded VALUES (-1)")
        conn.commit()
    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=time.monotonic, sleep=lambda _: None))
    with pytest.raises(cli.MaintenanceHold, match="integrity"):
        cli.online_backup(database, root)
    assert_sources_closed(sources)
    assert_no_checksum(root)
