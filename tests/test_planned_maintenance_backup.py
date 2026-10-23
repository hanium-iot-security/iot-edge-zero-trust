"""Native SQLite backup contracts using invented databases and real WAL writes."""
from contextlib import closing, contextmanager
import hashlib
import json
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


def test_timing_emits_one_private_line_only_after_connections_close(tmp_path, monkeypatch, capsys):
    database, root = tmp_path / "private-source.db", tmp_path / "private-backup"
    make_database(database, rows=1)
    original_connect, original_emit = sqlite3.connect, cli._emit_backup_timing
    opened, emissions = [], []

    def connect(*args, **kwargs):
        conn = original_connect(*args, **kwargs)
        opened.append(conn)
        return conn

    def emit(event):
        assert len(opened) == 2
        for conn in opened:
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                conn.execute("SELECT 1")
        emissions.append(event)
        original_emit(event)

    monkeypatch.setattr(cli.sqlite3, "connect", connect)
    monkeypatch.setattr(cli, "_emit_backup_timing", emit)
    result = cli.online_backup(database, root)
    captured = capsys.readouterr()
    assert not captured.out
    lines = captured.err.splitlines()
    assert len(lines) == len(emissions) == 1
    event = json.loads(lines[0])
    assert event == emissions[0]
    assert list(result) == ["backup_path", "backup_sha256"]
    assert event["event"] == "online_backup_timing"
    assert event["outcome"] == "success"
    assert event["failed_phase"] is event["exception_class"] is None
    assert event["timeout_seconds"] == 600
    assert event["timing_scope"] == "backup_before_diagnostic_output"
    assert event["started_at_utc"].endswith("+00:00")
    assert list(event["phases_seconds"]) == [
        "artifact_setup", "connection_open", "source_snapshot_pin", "copy",
        "integrity_check", "foreign_key_check", "connection_close", "hash",
        "checksum_publication"]
    assert all(value >= 0 for value in event["phases_seconds"].values())
    assert event["elapsed_seconds"] == pytest.approx(sum(event["phases_seconds"].values()), abs=1e-7)
    assert str(database) not in lines[0] and str(root) not in lines[0]
    backup = Path(result["backup_path"])
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == result["backup_sha256"]
    assert backup.with_suffix(".db.sha256").read_text() == (
        result["backup_sha256"] + "  database.backup.db\n")


@pytest.mark.parametrize("failed_phase", ["copy", "checksum_publication"])
def test_timing_failure_preserves_exact_exception_and_does_not_publish(
        tmp_path, monkeypatch, capsys, sources, failed_phase):
    database, root = tmp_path / "private-source.db", tmp_path / "private-backup"
    make_database(database, rows=1)
    failure = RuntimeError("private-path-and-credentials-must-not-be-logged")
    original_connect, original_open = sqlite3.connect, Path.open

    class FailingCopy(sqlite3.Connection):
        def backup(self, *args, **kwargs):
            raise failure

    def connect(*args, **kwargs):
        return original_connect(*args, **{**kwargs, "factory": FailingCopy})

    def open_file(path, *args, **kwargs):
        if path.suffix == ".sha256":
            raise failure
        return original_open(path, *args, **kwargs)

    if failed_phase == "copy":
        monkeypatch.setattr(cli.sqlite3, "connect", connect)
    else:
        monkeypatch.setattr(Path, "open", open_file)
    with pytest.raises(RuntimeError) as raised:
        cli.online_backup(database, root)
    assert raised.value is failure
    assert_sources_closed(sources)
    assert_no_checksum(root)
    captured = capsys.readouterr()
    assert not captured.out and len(captured.err.splitlines()) == 1
    event = json.loads(captured.err)
    assert event["outcome"] == "failure"
    assert event["failed_phase"] == failed_phase
    assert event["exception_class"] == "RuntimeError"
    assert str(database) not in captured.err and str(root) not in captured.err
    assert str(failure) not in captured.err


def test_timing_output_failure_cannot_replace_success_or_original_error(tmp_path, monkeypatch):
    database = tmp_path / "source.db"
    make_database(database, rows=1)
    emissions = []

    def broken_emit(event):
        emissions.append(event["outcome"])
        if event["outcome"] == "success":
            raise OSError("diagnostic output failed")
        raise RuntimeError("diagnostic output failed")

    monkeypatch.setattr(cli, "_emit_backup_timing", broken_emit)
    result = cli.online_backup(database, tmp_path / "good-backup")
    assert list(result) == ["backup_path", "backup_sha256"]
    assert Path(result["backup_path"]).with_suffix(".db.sha256").exists()
    original = sqlite3.connect
    failure = OSError("original copy failure")

    class FailingCopy(sqlite3.Connection):
        def backup(self, *args, **kwargs):
            raise failure

    def connect(*args, **kwargs):
        return original(*args, **{**kwargs, "factory": FailingCopy})

    monkeypatch.setattr(cli.sqlite3, "connect", connect)
    with pytest.raises(OSError) as raised:
        cli.online_backup(database, tmp_path / "failed-backup")
    assert raised.value is failure
    assert emissions == ["success", "failure"]
    assert_no_checksum(tmp_path / "failed-backup")



def test_timing_output_cancellation_still_interrupts_the_caller(tmp_path, monkeypatch):
    database = tmp_path / "source.db"
    make_database(database, rows=1)
    cancellation = KeyboardInterrupt("cancel before caller continues")

    def cancelled_emit(_event):
        raise cancellation

    monkeypatch.setattr(cli, "_emit_backup_timing", cancelled_emit)
    with pytest.raises(KeyboardInterrupt) as raised:
        cli.online_backup(database, tmp_path / "backup")
    assert raised.value is cancellation


def test_timing_attributes_distinct_operation_delays_without_intermediate_output(
        tmp_path, monkeypatch, capsys):
    database = tmp_path / "source.db"
    make_database(database, rows=1)
    clock = SimpleNamespace(now=0)
    original_connect, original_mkdir = sqlite3.connect, Path.mkdir
    original_open, original_digest = Path.open, hashlib.sha256
    original_emit, emissions = cli._emit_backup_timing, []

    class DelayedConnection(sqlite3.Connection):
        def execute(self, statement, *args, **kwargs):
            result = super().execute(statement, *args, **kwargs)
            clock.now += {"SELECT COUNT(*) FROM sqlite_schema": .1,
                          "PRAGMA integrity_check": .3,
                          "PRAGMA foreign_key_check": .4}.get(statement, 0)
            return result

        def backup(self, *args, **kwargs):
            assert not emissions
            result = super().backup(*args, **kwargs)
            clock.now += .2
            return result

        def close(self):
            assert not emissions
            super().close()
            clock.now += .5

    def connect(*args, **kwargs):
        result = original_connect(*args, **{**kwargs, "factory": DelayedConnection})
        clock.now += .6
        return result

    def mkdir(path, *args, **kwargs):
        result = original_mkdir(path, *args, **kwargs)
        clock.now += .05
        return result

    class DelayedDigest:
        def __init__(self):
            self.digest = original_digest()

        def update(self, chunk):
            self.digest.update(chunk)
            clock.now += .7

        def hexdigest(self):
            return self.digest.hexdigest()

    @contextmanager
    def delayed_checksum(path, *args, **kwargs):
        with original_open(path, *args, **kwargs) as stream:
            class Writer:
                def write(self, value):
                    assert not emissions
                    result = stream.write(value)
                    clock.now += .8
                    return result
            yield Writer()
        clock.now += .9

    def open_file(path, *args, **kwargs):
        if path.suffix == ".sha256":
            return delayed_checksum(path, *args, **kwargs)
        return original_open(path, *args, **kwargs)

    def emit(event):
        emissions.append(event)
        original_emit(event)

    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=lambda: clock.now, sleep=lambda _: None))
    monkeypatch.setattr(cli.sqlite3, "connect", connect)
    monkeypatch.setattr(Path, "mkdir", mkdir)
    monkeypatch.setattr(Path, "open", open_file)
    monkeypatch.setattr(cli.hashlib, "sha256", DelayedDigest)
    monkeypatch.setattr(cli, "_emit_backup_timing", emit)
    result = cli.online_backup(database, tmp_path / "backup")
    assert Path(result["backup_path"]).stat().st_size < 1024 * 1024
    event = json.loads(capsys.readouterr().err)
    assert len(emissions) == 1
    assert event["phases_seconds"] == pytest.approx({
        "artifact_setup": .1, "connection_open": 1.2, "source_snapshot_pin": .1,
        "copy": .2, "integrity_check": .3, "foreign_key_check": .4,
        "connection_close": 1.0, "hash": .7, "checksum_publication": 1.7})
    assert event["elapsed_seconds"] == pytest.approx(5.7)
