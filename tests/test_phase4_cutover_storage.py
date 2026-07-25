from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3

import pytest

from edge.scripts.phase4_cutover_storage import (
    CutoverSafetyError,
    create_sqlite_backup,
    operation_lock,
    restore_sqlite_backup,
    verify_database,
)
from tests.phase4_cutover_test_support import create_source_database


def test_storage_module_verifies_a_valid_sqlite_database(tmp_path: Path) -> None:
    database = tmp_path / "operational.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY)")

    result = verify_database(database)

    assert result.integrity_check == "ok"
    assert result.foreign_key_violations == ()


def test_create_sqlite_backup_writes_consistent_snapshot_and_sha256(tmp_path: Path) -> None:
    source = tmp_path / "operational.db"
    backup = tmp_path / "backups" / "operational_before_phase4.db"
    create_source_database(source)

    result = create_sqlite_backup(source, backup)

    assert result.database_path == backup.resolve()
    assert result.sha256_path == backup.with_suffix(backup.suffix + ".sha256").resolve()
    assert result.sha256 == hashlib.sha256(backup.read_bytes()).hexdigest()
    assert result.integrity_check == "ok"
    assert result.foreign_key_violations == ()
    assert result.sha256_path.read_text(encoding="utf-8") == (
        f"{result.sha256}  {backup.name}\n"
    )

    with sqlite3.connect(backup) as connection:
        assert connection.execute("SELECT name FROM parent WHERE id = 1").fetchone()[0] == (
            "before-cutover"
        )


def test_create_sqlite_backup_rejects_source_as_destination(tmp_path: Path) -> None:
    source = tmp_path / "operational.db"
    create_source_database(source)

    with pytest.raises(CutoverSafetyError, match="different paths"):
        create_sqlite_backup(source, source)


def test_create_sqlite_backup_rejects_missing_source_and_existing_destination(
    tmp_path: Path,
) -> None:
    source = tmp_path / "operational.db"
    backup = tmp_path / "operational.before.db"

    with pytest.raises(CutoverSafetyError, match="does not exist"):
        create_sqlite_backup(source, backup)
    assert not source.exists()

    create_source_database(source)
    backup.write_bytes(b"existing evidence")
    with pytest.raises(CutoverSafetyError, match="already exists"):
        create_sqlite_backup(source, backup)
    assert backup.read_bytes() == b"existing evidence"

    backup.unlink()
    checksum_manifest = backup.with_suffix(backup.suffix + ".sha256")
    checksum_manifest.write_text("existing manifest\n", encoding="utf-8")
    with pytest.raises(CutoverSafetyError, match="SHA256 destination already exists"):
        create_sqlite_backup(source, backup)
    assert not backup.exists()
    assert checksum_manifest.read_text(encoding="utf-8") == "existing manifest\n"


def test_restore_sqlite_backup_rejects_checksum_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "operational.db"
    backup = tmp_path / "operational.before.db"
    create_source_database(source)
    artifact = create_sqlite_backup(source, backup)
    backup.write_bytes(backup.read_bytes() + b"tampered")

    with pytest.raises(CutoverSafetyError, match="SHA256 mismatch"):
        restore_sqlite_backup(
            target_path=source,
            backup_path=backup,
            sha256_path=artifact.sha256_path,
        )


def test_restore_sqlite_backup_replaces_database_after_verification(tmp_path: Path) -> None:
    target = tmp_path / "operational.db"
    backup = tmp_path / "operational.before.db"
    create_source_database(target)
    artifact = create_sqlite_backup(target, backup)

    with sqlite3.connect(target) as connection:
        connection.execute("UPDATE parent SET name = 'after-cutover' WHERE id = 1")

    restored = restore_sqlite_backup(
        target_path=target,
        backup_path=backup,
        sha256_path=artifact.sha256_path,
    )

    assert restored.integrity_check == "ok"
    assert restored.foreign_key_violations == ()
    with sqlite3.connect(target) as connection:
        assert connection.execute("SELECT name FROM parent WHERE id = 1").fetchone()[0] == (
            "before-cutover"
        )


def test_sqlite_backup_preserves_wal_mode_committed_rows(tmp_path: Path) -> None:
    source = tmp_path / "wal-operational.db"
    backup = tmp_path / "wal-backup.db"
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("CREATE TABLE samples (id INTEGER PRIMARY KEY, value TEXT)")
        connection.execute("INSERT INTO samples (value) VALUES ('committed-in-wal')")
        connection.commit()
        artifact = create_sqlite_backup(source, backup)

    assert artifact.integrity_check == "ok"
    with sqlite3.connect(backup) as connection:
        assert connection.execute("SELECT value FROM samples").fetchone()[0] == (
            "committed-in-wal"
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX flock behavior")
def test_posix_lock_file_is_reused_without_unlink_race(tmp_path: Path) -> None:
    database = tmp_path / "operational.db"
    create_source_database(database)
    lock_path = database.with_suffix(database.suffix + ".phase4.lock")

    with operation_lock(database):
        assert lock_path.is_file()
        with pytest.raises(CutoverSafetyError, match="holds the lock"):
            with operation_lock(database):
                pass

    assert lock_path.is_file()
    with operation_lock(database):
        assert lock_path.is_file()
    assert lock_path.is_file()
