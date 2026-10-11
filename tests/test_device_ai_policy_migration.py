"""P9-03: Migration 012(device_ai_policy_revisions)의 적용과 DB 제약 검증."""

from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

import pytest

from db.migration_runner import MIGRATIONS_DIR, apply_migrations, connect_database
from tests.device_policy_support import count, insert_legacy_device


def _insert(connection: sqlite3.Connection, **overrides) -> None:
    values = {
        "device_id": "dev_a",
        "revision": 1,
        "mode": "OFF",
        "effective_from": "2026-10-12T00:00:10Z",
        "created_at": "2026-10-12T00:00:03.000Z",
        "created_by": "tester",
        "reason": "test",
    }
    values.update(overrides)
    connection.execute(
        f"INSERT INTO device_ai_policy_revisions ({', '.join(values)}) "
        f"VALUES ({', '.join('?' * len(values))})",
        tuple(values.values()),
    )


@pytest.fixture
def db(tmp_path: Path):
    path = tmp_path / "ai-policy.db"
    apply_migrations(path, MIGRATIONS_DIR)
    connection = connect_database(path)
    insert_legacy_device(connection, "dev_a")
    connection.commit()
    try:
        yield connection
    finally:
        connection.close()


class TestApply:
    def test_existing_011_database_keeps_data_and_gets_an_empty_table(self, tmp_path: Path) -> None:
        old = tmp_path / "old"
        old.mkdir()
        for path in MIGRATIONS_DIR.glob("*.sql"):
            if int(path.name.split("_", 1)[0]) < 12:
                shutil.copy(path, old / path.name)
        database = tmp_path / "legacy.db"
        apply_migrations(database, old)
        connection = connect_database(database)
        insert_legacy_device(connection, "legacy_1", "192.168.0.31", trust_score=70)
        connection.commit()
        connection.close()

        assert apply_migrations(database, MIGRATIONS_DIR).applied_versions == [12]

        connection = connect_database(database)
        try:
            row = connection.execute(
                "SELECT device_id, trust_score FROM devices WHERE device_id = 'legacy_1'"
            ).fetchone()
            assert tuple(row) == ("legacy_1", 70)
            assert count(connection, "device_ai_policy_revisions") == 0
        finally:
            connection.close()


class TestConstraints:
    def test_valid_first_revision_is_accepted(self, db) -> None:
        _insert(db)
        assert count(db, "device_ai_policy_revisions") == 1

    @pytest.mark.parametrize(
        "overrides",
        [
            {"mode": "ENFORCE"},
            {"mode": "observe"},
            {"revision": "one"},
            {"effective_from": "2026-10-12T00:00:05Z"},  # 10초 경계 아님
            {"effective_from": "2026-10-12 00:00:10"},  # UTC Z 형식 아님
            {"effective_from": "2026-13-45T00:00:10Z"},  # 존재하지 않는 날짜
            {"created_by": "  "},
            {"reason": ""},
            {"device_id": "ghost"},  # FK
        ],
        ids=["enforce", "lowercase", "text-revision", "not-boundary", "not-utc-z", "bad-date",
             "blank-actor", "blank-reason", "unknown-device"],
    )
    def test_invalid_row_is_rejected(self, db, overrides) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            _insert(db, **overrides)
        assert count(db, "device_ai_policy_revisions") == 0

    def test_revision_must_follow_the_previous_one(self, db) -> None:
        _insert(db)
        with pytest.raises(sqlite3.DatabaseError, match="plus one"):
            _insert(db, revision=3, effective_from="2026-10-12T00:00:30Z", mode="OBSERVE")
        with pytest.raises(sqlite3.DatabaseError, match="plus one"):
            _insert(db, revision=1, effective_from="2026-10-12T00:00:30Z", mode="OBSERVE")

    def test_effective_from_must_move_forward(self, db) -> None:
        _insert(db)
        with pytest.raises(sqlite3.DatabaseError, match="later than every earlier"):
            _insert(db, revision=2, mode="OBSERVE", effective_from="2026-10-12T00:00:10Z")
        with pytest.raises(sqlite3.DatabaseError, match="later than every earlier"):
            _insert(db, revision=2, mode="OBSERVE", effective_from="2026-10-12T00:00:00Z")

    def test_rows_are_immutable(self, db) -> None:
        _insert(db)
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            db.execute("UPDATE device_ai_policy_revisions SET mode = 'OBSERVE'")
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            db.execute("DELETE FROM device_ai_policy_revisions")

    def test_device_with_revisions_cannot_be_deleted(self, db) -> None:
        _insert(db)
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("DELETE FROM devices WHERE device_id = 'dev_a'")
