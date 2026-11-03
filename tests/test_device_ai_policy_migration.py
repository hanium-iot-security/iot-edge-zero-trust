"""P9-03: Migration 012(device_ai_policy_revisions)의 적용과 DB 제약 검증."""

from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

import pytest

from db.migration_runner import MIGRATIONS_DIR, apply_migrations, connect_database
from edge.policy.device_ai_policy_resolver import AI_RESOLUTION_OK, resolve_ai_mode
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

        assert apply_migrations(database, MIGRATIONS_DIR).applied_versions == [12, 13, 14, 15, 16]

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

    @pytest.mark.parametrize("field,value", [
        ("effective_from", "2026-02-30T00:00:10Z"),
        ("effective_from", "2026-02-29T00:00:10Z"),
        ("effective_from", "1900-02-29T00:00:10Z"),
        ("effective_from", "2026-04-31T00:00:10Z"),
        ("effective_from", "2026-10-12T24:00:10Z"),
        ("effective_from", "0000-10-12T00:00:10Z"),
        ("created_at", "2026-02-30T00:00:03Z"),
        ("created_at", "2026-02-30T00:00:03.123Z"),
        ("created_at", "2026-02-29T00:00:03Z"),
        ("created_at", "1900-02-29T00:00:03Z"),
        ("created_at", "2026-04-31T00:00:03Z"),
        ("created_at", "2026-10-12T24:00:03Z"),
        ("created_at", "2026-10-12T24:00:03.123Z"),
        ("created_at", "0000-10-12T00:00:03Z"),
        ("created_at", "0000-10-12T00:00:03.123Z"),
    ])
    def test_noncanonical_calendar_timestamp_is_rejected(self, db, field, value) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            _insert(db, **{field: value})
        assert count(db, "device_ai_policy_revisions") == 0

    @pytest.mark.parametrize("effective_from,created_at", [
        ("2028-02-29T00:00:10Z", "2028-02-29T00:00:03Z"),
        ("2028-02-29T00:00:10Z", "2028-02-29T00:00:03.123Z"),
        ("2000-02-29T23:59:50Z", "2000-02-29T23:59:49.999Z"),
        ("0001-01-01T00:00:10Z", "0001-01-01T00:00:03.000Z"),
        ("9999-12-31T23:59:50Z", "9999-12-31T23:59:49.999Z"),
    ])
    def test_valid_calendar_timestamp_is_preserved_and_resolves(self, db, effective_from, created_at) -> None:
        _insert(db, effective_from=effective_from, created_at=created_at)
        stored = db.execute("SELECT effective_from,created_at FROM device_ai_policy_revisions").fetchone()
        assert tuple(stored) == (effective_from, created_at)
        resolved = resolve_ai_mode(db, "dev_a", effective_from)
        assert (resolved.resolution, resolved.ai_policy_revision, resolved.mode) == (AI_RESOLUTION_OK, 1, "OFF")

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
