"""P8-S04 후반: mqtt_logs가 수신 원본 바이트와 UTF-8 해석 결과를 보존하는지 검증 (Migration 009)."""

from __future__ import annotations

import shutil
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend.app.services.mqtt_log_query_service import list_mqtt_logs
from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.mqtt.subscriber import build_mqtt_log_row, insert_mqtt_log


TOPIC = "iot/dev_a/sensor"
# 0xFF는 UTF-8로 해석할 수 없고 NUL은 문자열 처리에서 흔히 잘리는 바이트다.
INVALID_BYTES = b'{"device_id":"dev_a","note":"\xff\x00\xfe"}'
VALID_BYTES = '{"device_id":"dev_a","note":"온도"}'.encode("utf-8")
# 정상 UTF-8로 보낸 U+FFFD는 잘못된 바이트를 치환한 문자열과 같은 text가 된다.
REPLACEMENT_VALID = '{"device_id":"dev_a","note":"�"}'.encode("utf-8")
REPLACEMENT_INVALID = b'{"device_id":"dev_a","note":"\xff"}'


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "raw-payload.db"
    apply_migrations(path, MIGRATIONS_DIR)
    return path


@pytest.fixture
def SessionLocal(db_path: Path):
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    maker = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        yield maker
    finally:
        engine.dispose()


def _store(maker, payload: bytes | str) -> int:
    with maker() as db:
        return insert_mqtt_log(db, build_mqtt_log_row(TOPIC, payload))


def _stored(maker, log_id: int) -> dict:
    with maker() as db:
        return dict(
            db.execute(
                text(
                    "SELECT payload, payload_size, typeof(payload_raw) AS raw_type, payload_raw, "
                    "payload_decode_status FROM mqtt_logs WHERE id = :id"
                ),
                {"id": log_id},
            )
            .mappings()
            .one()
        )


class TestRowBuilding:
    def test_invalid_utf8_keeps_raw_bytes_and_marks_status(self) -> None:
        row = build_mqtt_log_row(TOPIC, INVALID_BYTES)

        assert row["payload_raw"] == INVALID_BYTES
        assert row["payload_decode_status"] == "INVALID_UTF8"
        assert row["payload_size"] == len(INVALID_BYTES)
        assert "�" in row["payload"]

    def test_valid_multibyte_payload_is_ok(self) -> None:
        row = build_mqtt_log_row(TOPIC, VALID_BYTES)

        assert row["payload_raw"] == VALID_BYTES
        assert row["payload_decode_status"] == "OK"
        assert row["payload_size"] == len(VALID_BYTES)

    def test_text_payload_is_stored_as_its_utf8_bytes(self) -> None:
        row = build_mqtt_log_row(TOPIC, '{"device_id":"dev_a","note":"온도"}')

        assert row["payload_raw"] == VALID_BYTES
        assert row["payload_decode_status"] == "OK"


class TestStorage:
    def test_invalid_bytes_round_trip_exactly(self, SessionLocal) -> None:
        stored = _stored(SessionLocal, _store(SessionLocal, INVALID_BYTES))

        assert stored["raw_type"] == "blob"
        assert stored["payload_raw"] == INVALID_BYTES
        assert stored["payload_decode_status"] == "INVALID_UTF8"
        assert stored["payload_size"] == len(INVALID_BYTES)

    def test_same_text_is_distinguished_by_raw_bytes_and_status(self, SessionLocal) -> None:
        valid = _stored(SessionLocal, _store(SessionLocal, REPLACEMENT_VALID))
        invalid = _stored(SessionLocal, _store(SessionLocal, REPLACEMENT_INVALID))

        assert valid["payload"] == invalid["payload"]
        assert (valid["payload_raw"], valid["payload_decode_status"]) == (REPLACEMENT_VALID, "OK")
        assert (invalid["payload_raw"], invalid["payload_decode_status"]) == (
            REPLACEMENT_INVALID,
            "INVALID_UTF8",
        )

    def test_empty_payload_is_stored_as_empty_blob(self, SessionLocal) -> None:
        stored = _stored(SessionLocal, _store(SessionLocal, b""))

        assert (stored["raw_type"], stored["payload_raw"]) == ("blob", b"")
        assert stored["payload_decode_status"] == "OK"

    def test_row_without_raw_columns_is_stored_as_null(self, SessionLocal) -> None:
        row = build_mqtt_log_row(TOPIC, VALID_BYTES)
        del row["payload_raw"], row["payload_decode_status"]
        with SessionLocal() as db:
            log_id = insert_mqtt_log(db, row)

        stored = _stored(SessionLocal, log_id)
        assert stored["payload_raw"] is None
        assert stored["payload_decode_status"] is None

    def test_api_does_not_expose_raw_bytes(self, SessionLocal) -> None:
        _store(SessionLocal, INVALID_BYTES)

        with SessionLocal() as db:
            item = list_mqtt_logs(db)["items"][0]

        assert "payload_raw" not in item
        assert "payload_decode_status" not in item


@contextmanager
def _connect(path: Path):
    # Windows에서 임시 DB 파일이 열린 채 남지 않도록 항상 닫는다.
    connection = sqlite3.connect(path)
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def _insert(connection: sqlite3.Connection, **values) -> None:
    columns = {"topic": TOPIC, "payload": "x", "payload_size": 1, **values}
    connection.execute(
        f"INSERT INTO mqtt_logs ({', '.join(columns)}) VALUES ({', '.join('?' * len(columns))})",
        tuple(columns.values()),
    )


class TestDatabaseGuards:
    @pytest.mark.parametrize(
        "values",
        [
            {"payload_raw": b"x"},
            {"payload_decode_status": "OK"},
            {"payload_raw": "x", "payload_decode_status": "OK"},
            {"payload_raw": b"xx", "payload_decode_status": "OK"},
            {"payload_raw": b"x", "payload_decode_status": "ok"},
            {"payload_raw": b"x", "payload_decode_status": ""},
        ],
        ids=["raw-only", "status-only", "text-raw", "size-mismatch", "bad-status", "empty-status"],
    )
    def test_inconsistent_insert_is_rejected(self, db_path: Path, values) -> None:
        with _connect(db_path) as connection:
            with pytest.raises(sqlite3.DatabaseError):
                _insert(connection, **values)
            assert connection.execute("SELECT COUNT(*) FROM mqtt_logs").fetchone()[0] == 0

    @pytest.mark.parametrize(
        "assignment",
        ["payload_raw = x'41'", "payload_decode_status = 'INVALID_UTF8'", "payload_size = 5"],
    )
    def test_stored_raw_is_immutable(self, db_path: Path, assignment: str) -> None:
        with _connect(db_path) as connection:
            _insert(connection, payload_raw=b"x", payload_decode_status="OK")
            with pytest.raises(sqlite3.DatabaseError, match="immutable"):
                connection.execute(f"UPDATE mqtt_logs SET {assignment}")

    def test_legacy_row_cannot_be_filled_with_guessed_raw(self, db_path: Path) -> None:
        with _connect(db_path) as connection:
            _insert(connection)
            with pytest.raises(sqlite3.DatabaseError, match="immutable"):
                connection.execute(
                    "UPDATE mqtt_logs SET payload_raw = x'78', payload_decode_status = 'OK'"
                )

    def test_unrelated_update_of_a_raw_row_is_allowed(self, db_path: Path) -> None:
        with _connect(db_path) as connection:
            _insert(connection, payload_raw=b"x", payload_decode_status="OK")
            connection.execute("UPDATE mqtt_logs SET error_message = 'reviewed'")
            assert connection.execute("SELECT error_message FROM mqtt_logs").fetchone()[0] == (
                "reviewed"
            )


class TestMigrationOnExistingDatabase:
    def test_legacy_rows_are_kept_and_left_null(self, tmp_path: Path) -> None:
        old = tmp_path / "old"
        old.mkdir()
        for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            if int(path.name.split("_", 1)[0]) < 9:
                shutil.copy(path, old / path.name)
        database = tmp_path / "legacy.db"
        apply_migrations(database, old)
        with _connect(database) as connection:
            connection.execute(
                "INSERT INTO mqtt_logs (topic, payload, payload_size, is_json_valid) "
                "VALUES (?, ?, ?, 1)",
                (TOPIC, "legacy � text", 19),
            )

        result = apply_migrations(database, MIGRATIONS_DIR)

        assert result.applied_versions == [9, 10, 11, 12, 13]
        with _connect(database) as connection:
            row = connection.execute(
                "SELECT payload, payload_size, is_json_valid, payload_raw, payload_decode_status "
                "FROM mqtt_logs"
            ).fetchone()
        assert row == ("legacy � text", 19, 1, None, None)
