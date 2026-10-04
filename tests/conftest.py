from collections.abc import Iterator
import os
from pathlib import Path
import shutil
import tempfile

import pytest
from sqlalchemy import text

TEST_DB_DIR = Path(tempfile.mkdtemp(prefix="iot-edge-zero-trust-tests-"))
TEST_DB_PATH = TEST_DB_DIR / "iot_security_test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH.as_posix()}"

from backend.app.database import SessionLocal, engine

SCHEMA_PATH = Path("db/migrations/001_init.sql")
RAW_PAYLOAD_MIGRATION_PATH = Path("db/migrations/009_mqtt_raw_payload.sql")


def ensure_schema() -> None:
    # Some runtime tests migrate this temporary global DB to v2.  Each MVP
    # fixture must start from 001 so a later test cannot inherit that schema.
    engine.dispose()
    TEST_DB_PATH.unlink(missing_ok=True)
    raw_connection = engine.raw_connection()
    try:
        raw_connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        raw_connection.commit()
    finally:
        raw_connection.close()


@pytest.fixture()
def db_session() -> Iterator:
    ensure_schema()
    with SessionLocal() as db:
        yield db


@pytest.fixture()
def db_session_with_raw_payload() -> Iterator:
    """001 스키마에 원본 바이트 컬럼(Migration 009)만 더한 세션. `insert_mqtt_log`를 쓰는 테스트용."""
    ensure_schema()
    raw_connection = engine.raw_connection()
    try:
        raw_connection.executescript(RAW_PAYLOAD_MIGRATION_PATH.read_text(encoding="utf-8"))
        raw_connection.commit()
    finally:
        raw_connection.close()
    try:
        with SessionLocal() as db:
            yield db
    finally:
        # 이후 전역 DB에 Migration을 적용하는 테스트가 009를 중복 적용하지 않도록 되돌린다.
        ensure_schema()


def cleanup_device(db, device_id: str) -> None:
    for table in ("feature_logs", "mqtt_logs", "detection_events", "isolation_history", "devices"):
        db.execute(text(f"DELETE FROM {table} WHERE device_id = :device_id"), {"device_id": device_id})
    db.commit()


def pytest_sessionfinish(session, exitstatus) -> None:
    engine.dispose()
    shutil.rmtree(TEST_DB_DIR, ignore_errors=True)
