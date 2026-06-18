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


def ensure_schema() -> None:
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


def cleanup_device(db, device_id: str) -> None:
    for table in ("feature_logs", "mqtt_logs", "detection_events", "isolation_history", "devices"):
        db.execute(text(f"DELETE FROM {table} WHERE device_id = :device_id"), {"device_id": device_id})
    db.commit()


def pytest_sessionfinish(session, exitstatus) -> None:
    engine.dispose()
    shutil.rmtree(TEST_DB_DIR, ignore_errors=True)
