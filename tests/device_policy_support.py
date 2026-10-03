"""기기 정책 저장소 테스트가 공유하는 보조 값과 함수."""

from __future__ import annotations

import ipaddress
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from db.migration_runner import MIGRATIONS_DIR, apply_migrations, connect_database
from edge.policy.device_policy import IpRegistrationPolicy


POLICY: dict[str, Any] = {
    "policy_profile": "periodic-sensor-v1",
    "expected_publish_interval_seconds": 5.0,
    "publish_count_max": 15,
    "payload_size_max_bytes": 5120,
    "packet_rate_max_pps": 10.0,
    "byte_rate_max_bytes_per_second": 2500.0,
}

LAN_POLICY = IpRegistrationPolicy(
    network=ipaddress.IPv4Network("192.168.0.0/24"),
    excluded=frozenset({ipaddress.IPv4Address("192.168.0.1")}),
)

T0 = datetime(2026, 10, 2, 0, 0, 3, tzinfo=timezone.utc)


def at(seconds: float) -> datetime:
    """T0(00:00:03Z)에서 `seconds` 뒤 시각."""
    return T0 + timedelta(seconds=seconds)


def clock_at(value: datetime):
    return lambda: value


def open_db(tmp_path: Path, name: str = "policy.db") -> sqlite3.Connection:
    path = tmp_path / name
    apply_migrations(path, MIGRATIONS_DIR)
    return connect_database(path)


def insert_legacy_device(
    connection: sqlite3.Connection,
    device_id: str,
    ip_address: str | None = "192.168.0.10",
    *,
    status: str = "normal",
    trust_score: int = 100,
) -> None:
    """정책 도입 전 방식(revision 없음)으로 기기를 직접 넣는다."""
    connection.execute(
        "INSERT INTO devices (device_id, ip_address, status, trust_score) VALUES (?, ?, ?, ?)",
        (device_id, ip_address, status, trust_score),
    )


def revision_values(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "device_id": "dev_a",
        "revision": 1,
        "effective_from": "2026-10-02T00:00:10Z",
        "registration_state": "PENDING",
        "policy_profile": "periodic-sensor-v1",
        "expected_publish_interval_seconds": 5.0,
        "publish_count_max": 15,
        "payload_size_max_bytes": 5120,
        "packet_rate_max_pps": 10.0,
        "byte_rate_max_bytes_per_second": 2500.0,
        "created_at": "2026-10-02T00:00:03.000Z",
        "created_by": "tester",
        "reason": "test",
    }
    values.update(overrides)
    return values


def insert_revision_raw(connection: sqlite3.Connection, **overrides: Any) -> None:
    """검증 없이 `device_policy_revisions`에 직접 INSERT한다(DB 제약 테스트용)."""
    values = revision_values(**overrides)
    columns = ", ".join(values)
    placeholders = ", ".join("?" for _ in values)
    connection.execute(
        f"INSERT INTO device_policy_revisions ({columns}) VALUES ({placeholders})",
        tuple(values.values()),
    )


def count(connection: sqlite3.Connection, table: str) -> int:
    return int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
