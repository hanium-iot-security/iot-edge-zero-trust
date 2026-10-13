from pathlib import Path
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.database import get_db
from backend.app.main import app
from db.migration_runner import MigrationError, apply_migrations, connect_database


MIGRATIONS_DIR = Path("db/migrations")
SCHEMA_PATH = MIGRATIONS_DIR / "001_init.sql"


def _legacy_001_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "legacy_001.db"
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON;")
        connection.execute("PRAGMA busy_timeout = 5000;")
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return db_path


def _legacy_db_from_schema(tmp_path: Path, name: str, schema_sql: str) -> Path:
    db_path = tmp_path / name
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON;")
        connection.execute("PRAGMA busy_timeout = 5000;")
        connection.executescript(schema_sql)
    return db_path


def _write_project_migrations(migrations_dir: Path) -> None:
    migrations_dir.mkdir()
    for migration_file in MIGRATIONS_DIR.glob("*.sql"):
        (migrations_dir / migration_file.name).write_text(
            migration_file.read_text(encoding="utf-8"),
            encoding="utf-8",
        )


def _write_project_migrations_subset(
    migrations_dir: Path,
    migration_names: tuple[str, ...],
) -> None:
    migrations_dir.mkdir()
    for migration_name in migration_names:
        source_path = MIGRATIONS_DIR / migration_name
        (migrations_dir / migration_name).write_text(
            source_path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )


def _migration_versions(connection: sqlite3.Connection) -> list[int]:
    rows = connection.execute(
        """
        SELECT version
        FROM schema_migrations
        ORDER BY version
        """
    ).fetchall()
    return [int(row["version"]) for row in rows]


def _table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table'
          AND name = ?
        """,
        (table_name,),
    ).fetchone()
    return row is not None


def _column_names(connection: sqlite3.Connection, table_name: str) -> set[str]:
    return {row["name"] for row in connection.execute(f"PRAGMA table_info({table_name})")}


def _insert_gateway_metric(
    connection: sqlite3.Connection,
    **overrides,
) -> None:
    values = {
        "collected_at": "2026-07-16T10:00:00Z",
        "sample_interval_seconds": None,
        "cpu_percent": None,
        "memory_percent": 40.0,
        "disk_percent": 25.0,
        "disk_used_mb": 512.0,
        "network_rx_bytes": None,
        "network_tx_bytes": None,
        "temperature_c": None,
        "interface_metrics_json": json.dumps(_interface_metrics()),
    }
    values.update(overrides)
    connection.execute(
        """
        INSERT INTO gateway_metrics (
            collected_at,
            sample_interval_seconds,
            cpu_percent,
            memory_percent,
            disk_percent,
            disk_used_mb,
            network_rx_bytes,
            network_tx_bytes,
            temperature_c,
            interface_metrics_json
        )
        VALUES (
            :collected_at,
            :sample_interval_seconds,
            :cpu_percent,
            :memory_percent,
            :disk_percent,
            :disk_used_mb,
            :network_rx_bytes,
            :network_tx_bytes,
            :temperature_c,
            :interface_metrics_json
        )
        """,
        values,
    )


def _insert_packet_capture_session(
    connection: sqlite3.Connection,
    *,
    session_id: str = "11111111-1111-4111-8111-111111111111",
    started_at: str = "2026-07-16T10:00:00Z",
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO packet_capture_sessions (
            session_id,
            capture_interface,
            started_at
        )
        VALUES (?, 'wlan0', ?)
        """,
        (session_id, started_at),
    )
    return int(cursor.lastrowid)


def _insert_packet_capture_segment(
    connection: sqlite3.Connection,
    *,
    capture_session_id: int,
    file_name: str = "segment-001.pcap",
    window_start: str = "2026-07-16T10:00:00Z",
    window_end: str = "2026-07-16T10:00:10Z",
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO packet_capture_segments (
            capture_session_id,
            file_name,
            capture_interface,
            window_start,
            window_end
        )
        VALUES (?, ?, 'wlan0', ?, ?)
        """,
        (capture_session_id, file_name, window_start, window_end),
    )
    return int(cursor.lastrowid)


def _insert_packet_feature_log(
    connection: sqlite3.Connection,
    *,
    capture_segment_id: int,
    peer_ip: str = "10.0.0.8",
    direction: str = "INBOUND",
    window_start: str = "2026-07-16T10:00:00Z",
    window_end: str = "2026-07-16T10:00:10Z",
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO packet_feature_logs (
            capture_segment_id,
            peer_ip,
            direction,
            window_start,
            window_end,
            packet_count,
            total_bytes,
            avg_packet_size,
            max_packet_size
        )
        VALUES (?, ?, ?, ?, ?, 1, 60, 60.0, 60)
        """,
        (capture_segment_id, peer_ip, direction, window_start, window_end),
    )
    return int(cursor.lastrowid)


def _insert_packet_checkpoint_recovery(
    connection: sqlite3.Connection,
    **overrides,
) -> int:
    values = {
        "operation_id": "20260806T010000Z-111111111111",
        "detector_name": "packet_rule",
        "source_table": "packet_feature_logs",
        "current_capture_session_id": "11111111-1111-4111-8111-111111111111",
        "target_capture_session_id": "22222222-2222-4222-8222-222222222222",
        "last_processed_id_before": 42,
        "last_processed_id_after": 42,
        "last_completed_window_end_before": "2026-08-06T01:00:00Z",
        "last_completed_window_end_after": "2026-08-06T01:00:00Z",
        "updated_at_before": "2026-08-06T01:00:01Z",
        "updated_at_after": "2026-08-06T01:00:01Z",
        "plan_sha256": "a" * 64,
        "plan_json": "{}",
        "skipped_session_count": 0,
        "skipped_processable_session_count": 0,
        "approved_by": "operator@example.com",
        "reason": "checkpoint gap recovery",
        "repository_commit": "b" * 40,
        "database_path": "/var/lib/iot-security.db",
        "backup_path": "/var/backups/iot-security.db",
        "backup_sha256": "c" * 64,
    }
    values.update(overrides)
    cursor = connection.execute(
        """
        INSERT INTO packet_checkpoint_recoveries (
            operation_id, detector_name, source_table,
            current_capture_session_id, target_capture_session_id,
            last_processed_id_before, last_processed_id_after,
            last_completed_window_end_before, last_completed_window_end_after,
            updated_at_before, updated_at_after, plan_sha256, plan_json,
            skipped_session_count, skipped_processable_session_count,
            approved_by, reason, repository_commit, database_path,
            backup_path, backup_sha256
        )
        VALUES (
            :operation_id, :detector_name, :source_table,
            :current_capture_session_id, :target_capture_session_id,
            :last_processed_id_before, :last_processed_id_after,
            :last_completed_window_end_before, :last_completed_window_end_after,
            :updated_at_before, :updated_at_after, :plan_sha256, :plan_json,
            :skipped_session_count, :skipped_processable_session_count,
            :approved_by, :reason, :repository_commit, :database_path,
            :backup_path, :backup_sha256
        )
        """,
        values,
    )
    return int(cursor.lastrowid)


def _seed_packet_checkpoint_recovery_references(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        """
        INSERT INTO detector_checkpoints (
            detector_name, source_table, last_processed_id, last_completed_window_end
        )
        VALUES ('packet_rule', 'packet_feature_logs', 42, '2026-08-06T01:00:00Z')
        """
    )
    _insert_packet_capture_session(connection)
    _insert_packet_capture_session(
        connection,
        session_id="22222222-2222-4222-8222-222222222222",
    )


def _interface_metrics(
    *,
    internal_rate: float | None = None,
    usb_exists: bool = False,
    usb_is_up: bool = False,
) -> dict:
    return {
        "internal_lan": {
            "interface_name": "eth0",
            "exists": True,
            "is_up": True,
            "ip_address": "192.168.0.20",
            "rx_bytes": 124000000,
            "tx_bytes": 36000000,
            "rx_bytes_per_sec": internal_rate,
            "tx_bytes_per_sec": internal_rate,
        },
        "usb_lan": {
            "interface_name": "eth1",
            "exists": usb_exists,
            "is_up": usb_is_up,
            "ip_address": None,
            "rx_bytes": None,
            "tx_bytes": None,
            "rx_bytes_per_sec": None,
            "tx_bytes_per_sec": None,
        },
    }


def test_runner_applies_new_database_in_order(tmp_path: Path) -> None:
    db_path = tmp_path / "new.db"

    result = apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        assert result.applied_versions == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        assert result.baselined_versions == []
        assert _migration_versions(connection) == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        assert _table_exists(connection, "packet_capture_sessions")
        assert _table_exists(connection, "trust_score_history")


def test_packet_checkpoint_recovery_base_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "recovery.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    with connect_database(db_path) as connection:
        migration = connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version = 5"
        ).fetchone()
        assert migration is not None
        assert migration["version"] == 5
        assert migration["name"] == "packet_checkpoint_recovery"
        assert _table_exists(connection, "packet_checkpoint_recoveries")
        columns = _column_names(connection, "packet_checkpoint_recoveries")
        assert columns == {
            "id", "operation_id", "detector_name", "source_table",
            "current_capture_session_id", "target_capture_session_id",
            "last_processed_id_before", "last_processed_id_after",
            "last_completed_window_end_before", "last_completed_window_end_after",
            "updated_at_before", "updated_at_after", "plan_sha256", "plan_json",
            "skipped_session_count", "skipped_processable_session_count",
            "approved_by", "reason", "repository_commit", "database_path",
            "backup_path", "backup_sha256", "created_at",
        }
        column_info = {
            row["name"]: (row["type"], row["notnull"], row["pk"], row["dflt_value"])
            for row in connection.execute("PRAGMA table_info(packet_checkpoint_recoveries)")
        }
        assert column_info["id"] == ("INTEGER", 0, 1, None)
        assert column_info["last_processed_id_before"] == ("INTEGER", 0, 0, None)
        assert column_info["last_processed_id_after"] == ("INTEGER", 0, 0, None)
        assert column_info["skipped_session_count"] == ("INTEGER", 1, 0, None)
        assert column_info["skipped_processable_session_count"] == ("INTEGER", 1, 0, None)
        for column_name in columns - {
            "id", "last_processed_id_before", "last_processed_id_after",
            "skipped_session_count", "skipped_processable_session_count", "created_at",
        }:
            assert column_info[column_name] == ("TEXT", 1, 0, None)
        assert column_info["created_at"] == ("TEXT", 1, 0, "CURRENT_TIMESTAMP")


def test_firewall_release_requests_schema_and_constraints(tmp_path: Path) -> None:
    db_path = tmp_path / "firewall-release.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    with connect_database(db_path) as connection:
        migration = connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version = 6"
        ).fetchone()
        assert migration is not None
        assert migration["name"] == "firewall_release_requests"
        assert _table_exists(connection, "firewall_release_requests")
        assert _column_names(connection, "firewall_release_requests") == {
            "id",
            "firewall_rule_id",
            "status",
            "requested_by",
            "reason",
            "requested_at",
            "processed_at",
            "last_error",
            "created_at",
            "updated_at",
        }

        connection.execute(
            """
            INSERT INTO devices (device_id, ip_address, trust_score, status)
            VALUES ('esp32_01', '192.168.0.21', 20, 'isolated')
            """
        )
        rule_id = connection.execute(
            """
            INSERT INTO firewall_rules (
                device_id, source_ip, status, applied_at, reason
            )
            VALUES (
                'esp32_01', '192.168.0.21', 'APPLIED',
                '2026-08-22T00:00:00Z', 'test'
            )
            """
        ).lastrowid
        connection.execute(
            """
            INSERT INTO firewall_release_requests (
                firewall_rule_id, requested_by, reason, requested_at
            )
            VALUES (?, 'operator@example', 'official release', '2026-08-22T00:00:01Z')
            """,
            (rule_id,),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO firewall_release_requests (
                    firewall_rule_id, requested_by, reason, requested_at
                )
                VALUES (?, 'operator@example', 'duplicate', '2026-08-22T00:00:02Z')
                """,
                (rule_id,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO firewall_release_requests (
                    firewall_rule_id, status, requested_by, reason,
                    requested_at, processed_at
                )
                VALUES (
                    ?, 'FAILED', 'operator@example', 'failed',
                    '2026-08-22T00:00:02Z', '2026-08-22T00:00:03Z'
                )
                """,
                (rule_id,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO firewall_release_requests (
                    firewall_rule_id, requested_by, reason, requested_at
                )
                VALUES (999, 'operator@example', 'missing rule', '2026-08-22T00:00:02Z')
                """
            )

        connection.execute(
            """
            UPDATE firewall_release_requests
            SET status = 'SUCCEEDED',
                processed_at = '2026-08-22T00:00:03Z'
            WHERE firewall_rule_id = ?
            """,
            (rule_id,),
        )
        connection.execute(
            """
            INSERT INTO firewall_release_requests (
                firewall_rule_id, requested_by, reason, requested_at
            )
            VALUES (?, 'operator@example', 'retry request', '2026-08-22T00:00:04Z')
            """,
            (rule_id,),
        )


def test_packet_checkpoint_recovery_migration_applies_005_to_existing_004(
    tmp_path: Path,
) -> None:
    old_dir = tmp_path / "old"
    _write_project_migrations_subset(
        old_dir,
        (
            "001_init.sql",
            "002_packet_gateway.sql",
            "003_phase4_detection.sql",
            "004_trust_score_compensation.sql",
        ),
    )
    db_path = tmp_path / "existing-004.db"
    apply_migrations(db_path, old_dir)
    with connect_database(db_path) as connection:
        _seed_packet_checkpoint_recovery_references(connection)
        before = {
            "checkpoints": tuple(connection.execute(
                "SELECT * FROM detector_checkpoints ORDER BY detector_name, source_table"
            ).fetchall()),
            "sessions": tuple(connection.execute(
                "SELECT * FROM packet_capture_sessions ORDER BY id"
            ).fetchall()),
        }
    result = apply_migrations(db_path, MIGRATIONS_DIR)
    assert result.applied_versions == [5, 6, 7, 8, 9, 10, 11, 12, 13]
    with connect_database(db_path) as connection:
        after = {
            "checkpoints": tuple(connection.execute(
                "SELECT * FROM detector_checkpoints ORDER BY detector_name, source_table"
            ).fetchall()),
            "sessions": tuple(connection.execute(
                "SELECT * FROM packet_capture_sessions ORDER BY id"
            ).fetchall()),
        }
    assert after == before


def test_packet_checkpoint_recovery_rejects_duplicate_operation_id(tmp_path: Path) -> None:
    db_path = tmp_path / "duplicate-operation.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    with connect_database(db_path) as connection:
        _seed_packet_checkpoint_recovery_references(connection)
        _insert_packet_checkpoint_recovery(connection)
        with pytest.raises(sqlite3.IntegrityError):
            _insert_packet_checkpoint_recovery(connection)


def test_packet_checkpoint_recovery_rejects_duplicate_detector_target(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "duplicate-detector-target.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    with connect_database(db_path) as connection:
        _seed_packet_checkpoint_recovery_references(connection)
        _insert_packet_checkpoint_recovery(connection)
        with pytest.raises(sqlite3.IntegrityError):
            _insert_packet_checkpoint_recovery(
                connection,
                operation_id="20260806T010001Z-111111111111",
            )


def test_packet_checkpoint_recovery_rejects_invalid_detector_or_source(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "invalid-detector-source.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    with connect_database(db_path) as connection:
        _seed_packet_checkpoint_recovery_references(connection)
        for values in (
            {"detector_name": "mqtt_rule"},
            {"source_table": "mqtt_feature_logs"},
        ):
            with pytest.raises(sqlite3.IntegrityError):
                _insert_packet_checkpoint_recovery(connection, **values)


def test_packet_checkpoint_recovery_rejects_changed_last_processed_id(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "changed-last-processed-id.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    with connect_database(db_path) as connection:
        _seed_packet_checkpoint_recovery_references(connection)
        with pytest.raises(sqlite3.IntegrityError):
            _insert_packet_checkpoint_recovery(connection, last_processed_id_after=43)


def test_packet_checkpoint_recovery_rejects_negative_skip_counts(tmp_path: Path) -> None:
    db_path = tmp_path / "negative-skip-counts.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    with connect_database(db_path) as connection:
        _seed_packet_checkpoint_recovery_references(connection)
        for values in (
            {"skipped_session_count": -1},
            {"skipped_processable_session_count": -1},
        ):
            with pytest.raises(sqlite3.IntegrityError):
                _insert_packet_checkpoint_recovery(connection, **values)


def test_packet_checkpoint_recovery_foreign_keys_restrict_referenced_rows(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "recovery-foreign-keys.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    with connect_database(db_path) as connection:
        _seed_packet_checkpoint_recovery_references(connection)
        _insert_packet_checkpoint_recovery(connection)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                DELETE FROM detector_checkpoints
                WHERE detector_name = 'packet_rule'
                  AND source_table = 'packet_feature_logs'
                """
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                DELETE FROM packet_capture_sessions
                WHERE session_id = '11111111-1111-4111-8111-111111111111'
                """
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                DELETE FROM packet_capture_sessions
                WHERE session_id = '22222222-2222-4222-8222-222222222222'
                """
            )


def test_failed_005_migration_rolls_back_schema_and_version_record(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "failed-005.db"
    migrations_004_dir = tmp_path / "migrations-004"
    _write_project_migrations_subset(
        migrations_004_dir,
        (
            "001_init.sql",
            "002_packet_gateway.sql",
            "003_phase4_detection.sql",
            "004_trust_score_compensation.sql",
        ),
    )
    apply_migrations(db_path, migrations_004_dir)

    broken_migrations_dir = tmp_path / "broken-migrations"
    _write_project_migrations_subset(
        broken_migrations_dir,
        (
            "001_init.sql",
            "002_packet_gateway.sql",
            "003_phase4_detection.sql",
            "004_trust_score_compensation.sql",
            "005_packet_checkpoint_recovery.sql",
        ),
    )
    migration_005 = broken_migrations_dir / "005_packet_checkpoint_recovery.sql"
    migration_005.write_text(
        migration_005.read_text(encoding="utf-8")
        + "\nINSERT INTO missing_packet_checkpoint_recovery_table (id) VALUES (1);\n",
        encoding="utf-8",
    )

    with pytest.raises(MigrationError):
        apply_migrations(db_path, broken_migrations_dir)

    with connect_database(db_path) as connection:
        assert _migration_versions(connection) == [1, 2, 3, 4]
        assert not _table_exists(connection, "packet_checkpoint_recoveries")


def test_missing_migration_directory_fails_before_touching_db(tmp_path: Path) -> None:
    db_path = tmp_path / "missing-dir.db"
    migrations_dir = tmp_path / "missing-migrations"

    with pytest.raises(MigrationError, match="does not exist"):
        apply_migrations(db_path, migrations_dir)

    assert not db_path.exists()


def test_migration_path_must_be_directory(tmp_path: Path) -> None:
    db_path = tmp_path / "path-file.db"
    migrations_dir = tmp_path / "migrations.sql"
    migrations_dir.write_text("CREATE TABLE should_not_run (id INTEGER);", encoding="utf-8")

    with pytest.raises(MigrationError, match="not a directory"):
        apply_migrations(db_path, migrations_dir)


def test_empty_migration_directory_fails(tmp_path: Path) -> None:
    db_path = tmp_path / "empty-dir.db"
    migrations_dir = tmp_path / "migrations"
    migrations_dir.mkdir()

    with pytest.raises(MigrationError, match="No migration SQL files"):
        apply_migrations(db_path, migrations_dir)


def test_migration_versions_must_start_at_one(tmp_path: Path) -> None:
    db_path = tmp_path / "missing-001.db"
    migrations_dir = tmp_path / "migrations"
    migrations_dir.mkdir()
    (migrations_dir / "002_packet_gateway.sql").write_text(
        "CREATE TABLE only_version_two (id INTEGER PRIMARY KEY);",
        encoding="utf-8",
    )

    with pytest.raises(MigrationError, match="Missing migration version: 1"):
        apply_migrations(db_path, migrations_dir)


def test_migration_versions_must_be_contiguous(tmp_path: Path) -> None:
    db_path = tmp_path / "missing-002.db"
    migrations_dir = tmp_path / "migrations"
    migrations_dir.mkdir()
    (migrations_dir / "001_init.sql").write_text(
        "CREATE TABLE version_one (id INTEGER PRIMARY KEY);",
        encoding="utf-8",
    )
    (migrations_dir / "003_next.sql").write_text(
        "CREATE TABLE version_three (id INTEGER PRIMARY KEY);",
        encoding="utf-8",
    )

    with pytest.raises(MigrationError, match="Missing migration version: 2"):
        apply_migrations(db_path, migrations_dir)


def test_invalid_migration_file_name_fails(tmp_path: Path) -> None:
    db_path = tmp_path / "invalid-name.db"
    migrations_dir = tmp_path / "migrations"
    migrations_dir.mkdir()
    (migrations_dir / "001-init.sql").write_text(
        "CREATE TABLE invalid_name (id INTEGER PRIMARY KEY);",
        encoding="utf-8",
    )

    with pytest.raises(MigrationError, match="Invalid migration file name"):
        apply_migrations(db_path, migrations_dir)


def test_duplicate_migration_version_fails(tmp_path: Path) -> None:
    db_path = tmp_path / "duplicate-version.db"
    migrations_dir = tmp_path / "migrations"
    migrations_dir.mkdir()
    (migrations_dir / "001_init.sql").write_text(
        "CREATE TABLE first_version (id INTEGER PRIMARY KEY);",
        encoding="utf-8",
    )
    (migrations_dir / "001_duplicate.sql").write_text(
        "CREATE TABLE duplicate_version (id INTEGER PRIMARY KEY);",
        encoding="utf-8",
    )

    with pytest.raises(MigrationError, match="Duplicate migration version: 1"):
        apply_migrations(db_path, migrations_dir)


def test_empty_migration_file_fails(tmp_path: Path) -> None:
    db_path = tmp_path / "empty-file.db"
    migrations_dir = tmp_path / "migrations"
    migrations_dir.mkdir()
    (migrations_dir / "001_empty.sql").write_text(
        """
        -- comment only

        -- still no executable SQL
        """,
        encoding="utf-8",
    )

    with pytest.raises(MigrationError, match="no executable SQL"):
        apply_migrations(db_path, migrations_dir)


def test_applied_migration_record_requires_matching_sql_file(tmp_path: Path) -> None:
    db_path = tmp_path / "missing-applied-file.db"
    migrations_dir = tmp_path / "migrations"
    migrations_dir.mkdir()
    (migrations_dir / "001_init.sql").write_text(
        "CREATE TABLE version_one (id INTEGER PRIMARY KEY);",
        encoding="utf-8",
    )
    (migrations_dir / "002_packet_gateway.sql").write_text(
        "CREATE TABLE version_two (id INTEGER PRIMARY KEY);",
        encoding="utf-8",
    )
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.executemany(
            "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
            [(1, "init"), (2, "packet_gateway"), (3, "future_change")],
        )

    with pytest.raises(MigrationError, match="3"):
        apply_migrations(db_path, migrations_dir)

    with connect_database(db_path) as connection:
        assert _migration_versions(connection) == [1, 2, 3]
        assert not _table_exists(connection, "version_one")
        assert not _table_exists(connection, "version_two")


def test_partial_legacy_db_is_not_baselined_or_auto_repaired(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "partial.db"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE devices (
                device_id TEXT PRIMARY KEY
            )
            """
        )

    with pytest.raises(MigrationError, match="Incomplete legacy 001 schema"):
        apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        assert _table_exists(connection, "devices")
        assert not _table_exists(connection, "schema_migrations")
        assert not _table_exists(connection, "mqtt_logs")
        assert not _table_exists(connection, "packet_capture_sessions")
        assert _column_names(connection, "devices") == {"device_id"}


def test_legacy_db_missing_required_columns_is_not_baselined(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "missing-column.db"
    with sqlite3.connect(db_path) as connection:
        connection.executescript(
            """
            CREATE TABLE devices (
                device_id TEXT PRIMARY KEY,
                ip_address TEXT,
                status TEXT,
                last_seen_at DATETIME,
                created_at DATETIME
            );

            CREATE TABLE mqtt_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT,
                topic TEXT,
                payload TEXT,
                payload_size INTEGER,
                received_at DATETIME,
                is_json_valid INTEGER,
                is_topic_valid INTEGER,
                error_message TEXT
            );

            CREATE TABLE feature_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT,
                window_start DATETIME,
                window_end DATETIME,
                publish_count INTEGER,
                avg_payload_size REAL,
                max_payload_size INTEGER,
                avg_message_interval REAL,
                min_message_interval REAL,
                topic_count INTEGER,
                abnormal_topic_count INTEGER,
                malformed_payload_count INTEGER
            );

            CREATE TABLE detection_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT,
                feature_log_id INTEGER,
                mqtt_log_id INTEGER,
                detector_type TEXT,
                event_type TEXT,
                severity TEXT,
                score_delta INTEGER,
                applied_to_score INTEGER,
                description TEXT,
                detected_at DATETIME
            );

            CREATE TABLE isolation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT,
                action TEXT,
                reason TEXT,
                trust_score INTEGER,
                trigger_event_id INTEGER,
                created_at DATETIME
            );
            """
        )

    with pytest.raises(MigrationError, match="trust_score"):
        apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        assert not _table_exists(connection, "schema_migrations")
        assert not _table_exists(connection, "packet_capture_sessions")
        assert "trust_score" not in _column_names(connection, "devices")


def test_legacy_db_column_pk_mismatch_is_not_baselined(tmp_path: Path) -> None:
    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8").replace(
        "device_id TEXT PRIMARY KEY,",
        "device_id TEXT,",
        1,
    )
    db_path = _legacy_db_from_schema(tmp_path, "pk-mismatch.db", schema_sql)

    with pytest.raises(MigrationError, match="devices.device_id.*pk=1"):
        apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        assert not _table_exists(connection, "schema_migrations")
        assert not _table_exists(connection, "packet_capture_sessions")


def test_legacy_db_column_type_mismatch_is_not_baselined(tmp_path: Path) -> None:
    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8").replace(
        "trust_score INTEGER NOT NULL DEFAULT 100",
        "trust_score TEXT NOT NULL DEFAULT 100",
        1,
    )
    db_path = _legacy_db_from_schema(tmp_path, "type-mismatch.db", schema_sql)

    with pytest.raises(MigrationError, match="devices.trust_score.*type=INTEGER"):
        apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        assert not _table_exists(connection, "schema_migrations")
        assert not _table_exists(connection, "packet_capture_sessions")


def test_legacy_db_notnull_mismatch_is_not_baselined(tmp_path: Path) -> None:
    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8").replace(
        "topic TEXT NOT NULL,",
        "topic TEXT,",
        1,
    )
    db_path = _legacy_db_from_schema(tmp_path, "notnull-mismatch.db", schema_sql)

    with pytest.raises(MigrationError, match="mqtt_logs.topic.*notnull=1"):
        apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        assert not _table_exists(connection, "schema_migrations")
        assert not _table_exists(connection, "packet_capture_sessions")


def test_legacy_db_missing_feature_unique_is_not_baselined(tmp_path: Path) -> None:
    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8").replace(
        """malformed_payload_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(device_id, window_start, window_end)""",
        "malformed_payload_count INTEGER NOT NULL DEFAULT 0",
        1,
    )
    db_path = _legacy_db_from_schema(tmp_path, "missing-unique.db", schema_sql)

    with pytest.raises(MigrationError, match="missing_unique_constraints"):
        apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        assert not _table_exists(connection, "schema_migrations")
        assert not _table_exists(connection, "packet_capture_sessions")


def test_runner_applies_002_and_003_to_existing_001_db_and_preserves_rows(
    tmp_path: Path,
) -> None:
    db_path = _legacy_001_db(tmp_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES ('esp32_01', '192.168.0.4', 'warning', 65)
            """
        )
        mqtt_cursor = connection.execute(
            """
            INSERT INTO mqtt_logs (
                device_id,
                topic,
                payload,
                payload_size,
                is_json_valid,
                is_topic_valid
            )
            VALUES ('esp32_01', 'iot/esp32_01/sensor', '{}', 2, 1, 1)
            """
        )
        feature_cursor = connection.execute(
            """
            INSERT INTO feature_logs (
                device_id,
                window_start,
                window_end,
                publish_count
            )
            VALUES ('esp32_01', '2026-07-16 10:00:00', '2026-07-16 10:00:10', 3)
            """
        )
        event_cursor = connection.execute(
            """
            INSERT INTO detection_events (
                device_id,
                feature_log_id,
                mqtt_log_id,
                detector_type,
                event_type,
                severity,
                score_delta,
                applied_to_score,
                description
            )
            VALUES (?, ?, ?, 'RULE', 'ABNORMAL_PUBLISH_RATE', 'high', -20, 1, 'seed')
            """,
            ("esp32_01", feature_cursor.lastrowid, mqtt_cursor.lastrowid),
        )
        mqtt_id = mqtt_cursor.lastrowid
        feature_id = feature_cursor.lastrowid
        event_id = event_cursor.lastrowid

    result = apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        assert result.baselined_versions == [1]
        assert result.applied_versions == [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        assert _migration_versions(connection) == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        device = connection.execute(
            "SELECT device_id, status, trust_score FROM devices"
        ).fetchone()
        assert device["device_id"] == "esp32_01"
        assert device["status"] == "warning"
        assert device["trust_score"] == 65
        assert connection.execute("SELECT id FROM mqtt_logs").fetchone()["id"] == mqtt_id
        assert connection.execute("SELECT id FROM feature_logs").fetchone()["id"] == feature_id
        event = connection.execute(
            """
            SELECT
                id,
                feature_log_id,
                mqtt_log_id,
                applied_to_score,
                processed_at,
                processing_reason,
                incident_family
            FROM detection_events
            """
        ).fetchone()
        assert event["id"] == event_id
        assert event["feature_log_id"] == feature_id
        assert event["mqtt_log_id"] == mqtt_id
        assert event["applied_to_score"] == 1
        assert event["processed_at"] is None
        assert event["processing_reason"] is None
        assert event["incident_family"] is None
        assert connection.execute(
            "SELECT COUNT(*) AS count FROM trust_score_history"
        ).fetchone()["count"] == 0


def test_runner_skips_already_applied_migrations(tmp_path: Path) -> None:
    db_path = tmp_path / "idempotent.db"

    first = apply_migrations(db_path, MIGRATIONS_DIR)
    second = apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        assert first.applied_versions == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        assert second.applied_versions == []
        assert second.skipped_versions == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        assert _migration_versions(connection) == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]


def test_runner_sorts_migration_files_by_version(tmp_path: Path) -> None:
    migrations_dir = tmp_path / "migrations"
    migrations_dir.mkdir()
    (migrations_dir / "002_insert_order.sql").write_text(
        """
        INSERT INTO migration_order (step_name)
        VALUES ('second');
        """,
        encoding="utf-8",
    )
    (migrations_dir / "001_create_order.sql").write_text(
        """
        CREATE TABLE migration_order (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            step_name TEXT NOT NULL
        );

        INSERT INTO migration_order (step_name)
        VALUES ('first');
        """,
        encoding="utf-8",
    )

    db_path = tmp_path / "ordered.db"
    result = apply_migrations(db_path, migrations_dir)

    with connect_database(db_path) as connection:
        rows = connection.execute(
            "SELECT step_name FROM migration_order ORDER BY id"
        ).fetchall()
        assert result.applied_versions == [1, 2]
        assert [row["step_name"] for row in rows] == ["first", "second"]
        assert _migration_versions(connection) == [1, 2]


def test_failed_migration_rolls_back_sql_and_version_record(tmp_path: Path) -> None:
    migrations_dir = tmp_path / "migrations"
    migrations_dir.mkdir()
    (migrations_dir / "001_create_anchor.sql").write_text(
        """
        CREATE TABLE rollback_anchor (
            id INTEGER PRIMARY KEY AUTOINCREMENT
        );
        """,
        encoding="utf-8",
    )
    (migrations_dir / "002_fail_after_partial_sql.sql").write_text(
        """
        CREATE TABLE rollback_marker (
            id INTEGER PRIMARY KEY AUTOINCREMENT
        );

        ALTER TABLE rollback_anchor ADD COLUMN failed_column TEXT;

        INSERT INTO missing_table (id)
        VALUES (1);
        """,
        encoding="utf-8",
    )
    db_path = tmp_path / "rollback.db"

    with pytest.raises(MigrationError):
        apply_migrations(db_path, migrations_dir)

    with connect_database(db_path) as connection:
        assert _migration_versions(connection) == [1]
        assert _table_exists(connection, "rollback_anchor")
        assert not _table_exists(connection, "rollback_marker")
        assert "failed_column" not in _column_names(connection, "rollback_anchor")


def test_failed_002_migration_can_be_retried_after_fix(tmp_path: Path) -> None:
    db_path = _legacy_001_db(tmp_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO devices (device_id, status, trust_score)
            VALUES ('esp32_01', 'normal', 100)
            """
        )
        connection.execute(
            """
            INSERT INTO detection_events (
                device_id,
                detector_type,
                event_type,
                score_delta,
                applied_to_score
            )
            VALUES ('esp32_01', 'RULE', 'ABNORMAL_PUBLISH_RATE', -20, 1)
            """
        )

    migrations_dir = tmp_path / "retry-migrations"
    _write_project_migrations(migrations_dir)
    migration_002 = migrations_dir / "002_packet_gateway.sql"
    migration_002.write_text(
        """
        CREATE TABLE retry_marker (
            id INTEGER PRIMARY KEY AUTOINCREMENT
        );

        ALTER TABLE detection_events ADD COLUMN failed_retry_column TEXT;

        INSERT INTO missing_retry_table (id)
        VALUES (1);
        """,
        encoding="utf-8",
    )

    with pytest.raises(MigrationError):
        apply_migrations(db_path, migrations_dir)

    with connect_database(db_path) as connection:
        assert _migration_versions(connection) == [1]
        assert not _table_exists(connection, "retry_marker")
        assert not _table_exists(connection, "packet_capture_sessions")
        assert "failed_retry_column" not in _column_names(
            connection,
            "detection_events",
        )
        assert connection.execute(
            "SELECT COUNT(*) AS count FROM detection_events"
        ).fetchone()["count"] == 1

    migration_002.write_text(
        (MIGRATIONS_DIR / "002_packet_gateway.sql").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    result = apply_migrations(db_path, migrations_dir)

    with connect_database(db_path) as connection:
        assert result.applied_versions == [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        assert _migration_versions(connection) == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        assert not _table_exists(connection, "retry_marker")
        assert _table_exists(connection, "packet_capture_sessions")
        assert "failed_retry_column" not in _column_names(
            connection,
            "detection_events",
        )
        assert connection.execute(
            "SELECT COUNT(*) AS count FROM schema_migrations WHERE version = 2"
        ).fetchone()["count"] == 1


def test_gateway_metrics_schema_matches_phase_contract(tmp_path: Path) -> None:
    db_path = tmp_path / "gateway-schema.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

    expected_columns = {
        "id",
        "collected_at",
        "sample_interval_seconds",
        "cpu_percent",
        "memory_percent",
        "disk_percent",
        "disk_used_mb",
        "network_rx_bytes",
        "network_tx_bytes",
        "temperature_c",
        "interface_metrics_json",
        "created_at",
    }
    removed_columns = {
        "capture_interface",
        "active_session_count",
        "ready_segment_count",
        "processed_segment_count",
        "failed_segment_count",
        "details_json",
        "disk_total_mb",
    }

    with connect_database(db_path) as connection:
        columns = _column_names(connection, "gateway_metrics")
        assert expected_columns <= columns
        assert not removed_columns & columns


def test_gateway_metrics_accepts_pr14_sample_shapes_and_json_round_trip(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "gateway-samples.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

    first_sample = _interface_metrics(internal_rate=None)
    second_sample = _interface_metrics(internal_rate=100.0)
    long_interval_sample = _interface_metrics(internal_rate=None)
    down_sample = _interface_metrics(internal_rate=None, usb_exists=True, usb_is_up=False)

    with connect_database(db_path) as connection:
        _insert_gateway_metric(
            connection,
            collected_at="2026-07-16T10:00:00Z",
            sample_interval_seconds=None,
            cpu_percent=None,
            memory_percent=40.0,
            disk_percent=25.0,
            disk_used_mb=5.0,
            network_rx_bytes=None,
            network_tx_bytes=None,
            temperature_c=None,
            interface_metrics_json=json.dumps(first_sample),
        )
        _insert_gateway_metric(
            connection,
            collected_at="2026-07-16T10:00:10.500000Z",
            sample_interval_seconds=10.5,
            cpu_percent=75.0,
            memory_percent=41.0,
            disk_percent=25.5,
            disk_used_mb=5.1,
            temperature_c=48.5,
            interface_metrics_json=json.dumps(second_sample),
        )
        _insert_gateway_metric(
            connection,
            collected_at="2026-07-16T10:00:41.500000Z",
            sample_interval_seconds=31.0,
            cpu_percent=50.0,
            memory_percent=42.0,
            disk_percent=26.0,
            disk_used_mb=None,
            interface_metrics_json=json.dumps(long_interval_sample),
        )
        _insert_gateway_metric(
            connection,
            collected_at="2026-07-16T10:00:52Z",
            sample_interval_seconds=0,
            cpu_percent=None,
            memory_percent=43.0,
            disk_percent=27.0,
            disk_used_mb=None,
            interface_metrics_json=json.dumps(down_sample),
        )

        rows = connection.execute(
            """
            SELECT collected_at, sample_interval_seconds, cpu_percent,
                   disk_used_mb, network_rx_bytes, network_tx_bytes,
                   temperature_c, interface_metrics_json
            FROM gateway_metrics
            ORDER BY id
            """
        ).fetchall()

        first_json = json.loads(rows[0]["interface_metrics_json"])
        assert rows[0]["sample_interval_seconds"] is None
        assert rows[0]["cpu_percent"] is None
        assert rows[0]["network_rx_bytes"] is None
        assert rows[0]["network_tx_bytes"] is None
        assert rows[0]["temperature_c"] is None
        assert first_json["internal_lan"]["interface_name"] == "eth0"
        assert first_json["internal_lan"]["exists"] is True
        assert first_json["internal_lan"]["rx_bytes"] == 124000000
        assert first_json["internal_lan"]["rx_bytes_per_sec"] is None
        assert first_json["usb_lan"]["interface_name"] == "eth1"
        assert first_json["usb_lan"]["exists"] is False
        assert first_json["usb_lan"]["is_up"] is False
        assert first_json["usb_lan"]["ip_address"] is None

        second_json = json.loads(rows[1]["interface_metrics_json"])
        assert rows[1]["sample_interval_seconds"] == 10.5
        assert rows[1]["cpu_percent"] == 75.0
        assert second_json["internal_lan"]["rx_bytes_per_sec"] == 100.0
        assert second_json["internal_lan"]["tx_bytes_per_sec"] == 100.0

        long_interval_json = json.loads(rows[2]["interface_metrics_json"])
        assert rows[2]["sample_interval_seconds"] == 31.0
        assert rows[2]["disk_used_mb"] is None
        assert long_interval_json["internal_lan"]["rx_bytes_per_sec"] is None
        assert long_interval_json["internal_lan"]["tx_bytes_per_sec"] is None

        down_json = json.loads(rows[3]["interface_metrics_json"])
        assert rows[3]["sample_interval_seconds"] == 0
        assert down_json["usb_lan"]["exists"] is True
        assert down_json["usb_lan"]["is_up"] is False


def test_gateway_metrics_constraints(tmp_path: Path) -> None:
    db_path = tmp_path / "gateway-constraints.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

    failing_values = [
        {"memory_percent": -0.1},
        {"memory_percent": 100.1},
        {"disk_percent": -0.1},
        {"disk_percent": 100.1},
        {"cpu_percent": -0.1},
        {"cpu_percent": 100.1},
        {"disk_used_mb": -1.0},
        {"network_rx_bytes": -1},
        {"network_tx_bytes": -1},
        {"sample_interval_seconds": -1},
        {"collected_at": None},
        {"memory_percent": None},
        {"disk_percent": None},
        {"interface_metrics_json": None},
    ]

    with connect_database(db_path) as connection:
        for values in failing_values:
            with pytest.raises(sqlite3.IntegrityError):
                _insert_gateway_metric(connection, **values)

        _insert_gateway_metric(
            connection,
            sample_interval_seconds=None,
            cpu_percent=None,
            disk_used_mb=None,
            network_rx_bytes=None,
            network_tx_bytes=None,
            temperature_c=None,
        )
        _insert_gateway_metric(
            connection,
            collected_at="2026-07-16T10:00:01Z",
            sample_interval_seconds=0,
            cpu_percent=None,
        )

        assert connection.execute(
            "SELECT COUNT(*) AS count FROM gateway_metrics"
        ).fetchone()["count"] == 2


def test_detector_checkpoints_schema_and_key_contract(tmp_path: Path) -> None:
    db_path = tmp_path / "detector-checkpoints.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        columns = _column_names(connection, "detector_checkpoints")
        assert {
            "detector_name",
            "source_table",
            "last_processed_id",
            "last_completed_window_end",
            "updated_at",
        } <= columns
        assert not {"id", "checkpoint_key", "last_processed_at"} & columns

        connection.execute(
            """
            INSERT INTO detector_checkpoints (
                detector_name,
                source_table,
                last_processed_id,
                last_completed_window_end
            )
            VALUES ('packet_rule', 'packet_feature', 10, '2026-07-16T10:00:10Z')
            """
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO detector_checkpoints (
                    detector_name,
                    source_table
                )
                VALUES ('packet_rule', 'packet_feature')
                """
            )
        connection.execute(
            """
            INSERT INTO detector_checkpoints (
                detector_name,
                source_table
            )
            VALUES ('packet_rule', 'mqtt_feature')
            """
        )


def test_trust_score_history_schema_and_window_contract(tmp_path: Path) -> None:
    db_path = tmp_path / "trust-score-history.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        columns = _column_names(connection, "trust_score_history")
        assert {
            "id",
            "device_id",
            "analysis_window_start",
            "analysis_window_end",
            "previous_score",
            "calculated_delta",
            "capped_delta",
            "actual_delta",
            "new_score",
            "representative_event_ids_json",
            "policy_version",
            "created_at",
        } <= columns
        assert not {
            "packet_feature_log_id",
            "detection_event_id",
            "score_before",
            "score_delta",
            "score_after",
            "status_before",
            "status_after",
            "reason",
        } & columns

        connection.execute(
            """
            INSERT INTO devices (device_id, status, trust_score)
            VALUES ('esp32_01', 'danger', 35)
            """
        )
        event_ids_json = json.dumps([31, 34])
        connection.execute(
            """
            INSERT INTO trust_score_history (
                device_id,
                analysis_window_start,
                analysis_window_end,
                previous_score,
                calculated_delta,
                capped_delta,
                actual_delta,
                new_score,
                representative_event_ids_json,
                policy_version
            )
            VALUES ('esp32_01', '2026-07-16T10:00:00Z',
                    '2026-07-16T10:00:10Z', 50, -40, -25, -15, 35, ?, 'v1')
            """,
            (event_ids_json,),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO trust_score_history (
                    device_id,
                    analysis_window_start,
                    analysis_window_end,
                    previous_score,
                    calculated_delta,
                    capped_delta,
                    actual_delta,
                    new_score,
                    representative_event_ids_json,
                    policy_version
                )
                VALUES ('esp32_01', '2026-07-16T10:00:00Z',
                        '2026-07-16T10:00:10Z', 35, -10, -10, -10, 25, '[]', 'v1')
                """
            )
        connection.execute(
            """
            INSERT INTO trust_score_history (
                device_id,
                analysis_window_start,
                analysis_window_end,
                previous_score,
                calculated_delta,
                capped_delta,
                actual_delta,
                new_score,
                representative_event_ids_json,
                policy_version
            )
            VALUES ('esp32_01', '2026-07-16T10:00:10Z',
                    '2026-07-16T10:00:20Z', 35, 0, 0, 0, 35, '[]', 'v1')
            """
        )

        for column_name in ("previous_score", "new_score"):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    f"""
                    INSERT INTO trust_score_history (
                        device_id,
                        analysis_window_start,
                        analysis_window_end,
                        previous_score,
                        calculated_delta,
                        capped_delta,
                        actual_delta,
                        new_score,
                        representative_event_ids_json,
                        policy_version
                    )
                    VALUES ('esp32_01', '2026-07-16T11:00:00Z',
                            '2026-07-16T11:00:10Z',
                            {101 if column_name == 'previous_score' else 50},
                            0, 0, 0,
                            {101 if column_name == 'new_score' else 50},
                            '[]', 'v1')
                    """
                )

        for values in (
            {"representative_event_ids_json": None, "policy_version": "v1"},
            {"representative_event_ids_json": "[]", "policy_version": None},
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO trust_score_history (
                        device_id,
                        analysis_window_start,
                        analysis_window_end,
                        previous_score,
                        calculated_delta,
                        capped_delta,
                        actual_delta,
                        new_score,
                        representative_event_ids_json,
                        policy_version
                    )
                    VALUES ('esp32_01', '2026-07-16T12:00:00Z',
                            '2026-07-16T12:00:10Z',
                            50, 0, 0, 0, 50,
                            :representative_event_ids_json,
                            :policy_version)
                    """,
                    values,
                )

        stored_json = connection.execute(
            """
            SELECT representative_event_ids_json
            FROM trust_score_history
            WHERE analysis_window_start = '2026-07-16T10:00:00Z'
            """
        ).fetchone()["representative_event_ids_json"]
        assert json.loads(stored_json) == [31, 34]


def test_packet_session_id_requires_strict_uuid_v4(tmp_path: Path) -> None:
    db_path = tmp_path / "session-uuid.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

    valid_session_ids = [
        "11111111-1111-4111-8111-111111111111",
        "AAAAAAAA-AAAA-4AAA-BAAA-AAAAAAAAAAAA",
    ]
    invalid_session_ids = [
        "11111111-1111-3111-8111-111111111111",
        "11111111-1111-4111-7111-111111111111",
        "11111111-1111-4111-8111-11111111111",
        "111111111111-4111-8111-111111111111",
        "zzzzzzzz-zzzz-4zzz-8zzz-zzzzzzzzzzzz",
    ]

    with connect_database(db_path) as connection:
        for index, session_id in enumerate(valid_session_ids):
            _insert_packet_capture_session(
                connection,
                session_id=session_id,
                started_at=f"2026-07-16T10:00:0{index}Z",
            )

        for index, session_id in enumerate(invalid_session_ids):
            with pytest.raises(sqlite3.IntegrityError):
                _insert_packet_capture_session(
                    connection,
                    session_id=session_id,
                    started_at=f"2026-07-16T10:01:0{index}Z",
                )


def test_packet_capture_segment_window_must_be_exactly_ten_seconds(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "segment-window.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

    invalid_windows = [
        ("segment-009.pcap", "2026-07-16T10:00:20Z", "2026-07-16T10:00:29Z"),
        ("segment-011.pcap", "2026-07-16T10:00:30Z", "2026-07-16T10:00:41Z"),
        ("segment-020.pcap", "2026-07-16T10:00:50Z", "2026-07-16T10:01:10Z"),
        ("segment-frac-short.pcap", "2026-07-16T10:02:00.900Z", "2026-07-16T10:02:10.100Z"),
        ("segment-frac-long.pcap", "2026-07-16T10:02:20.100Z", "2026-07-16T10:02:30.900Z"),
        ("segment-bad.pcap", "not-a-date", "2026-07-16T10:01:20Z"),
        ("segment-before.pcap", "2026-07-16T10:01:30Z", "2026-07-16T10:01:20Z"),
    ]

    with connect_database(db_path) as connection:
        capture_session_id = _insert_packet_capture_session(connection)
        _insert_packet_capture_segment(
            connection,
            capture_session_id=capture_session_id,
            file_name="segment-010.pcap",
            window_start="2026-07-16T10:00:00Z",
            window_end="2026-07-16T10:00:10Z",
        )

        for file_name, window_start, window_end in invalid_windows:
            with pytest.raises(sqlite3.IntegrityError):
                _insert_packet_capture_segment(
                    connection,
                    capture_session_id=capture_session_id,
                    file_name=file_name,
                    window_start=window_start,
                    window_end=window_end,
                )


def test_packet_feature_window_must_be_exactly_ten_seconds(tmp_path: Path) -> None:
    db_path = tmp_path / "feature-window.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

    invalid_windows = [
        ("10.0.0.9", "2026-07-16T10:00:20Z", "2026-07-16T10:00:29Z"),
        ("10.0.0.10", "2026-07-16T10:00:30Z", "2026-07-16T10:00:41Z"),
        ("10.0.0.11", "2026-07-16T10:00:50Z", "2026-07-16T10:01:10Z"),
        ("10.0.0.14", "2026-07-16T10:02:00.900Z", "2026-07-16T10:02:10.100Z"),
        ("10.0.0.15", "2026-07-16T10:02:20.100Z", "2026-07-16T10:02:30.900Z"),
        ("10.0.0.12", "not-a-date", "2026-07-16T10:01:20Z"),
        ("10.0.0.13", "2026-07-16T10:01:30Z", "2026-07-16T10:01:20Z"),
    ]

    with connect_database(db_path) as connection:
        capture_session_id = _insert_packet_capture_session(connection)
        capture_segment_id = _insert_packet_capture_segment(
            connection,
            capture_session_id=capture_session_id,
        )
        _insert_packet_feature_log(
            connection,
            capture_segment_id=capture_segment_id,
            peer_ip="10.0.0.8",
            window_start="2026-07-16T10:00:00Z",
            window_end="2026-07-16T10:00:10Z",
        )

        for peer_ip, window_start, window_end in invalid_windows:
            with pytest.raises(sqlite3.IntegrityError):
                _insert_packet_feature_log(
                    connection,
                    capture_segment_id=capture_segment_id,
                    peer_ip=peer_ip,
                    window_start=window_start,
                    window_end=window_end,
                )


def test_packet_gateway_schema_constraints(tmp_path: Path) -> None:
    db_path = tmp_path / "constraints.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        connection.execute(
            """
            INSERT INTO devices (device_id, status, trust_score)
            VALUES ('esp32_01', 'isolated', 25)
            """
        )
        session_id = "11111111-1111-4111-8111-111111111111"
        connection.execute(
            """
            INSERT INTO packet_capture_sessions (
                session_id,
                capture_interface,
                started_at
            )
            VALUES (?, 'wlan0', '2026-07-16T10:00:00Z')
            """,
            (session_id,),
        )
        capture_session_id = connection.execute(
            "SELECT id FROM packet_capture_sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()["id"]

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO packet_capture_sessions (
                    session_id,
                    capture_interface,
                    started_at
                )
                VALUES (?, 'wlan0', '2026-07-16T10:00:01Z')
                """,
                (session_id,),
            )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO packet_capture_segments (
                    capture_session_id,
                    file_name,
                    capture_interface,
                    window_start,
                    window_end
                )
                VALUES (999, 'missing-session.pcap', 'wlan0',
                        '2026-07-16T10:00:00Z', '2026-07-16T10:00:10Z')
                """
            )

        connection.execute(
            """
            INSERT INTO packet_capture_segments (
                capture_session_id,
                file_name,
                capture_interface,
                window_start,
                window_end,
                status,
                packet_count
            )
            VALUES (?, 'segment-001.pcap', 'wlan0',
                    '2026-07-16T10:00:00Z', '2026-07-16T10:00:10Z',
                    'READY', NULL)
            """,
            (capture_session_id,),
        )
        capture_segment_id = connection.execute(
            "SELECT id FROM packet_capture_segments WHERE file_name = 'segment-001.pcap'"
        ).fetchone()["id"]

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO packet_capture_segments (
                    capture_session_id,
                    file_name,
                    capture_interface,
                    window_start,
                    window_end
                )
                VALUES (?, 'segment-001.pcap', 'wlan0',
                        '2026-07-16T10:00:10Z', '2026-07-16T10:00:20Z')
                """,
                (capture_session_id,),
            )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO packet_capture_segments (
                    capture_session_id,
                    file_name,
                    capture_interface,
                    window_start,
                    window_end
                )
                VALUES (?, 'segment-002.pcap', 'wlan0',
                        '2026-07-16T10:00:00Z', '2026-07-16T10:00:10Z')
                """,
                (capture_session_id,),
            )

        connection.execute(
            """
            INSERT INTO packet_feature_logs (
                capture_segment_id,
                device_id,
                peer_ip,
                direction,
                window_start,
                window_end,
                packet_count,
                total_bytes,
                avg_packet_size,
                max_packet_size
            )
            VALUES (?, NULL, '10.0.0.8', 'INBOUND',
                    '2026-07-16T10:00:00Z', '2026-07-16T10:00:10Z',
                    2, 200, 100.0, 120)
            """,
            (capture_segment_id,),
        )
        connection.execute(
            """
            INSERT INTO packet_feature_logs (
                capture_segment_id,
                device_id,
                peer_ip,
                direction,
                window_start,
                window_end,
                packet_count,
                total_bytes,
                avg_packet_size,
                max_packet_size
            )
            VALUES (?, 'esp32_01', '10.0.0.8', 'OUTBOUND',
                    '2026-07-16T10:00:00Z', '2026-07-16T10:00:10Z',
                    1, 100, 100.0, 100)
            """,
            (capture_segment_id,),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO packet_feature_logs (
                    capture_segment_id,
                    peer_ip,
                    direction,
                    window_start,
                    window_end,
                    packet_count,
                    total_bytes,
                    avg_packet_size,
                    max_packet_size
                )
                VALUES (?, '10.0.0.8', 'INBOUND',
                        '2026-07-16T10:00:00Z', '2026-07-16T10:00:10Z',
                        2, 200, 100.0, 120)
                """,
                (capture_segment_id,),
            )

        connection.execute(
            """
            INSERT INTO trust_score_history (
                device_id,
                analysis_window_start,
                analysis_window_end,
                previous_score,
                calculated_delta,
                capped_delta,
                actual_delta,
                new_score,
                representative_event_ids_json,
                policy_version
            )
            VALUES ('esp32_01', '2026-07-16T10:00:00Z',
                    '2026-07-16T10:00:10Z', 50, -25, -25, -25, 25, '[1]', 'v1')
            """
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO trust_score_history (
                device_id,
                analysis_window_start,
                analysis_window_end,
                    previous_score,
                    calculated_delta,
                    capped_delta,
                    actual_delta,
                    new_score,
                    representative_event_ids_json,
                    policy_version
                )
                VALUES ('esp32_01', '2026-07-16T10:00:00Z',
                        '2026-07-16T10:00:10Z', 25, 0, 0, 0, 25, '[]', 'v1')
                """
            )

        assert connection.execute(
            "SELECT COUNT(*) AS count FROM packet_feature_logs WHERE device_id IS NULL"
        ).fetchone()["count"] == 1


def test_detection_event_packet_feature_log_fk_is_enforced(tmp_path: Path) -> None:
    db_path = tmp_path / "packet-feature-fk.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO detection_events (
                    device_id,
                    detector_type,
                    event_type,
                    packet_feature_log_id
                )
                VALUES ('esp32_01', 'RULE', 'PACKET_ANOMALY', 999)
                """
            )

        connection.execute(
            """
            INSERT INTO packet_capture_sessions (
                session_id,
                capture_interface,
                started_at
            )
            VALUES (
                '22222222-2222-4222-8222-222222222222',
                'wlan0',
                '2026-07-16T10:00:00Z'
            )
            """
        )
        capture_session_id = connection.execute(
            """
            SELECT id
            FROM packet_capture_sessions
            WHERE session_id = '22222222-2222-4222-8222-222222222222'
            """
        ).fetchone()["id"]
        connection.execute(
            """
            INSERT INTO packet_capture_segments (
                capture_session_id,
                file_name,
                capture_interface,
                window_start,
                window_end
            )
            VALUES (?, 'segment-fk.pcap', 'wlan0',
                    '2026-07-16T10:00:00Z', '2026-07-16T10:00:10Z')
            """,
            (capture_session_id,),
        )
        capture_segment_id = connection.execute(
            "SELECT id FROM packet_capture_segments WHERE file_name = 'segment-fk.pcap'"
        ).fetchone()["id"]
        connection.execute(
            """
            INSERT INTO packet_feature_logs (
                capture_segment_id,
                peer_ip,
                direction,
                window_start,
                window_end,
                packet_count,
                total_bytes,
                avg_packet_size,
                max_packet_size
            )
            VALUES (?, '10.0.0.9', 'INBOUND',
                    '2026-07-16T10:00:00Z', '2026-07-16T10:00:10Z',
                    1, 60, 60.0, 60)
            """,
            (capture_segment_id,),
        )
        packet_feature_log_id = connection.execute(
            "SELECT id FROM packet_feature_logs WHERE peer_ip = '10.0.0.9'"
        ).fetchone()["id"]

        connection.execute(
            """
            INSERT INTO detection_events (
                device_id,
                detector_type,
                event_type,
                packet_feature_log_id
            )
            VALUES ('esp32_01', 'RULE', 'PACKET_ANOMALY', ?)
            """,
            (packet_feature_log_id,),
        )

        assert connection.execute(
            """
            SELECT packet_feature_log_id
            FROM detection_events
            WHERE packet_feature_log_id = ?
            """,
            (packet_feature_log_id,),
        ).fetchone()["packet_feature_log_id"] == packet_feature_log_id


def test_firewall_rules_status_and_active_unique_contract(tmp_path: Path) -> None:
    db_path = tmp_path / "firewall.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        columns = _column_names(connection, "firewall_rules")
        assert {
            "id",
            "device_id",
            "source_ip",
            "protocol",
            "dest_port",
            "action",
            "reason",
            "trigger_event_id",
            "status",
            "last_error",
            "applied_at",
            "released_at",
            "created_at",
            "updated_at",
        } <= columns
        assert not {"subject_ip", "port", "requested_at"} & columns

        for offset, status in enumerate(("PENDING", "APPLIED", "FAILED", "REMOVED")):
            connection.execute(
                """
                INSERT INTO firewall_rules (
                    source_ip,
                    protocol,
                    dest_port,
                    status
                )
                VALUES (?, 'tcp', ?, ?)
                """,
                (f"192.168.0.{10 + offset}", 1883, status),
            )

        for status in ("ACTIVE", "RELEASED", "UNKNOWN"):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO firewall_rules (
                        source_ip,
                        protocol,
                        dest_port,
                        status
                    )
                    VALUES ('192.168.0.200', 'tcp', 1883, ?)
                    """,
                    (status,),
                )

        for values in (
            {"protocol": "TCP", "dest_port": 1883, "action": "DROP", "status": "PENDING"},
            {"protocol": "udp", "dest_port": 1883, "action": "DROP", "status": "PENDING"},
            {"protocol": "tcp", "dest_port": 8883, "action": "DROP", "status": "PENDING"},
            {"protocol": "tcp", "dest_port": 1883, "action": "ACCEPT", "status": "PENDING"},
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO firewall_rules (
                        source_ip,
                        protocol,
                        dest_port,
                        action,
                        status
                    )
                    VALUES ('192.168.0.201',
                            :protocol,
                            :dest_port,
                            :action,
                            :status)
                    """,
                    values,
                )

        connection.execute(
            """
            INSERT INTO firewall_rules (source_ip, protocol, dest_port, status)
            VALUES ('192.168.0.30', 'tcp', 1883, 'PENDING')
            """
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO firewall_rules (source_ip, protocol, dest_port, status)
                VALUES ('192.168.0.30', 'tcp', 1883, 'PENDING')
                """
            )

        connection.execute(
            """
            INSERT INTO firewall_rules (source_ip, protocol, dest_port, status)
            VALUES ('192.168.0.31', 'tcp', 1883, 'APPLIED')
            """
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO firewall_rules (source_ip, protocol, dest_port, status)
                VALUES ('192.168.0.31', 'tcp', 1883, 'PENDING')
                """
            )

        connection.execute(
            """
            INSERT INTO firewall_rules (source_ip, protocol, dest_port, status)
            VALUES ('192.168.0.32', 'tcp', 1883, 'FAILED')
            """
        )
        connection.execute(
            """
            INSERT INTO firewall_rules (source_ip, protocol, dest_port, status)
            VALUES ('192.168.0.32', 'tcp', 1883, 'PENDING')
            """
        )

        connection.execute(
            """
            INSERT INTO firewall_rules (source_ip, protocol, dest_port, status)
            VALUES ('192.168.0.33', 'tcp', 1883, 'REMOVED')
            """
        )
        connection.execute(
            """
            INSERT INTO firewall_rules (source_ip, protocol, dest_port, status)
            VALUES ('192.168.0.33', 'tcp', 1883, 'PENDING')
            """
        )

        connection.execute(
            """
            INSERT INTO firewall_rules (source_ip, protocol, dest_port, status)
            VALUES ('192.168.0.35', 'tcp', 1883, 'APPLIED')
            """
        )
        connection.execute(
            """
            INSERT INTO firewall_rules (source_ip, protocol, dest_port, status)
            VALUES ('192.168.0.36', 'tcp', 1883, 'PENDING')
            """
        )


def test_phase4_migration_applies_003_to_existing_002_and_preserves_segments(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "phase4-existing-002.db"
    migrations_002_dir = tmp_path / "migrations-002"
    _write_project_migrations_subset(
        migrations_002_dir,
        ("001_init.sql", "002_packet_gateway.sql"),
    )
    apply_migrations(db_path, migrations_002_dir)

    with connect_database(db_path) as connection:
        session_id = _insert_packet_capture_session(connection)
        segment_id = _insert_packet_capture_segment(
            connection,
            capture_session_id=session_id,
            file_name="phase4-preserve.pcap",
        )
        feature_id = _insert_packet_feature_log(
            connection,
            capture_segment_id=segment_id,
        )

    result = apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        assert result.applied_versions == [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        assert _migration_versions(connection) == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        assert {
            "actual_capture_started_at",
            "capture_stop_requested_at",
            "capture_process_exited_at",
            "start_delay_seconds",
            "captured_duration_seconds",
        } <= _column_names(connection, "packet_capture_segments")
        assert {"dedupe_key", "policy_version"} <= _column_names(
            connection,
            "detection_events",
        )
        segment = connection.execute(
            """
            SELECT id, file_name, actual_capture_started_at,
                   captured_duration_seconds
            FROM packet_capture_segments
            WHERE id = ?
            """,
            (segment_id,),
        ).fetchone()
        feature = connection.execute(
            """
            SELECT id, capture_segment_id
            FROM packet_feature_logs
            WHERE id = ?
            """,
            (feature_id,),
        ).fetchone()
        assert segment["id"] == segment_id
        assert segment["file_name"] == "phase4-preserve.pcap"
        assert segment["actual_capture_started_at"] is None
        assert segment["captured_duration_seconds"] is None
        assert feature["capture_segment_id"] == segment_id
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

        new_segment_id = _insert_packet_capture_segment(
            connection,
            capture_session_id=session_id,
            file_name="phase4-next.pcap",
            window_start="2026-07-16T10:00:10Z",
            window_end="2026-07-16T10:00:20Z",
        )
        assert new_segment_id > segment_id


def test_phase4_segment_timing_and_file_name_constraints(tmp_path: Path) -> None:
    db_path = tmp_path / "phase4-segment-constraints.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        session_id = _insert_packet_capture_session(connection)

        for status, file_name, start_second in (
            ("READY", None, 0),
            ("PROCESSED", None, 10),
            ("EMPTY", None, 20),
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO packet_capture_segments (
                        capture_session_id, file_name, capture_interface,
                        window_start, window_end, status
                    )
                    VALUES (?, ?, 'wlan0', ?, ?, ?)
                    """,
                    (
                        session_id,
                        file_name,
                        f"2026-07-16T10:00:{start_second:02d}Z",
                        f"2026-07-16T10:00:{start_second + 10:02d}Z",
                        status,
                    ),
                )

        connection.execute(
            """
            INSERT INTO packet_capture_segments (
                capture_session_id, file_name, capture_interface,
                window_start, window_end, status, error_code,
                captured_duration_seconds
            )
            VALUES (?, NULL, 'wlan0', '2026-07-16T10:01:00Z',
                    '2026-07-16T10:01:10Z', 'FAILED',
                    'LATE_CAPTURE', 0)
            """,
            (session_id,),
        )
        connection.execute(
            """
            INSERT INTO packet_capture_segments (
                capture_session_id, file_name, capture_interface,
                window_start, window_end, status,
                captured_duration_seconds
            )
            VALUES (?, NULL, 'wlan0', '2026-07-16T10:01:10Z',
                    '2026-07-16T10:01:20Z', 'FAILED', 9)
            """,
            (session_id,),
        )
        connection.execute(
            """
            INSERT INTO packet_capture_segments (
                capture_session_id, file_name, capture_interface,
                window_start, window_end, status,
                captured_duration_seconds
            )
            VALUES (?, NULL, 'wlan0', '2026-07-16T10:01:20Z',
                    '2026-07-16T10:01:30Z', 'FAILED', 10)
            """,
            (session_id,),
        )

        invalid_values = [
            {
                "window_start": "2026-07-16T10:02:00Z",
                "window_end": "2026-07-16T10:02:10Z",
                "status": "FAILED",
                "file_name": "late-file.pcap",
                "error_code": "LATE_CAPTURE",
                "actual_capture_started_at": None,
                "captured_duration_seconds": 0,
            },
            {
                "window_start": "2026-07-16T10:02:10Z",
                "window_end": "2026-07-16T10:02:20Z",
                "status": "FAILED",
                "file_name": None,
                "error_code": "LATE_CAPTURE",
                "actual_capture_started_at": "2026-07-16T10:02:10Z",
                "captured_duration_seconds": 0,
            },
            {
                "window_start": "2026-07-16T10:02:20Z",
                "window_end": "2026-07-16T10:02:30Z",
                "status": "FAILED",
                "file_name": None,
                "error_code": "LATE_CAPTURE",
                "actual_capture_started_at": None,
                "captured_duration_seconds": 1,
            },
            {
                "window_start": "2026-07-16T10:02:30Z",
                "window_end": "2026-07-16T10:02:40Z",
                "status": "FAILED",
                "file_name": None,
                "error_code": "PARTIAL_CAPTURE",
                "actual_capture_started_at": None,
                "captured_duration_seconds": -1,
            },
            {
                "window_start": "2026-07-16T10:02:40Z",
                "window_end": "2026-07-16T10:02:50Z",
                "status": "FAILED",
                "file_name": None,
                "error_code": "PARTIAL_CAPTURE",
                "actual_capture_started_at": None,
                "captured_duration_seconds": 10.1,
            },
        ]
        for values in invalid_values:
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO packet_capture_segments (
                        capture_session_id, file_name, capture_interface,
                        window_start, window_end, status, error_code,
                        actual_capture_started_at, captured_duration_seconds
                    )
                    VALUES (
                        :capture_session_id, :file_name, 'wlan0',
                        :window_start, :window_end, :status, :error_code,
                        :actual_capture_started_at, :captured_duration_seconds
                    )
                    """,
                    {"capture_session_id": session_id, **values},
                )


def test_phase4_detection_isolation_firewall_constraints(tmp_path: Path) -> None:
    db_path = tmp_path / "phase4-constraints.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        connection.execute(
            """
            INSERT INTO devices (device_id, status, trust_score)
            VALUES ('esp32_01', 'normal', 100)
            """
        )
        connection.execute(
            """
            INSERT INTO detection_events (
                device_id, detector_type, event_type, score_delta,
                applied_to_score, dedupe_key, policy_version
            )
            VALUES ('esp32_01', 'RULE', 'ABNORMAL_TOPIC', -20, 0,
                    NULL, NULL)
            """
        )
        connection.execute(
            """
            INSERT INTO detection_events (
                device_id, detector_type, event_type, score_delta,
                applied_to_score, dedupe_key, policy_version
            )
            VALUES ('esp32_01', 'RULE', 'ABNORMAL_TOPIC', -20, 0,
                    NULL, NULL)
            """
        )
        connection.execute(
            """
            INSERT INTO detection_events (
                device_id, detector_type, event_type, score_delta,
                applied_to_score, dedupe_key, policy_version
            )
            VALUES ('esp32_01', 'RULE', 'ABNORMAL_TOPIC', -20, 0,
                    'rule:feature:1:ABNORMAL_TOPIC:v1', 'v1')
            """
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO detection_events (
                    device_id, detector_type, event_type, score_delta,
                    applied_to_score, dedupe_key, policy_version
                )
                VALUES ('esp32_01', 'RULE', 'ABNORMAL_TOPIC', -20, 0,
                        'rule:feature:1:ABNORMAL_TOPIC:v1', 'v1')
                """
            )

        connection.execute(
            """
            INSERT INTO trust_score_history (
                device_id, analysis_window_start, analysis_window_end,
                previous_score, calculated_delta, capped_delta,
                actual_delta, new_score, representative_event_ids_json,
                policy_version
            )
            VALUES ('esp32_01', '2026-07-16T10:00:00Z',
                    '2026-07-16T10:00:10Z', 100, -20, -20,
                    -20, 80, '[1]', 'v2')
            """
        )
        trust_score_history_id = connection.execute(
            "SELECT id FROM trust_score_history"
        ).fetchone()["id"]
        connection.execute(
            """
            INSERT INTO isolation_history (
                device_id, action, trust_score, trust_score_history_id
            )
            VALUES ('esp32_01', 'ISOLATED', 25, ?)
            """,
            (trust_score_history_id,),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO isolation_history (
                    device_id, action, trust_score, trust_score_history_id
                )
                VALUES ('esp32_01', 'ISOLATED', 25, ?)
                """,
                (trust_score_history_id,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO isolation_history (
                    device_id, action, trust_score, trust_score_history_id
                )
                VALUES ('esp32_01', 'ISOLATED', 25, 999)
                """
            )

        connection.execute(
            """
            INSERT INTO firewall_rules (source_ip, status)
            VALUES ('192.168.0.90', 'FAILED')
            """
        )
        retry_count = connection.execute(
            """
            SELECT retry_count
            FROM firewall_rules
            WHERE source_ip = '192.168.0.90'
            """
        ).fetchone()["retry_count"]
        assert retry_count == 0

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO firewall_rules (source_ip, status, retry_count)
                VALUES ('192.168.0.91', 'FAILED', -1)
                """
            )


def test_phase4_migration_failure_rolls_back_rebuild_and_restores_schema(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "phase4-rollback.db"
    migrations_002_dir = tmp_path / "migrations-002"
    _write_project_migrations_subset(
        migrations_002_dir,
        ("001_init.sql", "002_packet_gateway.sql"),
    )
    apply_migrations(db_path, migrations_002_dir)
    with connect_database(db_path) as connection:
        session_id = _insert_packet_capture_session(connection)
        segment_id = _insert_packet_capture_segment(
            connection,
            capture_session_id=session_id,
        )
        _insert_packet_feature_log(connection, capture_segment_id=segment_id)

    broken_migrations_dir = tmp_path / "broken-migrations"
    _write_project_migrations_subset(
        broken_migrations_dir,
        ("001_init.sql", "002_packet_gateway.sql", "003_phase4_detection.sql"),
    )
    migration_003 = broken_migrations_dir / "003_phase4_detection.sql"
    migration_003.write_text(
        migration_003.read_text(encoding="utf-8")
        + "\nINSERT INTO missing_phase4_table (id) VALUES (1);\n",
        encoding="utf-8",
    )

    with pytest.raises(MigrationError):
        apply_migrations(db_path, broken_migrations_dir)

    with connect_database(db_path) as connection:
        assert _migration_versions(connection) == [1, 2]
        assert "dedupe_key" not in _column_names(connection, "detection_events")
        assert "captured_duration_seconds" not in _column_names(
            connection,
            "packet_capture_segments",
        )
        file_name_info = {
            row["name"]: row
            for row in connection.execute("PRAGMA table_info(packet_capture_segments)")
        }["file_name"]
        assert file_name_info["notnull"] == 1
        assert connection.execute(
            """
            SELECT capture_segment_id
            FROM packet_feature_logs
            WHERE capture_segment_id = ?
            """,
            (segment_id,),
        ).fetchone()["capture_segment_id"] == segment_id
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_trust_score_history_api_uses_trust_score_history_table(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "api.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    with connect_database(db_path) as connection:
        connection.execute(
            """
            INSERT INTO devices (device_id, status, trust_score)
            VALUES ('esp32_01', 'normal', 80)
            """
        )
        connection.execute(
            """
            INSERT INTO trust_score_history (
                device_id,
                analysis_window_start,
                analysis_window_end,
                previous_score,
                calculated_delta,
                capped_delta,
                actual_delta,
                new_score,
                representative_event_ids_json,
                policy_version,
                created_at
            )
            VALUES (
                'esp32_01',
                '2026-07-16T10:00:00Z',
                '2026-07-16T10:00:10Z',
                100,
                -20,
                -20,
                -20,
                80,
                '[1]',
                'trust-score-v2',
                '2026-07-16T10:00:10Z'
            )
            """
        )

    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = testing_session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        response = TestClient(app).get("/api/trust-score/esp32_01/history")
    finally:
        app.dependency_overrides.clear()
        engine.dispose()

    with connect_database(db_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) AS count FROM trust_score_history"
        ).fetchone()["count"] == 1

    assert response.status_code == 200
    body = response.json()
    assert body["current_score"] == 80
    assert body["current_status"] == "normal"
    assert body["total"] == 1
    assert body["items"][0]["previous_score"] == 100
    assert body["items"][0]["new_score"] == 80
    assert body["items"][0]["representative_event_ids"] == [1]


def test_trust_score_compensation_schema_and_constraints(tmp_path: Path) -> None:
    db_path = tmp_path / "trust-score-compensation.db"
    apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        assert {
            "id",
            "operation_id",
            "device_id",
            "source_event_id",
            "source_trust_history_id",
            "previous_score",
            "compensation_delta",
            "new_score",
            "reason",
            "approved_by",
            "backup_path",
            "backup_sha256",
            "created_at",
        } <= _column_names(connection, "trust_score_compensations")

        connection.execute(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES ('esp32_01', '192.168.0.4', 'normal', 80)
            """
        )
        event_id = connection.execute(
            """
            INSERT INTO detection_events (
                device_id, detector_type, event_type, severity,
                score_delta, applied_to_score, processed_at, processing_reason
            )
            VALUES (
                'esp32_01', 'MQTT_RULE', 'ABNORMAL_PUBLISH_RATE', 'high',
                -20, 1, '2026-08-03T06:40:00Z', 'APPLIED_TO_TRUST'
            )
            """
        ).lastrowid
        history_id = connection.execute(
            """
            INSERT INTO trust_score_history (
                device_id, analysis_window_start, analysis_window_end,
                previous_score, calculated_delta, capped_delta, actual_delta,
                new_score, representative_event_ids_json, policy_version
            )
            VALUES (
                'esp32_01', '2026-08-03T06:39:30Z',
                '2026-08-03T06:39:40Z', 100, -20, -20, -20, 80,
                ?, 'trust-score-v2'
            )
            """,
            (json.dumps([event_id]),),
        ).lastrowid

        values = {
            "operation_id": "20260803T080000Z-111111111111",
            "device_id": "esp32_01",
            "source_event_id": event_id,
            "source_trust_history_id": history_id,
            "previous_score": 80,
            "compensation_delta": 20,
            "new_score": 100,
            "reason": "subscriber backlog false positive",
            "approved_by": "operator@example",
            "backup_path": "/evidence/trust-compensation.db",
            "backup_sha256": "a" * 64,
        }
        compensation_id = connection.execute(
            """
            INSERT INTO trust_score_compensations (
                operation_id, device_id, source_event_id,
                source_trust_history_id, previous_score,
                compensation_delta, new_score, reason, approved_by,
                backup_path, backup_sha256
            )
            VALUES (
                :operation_id, :device_id, :source_event_id,
                :source_trust_history_id, :previous_score,
                :compensation_delta, :new_score, :reason, :approved_by,
                :backup_path, :backup_sha256
            )
            """,
            values,
        ).lastrowid

        for column_name, invalid_value in (
            ("operation_id", " "),
            ("previous_score", -1),
            ("compensation_delta", 0),
            ("new_score", 99),
            ("reason", "   "),
            ("approved_by", ""),
            ("backup_path", " "),
            ("backup_sha256", "A" * 64),
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    f"""
                    UPDATE trust_score_compensations
                    SET {column_name} = ?
                    WHERE id = ?
                    """,
                    (invalid_value, compensation_id),
                )

        event_id_2 = connection.execute(
            """
            INSERT INTO detection_events (
                device_id, detector_type, event_type, severity,
                score_delta, applied_to_score, processed_at, processing_reason
            )
            VALUES (
                'esp32_01', 'MQTT_RULE', 'ABNORMAL_TOPIC', 'high',
                -20, 1, '2026-08-03T06:40:10Z', 'APPLIED_TO_TRUST'
            )
            """
        ).lastrowid
        history_id_2 = connection.execute(
            """
            INSERT INTO trust_score_history (
                device_id, analysis_window_start, analysis_window_end,
                previous_score, calculated_delta, capped_delta, actual_delta,
                new_score, representative_event_ids_json, policy_version
            )
            VALUES (
                'esp32_01', '2026-08-03T06:39:40Z',
                '2026-08-03T06:39:50Z', 80, -20, -20, -20, 60,
                ?, 'trust-score-v2'
            )
            """,
            (json.dumps([event_id_2]),),
        ).lastrowid

        for operation_id, duplicate_event_id, duplicate_history_id in (
            (values["operation_id"], event_id_2, history_id_2),
            ("duplicate-source-event", event_id, history_id_2),
            ("duplicate-source-history", event_id_2, history_id),
        ):
            duplicate = dict(values)
            duplicate.update(
                {
                    "operation_id": operation_id,
                    "source_event_id": duplicate_event_id,
                    "source_trust_history_id": duplicate_history_id,
                }
            )
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO trust_score_compensations (
                        operation_id, device_id, source_event_id,
                        source_trust_history_id, previous_score,
                        compensation_delta, new_score, reason, approved_by,
                        backup_path, backup_sha256
                    )
                    VALUES (
                        :operation_id, :device_id, :source_event_id,
                        :source_trust_history_id, :previous_score,
                        :compensation_delta, :new_score, :reason, :approved_by,
                        :backup_path, :backup_sha256
                    )
                    """,
                    duplicate,
                )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM detection_events WHERE id = ?",
                (event_id,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM trust_score_history WHERE id = ?",
                (history_id,),
            )


def test_trust_score_compensation_migration_applies_004_to_existing_003(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "existing-003.db"
    migrations_003_dir = tmp_path / "migrations-003"
    _write_project_migrations_subset(
        migrations_003_dir,
        (
            "001_init.sql",
            "002_packet_gateway.sql",
            "003_phase4_detection.sql",
        ),
    )
    apply_migrations(db_path, migrations_003_dir)

    with connect_database(db_path) as connection:
        connection.execute(
            """
            INSERT INTO devices (device_id, status, trust_score)
            VALUES ('esp32_01', 'normal', 80)
            """
        )
        event_id = connection.execute(
            """
            INSERT INTO detection_events (
                device_id, detector_type, event_type, score_delta,
                applied_to_score, processed_at, processing_reason
            )
            VALUES (
                'esp32_01', 'MQTT_RULE', 'ABNORMAL_PUBLISH_RATE', -20,
                1, '2026-08-03T06:40:00Z', 'APPLIED_TO_TRUST'
            )
            """
        ).lastrowid
        history_id = connection.execute(
            """
            INSERT INTO trust_score_history (
                device_id, analysis_window_start, analysis_window_end,
                previous_score, calculated_delta, capped_delta, actual_delta,
                new_score, representative_event_ids_json, policy_version
            )
            VALUES (
                'esp32_01', '2026-08-03T06:39:30Z',
                '2026-08-03T06:39:40Z', 100, -20, -20, -20, 80,
                ?, 'trust-score-v2'
            )
            """,
            (json.dumps([event_id]),),
        ).lastrowid
        event_before = tuple(
            connection.execute(
                "SELECT * FROM detection_events WHERE id = ?", (event_id,)
            ).fetchone()
        )
        history_before = tuple(
            connection.execute(
                "SELECT * FROM trust_score_history WHERE id = ?", (history_id,)
            ).fetchone()
        )

    result = apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        assert result.applied_versions == [4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        assert _migration_versions(connection) == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        assert _table_exists(connection, "trust_score_compensations")
        assert tuple(
            connection.execute(
                "SELECT * FROM detection_events WHERE id = ?", (event_id,)
            ).fetchone()
        ) == event_before
        assert tuple(
            connection.execute(
                "SELECT * FROM trust_score_history WHERE id = ?", (history_id,)
            ).fetchone()
        ) == history_before
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
