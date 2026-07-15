from pathlib import Path
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


def _write_project_migrations(migrations_dir: Path) -> None:
    migrations_dir.mkdir()
    for migration_file in MIGRATIONS_DIR.glob("*.sql"):
        (migrations_dir / migration_file.name).write_text(
            migration_file.read_text(encoding="utf-8"),
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


def test_runner_applies_new_database_in_order(tmp_path: Path) -> None:
    db_path = tmp_path / "new.db"

    result = apply_migrations(db_path, MIGRATIONS_DIR)

    with connect_database(db_path) as connection:
        assert result.applied_versions == [1, 2]
        assert result.baselined_versions == []
        assert _migration_versions(connection) == [1, 2]
        assert _table_exists(connection, "packet_capture_sessions")
        assert _table_exists(connection, "trust_score_history")


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


def test_runner_applies_only_002_to_existing_001_db_and_preserves_rows(
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
        assert result.applied_versions == [2]
        assert _migration_versions(connection) == [1, 2]
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
        assert first.applied_versions == [1, 2]
        assert second.applied_versions == []
        assert second.skipped_versions == [1, 2]
        assert _migration_versions(connection) == [1, 2]


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
        assert result.applied_versions == [2]
        assert _migration_versions(connection) == [1, 2]
        assert not _table_exists(connection, "retry_marker")
        assert _table_exists(connection, "packet_capture_sessions")
        assert "failed_retry_column" not in _column_names(
            connection,
            "detection_events",
        )
        assert connection.execute(
            "SELECT COUNT(*) AS count FROM schema_migrations WHERE version = 2"
        ).fetchone()["count"] == 1


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
                score_before,
                score_delta,
                score_after
            )
            VALUES ('esp32_01', '2026-07-16T10:00:00Z',
                    '2026-07-16T10:00:10Z', 50, -25, 25)
            """
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO trust_score_history (
                    device_id,
                    analysis_window_start,
                    analysis_window_end,
                    score_before,
                    score_delta,
                    score_after
                )
                VALUES ('esp32_01', '2026-07-16T10:00:00Z',
                        '2026-07-16T10:00:10Z', 25, 0, 25)
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
                (f"192.168.0.{10 + offset}", 1883 + offset, status),
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
            VALUES ('192.168.0.34', 'tcp', 1883, 'APPLIED')
            """
        )
        connection.execute(
            """
            INSERT INTO firewall_rules (source_ip, protocol, dest_port, status)
            VALUES ('192.168.0.34', 'tcp', 8000, 'PENDING')
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


def test_existing_trust_score_history_api_still_uses_detection_events(
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
            INSERT INTO detection_events (
                device_id,
                detector_type,
                event_type,
                severity,
                score_delta,
                applied_to_score,
                detected_at
            )
            VALUES ('esp32_01', 'RULE', 'ABNORMAL_PUBLISH_RATE',
                    'high', -20, 1, '2026-07-16T10:00:10Z')
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
        ).fetchone()["count"] == 0

    assert response.status_code == 200
    body = response.json()
    assert body["current_score"] == 80
    assert body["current_status"] == "normal"
    assert body["total"] == 1
    assert body["items"][0]["event_type"] == "ABNORMAL_PUBLISH_RATE"
    assert body["items"][0]["score_before"] == 100
    assert body["items"][0]["score_after"] == 80
