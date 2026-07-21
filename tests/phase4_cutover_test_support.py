from __future__ import annotations

from pathlib import Path
import sqlite3


CHECKPOINT_KEYS = (
    "mqtt_feature_builder+mqtt_logs",
    "mqtt_feature_rule+feature_logs",
    "mqtt_message_rule+mqtt_logs",
    "mqtt_if+feature_logs",
    "packet_rule+packet_feature_logs",
    "packet_if+packet_feature_logs",
    "trust_score_v2+detection_events",
)


def complete_checkpoint_summary() -> dict[str, object]:
    return {
        "legacy_migration_event_count": 0,
        "checkpoints": {
            key: {
                "last_processed_id": None,
                "last_completed_window_end": "2026-07-21T04:30:00Z",
            }
            for key in CHECKPOINT_KEYS
        },
    }


def create_source_database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
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
            ((1, "init"), (2, "packet_gateway")),
        )
        connection.execute(
            """
            CREATE TABLE parent (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE child (
                id INTEGER PRIMARY KEY,
                parent_id INTEGER NOT NULL REFERENCES parent(id)
            )
            """
        )
        connection.execute("INSERT INTO parent (id, name) VALUES (1, 'before-cutover')")
        connection.execute("INSERT INTO child (id, parent_id) VALUES (1, 1)")
        connection.execute(
            """
            CREATE TABLE detector_checkpoints (
                detector_name TEXT NOT NULL,
                source_table TEXT NOT NULL,
                last_processed_id INTEGER,
                last_completed_window_end DATETIME,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (detector_name, source_table)
            )
            """
        )
        for table_name in (
            "devices",
            "mqtt_logs",
            "feature_logs",
            "isolation_history",
            "packet_capture_sessions",
            "gateway_metrics",
            "trust_score_history",
            "firewall_rules",
        ):
            connection.execute(
                f'CREATE TABLE "{table_name}" (id INTEGER PRIMARY KEY)'
            )
        connection.execute(
            """
            CREATE TABLE packet_capture_segments (
                id INTEGER PRIMARY KEY,
                status TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE packet_feature_logs (
                id INTEGER PRIMARY KEY,
                capture_segment_id INTEGER
                    REFERENCES packet_capture_segments(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE detection_events (
                id INTEGER PRIMARY KEY,
                detector_type TEXT,
                event_type TEXT,
                severity TEXT,
                score_delta INTEGER,
                description TEXT
            )
            """
        )


def create_migration_set(directory: Path) -> None:
    directory.mkdir(parents=True)
    for version, name in (
        (1, "init"),
        (2, "packet_gateway"),
        (3, "phase4_detection"),
    ):
        (directory / f"{version:03d}_{name}.sql").write_text(
            f"CREATE TABLE migration_{version} (id INTEGER);\n",
            encoding="utf-8",
        )


def persist_checkpoint_summary(
    database: Path,
    summary: dict[str, object] | None = None,
) -> dict[str, object]:
    result = summary or complete_checkpoint_summary()
    checkpoints = result["checkpoints"]
    assert isinstance(checkpoints, dict)
    with sqlite3.connect(database) as connection:
        for key, value in checkpoints.items():
            assert isinstance(value, dict)
            detector_name, source_table = key.split("+", 1)
            connection.execute(
                """
                INSERT OR REPLACE INTO detector_checkpoints (
                    detector_name,
                    source_table,
                    last_processed_id,
                    last_completed_window_end
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    detector_name,
                    source_table,
                    value["last_processed_id"],
                    value["last_completed_window_end"],
                ),
            )
    return result


def create_phase3b_evidence_tables(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "INSERT INTO packet_capture_segments (id, status) VALUES (10, 'PROCESSED')"
        )
        connection.execute(
            "INSERT INTO packet_feature_logs (id, capture_segment_id) VALUES (20, 10)"
        )
        connection.execute(
            """
            INSERT INTO detection_events (
                id,
                detector_type,
                event_type,
                severity,
                score_delta,
                description
            ) VALUES (30, 'RULE', 'LEGACY', 'high', -20, 'existing event')
            """
        )
