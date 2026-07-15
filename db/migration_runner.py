"""SQLite schema migration runner."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
from pathlib import Path
import re
import sqlite3


DB_PATH = Path("backend/data/iot_security.db")
MIGRATIONS_DIR = Path("db/migrations")
SCHEMA_MIGRATIONS_TABLE = "schema_migrations"
MIGRATION_FILE_PATTERN = re.compile(r"^(?P<version>\d+)_(?P<name>[A-Za-z0-9_]+)\.sql$")
LEGACY_001_TABLES = {
    "devices",
    "mqtt_logs",
    "feature_logs",
    "detection_events",
    "isolation_history",
}
LEGACY_001_REQUIRED_COLUMNS = {
    "devices": {
        "device_id",
        "ip_address",
        "status",
        "trust_score",
        "last_seen_at",
        "created_at",
    },
    "mqtt_logs": {
        "id",
        "device_id",
        "topic",
        "payload",
        "payload_size",
        "received_at",
        "is_json_valid",
        "is_topic_valid",
        "error_message",
    },
    "feature_logs": {
        "id",
        "device_id",
        "window_start",
        "window_end",
        "publish_count",
        "avg_payload_size",
        "max_payload_size",
        "avg_message_interval",
        "min_message_interval",
        "topic_count",
        "abnormal_topic_count",
        "malformed_payload_count",
    },
    "detection_events": {
        "id",
        "device_id",
        "feature_log_id",
        "mqtt_log_id",
        "detector_type",
        "event_type",
        "severity",
        "score_delta",
        "applied_to_score",
        "description",
        "detected_at",
    },
    "isolation_history": {
        "id",
        "device_id",
        "action",
        "reason",
        "trust_score",
        "trigger_event_id",
        "created_at",
    },
}

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: Path


@dataclass
class MigrationResult:
    applied_versions: list[int] = field(default_factory=list)
    skipped_versions: list[int] = field(default_factory=list)
    baselined_versions: list[int] = field(default_factory=list)


class MigrationError(RuntimeError):
    """Raised when a migration cannot be applied atomically."""


@dataclass(frozen=True)
class Legacy001Inspection:
    existing_tables: set[str]
    missing_tables: set[str]
    missing_columns: dict[str, set[str]]

    @property
    def is_empty(self) -> bool:
        return not self.existing_tables

    @property
    def is_complete(self) -> bool:
        return not self.missing_tables and not self.missing_columns


def connect_database(db_path: str | Path = DB_PATH) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.isolation_level = None
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON;")
    connection.execute("PRAGMA busy_timeout = 5000;")
    connection.execute("PRAGMA journal_mode = WAL;")
    return connection


def discover_migrations(migrations_dir: str | Path = MIGRATIONS_DIR) -> list[Migration]:
    migrations: list[Migration] = []
    seen_versions: set[int] = set()

    for path in Path(migrations_dir).glob("*.sql"):
        match = MIGRATION_FILE_PATTERN.match(path.name)
        if match is None:
            continue

        version = int(match.group("version"))
        if version in seen_versions:
            raise MigrationError(f"Duplicate migration version: {version}")
        seen_versions.add(version)
        migrations.append(
            Migration(
                version=version,
                name=match.group("name"),
                path=path,
            )
        )

    return sorted(migrations, key=lambda migration: migration.version)


def apply_migrations(
    db_path: str | Path = DB_PATH,
    migrations_dir: str | Path = MIGRATIONS_DIR,
) -> MigrationResult:
    migrations = discover_migrations(migrations_dir)
    result = MigrationResult()

    with connect_database(db_path) as connection:
        legacy_001_inspection = _inspect_legacy_001_schema(connection)
        if not legacy_001_inspection.is_empty and not legacy_001_inspection.is_complete:
            raise MigrationError(_format_legacy_001_error(legacy_001_inspection))

        _ensure_schema_migrations_table(connection)
        applied_versions = _fetch_applied_versions(connection)
        applied_versions.update(
            _baseline_legacy_001_if_needed(
                connection,
                migrations,
                applied_versions,
                result,
                legacy_001_inspection,
            )
        )

        for migration in migrations:
            if migration.version in applied_versions:
                result.skipped_versions.append(migration.version)
                logger.info("Skipping already applied migration %03d_%s", migration.version, migration.name)
                continue

            _apply_single_migration(connection, migration)
            applied_versions.add(migration.version)
            result.applied_versions.append(migration.version)

    return result


def _ensure_schema_migrations_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def _fetch_applied_versions(connection: sqlite3.Connection) -> set[int]:
    rows = connection.execute(
        """
        SELECT version
        FROM schema_migrations
        ORDER BY version
        """
    ).fetchall()
    return {int(row["version"]) for row in rows}


def _baseline_legacy_001_if_needed(
    connection: sqlite3.Connection,
    migrations: list[Migration],
    applied_versions: set[int],
    result: MigrationResult,
    inspection: Legacy001Inspection,
) -> set[int]:
    if 1 in applied_versions:
        return set()

    migration_001 = next((migration for migration in migrations if migration.version == 1), None)
    if migration_001 is None:
        return set()

    if inspection.is_empty:
        return set()

    connection.execute(
        """
        INSERT INTO schema_migrations (version, name)
        VALUES (?, ?)
        """,
        (migration_001.version, migration_001.name),
    )
    result.baselined_versions.append(migration_001.version)
    logger.info("Baselined existing 001 schema without re-running 001_init.sql")
    return {migration_001.version}


def _inspect_legacy_001_schema(connection: sqlite3.Connection) -> Legacy001Inspection:
    rows = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name IN ({})
        """.format(",".join("?" for _ in LEGACY_001_TABLES)),
        tuple(LEGACY_001_TABLES),
    ).fetchall()
    existing_tables = {row["name"] for row in rows}
    missing_tables = LEGACY_001_TABLES - existing_tables
    missing_columns: dict[str, set[str]] = {}

    for table_name in sorted(existing_tables):
        existing_columns = _column_names(connection, table_name)
        required_columns = LEGACY_001_REQUIRED_COLUMNS[table_name]
        table_missing_columns = required_columns - existing_columns
        if table_missing_columns:
            missing_columns[table_name] = table_missing_columns

    return Legacy001Inspection(
        existing_tables=existing_tables,
        missing_tables=missing_tables,
        missing_columns=missing_columns,
    )


def _column_names(connection: sqlite3.Connection, table_name: str) -> set[str]:
    rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


def _format_legacy_001_error(inspection: Legacy001Inspection) -> str:
    parts = ["Incomplete legacy 001 schema; refusing to baseline or auto-repair."]
    if inspection.missing_tables:
        parts.append(f"missing_tables={sorted(inspection.missing_tables)}")
    if inspection.missing_columns:
        missing_columns = {
            table_name: sorted(columns)
            for table_name, columns in sorted(inspection.missing_columns.items())
        }
        parts.append(f"missing_columns={missing_columns}")
    return " ".join(parts)


def _apply_single_migration(connection: sqlite3.Connection, migration: Migration) -> None:
    logger.info("Applying migration %03d_%s", migration.version, migration.name)
    statements = list(_iter_sql_statements(migration.path.read_text(encoding="utf-8")))

    connection.execute("BEGIN;")
    try:
        for statement in statements:
            connection.execute(statement)
        connection.execute(
            """
            INSERT INTO schema_migrations (version, name)
            VALUES (?, ?)
            """,
            (migration.version, migration.name),
        )
        connection.execute("COMMIT;")
    except sqlite3.Error as exc:
        connection.execute("ROLLBACK;")
        logger.exception("Failed to apply migration %03d_%s", migration.version, migration.name)
        raise MigrationError(
            f"Failed to apply migration {migration.version:03d}_{migration.name}: {exc}"
        ) from exc


def _iter_sql_statements(sql_script: str):
    buffer: list[str] = []
    for line in sql_script.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue

        buffer.append(line)
        candidate = "\n".join(buffer).strip()
        if sqlite3.complete_statement(candidate):
            yield candidate
            buffer.clear()

    trailing = "\n".join(buffer).strip()
    if trailing:
        raise MigrationError("Incomplete SQL statement at end of migration file")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    result = apply_migrations()
    print(
        "Migrations complete: "
        f"applied={result.applied_versions}, "
        f"skipped={result.skipped_versions}, "
        f"baselined={result.baselined_versions}"
    )


if __name__ == "__main__":
    main()
