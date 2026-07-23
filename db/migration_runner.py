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
FOREIGN_KEY_REBUILD_MIGRATIONS = {(3, "phase4_detection")}
LEGACY_001_TABLES = {
    "devices",
    "mqtt_logs",
    "feature_logs",
    "detection_events",
    "isolation_history",
}
LEGACY_001_COLUMN_SIGNATURES = {
    "devices": {
        "device_id": {"type": "TEXT", "pk": 1},
        "status": {"type": "TEXT", "notnull": 1},
        "trust_score": {"type": "INTEGER", "notnull": 1},
    },
    "mqtt_logs": {
        "id": {"type": "INTEGER", "pk": 1},
        "topic": {"type": "TEXT", "notnull": 1},
        "is_json_valid": {"type": "INTEGER", "notnull": 1},
        "is_topic_valid": {"type": "INTEGER", "notnull": 1},
    },
    "feature_logs": {
        "id": {"type": "INTEGER", "pk": 1},
        "device_id": {"type": "TEXT", "notnull": 1},
        "window_start": {"type": "DATETIME", "notnull": 1},
        "window_end": {"type": "DATETIME", "notnull": 1},
        "publish_count": {"type": "INTEGER", "notnull": 1},
    },
    "detection_events": {
        "id": {"type": "INTEGER", "pk": 1},
        "detector_type": {"type": "TEXT", "notnull": 1},
        "event_type": {"type": "TEXT", "notnull": 1},
        "score_delta": {"type": "INTEGER", "notnull": 1},
        "applied_to_score": {"type": "INTEGER", "notnull": 1},
    },
    "isolation_history": {
        "id": {"type": "INTEGER", "pk": 1},
        "device_id": {"type": "TEXT", "notnull": 1},
        "action": {"type": "TEXT", "notnull": 1},
    },
}
LEGACY_001_UNIQUE_CONSTRAINTS = {
    "feature_logs": [
        ("device_id", "window_start", "window_end"),
    ],
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
    column_definition_mismatches: dict[str, list[str]] = field(default_factory=dict)
    missing_unique_constraints: dict[str, list[tuple[str, ...]]] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return not self.existing_tables

    @property
    def is_complete(self) -> bool:
        return (
            not self.missing_tables
            and not self.missing_columns
            and not self.column_definition_mismatches
            and not self.missing_unique_constraints
        )


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
    migrations_path = Path(migrations_dir)
    if not migrations_path.exists():
        raise MigrationError(f"Migration directory does not exist: {migrations_path}")
    if not migrations_path.is_dir():
        raise MigrationError(f"Migration path is not a directory: {migrations_path}")

    sql_paths = sorted(migrations_path.glob("*.sql"))
    if not sql_paths:
        raise MigrationError(f"No migration SQL files found: {migrations_path}")

    migrations: list[Migration] = []
    seen_versions: set[int] = set()

    for path in sql_paths:
        match = MIGRATION_FILE_PATTERN.match(path.name)
        if match is None:
            raise MigrationError(f"Invalid migration file name: {path.name}")

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

    sorted_migrations = sorted(migrations, key=lambda migration: migration.version)
    for expected_version, migration in enumerate(sorted_migrations, start=1):
        if migration.version != expected_version:
            raise MigrationError(f"Missing migration version: {expected_version}")
        _validate_migration_has_statements(migration)

    return sorted_migrations


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
        _validate_applied_migration_files_present(applied_versions, migrations)
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


def _validate_applied_migration_files_present(
    applied_versions: set[int],
    migrations: list[Migration],
) -> None:
    migration_versions = {migration.version for migration in migrations}
    missing_applied_versions = sorted(applied_versions - migration_versions)
    if missing_applied_versions:
        raise MigrationError(
            "Applied migration files are missing from the current branch: "
            f"{missing_applied_versions}"
        )


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
    column_definition_mismatches: dict[str, list[str]] = {}
    missing_unique_constraints: dict[str, list[tuple[str, ...]]] = {}

    for table_name in sorted(existing_tables):
        column_rows = _column_info_by_name(connection, table_name)
        existing_columns = set(column_rows)
        required_columns = set(LEGACY_001_COLUMN_SIGNATURES[table_name])
        table_missing_columns = required_columns - existing_columns
        if table_missing_columns:
            missing_columns[table_name] = table_missing_columns
        table_mismatches = _column_signature_mismatches(
            table_name,
            column_rows,
            table_missing_columns,
        )
        if table_mismatches:
            column_definition_mismatches[table_name] = table_mismatches

        for unique_columns in LEGACY_001_UNIQUE_CONSTRAINTS.get(table_name, []):
            if not _has_unique_constraint(connection, table_name, unique_columns):
                missing_unique_constraints.setdefault(table_name, []).append(unique_columns)

    return Legacy001Inspection(
        existing_tables=existing_tables,
        missing_tables=missing_tables,
        missing_columns=missing_columns,
        column_definition_mismatches=column_definition_mismatches,
        missing_unique_constraints=missing_unique_constraints,
    )


def _column_info_by_name(
    connection: sqlite3.Connection,
    table_name: str,
) -> dict[str, sqlite3.Row]:
    rows = connection.execute(f"PRAGMA table_info({_quote_identifier(table_name)})").fetchall()
    return {row["name"]: row for row in rows}


def _column_names(connection: sqlite3.Connection, table_name: str) -> set[str]:
    rows = connection.execute(f"PRAGMA table_info({_quote_identifier(table_name)})").fetchall()
    return {row["name"] for row in rows}


def _column_signature_mismatches(
    table_name: str,
    column_rows: dict[str, sqlite3.Row],
    missing_columns: set[str],
) -> list[str]:
    mismatches: list[str] = []
    for column_name, expected_signature in LEGACY_001_COLUMN_SIGNATURES[table_name].items():
        if column_name in missing_columns:
            continue

        row = column_rows[column_name]
        expected_type = expected_signature.get("type")
        if expected_type is not None:
            actual_type = _normalize_sqlite_type(row["type"])
            if actual_type != expected_type:
                mismatches.append(
                    f"{table_name}.{column_name} expected type={expected_type} "
                    f"actual type={actual_type or '<empty>'}"
                )

        expected_notnull = expected_signature.get("notnull")
        if expected_notnull is not None and int(row["notnull"]) != expected_notnull:
            mismatches.append(
                f"{table_name}.{column_name} expected notnull={expected_notnull} "
                f"actual notnull={int(row['notnull'])}"
            )

        expected_pk = expected_signature.get("pk")
        if expected_pk is not None and int(row["pk"]) != expected_pk:
            mismatches.append(
                f"{table_name}.{column_name} expected pk={expected_pk} "
                f"actual pk={int(row['pk'])}"
            )

    return mismatches


def _normalize_sqlite_type(column_type: str | None) -> str:
    return (column_type or "").strip().upper()


def _has_unique_constraint(
    connection: sqlite3.Connection,
    table_name: str,
    expected_columns: tuple[str, ...],
) -> bool:
    indexes = connection.execute(f"PRAGMA index_list({_quote_identifier(table_name)})").fetchall()
    for index in indexes:
        if int(index["unique"]) != 1:
            continue
        columns = connection.execute(
            f"PRAGMA index_info({_quote_identifier(index['name'])})"
        ).fetchall()
        indexed_columns = tuple(column["name"] for column in columns)
        if indexed_columns == expected_columns:
            return True
    return False


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


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
    if inspection.column_definition_mismatches:
        parts.append(
            "column_definition_mismatches="
            f"{dict(sorted(inspection.column_definition_mismatches.items()))}"
        )
    if inspection.missing_unique_constraints:
        missing_unique_constraints = {
            table_name: [list(columns) for columns in constraints]
            for table_name, constraints in sorted(
                inspection.missing_unique_constraints.items()
            )
        }
        parts.append(f"missing_unique_constraints={missing_unique_constraints}")
    return " ".join(parts)


def _apply_single_migration(connection: sqlite3.Connection, migration: Migration) -> None:
    logger.info("Applying migration %03d_%s", migration.version, migration.name)
    statements = list(_iter_sql_statements(migration.path.read_text(encoding="utf-8")))
    if (migration.version, migration.name) in FOREIGN_KEY_REBUILD_MIGRATIONS:
        _apply_single_migration_with_foreign_keys_off(connection, migration, statements)
        return

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


def _apply_single_migration_with_foreign_keys_off(
    connection: sqlite3.Connection,
    migration: Migration,
    statements: list[str],
) -> None:
    original_foreign_keys = int(connection.execute("PRAGMA foreign_keys").fetchone()[0])
    connection.execute("PRAGMA foreign_keys = OFF;")
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
        _assert_database_checks_pass(connection)
        connection.execute("COMMIT;")
    except sqlite3.Error as exc:
        connection.execute("ROLLBACK;")
        logger.exception("Failed to apply migration %03d_%s", migration.version, migration.name)
        raise MigrationError(
            f"Failed to apply migration {migration.version:03d}_{migration.name}: {exc}"
        ) from exc
    except Exception:
        connection.execute("ROLLBACK;")
        raise
    finally:
        connection.execute(
            f"PRAGMA foreign_keys = {'ON' if original_foreign_keys else 'OFF'};"
        )


def _assert_database_checks_pass(connection: sqlite3.Connection) -> None:
    foreign_key_violations = connection.execute("PRAGMA foreign_key_check").fetchall()
    if foreign_key_violations:
        raise MigrationError(
            f"foreign_key_check failed with {len(foreign_key_violations)} violation(s)"
        )

    integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
    integrity_errors = [row[0] for row in integrity_rows if row[0] != "ok"]
    if integrity_errors:
        raise MigrationError(f"integrity_check failed: {integrity_errors}")


def _validate_migration_has_statements(migration: Migration) -> None:
    try:
        statements = list(_iter_sql_statements(migration.path.read_text(encoding="utf-8")))
    except MigrationError as exc:
        raise MigrationError(f"{migration.path.name}: {exc}") from exc

    if not statements:
        raise MigrationError(
            f"Migration file has no executable SQL statements: {migration.path.name}"
        )


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
