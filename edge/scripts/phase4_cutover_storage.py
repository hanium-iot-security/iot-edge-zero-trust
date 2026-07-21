"""SQLite safety and evidence helpers for the Phase 4 cutover workflow."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import sqlite3
from typing import Iterator, Mapping


class CutoverSafetyError(RuntimeError):
    """Raised when a cutover action violates an explicit safety contract."""


_DETECTION_EVENT_PRESERVED_COLUMNS = (
    "device_id",
    "feature_log_id",
    "mqtt_log_id",
    "packet_feature_log_id",
    "detector_type",
    "event_type",
    "severity",
    "score_delta",
    "description",
    "detected_at",
    "analysis_window_start",
    "analysis_window_end",
    "incident_family",
    "subject_ip",
    "evidence_json",
    "evidence_schema_version",
    "dedupe_key",
    "policy_version",
)


@dataclass(frozen=True)
class DatabaseVerification:
    integrity_check: str
    foreign_key_violations: tuple[tuple[object, ...], ...]


@dataclass(frozen=True)
class BackupArtifact:
    database_path: Path
    sha256_path: Path
    sha256: str
    integrity_check: str
    foreign_key_violations: tuple[tuple[object, ...], ...]


def _database_checks(database_path: Path) -> tuple[str, tuple[tuple[object, ...], ...]]:
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_key_rows = connection.execute("PRAGMA foreign_key_check").fetchall()
    return integrity, tuple(tuple(row) for row in foreign_key_rows)


def verify_database(database_path: str | Path) -> DatabaseVerification:
    path = Path(database_path).expanduser().resolve()
    if not path.is_file():
        raise CutoverSafetyError(f"Database does not exist: {path}")
    integrity, foreign_key_violations = _database_checks(path)
    return DatabaseVerification(
        integrity_check=integrity,
        foreign_key_violations=foreign_key_violations,
    )


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_backup_sha256(sha256_path: Path, backup_path: Path) -> str:
    parts = sha256_path.read_text(encoding="utf-8").strip().split()
    if len(parts) != 2 or parts[1] != backup_path.name:
        raise CutoverSafetyError("Invalid SHA256 manifest for the selected backup")
    return parts[0].lower()


def create_sqlite_backup(source_path: str | Path, backup_path: str | Path) -> BackupArtifact:
    """Create and verify a transactionally consistent SQLite backup."""

    source = Path(source_path).expanduser().resolve()
    backup = Path(backup_path).expanduser().resolve()
    if not source.is_file():
        raise CutoverSafetyError(f"Source database does not exist: {source}")
    if source == backup:
        raise CutoverSafetyError("Source and backup must use different paths")
    if backup.exists():
        raise CutoverSafetyError(f"Backup destination already exists: {backup}")
    sha256_path = backup.with_suffix(backup.suffix + ".sha256")
    if sha256_path.exists():
        raise CutoverSafetyError(f"SHA256 destination already exists: {sha256_path}")
    backup.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(source) as source_connection, sqlite3.connect(backup) as backup_connection:
        source_connection.backup(backup_connection)

    integrity, foreign_key_violations = _database_checks(backup)
    digest = file_sha256(backup)
    sha256_path.write_text(f"{digest}  {backup.name}\n", encoding="utf-8")
    return BackupArtifact(
        database_path=backup,
        sha256_path=sha256_path,
        sha256=digest,
        integrity_check=integrity,
        foreign_key_violations=foreign_key_violations,
    )


def restore_sqlite_backup(
    *,
    target_path: str | Path,
    backup_path: str | Path,
    sha256_path: str | Path,
) -> DatabaseVerification:
    """Verify a backup and restore it through SQLite's Backup API."""

    target = Path(target_path).expanduser().resolve()
    backup = Path(backup_path).expanduser().resolve()
    checksum_manifest = Path(sha256_path).expanduser().resolve()
    if target == backup:
        raise CutoverSafetyError("Target and backup must use different paths")

    expected = expected_backup_sha256(checksum_manifest, backup)
    actual = file_sha256(backup)
    if actual != expected:
        raise CutoverSafetyError("Backup SHA256 mismatch; refusing to restore")

    backup_integrity, backup_foreign_keys = _database_checks(backup)
    if backup_integrity != "ok" or backup_foreign_keys:
        raise CutoverSafetyError("Backup database failed integrity or foreign-key checks")

    target.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(backup) as backup_connection, sqlite3.connect(target) as target_connection:
        backup_connection.backup(target_connection)

    integrity, foreign_key_violations = _database_checks(target)
    if integrity != "ok" or foreign_key_violations:
        raise CutoverSafetyError("Restored database failed integrity or foreign-key checks")
    return DatabaseVerification(
        integrity_check=integrity,
        foreign_key_violations=foreign_key_violations,
    )


def table_row_counts(database: Path) -> Mapping[str, int]:
    with sqlite3.connect(database) as connection:
        tables = [
            str(row[0])
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            ).fetchall()
        ]
        return {
            table: int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            for table in tables
        }


def _optional_scalar(database: Path, query: str) -> object | None:
    try:
        with sqlite3.connect(database) as connection:
            row = connection.execute(query).fetchone()
    except sqlite3.OperationalError:
        return None
    return row[0] if row is not None else None


def _id_digest(database: Path, table: str) -> str | None:
    try:
        with sqlite3.connect(database) as connection:
            ids = [
                str(row[0])
                for row in connection.execute(f'SELECT id FROM "{table}" ORDER BY id')
            ]
    except sqlite3.OperationalError:
        return None
    return hashlib.sha256(",".join(ids).encode("utf-8")).hexdigest()


def _optional_ids(database: Path, table: str) -> tuple[int, ...] | None:
    try:
        with sqlite3.connect(database) as connection:
            return tuple(
                int(row[0])
                for row in connection.execute(f'SELECT id FROM "{table}" ORDER BY id')
            )
    except sqlite3.OperationalError:
        return None


def _optional_detection_event_rows(
    database: Path,
) -> Mapping[int, Mapping[str, object]] | None:
    try:
        with sqlite3.connect(database) as connection:
            available_columns = {
                str(row[1])
                for row in connection.execute(
                    'PRAGMA table_info("detection_events")'
                ).fetchall()
            }
            if "id" not in available_columns:
                return None
            preserved_columns = [
                column
                for column in _DETECTION_EVENT_PRESERVED_COLUMNS
                if column in available_columns
            ]
            selected_columns = ["id", *preserved_columns]
            rows = connection.execute(
                "SELECT "
                + ", ".join(f'"{column}"' for column in selected_columns)
                + ' FROM "detection_events" ORDER BY id'
            ).fetchall()
    except sqlite3.OperationalError:
        return None
    return {
        int(row[0]): {
            column: row[index]
            for index, column in enumerate(preserved_columns, start=1)
        }
        for row in rows
    }


def database_evidence(database: Path) -> Mapping[str, object]:
    return {
        "table_row_counts": table_row_counts(database),
        "segment_count": _optional_scalar(
            database, "SELECT COUNT(*) FROM packet_capture_segments"
        ),
        "segment_id_digest": _id_digest(database, "packet_capture_segments"),
        "packet_feature_count": _optional_scalar(
            database, "SELECT COUNT(*) FROM packet_feature_logs"
        ),
        "orphan_packet_feature_fk_count": _optional_scalar(
            database,
            """
            SELECT COUNT(*)
            FROM packet_feature_logs AS feature
            LEFT JOIN packet_capture_segments AS segment
              ON segment.id = feature.capture_segment_id
            WHERE segment.id IS NULL
            """,
        ),
        "detection_event_count": _optional_scalar(
            database, "SELECT COUNT(*) FROM detection_events"
        ),
        "detection_event_ids": _optional_ids(database, "detection_events"),
        "detection_event_rows": _optional_detection_event_rows(database),
    }


def validate_data_preservation(
    before: Mapping[str, object],
    after: Mapping[str, object],
) -> None:
    """Reject destructive Migration changes to existing Phase 3-B data."""

    errors: list[str] = []

    segment_count_before = before.get("segment_count")
    if segment_count_before is not None:
        if after.get("segment_count") != segment_count_before:
            errors.append("packet capture segment rows changed")
        if after.get("segment_id_digest") != before.get("segment_id_digest"):
            errors.append("packet capture segment IDs changed")

    feature_count_before = before.get("packet_feature_count")
    if feature_count_before is not None:
        feature_count_after = after.get("packet_feature_count")
        if feature_count_after is None:
            errors.append("packet feature rows decreased")
        elif int(feature_count_after) != int(feature_count_before):
            if int(feature_count_after) < int(feature_count_before):
                errors.append("packet feature rows decreased")
            else:
                errors.append("packet feature rows changed")
        orphan_count = after.get("orphan_packet_feature_fk_count")
        if orphan_count is None or int(orphan_count) != 0:
            errors.append("orphan packet feature foreign keys were created")

    event_count_before = before.get("detection_event_count")
    if event_count_before is not None:
        event_count_after = after.get("detection_event_count")
        if event_count_after is None or int(event_count_after) < int(event_count_before):
            errors.append("detection event rows decreased")
        event_ids_before = before.get("detection_event_ids")
        event_ids_after = after.get("detection_event_ids")
        if isinstance(event_ids_before, (tuple, list)):
            if not isinstance(event_ids_after, (tuple, list)) or not set(
                event_ids_before
            ).issubset(event_ids_after):
                errors.append("detection event IDs were removed")
        event_rows_before = before.get("detection_event_rows")
        event_rows_after = after.get("detection_event_rows")
        if isinstance(event_rows_before, Mapping):
            if not isinstance(event_rows_after, Mapping):
                errors.append("detection event evidence is unavailable")
            else:
                for event_id, values_before in event_rows_before.items():
                    values_after = event_rows_after.get(event_id)
                    if values_after is None:
                        continue
                    changed_fields = [
                        field
                        for field, value_before in values_before.items()
                        if field not in values_after
                        or values_after[field] != value_before
                    ]
                    if changed_fields:
                        errors.append(
                            "existing detection event values changed: "
                            f"id={event_id}, fields={changed_fields}"
                        )
                new_event_ids = set(event_rows_after) - set(event_rows_before)
                non_legacy_ids = [
                    event_id
                    for event_id in sorted(new_event_ids)
                    if event_rows_after[event_id].get("event_type")
                    != "LEGACY_MIGRATION"
                ]
                if non_legacy_ids:
                    errors.append(
                        "non-LEGACY_MIGRATION detection events were added: "
                        f"ids={non_legacy_ids}"
                    )

    table_counts_before = before.get("table_row_counts")
    table_counts_after = after.get("table_row_counts")
    if isinstance(table_counts_before, Mapping) and isinstance(table_counts_after, Mapping):
        for table, count_before in table_counts_before.items():
            count_after = table_counts_after.get(table)
            if count_after is None or int(count_after) < int(count_before):
                errors.append(f'existing table rows decreased: "{table}"')

    if errors:
        raise CutoverSafetyError("Data preservation check failed: " + "; ".join(errors))


@contextmanager
def operation_lock(database: Path) -> Iterator[None]:
    lock_path = database.with_suffix(database.suffix + ".phase4.lock")
    if os.name == "posix":
        import fcntl

        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+", encoding="ascii") as lock_file:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise CutoverSafetyError(
                    f"Another Phase 4 operation holds the lock: {lock_path}"
                ) from exc
            lock_file.seek(0)
            lock_file.truncate()
            lock_file.write(f"pid={os.getpid()}\n")
            lock_file.flush()
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        return

    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise CutoverSafetyError(
            f"Another Phase 4 operation holds the lock: {lock_path}"
        ) from exc
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.close(descriptor)
        yield
    finally:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass
