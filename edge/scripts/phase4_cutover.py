"""Safety primitives shared by the Phase 4 cutover and rollback CLIs."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import date, datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Callable, Iterator, Mapping


EXPECTED_CHECKPOINT_KEYS = frozenset(
    {
        "mqtt_feature_builder+mqtt_logs",
        "mqtt_feature_rule+feature_logs",
        "mqtt_message_rule+mqtt_logs",
        "mqtt_if+feature_logs",
        "packet_rule+packet_feature_logs",
        "packet_if+packet_feature_logs",
        "trust_score_v2+detection_events",
    }
)


class CutoverSafetyError(RuntimeError):
    """Raised when a cutover action violates an explicit safety contract."""


class CutoverExecutionError(RuntimeError):
    """Raised after a failed cutover has attempted its rollback path."""


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


@dataclass(frozen=True)
class CutoverConfig:
    database_path: Path
    backup_directory: Path
    migrations_directory: Path
    result_path: Path
    git_sha: str
    legacy_services: tuple[str, ...] = ()
    new_services: tuple[str, ...] = ()
    paused_writer_services: tuple[str, ...] = ()


@dataclass(frozen=True)
class CutoverDependencies:
    stop_service: Callable[[str], None]
    start_service: Callable[[str], None]
    is_service_active: Callable[[str], bool]
    apply_migrations: Callable[[Path, Path], object]
    initialize_checkpoints: Callable[[Path, datetime], Mapping[str, object]]
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)


@dataclass(frozen=True)
class CutoverReport:
    status: str
    git_sha: str
    phase4_cutover_at: str
    database_path: str
    backup_database: str | None
    backup_sha256_path: str | None
    backup_sha256: str | None
    integrity_check: str | None
    foreign_key_violations: tuple[tuple[object, ...], ...] = ()
    migration_summary: Mapping[str, object] = field(default_factory=dict)
    checkpoint_summary: Mapping[str, object] = field(default_factory=dict)
    legacy_services: tuple[str, ...] = ()
    new_services: tuple[str, ...] = ()
    paused_writer_services: tuple[str, ...] = ()
    services_before: Mapping[str, bool] = field(default_factory=dict)
    services_after: Mapping[str, bool] = field(default_factory=dict)
    failure_stage: str | None = None
    error: str | None = None
    rollback_verification: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class SmokeTestConfig:
    source_database_path: Path
    smoke_database_path: Path
    migrations_directory: Path
    result_path: Path
    git_sha: str


@dataclass(frozen=True)
class SmokeTestReport:
    status: str
    mode: str
    git_sha: str
    phase4_cutover_at: str
    source_database: str
    smoke_database: str
    source_sha256_before: str
    source_sha256_after: str | None
    source_unchanged: bool | None
    source_table_row_counts_before: Mapping[str, int]
    source_table_row_counts_after: Mapping[str, int]
    smoke_sha256_before_migration: str
    smoke_sha256_after_migration: str | None
    smoke_pre_migration_sha256_path: str
    smoke_post_migration_sha256_path: str | None
    integrity_check: str | None
    foreign_key_violations: tuple[tuple[object, ...], ...]
    migration_summary: Mapping[str, object]
    checkpoint_summary: Mapping[str, object]
    database_evidence: Mapping[str, object] = field(default_factory=dict)
    failure_stage: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class RollbackConfig:
    database_path: Path
    backup_path: Path
    sha256_path: Path
    result_path: Path
    git_sha: str
    backup_directory: Path | None = None
    legacy_services: tuple[str, ...] = ()
    new_services: tuple[str, ...] = ()
    paused_writer_services: tuple[str, ...] = ()


@dataclass(frozen=True)
class RollbackDependencies:
    stop_service: Callable[[str], None]
    start_service: Callable[[str], None]
    is_service_active: Callable[[str], bool]
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)


@dataclass(frozen=True)
class RollbackReport:
    status: str
    git_sha: str
    rolled_back_at: str
    database_path: str
    backup_path: str
    restored_backup_sha256: str | None
    pre_rollback_backup: str | None
    pre_rollback_sha256_path: str | None
    integrity_check: str | None
    foreign_key_violations: tuple[tuple[object, ...], ...]
    legacy_services: tuple[str, ...]
    new_services: tuple[str, ...]
    paused_writer_services: tuple[str, ...]
    services_before: Mapping[str, bool] = field(default_factory=dict)
    services_after: Mapping[str, bool] = field(default_factory=dict)
    failure_stage: str | None = None
    error: str | None = None


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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expected_sha256(sha256_path: Path, backup_path: Path) -> str:
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
    digest = _sha256_file(backup)
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

    expected = _expected_sha256(checksum_manifest, backup)
    actual = _sha256_file(backup)
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


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CutoverSafetyError("Cutover timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _summary(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    result: dict[str, object] = {}
    for name in ("applied_versions", "skipped_versions", "baselined_versions"):
        if hasattr(value, name):
            result[name] = list(getattr(value, name))
    return result


def _validate_migration_summary(summary: Mapping[str, object]) -> None:
    applied = {int(version) for version in summary.get("applied_versions", [])}
    skipped = {int(version) for version in summary.get("skipped_versions", [])}
    if 3 not in applied | skipped:
        raise CutoverSafetyError("Migration 003 was neither applied nor already present")


def _validate_checkpoint_summary(summary: Mapping[str, object]) -> None:
    checkpoints = summary.get("checkpoints")
    if not isinstance(checkpoints, Mapping):
        raise CutoverSafetyError("Cutover checkpoint keys are missing")
    actual_keys = set(checkpoints)
    if actual_keys != EXPECTED_CHECKPOINT_KEYS:
        missing = sorted(EXPECTED_CHECKPOINT_KEYS - actual_keys)
        unexpected = sorted(actual_keys - EXPECTED_CHECKPOINT_KEYS)
        raise CutoverSafetyError(
            f"Cutover checkpoint keys are incomplete: missing={missing}, unexpected={unexpected}"
        )
    for key, checkpoint in checkpoints.items():
        if not isinstance(checkpoint, Mapping):
            raise CutoverSafetyError(f"Checkpoint result must be an object: {key}")
        required_fields = {"last_processed_id", "last_completed_window_end"}
        missing_fields = required_fields - set(checkpoint)
        if missing_fields:
            raise CutoverSafetyError(
                f"Checkpoint result is missing fields for {key}: {sorted(missing_fields)}"
            )
        last_processed_id = checkpoint["last_processed_id"]
        if (
            last_processed_id is not None
            and (
                isinstance(last_processed_id, bool)
                or not isinstance(last_processed_id, int)
                or last_processed_id < 0
            )
        ):
            raise CutoverSafetyError(
                f"Checkpoint last_processed_id must be null or a non-negative integer: {key}"
            )
        _normalize_checkpoint_window(checkpoint["last_completed_window_end"], key)
    legacy_count = summary.get("legacy_migration_event_count")
    if not isinstance(legacy_count, int) or legacy_count < 0:
        raise CutoverSafetyError(
            "Checkpoint summary requires a non-negative legacy_migration_event_count"
        )


def _normalize_checkpoint_window(value: object, key: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return _utc_iso(value)
    if not isinstance(value, str):
        raise CutoverSafetyError(
            f"Checkpoint last_completed_window_end must be null or UTC ISO text: {key}"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CutoverSafetyError(
            f"Checkpoint last_completed_window_end is invalid: {key}"
        ) from exc
    return _utc_iso(parsed)


def _checkpoint_rows(database: Path) -> Mapping[str, Mapping[str, object]]:
    with sqlite3.connect(database) as connection:
        table_exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='detector_checkpoints'"
        ).fetchone()
        if table_exists is None:
            raise CutoverSafetyError("detector_checkpoints table is missing")
        rows = connection.execute(
            """
            SELECT detector_name, source_table, last_processed_id, last_completed_window_end
            FROM detector_checkpoints
            """
        ).fetchall()
    return {
        f"{detector_name}+{source_table}": {
            "last_processed_id": last_processed_id,
            "last_completed_window_end": _normalize_checkpoint_window(
                last_completed_window_end,
                f"{detector_name}+{source_table}",
            ),
        }
        for detector_name, source_table, last_processed_id, last_completed_window_end in rows
    }


def _validate_checkpoint_database(
    database: Path,
    summary: Mapping[str, object],
) -> None:
    checkpoints = summary["checkpoints"]
    assert isinstance(checkpoints, Mapping)
    expected = {
        str(key): {
            "last_processed_id": value["last_processed_id"],
            "last_completed_window_end": _normalize_checkpoint_window(
                value["last_completed_window_end"], str(key)
            ),
        }
        for key, value in checkpoints.items()
        if isinstance(value, Mapping)
    }
    actual = _checkpoint_rows(database)
    selected_actual = {key: actual[key] for key in expected if key in actual}
    if set(selected_actual) != EXPECTED_CHECKPOINT_KEYS or selected_actual != expected:
        raise CutoverSafetyError(
            "Cutover checkpoint summary does not match detector_checkpoints database rows"
        )


def _json_compatible(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return _utc_iso(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Enum):
        return _json_compatible(value.value)
    if isinstance(value, tuple):
        return [_json_compatible(item) for item in value]
    if isinstance(value, list):
        return [_json_compatible(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    return value


def _table_row_counts(database: Path) -> Mapping[str, int]:
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
            ids = [str(row[0]) for row in connection.execute(f'SELECT id FROM "{table}" ORDER BY id')]
    except sqlite3.OperationalError:
        return None
    return hashlib.sha256(",".join(ids).encode("utf-8")).hexdigest()


def _database_evidence(database: Path) -> Mapping[str, object]:
    return {
        "table_row_counts": _table_row_counts(database),
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
    }


def _service_states(
    services: tuple[str, ...],
    is_active: Callable[[str], bool],
) -> Mapping[str, bool]:
    return {service: bool(is_active(service)) for service in services}


def _stop_services(
    services: tuple[str, ...],
    stop_service: Callable[[str], None],
) -> None:
    errors: list[str] = []
    for service in services:
        try:
            stop_service(service)
        except Exception as exc:  # noqa: BLE001 - collect every service failure
            errors.append(f"{service}: {exc}")
    if errors:
        raise CutoverSafetyError("Failed to stop services: " + "; ".join(errors))


def _restore_service_states(
    states: Mapping[str, bool],
    *,
    start_service: Callable[[str], None],
    stop_service: Callable[[str], None],
) -> None:
    errors: list[str] = []
    for service, was_active in states.items():
        try:
            (start_service if was_active else stop_service)(service)
        except Exception as exc:  # noqa: BLE001 - best effort for every service
            errors.append(f"{service}: {exc}")
    if errors:
        raise CutoverSafetyError("Failed to restore service states: " + "; ".join(errors))


@contextmanager
def _operation_lock(database: Path) -> Iterator[None]:
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
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass
        return

    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise CutoverSafetyError(f"Another Phase 4 operation holds the lock: {lock_path}") from exc
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.close(descriptor)
        yield
    finally:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def _write_report(path: Path, report: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(_json_compatible(asdict(report)), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _validate_new_result_path(path: Path, protected_paths: tuple[Path, ...]) -> None:
    if path in protected_paths:
        raise CutoverSafetyError("Cutover result path conflicts with a protected database path")
    if path.exists():
        raise CutoverSafetyError(f"Cutover result already exists: {path}")
    temporary = path.with_suffix(path.suffix + ".tmp")
    if temporary in protected_paths or temporary.exists():
        raise CutoverSafetyError(f"Cutover temporary result path is unsafe: {temporary}")


def _backup_name(database_path: Path, cutover_at: datetime) -> str:
    timestamp = cutover_at.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{database_path.stem}_before_phase4_{timestamp}{database_path.suffix}"


def _verification_mapping(verification: DatabaseVerification) -> Mapping[str, object]:
    return {
        "integrity_check": verification.integrity_check,
        "foreign_key_violations": verification.foreign_key_violations,
    }


def execute_cutover(
    config: CutoverConfig,
    dependencies: CutoverDependencies,
) -> CutoverReport:
    """Execute the guarded Phase 4 cutover and automatically restore on failure."""

    database = config.database_path.expanduser().resolve()
    backup_directory = config.backup_directory.expanduser().resolve()
    result_path = config.result_path.expanduser().resolve()
    migrations_directory = config.migrations_directory.expanduser().resolve()
    if not database.is_file():
        raise CutoverSafetyError(f"Operational database does not exist: {database}")
    _validate_new_result_path(result_path, (database,))

    all_services = tuple(
        dict.fromkeys(
            config.legacy_services
            + config.new_services
            + config.paused_writer_services
        )
    )
    services_before = _service_states(all_services, dependencies.is_service_active)
    cutover_at = dependencies.now()
    cutover_at_iso = _utc_iso(cutover_at)
    backup_path = backup_directory / _backup_name(database, cutover_at)
    backup_sha256_path = backup_path.with_suffix(backup_path.suffix + ".sha256")
    if backup_path.exists():
        raise CutoverSafetyError(f"Backup destination already exists: {backup_path}")
    if backup_sha256_path.exists():
        raise CutoverSafetyError(
            f"SHA256 destination already exists: {backup_sha256_path}"
        )
    artifact: BackupArtifact | None = None
    migration_summary: Mapping[str, object] = {}
    checkpoint_summary: Mapping[str, object] = {}
    failure_stage = "service-stop"

    with _operation_lock(database):
        try:
            _stop_services(all_services, dependencies.stop_service)

            failure_stage = "backup"
            artifact = create_sqlite_backup(database, backup_path)
            if artifact.integrity_check != "ok" or artifact.foreign_key_violations:
                raise CutoverSafetyError(
                    "Pre-cutover backup failed integrity or foreign-key checks"
                )

            failure_stage = "migration"
            migration_summary = _summary(
                dependencies.apply_migrations(database, migrations_directory)
            )
            _validate_migration_summary(migration_summary)
            post_migration = verify_database(database)
            if post_migration.integrity_check != "ok" or post_migration.foreign_key_violations:
                raise CutoverSafetyError(
                    "Migrated database failed integrity or foreign-key checks"
                )

            failure_stage = "checkpoint-initialization"
            checkpoint_summary = dict(
                dependencies.initialize_checkpoints(database, cutover_at)
            )
            _validate_checkpoint_summary(checkpoint_summary)
            _validate_checkpoint_database(database, checkpoint_summary)
            post_checkpoint = verify_database(database)
            if post_checkpoint.integrity_check != "ok" or post_checkpoint.foreign_key_violations:
                raise CutoverSafetyError(
                    "Checkpoint initialization failed database checks"
                )

            failure_stage = "service-start"
            for service in config.new_services:
                dependencies.start_service(service)
            writer_states = {
                service: services_before[service]
                for service in config.paused_writer_services
            }
            _restore_service_states(
                writer_states,
                start_service=dependencies.start_service,
                stop_service=dependencies.stop_service,
            )
            services_after = _service_states(all_services, dependencies.is_service_active)

            report = CutoverReport(
                status="succeeded",
                git_sha=config.git_sha,
                phase4_cutover_at=cutover_at_iso,
                database_path=str(database),
                backup_database=str(artifact.database_path),
                backup_sha256_path=str(artifact.sha256_path),
                backup_sha256=artifact.sha256,
                integrity_check=post_checkpoint.integrity_check,
                foreign_key_violations=post_checkpoint.foreign_key_violations,
                migration_summary=migration_summary,
                checkpoint_summary=checkpoint_summary,
                legacy_services=config.legacy_services,
                new_services=config.new_services,
                paused_writer_services=config.paused_writer_services,
                services_before=services_before,
                services_after=services_after,
            )
            _write_report(result_path, report)
            return report
        except Exception as exc:
            rollback_verification: Mapping[str, object] = {}
            rollback_errors: list[str] = []
            try:
                _stop_services(config.new_services, dependencies.stop_service)
            except Exception as stop_exc:  # noqa: BLE001
                rollback_errors.append(str(stop_exc))
            if artifact is not None:
                try:
                    restored = restore_sqlite_backup(
                        target_path=database,
                        backup_path=artifact.database_path,
                        sha256_path=artifact.sha256_path,
                    )
                    rollback_verification = _verification_mapping(restored)
                except Exception as restore_exc:  # noqa: BLE001
                    rollback_errors.append(str(restore_exc))
            try:
                _restore_service_states(
                    services_before,
                    start_service=dependencies.start_service,
                    stop_service=dependencies.stop_service,
                )
            except Exception as service_exc:  # noqa: BLE001
                rollback_errors.append(str(service_exc))

            status = "rolled_back" if not rollback_errors else "rollback_failed"
            error_message = str(exc)
            if rollback_errors:
                error_message += "; rollback failed: " + "; ".join(rollback_errors)
            services_after = _service_states(all_services, dependencies.is_service_active)
            report = CutoverReport(
                status=status,
                git_sha=config.git_sha,
                phase4_cutover_at=cutover_at_iso,
                database_path=str(database),
                backup_database=str(artifact.database_path) if artifact else None,
                backup_sha256_path=str(artifact.sha256_path) if artifact else None,
                backup_sha256=artifact.sha256 if artifact else None,
                integrity_check=None,
                migration_summary=migration_summary,
                checkpoint_summary=checkpoint_summary,
                legacy_services=config.legacy_services,
                new_services=config.new_services,
                paused_writer_services=config.paused_writer_services,
                services_before=services_before,
                services_after=services_after,
                failure_stage=failure_stage,
                error=error_message,
                rollback_verification=rollback_verification,
            )
            _write_report(result_path, report)
            raise CutoverExecutionError(error_message) from exc


def run_cutover_smoke_test(
    config: SmokeTestConfig,
    *,
    apply_migrations: Callable[[Path, Path], object],
    initialize_checkpoints: Callable[[Path, datetime], Mapping[str, object]],
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> SmokeTestReport:
    """Exercise Migration and checkpoint initialization on a verified DB copy."""

    source = config.source_database_path.expanduser().resolve()
    smoke_database = config.smoke_database_path.expanduser().resolve()
    migrations_directory = config.migrations_directory.expanduser().resolve()
    result_path = config.result_path.expanduser().resolve()
    if not source.is_file():
        raise CutoverSafetyError(f"Source database does not exist: {source}")
    if source == smoke_database:
        raise CutoverSafetyError("Smoke-test database must differ from the source database")
    _validate_new_result_path(result_path, (source, smoke_database))

    cutover_at = now()
    cutover_at_iso = _utc_iso(cutover_at)
    source_sha_before = _sha256_file(source)
    source_counts_before = _table_row_counts(source)
    source_evidence_before = _database_evidence(source)
    source_sha_after: str | None = None
    source_counts_after: Mapping[str, int] = {}
    source_unchanged: bool | None = None
    artifact: BackupArtifact | None = None
    final_smoke_sha256: str | None = None
    post_manifest: Path | None = None
    migration_summary: Mapping[str, object] = {}
    checkpoint_summary: Mapping[str, object] = {}
    final_verification: DatabaseVerification | None = None
    evidence: Mapping[str, object] = {"source_before": source_evidence_before}
    failure_stage = "snapshot"

    with _operation_lock(source):
        try:
            artifact = create_sqlite_backup(source, smoke_database)
            if artifact.integrity_check != "ok" or artifact.foreign_key_violations:
                raise CutoverSafetyError(
                    "Smoke-test snapshot failed integrity or foreign-key checks"
                )
            smoke_before = _database_evidence(smoke_database)

            failure_stage = "migration"
            migration_summary = _summary(
                apply_migrations(smoke_database, migrations_directory)
            )
            _validate_migration_summary(migration_summary)
            post_migration = verify_database(smoke_database)
            if post_migration.integrity_check != "ok" or post_migration.foreign_key_violations:
                raise CutoverSafetyError("Smoke-test migration failed database checks")

            failure_stage = "checkpoint-initialization"
            checkpoint_summary = dict(initialize_checkpoints(smoke_database, cutover_at))
            _validate_checkpoint_summary(checkpoint_summary)
            _validate_checkpoint_database(smoke_database, checkpoint_summary)
            final_verification = verify_database(smoke_database)
            if (
                final_verification.integrity_check != "ok"
                or final_verification.foreign_key_violations
            ):
                raise CutoverSafetyError(
                    "Smoke-test checkpoint initialization failed database checks"
                )

            final_smoke_sha256 = _sha256_file(smoke_database)
            post_manifest = smoke_database.with_suffix(
                smoke_database.suffix + ".post-migration.sha256"
            )
            if post_manifest.exists():
                raise CutoverSafetyError(
                    f"Smoke post-migration SHA256 already exists: {post_manifest}"
                )
            post_manifest.write_text(
                f"{final_smoke_sha256}  {smoke_database.name}\n",
                encoding="utf-8",
            )
            evidence = {
                "source_before": source_evidence_before,
                "smoke_before": smoke_before,
                "smoke_after": _database_evidence(smoke_database),
            }

            failure_stage = "source-preservation-check"
            source_sha_after = _sha256_file(source)
            source_counts_after = _table_row_counts(source)
            source_unchanged = (
                source_sha_before == source_sha_after
                and source_counts_before == source_counts_after
            )
            if not source_unchanged:
                raise CutoverSafetyError("Smoke-test source database changed unexpectedly")

            report = SmokeTestReport(
                status="succeeded",
                mode="smoke-test",
                git_sha=config.git_sha,
                phase4_cutover_at=cutover_at_iso,
                source_database=str(source),
                smoke_database=str(smoke_database),
                source_sha256_before=source_sha_before,
                source_sha256_after=source_sha_after,
                source_unchanged=True,
                source_table_row_counts_before=source_counts_before,
                source_table_row_counts_after=source_counts_after,
                smoke_sha256_before_migration=artifact.sha256,
                smoke_sha256_after_migration=final_smoke_sha256,
                smoke_pre_migration_sha256_path=str(artifact.sha256_path),
                smoke_post_migration_sha256_path=str(post_manifest),
                integrity_check=final_verification.integrity_check,
                foreign_key_violations=final_verification.foreign_key_violations,
                migration_summary=migration_summary,
                checkpoint_summary=checkpoint_summary,
                database_evidence=evidence,
            )
            _write_report(result_path, report)
            return report
        except Exception as exc:
            source_sha_after = _sha256_file(source)
            source_counts_after = _table_row_counts(source)
            source_unchanged = (
                source_sha_before == source_sha_after
                and source_counts_before == source_counts_after
            )
            report = SmokeTestReport(
                status="failed",
                mode="smoke-test",
                git_sha=config.git_sha,
                phase4_cutover_at=cutover_at_iso,
                source_database=str(source),
                smoke_database=str(smoke_database),
                source_sha256_before=source_sha_before,
                source_sha256_after=source_sha_after,
                source_unchanged=source_unchanged,
                source_table_row_counts_before=source_counts_before,
                source_table_row_counts_after=source_counts_after,
                smoke_sha256_before_migration=artifact.sha256 if artifact else "",
                smoke_sha256_after_migration=final_smoke_sha256,
                smoke_pre_migration_sha256_path=(
                    str(artifact.sha256_path) if artifact else ""
                ),
                smoke_post_migration_sha256_path=(
                    str(post_manifest) if post_manifest else None
                ),
                integrity_check=(
                    final_verification.integrity_check if final_verification else None
                ),
                foreign_key_violations=(
                    final_verification.foreign_key_violations
                    if final_verification
                    else ()
                ),
                migration_summary=migration_summary,
                checkpoint_summary=checkpoint_summary,
                database_evidence=evidence,
                failure_stage=failure_stage,
                error=str(exc),
            )
            _write_report(result_path, report)
            raise CutoverExecutionError(str(exc)) from exc


def execute_rollback(
    config: RollbackConfig,
    dependencies: RollbackDependencies,
) -> RollbackReport:
    """Restore a selected verified backup and reactivate the legacy services."""

    database = config.database_path.expanduser().resolve()
    backup = config.backup_path.expanduser().resolve()
    sha256_path = config.sha256_path.expanduser().resolve()
    result_path = config.result_path.expanduser().resolve()
    _validate_new_result_path(result_path, (database, backup, sha256_path))
    rollback_at = dependencies.now()
    rollback_at_iso = _utc_iso(rollback_at)
    backup_directory = (
        config.backup_directory.expanduser().resolve()
        if config.backup_directory is not None
        else backup.parent / "pre-rollback"
    )
    all_services = tuple(
        dict.fromkeys(
            config.legacy_services
            + config.new_services
            + config.paused_writer_services
        )
    )
    services_before = _service_states(all_services, dependencies.is_service_active)

    def record_preflight_failure(message: str) -> None:
        _write_report(
            result_path,
            RollbackReport(
                status="failed",
                git_sha=config.git_sha,
                rolled_back_at=rollback_at_iso,
                database_path=str(database),
                backup_path=str(backup),
                restored_backup_sha256=None,
                pre_rollback_backup=None,
                pre_rollback_sha256_path=None,
                integrity_check=None,
                foreign_key_violations=(),
                legacy_services=config.legacy_services,
                new_services=config.new_services,
                paused_writer_services=config.paused_writer_services,
                services_before=services_before,
                services_after=services_before,
                failure_stage="preflight",
                error=message,
            ),
        )

    if not database.is_file():
        message = f"Operational database does not exist: {database}"
        record_preflight_failure(message)
        raise CutoverSafetyError(message)
    try:
        expected = _expected_sha256(sha256_path, backup)
        actual = _sha256_file(backup)
        if actual != expected:
            raise CutoverSafetyError(
                "Backup SHA256 mismatch; refusing to change services or database"
            )
        backup_verification = verify_database(backup)
        if (
            backup_verification.integrity_check != "ok"
            or backup_verification.foreign_key_violations
        ):
            raise CutoverSafetyError("Backup database failed checks; refusing rollback")
    except Exception as exc:
        record_preflight_failure(str(exc))
        raise

    pre_rollback_artifact: BackupArtifact | None = None
    restored: DatabaseVerification | None = None
    failure_stage = "service-stop"

    with _operation_lock(database):
        try:
            _stop_services(all_services, dependencies.stop_service)

            failure_stage = "pre-rollback-backup"
            timestamp = rollback_at.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            pre_rollback_path = (
                backup_directory
                / f"{database.stem}_pre_manual_rollback_{timestamp}{database.suffix}"
            )
            pre_rollback_artifact = create_sqlite_backup(database, pre_rollback_path)

            failure_stage = "database-restore"
            restored = restore_sqlite_backup(
                target_path=database,
                backup_path=backup,
                sha256_path=sha256_path,
            )

            failure_stage = "service-restore"
            for service in config.legacy_services:
                dependencies.start_service(service)
            writer_states = {
                service: services_before[service]
                for service in config.paused_writer_services
            }
            _restore_service_states(
                writer_states,
                start_service=dependencies.start_service,
                stop_service=dependencies.stop_service,
            )
            services_after = _service_states(all_services, dependencies.is_service_active)

            report = RollbackReport(
                status="succeeded",
                git_sha=config.git_sha,
                rolled_back_at=rollback_at_iso,
                database_path=str(database),
                backup_path=str(backup),
                restored_backup_sha256=actual,
                pre_rollback_backup=str(pre_rollback_artifact.database_path),
                pre_rollback_sha256_path=str(pre_rollback_artifact.sha256_path),
                integrity_check=restored.integrity_check,
                foreign_key_violations=restored.foreign_key_violations,
                legacy_services=config.legacy_services,
                new_services=config.new_services,
                paused_writer_services=config.paused_writer_services,
                services_before=services_before,
                services_after=services_after,
            )
            _write_report(result_path, report)
            return report
        except Exception as exc:
            recovery_errors: list[str] = []
            if pre_rollback_artifact is not None:
                try:
                    restore_sqlite_backup(
                        target_path=database,
                        backup_path=pre_rollback_artifact.database_path,
                        sha256_path=pre_rollback_artifact.sha256_path,
                    )
                except Exception as restore_exc:  # noqa: BLE001
                    recovery_errors.append(str(restore_exc))
            try:
                _restore_service_states(
                    services_before,
                    start_service=dependencies.start_service,
                    stop_service=dependencies.stop_service,
                )
            except Exception as service_exc:  # noqa: BLE001
                recovery_errors.append(str(service_exc))
            error_message = str(exc)
            if recovery_errors:
                error_message += "; rollback recovery failed: " + "; ".join(
                    recovery_errors
                )
            services_after = _service_states(all_services, dependencies.is_service_active)
            report = RollbackReport(
                status="failed" if not recovery_errors else "recovery_failed",
                git_sha=config.git_sha,
                rolled_back_at=rollback_at_iso,
                database_path=str(database),
                backup_path=str(backup),
                restored_backup_sha256=None,
                pre_rollback_backup=(
                    str(pre_rollback_artifact.database_path)
                    if pre_rollback_artifact
                    else None
                ),
                pre_rollback_sha256_path=(
                    str(pre_rollback_artifact.sha256_path)
                    if pre_rollback_artifact
                    else None
                ),
                integrity_check=restored.integrity_check if restored else None,
                foreign_key_violations=(
                    restored.foreign_key_violations if restored else ()
                ),
                legacy_services=config.legacy_services,
                new_services=config.new_services,
                paused_writer_services=config.paused_writer_services,
                services_before=services_before,
                services_after=services_after,
                failure_stage=failure_stage,
                error=error_message,
            )
            _write_report(result_path, report)
            raise CutoverExecutionError(error_message) from exc
