"""Safety primitives shared by the Phase 4 cutover and rollback CLIs."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Callable, Mapping


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


@dataclass(frozen=True)
class CutoverDependencies:
    stop_service: Callable[[str], None]
    start_service: Callable[[str], None]
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
    smoke_database_sha256: str
    integrity_check: str
    foreign_key_violations: tuple[tuple[object, ...], ...]
    migration_summary: Mapping[str, object]
    checkpoint_summary: Mapping[str, object]


@dataclass(frozen=True)
class RollbackConfig:
    database_path: Path
    backup_path: Path
    sha256_path: Path
    result_path: Path
    git_sha: str
    legacy_services: tuple[str, ...] = ()
    new_services: tuple[str, ...] = ()


@dataclass(frozen=True)
class RollbackDependencies:
    stop_service: Callable[[str], None]
    start_service: Callable[[str], None]
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)


@dataclass(frozen=True)
class RollbackReport:
    status: str
    git_sha: str
    rolled_back_at: str
    database_path: str
    backup_path: str
    restored_backup_sha256: str
    integrity_check: str
    foreign_key_violations: tuple[tuple[object, ...], ...]
    legacy_services: tuple[str, ...]
    new_services: tuple[str, ...]


def _database_checks(database_path: Path) -> tuple[str, tuple[tuple[object, ...], ...]]:
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_key_rows = connection.execute("PRAGMA foreign_key_check").fetchall()
    return integrity, tuple(tuple(row) for row in foreign_key_rows)


def verify_database(database_path: str | Path) -> DatabaseVerification:
    path = Path(database_path).expanduser().resolve()
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
    legacy_count = summary.get("legacy_migration_event_count")
    if not isinstance(legacy_count, int) or legacy_count < 0:
        raise CutoverSafetyError(
            "Checkpoint summary requires a non-negative legacy_migration_event_count"
        )


def _json_compatible(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, tuple):
        return [_json_compatible(item) for item in value]
    if isinstance(value, list):
        return [_json_compatible(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    return value


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

    cutover_at: datetime | None = None
    cutover_at_iso: str | None = None
    artifact: BackupArtifact | None = None
    migration_summary: Mapping[str, object] = {}
    checkpoint_summary: Mapping[str, object] = {}

    try:
        for service in config.legacy_services:
            dependencies.stop_service(service)
        for service in config.new_services:
            dependencies.stop_service(service)

        cutover_at = dependencies.now()
        cutover_at_iso = _utc_iso(cutover_at)
        backup_path = backup_directory / _backup_name(database, cutover_at)
        artifact = create_sqlite_backup(database, backup_path)
        if artifact.integrity_check != "ok" or artifact.foreign_key_violations:
            raise CutoverSafetyError("Pre-cutover backup failed integrity or foreign-key checks")

        migration_summary = _summary(
            dependencies.apply_migrations(database, migrations_directory)
        )
        _validate_migration_summary(migration_summary)
        post_migration = verify_database(database)
        if post_migration.integrity_check != "ok" or post_migration.foreign_key_violations:
            raise CutoverSafetyError("Migrated database failed integrity or foreign-key checks")

        checkpoint_summary = dict(
            dependencies.initialize_checkpoints(database, cutover_at)
        )
        _validate_checkpoint_summary(checkpoint_summary)
        post_checkpoint = verify_database(database)
        if post_checkpoint.integrity_check != "ok" or post_checkpoint.foreign_key_violations:
            raise CutoverSafetyError("Checkpoint initialization failed database checks")

        for service in config.new_services:
            dependencies.start_service(service)

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
        )
        _write_report(result_path, report)
        return report
    except Exception as exc:
        rollback_verification: Mapping[str, object] = {}
        rollback_error: Exception | None = None
        try:
            for service in config.new_services:
                dependencies.stop_service(service)
            if artifact is not None:
                restored = restore_sqlite_backup(
                    target_path=database,
                    backup_path=artifact.database_path,
                    sha256_path=artifact.sha256_path,
                )
                rollback_verification = _verification_mapping(restored)
            for service in config.legacy_services:
                dependencies.start_service(service)
        except Exception as restore_exc:  # pragma: no cover - tested via CLI integration later
            rollback_error = restore_exc

        status = "rolled_back" if rollback_error is None else "rollback_failed"
        error_message = str(exc)
        if rollback_error is not None:
            error_message = f"{error_message}; rollback failed: {rollback_error}"
        if cutover_at_iso is None:
            cutover_at_iso = _utc_iso(dependencies.now())
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
    artifact = create_sqlite_backup(source, smoke_database)
    if artifact.integrity_check != "ok" or artifact.foreign_key_violations:
        raise CutoverSafetyError("Smoke-test snapshot failed integrity or foreign-key checks")

    migration_summary = _summary(apply_migrations(smoke_database, migrations_directory))
    _validate_migration_summary(migration_summary)
    post_migration = verify_database(smoke_database)
    if post_migration.integrity_check != "ok" or post_migration.foreign_key_violations:
        raise CutoverSafetyError("Smoke-test migration failed database checks")

    checkpoint_summary = dict(initialize_checkpoints(smoke_database, cutover_at))
    _validate_checkpoint_summary(checkpoint_summary)
    final_verification = verify_database(smoke_database)
    if final_verification.integrity_check != "ok" or final_verification.foreign_key_violations:
        raise CutoverSafetyError("Smoke-test checkpoint initialization failed database checks")

    final_smoke_sha256 = _sha256_file(smoke_database)
    artifact.sha256_path.write_text(
        f"{final_smoke_sha256}  {smoke_database.name}\n",
        encoding="utf-8",
    )
    report = SmokeTestReport(
        status="succeeded",
        mode="smoke-test",
        git_sha=config.git_sha,
        phase4_cutover_at=cutover_at_iso,
        source_database=str(source),
        smoke_database=str(smoke_database),
        smoke_database_sha256=final_smoke_sha256,
        integrity_check=final_verification.integrity_check,
        foreign_key_violations=final_verification.foreign_key_violations,
        migration_summary=migration_summary,
        checkpoint_summary=checkpoint_summary,
    )
    _write_report(result_path, report)
    return report


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

    expected = _expected_sha256(sha256_path, backup)
    actual = _sha256_file(backup)
    if actual != expected:
        raise CutoverSafetyError("Backup SHA256 mismatch; refusing to change services or database")
    backup_verification = verify_database(backup)
    if (
        backup_verification.integrity_check != "ok"
        or backup_verification.foreign_key_violations
    ):
        raise CutoverSafetyError("Backup database failed checks; refusing rollback")

    for service in config.new_services:
        dependencies.stop_service(service)
    restored = restore_sqlite_backup(
        target_path=database,
        backup_path=backup,
        sha256_path=sha256_path,
    )
    for service in config.legacy_services:
        dependencies.start_service(service)

    report = RollbackReport(
        status="succeeded",
        git_sha=config.git_sha,
        rolled_back_at=_utc_iso(dependencies.now()),
        database_path=str(database),
        backup_path=str(backup),
        restored_backup_sha256=actual,
        integrity_check=restored.integrity_check,
        foreign_key_violations=restored.foreign_key_violations,
        legacy_services=config.legacy_services,
        new_services=config.new_services,
    )
    _write_report(result_path, report)
    return report
