"""Safety primitives shared by the Phase 4 cutover and rollback CLIs."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import date, datetime, timezone
from enum import Enum
import json
from pathlib import Path
import signal
import sqlite3
from typing import Any, Callable, Iterator, Mapping

from edge.scripts.phase4_cutover_storage import (
    BackupArtifact,
    CutoverSafetyError,
    DatabaseVerification,
    create_sqlite_backup,
    database_evidence as _database_evidence,
    expected_backup_sha256 as _expected_sha256,
    file_sha256 as _sha256_file,
    operation_lock as _operation_lock,
    restore_sqlite_backup,
    table_row_counts as _table_row_counts,
    validate_data_preservation as _validate_data_preservation,
    verify_database,
    verify_phase3b_database_identity,
)


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


class CutoverExecutionError(RuntimeError):
    """Raised after a failed cutover has attempted its rollback path."""


@contextmanager
def termination_signal_guard() -> Iterator[None]:
    """Convert SIGINT/SIGTERM into an exception handled by guarded workflows."""

    previous_handlers: dict[signal.Signals, object] = {}

    def interrupt(signum: int, _frame: object) -> None:
        raise KeyboardInterrupt(signal.Signals(signum).name)

    for signal_name in ("SIGINT", "SIGTERM"):
        current_signal = getattr(signal, signal_name, None)
        if current_signal is None:
            continue
        previous_handlers[current_signal] = signal.getsignal(current_signal)
        signal.signal(current_signal, interrupt)
    try:
        yield
    finally:
        for current_signal, previous_handler in previous_handlers.items():
            signal.signal(current_signal, previous_handler)


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
    primary_error: str | None = None
    rollback_attempted: bool = False
    rollback_succeeded: bool | None = None
    rollback_error: str | None = None
    rollback_verification: Mapping[str, object] = field(default_factory=dict)
    database_evidence: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class SmokeTestConfig:
    source_database_path: Path
    smoke_database_path: Path
    migrations_directory: Path
    result_path: Path
    git_sha: str
    paused_writer_services: tuple[str, ...] = ()


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
    source_snapshot_before: str | None
    source_snapshot_after: str | None
    source_snapshot_sha256_before: str | None
    source_snapshot_sha256_after: str | None
    source_snapshot_before_sha256_path: str | None
    source_snapshot_after_sha256_path: str | None
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
    paused_writer_services: tuple[str, ...] = ()
    writer_services_before: Mapping[str, bool] = field(default_factory=dict)
    writer_services_after: Mapping[str, bool] = field(default_factory=dict)
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
    primary_error: str | None = None
    rollback_attempted: bool = False
    rollback_succeeded: bool | None = None
    rollback_error: str | None = None


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


def _service_states(
    services: tuple[str, ...],
    is_active: Callable[[str], bool],
) -> Mapping[str, bool]:
    return {service: bool(is_active(service)) for service in services}


def _expected_cutover_service_states(
    config: CutoverConfig,
    services_before: Mapping[str, bool],
) -> Mapping[str, bool]:
    expected: dict[str, bool] = {
        service: False for service in config.legacy_services
    }
    expected.update({service: True for service in config.new_services})
    expected.update(
        {
            service: services_before[service]
            for service in config.paused_writer_services
        }
    )
    return expected


def _validate_service_states(
    actual: Mapping[str, bool],
    expected: Mapping[str, bool],
    *,
    context: str = "post-cutover",
) -> None:
    mismatches = {
        service: {"expected": expected_state, "actual": actual.get(service)}
        for service, expected_state in expected.items()
        if actual.get(service) is not expected_state
    }
    if mismatches:
        raise CutoverSafetyError(
            f"{context} service state verification failed: {mismatches}"
        )


def _expected_rollback_service_states(
    config: RollbackConfig,
    services_before: Mapping[str, bool],
) -> Mapping[str, bool]:
    expected: dict[str, bool] = {
        service: True for service in config.legacy_services
    }
    expected.update({service: False for service in config.new_services})
    expected.update(
        {
            service: services_before[service]
            for service in config.paused_writer_services
        }
    )
    return expected


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


def _validate_distinct_artifact_paths(paths: Mapping[str, Path]) -> None:
    by_path: dict[Path, list[str]] = {}
    for label, path in paths.items():
        by_path.setdefault(path.expanduser().resolve(), []).append(label)
    conflicts = {
        str(path): labels
        for path, labels in by_path.items()
        if len(labels) > 1
    }
    if conflicts:
        raise CutoverSafetyError(f"Workflow artifact paths conflict: {conflicts}")


def _validate_new_artifact_paths(paths: Mapping[str, Path]) -> None:
    existing = {
        label: str(path)
        for label, path in paths.items()
        if path.expanduser().resolve().exists()
    }
    if existing:
        raise CutoverSafetyError(f"Workflow artifact paths already exist: {existing}")


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
    verify_phase3b_database_identity(database)
    cutover_at = dependencies.now()
    cutover_at_iso = _utc_iso(cutover_at)
    backup_path = backup_directory / _backup_name(database, cutover_at)
    backup_sha256_path = backup_path.with_suffix(backup_path.suffix + ".sha256")
    result_temporary = result_path.with_suffix(result_path.suffix + ".tmp")
    operation_lock = database.with_suffix(database.suffix + ".phase4.lock")
    _validate_distinct_artifact_paths(
        {
            "operational_database": database,
            "operation_lock": operation_lock,
            "backup_database": backup_path,
            "backup_sha256": backup_sha256_path,
            "result_json": result_path,
            "result_json_temporary": result_temporary,
        }
    )
    _validate_new_result_path(result_path, (database, operation_lock))

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
            CutoverReport(
                status="failed",
                git_sha=config.git_sha,
                phase4_cutover_at=cutover_at_iso,
                database_path=str(database),
                backup_database=None,
                backup_sha256_path=None,
                backup_sha256=None,
                integrity_check=None,
                legacy_services=config.legacy_services,
                new_services=config.new_services,
                paused_writer_services=config.paused_writer_services,
                services_before=services_before,
                services_after=services_before,
                failure_stage="preflight",
                error=message,
                primary_error=message,
                rollback_attempted=False,
                rollback_succeeded=None,
                rollback_error=None,
            ),
        )

    if backup_path.exists():
        message = f"Backup destination already exists: {backup_path}"
        record_preflight_failure(message)
        raise CutoverSafetyError(message)
    if backup_sha256_path.exists():
        message = f"SHA256 destination already exists: {backup_sha256_path}"
        record_preflight_failure(message)
        raise CutoverSafetyError(message)
    artifact: BackupArtifact | None = None
    migration_summary: Mapping[str, object] = {}
    checkpoint_summary: Mapping[str, object] = {}
    database_evidence: dict[str, object] = {}
    database_mutation_started = False
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
            database_evidence["before"] = _database_evidence(artifact.database_path)

            failure_stage = "migration"
            database_mutation_started = True
            migration_summary = _summary(
                dependencies.apply_migrations(database, migrations_directory)
            )
            _validate_migration_summary(migration_summary)
            database_evidence["after_migration"] = _database_evidence(database)
            failure_stage = "data-preservation-check"
            _validate_data_preservation(
                database_evidence["before"],
                database_evidence["after_migration"],
            )
            failure_stage = "migration-verification"
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
            database_evidence["final"] = _database_evidence(database)
            failure_stage = "final-data-preservation-check"
            _validate_data_preservation(
                database_evidence["before"],
                database_evidence["final"],
            )
            failure_stage = "checkpoint-verification"
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
            failure_stage = "post-service-verification"
            services_after = _service_states(all_services, dependencies.is_service_active)
            _validate_service_states(
                services_after,
                _expected_cutover_service_states(config, services_before),
            )

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
                database_evidence=database_evidence,
            )
            _write_report(result_path, report)
            return report
        except (Exception, KeyboardInterrupt) as exc:
            rollback_verification: Mapping[str, object] = {}
            rollback_errors: list[str] = []
            database_safe = not database_mutation_started
            try:
                _stop_services(config.new_services, dependencies.stop_service)
            except Exception as stop_exc:  # noqa: BLE001
                rollback_errors.append(str(stop_exc))
            if artifact is not None and database_mutation_started:
                try:
                    restored = restore_sqlite_backup(
                        target_path=database,
                        backup_path=artifact.database_path,
                        sha256_path=artifact.sha256_path,
                    )
                    rollback_verification = _verification_mapping(restored)
                    database_safe = True
                except Exception as restore_exc:  # noqa: BLE001
                    rollback_errors.append(str(restore_exc))
            if database_safe:
                try:
                    _restore_service_states(
                        services_before,
                        start_service=dependencies.start_service,
                        stop_service=dependencies.stop_service,
                    )
                except Exception as service_exc:  # noqa: BLE001
                    rollback_errors.append(str(service_exc))
            else:
                rollback_errors.append(
                    "service restart skipped because database restoration was not verified"
                )

            services_after: Mapping[str, bool] = {}
            try:
                services_after = _service_states(
                    all_services, dependencies.is_service_active
                )
                if database_safe:
                    _validate_service_states(
                        services_after,
                        services_before,
                        context="automatic rollback",
                    )
            except Exception as verification_exc:  # noqa: BLE001
                rollback_errors.append(str(verification_exc))

            status = "rolled_back" if not rollback_errors else "rollback_failed"
            error_message = str(exc)
            if rollback_errors:
                error_message += "; rollback failed: " + "; ".join(rollback_errors)
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
                primary_error=str(exc),
                rollback_attempted=True,
                rollback_succeeded=not rollback_errors,
                rollback_error="; ".join(rollback_errors) if rollback_errors else None,
                rollback_verification=rollback_verification,
                database_evidence=database_evidence,
            )
            _write_report(result_path, report)
            raise CutoverExecutionError(error_message) from exc


def run_cutover_smoke_test(
    config: SmokeTestConfig,
    *,
    apply_migrations: Callable[[Path, Path], object],
    initialize_checkpoints: Callable[[Path, datetime], Mapping[str, object]],
    stop_service: Callable[[str], None] | None = None,
    start_service: Callable[[str], None] | None = None,
    is_service_active: Callable[[str], bool] | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> SmokeTestReport:
    """Exercise Migration and checkpoint initialization on a verified DB copy."""

    source = config.source_database_path.expanduser().resolve()
    smoke_database = config.smoke_database_path.expanduser().resolve()
    migrations_directory = config.migrations_directory.expanduser().resolve()
    result_path = config.result_path.expanduser().resolve()
    if not source.is_file():
        raise CutoverSafetyError(f"Source database does not exist: {source}")
    verify_phase3b_database_identity(source)
    if source == smoke_database:
        raise CutoverSafetyError("Smoke-test database must differ from the source database")
    if config.paused_writer_services and (
        stop_service is None or start_service is None or is_service_active is None
    ):
        raise CutoverSafetyError(
            "Smoke-test writer services require stop, start, and status callbacks"
        )
    source_snapshot_before = smoke_database.with_name(
        f"{smoke_database.stem}.source-before{source.suffix}"
    )
    source_snapshot_after = smoke_database.with_name(
        f"{smoke_database.stem}.source-after{source.suffix}"
    )
    smoke_sha256_path = smoke_database.with_suffix(smoke_database.suffix + ".sha256")
    source_snapshot_before_sha256 = source_snapshot_before.with_suffix(
        source_snapshot_before.suffix + ".sha256"
    )
    source_snapshot_after_sha256 = source_snapshot_after.with_suffix(
        source_snapshot_after.suffix + ".sha256"
    )
    post_manifest_path = smoke_database.with_suffix(
        smoke_database.suffix + ".post-migration.sha256"
    )
    result_temporary = result_path.with_suffix(result_path.suffix + ".tmp")
    operation_lock = source.with_suffix(source.suffix + ".phase4.lock")
    _validate_distinct_artifact_paths(
        {
            "source_database": source,
            "operation_lock": operation_lock,
            "smoke_database": smoke_database,
            "smoke_sha256": smoke_sha256_path,
            "source_snapshot_before": source_snapshot_before,
            "source_snapshot_before_sha256": source_snapshot_before_sha256,
            "source_snapshot_after": source_snapshot_after,
            "source_snapshot_after_sha256": source_snapshot_after_sha256,
            "post_migration_sha256": post_manifest_path,
            "result_json": result_path,
            "result_json_temporary": result_temporary,
        }
    )
    _validate_new_result_path(result_path, (source, smoke_database, operation_lock))
    _validate_new_artifact_paths(
        {
            "smoke_database": smoke_database,
            "smoke_sha256": smoke_sha256_path,
            "source_snapshot_before": source_snapshot_before,
            "source_snapshot_before_sha256": source_snapshot_before_sha256,
            "source_snapshot_after": source_snapshot_after,
            "source_snapshot_after_sha256": source_snapshot_after_sha256,
            "post_migration_sha256": post_manifest_path,
        }
    )

    cutover_at = now()
    cutover_at_iso = _utc_iso(cutover_at)
    source_sha_before = _sha256_file(source)
    source_counts_before: Mapping[str, int] = {}
    source_evidence_before: Mapping[str, object] = {}
    source_sha_after: str | None = None
    source_counts_after: Mapping[str, int] = {}
    source_unchanged: bool | None = None
    source_snapshot_before_artifact: BackupArtifact | None = None
    source_snapshot_after_artifact: BackupArtifact | None = None
    artifact: BackupArtifact | None = None
    final_smoke_sha256: str | None = None
    post_manifest: Path | None = None
    migration_summary: Mapping[str, object] = {}
    checkpoint_summary: Mapping[str, object] = {}
    final_verification: DatabaseVerification | None = None
    evidence: Mapping[str, object] = {}
    writer_states: Mapping[str, bool] = {}
    writer_states_after: Mapping[str, bool] = {}
    writer_pause_attempted = False
    failure_stage = "snapshot"

    with _operation_lock(source):
        try:
            if config.paused_writer_services:
                assert stop_service is not None
                assert start_service is not None
                assert is_service_active is not None
                failure_stage = "writer-pause"
                writer_states = _service_states(
                    config.paused_writer_services, is_service_active
                )
                writer_pause_attempted = True
                _stop_services(config.paused_writer_services, stop_service)
                _validate_service_states(
                    _service_states(config.paused_writer_services, is_service_active),
                    {service: False for service in config.paused_writer_services},
                    context="smoke-test writer pause",
                )
                failure_stage = "snapshot"
            source_snapshot_before_artifact = create_sqlite_backup(
                source, source_snapshot_before
            )
            source_counts_before = _table_row_counts(source_snapshot_before)
            source_evidence_before = _database_evidence(source_snapshot_before)
            evidence = {"source_before": source_evidence_before}
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
            smoke_after = _database_evidence(smoke_database)
            evidence = {
                "source_before": source_evidence_before,
                "smoke_before": smoke_before,
                "smoke_after": smoke_after,
            }
            failure_stage = "data-preservation-check"
            _validate_data_preservation(smoke_before, smoke_after)

            failure_stage = "migration-verification"
            post_migration = verify_database(smoke_database)
            if post_migration.integrity_check != "ok" or post_migration.foreign_key_violations:
                raise CutoverSafetyError("Smoke-test migration failed database checks")

            failure_stage = "checkpoint-initialization"
            checkpoint_summary = dict(initialize_checkpoints(smoke_database, cutover_at))
            _validate_checkpoint_summary(checkpoint_summary)
            _validate_checkpoint_database(smoke_database, checkpoint_summary)
            smoke_final = _database_evidence(smoke_database)
            evidence = {
                "source_before": source_evidence_before,
                "smoke_before": smoke_before,
                "smoke_after": smoke_after,
                "smoke_final": smoke_final,
            }
            failure_stage = "final-data-preservation-check"
            _validate_data_preservation(smoke_before, smoke_final)
            failure_stage = "checkpoint-verification"
            final_verification = verify_database(smoke_database)
            if (
                final_verification.integrity_check != "ok"
                or final_verification.foreign_key_violations
            ):
                raise CutoverSafetyError(
                    "Smoke-test checkpoint initialization failed database checks"
                )

            final_smoke_sha256 = _sha256_file(smoke_database)
            post_manifest = post_manifest_path
            if post_manifest.exists():
                raise CutoverSafetyError(
                    f"Smoke post-migration SHA256 already exists: {post_manifest}"
                )
            post_manifest.write_text(
                f"{final_smoke_sha256}  {smoke_database.name}\n",
                encoding="utf-8",
            )
            failure_stage = "source-preservation-check"
            source_sha_after = _sha256_file(source)
            source_snapshot_after_artifact = create_sqlite_backup(
                source, source_snapshot_after
            )
            source_counts_after = _table_row_counts(source_snapshot_after)
            source_unchanged = (
                source_snapshot_before_artifact.sha256
                == source_snapshot_after_artifact.sha256
                and source_counts_before == source_counts_after
            )
            if not source_unchanged:
                raise CutoverSafetyError("Smoke-test source database changed unexpectedly")

            if writer_pause_attempted:
                assert start_service is not None
                assert stop_service is not None
                assert is_service_active is not None
                failure_stage = "writer-restore"
                _restore_service_states(
                    writer_states,
                    start_service=start_service,
                    stop_service=stop_service,
                )
                _validate_service_states(
                    _service_states(config.paused_writer_services, is_service_active),
                    writer_states,
                    context="smoke-test writer restore",
                )
                writer_states_after = _service_states(
                    config.paused_writer_services, is_service_active
                )

            report = SmokeTestReport(
                status="succeeded",
                mode="smoke-test",
                git_sha=config.git_sha,
                phase4_cutover_at=cutover_at_iso,
                source_database=str(source),
                smoke_database=str(smoke_database),
                source_sha256_before=source_sha_before,
                source_sha256_after=source_sha_after,
                source_snapshot_before=str(source_snapshot_before),
                source_snapshot_after=str(source_snapshot_after),
                source_snapshot_sha256_before=source_snapshot_before_artifact.sha256,
                source_snapshot_sha256_after=source_snapshot_after_artifact.sha256,
                source_snapshot_before_sha256_path=str(
                    source_snapshot_before_artifact.sha256_path
                ),
                source_snapshot_after_sha256_path=str(
                    source_snapshot_after_artifact.sha256_path
                ),
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
                paused_writer_services=config.paused_writer_services,
                writer_services_before=writer_states,
                writer_services_after=writer_states_after,
            )
            _write_report(result_path, report)
            return report
        except (Exception, KeyboardInterrupt) as exc:
            writer_restore_error: str | None = None
            if writer_pause_attempted:
                assert start_service is not None
                assert stop_service is not None
                assert is_service_active is not None
                try:
                    _restore_service_states(
                        writer_states,
                        start_service=start_service,
                        stop_service=stop_service,
                    )
                    _validate_service_states(
                        _service_states(config.paused_writer_services, is_service_active),
                        writer_states,
                        context="smoke-test writer recovery",
                    )
                    writer_states_after = _service_states(
                        config.paused_writer_services, is_service_active
                    )
                except Exception as writer_exc:  # noqa: BLE001
                    writer_restore_error = str(writer_exc)
            source_sha_after = _sha256_file(source)
            if source_snapshot_after_artifact is None:
                try:
                    source_snapshot_after_artifact = create_sqlite_backup(
                        source, source_snapshot_after
                    )
                except Exception:  # noqa: BLE001 - preserve the primary smoke failure
                    source_snapshot_after_artifact = None
            if source_snapshot_after_artifact is not None:
                source_counts_after = _table_row_counts(source_snapshot_after)
            source_unchanged = (
                source_snapshot_before_artifact is not None
                and source_snapshot_after_artifact is not None
                and source_snapshot_before_artifact.sha256
                == source_snapshot_after_artifact.sha256
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
                source_snapshot_before=(
                    str(source_snapshot_before)
                    if source_snapshot_before_artifact is not None
                    else None
                ),
                source_snapshot_after=(
                    str(source_snapshot_after)
                    if source_snapshot_after_artifact is not None
                    else None
                ),
                source_snapshot_sha256_before=(
                    source_snapshot_before_artifact.sha256
                    if source_snapshot_before_artifact is not None
                    else None
                ),
                source_snapshot_sha256_after=(
                    source_snapshot_after_artifact.sha256
                    if source_snapshot_after_artifact is not None
                    else None
                ),
                source_snapshot_before_sha256_path=(
                    str(source_snapshot_before_artifact.sha256_path)
                    if source_snapshot_before_artifact is not None
                    else None
                ),
                source_snapshot_after_sha256_path=(
                    str(source_snapshot_after_artifact.sha256_path)
                    if source_snapshot_after_artifact is not None
                    else None
                ),
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
                paused_writer_services=config.paused_writer_services,
                writer_services_before=writer_states,
                writer_services_after=writer_states_after,
                failure_stage=failure_stage,
                error=(
                    str(exc)
                    if writer_restore_error is None
                    else f"{exc}; writer recovery failed: {writer_restore_error}"
                ),
            )
            _write_report(result_path, report)
            raise CutoverExecutionError(report.error or str(exc)) from exc


def execute_rollback(
    config: RollbackConfig,
    dependencies: RollbackDependencies,
) -> RollbackReport:
    """Restore a selected verified backup and reactivate the legacy services."""

    database = config.database_path.expanduser().resolve()
    backup = config.backup_path.expanduser().resolve()
    sha256_path = config.sha256_path.expanduser().resolve()
    result_path = config.result_path.expanduser().resolve()
    rollback_at = dependencies.now()
    rollback_at_iso = _utc_iso(rollback_at)
    backup_directory = (
        config.backup_directory.expanduser().resolve()
        if config.backup_directory is not None
        else backup.parent / "pre-rollback"
    )
    timestamp = rollback_at.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    pre_rollback_path = (
        backup_directory
        / f"{database.stem}_pre_manual_rollback_{timestamp}{database.suffix}"
    )
    pre_rollback_sha256_path = pre_rollback_path.with_suffix(
        pre_rollback_path.suffix + ".sha256"
    )
    result_temporary = result_path.with_suffix(result_path.suffix + ".tmp")
    operation_lock = database.with_suffix(database.suffix + ".phase4.lock")
    _validate_distinct_artifact_paths(
        {
            "operational_database": database,
            "selected_backup": backup,
            "selected_backup_sha256": sha256_path,
            "operation_lock": operation_lock,
            "pre_rollback_backup": pre_rollback_path,
            "pre_rollback_sha256": pre_rollback_sha256_path,
            "result_json": result_path,
            "result_json_temporary": result_temporary,
        }
    )
    _validate_new_result_path(
        result_path,
        (database, backup, sha256_path, operation_lock),
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
                primary_error=message,
                rollback_attempted=False,
                rollback_succeeded=None,
                rollback_error=None,
            ),
        )

    if not database.is_file():
        message = f"Operational database does not exist: {database}"
        record_preflight_failure(message)
        raise CutoverSafetyError(message)
    try:
        verify_phase3b_database_identity(database)
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
        verify_phase3b_database_identity(backup)
    except Exception as exc:
        record_preflight_failure(str(exc))
        raise

    if pre_rollback_path.exists() or pre_rollback_sha256_path.exists():
        message = (
            "Pre-rollback backup destination already exists: "
            f"{pre_rollback_path}"
        )
        record_preflight_failure(message)
        raise CutoverSafetyError(message)

    pre_rollback_artifact: BackupArtifact | None = None
    restored: DatabaseVerification | None = None
    database_mutation_started = False
    failure_stage = "service-stop"

    with _operation_lock(database):
        try:
            _stop_services(all_services, dependencies.stop_service)

            failure_stage = "pre-rollback-backup"
            pre_rollback_artifact = create_sqlite_backup(database, pre_rollback_path)
            if (
                pre_rollback_artifact.integrity_check != "ok"
                or pre_rollback_artifact.foreign_key_violations
            ):
                raise CutoverSafetyError(
                    "Pre-rollback backup failed integrity or foreign-key checks"
                )
            verify_phase3b_database_identity(pre_rollback_artifact.database_path)

            failure_stage = "database-restore"
            database_mutation_started = True
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
            failure_stage = "post-service-verification"
            services_after = _service_states(all_services, dependencies.is_service_active)
            _validate_service_states(
                services_after,
                _expected_rollback_service_states(config, services_before),
                context="manual rollback",
            )

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
        except (Exception, KeyboardInterrupt) as exc:
            recovery_errors: list[str] = []
            database_safe = not database_mutation_started
            if pre_rollback_artifact is not None and database_mutation_started:
                try:
                    restore_sqlite_backup(
                        target_path=database,
                        backup_path=pre_rollback_artifact.database_path,
                        sha256_path=pre_rollback_artifact.sha256_path,
                    )
                    database_safe = True
                except Exception as restore_exc:  # noqa: BLE001
                    recovery_errors.append(str(restore_exc))
            if database_safe:
                try:
                    _restore_service_states(
                        services_before,
                        start_service=dependencies.start_service,
                        stop_service=dependencies.stop_service,
                    )
                except Exception as service_exc:  # noqa: BLE001
                    recovery_errors.append(str(service_exc))
            else:
                recovery_errors.append(
                    "service restart skipped because database recovery was not verified"
                )
            services_after: Mapping[str, bool] = {}
            try:
                services_after = _service_states(
                    all_services, dependencies.is_service_active
                )
                if database_safe:
                    _validate_service_states(
                        services_after,
                        services_before,
                        context="rollback recovery",
                    )
            except Exception as verification_exc:  # noqa: BLE001
                recovery_errors.append(str(verification_exc))
            error_message = str(exc)
            if recovery_errors:
                error_message += "; rollback recovery failed: " + "; ".join(
                    recovery_errors
                )
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
                primary_error=str(exc),
                rollback_attempted=True,
                rollback_succeeded=not recovery_errors,
                rollback_error=(
                    "; ".join(recovery_errors) if recovery_errors else None
                ),
            )
            _write_report(result_path, report)
            raise CutoverExecutionError(error_message) from exc
