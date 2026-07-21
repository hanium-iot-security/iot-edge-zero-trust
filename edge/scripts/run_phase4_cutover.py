"""Guarded CLI for the Phase 4 database cutover."""

from __future__ import annotations

import argparse
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import shutil
import tempfile
from typing import Callable, Mapping, Sequence

from db.migration_runner import (
    MigrationError,
    apply_migrations,
    discover_migrations,
)
from edge.scripts.phase4_cutover import (
    CutoverConfig,
    CutoverDependencies,
    CutoverExecutionError,
    CutoverSafetyError,
    SmokeTestConfig,
    execute_cutover,
    run_cutover_smoke_test,
    termination_signal_guard,
)


DEFAULT_CHECKPOINT_INITIALIZER = (
    "edge.detection.phase4_cutover_repository:initialize_phase4_cutover"
)
SERVICE_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]+\.service$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--migrations-dir", type=Path, default=Path("db/migrations"))
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--legacy-service", action="append", default=[])
    parser.add_argument("--new-service", action="append", default=[])
    parser.add_argument("--writer-service", action="append", default=[])
    parser.add_argument("--checkpoint-initializer", default=DEFAULT_CHECKPOINT_INITIALIZER)
    parser.add_argument("--smoke-database", type=Path)
    parser.add_argument("--confirm")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--smoke-test", action="store_true")
    mode.add_argument("--execute", action="store_true")
    return parser


def _validate_services(services: Sequence[str]) -> tuple[str, ...]:
    result = tuple(services)
    invalid = [service for service in result if not SERVICE_PATTERN.fullmatch(service)]
    if invalid:
        raise CutoverSafetyError(f"Invalid systemd service names: {invalid}")
    if len(result) != len(set(result)):
        raise CutoverSafetyError("Duplicate systemd service names are not allowed")
    return result


def _load_initializer(import_path: str) -> Callable[[Path, object], Mapping[str, object]]:
    try:
        module_name, function_name = import_path.split(":", 1)
        function = getattr(importlib.import_module(module_name), function_name)
    except (ValueError, ImportError, AttributeError) as exc:
        raise CutoverSafetyError(
            "Checkpoint initializer is unavailable. Merge the P4-0-03 DB function first: "
            f"{import_path}"
        ) from exc
    if not callable(function):
        raise CutoverSafetyError(f"Checkpoint initializer is not callable: {import_path}")
    return function


def _systemctl(action: str, service: str) -> None:
    subprocess.run(["systemctl", action, service], check=True)


def _systemctl_is_active(service: str) -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", service],
        check=False,
    )
    return result.returncode == 0


def _validate_operational_preflight(
    database: Path,
    migrations_directory: Path,
    services: tuple[str, ...],
    *,
    backup_directory: Path | None = None,
    result_path: Path | None = None,
) -> None:
    migrations = migrations_directory.expanduser().resolve()
    try:
        discovered = discover_migrations(migrations)
    except MigrationError as exc:
        raise CutoverSafetyError(f"Migration preflight failed: {exc}") from exc
    version_3 = [migration for migration in discovered if migration.version == 3]
    if len(version_3) != 1:
        raise CutoverSafetyError(
            "Migration set must contain exactly one version 3; "
            f"found={len(version_3)}"
        )

    resolved_database = database.expanduser().resolve()
    directories = {resolved_database.parent}
    if backup_directory is not None:
        directories.add(backup_directory.expanduser().resolve())
    if result_path is not None:
        resolved_result = result_path.expanduser().resolve()
        if resolved_result.exists():
            raise CutoverSafetyError(f"Cutover result already exists: {resolved_result}")
        directories.add(resolved_result.parent)

    required_bytes = max(database.stat().st_size * 3, 10 * 1024 * 1024)
    checked_filesystems: set[int] = set()
    for directory in sorted(directories, key=str):
        _probe_writable_directory(directory)
        disk_path = directory
        while not disk_path.exists() and disk_path != disk_path.parent:
            disk_path = disk_path.parent
        device = disk_path.stat().st_dev
        if device in checked_filesystems:
            continue
        checked_filesystems.add(device)
        if shutil.disk_usage(disk_path).free < required_bytes:
            raise CutoverSafetyError(
                f"Insufficient disk space for Phase 4 output path: {directory}"
            )
    for service in services:
        result = subprocess.run(
            ["systemctl", "show", service, "--property=LoadState", "--value"],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0 or result.stdout.strip() == "not-found":
            raise CutoverSafetyError(f"systemd service unit is unavailable: {service}")


def _probe_writable_directory(directory: Path) -> None:
    """Create, fsync, and remove a probe in an actual operation output directory."""

    descriptor: int | None = None
    probe_path: Path | None = None
    try:
        directory.mkdir(parents=True, exist_ok=True)
        descriptor, probe_name = tempfile.mkstemp(
            prefix=".phase4-preflight-",
            suffix=".tmp",
            dir=directory,
        )
        probe_path = Path(probe_name)
        os.write(descriptor, b"phase4-preflight\n")
        os.fsync(descriptor)
    except OSError as exc:
        raise CutoverSafetyError(
            f"Phase 4 output directory is not writable: {directory}: {exc}"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if probe_path is not None:
            try:
                probe_path.unlink()
            except FileNotFoundError:
                pass


def _require_root_for_operational_cutover() -> None:
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
        raise CutoverSafetyError("Operational cutover must run as root on Raspberry Pi")


def _migration_adapter(database: Path, migrations_directory: Path) -> object:
    return apply_migrations(db_path=database, migrations_dir=migrations_directory)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    database = args.database.expanduser().resolve()
    backup_directory = args.backup_dir.expanduser().resolve()
    result_path = args.result.expanduser().resolve()
    legacy_services = _validate_services(args.legacy_service)
    new_services = _validate_services(args.new_service)
    writer_services = _validate_services(args.writer_service)
    overlap = (
        (set(legacy_services) & set(new_services))
        | (set(legacy_services) & set(writer_services))
        | (set(new_services) & set(writer_services))
    )
    if overlap:
        raise CutoverSafetyError(
            f"Legacy, new, and writer service sets overlap: {sorted(overlap)}"
        )
    if not database.is_file():
        raise CutoverSafetyError(f"Operational database does not exist: {database}")

    if args.dry_run:
        print(
            json.dumps(
                {
                    "mode": "dry-run",
                    "will_modify_database": False,
                    "database": str(database),
                    "backup_directory": str(backup_directory),
                    "result": str(result_path),
                    "git_sha": args.git_sha,
                    "legacy_services_to_stop": legacy_services,
                    "new_services_to_start": new_services,
                    "paused_writer_services": writer_services,
                    "checkpoint_initializer": args.checkpoint_initializer,
                    "execution_order": [
                        "record service states and stop legacy, new, and writer services",
                        "create SQLite backup and SHA256",
                        "apply migrations",
                        "run foreign_key_check and integrity_check",
                        "initialize cutover checkpoints",
                        "verify database",
                        "start new services",
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.smoke_test:
        if args.smoke_database is None:
            raise CutoverSafetyError("--smoke-test requires --smoke-database")
        _validate_operational_preflight(
            database,
            args.migrations_dir,
            writer_services,
            backup_directory=args.smoke_database.parent,
            result_path=result_path,
        )
        initializer = _load_initializer(args.checkpoint_initializer)
        with termination_signal_guard():
            report = run_cutover_smoke_test(
                SmokeTestConfig(
                    source_database_path=database,
                    smoke_database_path=args.smoke_database,
                    migrations_directory=args.migrations_dir,
                    result_path=result_path,
                    git_sha=args.git_sha,
                    paused_writer_services=writer_services,
                ),
                apply_migrations=_migration_adapter,
                initialize_checkpoints=initializer,
                stop_service=lambda service: _systemctl("stop", service),
                start_service=lambda service: _systemctl("start", service),
                is_service_active=_systemctl_is_active,
            )
        print(json.dumps({"status": report.status, "result": str(result_path.resolve())}))
        return 0

    if args.confirm != "PHASE4-CUTOVER":
        raise CutoverSafetyError("--execute requires --confirm PHASE4-CUTOVER")
    if not new_services:
        raise CutoverSafetyError("Operational cutover requires at least one --new-service")
    _require_root_for_operational_cutover()
    initializer = _load_initializer(args.checkpoint_initializer)
    _validate_operational_preflight(
        database,
        args.migrations_dir,
        legacy_services + new_services + writer_services,
        backup_directory=backup_directory,
        result_path=result_path,
    )
    with termination_signal_guard():
        report = execute_cutover(
            CutoverConfig(
                database_path=database,
                backup_directory=backup_directory,
                migrations_directory=args.migrations_dir,
                result_path=result_path,
                git_sha=args.git_sha,
                legacy_services=legacy_services,
                new_services=new_services,
                paused_writer_services=writer_services,
            ),
            CutoverDependencies(
                stop_service=lambda service: _systemctl("stop", service),
                start_service=lambda service: _systemctl("start", service),
                is_service_active=_systemctl_is_active,
                apply_migrations=_migration_adapter,
                initialize_checkpoints=initializer,
            ),
        )
    print(json.dumps({"status": report.status, "result": str(result_path)}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CutoverSafetyError, CutoverExecutionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
