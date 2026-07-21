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
from typing import Callable, Mapping, Sequence

from db.migration_runner import apply_migrations
from edge.scripts.phase4_cutover import (
    CutoverConfig,
    CutoverDependencies,
    CutoverSafetyError,
    SmokeTestConfig,
    execute_cutover,
    run_cutover_smoke_test,
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
    overlap = set(legacy_services) & set(new_services)
    if overlap:
        raise CutoverSafetyError(f"Legacy and new service sets overlap: {sorted(overlap)}")
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
                    "checkpoint_initializer": args.checkpoint_initializer,
                    "execution_order": [
                        "stop legacy and new services",
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
        initializer = _load_initializer(args.checkpoint_initializer)
        report = run_cutover_smoke_test(
            SmokeTestConfig(
                source_database_path=database,
                smoke_database_path=args.smoke_database,
                migrations_directory=args.migrations_dir,
                result_path=result_path,
                git_sha=args.git_sha,
            ),
            apply_migrations=_migration_adapter,
            initialize_checkpoints=initializer,
        )
        print(json.dumps({"status": report.status, "result": str(result_path.resolve())}))
        return 0

    if args.confirm != "PHASE4-CUTOVER":
        raise CutoverSafetyError("--execute requires --confirm PHASE4-CUTOVER")
    if not new_services:
        raise CutoverSafetyError("Operational cutover requires at least one --new-service")
    _require_root_for_operational_cutover()
    initializer = _load_initializer(args.checkpoint_initializer)
    report = execute_cutover(
        CutoverConfig(
            database_path=database,
            backup_directory=backup_directory,
            migrations_directory=args.migrations_dir,
            result_path=result_path,
            git_sha=args.git_sha,
            legacy_services=legacy_services,
            new_services=new_services,
        ),
        CutoverDependencies(
            stop_service=lambda service: _systemctl("stop", service),
            start_service=lambda service: _systemctl("start", service),
            apply_migrations=_migration_adapter,
            initialize_checkpoints=initializer,
        ),
    )
    print(json.dumps({"status": report.status, "result": str(result_path)}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CutoverSafetyError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
