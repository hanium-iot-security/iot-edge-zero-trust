"""Guarded CLI for restoring a Phase 4 pre-cutover SQLite backup."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Sequence

from edge.scripts.phase4_cutover import (
    CutoverExecutionError,
    CutoverSafetyError,
    RollbackConfig,
    RollbackDependencies,
    execute_rollback,
)
from edge.scripts.run_phase4_cutover import (
    _probe_writable_directory,
    _validate_services,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--sha256", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--pre-rollback-backup-dir", type=Path)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--legacy-service", action="append", default=[])
    parser.add_argument("--new-service", action="append", default=[])
    parser.add_argument("--writer-service", action="append", default=[])
    parser.add_argument("--confirm")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    return parser


def _systemctl(action: str, service: str) -> None:
    subprocess.run(["systemctl", action, service], check=True)


def _systemctl_is_active(service: str) -> bool:
    return (
        subprocess.run(
            ["systemctl", "is-active", "--quiet", service],
            check=False,
        ).returncode
        == 0
    )


def _validate_rollback_preflight(
    *,
    database: Path,
    backup: Path,
    sha256_path: Path,
    pre_rollback_backup_directory: Path,
    result_path: Path,
) -> None:
    for required_file, label in (
        (database, "Operational database"),
        (backup, "Selected rollback backup"),
        (sha256_path, "Selected rollback SHA256 manifest"),
    ):
        if not required_file.is_file():
            raise CutoverSafetyError(f"{label} does not exist: {required_file}")
    if result_path.exists():
        raise CutoverSafetyError(f"Rollback result already exists: {result_path}")

    required_bytes = max(
        database.stat().st_size + backup.stat().st_size,
        10 * 1024 * 1024,
    )
    directories = {
        database.parent.resolve(),
        pre_rollback_backup_directory.resolve(),
        result_path.parent.resolve(),
    }
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
                f"Insufficient disk space for rollback output path: {directory}"
            )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    database = args.database.expanduser().resolve()
    backup = args.backup.expanduser().resolve()
    sha256_path = args.sha256.expanduser().resolve()
    result_path = args.result.expanduser().resolve()
    legacy_services = _validate_services(args.legacy_service)
    new_services = _validate_services(args.new_service)
    writer_services = _validate_services(args.writer_service)
    all_services = legacy_services + new_services + writer_services
    if len(all_services) != len(set(all_services)):
        raise CutoverSafetyError(
            "Legacy, new, and writer service sets must not overlap"
        )

    if args.dry_run:
        print(
            json.dumps(
                {
                    "mode": "dry-run",
                    "will_restore_database": False,
                    "database": str(database),
                    "backup": str(backup),
                    "sha256": str(sha256_path),
                    "result": str(result_path),
                    "new_services_to_stop": new_services,
                    "legacy_services_to_start": legacy_services,
                    "paused_writer_services": writer_services,
                    "pre_rollback_backup_directory": str(
                        args.pre_rollback_backup_dir.resolve()
                        if args.pre_rollback_backup_dir
                        else backup.parent / "pre-rollback"
                    ),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.confirm != "PHASE4-ROLLBACK":
        raise CutoverSafetyError("--execute requires --confirm PHASE4-ROLLBACK")
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
        raise CutoverSafetyError("Operational rollback must run as root on Raspberry Pi")
    pre_rollback_backup_directory = (
        args.pre_rollback_backup_dir.expanduser().resolve()
        if args.pre_rollback_backup_dir is not None
        else backup.parent / "pre-rollback"
    )
    _validate_rollback_preflight(
        database=database,
        backup=backup,
        sha256_path=sha256_path,
        pre_rollback_backup_directory=pre_rollback_backup_directory,
        result_path=result_path,
    )
    report = execute_rollback(
        RollbackConfig(
            database_path=database,
            backup_path=backup,
            sha256_path=sha256_path,
            backup_directory=args.pre_rollback_backup_dir,
            result_path=result_path,
            git_sha=args.git_sha,
            legacy_services=legacy_services,
            new_services=new_services,
            paused_writer_services=writer_services,
        ),
        RollbackDependencies(
            stop_service=lambda service: _systemctl("stop", service),
            start_service=lambda service: _systemctl("start", service),
            is_service_active=_systemctl_is_active,
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
