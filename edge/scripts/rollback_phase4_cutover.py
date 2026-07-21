"""Guarded CLI for restoring a Phase 4 pre-cutover SQLite backup."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Sequence

from edge.scripts.phase4_cutover import (
    CutoverSafetyError,
    RollbackConfig,
    RollbackDependencies,
    execute_rollback,
)
from edge.scripts.run_phase4_cutover import _validate_services


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--sha256", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--legacy-service", action="append", default=[])
    parser.add_argument("--new-service", action="append", default=[])
    parser.add_argument("--confirm")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    return parser


def _systemctl(action: str, service: str) -> None:
    subprocess.run(["systemctl", action, service], check=True)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    database = args.database.expanduser().resolve()
    backup = args.backup.expanduser().resolve()
    sha256_path = args.sha256.expanduser().resolve()
    result_path = args.result.expanduser().resolve()
    legacy_services = _validate_services(args.legacy_service)
    new_services = _validate_services(args.new_service)

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
    report = execute_rollback(
        RollbackConfig(
            database_path=database,
            backup_path=backup,
            sha256_path=sha256_path,
            result_path=result_path,
            git_sha=args.git_sha,
            legacy_services=legacy_services,
            new_services=new_services,
        ),
        RollbackDependencies(
            stop_service=lambda service: _systemctl("stop", service),
            start_service=lambda service: _systemctl("start", service),
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
