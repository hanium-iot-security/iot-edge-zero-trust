"""CLI for packet checkpoint recovery inspection and execution."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import subprocess
from typing import Sequence

from edge.detection.packet_checkpoint_recovery import (
    GAP_RECOVERY_MODE,
    LIVE_RESUME_MODE,
    PacketCheckpointRecoveryCommittedArtifactError,
    PacketCheckpointRecoveryError,
    execute_packet_checkpoint_recovery,
    inspect_packet_checkpoint_recovery,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    dry_run = commands.add_parser("dry-run")
    dry_run.add_argument("--db-path", required=True)
    dry_run.add_argument("--repository-root", required=True)
    dry_run.add_argument("--detector", required=True)
    dry_run.add_argument("--current-session-id", required=True)
    dry_run.add_argument("--target-session-id", required=True)
    dry_run.add_argument("--approved-by", required=True)
    dry_run.add_argument("--reason", required=True)
    dry_run.add_argument("--plan-output", required=True)
    dry_run.add_argument("--allow-failed-current-session", action="store_true")
    dry_run.add_argument(
        "--mode",
        choices=(GAP_RECOVERY_MODE, LIVE_RESUME_MODE),
        default=GAP_RECOVERY_MODE,
    )
    dry_run.add_argument("--orchestrator-lock-path", type=Path)
    dry_run.add_argument("--manual-lock-path", type=Path)
    dry_run.add_argument("--extractor-lock-path", type=Path)
    execute = commands.add_parser("execute")
    execute.add_argument("--plan-file", required=True)
    execute.add_argument("--db-path", required=True)
    execute.add_argument("--artifact-dir", required=True)
    execute.add_argument("--confirm", required=True)
    execute.add_argument("--confirm-skip-processable")
    return parser


def _run_command(args: argparse.Namespace) -> dict[str, object]:
    if args.command == "dry-run":
        return inspect_packet_checkpoint_recovery(
            db_path=args.db_path,
            repository_root=args.repository_root,
            detector_name=args.detector,
            current_session_id=args.current_session_id,
            target_session_id=args.target_session_id,
            approved_by=args.approved_by,
            reason=args.reason,
            plan_output=args.plan_output,
            mode=args.mode,
            allow_failed_current_session=args.allow_failed_current_session,
            orchestrator_lock_path=args.orchestrator_lock_path,
            manual_lock_path=args.manual_lock_path,
            extractor_lock_path=args.extractor_lock_path,
        )
    return execute_packet_checkpoint_recovery(
        plan_file=args.plan_file,
        db_path=args.db_path,
        artifact_dir=args.artifact_dir,
        confirm=args.confirm,
        confirm_skip_processable=args.confirm_skip_processable,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = _run_command(args)
    except PacketCheckpointRecoveryCommittedArtifactError as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "database_committed": True,
                    "operation_status": "HOLD",
                    "operation_id": exc.operation_id,
                    "backup_path": str(exc.backup_path),
                    "error": str(exc),
                },
                sort_keys=True,
            )
        )
        return 3
    except (
        PacketCheckpointRecoveryError,
        OSError,
        sqlite3.DatabaseError,
        subprocess.CalledProcessError,
    ) as exc:
        print(
            json.dumps(
                {"ok": False, "database_committed": False, "error": str(exc)},
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
