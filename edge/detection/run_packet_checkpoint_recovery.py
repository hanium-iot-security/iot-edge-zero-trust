"""CLI for query-only packet checkpoint recovery inspection."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from typing import Sequence

from edge.detection.packet_checkpoint_recovery import (
    PacketCheckpointRecoveryError,
    inspect_packet_checkpoint_recovery,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-path", required=True)
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--detector", required=True)
    parser.add_argument("--current-session-id", required=True)
    parser.add_argument("--target-session-id", required=True)
    parser.add_argument("--approved-by", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--plan-output", required=True)
    parser.add_argument("--orchestrator-lock-path", type=Path)
    parser.add_argument("--manual-lock-path", type=Path)
    parser.add_argument("--extractor-lock-path", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        plan = inspect_packet_checkpoint_recovery(
            db_path=args.db_path,
            repository_root=args.repository_root,
            detector_name=args.detector,
            current_session_id=args.current_session_id,
            target_session_id=args.target_session_id,
            approved_by=args.approved_by,
            reason=args.reason,
            plan_output=args.plan_output,
            orchestrator_lock_path=args.orchestrator_lock_path,
            manual_lock_path=args.manual_lock_path,
            extractor_lock_path=args.extractor_lock_path,
        )
    except (
        PacketCheckpointRecoveryError,
        OSError,
        sqlite3.DatabaseError,
        subprocess.CalledProcessError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(plan, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
