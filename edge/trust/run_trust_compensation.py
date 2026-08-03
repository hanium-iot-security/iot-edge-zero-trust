"""CLI for one operator-approved Trust Score compensation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence


if __package__ in (None, ""):
    sys.path.append(str(Path(__file__).resolve().parents[2]))

from edge.trust.trust_compensation import (
    TrustCompensationCommittedArtifactError,
    TrustCompensationError,
    execute_trust_compensation,
    inspect_trust_compensation,
)


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db-path", type=Path, required=True)
    parser.add_argument("--device", required=True, dest="device_id")
    parser.add_argument("--source-event-id", type=int, required=True)
    parser.add_argument("--expected-status", required=True)
    parser.add_argument("--expected-trust-score", type=int, required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--approved-by", required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="검증된 단일 오탐 감점을 운영자 승인으로 정확히 보상합니다."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    dry_run = subparsers.add_parser("dry-run", help="변경 없이 보상 가능성 확인")
    _add_common_arguments(dry_run)

    execute = subparsers.add_parser("execute", help="Backup 후 보상과 감사 Row 기록")
    _add_common_arguments(execute)
    execute.add_argument("--confirm", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    parameters = {
        "db_path": args.db_path,
        "device_id": args.device_id,
        "source_event_id": args.source_event_id,
        "expected_status": args.expected_status,
        "expected_trust_score": args.expected_trust_score,
        "reason": args.reason,
        "approved_by": args.approved_by,
        "artifact_dir": args.artifact_dir,
    }
    try:
        if args.mode == "dry-run":
            result = inspect_trust_compensation(**parameters)
        else:
            result = execute_trust_compensation(
                **parameters,
                confirm=args.confirm,
            )
    except TrustCompensationCommittedArtifactError as exc:
        print(
            json.dumps(
                {
                    "mode": args.mode,
                    "result": "FAILED",
                    "database_committed": True,
                    "operation_status": "HOLD",
                    "operation_id": exc.operation_id,
                    "backup_path": str(exc.backup_path),
                    "error": str(exc),
                },
                ensure_ascii=False,
                indent=2,
            ),
            file=sys.stderr,
        )
        return 3
    except TrustCompensationError as exc:
        print(
            json.dumps(
                {
                    "mode": args.mode,
                    "result": "FAILED",
                    "database_committed": False,
                    "error": str(exc),
                },
                ensure_ascii=False,
                indent=2,
            ),
            file=sys.stderr,
        )
        return 2

    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.mode == "dry-run" and not result["can_execute"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
