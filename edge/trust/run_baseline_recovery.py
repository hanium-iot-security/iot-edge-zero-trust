"""CLI for explicit Device status and Trust Score baseline recovery."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence


if __package__ in (None, ""):
    sys.path.append(str(Path(__file__).resolve().parents[2]))

from edge.trust.baseline_recovery import (
    BaselineRecoveryError,
    BaselineRecoveryHoldError,
    execute_baseline_recovery,
    inspect_baseline_recovery,
    parse_device_expectations,
)


def _add_target_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db-path", type=Path, required=True)
    parser.add_argument("--device", action="append", required=True, dest="devices")
    parser.add_argument(
        "--expected-trust-score",
        action="append",
        required=True,
        default=[],
        dest="expected_trust_scores",
        metavar="DEVICE=SCORE",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="격리 Device의 status와 Trust Score Baseline을 안전하게 복구합니다."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    dry_run = subparsers.add_parser("dry-run", help="변경 없이 실행 가능성을 확인")
    _add_target_arguments(dry_run)
    dry_run.add_argument("--artifact-dir", type=Path, required=True)

    execute = subparsers.add_parser("execute", help="Backup 후 조건부 복구 실행")
    _add_target_arguments(execute)
    execute.add_argument("--artifact-dir", type=Path, required=True)
    execute.add_argument("--confirm", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        expected_scores = parse_device_expectations(
            args.devices,
            args.expected_trust_scores,
        )
        if args.mode == "dry-run":
            result = inspect_baseline_recovery(
                db_path=args.db_path,
                device_ids=args.devices,
                expected_trust_scores=expected_scores,
                artifact_dir=args.artifact_dir,
            )
        else:
            result = execute_baseline_recovery(
                db_path=args.db_path,
                device_ids=args.devices,
                expected_trust_scores=expected_scores,
                artifact_dir=args.artifact_dir,
                confirm=args.confirm,
            )
    except BaselineRecoveryError as exc:
        print(
            json.dumps(
                {"mode": args.mode, "result": "HOLD" if isinstance(exc, BaselineRecoveryHoldError) else "FAILED", "error": str(exc)},
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
