"""Manual Packet Isolation Forest detector runner.

The production runtime should invoke PacketIsolationForestStage through the
Phase 4 orchestrator. This CLI is for controlled smoke tests and recovery
verification.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager, nullcontext
from datetime import datetime
import json
import logging
import os
from pathlib import Path
from typing import Iterator, Sequence

from backend.app.database import SessionLocal
from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.packet_ai_detector import PacketIsolationForestStage
from edge.detection.phase4_time import format_db_utc, parse_db_utc
from edge.packet.capture_session_repository import (
    get_packet_feature_ready_through,
)


logger = logging.getLogger(__name__)
DEFAULT_LOCK_PATH = Path("data/phase4-detection-cycle.lock")


def _parse_cli_utc(value: str) -> datetime:
    if not value.endswith("Z") or "." in value:
        raise argparse.ArgumentTypeError(
            "timestamp must use whole-second UTC Z format"
        )
    try:
        return parse_db_utc(value, "timestamp")
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="지정한 UTC Window 범위의 Packet IF Stage를 한 번 실행합니다."
    )
    parser.add_argument(
        "--session-id",
        required=True,
        help="검증할 Capture Session UUID",
    )
    parser.add_argument(
        "--range-start",
        type=_parse_cli_utc,
        required=True,
        help="포함할 시작 시각(UTC 10초 경계, 예: 2026-07-26T10:00:00Z)",
    )
    parser.add_argument(
        "--cutoff",
        type=_parse_cli_utc,
        required=True,
        help="포함하지 않을 종료 시각(UTC 10초 경계)",
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        help="설정된 PACKET_IF_ARTIFACT_DIR 대신 사용할 Artifact Directory",
    )
    parser.add_argument(
        "--expected-model-version",
        help="설정된 PACKET_IF_EXPECTED_MODEL_VERSION 대신 검증할 Version",
    )
    parser.add_argument(
        "--expected-bundle-sha256",
        help="설정된 PACKET_IF_EXPECTED_BUNDLE_SHA256 대신 검증할 외부 SHA256",
    )
    parser.add_argument(
        "--commit",
        action="store_true",
        help="Event와 Checkpoint를 실제로 커밋합니다. 생략하면 검증 후 롤백합니다.",
    )
    parser.add_argument(
        "--lock-path",
        type=Path,
        default=DEFAULT_LOCK_PATH,
        help="--commit 실행의 단일 프로세스 Lock 경로",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    stage = PacketIsolationForestStage.from_settings(
        artifact_dir=args.artifact_dir,
        expected_model_version=args.expected_model_version,
        expected_bundle_sha256=args.expected_bundle_sha256,
    )

    lock_context = _runner_lock(args.lock_path) if args.commit else nullcontext()
    with lock_context:
        with SessionLocal() as db:
            transaction = db.begin()
            try:
                _validate_manual_range(
                    db,
                    session_id=args.session_id,
                    range_start=args.range_start,
                    cutoff=args.cutoff,
                )
                result = stage.run_until_for_capture_session(
                    db,
                    cycle_range_start=args.range_start,
                    cycle_cutoff=args.cutoff,
                    expected_capture_session_id=args.session_id,
                )
                if args.commit:
                    transaction.commit()
                else:
                    transaction.rollback()
            except BaseException:
                if transaction.is_active:
                    transaction.rollback()
                raise

    print(
        json.dumps(
            {
                "committed": args.commit,
                "session_id": args.session_id,
                "detector_name": result.detector_name,
                "source_table": result.source_table,
                "range_start": format_db_utc(result.range_start),
                "cutoff": format_db_utc(result.cutoff),
                "selected_count": result.selected_count,
                "created_event_count": result.created_event_count,
                "last_processed_id_before": result.last_processed_id_before,
                "last_processed_id_after": result.last_processed_id_after,
                "completed_window_end_before": (
                    format_db_utc(result.completed_window_end_before)
                    if result.completed_window_end_before is not None
                    else None
                ),
                "completed_window_end_after": format_db_utc(
                    result.completed_window_end_after
                ),
            },
            sort_keys=True,
        )
    )
    return 0


def _validate_manual_range(
    db,
    *,
    session_id: str,
    range_start: datetime,
    cutoff: datetime,
) -> None:
    readiness = get_packet_feature_ready_through(
        db,
        session_id=session_id,
    )
    if readiness is None:
        raise ValueError(f"Capture Session not found: {session_id}")
    if readiness.first_window_start is None:
        raise RuntimeError(
            f"Capture Session has no first_window_start: {session_id}"
        )
    if readiness.packet_feature_ready_through is None:
        raise RuntimeError(
            f"Capture Session has no Packet Feature ready range: {session_id}"
        )
    if cutoff > readiness.packet_feature_ready_through:
        raise RuntimeError(
            "Packet IF cutoff exceeds the contiguous Packet Feature ready range: "
            f"cutoff={format_db_utc(cutoff)}, "
            "packet_feature_ready_through="
            f"{format_db_utc(readiness.packet_feature_ready_through)}"
        )

    checkpoint = checkpoints.get_detector_checkpoint(
        db,
        detector_name="packet_if",
        source_table="packet_feature_logs",
    )
    expected_range_start = readiness.first_window_start
    if checkpoint is not None and checkpoint["last_completed_window_end"] is not None:
        expected_range_start = parse_db_utc(
            checkpoint["last_completed_window_end"],
            "last_completed_window_end",
        )
        if expected_range_start < readiness.first_window_start:
            raise RuntimeError(
                "Packet IF manual runner cannot bridge a Capture Session gap: "
                "checkpoint="
                f"{format_db_utc(expected_range_start)}, "
                "session_first_window="
                f"{format_db_utc(readiness.first_window_start)}"
            )
    if range_start != expected_range_start:
        raise RuntimeError(
            "Packet IF manual range must continue from the current checkpoint "
            "or the Session first window: "
            f"expected={format_db_utc(expected_range_start)}, "
            f"actual={format_db_utc(range_start)}"
        )


@contextmanager
def _runner_lock(lock_path: Path) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock_file:
        lock_file.seek(0, os.SEEK_END)
        if lock_file.tell() == 0:
            lock_file.write(b"0")
            lock_file.flush()

        if os.name == "posix":
            import fcntl

            try:
                fcntl.flock(
                    lock_file.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
            except BlockingIOError as exc:
                raise RuntimeError(
                    f"another detection process holds the lock: {lock_path}"
                ) from exc
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            return

        if os.name == "nt":
            import msvcrt

            lock_file.seek(0)
            try:
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError(
                    f"another detection process holds the lock: {lock_path}"
                ) from exc
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            return

        raise RuntimeError(
            f"unsupported platform for Packet IF commit lock: {os.name}"
        )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    raise SystemExit(main())
