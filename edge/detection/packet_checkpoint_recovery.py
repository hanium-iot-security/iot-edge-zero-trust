"""Canonical plan helpers for packet checkpoint gap recovery."""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
import shlex
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
import sqlite3
import stat
import subprocess
import uuid
from datetime import datetime, timezone
from tempfile import NamedTemporaryFile
from typing import Callable, ContextManager, Iterator, Mapping, Sequence

from backend.app.config import Settings
from edge.detection import packet_checkpoint_recovery_repository as recovery_repository
from edge.detection import run_packet_ai_detector, run_packet_rule_detector
from edge.detection.phase4_time import format_db_utc, parse_db_utc
from edge.features import run_packet_feature_extractor
from edge.orchestration import run_detection_orchestrator
from edge.runtime_lock import single_instance_lock
from edge.scripts.phase4_cutover_storage import (
    create_sqlite_backup,
    file_sha256,
    verify_database,
)


PLAN_SCHEMA_VERSION = "packet-checkpoint-gap-recovery-plan-v1"
GAP_RECOVERY_MODE = "gap-recovery"
LIVE_RESUME_MODE = "live-resume"
BOUNDED_REPLAY_MODE = "bounded-replay"
RECOVERY_MODES = frozenset({GAP_RECOVERY_MODE, LIVE_RESUME_MODE, BOUNDED_REPLAY_MODE})
EXECUTE_CONFIRMATION = "APPLY-PACKET-CHECKPOINT-GAP-RECOVERY"
LIVE_RESUME_CONFIRMATION = "APPLY-PACKET-LIVE-RESUME"
FAILED_TAIL_RESUME_CONFIRMATION = "APPLY-PACKET-FAILED-TAIL-LIVE-RESUME"
BOUNDED_REPLAY_CONFIRMATION = "APPLY-PACKET-BOUNDED-REPLAY"
FAILED_TAIL_BOUNDED_REPLAY_CONFIRMATION = "APPLY-PACKET-FAILED-TAIL-BOUNDED-REPLAY"
FAILED_TARGET_PREFIX_BOUNDED_REPLAY_CONFIRMATION = "APPLY-PACKET-FAILED-TARGET-PREFIX-BOUNDED-REPLAY"
PROCESSABLE_SKIP_PREFIX = "SKIP-PROCESSABLE-SESSIONS:"
_MIGRATION_005_SCHEMA_SHA256 = (
    "a4237ba4405a99a62c533e89fc75d68c76c09bfdc77e73587027022ac326bc0d"
)
_VOLATILE_PLAN_KEYS = frozenset({
    "plan_sha256", "generated_at", "executed_at", "operation_id",
    "plan_path", "artifact_dir", "backup_path", "result_path", "backup_sha256",
    "execute_command", "repository_branch", "file_mtime_ns", "data_version",
    "process_id", "lock_acquired_at", "post_commit_verified_at",
})


class PacketCheckpointRecoveryError(Exception):
    """Raised when a packet checkpoint recovery plan is invalid."""


class PacketCheckpointRecoveryCommittedArtifactError(PacketCheckpointRecoveryError):
    """Raised when post-commit verification or artifact creation fails."""

    def __init__(self, operation_id: str, backup_path: str | Path) -> None:
        self.operation_id = operation_id
        self.backup_path = Path(backup_path)
        super().__init__(
            "database committed but post-commit verification or result artifact "
            "creation failed; manual HOLD required"
        )


@dataclass(frozen=True)
class ResolvedRecoveryLock:
    path: Path
    roles: tuple[str, ...]


def _absolute_lock_path(repository_root: Path, path: Path) -> Path:
    candidate = path if path.is_absolute() else repository_root / path
    return candidate.resolve(strict=False)


def resolve_recovery_locks(
    *,
    repository_root: Path,
    database_url: str,
    orchestrator_lock_path: Path | None,
    manual_lock_path: Path | None,
    extractor_lock_path: Path | None,
) -> tuple[ResolvedRecoveryLock, ...]:
    orchestrator = run_detection_orchestrator.resolve_lock_path(
        Settings(
            database_url=database_url,
            orchestrator_lock_path=(
                str(orchestrator_lock_path)
                if orchestrator_lock_path is not None
                else ""
            ),
        )
    )
    rule_manual = (
        manual_lock_path
        if manual_lock_path is not None
        else run_packet_rule_detector.DEFAULT_LOCK_PATH
    )
    if_manual = (
        manual_lock_path
        if manual_lock_path is not None
        else run_packet_ai_detector.DEFAULT_LOCK_PATH
    )
    extractor = (
        extractor_lock_path
        if extractor_lock_path is not None
        else run_packet_feature_extractor.DEFAULT_LOCK_PATH
    )
    roles_by_path: dict[Path, set[str]] = {}
    for role, path in (
        ("detection_orchestrator", orchestrator),
        ("packet_rule_manual", rule_manual),
        ("packet_if_manual", if_manual),
        ("packet_feature_extractor", extractor),
    ):
        absolute = _absolute_lock_path(repository_root, Path(path))
        roles_by_path.setdefault(absolute, set()).add(role)
    return tuple(
        ResolvedRecoveryLock(path, tuple(sorted(roles)))
        for path, roles in sorted(roles_by_path.items(), key=lambda item: str(item[0]))
    )


def serialize_resolved_locks(
    locks: Sequence[ResolvedRecoveryLock],
) -> tuple[dict[str, object], ...]:
    return tuple(
        {"path": str(lock.path), "roles": list(lock.roles)}
        for lock in sorted(locks, key=lambda item: str(item.path))
    )


@contextmanager
def acquire_recovery_locks(
    locks: Sequence[ResolvedRecoveryLock],
    *,
    lock_factory: Callable[[Path], ContextManager[None]] = single_instance_lock,
) -> Iterator[None]:
    with ExitStack() as stack:
        for lock in sorted(locks, key=lambda item: str(item.path)):
            stack.enter_context(lock_factory(lock.path))
        yield


def _readiness_summary(
    session: sqlite3.Row,
    readiness: recovery_repository.RecoverySessionReadiness,
    *,
    include_live_resume: bool = False,
) -> dict[str, object]:
    summary: dict[str, object] = {
        "session_id": readiness.session_id,
        "status": str(session["status"]),
        "first_window_start": (
            format_db_utc(readiness.first_window_start)
            if readiness.first_window_start is not None
            else None
        ),
        "packet_feature_ready_through": (
            format_db_utc(readiness.packet_feature_ready_through)
            if readiness.packet_feature_ready_through is not None
            else None
        ),
        "segment_count": readiness.segment_count,
        "feature_row_count": readiness.feature_row_count,
        "full_ready": readiness.full_ready,
        "blocking_reasons": list(readiness.blocking_reasons),
    }
    if include_live_resume:
        summary["blocking_reasons"] = list(
            readiness.live_resume_blocking_reasons
        )
        summary["live_resume_blocking_reasons"] = list(
            readiness.live_resume_blocking_reasons
        )
    return summary


def classify_skipped_sessions(
    connection: sqlite3.Connection,
    *,
    checkpoint_window_end: str,
    target_first_window_start: str,
) -> list[dict[str, object]]:
    summaries: list[dict[str, object]] = []
    for session in recovery_repository.list_sessions_between(
        connection,
        after_window_end=checkpoint_window_end,
        before_window_start=target_first_window_start,
    ):
        readiness = recovery_repository.calculate_packet_feature_readiness(
            connection, str(session["session_id"])
        )
        if session["status"] == "FAILED":
            classification = "SKIPPED_FAILED"
        elif session["status"] == "RUNNING":
            classification = "BLOCKING_RUNNING"
        elif readiness is not None and readiness.full_ready:
            classification = "SKIPPED_FULL_READY_COMPLETED"
        else:
            classification = "SKIPPED_NOT_READY"
        summaries.append(
            {
                "classification": classification,
                "session_id": str(session["session_id"]),
                "first_window_start": str(session["first_window_start"]),
                "packet_feature_ready_through": (
                    format_db_utc(readiness.packet_feature_ready_through)
                    if readiness is not None
                    and readiness.packet_feature_ready_through is not None
                    else None
                ),
                "segment_count": readiness.segment_count if readiness is not None else 0,
                "feature_row_count": (
                    readiness.feature_row_count if readiness is not None else 0
                ),
                "warning_codes": (
                    ["PROCESSABLE_SESSION_SKIP"]
                    if classification == "SKIPPED_FULL_READY_COMPLETED"
                    else []
                ),
            }
        )
    return summaries


def recovery_execute_confirmation(plan: Mapping[str, object]) -> str:
    if plan.get("mode", GAP_RECOVERY_MODE) == BOUNDED_REPLAY_MODE:
        if plan.get("allow_failed_target_session") is True:
            return FAILED_TARGET_PREFIX_BOUNDED_REPLAY_CONFIRMATION
        return (FAILED_TAIL_BOUNDED_REPLAY_CONFIRMATION
                if plan.get("allow_failed_current_session") is True
                else BOUNDED_REPLAY_CONFIRMATION)
    return (FAILED_TAIL_RESUME_CONFIRMATION
            if plan.get("allow_failed_current_session") is True
            else LIVE_RESUME_CONFIRMATION
            if plan.get("mode", GAP_RECOVERY_MODE) == LIVE_RESUME_MODE
            else EXECUTE_CONFIRMATION)


def require_execute_confirmations(
    plan: Mapping[str, object],
    *,
    confirm: str,
    confirm_skip_processable: str | None,
) -> None:
    expected_confirmation = recovery_execute_confirmation(plan)
    if confirm != expected_confirmation:
        raise PacketCheckpointRecoveryError("execute confirmation mismatch")
    expected = f"{PROCESSABLE_SKIP_PREFIX}{plan['plan_sha256']}"
    skips = bool(plan["summary"]["skips_processable_sessions"])
    if skips and confirm_skip_processable != expected:
        raise PacketCheckpointRecoveryError("processable-session confirmation mismatch")
    if not skips and confirm_skip_processable is not None:
        raise PacketCheckpointRecoveryError("processable-session confirmation not allowed")


def _failed_capture_tail_evidence(
    connection: sqlite3.Connection,
    session: sqlite3.Row,
    checkpoint: sqlite3.Row | None,
) -> dict[str, object] | None:
    """Accept only one uncaptured LATE_CAPTURE tail at the consumed boundary.

    This does not relabel failed capture data or consume features. The explicit
    operator plan records the discarded capture opportunity and is revalidated
    under the existing transaction and runtime locks before either checkpoint moves.
    """
    if checkpoint is None or not checkpoint["last_completed_window_end"]:
        return None
    boundary = parse_db_utc(checkpoint["last_completed_window_end"], "checkpoint")
    if not session["ended_at"]:
        return None
    segments = connection.execute(
        "SELECT s.*, (SELECT COUNT(*) FROM packet_feature_logs f "
        "WHERE f.capture_segment_id = s.id) AS feature_count "
        "FROM packet_capture_segments s WHERE s.capture_session_id = ? "
        "ORDER BY s.window_start, s.id",
        (session["id"],),
    ).fetchall()
    tail = [s for s in segments if parse_db_utc(s["window_end"], "window_end") > boundary]
    if len(tail) != 1 or not segments or tail[0]["id"] != segments[-1]["id"]:
        return None
    segment = tail[0]
    window_start = parse_db_utc(segment["window_start"], "window_start")
    window_end = parse_db_utc(segment["window_end"], "window_end")
    ended_at = parse_db_utc(session["ended_at"], "ended_at")
    if (
        segment["status"] != "FAILED"
        or segment["error_code"] != "LATE_CAPTURE"
        or window_start != boundary
        or (window_end - window_start).total_seconds() != 10
        or not window_start <= ended_at <= window_end
        or segment["file_name"] is not None
        or segment["actual_capture_started_at"] is not None
        or segment["captured_duration_seconds"] != 0
        or segment["packet_count"] not in (None, 0)
        or segment["feature_count"] != 0
    ):
        return None
    return {
        "session_id": session["session_id"],
        "session_status": session["status"],
        "ended_at": session["ended_at"],
        "segment_id": segment["id"],
        "window_start": segment["window_start"],
        "window_end": segment["window_end"],
        "error_code": segment["error_code"],
        "captured_duration_seconds": segment["captured_duration_seconds"],
        "feature_count": segment["feature_count"],
    }


def _bounded_replay_evidence(connection: sqlite3.Connection, target_session_id: str,
                             *, allow_failed_target_session: bool = False) -> dict[str, object] | None:
    evidence = recovery_repository.get_bounded_replay_target_evidence(
        connection, target_session_id, allow_failed_target_session=allow_failed_target_session)
    if evidence is not None:
        running = recovery_repository.list_running_capture_sessions(connection)
        evidence["later_running_session"] = (dict(recovery_repository.get_capture_session(connection, running[0]["session_id"]))
                                             if len(running) == 1 else None)
    return evidence


def build_recovery_plan(
    connection: sqlite3.Connection,
    *,
    repository_state: Mapping[str, object],
    database_path: Path,
    detector_name: str,
    current_session_id: str,
    target_session_id: str,
    approved_by: str,
    reason: str,
    lock_entries: Sequence[Mapping[str, object]],
    mode: str = GAP_RECOVERY_MODE,
    allow_failed_current_session: bool = False,
    allow_failed_target_session: bool = False,
) -> dict[str, object]:
    if type(allow_failed_target_session) is not bool:
        raise PacketCheckpointRecoveryError("failed-target-session approval must be boolean")
    if mode not in RECOVERY_MODES:
        raise PacketCheckpointRecoveryError(f"unsupported recovery mode: {mode}")
    source_table = recovery_repository.SUPPORTED_DETECTORS.get(detector_name)
    if source_table is None:
        raise PacketCheckpointRecoveryError(
            f"unsupported detector: {detector_name}"
        )

    blocking_reasons: list[str] = []
    checkpoint = recovery_repository.get_checkpoint(
        connection, detector_name, source_table
    )
    current_session = recovery_repository.get_capture_session(
        connection, current_session_id
    )
    target_session = recovery_repository.get_capture_session(
        connection, target_session_id
    )
    current_readiness = recovery_repository.calculate_packet_feature_readiness(
        connection, current_session_id
    )
    target_readiness = recovery_repository.calculate_packet_feature_readiness(
        connection, target_session_id
    )

    if checkpoint is None:
        blocking_reasons.append("CHECKPOINT_NOT_FOUND")
    failed_tail_evidence = None
    if allow_failed_current_session:
        if mode not in (LIVE_RESUME_MODE, BOUNDED_REPLAY_MODE) or current_session is None or current_session["status"] != "FAILED":
            blocking_reasons.append("FAILED_TAIL_RESUME_REQUIRES_FAILED_SOURCE_AND_LIVE_MODE")
        else:
            failed_tail_evidence = _failed_capture_tail_evidence(connection, current_session, checkpoint)
            if failed_tail_evidence is None:
                blocking_reasons.append("FAILED_CURRENT_SESSION_TAIL_NOT_RECOVERABLE")
    if current_session is None:
        blocking_reasons.append("CURRENT_SESSION_NOT_FOUND")
    elif current_session["status"] != "COMPLETED" and failed_tail_evidence is None:
        blocking_reasons.append("CURRENT_SESSION_NOT_COMPLETED")
    failed_target_tail = None
    if allow_failed_target_session:
        if mode != BOUNDED_REPLAY_MODE or target_session is None or target_session["status"] != "FAILED":
            blocking_reasons.append("FAILED_TARGET_PREFIX_REQUIRES_FAILED_TARGET_AND_BOUNDED_MODE")
        else:
            prefix = recovery_repository.get_bounded_replay_target_evidence(
                connection, target_session_id, allow_failed_target_session=True)
            if prefix is None:
                blocking_reasons.append("FAILED_TARGET_SESSION_PREFIX_NOT_RECOVERABLE")
            else:
                failed_target_tail = prefix["failed_target_tail"]
    if target_session is None:
        blocking_reasons.append("TARGET_SESSION_NOT_FOUND")
    elif mode in (GAP_RECOVERY_MODE, BOUNDED_REPLAY_MODE) and target_session["status"] != "COMPLETED" and failed_target_tail is None:
        blocking_reasons.append("TARGET_SESSION_NOT_COMPLETED")
    elif mode == LIVE_RESUME_MODE and target_session["status"] != "RUNNING":
        blocking_reasons.append("TARGET_SESSION_NOT_RUNNING")
    if current_session_id == target_session_id:
        blocking_reasons.append("CURRENT_AND_TARGET_SESSION_MATCH")

    checkpoint_window: datetime | None = None
    if checkpoint is not None and checkpoint["last_completed_window_end"] is not None:
        checkpoint_window = parse_db_utc(
            checkpoint["last_completed_window_end"],
            "last_completed_window_end",
        )
    elif checkpoint is not None:
        blocking_reasons.append("CHECKPOINT_WINDOW_END_MISSING")

    if current_readiness is None:
        if current_session is not None:
            blocking_reasons.append("CURRENT_SESSION_READINESS_MISSING")
    elif current_readiness.packet_feature_ready_through is None:
        blocking_reasons.append("CURRENT_SESSION_NOT_FEATURE_READY")
    elif checkpoint_window is not None:
        if checkpoint_window < current_readiness.packet_feature_ready_through:
            blocking_reasons.append(
                "CURRENT_SESSION_HAS_READY_PREFIX_AFTER_CHECKPOINT"
            )
        elif checkpoint_window > current_readiness.packet_feature_ready_through:
            blocking_reasons.append("CURRENT_CHECKPOINT_NOT_AT_READY_THROUGH")

    target_first: datetime | None = None
    if target_readiness is None:
        if target_session is not None:
            blocking_reasons.append("TARGET_SESSION_READINESS_MISSING")
    else:
        target_first = target_readiness.first_window_start
        if mode in (GAP_RECOVERY_MODE, BOUNDED_REPLAY_MODE) and not target_readiness.full_ready and failed_target_tail is None:
            blocking_reasons.append("TARGET_SESSION_NOT_FULL_READY")
        elif mode == LIVE_RESUME_MODE:
            if (
                target_first is None
                or target_readiness.packet_feature_ready_through is None
                or target_readiness.packet_feature_ready_through <= target_first
            ):
                blocking_reasons.append("TARGET_SESSION_READY_PREFIX_MISSING")
            if target_readiness.live_resume_blocking_reasons:
                blocking_reasons.append("TARGET_SESSION_READINESS_BLOCKED")
    if checkpoint_window is not None and target_first is not None:
        if target_first <= checkpoint_window:
            blocking_reasons.append("CHECKPOINT_WOULD_NOT_ADVANCE")

    running_rows = recovery_repository.list_running_capture_sessions(connection)
    running_sessions = [
        {"session_id": str(row["session_id"]), "started_at": str(row["started_at"])}
        for row in running_rows
    ]
    if mode == GAP_RECOVERY_MODE and running_sessions:
        blocking_reasons.append("RUNNING_CAPTURE_SESSIONS")
    elif mode == LIVE_RESUME_MODE and (
        len(running_sessions) != 1
        or running_sessions[0]["session_id"] != target_session_id
    ):
        blocking_reasons.append("LIVE_RESUME_RUNNING_SESSION_MISMATCH")

    bounded_replay = None
    if mode == BOUNDED_REPLAY_MODE:
        bounded_replay = _bounded_replay_evidence(connection, target_session_id, allow_failed_target_session=allow_failed_target_session)
        if bounded_replay is not None:
            replay_end = bounded_replay["replay_end"]
            if checkpoint is not None:
                target_minimum_id = connection.execute(
                    "SELECT MIN(f.id) FROM packet_feature_logs f JOIN packet_capture_segments g ON g.id=f.capture_segment_id "
                    "WHERE g.capture_session_id=? AND (?='packet_if' OR f.direction='INBOUND')",
                    (target_session["id"], detector_name)).fetchone()[0]
                if (target_minimum_id is not None and checkpoint["last_processed_id"] is not None
                        and checkpoint["last_processed_id"] >= target_minimum_id):
                    blocking_reasons.append("BOUNDED_REPLAY_TARGET_FEATURE_IDS_ALREADY_PASSED")
                if current_session is not None and checkpoint["last_completed_window_end"] is not None:
                    source_maximum_id = connection.execute(
                        "SELECT MAX(f.id) FROM packet_feature_logs f JOIN packet_capture_segments g ON g.id=f.capture_segment_id "
                        "WHERE g.capture_session_id=? AND unixepoch(f.window_end)<=unixepoch(?) "
                        "AND (?='packet_if' OR f.direction='INBOUND')",
                        (current_session["id"], checkpoint["last_completed_window_end"], detector_name)).fetchone()[0]
                    if (source_maximum_id is not None and (checkpoint["last_processed_id"] is None
                            or checkpoint["last_processed_id"] < source_maximum_id)):
                        blocking_reasons.append("BOUNDED_REPLAY_SOURCE_FEATURES_NOT_CONSUMED")
            if (current_session is not None and current_session["status"] == "COMPLETED"
                    and (current_session["ended_at"] is None or current_readiness is None
                         or not current_readiness.full_ready
                         or parse_db_utc(current_session["ended_at"]) < current_readiness.packet_feature_ready_through)):
                blocking_reasons.append("BOUNDED_REPLAY_SOURCE_NOT_CLOSED_FULL_READY")
            if failed_target_tail is None and (target_session["ended_at"] is None or replay_end is None
                    or parse_db_utc(target_session["ended_at"]) < parse_db_utc(replay_end)
                    or connection.execute(
                        "SELECT 1 FROM packet_capture_segments WHERE capture_session_id=? "
                        "AND (status NOT IN ('PROCESSED','EMPTY') OR error_code IS NOT NULL) LIMIT 1",
                        (target_session["id"],)).fetchone() is not None):
                blocking_reasons.append("BOUNDED_REPLAY_TARGET_NOT_NORMAL_FULL_READY")
            if current_session is not None and current_session["first_window_start"] is not None:
                successors = connection.execute(
                    "SELECT session_id,first_window_start FROM packet_capture_sessions "
                    "WHERE unixepoch(first_window_start)>unixepoch(?) "
                    "ORDER BY unixepoch(first_window_start),id LIMIT 2",
                    (current_session["first_window_start"],)).fetchall()
                if (not successors or successors[0]["session_id"] != target_session_id
                        or len(successors) > 1 and parse_db_utc(successors[0]["first_window_start"]) == parse_db_utc(successors[1]["first_window_start"])):
                    blocking_reasons.append("BOUNDED_REPLAY_TARGET_NOT_NEXT_SESSION")
            if (failed_tail_evidence is not None and
                    parse_db_utc(target_session["first_window_start"]) != parse_db_utc(failed_tail_evidence["window_end"])):
                blocking_reasons.append("BOUNDED_REPLAY_FAILED_TAIL_BOUNDARY_MISMATCH")
            if target_first is not None and replay_end is not None and connection.execute(
                    "SELECT 1 FROM packet_capture_segments WHERE capture_session_id<>? "
                    "AND unixepoch(window_start)<unixepoch(?) AND unixepoch(window_end)>unixepoch(?) LIMIT 1",
                    (target_session["id"], replay_end, target_session["first_window_start"])).fetchone():
                blocking_reasons.append("BOUNDED_REPLAY_OVERLAPPING_SESSION")
            if len(running_rows) > 1:
                blocking_reasons.append("BOUNDED_REPLAY_RUNNING_SESSION_MISMATCH")
            elif running_rows:
                later = recovery_repository.get_capture_session(connection, running_rows[0]["session_id"])
                bounded_replay["later_running_session"] = dict(later)
                if (later["session_id"] == target_session_id or later["ended_at"] is not None
                        or later["first_window_start"] is None or replay_end is None
                        or parse_db_utc(later["first_window_start"]) < parse_db_utc(
                            failed_target_tail["window_end"] if failed_target_tail is not None else replay_end)):
                    blocking_reasons.append("BOUNDED_REPLAY_RUNNING_SESSION_MISMATCH")

    existing_recovery = recovery_repository.get_existing_recovery(
        connection,
        detector_name=detector_name,
        source_table=source_table,
        target_session_id=target_session_id,
    )
    if existing_recovery is not None:
        blocking_reasons.append("DUPLICATE_RECOVERY")

    checkpoint_before = (
        {
            "detector_name": str(checkpoint["detector_name"]),
            "source_table": str(checkpoint["source_table"]),
            "last_processed_id": checkpoint["last_processed_id"],
            "last_completed_window_end": checkpoint["last_completed_window_end"],
            "updated_at": checkpoint["updated_at"],
        }
        if checkpoint is not None
        else None
    )
    checkpoint_after = (
        {
            "detector_name": detector_name,
            "source_table": source_table,
            "last_processed_id": checkpoint["last_processed_id"],
            "last_completed_window_end": format_db_utc(target_first),
        }
        if checkpoint is not None and target_first is not None
        else None
    )
    sessions_between: list[dict[str, object]] = []
    if checkpoint_window is not None and target_first is not None:
        sessions_between = classify_skipped_sessions(
            connection,
            checkpoint_window_end=format_db_utc(checkpoint_window),
            target_first_window_start=format_db_utc(target_first),
        )
    if mode == BOUNDED_REPLAY_MODE and sessions_between:
        blocking_reasons.append("BOUNDED_REPLAY_INTERMEDIATE_SESSION")
    skips_processable_sessions = any(
        row["classification"] == "SKIPPED_FULL_READY_COMPLETED"
        for row in sessions_between
    )
    warning_codes = (
        ["PROCESSABLE_SESSION_SKIP"] if skips_processable_sessions else []
    )
    if failed_tail_evidence is not None:
        warning_codes.append("UNCAPTURED_FAILED_TAIL_SKIP")
    if failed_target_tail is not None:
        warning_codes.append("FAILED_TARGET_TAIL_NOT_REPLAYED")

    return {
        "plan_schema_version": PLAN_SCHEMA_VERSION,
        "mode": mode,
        "allow_failed_current_session": allow_failed_current_session,
        "failed_current_tail": failed_tail_evidence,
        "allow_failed_target_session": allow_failed_target_session,
        "failed_target_tail": failed_target_tail,
        **({"bounded_replay": bounded_replay} if mode == BOUNDED_REPLAY_MODE else {}),
        "repository_root": repository_state.get("repository_root"),
        "repository_commit": repository_state.get("repository_commit"),
        "repository_state": dict(repository_state),
        "database_path": str(database_path.resolve()),
        "detector_name": detector_name,
        "source_table": source_table,
        "current_session_id": current_session_id,
        "target_session_id": target_session_id,
        "approved_by": approved_by,
        "reason": reason,
        "checkpoint": {"before": checkpoint_before, "after": checkpoint_after},
        "current_session": (
            _readiness_summary(current_session, current_readiness)
            if current_session is not None and current_readiness is not None
            else None
        ),
        "target_session": (
            _readiness_summary(
                target_session,
                target_readiness,
                include_live_resume=mode == LIVE_RESUME_MODE,
            )
            if target_session is not None and target_readiness is not None
            else None
        ),
        "sessions_between": sessions_between,
        "running_sessions": running_sessions,
        "summary": {
            "current_session_classification": (
                "EXHAUSTED_CURRENT"
                if checkpoint_window is not None
                and current_readiness is not None
                and checkpoint_window == current_readiness.packet_feature_ready_through
                else None
            ),
            "skipped_sessions": sessions_between,
            "running_sessions": [
                {
                    "classification": (
                        "LIVE_RESUME_TARGET"
                        if mode == LIVE_RESUME_MODE
                        and session["session_id"] == target_session_id
                        else "BLOCKING_RUNNING"
                    ),
                    **session,
                }
                for session in running_sessions
            ],
            "target_session_classification": (
                "TARGET_FAILED_NORMAL_PREFIX"
                if failed_target_tail is not None
                else "TARGET_LIVE_READY_PREFIX"
                if mode == LIVE_RESUME_MODE
                and target_readiness is not None
                and target_readiness.first_window_start is not None
                and target_readiness.packet_feature_ready_through is not None
                and target_readiness.packet_feature_ready_through
                > target_readiness.first_window_start
                and not target_readiness.live_resume_blocking_reasons
                else (
                    "TARGET_FULL_READY_COMPLETED"
                    if target_readiness is not None and target_readiness.full_ready
                    else None
                )
            ),
            "skips_processable_sessions": skips_processable_sessions,
            "warning_codes": warning_codes,
        },
        "existing_recovery": (
            dict(existing_recovery) if existing_recovery is not None else None
        ),
        "locks": [dict(entry) for entry in lock_entries],
        "blocking_reasons": blocking_reasons,
        "can_execute": not blocking_reasons,
    }


def require_migration_005(connection: sqlite3.Connection) -> None:
    try:
        migration = connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version = 5"
        ).fetchone()
        schema_rows = connection.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_master
            WHERE name IN (
                'packet_checkpoint_recoveries',
                'uq_packet_checkpoint_recovery_detector_target'
            )
            ORDER BY type, name
            """
        ).fetchall()
    except sqlite3.DatabaseError as exc:
        raise PacketCheckpointRecoveryError(
            "Migration 005 schema does not match the recovery contract"
        ) from exc
    schema_json = json.dumps(
        [list(row) for row in schema_rows],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    schema_sha256 = hashlib.sha256(schema_json.encode("utf-8")).hexdigest()
    if (
        migration is None
        or tuple(migration) != (5, "packet_checkpoint_recovery")
        or schema_sha256 != _MIGRATION_005_SCHEMA_SHA256
    ):
        raise PacketCheckpointRecoveryError(
            "Migration 005 schema does not match the recovery contract"
        )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _execute_command(
    *, database: Path, plan_path: Path, plan: Mapping[str, object]
) -> str:
    command = [
        "python",
        "-m",
        "edge.detection.run_packet_checkpoint_recovery",
        "execute",
        "--plan-file",
        str(plan_path),
        "--db-path",
        str(database),
        "--artifact-dir",
        "<ARTIFACT_DIR>",
        "--confirm",
        recovery_execute_confirmation(plan),
    ]
    if plan["summary"]["skips_processable_sessions"]:
        command.extend(
            [
                "--confirm-skip-processable",
                f"{PROCESSABLE_SKIP_PREFIX}{plan['plan_sha256']}",
            ]
        )
    return shlex.join(command)


def _write_json_atomically(path: Path, payload: Mapping[str, object]) -> None:
    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            json.dump(payload, temporary, ensure_ascii=False, sort_keys=True, indent=2)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def inspect_packet_checkpoint_recovery(
    *,
    db_path: str | Path,
    repository_root: str | Path,
    detector_name: str,
    current_session_id: str,
    target_session_id: str,
    approved_by: str,
    reason: str,
    plan_output: str | Path,
    mode: str = GAP_RECOVERY_MODE,
    allow_failed_current_session: bool = False,
    allow_failed_target_session: bool = False,
    orchestrator_lock_path: Path | None = None,
    manual_lock_path: Path | None = None,
    extractor_lock_path: Path | None = None,
) -> dict[str, object]:
    database = resolve_database_path(db_path)
    root = Path(repository_root).expanduser().resolve(strict=True)
    raw_plan_output = Path(plan_output).expanduser()
    plan_path = (
        raw_plan_output if raw_plan_output.is_absolute() else root / raw_plan_output
    ).resolve(strict=False)
    require_existing_parent(plan_path, field_name="plan_output")

    wal_path = database.with_name(f"{database.name}-wal")
    read_only_options = "mode=ro" if wal_path.exists() else "mode=ro&immutable=1"
    with sqlite3.connect(
        f"file:{database}?{read_only_options}", uri=True
    ) as connection:
        connection.row_factory = sqlite3.Row
        require_migration_005(connection)
        locks = resolve_recovery_locks(
            repository_root=root,
            database_url=f"sqlite:///{database}",
            orchestrator_lock_path=orchestrator_lock_path,
            manual_lock_path=manual_lock_path,
            extractor_lock_path=extractor_lock_path,
        )
        paths = validate_generated_paths(
            repository_root=root,
            plan_output=plan_path,
            lock_paths=tuple(lock.path for lock in locks),
        )
        repository_state = inspect_repository_state(root)
        payload = build_recovery_plan(
            connection,
            repository_state=repository_state,
            database_path=database,
            detector_name=detector_name,
            current_session_id=current_session_id,
            target_session_id=target_session_id,
            approved_by=approved_by,
            reason=reason,
            lock_entries=serialize_resolved_locks(locks),
            mode=mode,
            allow_failed_current_session=allow_failed_current_session,
            allow_failed_target_session=allow_failed_target_session,
        )

    plan = attach_plan_sha256(
        payload, generated_at=_utc_now().replace(microsecond=0)
    )
    plan["execute_command"] = _execute_command(
        database=database,
        plan_path=paths["plan_output"],
        plan=plan,
    )
    _write_json_atomically(paths["plan_output"], plan)
    return plan


def _current_platform_name() -> str:
    return os.name


def require_execute_platform(platform_name: str) -> None:
    if platform_name != "posix":
        raise PacketCheckpointRecoveryError(
            "execute is supported only on POSIX; dry-run is available on Windows"
        )


def _load_plan(plan_file: str | Path) -> tuple[Path, dict[str, object]]:
    path = Path(plan_file).expanduser().resolve(strict=True)
    if not path.is_file():
        raise PacketCheckpointRecoveryError("plan file must be a regular file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PacketCheckpointRecoveryError("plan file must contain valid JSON") from exc
    if not isinstance(payload, dict):
        raise PacketCheckpointRecoveryError("plan file must contain a JSON object")
    verify_plan_sha256(payload)
    if type(payload.get("allow_failed_target_session", False)) is not bool:
        raise PacketCheckpointRecoveryError("failed-target-session approval must be boolean")
    return path, payload


def _locks_from_plan(plan: Mapping[str, object]) -> tuple[ResolvedRecoveryLock, ...]:
    entries = plan.get("locks")
    if not isinstance(entries, list):
        raise PacketCheckpointRecoveryError("plan locks are invalid")
    locks: list[ResolvedRecoveryLock] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise PacketCheckpointRecoveryError("plan locks are invalid")
        path = entry.get("path")
        roles = entry.get("roles")
        if not isinstance(path, str) or not isinstance(roles, list) or not all(
            isinstance(role, str) for role in roles
        ):
            raise PacketCheckpointRecoveryError("plan locks are invalid")
        locks.append(ResolvedRecoveryLock(Path(path).resolve(strict=False), tuple(roles)))
    if serialize_resolved_locks(locks) != tuple(dict(entry) for entry in entries):
        raise PacketCheckpointRecoveryError("plan locks are not canonical")
    return tuple(locks)


def _rebuild_execute_plan(
    connection: sqlite3.Connection,
    *,
    plan: Mapping[str, object],
    repository_state: Mapping[str, object],
    database: Path,
    locks: Sequence[ResolvedRecoveryLock],
) -> dict[str, object]:
    return build_recovery_plan(
        connection,
        repository_state=repository_state,
        database_path=database,
        detector_name=str(plan["detector_name"]),
        current_session_id=str(plan["current_session_id"]),
        target_session_id=str(plan["target_session_id"]),
        approved_by=str(plan["approved_by"]),
        reason=str(plan["reason"]),
        lock_entries=serialize_resolved_locks(locks),
        mode=str(plan.get("mode", GAP_RECOVERY_MODE)),
        allow_failed_current_session=plan.get("allow_failed_current_session") is True,
        allow_failed_target_session=plan.get("allow_failed_target_session", False),
    )


def _require_same_canonical_plan(
    plan: Mapping[str, object], rebuilt: Mapping[str, object]
) -> None:
    if not rebuilt.get("can_execute"):
        reasons = rebuilt.get("blocking_reasons", ())
        raise PacketCheckpointRecoveryError(
            "canonical plan changed: "
            + ",".join(str(reason) for reason in reasons)
        )

    planned_binding = canonical_plan_binding(plan)
    rebuilt_binding = canonical_plan_binding(rebuilt)
    # Keep the original SHA algorithm intact for pre-opt-in approvals. Only the
    # execution comparison may normalize absent new fields to false/None.
    if ("allow_failed_target_session" not in plan
            and plan.get("failed_target_tail") is None
            and rebuilt.get("allow_failed_target_session") is False
            and rebuilt.get("failed_target_tail") is None):
        for binding in (planned_binding, rebuilt_binding):
            binding.pop("allow_failed_target_session", None)
            binding.pop("failed_target_tail", None)
    if plan.get("mode", GAP_RECOVERY_MODE) == LIVE_RESUME_MODE:
        planned_target = plan.get("target_session")
        rebuilt_target = rebuilt.get("target_session")
        if not isinstance(planned_target, Mapping) or not isinstance(
            rebuilt_target, Mapping
        ):
            raise PacketCheckpointRecoveryError("canonical plan changed: target")
        planned_ready = planned_target.get("packet_feature_ready_through")
        rebuilt_ready = rebuilt_target.get("packet_feature_ready_through")
        if not isinstance(planned_ready, str) or not isinstance(rebuilt_ready, str):
            raise PacketCheckpointRecoveryError("canonical plan changed: readiness")
        if parse_db_utc(rebuilt_ready, "packet_feature_ready_through") < parse_db_utc(
            planned_ready, "packet_feature_ready_through"
        ):
            raise PacketCheckpointRecoveryError(
                "canonical plan changed: readiness regressed"
            )
        for binding in (planned_binding, rebuilt_binding):
            target = binding.get("target_session")
            if not isinstance(target, dict):
                raise PacketCheckpointRecoveryError("canonical plan changed: target")
            for key in (
                "packet_feature_ready_through",
                "segment_count",
                "feature_row_count",
                "blocking_reasons",
                "live_resume_blocking_reasons",
            ):
                target.pop(key, None)

    if planned_binding != rebuilt_binding:
        reasons = rebuilt.get("blocking_reasons")
        detail = ",".join(str(reason) for reason in reasons) if reasons else "changed"
        raise PacketCheckpointRecoveryError(f"canonical plan changed: {detail}")


def _other_checkpoint_rows(
    connection: sqlite3.Connection, detector_name: str, source_table: str
) -> tuple[tuple[object, ...], ...]:
    return tuple(
        tuple(row)
        for row in connection.execute(
            """
            SELECT detector_name, source_table, last_processed_id,
                   last_completed_window_end, updated_at
            FROM detector_checkpoints
            WHERE NOT (detector_name = ? AND source_table = ?)
            ORDER BY detector_name, source_table
            """,
            (detector_name, source_table),
        ).fetchall()
    )


def _remove_failed_backup_artifacts(
    operation_dir: Path, backup_path: Path, backup_sha256_path: Path
) -> None:
    backup_sha256_path.unlink(missing_ok=True)
    backup_path.unlink(missing_ok=True)
    try:
        operation_dir.rmdir()
    except OSError:
        pass


def _execute_locked_recovery(
    *,
    plan_path: Path,
    plan: dict[str, object],
    database: Path,
    artifact_root: Path,
    operation_id: str,
    operation_dir: Path,
    backup_path: Path,
    backup_sha256_path: Path,
    result_path: Path,
    locks: Sequence[ResolvedRecoveryLock],
) -> dict[str, object]:
    repository_state = inspect_repository_state(str(plan["repository_root"]))
    if repository_state != plan.get("repository_state"):
        raise PacketCheckpointRecoveryError("repository state changed from plan")

    with sqlite3.connect(database, isolation_level=None) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        require_migration_005(connection)
        rebuilt = _rebuild_execute_plan(
            connection,
            plan=plan,
            repository_state=repository_state,
            database=database,
            locks=locks,
        )
        _require_same_canonical_plan(plan, rebuilt)
        if recovery_repository.get_recovery_audit(connection, operation_id) is not None:
            raise PacketCheckpointRecoveryError("duplicate recovery operation_id")

        live_verification = verify_database(database)
        if (
            live_verification.integrity_check != "ok"
            or live_verification.foreign_key_violations
        ):
            raise PacketCheckpointRecoveryError(
                "live database failed integrity or foreign-key checks"
            )
        data_version_before = int(connection.execute("PRAGMA data_version").fetchone()[0])
        operation_dir.mkdir()
        try:
            # The fresh checksum and full verification below remain mandatory.
            backup = create_sqlite_backup(database, backup_path, verify=False)
            if backup.database_path != backup_path or backup.sha256_path != backup_sha256_path:
                raise PacketCheckpointRecoveryError("backup artifact path mismatch")
            if file_sha256(backup_path) != backup.sha256:
                raise PacketCheckpointRecoveryError("backup SHA256 mismatch")
            backup_verification = verify_database(backup_path)
            if (
                backup_verification.integrity_check != "ok"
                or backup_verification.foreign_key_violations
            ):
                raise PacketCheckpointRecoveryError(
                    "backup database failed integrity or foreign-key checks"
                )
        except Exception:
            _remove_failed_backup_artifacts(
                operation_dir, backup_path, backup_sha256_path
            )
            raise
        data_version_after = int(connection.execute("PRAGMA data_version").fetchone()[0])
        if data_version_after != data_version_before:
            raise PacketCheckpointRecoveryError("database changed during backup")

        try:
            connection.execute("BEGIN IMMEDIATE")
            transaction_data_version = int(
                connection.execute("PRAGMA data_version").fetchone()[0]
            )
            if transaction_data_version != data_version_after:
                raise PacketCheckpointRecoveryError(
                    "database changed after backup before transaction"
                )
            current_plan_path, transaction_plan = _load_plan(plan_path)
            if current_plan_path != plan_path or transaction_plan != plan:
                raise PacketCheckpointRecoveryError("plan file changed before mutation")
            transaction_repository_state = inspect_repository_state(
                str(plan["repository_root"])
            )
            if transaction_repository_state != repository_state:
                raise PacketCheckpointRecoveryError("repository state changed before mutation")
            transaction_plan_rebuilt = _rebuild_execute_plan(
                connection,
                plan=plan,
                repository_state=transaction_repository_state,
                database=database,
                locks=locks,
            )
            _require_same_canonical_plan(plan, transaction_plan_rebuilt)

            checkpoint_plan = plan["checkpoint"]
            if not isinstance(checkpoint_plan, Mapping):
                raise PacketCheckpointRecoveryError("checkpoint plan is invalid")
            before = checkpoint_plan.get("before")
            planned_after = checkpoint_plan.get("after")
            if not isinstance(before, Mapping) or not isinstance(planned_after, Mapping):
                raise PacketCheckpointRecoveryError("checkpoint plan is invalid")
            updated_at_after = format_db_utc(_utc_now().replace(microsecond=0))
            after = {**planned_after, "updated_at": updated_at_after}
            other_checkpoints_before = _other_checkpoint_rows(
                connection, str(before["detector_name"]), str(before["source_table"])
            )
            changes_before = connection.total_changes
            if recovery_repository.update_checkpoint_conditionally(
                connection, before=before, after=after
            ) != 1:
                raise PacketCheckpointRecoveryError(
                    "conditional checkpoint update affected an unexpected row count"
                )
            sessions_between = plan.get("sessions_between", [])
            if not isinstance(sessions_between, list):
                raise PacketCheckpointRecoveryError("plan session summary is invalid")
            audit = {
                "operation_id": operation_id,
                "detector_name": before["detector_name"],
                "source_table": before["source_table"],
                "current_capture_session_id": plan["current_session_id"],
                "target_capture_session_id": plan["target_session_id"],
                "last_processed_id_before": before["last_processed_id"],
                "last_processed_id_after": after["last_processed_id"],
                "last_completed_window_end_before": before["last_completed_window_end"],
                "last_completed_window_end_after": after["last_completed_window_end"],
                "updated_at_before": before["updated_at"],
                "updated_at_after": updated_at_after,
                "plan_sha256": plan["plan_sha256"],
                "plan_json": json.dumps(
                    plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ),
                "skipped_session_count": len(sessions_between),
                "skipped_processable_session_count": sum(
                    row.get("classification") == "SKIPPED_FULL_READY_COMPLETED"
                    for row in sessions_between
                    if isinstance(row, Mapping)
                ),
                "approved_by": plan["approved_by"],
                "reason": plan["reason"],
                "repository_commit": plan["repository_commit"],
                "database_path": str(database),
                "backup_path": str(backup_path),
                "backup_sha256": backup.sha256,
            }
            if recovery_repository.insert_recovery_audit(
                connection, audit=audit
            ) != 1:
                raise PacketCheckpointRecoveryError(
                    "recovery audit insert affected an unexpected row count"
                )
            delta = connection.total_changes - changes_before
            if delta != 2:
                raise PacketCheckpointRecoveryError(
                    "transaction total_changes delta must be exactly 2"
                )
            checkpoint_after = recovery_repository.get_checkpoint(
                connection, str(before["detector_name"]), str(before["source_table"])
            )
            if checkpoint_after is None or dict(checkpoint_after) != after:
                raise PacketCheckpointRecoveryError("checkpoint verification failed")
            if recovery_repository.get_recovery_audit(connection, operation_id) is None:
                raise PacketCheckpointRecoveryError("recovery audit verification failed")
            if _other_checkpoint_rows(
                connection, str(before["detector_name"]), str(before["source_table"])
            ) != other_checkpoints_before:
                raise PacketCheckpointRecoveryError("unrelated checkpoint changed")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise PacketCheckpointRecoveryError(
                    "transaction foreign-key verification failed"
                )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    try:
        post_commit = verify_database(database)
        if post_commit.integrity_check != "ok" or post_commit.foreign_key_violations:
            raise PacketCheckpointRecoveryError(
                "post-commit database failed integrity or foreign-key checks"
            )
        result: dict[str, object] = {
            "operation_id": operation_id,
            "database_committed": True,
            "database_path": str(database),
            "artifact_dir": str(artifact_root),
            "backup_path": str(backup_path),
            "backup_sha256_path": str(backup_sha256_path),
            "backup_sha256": backup.sha256,
            "result_path": str(result_path),
            "plan_sha256": plan["plan_sha256"],
            "transaction_total_changes_delta": delta,
            "post_commit_verified_at": format_db_utc(
                _utc_now().replace(microsecond=0)
            ),
        }
        _write_json_atomically(result_path, result)
        return result
    except Exception as exc:
        raise PacketCheckpointRecoveryCommittedArtifactError(
            operation_id, backup_path
        ) from exc


def _prepare_recovery_execution(
    *,
    plan_file: str | Path,
    db_path: str | Path,
    artifact_dir: str | Path,
    confirm: str,
    confirm_skip_processable: str | None = None,
    operation_id: str | None = None,
) -> dict[str, object]:
    require_execute_platform(_current_platform_name())
    plan_path, plan = _load_plan(plan_file)
    database = require_plan_database_path(plan, db_path)
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        require_migration_005(connection)
    require_execute_confirmations(
        plan,
        confirm=confirm,
        confirm_skip_processable=confirm_skip_processable,
    )
    repository_root = Path(str(plan["repository_root"])).resolve(strict=True)
    locks = _locks_from_plan(plan)
    operation_id = operation_id or str(uuid.uuid4())
    artifact_root = Path(artifact_dir).expanduser().resolve(strict=False)
    operation_dir = artifact_root / operation_id
    backup_path = operation_dir / "database.backup.db"
    result_path = operation_dir / "result.json"
    paths = validate_generated_paths(
        repository_root=repository_root,
        artifact_dir=artifact_root,
        backup_path=backup_path,
        result_path=result_path,
        lock_paths=tuple(lock.path for lock in locks),
    )
    backup_sha256_path = paths["backup_sha256_path"]
    if not isinstance(backup_sha256_path, Path):
        raise PacketCheckpointRecoveryError("backup SHA256 path is invalid")
    return dict(
        plan_path=plan_path,
        plan=plan,
        database=database,
        artifact_root=artifact_root,
        operation_id=operation_id,
        operation_dir=operation_dir,
        backup_path=backup_path,
        backup_sha256_path=backup_sha256_path,
        result_path=result_path,
        locks=locks,
    )


def execute_packet_checkpoint_recovery(
    *,
    plan_file: str | Path,
    db_path: str | Path,
    artifact_dir: str | Path,
    confirm: str,
    confirm_skip_processable: str | None = None,
) -> dict[str, object]:
    prepared = _prepare_recovery_execution(
        plan_file=plan_file,
        db_path=db_path,
        artifact_dir=artifact_dir,
        confirm=confirm,
        confirm_skip_processable=confirm_skip_processable,
    )
    with acquire_recovery_locks(prepared["locks"]):
        return _execute_locked_recovery(**prepared)


def resolve_database_path(db_path: str | Path) -> Path:
    resolved = Path(db_path).expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise PacketCheckpointRecoveryError("database path must be a regular file")
    return resolved


def require_plan_database_path(plan: Mapping[str, object], db_path: str | Path) -> Path:
    resolved = resolve_database_path(db_path)
    if str(resolved) != plan.get("database_path"):
        raise PacketCheckpointRecoveryError("database path does not match plan")
    return resolved


def validate_generated_path(
    repository_root: Path, candidate: str | Path, *, field_name: str
) -> Path:
    root = repository_root.expanduser().resolve(strict=True)
    raw = Path(candidate).expanduser()
    path = (raw if raw.is_absolute() else root / raw).resolve(strict=False)
    if not path.is_relative_to(root):
        return path
    result = subprocess.run(
        ["git", "check-ignore", "--quiet", "--", path.relative_to(root).as_posix()],
        cwd=root,
        check=False,
    )
    if result.returncode != 0:
        raise PacketCheckpointRecoveryError(f"{field_name} must be Git-ignored")
    return path


def require_existing_parent(path: Path, *, field_name: str) -> Path:
    parent = path.expanduser().resolve(strict=False).parent
    if not parent.is_dir():
        raise PacketCheckpointRecoveryError(f"{field_name} parent must already exist")
    return parent


def require_existing_directory(path: Path, *, field_name: str) -> Path:
    resolved = path.expanduser().resolve(strict=False)
    if not resolved.is_dir():
        raise PacketCheckpointRecoveryError(f"{field_name} must be an existing directory")
    return resolved


def validate_generated_paths(
    *,
    repository_root: Path,
    plan_output: Path | None = None,
    artifact_dir: Path | None = None,
    backup_path: Path | None = None,
    result_path: Path | None = None,
    lock_paths: Sequence[Path] = (),
) -> dict[str, object]:
    checked: dict[str, object] = {}
    if plan_output is not None:
        require_existing_parent(plan_output, field_name="plan_output")
        checked["plan_output"] = validate_generated_path(
            repository_root, plan_output, field_name="plan_output"
        )
    if artifact_dir is not None:
        checked["artifact_dir"] = validate_generated_path(
            repository_root,
            require_existing_directory(artifact_dir, field_name="artifact_dir"),
            field_name="artifact_dir",
        )
    if backup_path is not None:
        backup = validate_generated_path(
            repository_root, backup_path, field_name="backup_path"
        )
        checked["backup_path"] = backup
        checked["backup_sha256_path"] = validate_generated_path(
            repository_root,
            backup.with_suffix(backup.suffix + ".sha256"),
            field_name="backup_sha256_path",
        )
    if result_path is not None:
        checked["result_path"] = validate_generated_path(
            repository_root, result_path, field_name="result_path"
        )
    checked["lock_paths"] = tuple(
        validate_generated_path(repository_root, path, field_name="lock_path")
        for path in lock_paths
    )
    return checked


def _without_volatile_fields(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): _without_volatile_fields(item)
            for key, item in value.items()
            if key not in _VOLATILE_PLAN_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_without_volatile_fields(item) for item in value]
    return value


def canonical_plan_binding(plan: Mapping[str, object]) -> dict[str, object]:
    binding = _without_volatile_fields(plan)
    if not isinstance(binding, dict):
        raise PacketCheckpointRecoveryError("canonical plan must be an object")
    return binding


def canonical_plan_json(plan: Mapping[str, object]) -> str:
    return json.dumps(
        canonical_plan_binding(plan),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def calculate_plan_sha256(plan: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_plan_json(plan).encode("utf-8")).hexdigest()


def attach_plan_sha256(
    payload: Mapping[str, object], *, generated_at: datetime
) -> dict[str, object]:
    plan = {**payload, "generated_at": format_db_utc(generated_at)}
    return {**plan, "plan_sha256": calculate_plan_sha256(plan)}


def verify_plan_sha256(plan: Mapping[str, object]) -> None:
    expected = plan.get("plan_sha256")
    actual = calculate_plan_sha256(plan)
    if not isinstance(expected, str) or not hmac.compare_digest(expected, actual):
        raise PacketCheckpointRecoveryError("plan SHA256 mismatch")


def _git(repository_root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout


def _sha256_open_regular_file(path: Path, expected: os.stat_result) -> str:
    # A regular file can be replaced by a FIFO after lstat; do not block in
    # open before fstat gets a chance to reject the replacement.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise PacketCheckpointRecoveryError("untracked entry must be a regular file")
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise PacketCheckpointRecoveryError("untracked entry changed before hashing")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _inventory_entry(repository_root: Path, relative_path: str) -> dict[str, object]:
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise PacketCheckpointRecoveryError("invalid untracked repository path")
    absolute = repository_root / relative
    before = absolute.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise PacketCheckpointRecoveryError("untracked entry must be a regular file")
    digest = _sha256_open_regular_file(absolute, before)
    after = absolute.lstat()
    identity_before = (
        before.st_mode, before.st_dev, before.st_ino,
        before.st_size, before.st_mtime_ns,
    )
    identity_after = (
        after.st_mode, after.st_dev, after.st_ino,
        after.st_size, after.st_mtime_ns,
    )
    if identity_before != identity_after:
        raise PacketCheckpointRecoveryError("untracked file changed during inventory")
    return {"path": relative.as_posix(), "size": after.st_size, "sha256": digest}


class _RepositoryTraversalChanged(Exception):
    """Only an entry that disappeared during the filesystem traversal."""


def _reject_non_regular_repository_entries(root: Path) -> None:
    """Git omits FIFOs/sockets from ls-files; reject them without opening them.

    Prune ignored directories before descent, including large local environments
    and evidence directories. Untracked symlinks remain subject to the existing
    Git inventory check and are never followed by this traversal.
    """
    pending = [root]
    while pending:
        directory = pending.pop()
        candidates: dict[str, tuple[Path, bool]] = {}
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.name == ".git":
                        continue
                    mode = entry.stat(follow_symlinks=False).st_mode
                    if stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                        continue
                    path = Path(entry.path)
                    candidates[path.relative_to(root).as_posix()] = (path, stat.S_ISDIR(mode))
        except FileNotFoundError as exc:
            if exc.errno != errno.ENOENT:
                raise
            # A capture worker may rename an ignored PCAP after enumeration.
            # Do not skip it: discard this traversal and all earlier Git reads.
            raise _RepositoryTraversalChanged from exc
        if not candidates:
            continue
        ignored = subprocess.run(
            ["git", "check-ignore", "--stdin", "-z"],
            cwd=root,
            input="\0".join(candidates) + "\0",
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if ignored.returncode not in (0, 1):
            ignored.check_returncode()
        ignored_paths = set(ignored.stdout.split("\0"))
        for relative_path, (path, is_directory) in candidates.items():
            if relative_path in ignored_paths:
                continue
            if not is_directory:
                raise PacketCheckpointRecoveryError("untracked entry must be a regular file")
            pending.append(path)


def inspect_repository_state(repository_root: str | Path) -> dict[str, object]:
    root = Path(repository_root).expanduser().resolve(strict=True)
    for attempt in range(3):
        commit = _git(root, "rev-parse", "HEAD").strip()
        tracked = _git(root, "diff", "--name-only", "--").splitlines()
        staged = _git(root, "diff", "--cached", "--name-only", "--").splitlines()
        untracked = _git(
            root, "ls-files", "--others", "--exclude-standard", "-z"
        ).split("\0")
        try:
            _reject_non_regular_repository_entries(root)
        except _RepositoryTraversalChanged as exc:
            if attempt == 2:
                raise PacketCheckpointRecoveryError(
                    "repository filesystem changed repeatedly during inspection"
                ) from exc
            continue
        # Inventory disappearance/mutation and Git errors remain fail-closed;
        # they do not share the capture traversal's bounded retry allowance.
        inventory = [_inventory_entry(root, path) for path in untracked if path]
        if tracked or staged:
            raise PacketCheckpointRecoveryError("tracked/staged worktree must be clean")
        return {
            "repository_root": str(root),
            "repository_commit": commit,
            "tracked_worktree_clean": True,
            "staged_worktree_clean": True,
            "untracked_inventory": sorted(inventory, key=lambda row: row["path"]),
        }
