"""Canonical plan helpers for packet checkpoint gap recovery."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
from datetime import datetime
from typing import Mapping, Sequence

from edge.detection import packet_checkpoint_recovery_repository as recovery_repository
from edge.detection.phase4_time import format_db_utc, parse_db_utc


PLAN_SCHEMA_VERSION = "packet-checkpoint-gap-recovery-plan-v1"
_VOLATILE_PLAN_KEYS = frozenset({
    "plan_sha256", "generated_at", "executed_at", "operation_id", "mode",
    "plan_path", "artifact_dir", "backup_path", "result_path", "backup_sha256",
    "execute_command", "repository_branch", "file_mtime_ns", "data_version",
    "process_id", "lock_acquired_at", "post_commit_verified_at",
})


class PacketCheckpointRecoveryError(Exception):
    """Raised when a packet checkpoint recovery plan is invalid."""


def _readiness_summary(
    session: sqlite3.Row,
    readiness: recovery_repository.RecoverySessionReadiness,
) -> dict[str, object]:
    return {
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
) -> dict[str, object]:
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
    if current_session is None:
        blocking_reasons.append("CURRENT_SESSION_NOT_FOUND")
    elif current_session["status"] != "COMPLETED":
        blocking_reasons.append("CURRENT_SESSION_NOT_COMPLETED")
    if target_session is None:
        blocking_reasons.append("TARGET_SESSION_NOT_FOUND")
    elif target_session["status"] != "COMPLETED":
        blocking_reasons.append("TARGET_SESSION_NOT_COMPLETED")
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
        if not target_readiness.full_ready:
            blocking_reasons.append("TARGET_SESSION_NOT_FULL_READY")
    if checkpoint_window is not None and target_first is not None:
        if target_first <= checkpoint_window:
            blocking_reasons.append("CHECKPOINT_WOULD_NOT_ADVANCE")

    running_rows = recovery_repository.list_running_capture_sessions(connection)
    running_sessions = [
        {"session_id": str(row["session_id"]), "started_at": str(row["started_at"])}
        for row in running_rows
    ]
    if running_sessions:
        blocking_reasons.append("RUNNING_CAPTURE_SESSIONS")

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
        sessions_between = [
            {
                "session_id": str(row["session_id"]),
                "first_window_start": str(row["first_window_start"]),
                "status": str(row["status"]),
            }
            for row in recovery_repository.list_sessions_between(
                connection,
                after_window_end=format_db_utc(checkpoint_window),
                before_window_start=format_db_utc(target_first),
            )
        ]

    return {
        "plan_schema_version": PLAN_SCHEMA_VERSION,
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
            _readiness_summary(target_session, target_readiness)
            if target_session is not None and target_readiness is not None
            else None
        ),
        "sessions_between": sessions_between,
        "running_sessions": running_sessions,
        "existing_recovery": (
            dict(existing_recovery) if existing_recovery is not None else None
        ),
        "locks": [dict(entry) for entry in lock_entries],
        "blocking_reasons": blocking_reasons,
        "can_execute": not blocking_reasons,
    }


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
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
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


def inspect_repository_state(repository_root: str | Path) -> dict[str, object]:
    root = Path(repository_root).expanduser().resolve(strict=True)
    commit = _git(root, "rev-parse", "HEAD").strip()
    tracked = _git(root, "diff", "--name-only", "--").splitlines()
    staged = _git(root, "diff", "--cached", "--name-only", "--").splitlines()
    untracked = _git(
        root, "ls-files", "--others", "--exclude-standard", "-z"
    ).split("\0")
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
