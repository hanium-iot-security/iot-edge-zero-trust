"""Canonical plan helpers for packet checkpoint gap recovery."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import subprocess
from datetime import datetime
from typing import Mapping, Sequence

from edge.detection.phase4_time import format_db_utc


PLAN_SCHEMA_VERSION = "packet-checkpoint-gap-recovery-plan-v1"
_VOLATILE_PLAN_KEYS = frozenset({
    "plan_sha256", "generated_at", "executed_at", "operation_id", "mode",
    "plan_path", "artifact_dir", "backup_path", "result_path", "backup_sha256",
    "execute_command", "repository_branch", "file_mtime_ns", "data_version",
    "process_id", "lock_acquired_at", "post_commit_verified_at",
})


class PacketCheckpointRecoveryError(Exception):
    """Raised when a packet checkpoint recovery plan is invalid."""


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
