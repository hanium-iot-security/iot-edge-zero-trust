from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import subprocess

import pytest

from edge.detection import packet_checkpoint_recovery
from edge.detection.packet_checkpoint_recovery import (
    PacketCheckpointRecoveryError,
    attach_plan_sha256,
    verify_plan_sha256,
)


UTC_A = datetime(2026, 8, 6, 10, 0, 0, tzinfo=timezone.utc)
UTC_B = datetime(2026, 8, 6, 11, 0, 0, tzinfo=timezone.utc)
OTHER_UTC = "2026-08-06T12:00:00Z"


def _git(repository_root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout


def _repository(tmp_path: Path) -> Path:
    repository_root = tmp_path / "repository"
    repository_root.mkdir()
    _git(repository_root, "init")
    _git(repository_root, "config", "user.email", "test@example.com")
    _git(repository_root, "config", "user.name", "Test User")
    (repository_root / "tracked.txt").write_bytes(b"tracked\n")
    _git(repository_root, "add", "tracked.txt")
    _git(repository_root, "commit", "-m", "initial")
    return repository_root


@pytest.fixture
def untracked_fifo_repository(tmp_path: Path) -> Path:
    repository_root = _repository(tmp_path)
    try:
        os.mkfifo(repository_root / "queue")
    except (AttributeError, NotImplementedError, OSError) as exc:
        pytest.skip(f"FIFO unsupported: {exc}")
    return repository_root


def test_canonical_plan_sha_is_independent_of_key_order_and_volatile_fields() -> None:
    payload = {
        "plan_schema_version": "packet-checkpoint-gap-recovery-plan-v1",
        "repository_commit": "a" * 40,
        "repository_root": "/repo",
        "database_path": "/data/iot.db",
        "detector_name": "packet_rule",
        "source_table": "packet_feature_logs",
    }
    first = attach_plan_sha256(payload, generated_at=UTC_A)
    second = attach_plan_sha256(dict(reversed(tuple(payload.items()))), generated_at=UTC_B)

    assert first["plan_sha256"] == second["plan_sha256"]


def test_verify_plan_sha256_rejects_bound_field_tampering() -> None:
    plan = attach_plan_sha256(
        {
            "plan_schema_version": "packet-checkpoint-gap-recovery-plan-v1",
            "repository_commit": "a" * 40,
            "repository_root": "/repo",
            "database_path": "/data/iot.db",
            "detector_name": "packet_rule",
            "source_table": "packet_feature_logs",
            "checkpoint": {
                "before": {"last_completed_window_end": "2026-08-06T10:00:00Z"},
                "after": {"last_completed_window_end": "2026-08-06T11:00:00Z"},
            },
        },
        generated_at=UTC_A,
    )
    plan["checkpoint"]["after"]["last_completed_window_end"] = OTHER_UTC

    with pytest.raises(PacketCheckpointRecoveryError, match="plan SHA256"):
        verify_plan_sha256(plan)


def test_repository_state_rejects_tracked_changes(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    (repository_root / "tracked.txt").write_bytes(b"changed\n")

    with pytest.raises(PacketCheckpointRecoveryError, match="tracked/staged"):
        packet_checkpoint_recovery.inspect_repository_state(repository_root)


def test_repository_state_rejects_staged_changes(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    (repository_root / "tracked.txt").write_bytes(b"staged\n")
    _git(repository_root, "add", "tracked.txt")

    with pytest.raises(PacketCheckpointRecoveryError, match="tracked/staged"):
        packet_checkpoint_recovery.inspect_repository_state(repository_root)


def test_repository_state_records_untracked_path_size_and_sha256(
    tmp_path: Path,
) -> None:
    repository_root = _repository(tmp_path)
    payload = b"untracked payload\n"
    (repository_root / "untracked.bin").write_bytes(payload)

    state = packet_checkpoint_recovery.inspect_repository_state(repository_root)

    assert state["repository_root"] == str(repository_root.resolve())
    assert state["tracked_worktree_clean"] is True
    assert state["staged_worktree_clean"] is True
    assert state["untracked_inventory"] == [{
        "path": "untracked.bin",
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }]


def test_repository_state_does_not_modify_untracked_file_named_zero(
    tmp_path: Path,
) -> None:
    repository_root = _repository(tmp_path)
    zero = repository_root / "0"
    zero.write_bytes(b"must remain untouched\n")
    before_bytes = zero.read_bytes()
    before_sha256 = hashlib.sha256(before_bytes).hexdigest()

    packet_checkpoint_recovery.inspect_repository_state(repository_root)

    assert zero.read_bytes() == before_bytes
    assert hashlib.sha256(zero.read_bytes()).hexdigest() == before_sha256


def test_repository_state_rejects_untracked_symlink(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    target = repository_root / "target.txt"
    target.write_bytes(b"target\n")
    link = repository_root / "untracked-link"
    try:
        os.symlink(target, link)
    except (AttributeError, NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink unsupported: {exc}")

    with pytest.raises(PacketCheckpointRecoveryError, match="regular file"):
        packet_checkpoint_recovery.inspect_repository_state(repository_root)


def test_inventory_entry_rejects_non_regular_file(
    untracked_fifo_repository: Path,
) -> None:
    with pytest.raises(PacketCheckpointRecoveryError, match="regular file"):
        packet_checkpoint_recovery.inspect_repository_state(untracked_fifo_repository)
