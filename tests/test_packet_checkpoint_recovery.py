from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.detection import packet_checkpoint_recovery
from edge.detection.packet_checkpoint_recovery import (
    PacketCheckpointRecoveryError,
    attach_plan_sha256,
    build_recovery_plan,
    verify_plan_sha256,
)
from edge.detection.packet_checkpoint_recovery_repository import (
    calculate_packet_feature_readiness,
)
from edge.packet.capture_session_repository import get_packet_feature_ready_through


UTC_A = datetime(2026, 8, 6, 10, 0, 0, tzinfo=timezone.utc)
UTC_B = datetime(2026, 8, 6, 11, 0, 0, tzinfo=timezone.utc)
OTHER_UTC = "2026-08-06T12:00:00Z"
CURRENT_SESSION = "11111111-1111-4111-8111-111111111111"
TARGET_SESSION = "22222222-2222-4222-8222-222222222222"
RUNNING_SESSION_A = "33333333-3333-4333-8333-333333333333"
RUNNING_SESSION_B = "44444444-4444-4444-8444-444444444444"
CURRENT_FIRST = datetime(2026, 8, 6, 10, 0, 0, tzinfo=timezone.utc)
CURRENT_READY_THROUGH = datetime(2026, 8, 6, 10, 0, 20, tzinfo=timezone.utc)
TARGET_FIRST = datetime(2026, 8, 6, 10, 1, 0, tzinfo=timezone.utc)
TARGET_READY_THROUGH = datetime(2026, 8, 6, 10, 1, 20, tzinfo=timezone.utc)
PROCESSABLE_SKIP_SESSION = "55555555-5555-4555-8555-555555555555"
FAILED_SKIP_SESSION = "66666666-6666-4666-8666-666666666666"
NOT_READY_SKIP_SESSION = "77777777-7777-4777-8777-777777777777"


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


def _db_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _open_migrated_database(path: Path) -> sqlite3.Connection:
    apply_migrations(path, MIGRATIONS_DIR)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _insert_capture_session(
    connection: sqlite3.Connection,
    *,
    session_id: str,
    capture_interface: str,
    first_window_start: datetime,
    status: str = "COMPLETED",
    started_at: datetime | None = None,
) -> int:
    started = started_at or first_window_start - timedelta(seconds=10)
    ended_at = None if status == "RUNNING" else first_window_start + timedelta(minutes=1)
    cursor = connection.execute(
        """
        INSERT INTO packet_capture_sessions (
            session_id, capture_interface, started_at,
            first_window_start, ended_at, status
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            session_id,
            capture_interface,
            _db_utc(started),
            _db_utc(first_window_start),
            _db_utc(ended_at) if ended_at is not None else None,
            status,
        ),
    )
    return int(cursor.lastrowid)


def _insert_capture_segment(
    connection: sqlite3.Connection,
    *,
    session_pk: int,
    capture_interface: str,
    window_start: datetime,
    status: str,
    feature_count: int = 0,
    error_code: str | None = None,
    file_suffix: str = "",
) -> int:
    window_end = window_start + timedelta(seconds=10)
    cursor = connection.execute(
        """
        INSERT INTO packet_capture_segments (
            capture_session_id, file_name, capture_interface,
            window_start, window_end, status, error_code
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session_pk,
            f"{session_pk}-{_db_utc(window_start)}{file_suffix}.pcap",
            capture_interface,
            _db_utc(window_start),
            _db_utc(window_end),
            status,
            error_code,
        ),
    )
    segment_id = int(cursor.lastrowid)
    for index in range(feature_count):
        connection.execute(
            """
            INSERT INTO packet_feature_logs (
                capture_segment_id, peer_ip, direction,
                window_start, window_end, packet_count,
                total_bytes, avg_packet_size, max_packet_size
            )
            VALUES (?, ?, 'INBOUND', ?, ?, 1, 60, 60.0, 60)
            """,
            (
                segment_id,
                f"10.0.{session_pk}.{index + 1}",
                _db_utc(window_start),
                _db_utc(window_end),
            ),
        )
    return segment_id


def _insert_feature_for_existing_segment(
    connection: sqlite3.Connection, segment_id: int
) -> None:
    row = connection.execute(
        "SELECT window_start, window_end FROM packet_capture_segments WHERE id = ?",
        (segment_id,),
    ).fetchone()
    assert row is not None
    connection.execute(
        """
        INSERT INTO packet_feature_logs (
            capture_segment_id, peer_ip, direction,
            window_start, window_end, packet_count,
            total_bytes, avg_packet_size, max_packet_size
        )
        VALUES (?, '10.255.255.1', 'INBOUND', ?, ?, 1, 60, 60.0, 60)
        """,
        (segment_id, row["window_start"], row["window_end"]),
    )


def _seed_valid_recovery_database(path: Path) -> sqlite3.Connection:
    connection = _open_migrated_database(path)
    current_pk = _insert_capture_session(
        connection,
        session_id=CURRENT_SESSION,
        capture_interface="eth-current",
        first_window_start=CURRENT_FIRST,
    )
    _insert_capture_segment(
        connection,
        session_pk=current_pk,
        capture_interface="eth-current",
        window_start=CURRENT_FIRST,
        status="PROCESSED",
        feature_count=1,
    )
    _insert_capture_segment(
        connection,
        session_pk=current_pk,
        capture_interface="eth-current",
        window_start=CURRENT_FIRST + timedelta(seconds=10),
        status="EMPTY",
    )
    target_pk = _insert_capture_session(
        connection,
        session_id=TARGET_SESSION,
        capture_interface="eth-target",
        first_window_start=TARGET_FIRST,
    )
    _insert_capture_segment(
        connection,
        session_pk=target_pk,
        capture_interface="eth-target",
        window_start=TARGET_FIRST,
        status="PROCESSED",
        feature_count=2,
    )
    _insert_capture_segment(
        connection,
        session_pk=target_pk,
        capture_interface="eth-target",
        window_start=TARGET_FIRST + timedelta(seconds=10),
        status="EMPTY",
    )
    connection.execute(
        """
        INSERT INTO detector_checkpoints (
            detector_name, source_table, last_processed_id,
            last_completed_window_end, updated_at
        )
        VALUES ('packet_rule', 'packet_feature_logs', 42, ?, ?)
        """,
        (_db_utc(CURRENT_READY_THROUGH), _db_utc(CURRENT_READY_THROUGH)),
    )
    connection.commit()
    return connection


def _repository_state_for_plan(tmp_path: Path) -> dict[str, object]:
    return {
        "repository_root": str(tmp_path.resolve()),
        "repository_commit": "a" * 40,
        "tracked_worktree_clean": True,
        "staged_worktree_clean": True,
        "untracked_inventory": [],
    }


def _build_plan(
    connection: sqlite3.Connection,
    *,
    tmp_path: Path,
    detector_name: str = "packet_rule",
    current_session_id: str = CURRENT_SESSION,
    target_session_id: str = TARGET_SESSION,
) -> dict[str, object]:
    database_path = Path(
        connection.execute("PRAGMA database_list").fetchone()["file"]
    ).resolve()
    return build_recovery_plan(
        connection,
        repository_state=_repository_state_for_plan(tmp_path),
        database_path=database_path,
        detector_name=detector_name,
        current_session_id=current_session_id,
        target_session_id=target_session_id,
        approved_by="operator@example.com",
        reason="recover capture-session gap",
        lock_entries=({"path": str(tmp_path / "recovery.lock"), "roles": ["test"]},),
    )


def _blocking_codes(plan: dict[str, object]) -> set[str]:
    return set(plan["blocking_reasons"])


def test_plan_classifies_full_ready_completed_session_as_processable_skip(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "processable-skip.db")
    try:
        skipped_first = CURRENT_READY_THROUGH + timedelta(seconds=10)
        skipped_pk = _insert_capture_session(
            connection,
            session_id=PROCESSABLE_SKIP_SESSION,
            capture_interface="eth-skipped",
            first_window_start=skipped_first,
        )
        _insert_capture_segment(
            connection,
            session_pk=skipped_pk,
            capture_interface="eth-skipped",
            window_start=skipped_first,
            status="PROCESSED",
            feature_count=1,
        )
        _insert_capture_segment(
            connection,
            session_pk=skipped_pk,
            capture_interface="eth-skipped",
            window_start=skipped_first + timedelta(seconds=10),
            status="EMPTY",
        )
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path)

        assert plan["sessions_between"] == [
            {
                "classification": "SKIPPED_FULL_READY_COMPLETED",
                "session_id": PROCESSABLE_SKIP_SESSION,
                "first_window_start": _db_utc(skipped_first),
                "packet_feature_ready_through": _db_utc(
                    skipped_first + timedelta(seconds=20)
                ),
                "segment_count": 2,
                "feature_row_count": 1,
                "warning_codes": ["PROCESSABLE_SESSION_SKIP"],
            }
        ]
        assert plan["summary"]["skips_processable_sessions"] is True
        assert plan["summary"]["warning_codes"] == [
            "PROCESSABLE_SESSION_SKIP"
        ]
        assert plan["summary"]["current_session_classification"] == "EXHAUSTED_CURRENT"
        assert (
            plan["summary"]["target_session_classification"]
            == "TARGET_FULL_READY_COMPLETED"
        )
    finally:
        connection.close()


def test_plan_classifies_failed_and_not_ready_sessions_separately(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "nonprocessable-skips.db")
    try:
        failed_first = CURRENT_READY_THROUGH + timedelta(seconds=10)
        not_ready_first = failed_first + timedelta(seconds=10)
        _insert_capture_session(
            connection,
            session_id=FAILED_SKIP_SESSION,
            capture_interface="eth-failed",
            first_window_start=failed_first,
            status="FAILED",
        )
        not_ready_pk = _insert_capture_session(
            connection,
            session_id=NOT_READY_SKIP_SESSION,
            capture_interface="eth-not-ready",
            first_window_start=not_ready_first,
        )
        _insert_capture_segment(
            connection,
            session_pk=not_ready_pk,
            capture_interface="eth-not-ready",
            window_start=not_ready_first,
            status="READY",
        )
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path)

        assert [row["classification"] for row in plan["sessions_between"]] == [
            "SKIPPED_FAILED",
            "SKIPPED_NOT_READY",
        ]
        assert plan["summary"]["skips_processable_sessions"] is False
        assert plan["summary"]["warning_codes"] == []
    finally:
        connection.close()


def test_processable_skip_requires_plan_sha_bound_confirmation(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "confirm-processable.db")
    try:
        skipped_first = CURRENT_READY_THROUGH + timedelta(seconds=10)
        skipped_pk = _insert_capture_session(
            connection,
            session_id=PROCESSABLE_SKIP_SESSION,
            capture_interface="eth-skipped",
            first_window_start=skipped_first,
        )
        _insert_capture_segment(
            connection,
            session_pk=skipped_pk,
            capture_interface="eth-skipped",
            window_start=skipped_first,
            status="EMPTY",
        )
        connection.commit()
        plan = attach_plan_sha256(_build_plan(connection, tmp_path=tmp_path), generated_at=UTC_A)

        packet_checkpoint_recovery.require_execute_confirmations(
            plan,
            confirm="APPLY-PACKET-CHECKPOINT-GAP-RECOVERY",
            confirm_skip_processable=(
                f"SKIP-PROCESSABLE-SESSIONS:{plan['plan_sha256']}"
            ),
        )
    finally:
        connection.close()


def test_processable_skip_rejects_missing_or_wrong_confirmation(tmp_path: Path) -> None:
    plan = {
        "plan_sha256": "a" * 64,
        "summary": {"skips_processable_sessions": True},
    }

    with pytest.raises(
        PacketCheckpointRecoveryError, match="processable-session confirmation mismatch"
    ):
        packet_checkpoint_recovery.require_execute_confirmations(
            plan,
            confirm="APPLY-PACKET-CHECKPOINT-GAP-RECOVERY",
            confirm_skip_processable=None,
        )
    with pytest.raises(
        PacketCheckpointRecoveryError, match="processable-session confirmation mismatch"
    ):
        packet_checkpoint_recovery.require_execute_confirmations(
            plan,
            confirm="APPLY-PACKET-CHECKPOINT-GAP-RECOVERY",
            confirm_skip_processable="SKIP-PROCESSABLE-SESSIONS:" + "b" * 64,
        )


def test_nonprocessable_gap_does_not_require_processable_skip_confirmation(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "confirm-nonprocessable.db")
    try:
        _insert_capture_session(
            connection,
            session_id=FAILED_SKIP_SESSION,
            capture_interface="eth-failed",
            first_window_start=CURRENT_READY_THROUGH + timedelta(seconds=10),
            status="FAILED",
        )
        connection.commit()
        plan = attach_plan_sha256(_build_plan(connection, tmp_path=tmp_path), generated_at=UTC_A)

        packet_checkpoint_recovery.require_execute_confirmations(
            plan,
            confirm="APPLY-PACKET-CHECKPOINT-GAP-RECOVERY",
            confirm_skip_processable=None,
        )
    finally:
        connection.close()


def test_confirmation_is_rejected_when_plan_has_no_processable_skip() -> None:
    plan = {
        "plan_sha256": "a" * 64,
        "summary": {"skips_processable_sessions": False},
    }

    with pytest.raises(
        PacketCheckpointRecoveryError, match="processable-session confirmation not allowed"
    ):
        packet_checkpoint_recovery.require_execute_confirmations(
            plan,
            confirm="APPLY-PACKET-CHECKPOINT-GAP-RECOVERY",
            confirm_skip_processable="SKIP-PROCESSABLE-SESSIONS:" + "a" * 64,
        )


def _insert_recovery_audit(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO packet_checkpoint_recoveries (
            operation_id, detector_name, source_table,
            current_capture_session_id, target_capture_session_id,
            last_processed_id_before, last_processed_id_after,
            last_completed_window_end_before, last_completed_window_end_after,
            updated_at_before, updated_at_after, plan_sha256, plan_json,
            skipped_session_count, skipped_processable_session_count,
            approved_by, reason, repository_commit, database_path,
            backup_path, backup_sha256
        )
        VALUES (
            '20260806T100000Z-111111111111', 'packet_rule', 'packet_feature_logs',
            ?, ?, 42, 42, ?, ?, ?, ?, ?, '{}', 0, 0,
            'operator@example.com', 'already recovered', ?, ?, ?, ?
        )
        """,
        (
            CURRENT_SESSION,
            TARGET_SESSION,
            _db_utc(CURRENT_READY_THROUGH),
            _db_utc(TARGET_FIRST),
            _db_utc(CURRENT_READY_THROUGH),
            _db_utc(TARGET_FIRST),
            "b" * 64,
            "a" * 40,
            str(Path("fixture.db").resolve()),
            str(Path("fixture.backup.db").resolve()),
            "c" * 64,
        ),
    )
    connection.commit()


def _assert_readiness_parity(database: Path, session_ids: tuple[str, ...]) -> None:
    engine = create_engine(f"sqlite:///{database}")
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        with session_factory() as sqlalchemy_session, sqlite3.connect(database) as raw:
            raw.row_factory = sqlite3.Row
            for session_id in session_ids:
                existing = get_packet_feature_ready_through(
                    sqlalchemy_session, session_id=session_id
                )
                recovery = calculate_packet_feature_readiness(raw, session_id)
                assert existing is not None
                assert recovery is not None
                assert recovery.first_window_start == existing.first_window_start
                assert (
                    recovery.packet_feature_ready_through
                    == existing.packet_feature_ready_through
                )
                assert recovery.first_window_start is not None
                assert recovery.first_window_start.utcoffset() == timedelta(0)
                if recovery.packet_feature_ready_through is not None:
                    assert recovery.packet_feature_ready_through.utcoffset() == timedelta(0)
    finally:
        engine.dispose()


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


def test_canonical_plan_sha_changes_when_resolved_database_path_changes(
    tmp_path: Path,
) -> None:
    first_db = tmp_path / "first.db"
    second_db = tmp_path / "second.db"
    first_db.write_bytes(b"first")
    second_db.write_bytes(b"second")

    first_plan = attach_plan_sha256(
        {"database_path": str(first_db.resolve())}, generated_at=UTC_A
    )
    second_plan = attach_plan_sha256(
        {"database_path": str(second_db.resolve())}, generated_at=UTC_A
    )

    assert first_plan["plan_sha256"] != second_plan["plan_sha256"]


def test_database_path_requires_existing_regular_file(tmp_path: Path) -> None:
    directory = tmp_path / "directory"
    directory.mkdir()

    with pytest.raises(PacketCheckpointRecoveryError, match="regular file"):
        packet_checkpoint_recovery.resolve_database_path(directory)


def test_require_plan_database_path_rejects_different_resolved_path(
    tmp_path: Path,
) -> None:
    first_db = tmp_path / "first.db"
    second_db = tmp_path / "second.db"
    first_db.write_bytes(b"first")
    second_db.write_bytes(b"second")
    plan = {"database_path": str(first_db.resolve())}

    with pytest.raises(PacketCheckpointRecoveryError, match="database path"):
        packet_checkpoint_recovery.require_plan_database_path(plan, second_db)


def test_require_plan_database_path_accepts_same_resolved_path(tmp_path: Path) -> None:
    database = tmp_path / "iot.db"
    database.write_bytes(b"sqlite fixture")
    plan = {"database_path": str(database.resolve())}

    assert (
        packet_checkpoint_recovery.require_plan_database_path(plan, database)
        == database.resolve()
    )


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


def test_generated_path_allows_path_outside_repository(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    outside = tmp_path / "outside" / "result.json"

    assert packet_checkpoint_recovery.validate_generated_path(
        repository_root, outside, field_name="result_path"
    ) == outside.resolve()
    assert not outside.exists()


def test_generated_path_allows_gitignored_path_inside_repository(
    tmp_path: Path,
) -> None:
    repository_root = _repository(tmp_path)
    (repository_root / ".gitignore").write_text("generated/\n", encoding="utf-8")
    plan = repository_root / "generated" / "plan.json"
    artifact_dir = repository_root / "generated"
    result = repository_root / "generated" / "result.json"
    lock = repository_root / "generated" / "run.lock"
    artifact_dir.mkdir()

    checked = packet_checkpoint_recovery.validate_generated_paths(
        repository_root=repository_root,
        plan_output=plan,
        artifact_dir=artifact_dir,
        result_path=result,
        lock_paths=(lock,),
    )

    assert checked == {
        "plan_output": plan.resolve(),
        "artifact_dir": artifact_dir.resolve(),
        "result_path": result.resolve(),
        "lock_paths": (lock.resolve(),),
    }
    assert not plan.exists()
    assert not result.exists()
    assert not lock.exists()


def test_generated_path_rejects_unignored_path_before_creation(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    candidate = repository_root / "generated" / "result.json"

    with pytest.raises(PacketCheckpointRecoveryError, match="result_path must be Git-ignored"):
        packet_checkpoint_recovery.validate_generated_path(
            repository_root, candidate, field_name="result_path"
        )

    assert not candidate.parent.exists()
    assert not candidate.exists()


def test_generated_path_checks_backup_sha256_sidecar(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    (repository_root / ".gitignore").write_text("backups/*.db\n", encoding="utf-8")
    backup = repository_root / "backups" / "checkpoint.db"
    sidecar = repository_root / "backups" / "checkpoint.db.sha256"

    with pytest.raises(
        PacketCheckpointRecoveryError, match="backup_sha256_path must be Git-ignored"
    ):
        packet_checkpoint_recovery.validate_generated_paths(
            repository_root=repository_root, backup_path=backup
        )

    assert not backup.parent.exists()
    assert not backup.exists()
    assert not sidecar.exists()


def test_lock_resolution_uses_orchestrator_manual_and_extractor_contracts(
    tmp_path: Path,
) -> None:
    repository_root = tmp_path.resolve()

    locks = packet_checkpoint_recovery.resolve_recovery_locks(
        repository_root=repository_root,
        database_url="sqlite:///data/recovery.db",
        orchestrator_lock_path=None,
        manual_lock_path=None,
        extractor_lock_path=None,
    )

    assert packet_checkpoint_recovery.serialize_resolved_locks(locks) == (
        {
            "path": str((repository_root / "data/pcap/.extractor.lock").resolve()),
            "roles": ["packet_feature_extractor"],
        },
        {
            "path": str(
                (repository_root / "data/phase4-detection-cycle.lock").resolve()
            ),
            "roles": ["packet_if_manual", "packet_rule_manual"],
        },
        {
            "path": str(
                (repository_root / "data/recovery.db.orchestrator.lock").resolve()
            ),
            "roles": ["detection_orchestrator"],
        },
    )


def test_lock_resolution_preserves_orchestrator_non_sqlite_fallback(
    tmp_path: Path,
) -> None:
    locks = packet_checkpoint_recovery.resolve_recovery_locks(
        repository_root=tmp_path,
        database_url="postgresql://localhost/iot",
        orchestrator_lock_path=None,
        manual_lock_path=None,
        extractor_lock_path=None,
    )

    orchestrator = next(
        lock for lock in locks if lock.roles == ("detection_orchestrator",)
    )
    assert orchestrator.path == (
        tmp_path / "data/detection-orchestrator.lock"
    ).resolve()


def test_relative_lock_paths_resolve_from_repository_root(tmp_path: Path) -> None:
    locks = packet_checkpoint_recovery.resolve_recovery_locks(
        repository_root=tmp_path,
        database_url="postgresql://localhost/iot",
        orchestrator_lock_path=Path("locks/orchestrator.lock"),
        manual_lock_path=Path("locks/manual.lock"),
        extractor_lock_path=Path("locks/extractor.lock"),
    )

    assert {lock.path for lock in locks} == {
        (tmp_path / "locks/orchestrator.lock").resolve(),
        (tmp_path / "locks/manual.lock").resolve(),
        (tmp_path / "locks/extractor.lock").resolve(),
    }


def test_shared_rule_if_lock_is_acquired_once_with_both_roles(tmp_path: Path) -> None:
    locks = packet_checkpoint_recovery.resolve_recovery_locks(
        repository_root=tmp_path,
        database_url="postgresql://localhost/iot",
        orchestrator_lock_path=None,
        manual_lock_path=None,
        extractor_lock_path=None,
    )

    manual = [lock for lock in locks if "packet_rule_manual" in lock.roles]
    assert manual == [
        packet_checkpoint_recovery.ResolvedRecoveryLock(
            path=(tmp_path / "data/phase4-detection-cycle.lock").resolve(),
            roles=("packet_if_manual", "packet_rule_manual"),
        )
    ]


def test_duplicate_orchestrator_and_manual_path_is_acquired_once(
    tmp_path: Path,
) -> None:
    shared = Path("locks/shared.lock")
    locks = packet_checkpoint_recovery.resolve_recovery_locks(
        repository_root=tmp_path,
        database_url="postgresql://localhost/iot",
        orchestrator_lock_path=shared,
        manual_lock_path=shared,
        extractor_lock_path=Path("locks/extractor.lock"),
    )

    assert locks == tuple(sorted(locks, key=lambda lock: str(lock.path)))
    assert next(lock for lock in locks if lock.path == (tmp_path / shared).resolve()) == (
        packet_checkpoint_recovery.ResolvedRecoveryLock(
            path=(tmp_path / shared).resolve(),
            roles=(
                "detection_orchestrator",
                "packet_if_manual",
                "packet_rule_manual",
            ),
        )
    )
    assert len(locks) == 2


def test_unique_locks_are_acquired_in_sorted_absolute_path_order_with_injected_lock(
    tmp_path: Path,
) -> None:
    first = (tmp_path / "a.lock").resolve()
    second = (tmp_path / "b.lock").resolve()
    events: list[tuple[str, Path]] = []

    @contextmanager
    def fake_lock(path: Path):
        events.append(("enter", path))
        try:
            yield
        finally:
            events.append(("exit", path))

    locks = (
        packet_checkpoint_recovery.ResolvedRecoveryLock(second, ("second",)),
        packet_checkpoint_recovery.ResolvedRecoveryLock(first, ("first",)),
    )

    with packet_checkpoint_recovery.acquire_recovery_locks(
        locks, lock_factory=fake_lock
    ):
        assert events == [("enter", first), ("enter", second)]

    assert events == [
        ("enter", first),
        ("enter", second),
        ("exit", second),
        ("exit", first),
    ]


def test_acquire_recovery_locks_releases_already_acquired_locks_on_conflict(
    tmp_path: Path,
) -> None:
    first = (tmp_path / "a.lock").resolve()
    conflict = (tmp_path / "b.lock").resolve()
    last = (tmp_path / "c.lock").resolve()
    events: list[tuple[str, Path]] = []

    @contextmanager
    def fake_lock(path: Path):
        events.append(("enter", path))
        if path == conflict:
            raise RuntimeError("lock conflict")
        try:
            yield
        finally:
            events.append(("exit", path))

    locks = (
        packet_checkpoint_recovery.ResolvedRecoveryLock(last, ("last",)),
        packet_checkpoint_recovery.ResolvedRecoveryLock(conflict, ("conflict",)),
        packet_checkpoint_recovery.ResolvedRecoveryLock(first, ("first",)),
    )

    with pytest.raises(RuntimeError, match="lock conflict"):
        with packet_checkpoint_recovery.acquire_recovery_locks(
            locks, lock_factory=fake_lock
        ):
            pytest.fail("conflicting lock must prevent entry")

    assert events == [
        ("enter", first),
        ("enter", conflict),
        ("exit", first),
    ]


def test_plan_output_requires_existing_parent_directory(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    plan = tmp_path / "missing" / "plan.json"

    with pytest.raises(
        PacketCheckpointRecoveryError, match="plan_output parent must already exist"
    ):
        packet_checkpoint_recovery.validate_generated_paths(
            repository_root=repository_root, plan_output=plan
        )

    assert not plan.parent.exists()


def test_artifact_directory_must_already_exist(tmp_path: Path) -> None:
    repository_root = _repository(tmp_path)
    artifact_dir = tmp_path / "missing-artifacts"

    with pytest.raises(
        PacketCheckpointRecoveryError, match="artifact_dir must be an existing directory"
    ):
        packet_checkpoint_recovery.validate_generated_paths(
            repository_root=repository_root, artifact_dir=artifact_dir
        )

    assert not artifact_dir.exists()


def test_plan_requires_supported_detector_and_source_table(tmp_path: Path) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "supported.db")
    try:
        with pytest.raises(PacketCheckpointRecoveryError, match="unsupported detector"):
            _build_plan(connection, tmp_path=tmp_path, detector_name="mqtt_rule")

        plan = _build_plan(connection, tmp_path=tmp_path)

        assert plan["detector_name"] == "packet_rule"
        assert plan["source_table"] == "packet_feature_logs"
    finally:
        connection.close()


def test_plan_requires_existing_completed_current_and_target_sessions(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "sessions.db")
    try:
        missing_current = _build_plan(
            connection,
            tmp_path=tmp_path,
            current_session_id="99999999-9999-4999-8999-999999999999",
        )
        missing_target = _build_plan(
            connection,
            tmp_path=tmp_path,
            target_session_id="88888888-8888-4888-8888-888888888888",
        )
        connection.execute(
            "UPDATE packet_capture_sessions SET status = 'FAILED' WHERE session_id = ?",
            (TARGET_SESSION,),
        )
        connection.commit()
        failed_target = _build_plan(connection, tmp_path=tmp_path)

        assert "CURRENT_SESSION_NOT_FOUND" in _blocking_codes(missing_current)
        assert "TARGET_SESSION_NOT_FOUND" in _blocking_codes(missing_target)
        assert "TARGET_SESSION_NOT_COMPLETED" in _blocking_codes(failed_target)
        assert missing_current["can_execute"] is False
        assert missing_target["can_execute"] is False
        assert failed_target["can_execute"] is False
    finally:
        connection.close()


def test_plan_requires_current_checkpoint_at_current_ready_through(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "checkpoint.db")
    try:
        plan = _build_plan(connection, tmp_path=tmp_path)

        assert plan["can_execute"] is True
        assert plan["checkpoint"]["before"]["last_completed_window_end"] == _db_utc(
            CURRENT_READY_THROUGH
        )
        assert plan["checkpoint"]["after"]["last_completed_window_end"] == _db_utc(
            TARGET_FIRST
        )

        connection.execute(
            "DELETE FROM detector_checkpoints WHERE detector_name = 'packet_rule'"
        )
        connection.commit()
        missing = _build_plan(connection, tmp_path=tmp_path)
        assert "CHECKPOINT_NOT_FOUND" in _blocking_codes(missing)
        assert missing["can_execute"] is False
    finally:
        connection.close()


def test_plan_rejects_current_session_with_remaining_ready_prefix(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "remaining-prefix.db")
    try:
        connection.execute(
            """
            UPDATE detector_checkpoints
            SET last_completed_window_end = ?
            WHERE detector_name = 'packet_rule' AND source_table = 'packet_feature_logs'
            """,
            (_db_utc(CURRENT_FIRST + timedelta(seconds=10)),),
        )
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path)

        assert "CURRENT_SESSION_HAS_READY_PREFIX_AFTER_CHECKPOINT" in _blocking_codes(
            plan
        )
        assert plan["can_execute"] is False
    finally:
        connection.close()


def test_plan_requires_target_full_ready_processed_or_empty_range(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "target-ready.db")
    try:
        plan = _build_plan(connection, tmp_path=tmp_path)

        assert plan["can_execute"] is True
        assert plan["target_session"] == {
            "session_id": TARGET_SESSION,
            "status": "COMPLETED",
            "first_window_start": _db_utc(TARGET_FIRST),
            "packet_feature_ready_through": _db_utc(TARGET_READY_THROUGH),
            "segment_count": 2,
            "feature_row_count": 2,
            "full_ready": True,
            "blocking_reasons": [],
        }
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("mutation", "readiness_reason"),
    (
        ("missing", "MISSING_WINDOW"),
        ("ready", "NON_TERMINAL_OR_ERROR"),
        ("failed", "NON_TERMINAL_OR_ERROR"),
        ("processed_without_feature", "FEATURE_COUNT_MISMATCH"),
        ("empty_with_feature", "FEATURE_COUNT_MISMATCH"),
    ),
)
def test_plan_rejects_missing_ready_failed_or_inconsistent_feature_segments(
    tmp_path: Path,
    mutation: str,
    readiness_reason: str,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / f"target-{mutation}.db")
    try:
        rows = connection.execute(
            """
            SELECT pcsg.id, pcsg.window_start
            FROM packet_capture_segments pcsg
            JOIN packet_capture_sessions pcs ON pcs.id = pcsg.capture_session_id
            WHERE pcs.session_id = ?
            ORDER BY pcsg.window_start
            """,
            (TARGET_SESSION,),
        ).fetchall()
        first_id, second_id = int(rows[0]["id"]), int(rows[1]["id"])
        if mutation == "missing":
            connection.execute(
                "DELETE FROM packet_feature_logs WHERE capture_segment_id = ?",
                (first_id,),
            )
            connection.execute(
                "DELETE FROM packet_capture_segments WHERE id = ?", (first_id,)
            )
        elif mutation == "ready":
            connection.execute(
                "UPDATE packet_capture_segments SET status = 'READY' WHERE id = ?",
                (second_id,),
            )
        elif mutation == "failed":
            connection.execute(
                "UPDATE packet_capture_segments SET status = 'FAILED' WHERE id = ?",
                (second_id,),
            )
        elif mutation == "processed_without_feature":
            connection.execute(
                "UPDATE packet_capture_segments SET status = 'PROCESSED' WHERE id = ?",
                (second_id,),
            )
        else:
            _insert_feature_for_existing_segment(connection, second_id)
        connection.commit()

        plan = _build_plan(connection, tmp_path=tmp_path)

        assert "TARGET_SESSION_NOT_FULL_READY" in _blocking_codes(plan)
        assert readiness_reason in plan["target_session"]["blocking_reasons"]
        assert plan["can_execute"] is False
    finally:
        connection.close()


def test_plan_lists_all_running_sessions_as_blocking(tmp_path: Path) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "running.db")
    try:
        _insert_capture_session(
            connection,
            session_id=RUNNING_SESSION_B,
            capture_interface="eth-running-b",
            first_window_start=TARGET_FIRST + timedelta(minutes=2),
            status="RUNNING",
            started_at=CURRENT_FIRST + timedelta(minutes=2),
        )
        _insert_capture_session(
            connection,
            session_id=RUNNING_SESSION_A,
            capture_interface="eth-running-a",
            first_window_start=TARGET_FIRST + timedelta(minutes=1),
            status="RUNNING",
            started_at=CURRENT_FIRST + timedelta(minutes=1),
        )
        connection.commit()
        before = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM packet_capture_sessions ORDER BY id"
            ).fetchall()
        )

        plan = _build_plan(connection, tmp_path=tmp_path)

        after = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM packet_capture_sessions ORDER BY id"
            ).fetchall()
        )
        assert plan["running_sessions"] == [
            {
                "session_id": RUNNING_SESSION_A,
                "started_at": _db_utc(CURRENT_FIRST + timedelta(minutes=1)),
            },
            {
                "session_id": RUNNING_SESSION_B,
                "started_at": _db_utc(CURRENT_FIRST + timedelta(minutes=2)),
            },
        ]
        assert "RUNNING_CAPTURE_SESSIONS" in _blocking_codes(plan)
        assert plan["can_execute"] is False
        assert after == before
    finally:
        connection.close()


def test_plan_rejects_checkpoint_regression_same_session_and_duplicate_recovery(
    tmp_path: Path,
) -> None:
    regression = _seed_valid_recovery_database(tmp_path / "regression.db")
    same_session = _seed_valid_recovery_database(tmp_path / "same-session.db")
    duplicate = _seed_valid_recovery_database(tmp_path / "duplicate.db")
    try:
        regression.execute(
            "UPDATE packet_capture_sessions SET first_window_start = ? WHERE session_id = ?",
            (_db_utc(CURRENT_FIRST), TARGET_SESSION),
        )
        regression.commit()
        regression_plan = _build_plan(regression, tmp_path=tmp_path)
        same_plan = _build_plan(
            same_session,
            tmp_path=tmp_path,
            target_session_id=CURRENT_SESSION,
        )
        _insert_recovery_audit(duplicate)
        duplicate_plan = _build_plan(duplicate, tmp_path=tmp_path)

        assert "CHECKPOINT_WOULD_NOT_ADVANCE" in _blocking_codes(regression_plan)
        assert "CURRENT_AND_TARGET_SESSION_MATCH" in _blocking_codes(same_plan)
        assert "DUPLICATE_RECOVERY" in _blocking_codes(duplicate_plan)
        assert regression_plan["can_execute"] is False
        assert same_plan["can_execute"] is False
        assert duplicate_plan["can_execute"] is False
    finally:
        regression.close()
        same_session.close()
        duplicate.close()


def test_recovery_readiness_matches_existing_helper_for_normal_and_empty_segments(
    tmp_path: Path,
) -> None:
    database = tmp_path / "parity-normal.db"
    connection = _seed_valid_recovery_database(database)
    connection.close()

    _assert_readiness_parity(database, (CURRENT_SESSION, TARGET_SESSION))


def test_recovery_readiness_matches_existing_helper_for_ready_failed_and_missing_window(
    tmp_path: Path,
) -> None:
    database = tmp_path / "parity-nonterminal.db"
    connection = _open_migrated_database(database)
    session_ids = (
        "55555555-5555-4555-8555-555555555555",
        "66666666-6666-4666-8666-666666666666",
        "77777777-7777-4777-8777-777777777777",
    )
    try:
        for index, (session_id, terminal_status) in enumerate(
            zip(session_ids, ("READY", "FAILED", "PROCESSED")), start=1
        ):
            session_pk = _insert_capture_session(
                connection,
                session_id=session_id,
                capture_interface=f"parity-{index}",
                first_window_start=TARGET_FIRST,
            )
            _insert_capture_segment(
                connection,
                session_pk=session_pk,
                capture_interface=f"parity-{index}",
                window_start=TARGET_FIRST,
                status="PROCESSED",
                feature_count=1,
            )
            second_start = TARGET_FIRST + timedelta(
                seconds=20 if terminal_status == "PROCESSED" else 10
            )
            _insert_capture_segment(
                connection,
                session_pk=session_pk,
                capture_interface=f"parity-{index}",
                window_start=second_start,
                status=terminal_status,
                feature_count=1 if terminal_status == "PROCESSED" else 0,
            )
        connection.commit()
    finally:
        connection.close()

    _assert_readiness_parity(database, session_ids)


def test_recovery_readiness_matches_existing_helper_for_error_code_and_feature_mismatch(
    tmp_path: Path,
) -> None:
    database = tmp_path / "parity-inconsistent.db"
    connection = _open_migrated_database(database)
    session_ids = (
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    )
    try:
        for index, session_id in enumerate(session_ids, start=1):
            session_pk = _insert_capture_session(
                connection,
                session_id=session_id,
                capture_interface=f"mismatch-{index}",
                first_window_start=TARGET_FIRST,
            )
            if index == 1:
                _insert_capture_segment(
                    connection,
                    session_pk=session_pk,
                    capture_interface=f"mismatch-{index}",
                    window_start=TARGET_FIRST,
                    status="PROCESSED",
                    feature_count=1,
                    error_code="EXTRACTOR_ERROR",
                )
            elif index == 2:
                _insert_capture_segment(
                    connection,
                    session_pk=session_pk,
                    capture_interface=f"mismatch-{index}",
                    window_start=TARGET_FIRST,
                    status="PROCESSED",
                )
            else:
                _insert_capture_segment(
                    connection,
                    session_pk=session_pk,
                    capture_interface=f"mismatch-{index}",
                    window_start=TARGET_FIRST,
                    status="EMPTY",
                    feature_count=1,
                )
        connection.commit()
    finally:
        connection.close()

    _assert_readiness_parity(database, session_ids)


def test_target_full_ready_rejects_segment_before_first_window(
    tmp_path: Path,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / "before-first.db")
    try:
        target_pk = int(
            connection.execute(
                "SELECT id FROM packet_capture_sessions WHERE session_id = ?",
                (TARGET_SESSION,),
            ).fetchone()["id"]
        )
        _insert_capture_segment(
            connection,
            session_pk=target_pk,
            capture_interface="eth-target",
            window_start=TARGET_FIRST - timedelta(seconds=10),
            status="PROCESSED",
            feature_count=1,
        )
        connection.commit()

        readiness = calculate_packet_feature_readiness(connection, TARGET_SESSION)
        plan = _build_plan(connection, tmp_path=tmp_path)

        assert readiness is not None
        assert readiness.packet_feature_ready_through == TARGET_READY_THROUGH
        assert readiness.full_ready is False
        assert "SEGMENT_BEFORE_OR_OVERLAPPING_PREFIX" in readiness.blocking_reasons
        assert "TARGET_SESSION_NOT_FULL_READY" in _blocking_codes(plan)
    finally:
        connection.close()


@pytest.mark.parametrize("extra_kind", ("overlap", "extra"))
def test_target_full_ready_rejects_overlapping_or_extra_segment(
    tmp_path: Path,
    extra_kind: str,
) -> None:
    connection = _seed_valid_recovery_database(tmp_path / f"{extra_kind}.db")
    try:
        target_pk = int(
            connection.execute(
                "SELECT id FROM packet_capture_sessions WHERE session_id = ?",
                (TARGET_SESSION,),
            ).fetchone()["id"]
        )
        start = (
            TARGET_FIRST + timedelta(seconds=5)
            if extra_kind == "overlap"
            else TARGET_READY_THROUGH + timedelta(seconds=10)
        )
        _insert_capture_segment(
            connection,
            session_pk=target_pk,
            capture_interface="eth-target",
            window_start=start,
            status="PROCESSED",
            feature_count=1,
            file_suffix=f"-{extra_kind}",
        )
        connection.commit()

        readiness = calculate_packet_feature_readiness(connection, TARGET_SESSION)

        assert readiness is not None
        assert readiness.full_ready is False
        assert readiness.segment_count < len(
            connection.execute(
                """
                SELECT pcsg.id
                FROM packet_capture_segments pcsg
                JOIN packet_capture_sessions pcs ON pcs.id = pcsg.capture_session_id
                WHERE pcs.session_id = ?
                """,
                (TARGET_SESSION,),
            ).fetchall()
        )
        assert readiness.blocking_reasons
    finally:
        connection.close()
